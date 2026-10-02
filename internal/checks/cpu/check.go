// Package cpu is the "cpu" domain check: processor inventory and socket
// status, CPUs taken offline, machine-check history (rasdaemon, mcelog) and
// thermal throttling.
package cpu

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/ras"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "cpu"

// Facts is the typed data of the cpu domain.
type Facts struct {
	Model      string      `json:"model,omitempty"`
	Vendor     string      `json:"vendor,omitempty"`
	Sockets    int         `json:"sockets,omitempty"`
	Logical    int         `json:"logicalCpus,omitempty"`
	Online     string      `json:"online,omitempty"`
	Offline    string      `json:"offline,omitempty"`
	Present    string      `json:"present,omitempty"`
	SMT        string      `json:"smt,omitempty"`
	Hypervisor string      `json:"hypervisor,omitempty"`
	Microcode  []string    `json:"microcode,omitempty"`
	Processors []Processor `json:"processors,omitempty"`
	Throttle   []Throttle  `json:"throttle,omitempty"`
	MCE        []ras.MCE   `json:"mce,omitempty"` // records (capped at 50)
	Rasdaemon  string      `json:"rasdaemon,omitempty"`
	Mcelog     string      `json:"mcelog,omitempty"`
}

// Throttle is the thermal throttle summary of one package.
type Throttle struct {
	Package       int    `json:"package"`
	PackageEvents uint64 `json:"packageEvents"`
	PackageTimeMS uint64 `json:"packageTimeMs,omitempty"`
	CoreEventsMax uint64 `json:"coreEventsMax"`
	CoreTimeMSMax uint64 `json:"coreTimeMsMax,omitempty"`
	CPUsAffected  int    `json:"cpusAffected"`
	CPUs          int    `json:"cpus"`
}

// HWWindowDays is how far back machine-check and memory-error history
// counts as "recent". Hardware error logs are sparse, so the usual log
// window (default 7 days) is too short to see a recurring fault; older
// events may predate a part replacement and are reported as history only.
const HWWindowDays = 30

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	if len(b.Prefix("cpu.")) == 0 {
		return res
	}
	switch env.OS {
	case collect.OSWindows:
		checkWindows(b, env, &res)
	case collect.OSLinux:
		c := &linuxCheck{b: b, env: env, res: &res, facts: &Facts{}}
		c.inventory()
		c.mce()
		c.throttle()
		res.Facts = c.facts
	}
	return res
}

type linuxCheck struct {
	b       *collect.Bundle
	env     model.Env
	res     *model.Result
	facts   *Facts
	virtual bool          // VM or container, by env or by the CPU's hypervisor flag
	thermal []ras.MCE     // mcelog/rasdaemon thermal notifications (recent)
	uptime  time.Duration // 0 when unknown
	// staleSockets: the OS runs every populated socket, so a "Disabled By
	// BIOS" status is out of date.
	staleSockets bool
}

func (c *linuxCheck) add(f model.Finding) {
	if f.Component == "" {
		f.Component = model.CompCPU
	}
	c.res.Findings = append(c.res.Findings, f)
}

func (c *linuxCheck) cov(id string, name model.Text, state string, reason, fix model.Text) {
	c.covCmd(id, name, state, reason, fix, "")
}

// covCmd records coverage with the one command that enables the check.
func (c *linuxCheck) covCmd(id string, name model.Text, state string, reason, fix model.Text, cmd string) {
	c.res.Coverage = append(c.res.Coverage, model.Coverage{
		ID: id, Component: model.CompCPU, Name: name, State: state, Reason: reason, Fix: fix, Cmd: cmd,
	})
}

// sudo prefixes cmd with sudo when the collector did not run as root.
func sudo(env model.Env, cmd string) string {
	if env.Root {
		return cmd
	}
	return "sudo " + cmd
}

// rootCmd is the command that reruns the check as root.
const rootCmd = "sudo diagward check"

// enableCmd starts rasdaemon now and at every boot.
func enableCmd(env model.Env) string { return sudo(env, "systemctl enable --now rasdaemon") }

var (
	nameInventory = model.T("CPU inventory and socket status", "Danh sách CPU và trạng thái socket")
	nameMCE       = model.T("Machine-check errors (MCE)", "Lỗi phần cứng machine-check (MCE)")
	nameThrottle  = model.T("CPU thermal throttling", "CPU giảm xung do quá nhiệt")
)

// Uptime returns the uptime recorded in meta.ident (0 when unknown).
func Uptime(b *collect.Bundle) time.Duration {
	f, err := strconv.ParseFloat(b.Get("meta.ident").KV()["uptime"], 64)
	if err != nil || f <= 0 || f > 1e10 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

// ---- inventory ----

func (c *linuxCheck) inventory() {
	b, f := c.b, c.facts
	c.uptime = Uptime(b)
	ls := lscpuFields(b.Get("cpu.lscpu_json").Text(), b.Get("cpu.lscpu").Text())
	ci := parseCpuinfo(b.Get("cpu.cpuinfo").Text())
	sys := sysfsBase(b.Get("cpu.sysfs"))

	f.Model = strings.Join(strings.Fields(firstNonEmpty(ls["Model name"], first(ci.sorted("model name")))), " ")
	f.Vendor = firstNonEmpty(ls["Vendor ID"], first(ci.sorted("vendor_id")))
	f.Hypervisor = ls["Hypervisor vendor"]
	f.Sockets = atoi(ls["Socket(s)"])
	if f.Sockets == 0 {
		f.Sockets = len(ci.Values["physical id"])
	}
	f.Logical = atoi(ls["CPU(s)"])
	if f.Logical == 0 {
		f.Logical = ci.Processors
	}
	f.Online = firstNonEmpty(sys["online"], ls["On-line CPU(s) list"])
	f.Offline = firstNonEmpty(sys["offline"], ls["Off-line CPU(s) list"])
	f.Present = sys["present"]
	f.SMT = sys["smt_control"]
	f.Microcode = ci.sorted("microcode")
	c.virtual = !c.env.Bare() || f.Hypervisor != "" || ci.Hypervisor

	dsec := b.Get("cpu.dmidecode")
	procs := dmiProcessors(dsec.Text())
	f.Processors = procs

	if f.Model == "" && f.Logical == 0 && len(procs) == 0 {
		reason := model.T("No CPU information could be read.", "Không đọc được thông tin CPU.")
		if s := firstErr(b, "cpu.lscpu_json", "cpu.lscpu", "cpu.cpuinfo"); s != "" {
			reason = model.Tf("No CPU information could be read: %s", "Không đọc được thông tin CPU: %s", s)
		}
		c.cov("cpu.inventory", nameInventory, model.CovFailed, reason, model.Text{})
		return
	}

	// Socket status needs dmidecode (root) on bare metal.
	switch {
	case len(procs) > 0 || c.virtual:
		c.cov("cpu.inventory", nameInventory, model.CovRan, model.Text{}, model.Text{})
	case dsec == nil:
		c.cov("cpu.inventory", nameInventory, model.CovPartial,
			model.T("Socket status was not collected.", "Chưa thu thập trạng thái socket."), model.Text{})
	case dsec.Skipped == "not-root":
		c.covCmd("cpu.inventory", nameInventory, model.CovPartial,
			model.T("Socket status (dmidecode) needs root.", "Trạng thái socket (dmidecode) cần quyền root."), hint.RunAsRoot(c.env), rootCmd)
	case dsec.Missing != "":
		fix, cmd := hint.InstallFix(c.env, "dmidecode")
		c.covCmd("cpu.inventory", nameInventory, model.CovPartial, hint.Missing("dmidecode"), fix, cmd)
	default:
		reason := model.T("dmidecode returned no processor records (no SMBIOS table).", "dmidecode không trả về thông tin CPU (không có bảng SMBIOS).")
		if dsec.Err != "" && !strings.Contains(dsec.Text(), "SMBIOS") {
			reason = model.Tf("dmidecode failed: %s", "dmidecode lỗi: %s", oneLine(dsec.Err))
		}
		c.cov("cpu.inventory", nameInventory, model.CovPartial, reason, model.Text{})
	}

	c.socketFindings(procs)
	c.onlineFindings()
	c.mixFindings(ci, procs)
	c.inventoryTable(ci, procs)
}

func (c *linuxCheck) socketFindings(procs []Processor) {
	// If the kernel sees as many sockets with online CPUs as the BIOS lists
	// populated sockets (disabled ones included), the "disabled" processor
	// is in fact running: the SMBIOS status is stale (seen after a CPU was
	// replaced, or with firmware that never updates the table).
	populatedAll := 0
	for _, p := range procs {
		if p.Populated {
			populatedAll++
		}
	}
	stale := c.facts.Sockets > 0 && c.facts.Sockets >= populatedAll
	c.staleSockets = stale
	disabled := 0
	for _, p := range procs {
		switch {
		case p.DisabledBIOS && !c.virtual && stale:
			c.add(model.Finding{
				ID: "cpu.socket_status_stale", Severity: model.Info, Target: p.Socket,
				Title: model.Tf("Socket %s is listed as disabled by the BIOS, but the OS sees all CPUs", "Socket %s bị BIOS ghi là đã tắt, nhưng hệ điều hành vẫn thấy đủ CPU", p.Socket),
				Detail: model.Tf("dmidecode reports \"%s\" for socket %s, yet Linux runs %d socket(s), as many as the BIOS lists as populated. The processor works; the firmware table is out of date, often after a CPU fault that has since been cleared or a CPU replacement.",
					"dmidecode báo \"%s\" cho socket %s, nhưng Linux vẫn chạy %d socket, bằng số socket BIOS ghi là có lắp CPU. CPU vẫn hoạt động; bảng SMBIOS của firmware chưa được cập nhật, thường gặp sau một lỗi CPU đã qua hoặc sau khi thay CPU.",
					p.Status, p.Socket, c.facts.Sockets),
				Action: model.T("Check the BMC event log (iDRAC Lifecycle Log, iLO IML, IPMI SEL) for past CPU errors; a cold boot or a BIOS update usually refreshes the table.",
					"Xem log sự kiện BMC (iDRAC Lifecycle Log, iLO IML, IPMI SEL) có lỗi CPU cũ không; tắt hẳn rồi bật lại máy hoặc cập nhật BIOS thường làm mới bảng này."),
				Evidence: []string{"Socket Designation: " + p.Socket, "Status: " + p.Status, fmt.Sprintf("lscpu Socket(s): %d", c.facts.Sockets)},
			})
		case p.DisabledBIOS && !c.virtual:
			// SMBIOS 3.x, type 4 "CPU Status" value 3 = "CPU Disabled By
			// BIOS (POST Error)": certain evidence. On VMs (VMware lists
			// dozens of unused sockets this way) it means nothing.
			disabled++
			c.add(model.Finding{
				ID: "cpu.socket_disabled", Severity: model.Crit, Target: p.Socket,
				Title: model.Tf("CPU in socket %s is disabled by the BIOS (POST error)", "CPU ở socket %s bị BIOS vô hiệu hoá (lỗi POST)", p.Socket),
				Detail: model.Tf("dmidecode reports \"%s\" for socket %s (%s). SMBIOS uses this status when the firmware turned the processor off after a power-on self-test error: the server runs with fewer CPUs, and the memory attached to that socket is usually missing too.",
					"dmidecode báo \"%s\" cho socket %s (%s). SMBIOS dùng trạng thái này khi firmware tắt CPU sau lỗi tự kiểm tra lúc khởi động (POST): máy chạy thiếu CPU, và RAM gắn với socket đó thường cũng mất theo.",
					p.Status, p.Socket, firstNonEmpty(p.Model, "?")),
				Action: model.Tf("Read the POST/hardware event log in the BMC (iDRAC Lifecycle Log, iLO IML, IPMI SEL) for socket %[1]s. Power the server off, reseat the CPU and heatsink and check the socket for bent pins. If it persists, swap the CPUs between sockets: if the fault follows the CPU, replace the CPU; if it stays with the socket, replace the motherboard. Then open a warranty case.",
					"Xem log POST/sự kiện phần cứng trên BMC (iDRAC Lifecycle Log, iLO IML, IPMI SEL) cho socket %[1]s. Tắt máy, gắn lại CPU và tản nhiệt, kiểm tra chân socket có bị cong không. Nếu vẫn lỗi, đổi chéo CPU giữa hai socket: lỗi đi theo CPU thì thay CPU, lỗi ở lại socket thì thay bo mạch chủ, rồi mở case bảo hành.", p.Socket),
				Evidence: []string{"Socket Designation: " + p.Socket, "Status: " + p.Status, "Version: " + p.Model},
				Part:     &model.Part{Kind: "cpu", Vendor: p.Manufacturer, Model: firstNonEmpty(p.PartNumber, p.Model), Serial: p.Serial, Location: p.Socket},
			})
		case p.DisabledUser && !c.virtual:
			c.add(model.Finding{
				ID: "cpu.socket_disabled_by_user", Severity: model.Info, Target: p.Socket,
				Title:  model.Tf("CPU in socket %s is disabled in the BIOS setup", "CPU ở socket %s bị tắt trong BIOS setup", p.Socket),
				Detail: model.Tf("dmidecode reports \"%s\": someone turned this processor off in the BIOS setup (not a fault).", "dmidecode báo \"%s\": CPU này đã được tắt thủ công trong BIOS setup (không phải lỗi).", p.Status),
				Action: model.T("If this was not intended, enable the processor again in the BIOS setup.", "Nếu không cố ý, bật lại CPU trong BIOS setup."),
			})
		}
		if p.Populated && p.Cores > 0 && p.CoresEnabled > 0 && p.CoresEnabled < p.Cores && !c.virtual {
			c.add(model.Finding{
				ID: "cpu.cores_disabled", Severity: model.Info, Target: p.Socket,
				Title: model.Tf("Socket %s: only %d of %d cores are enabled", "Socket %s: chỉ bật %d/%d nhân", p.Socket, p.CoresEnabled, p.Cores),
				Detail: model.T("The BIOS enables fewer cores than the processor has. This is usually a BIOS setting (core licensing, power saving); a core disabled after a fault shows up the same way.",
					"BIOS bật ít nhân hơn số nhân CPU có. Thường là do cấu hình BIOS (giới hạn license, tiết kiệm điện); nhân bị tắt do lỗi cũng hiện ra như vậy."),
				Action: model.T("Check the \"enabled cores\" setting in the BIOS. If nobody changed it, look for CPU errors in the BMC event log.",
					"Kiểm tra mục số nhân được bật (enabled cores) trong BIOS. Nếu không ai chỉnh, xem log sự kiện BMC có lỗi CPU không."),
			})
		}
	}
	populated := 0
	mdl := ""
	for _, p := range procs {
		if p.Populated && (!p.DisabledBIOS || stale) {
			populated++
			mdl = firstNonEmpty(mdl, p.Model)
		}
	}
	if disabled == 0 && populated > 0 && !c.virtual {
		mdl = firstNonEmpty(mdl, c.facts.Model)
		c.add(okFinding("cpu.sockets_ok",
			fmt.Sprintf("%d CPU socket(s) populated and enabled (%s)", populated, mdl),
			fmt.Sprintf("%d socket CPU đang lắp và hoạt động (%s)", populated, mdl)))
	}
}

func (c *linuxCheck) onlineFindings() {
	f := c.facts
	off := cpuList(f.Offline)
	if off <= 0 {
		return
	}
	if f.SMT == "off" || f.SMT == "forceoff" {
		return // SMT siblings are offline by design
	}
	// The kernel's "offline" file is "possible and not online"
	// (drivers/base/cpu.c print_cpus_offline), and "possible" includes the
	// empty hot-plug slots the firmware's ACPI tables announce ("smpboot:
	// Allowing 128 CPUs, 96 hotplug CPUs" is common on Dell/HPE servers and
	// VMs). Only CPUs that are present but not online were taken offline.
	offList := f.Offline
	total := cpuList(f.Present)
	if pres, ok := cpuIDs(f.Present); ok && len(pres) > 0 {
		if offs, ok := cpuIDs(f.Offline); ok {
			in := map[int]bool{}
			for _, p := range pres {
				in[p] = true
			}
			var both []int
			for _, o := range offs {
				if in[o] {
					both = append(both, o)
				}
			}
			off, offList = len(both), formatCPUs(both)
			if off == 0 {
				return
			}
		}
	}
	if total <= 0 {
		total = off + max(cpuList(f.Online), 0)
	}
	ev := []string{"online: " + f.Online, "offline: " + f.Offline}
	if f.Present != "" {
		ev = append(ev, "present: "+f.Present)
	}
	if f.SMT != "" {
		ev = append(ev, "smt/control: "+f.SMT)
	}
	c.add(model.Finding{
		ID: "cpu.cpus_offline", Severity: model.Warn, Target: "CPU " + offList,
		Title: model.Tf("%d of %d CPUs are offline", "%d/%d CPU đang offline", off, total),
		Detail: model.Tf("The kernel lists CPUs %s as offline, so the server runs with less processing power. An administrator may have turned them off (echo 0 > /sys/devices/system/cpu/cpuN/online), a kernel parameter such as maxcpus= may limit them, or the kernel took a CPU offline after machine-check errors.",
			"Kernel báo CPU %s đang offline nên máy chạy thiếu sức xử lý. Có thể quản trị viên đã tắt (echo 0 > /sys/devices/system/cpu/cpuN/online), tham số kernel như maxcpus= giới hạn, hoặc kernel tự tắt CPU sau lỗi machine-check.", offList),
		Action: model.T("Check the kernel command line (cat /proc/cmdline) and dmesg for \"CPU N is now offline\" or machine-check messages. If nobody took them offline on purpose, bring them back (echo 1 > /sys/devices/system/cpu/cpuN/online) and watch for errors; repeated machine checks on the same CPU mean the processor needs replacing.",
			"Kiểm tra dòng lệnh kernel (cat /proc/cmdline) và dmesg xem có \"CPU N is now offline\" hoặc lỗi machine-check không. Nếu không ai cố ý tắt, bật lại (echo 1 > /sys/devices/system/cpu/cpuN/online) và theo dõi; nếu một CPU lặp lại lỗi machine-check thì cần thay CPU."),
		Evidence: ev,
	})
}

func (c *linuxCheck) mixFindings(ci cpuinfoSummary, procs []Processor) {
	if c.virtual {
		return
	}
	models := map[string]bool{}
	for _, p := range procs {
		if p.Populated && p.Enabled && p.Model != "" {
			models[p.Model] = true
		}
	}
	if len(models) < 2 {
		models = map[string]bool{}
		for _, m := range ci.sorted("model name") {
			models[strings.Join(strings.Fields(m), " ")] = true
		}
	}
	if len(models) > 1 {
		var ms []string
		for m := range models {
			ms = append(ms, m)
		}
		sort.Strings(ms)
		c.add(model.Finding{
			ID: "cpu.mixed_models", Severity: model.Info,
			Title: model.T("The sockets hold different CPU models", "Các socket đang lắp CPU khác model"),
			Detail: model.Tf("Processors found: %s. Server vendors only support identical CPUs in all sockets; a mismatch usually comes from a replacement with the wrong part.",
				"CPU tìm thấy: %s. Nhà sản xuất server chỉ hỗ trợ các CPU giống hệt nhau trên mọi socket; lệch model thường do thay nhầm linh kiện.", strings.Join(ms, "; ")),
			Action: model.T("Check that all CPUs have the same model and stepping (part number on the CPU); replace the odd one.",
				"Kiểm tra các CPU cùng model và stepping (mã trên CPU); thay CPU bị lệch."),
			Evidence: ms,
		})
	}
	if mc := ci.sorted("microcode"); len(mc) > 1 {
		c.add(model.Finding{
			ID: "cpu.mixed_microcode", Severity: model.Info,
			Title: model.T("CPUs run different microcode revisions", "Các CPU chạy microcode khác phiên bản"),
			Detail: model.Tf("/proc/cpuinfo shows microcode %s. All CPUs should load the same revision; a difference points to mixed CPU steppings or an incomplete microcode update.",
				"/proc/cpuinfo cho thấy microcode %s. Mọi CPU phải cùng một bản; khác nhau là dấu hiệu CPU lệch stepping hoặc cập nhật microcode chưa trọn.", strings.Join(mc, ", ")),
			Action: model.T("Update the BIOS/firmware and the microcode package (microcode_ctl / intel-microcode / amd64-microcode), then reboot.",
				"Cập nhật BIOS/firmware và gói microcode (microcode_ctl / intel-microcode / amd64-microcode), rồi khởi động lại."),
		})
	}
}

func (c *linuxCheck) inventoryTable(ci cpuinfoSummary, procs []Processor) {
	t := model.Table{
		ID:    "cpu.sockets",
		Title: model.T("Processors", "Bộ xử lý (CPU)"),
		Columns: []model.Text{
			model.T("Socket", "Socket"), model.T("Model", "Model"), model.T("Status", "Trạng thái"),
			model.T("Cores (enabled/total)", "Nhân (bật/tổng)"), model.T("Threads", "Luồng"),
			model.T("Speed MHz (now/max)", "Xung MHz (hiện tại/tối đa)"), model.T("Serial", "Serial"),
		},
	}
	hidden := 0
	for _, p := range procs {
		if c.virtual && (!p.Populated || p.DisabledBIOS) {
			hidden++
			continue
		}
		st := model.OK
		switch {
		case p.DisabledBIOS && c.staleSockets:
			st = model.Info
		case p.DisabledBIOS:
			st = model.Crit
		case p.DisabledUser:
			st = model.Info
		}
		cores := ""
		if p.Cores > 0 {
			cores = fmt.Sprintf("%d/%d", firstPos(p.CoresEnabled, p.Cores), p.Cores)
		}
		t.Rows = append(t.Rows, model.NewRow(st,
			p.Socket, p.Model, statusCell(p.Status), cores, itoa(p.Threads), speeds(p.CurrentMHz, p.MaxMHz), p.Serial,
		))
	}
	if len(procs) == 0 {
		// Without dmidecode: one row per physical package from /proc/cpuinfo.
		ids := ci.sorted("physical id")
		sort.Strings(ids)
		for _, id := range ids {
			t.Rows = append(t.Rows, model.NewRow(model.OK,
				model.T("physical id "+id, "socket "+id+" (physical id)"), c.facts.Model, statusCell("online"), first(ci.sorted("cpu cores")), itoa(ci.Values["physical id"][id]), "", "",
			))
		}
		if len(ids) == 0 && c.facts.Model != "" {
			t.Rows = append(t.Rows, model.NewRow(model.OK, "-", c.facts.Model, statusCell("online"), "", itoa(c.facts.Logical), "", ""))
		}
	}
	if hidden > 0 {
		t.Note = model.Tf("%d empty virtual socket(s) of this VM are not shown.", "Ẩn %d socket ảo trống của máy ảo.", hidden)
	}
	if len(t.Rows) > 0 {
		c.res.Tables = append(c.res.Tables, t)
	}
}

// ---- machine checks ----

func (c *linuxCheck) mce() {
	b, env := c.b, c.env
	svc := b.Get("cpu.services").KV()
	c.facts.Rasdaemon = svcState(svc, "rasdaemon")
	c.facts.Mcelog = svcState(svc, "mcelog")
	sum := b.Get("cpu.ras_summary")
	errs := b.Get("cpu.ras_errors")
	mlog := b.Get("cpu.mcelog_log")
	mcli := b.Get("cpu.mcelog_client")
	status := b.Get("cpu.ras_status")
	if sum == nil && errs == nil && mlog == nil && mcli == nil && status == nil && b.Get("cpu.services") == nil {
		return // older collector without these sections
	}
	if allSkipped("container", sum, errs, mlog, mcli, status) {
		c.cov("cpu.mce", nameMCE, model.CovSkipped, hint.Virtual(env), model.Text{})
		return
	}

	rasInstalled := svc["rasdaemon.installed"] == "1" || (status != nil && status.Missing == "" && status.Skipped == "")
	mcelogInstalled := svc["mcelog.installed"] == "1" || (mcli != nil && mcli.Missing == "")
	rasRunning := svc["rasdaemon.running"] == "1" || svc["rasdaemon.active"] == "active"
	mcelogRunning := svc["mcelog.running"] == "1" || svc["mcelog.active"] == "active"

	var (
		sources []string
		errText string
		rep     ras.Report
		sumRep  ras.Report
	)
	if errs.Ran() {
		rep = ras.Parse(errs.Out)
		if !rep.Recognized && errs.Err != "" {
			errText = oneLine(errs.Err)
		}
	}
	if sum.Ran() {
		sumRep = ras.Parse(sum.Out)
		if !sumRep.Recognized && sum.Err != "" && errText == "" {
			errText = oneLine(sum.Err)
		}
	}
	if rep.Recognized || sumRep.Recognized {
		sources = append(sources, "rasdaemon")
		errText = ""
	}
	var mlogRecs []ras.MCE
	if mlog.Ran() {
		mlogRecs = ras.Mcelog(mlog.Out)
		sources = append(sources, "mcelog")
	}
	recs := rep.MCEs
	src := "rasdaemon"
	if len(recs) == 0 && len(mlogRecs) > 0 {
		recs, src = mlogRecs, "mcelog"
	} else if !rep.Recognized && !sumRep.Recognized {
		src = "mcelog"
	}
	// rasdaemon's memory-controller (EDAC) events are reported by the memory
	// domain; when present, memory-related MCEs are left to it.
	memByEDAC := len(rep.Mem)+len(rep.MemEvents)+len(sumRep.Mem) > 0

	switch {
	case len(sources) > 0:
		if !rasRunning && !mcelogRunning && b.Get("cpu.services").Ran() {
			c.covCmd("cpu.mce", nameMCE, model.CovPartial,
				model.T("History was read, but no error logger is running now: new machine checks are not being recorded.",
					"Đã đọc lịch sử, nhưng hiện không có dịch vụ ghi lỗi nào chạy: lỗi machine-check mới sẽ không được ghi lại."),
				enableFix(env, rasInstalled), c.enableCmd(rasInstalled))
		} else {
			c.cov("cpu.mce", nameMCE, model.CovRan, model.Text{}, model.Text{})
		}
	case !rasInstalled && !mcelogInstalled:
		if c.virtual {
			c.cov("cpu.mce", nameMCE, model.CovSkipped, hint.Virtual(env), model.Text{})
			return
		}
		c.covCmd("cpu.mce", nameMCE, model.CovSkipped, hint.Missing("rasdaemon"), enableFix(env, false), c.enableCmd(false))
		c.add(model.Finding{
			ID: "cpu.no_mce_logger", Severity: model.Info, Target: "rasdaemon",
			Title: model.T("No hardware error logger installed (rasdaemon/mcelog)", "Chưa cài dịch vụ ghi lỗi phần cứng (rasdaemon/mcelog)"),
			Detail: model.T("Without rasdaemon (or mcelog on older systems), CPU, memory and PCIe hardware errors are only printed to the kernel log and are lost after a reboot, so there is no history to diagnose intermittent faults. On RHEL/AlmaLinux/Rocky 8+ mcelog is deprecated in favour of rasdaemon.",
				"Không có rasdaemon (hoặc mcelog trên hệ cũ), lỗi phần cứng CPU, RAM, PCIe chỉ in ra log kernel và mất sau khi khởi động lại, nên không có lịch sử để chẩn đoán lỗi chập chờn. Trên RHEL/AlmaLinux/Rocky 8+, mcelog đã được thay bằng rasdaemon."),
			Action: installAndEnable(env),
		})
		return
	case rasNoDB(sum, errs) && !c.virtual:
		// ras-mc-ctl found no error database: rasdaemon has never run
		// with recording on, so there is no history at all.
		c.covCmd("cpu.mce", nameMCE, model.CovSkipped,
			model.T("rasdaemon is installed but has never recorded anything: its error database does not exist yet.",
				"Đã cài rasdaemon nhưng chưa từng ghi lỗi nào: chưa có cơ sở dữ liệu lỗi."),
			model.T("Start rasdaemon and enable it at boot; it records hardware errors from then on.",
				"Bật rasdaemon và cho chạy cùng hệ thống; từ đó lỗi phần cứng sẽ được ghi lại."), enableCmd(env))
		if !rasRunning {
			c.add(c.loggerStopped())
		}
		return
	case errText != "":
		c.cov("cpu.mce", nameMCE, model.CovFailed,
			model.Tf("ras-mc-ctl failed: %s", "ras-mc-ctl lỗi: %s", errText), model.Text{})
		return
	case (sum != nil && sum.Skipped == "not-root") || (mlog != nil && mlog.Skipped == "not-root"):
		c.covCmd("cpu.mce", nameMCE, model.CovSkipped, hint.NeedRoot(env), hint.RunAsRoot(env), rootCmd)
		return
	default:
		if c.virtual {
			c.cov("cpu.mce", nameMCE, model.CovSkipped, hint.Virtual(env), model.Text{})
			return
		}
		c.covCmd("cpu.mce", nameMCE, model.CovPartial,
			model.T("A hardware error logger is installed but its history could not be read.", "Đã cài dịch vụ ghi lỗi nhưng không đọc được lịch sử."),
			enableFix(env, rasInstalled), c.enableCmd(rasInstalled))
	}
	if rasInstalled && !rasRunning && !mcelogRunning && !c.virtual && b.Get("cpu.services").Ran() {
		c.add(c.loggerStopped())
	}

	c.analyzeMCE(recs, src, sumRep, memByEDAC)
	c.otherRasEvents(rep, sumRep)
}

func (c *linuxCheck) analyzeMCE(recs []ras.MCE, src string, sumRep ras.Report, memByEDAC bool) {
	now := c.env.Now
	window := time.Duration(HWWindowDays) * 24 * time.Hour
	var cpuUC, cpuDef, cpuCE, cpuUnk, memUC, memCE, old []ras.MCE
	var hints []string
	for _, m := range recs {
		recent := m.Time.IsZero() || now.IsZero() || now.Sub(m.Time) <= window
		if m.Class == ras.Thermal {
			if recent {
				c.thermal = append(c.thermal, m)
			}
			continue
		}
		if !recent {
			old = append(old, m)
			continue
		}
		if m.Hint != "" {
			hints = append(hints, m.Hint)
		}
		switch {
		case m.Memory && (m.Class == ras.Uncorrected || m.Class == ras.Fatal):
			memUC = append(memUC, m)
		case m.Memory:
			memCE = append(memCE, m)
		case m.Class == ras.Uncorrected || m.Class == ras.Fatal:
			cpuUC = append(cpuUC, m)
		case m.Class == ras.Deferred:
			cpuDef = append(cpuDef, m)
		case m.Class == ras.Corrected:
			cpuCE = append(cpuCE, m)
		default:
			cpuUnk = append(cpuUnk, m)
		}
	}
	for i := max(0, len(recs)-50); i < len(recs); i++ {
		c.facts.MCE = append(c.facts.MCE, recs[i])
	}

	// Summary-only data (no --errors records): counts without dates.
	sumOnly := len(recs) == 0 && len(sumRep.MCECounts) > 0
	if sumOnly {
		c.summaryMCE(sumRep, memByEDAC)
	}

	if len(cpuUC) > 0 {
		dated := 0
		for _, m := range cpuUC {
			if !m.Time.IsZero() {
				dated++
			}
		}
		sev := model.Crit
		if dated == 0 {
			sev = model.Warn // no dates: could be years old
		}
		tgt := mceTarget(cpuUC)
		c.add(model.Finding{
			ID: "cpu.mce_uncorrected", Severity: sev, Target: tgt,
			Title: model.Tf("%d uncorrected machine-check error(s) on %s", "%d lỗi machine-check không sửa được trên %s", len(cpuUC), tgt),
			Detail: model.Tf("The processor reported errors it could not correct (%s). This is a hardware event, not a software error: data may have been lost, and the kernel may have killed processes or panicked. These come from the CPU's caches, internal buses or the links between CPUs.",
				"CPU báo lỗi mà phần cứng không tự sửa được (%s). Đây là sự kiện phần cứng, không phải lỗi phần mềm: dữ liệu có thể đã hỏng, kernel có thể đã kill tiến trình hoặc treo máy. Lỗi đến từ cache, bus nội bộ của CPU hoặc kết nối giữa các CPU.", summarizeMsgs(cpuUC)),
			Action: model.Tf("Plan downtime soon. Check the BMC event log (iDRAC/iLO/IPMI SEL) for the same CPU, update BIOS and CPU microcode, then reseat the CPU. If errors repeat on %[1]s, replace the processor (open a warranty case with the evidence below).",
				"Sắp xếp thời gian dừng máy sớm. Kiểm tra log sự kiện BMC (iDRAC/iLO/IPMI SEL) cho CPU này, cập nhật BIOS và microcode, rồi gắn lại CPU. Nếu %[1]s tiếp tục lỗi, thay CPU (mở case bảo hành kèm bằng chứng bên dưới).", tgt),
			Evidence: mceEvidence(cpuUC),
			Part:     &model.Part{Kind: "cpu", Location: tgt},
		})
	}
	if len(cpuDef) > 0 {
		c.add(model.Finding{
			ID: "cpu.mce_deferred", Severity: model.Warn, Target: mceTarget(cpuDef),
			Title: model.Tf("%d deferred machine-check error(s)", "%d lỗi machine-check dạng deferred", len(cpuDef)),
			Detail: model.T("AMD processors report \"deferred\" errors when the hardware found data it could not correct but nothing has used it yet. It is a hardware event: if that data is read, it becomes an uncorrected error.",
				"CPU AMD báo lỗi \"deferred\" khi phần cứng phát hiện dữ liệu hỏng không sửa được nhưng chưa ai dùng tới. Đây là sự kiện phần cứng: nếu dữ liệu đó được đọc, nó sẽ thành lỗi không sửa được."),
			Action: model.T("Check which bank reported it (below). For memory banks, test or replace the DIMM; for others, update BIOS/microcode and watch for repeats; repeated errors mean replacing the CPU.",
				"Xem bank nào báo lỗi (bên dưới). Nếu là bank bộ nhớ, test hoặc thay thanh RAM; bank khác thì cập nhật BIOS/microcode và theo dõi; lỗi lặp lại thì thay CPU."),
			Evidence: mceEvidence(cpuDef),
		})
	}
	if len(cpuCE) > 0 || len(cpuUnk) > 0 {
		all := append(append([]ras.MCE{}, cpuCE...), cpuUnk...)
		// Warn from 10 corrected events in the window: the same count mcelog
		// uses by default for corrected DIMM errors (ce-error-threshold =
		// 10 / 24h in mcelog.conf). A hardware "yellow" threshold status
		// ("Large number of corrected cache errors", Intel SDM vol. 3B,
		// 16.4 "Enhanced cache error reporting") means the CPU itself
		// counted too many.
		sev := model.Info
		if len(cpuCE) >= 10 || len(hints) > 0 {
			sev = model.Warn
		}
		tgt := mceTarget(all)
		ev := mceEvidence(all)
		if len(hints) > 0 {
			ev = units.Evidence(append([]string{hints[0]}, ev...), 10)
		}
		c.add(model.Finding{
			ID: "cpu.mce_corrected", Severity: sev, Target: tgt,
			Title: model.Tf("%d corrected machine-check error(s) in the last %d days", "%d lỗi machine-check đã tự sửa trong %d ngày qua", len(all), HWWindowDays),
			Detail: model.Tf("The processor corrected these errors itself (%s), so nothing was lost. This is a hardware event, not a software error. A few over a server's life are normal; many, or a steady stream from the same CPU/bank, predict an uncorrected error.",
				"CPU đã tự sửa các lỗi này (%s), không mất dữ liệu. Đây là sự kiện phần cứng, không phải lỗi phần mềm. Thỉnh thoảng có vài lỗi là bình thường; nhiều lỗi, hoặc lặp lại đều đặn trên cùng CPU/bank, là dấu hiệu sắp có lỗi không sửa được.", summarizeMsgs(all)),
			Action: model.T("Keep watching (rasdaemon keeps the history) and update BIOS and microcode. If the count keeps growing on the same CPU/bank, plan to replace that processor.",
				"Tiếp tục theo dõi (rasdaemon lưu lịch sử) và cập nhật BIOS, microcode. Nếu số lỗi tiếp tục tăng trên cùng CPU/bank, lên kế hoạch thay CPU đó."),
			Evidence: ev,
		})
	}
	if !memByEDAC && len(memUC) > 0 {
		c.add(model.Finding{
			ID: "cpu.mce_memory_uncorrected", Component: model.CompMemory, Severity: model.Crit, Target: mceTarget(memUC),
			Title: model.Tf("%d uncorrected memory error(s) reported by the memory controller", "%d lỗi RAM không sửa được do bộ điều khiển bộ nhớ báo", len(memUC)),
			Detail: model.Tf("Machine checks from the CPU's memory controller (%s) show data that ECC could not correct. This is a hardware event: a DIMM (or its slot) is failing.",
				"Machine-check từ bộ điều khiển bộ nhớ của CPU (%s) cho thấy dữ liệu ECC không sửa được. Đây là sự kiện phần cứng: có thanh RAM (hoặc khe RAM) đang hỏng.", summarizeMsgs(memUC)),
			Action: model.T("Back up important data. Find the DIMM: load the EDAC driver or read the BMC event log, which names the slot. Replace that DIMM as soon as possible.",
				"Sao lưu dữ liệu quan trọng. Xác định thanh RAM: nạp driver EDAC hoặc xem log sự kiện BMC (có ghi tên khe). Thay thanh RAM đó sớm nhất có thể."),
			Evidence: mceEvidence(memUC),
		})
	}
	if !memByEDAC && len(memCE) > 0 {
		c.add(model.Finding{
			ID: "cpu.mce_memory_corrected", Component: model.CompMemory, Severity: model.Info, Target: mceTarget(memCE),
			Title: model.Tf("%d corrected memory error(s) reported by the memory controller", "%d lỗi RAM đã được ECC sửa (do bộ điều khiển bộ nhớ báo)", len(memCE)),
			Detail: model.T("ECC corrected these errors, so nothing was lost. The memory section shows per-DIMM counters when the EDAC driver is loaded.",
				"ECC đã sửa các lỗi này nên không mất dữ liệu. Phần RAM có số lỗi theo từng thanh nếu driver EDAC được nạp."),
			Evidence: mceEvidence(memCE),
		})
	}
	if len(old) > 0 {
		var last time.Time
		for _, m := range old {
			if m.Time.After(last) {
				last = m.Time
			}
		}
		c.add(model.Finding{
			ID: "cpu.mce_history", Severity: model.Info,
			Title: model.Tf("%d older machine-check record(s) (more than %d days ago)", "%d bản ghi machine-check cũ (hơn %d ngày trước)", len(old), HWWindowDays),
			Detail: model.Tf("The most recent was on %s. Old events may predate a repair; they matter if the same CPU/bank keeps showing up.",
				"Lần gần nhất vào %s. Lỗi cũ có thể xảy ra trước khi đã sửa chữa; chỉ đáng lo nếu cùng CPU/bank tiếp tục xuất hiện.", last.UTC().Format("2006-01-02")),
			Evidence: mceEvidence(old),
		})
	}
	total := len(cpuUC) + len(cpuDef) + len(cpuCE) + len(cpuUnk)
	memLeft := len(memUC) + len(memCE)
	if !memByEDAC {
		total += memLeft
	}
	switch {
	case total > 0 || sumOnly || len(old) > 0:
	case memLeft > 0:
		c.add(okFinding("cpu.mce_ok",
			fmt.Sprintf("No processor machine-check errors (%s); memory-controller events are reported in the memory section", src),
			fmt.Sprintf("Không có lỗi machine-check của CPU (%s); lỗi từ bộ điều khiển bộ nhớ được báo ở phần RAM", src)))
	default:
		c.add(okFinding("cpu.mce_ok",
			fmt.Sprintf("No machine-check errors recorded (%s)", src),
			fmt.Sprintf("Không có lỗi machine-check nào được ghi nhận (%s)", src)))
	}
}

// summaryMCE handles "MCE records summary" counts (no dates, no per-record
// status): rasdaemon was readable only through --summary.
func (c *linuxCheck) summaryMCE(sum ras.Report, memByEDAC bool) {
	var uc, ce []string
	nuc, nce := 0, 0
	for _, m := range sum.MCECounts {
		if ras.SummaryMemory(m.Msg) && memByEDAC {
			continue
		}
		switch ras.SummaryClass(m.Msg) {
		case ras.Uncorrected, ras.Fatal, ras.Deferred:
			uc, nuc = append(uc, m.Raw), nuc+m.Count
		case ras.Thermal:
		default:
			ce, nce = append(ce, m.Raw), nce+m.Count
		}
	}
	if nuc > 0 {
		// Summary counts cover the whole rasdaemon history without dates:
		// Warn, not Crit (they may be years old).
		c.add(model.Finding{
			ID: "cpu.mce_uncorrected", Severity: model.Warn,
			Title: model.Tf("rasdaemon has recorded %d uncorrected machine-check error(s)", "rasdaemon đã ghi %d lỗi machine-check không sửa được", nuc),
			Detail: model.T("These are hardware events, not software errors. The summary has no dates, so they may be old; the detailed list was not available.",
				"Đây là sự kiện phần cứng, không phải lỗi phần mềm. Bản tóm tắt không có ngày giờ nên có thể là lỗi cũ; không lấy được danh sách chi tiết."),
			Action: model.T("Run \"ras-mc-ctl --errors\" as root to see when and on which CPU they happened, and check the BMC event log.",
				"Chạy \"ras-mc-ctl --errors\" với quyền root để xem lỗi xảy ra khi nào, trên CPU nào, và kiểm tra log sự kiện BMC."),
			Evidence: units.Evidence(uc, 10),
		})
	}
	if nce > 0 {
		c.add(model.Finding{
			ID: "cpu.mce_corrected", Severity: model.Info,
			Title: model.Tf("rasdaemon has recorded %d corrected or unclassified machine-check event(s)", "rasdaemon đã ghi %d sự kiện machine-check đã sửa hoặc chưa phân loại", nce),
			Detail: model.T("Hardware corrected these events; the summary has no dates. A steady stream from the same CPU/bank predicts an uncorrected error.",
				"Phần cứng đã tự sửa các sự kiện này; bản tóm tắt không có ngày giờ. Lỗi lặp lại đều đặn trên cùng CPU/bank là dấu hiệu sắp có lỗi không sửa được."),
			Evidence: units.Evidence(ce, 10),
		})
	}
}

func (c *linuxCheck) otherRasEvents(rep, sum ras.Report) {
	r := rep
	if len(r.AER) == 0 && len(r.Disk) == 0 && len(r.MemFailure) == 0 {
		r = sum
	}
	n := func(xs []ras.MsgCount) (t int, ev []string) {
		for _, x := range xs {
			t += x.Count
			ev = append(ev, x.Raw)
		}
		return
	}
	aer, ev1 := n(r.AER)
	disk, ev2 := n(r.Disk)
	mf, ev3 := n(r.MemFailure)
	if aer+disk+mf == 0 {
		return
	}
	c.add(model.Finding{
		ID: "cpu.ras_other_events", Component: model.CompSystem, Severity: model.Info,
		Title: model.Tf("rasdaemon also recorded %d PCIe, %d disk and %d memory-failure event(s)", "rasdaemon còn ghi %d sự kiện PCIe, %d sự kiện ổ đĩa và %d sự kiện memory-failure", aer, disk, mf),
		Detail: model.T("PCIe AER errors point to a card, riser or slot; disk errors to a drive or its cable; memory-failure events mean the kernel retired a bad memory page. The disk and log sections check these devices in detail.",
			"Lỗi PCIe AER chỉ ra card, riser hoặc khe cắm; lỗi ổ đĩa chỉ ra ổ hoặc cáp; sự kiện memory-failure nghĩa là kernel đã loại bỏ một trang RAM hỏng. Phần ổ cứng và log kiểm tra chi tiết các thiết bị này."),
		Evidence: units.Evidence(append(append(ev1, ev2...), ev3...), 10),
	})
}

// ---- throttling ----

func (c *linuxCheck) throttle() {
	sec := c.b.Get("cpu.throttle")
	if sec == nil {
		return
	}
	if sec.Skipped != "" || c.env.Container {
		c.cov("cpu.throttle", nameThrottle, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		return
	}
	per := parseThrottle(sec)
	pk := map[int]*Throttle{}
	cpus := make([]int, 0, len(per))
	for id, t := range per {
		if t.HasCoreCount || t.HasPkgCounter {
			cpus = append(cpus, id)
		}
	}
	sort.Ints(cpus)
	for _, id := range cpus {
		t := per[id]
		p := pk[t.Package]
		if p == nil {
			p = &Throttle{Package: t.Package}
			pk[t.Package] = p
		}
		p.CPUs++
		// Package counters are per package but repeated on every CPU of
		// the package: take the maximum, never the sum. Core counters are
		// per logical CPU (SMT siblings count the same event), so report
		// the maximum too.
		p.PackageEvents = max(p.PackageEvents, t.PkgCount)
		p.PackageTimeMS = max(p.PackageTimeMS, t.PkgTimeMS)
		p.CoreEventsMax = max(p.CoreEventsMax, t.CoreCount)
		p.CoreTimeMSMax = max(p.CoreTimeMSMax, t.CoreTimeMS)
		if t.CoreCount > 0 || t.PkgCount > 0 {
			p.CPUsAffected++
		}
	}
	if len(cpus) == 0 {
		switch {
		case len(c.thermal) > 0:
			c.cov("cpu.throttle", nameThrottle, model.CovPartial,
				model.T("No throttle counters in sysfs; using mcelog thermal events.", "Không có bộ đếm throttle trong sysfs; dùng sự kiện nhiệt của mcelog."), model.Text{})
			c.throttleFromMCE()
		case c.virtual:
			c.cov("cpu.throttle", nameThrottle, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		default:
			c.cov("cpu.throttle", nameThrottle, model.CovSkipped,
				model.T("This CPU/kernel exposes no thermal throttle counters (AMD processors do not have them).", "CPU/kernel này không có bộ đếm thermal throttle (CPU AMD không có)."),
				model.T("Check the CPU temperatures in the sensors/BMC section instead.", "Hãy xem nhiệt độ CPU ở phần cảm biến/BMC."))
		}
		return
	}
	c.cov("cpu.throttle", nameThrottle, model.CovRan, model.Text{}, model.Text{})
	ids := make([]int, 0, len(pk))
	for id := range pk {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var hot []*Throttle
	for _, id := range ids {
		c.facts.Throttle = append(c.facts.Throttle, *pk[id])
		if pk[id].PackageEvents > 0 || pk[id].CoreEventsMax > 0 {
			hot = append(hot, pk[id])
		}
	}
	if len(hot) == 0 {
		if len(c.thermal) > 0 {
			c.throttleFromMCE()
			return
		}
		c.add(okFinding("cpu.throttle_ok",
			fmt.Sprintf("No thermal throttling since boot (%d CPUs)", len(cpus)),
			fmt.Sprintf("Không có giảm xung do nhiệt từ lúc khởi động (%d CPU)", len(cpus))))
		return
	}
	t := model.Table{
		ID:    "cpu.throttle",
		Title: model.T("Thermal throttling since boot", "Giảm xung do nhiệt từ lúc khởi động"),
		Columns: []model.Text{
			model.T("Package", "Package"), model.T("Package events", "Số lần (package)"), model.T("Package time", "Thời gian (package)"),
			model.T("Max core events", "Số lần nhiều nhất (nhân)"), model.T("Max core time", "Thời gian nhiều nhất (nhân)"), model.T("CPUs affected", "Số CPU bị ảnh hưởng"),
		},
	}
	var ev []string
	var worstTime, worstCount uint64
	for _, id := range ids {
		p := pk[id]
		st := model.OK
		if p.PackageEvents > 0 || p.CoreEventsMax > 0 {
			st = model.Warn
			ev = append(ev, fmt.Sprintf("%s: package_throttle_count=%d package_throttle_total_time_ms=%d max core_throttle_count=%d max core_throttle_total_time_ms=%d (%d/%d CPUs)",
				pkgName(id), p.PackageEvents, p.PackageTimeMS, p.CoreEventsMax, p.CoreTimeMSMax, p.CPUsAffected, p.CPUs))
		}
		t.Rows = append(t.Rows, model.NewRow(st,
			pkgName(id), units.Count(p.PackageEvents), msText(p.PackageTimeMS), units.Count(p.CoreEventsMax), msText(p.CoreTimeMSMax), fmt.Sprintf("%d/%d", p.CPUsAffected, p.CPUs),
		))
		worstTime = max(worstTime, p.PackageTimeMS, p.CoreTimeMSMax)
		worstCount = max(worstCount, p.PackageEvents, p.CoreEventsMax)
	}
	// Every throttle event means the CPU reached its temperature limit
	// (TCC activation / PROCHOT, Intel SDM vol. 3B "Thermal Monitoring and
	// Protection"). Brief episodes are normal on modern CPUs, which run up
	// to the limit under turbo load and even during boot: the kernel counts
	// them silently and only logs a warning when the temperature keeps
	// rising for several seconds (drivers/thermal/intel/therm_throt.c,
	// throttle_active_work(); commit f6656208f04e "Optimize notifications
	// of thermal throttle", v5.5). So a handful of short events is Info;
	// it is Warn when the CPU throttled often (>= 100 episodes), or spent
	// at least 1 % of the uptime or 10 minutes in total throttled, which
	// no healthy server cooling allows.
	upt := c.uptime
	wt := time.Duration(worstTime) * time.Millisecond
	often := worstCount >= 100 || wt >= 10*time.Minute || (upt > 0 && worstTime > 0 && wt*100 >= upt)
	sev := model.Info
	freqEN, freqVI := "briefly", "trong thời gian ngắn"
	if often {
		sev = model.Warn
		freqEN, freqVI = "often", "thường xuyên"
	}
	for i := range t.Rows {
		if t.Rows[i].Status == model.Warn {
			t.Rows[i].Status = sev
		}
	}
	c.res.Tables = append(c.res.Tables, t)
	sinceEN, sinceVI := "since boot", "từ lúc khởi động"
	if upt > 0 {
		d := units.Duration(upt)
		sinceEN, sinceVI = "since boot ("+d.EN+" ago)", "từ lúc khởi động ("+d.VI+" trước)"
	}
	timeEN, timeVI := "", ""
	if worstTime > 0 {
		timeEN, timeVI = ", for up to "+msText(worstTime).EN+" in total", ", tổng thời gian giảm xung tới "+msText(worstTime).VI
	}
	tgt := pkgName(hot[0].Package)
	if len(hot) > 1 {
		tgt = fmt.Sprintf("%d packages", len(hot))
	}
	n := units.Thousands(worstCount)
	nVI := units.ThousandsVI(worstCount)
	f := model.Finding{
		ID: "cpu.throttle", Severity: sev, Target: tgt,
		Title: model.Text{
			EN: fmt.Sprintf("CPU throttled %s because of heat: %s events %s", freqEN, n, sinceEN),
			VI: fmt.Sprintf("CPU giảm xung %s vì quá nhiệt: %s lần %s", freqVI, nVI, sinceVI),
		},
		Evidence: units.Evidence(ev, 10),
	}
	if often {
		f.Detail = model.Text{
			EN: fmt.Sprintf("The CPU reached its temperature limit and slowed itself down %s%s. The server is slower while this happens, and it means the cooling has no margin left: failed or slow fans, dust in the heatsinks or filters, dried thermal paste, blocked airflow or a hot server room.", sinceEN, timeEN),
			VI: fmt.Sprintf("CPU chạm ngưỡng nhiệt tối đa và tự giảm xung %s%s. Máy chạy chậm hơn trong lúc đó, và hệ thống làm mát không còn dư địa: quạt hỏng hoặc quay chậm, bụi bám tản nhiệt/lưới lọc, keo tản nhiệt khô, luồng gió bị chặn hoặc phòng máy quá nóng.", sinceVI, timeVI),
		}
		f.Action = model.T("Check fan status and CPU temperatures in the BMC (iDRAC/iLO/IPMI) and the sensors section. Clean dust from heatsinks and filters, make sure blanking panels and the air shroud are in place and nothing blocks the front or back of the rack, and check the room temperature. If one CPU is much hotter than the other, reseat its heatsink with new thermal paste.",
			"Kiểm tra trạng thái quạt và nhiệt độ CPU trên BMC (iDRAC/iLO/IPMI) và phần cảm biến. Vệ sinh bụi ở tản nhiệt và lưới lọc, đảm bảo có đủ tấm che (blanking panel), ốp gió (air shroud) và mặt trước/sau rack không bị chặn, kiểm tra nhiệt độ phòng máy. Nếu một CPU nóng hơn hẳn CPU còn lại, tháo tản nhiệt và tra lại keo tản nhiệt.")
	} else {
		f.Detail = model.Text{
			EN: fmt.Sprintf("The CPU touched its temperature limit a few times %s%s. Short episodes like this happen on healthy servers under turbo load or at boot, and the kernel does not even log them; they only matter if the count keeps growing.", sinceEN, timeEN),
			VI: fmt.Sprintf("CPU chạm ngưỡng nhiệt vài lần %s%s. Giảm xung ngắn như vậy vẫn xảy ra trên máy khỏe khi chạy turbo tải cao hoặc lúc khởi động, kernel cũng không ghi log; chỉ đáng lo nếu số lần tiếp tục tăng.", sinceVI, timeVI),
		}
		f.Action = model.T("No action now. If the count grows quickly, check the fans, CPU temperatures and airflow in the BMC and the sensors section.",
			"Chưa cần làm gì. Nếu số lần tăng nhanh, kiểm tra quạt, nhiệt độ CPU và luồng gió trên BMC và ở phần cảm biến.")
	}
	c.add(f)
}

// throttleFromMCE reports thermal-event records (Intel thermal interrupts
// decoded by mcelog) when sysfs counters are absent or zero.
func (c *linuxCheck) throttleFromMCE() {
	var ev []string
	for _, m := range c.thermal {
		ev = append(ev, m.Raw)
	}
	// mcelog logs a thermal event only when the kernel's thermal interrupt
	// fires, at most once per CPU every few minutes; like the sysfs counters
	// a few are normal (see throttle()), ten or more in the window are not.
	sev := model.Info
	if len(c.thermal) >= 10 {
		sev = model.Warn
	}
	c.add(model.Finding{
		ID: "cpu.throttle", Severity: sev, Target: mceTarget(c.thermal),
		Title: model.Tf("CPU throttled because of heat: %d thermal events logged", "CPU giảm xung vì quá nhiệt: ghi nhận %d sự kiện nhiệt", len(c.thermal)),
		Detail: model.T("mcelog recorded that a CPU heated above its trip temperature and throttled. The server slows down while this happens; the cooling is not keeping up.",
			"mcelog ghi nhận CPU vượt ngưỡng nhiệt và tự giảm xung. Máy chạy chậm trong lúc đó; hệ thống làm mát không đáp ứng kịp."),
		Action: model.T("Check fans and CPU temperatures in the BMC, clean dust from heatsinks and filters, check airflow and room temperature, and renew the thermal paste of the hot CPU.",
			"Kiểm tra quạt và nhiệt độ CPU trên BMC, vệ sinh bụi tản nhiệt và lưới lọc, kiểm tra luồng gió và nhiệt độ phòng, tra lại keo tản nhiệt cho CPU bị nóng."),
		Evidence: units.Evidence(ev, 10),
	})
}

// ---- helpers ----

func okFinding(id, en, vi string) model.Finding {
	return model.Finding{ID: id, Component: model.CompCPU, Severity: model.OK, Title: model.T(en, vi)}
}

func (c *linuxCheck) loggerStopped() model.Finding {
	st := firstNonEmpty(c.facts.Rasdaemon, "not running")
	return model.Finding{
		ID: "cpu.mce_logger_stopped", Severity: model.Info, Target: "rasdaemon",
		Title: model.T("rasdaemon is installed but not running", "rasdaemon đã cài nhưng không chạy"),
		Detail: model.Tf("Service state: %s. While it is stopped, new CPU/memory/PCIe hardware errors are not recorded.",
			"Trạng thái dịch vụ: %s. Khi dịch vụ dừng, lỗi phần cứng CPU/RAM/PCIe mới sẽ không được ghi lại.", st),
		Action: model.T("Start it and enable it at boot: systemctl enable --now rasdaemon", "Bật dịch vụ và cho chạy cùng hệ thống: systemctl enable --now rasdaemon"),
	}
}

// rasNoDB reports ras-mc-ctl output that means rasdaemon's SQLite database
// does not exist or is empty (rasdaemon never ran with --record): the
// collector found no database file, or ras-mc-ctl (rasdaemon 0.6-0.8)
// printed "no such table: mc_event" / "mc_event table missing" / "unable to
// open database file".
func rasNoDB(secs ...*collect.Section) bool {
	for _, s := range secs {
		if s == nil {
			continue
		}
		if strings.HasSuffix(s.Missing, "ras-mc_event.db") {
			return true
		}
		e := s.Err
		if strings.Contains(e, "no such table: mc_event") || strings.Contains(e, "mc_event table missing") || strings.Contains(e, "unable to open database file") {
			return true
		}
	}
	return false
}

// enableCmd is the command for coverage: install rasdaemon (when needed)
// and start it.
func (c *linuxCheck) enableCmd(rasInstalled bool) string {
	if rasInstalled {
		return enableCmd(c.env)
	}
	_, in := hint.InstallFix(c.env, "ras-mc-ctl")
	if in == "" {
		return ""
	}
	return in + " && " + enableCmd(c.env)
}

func installAndEnable(env model.Env) model.Text {
	in := hint.Install(env, "ras-mc-ctl")
	return model.Text{
		EN: in.EN + " Then enable it: systemctl enable --now rasdaemon",
		VI: in.VI + " Sau đó bật dịch vụ: systemctl enable --now rasdaemon",
	}
}

// enableFix is the coverage Fix text; the command itself goes in
// Coverage.Cmd (see enableCmd).
func enableFix(env model.Env, rasInstalled bool) model.Text {
	if rasInstalled {
		return model.T("Start rasdaemon and enable it at boot.", "Bật rasdaemon và cho chạy cùng hệ thống.")
	}
	fix, _ := hint.InstallFix(env, "ras-mc-ctl")
	return model.Text{
		EN: fix.EN + " Then start it and enable it at boot.",
		VI: fix.VI + " Sau đó bật dịch vụ và cho chạy cùng hệ thống.",
	}
}

func svcState(kv map[string]string, name string) string {
	switch kv[name+".installed"] {
	case "1":
	case "0":
		return "not installed"
	default:
		return ""
	}
	a, e := kv[name+".active"], kv[name+".enabled"]
	if a == "unknown" {
		a = ""
	}
	if e == "unknown" {
		e = ""
	}
	if a == "" && kv[name+".running"] == "1" {
		a = "running"
	}
	return strings.TrimSpace(a + " " + e)
}

func allSkipped(reason string, secs ...*collect.Section) bool {
	n := 0
	for _, s := range secs {
		if s == nil {
			continue
		}
		n++
		if s.Skipped != reason {
			return false
		}
	}
	return n > 0
}

func firstErr(b *collect.Bundle, names ...string) string {
	for _, n := range names {
		if s := b.Get(n); s != nil && s.Err != "" {
			return oneLine(s.Err)
		}
	}
	return ""
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func first(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func itoa(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func firstPos(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}

func speeds(cur, maxv int) string {
	switch {
	case cur > 0 && maxv > 0:
		return fmt.Sprintf("%d/%d", cur, maxv)
	case cur > 0:
		return strconv.Itoa(cur)
	case maxv > 0:
		return "-/" + strconv.Itoa(maxv)
	}
	return ""
}

func pkgName(id int) string {
	if id < 0 {
		return "CPU"
	}
	return fmt.Sprintf("package %d", id)
}

func msText(ms uint64) model.Text {
	if ms == 0 {
		return model.Text{}
	}
	d := time.Duration(ms) * time.Millisecond
	if d < time.Minute {
		s := fmt.Sprintf("%.1f", d.Seconds())
		return model.T(s+" s", strings.Replace(s, ".", ",", 1)+" giây")
	}
	return model.Tf("%.0f min", "%.0f phút", d.Minutes())
}

// cpuWords is Vietnamese for processor states: dmidecode "Status" ("Populated,
// Enabled", SMBIOS type 4 CPU Status) and Win32_Processor CpuStatus / Status.
var cpuWords = map[string]string{
	"populated":                           "có lắp",
	"unpopulated":                         "trống",
	"disabled by user":                    "bị tắt trong BIOS setup",
	"disabled by bios":                    "bị BIOS tắt (lỗi POST)",
	"cpu enabled":                         "đang bật",
	"cpu disabled by user via bios setup": "bị tắt trong BIOS setup",
	"cpu disabled by bios (post error)":   "bị BIOS tắt (lỗi POST)",
	"cpu is idle":                         "rảnh",
	"pred fail":                           "sắp hỏng",
	"nonrecover":                          "lỗi không phục hồi",
	"no contact":                          "mất liên lạc",
	"lost comm":                           "mất liên lạc",
	"stressed":                            "quá tải",
	"starting":                            "đang khởi động",
	"stopping":                            "đang dừng",
	"service":                             "đang bảo trì",
}

// statusCell is a processor status for the table, in both languages.
func statusCell(s string) model.Text { return units.Words(s, cpuWords) }

// mceTarget names the CPUs/sockets involved: "socket 1", "CPU 12",
// "sockets 0,1".
func mceTarget(ms []ras.MCE) string {
	sockets := map[int]bool{}
	cpus := map[int]bool{}
	for _, m := range ms {
		if m.Socket >= 0 {
			sockets[m.Socket] = true
		}
		if m.CPU >= 0 {
			cpus[m.CPU] = true
		}
	}
	join := func(m map[int]bool) string {
		xs := make([]int, 0, len(m))
		for k := range m {
			xs = append(xs, k)
		}
		sort.Ints(xs)
		s := make([]string, 0, len(xs))
		for _, x := range xs {
			s = append(s, strconv.Itoa(x))
		}
		return strings.Join(s, ",")
	}
	switch {
	case len(sockets) == 1:
		return "socket " + join(sockets)
	case len(sockets) > 1:
		return "sockets " + join(sockets)
	case len(cpus) == 1:
		return "CPU " + join(cpus)
	case len(cpus) > 1 && len(cpus) <= 8:
		return "CPUs " + join(cpus)
	}
	return "CPU"
}

func mceEvidence(ms []ras.MCE) []string {
	ev := make([]string, 0, len(ms))
	for i := len(ms) - 1; i >= 0; i-- { // newest first
		m := ms[i]
		ts := "time unknown"
		if !m.Time.IsZero() {
			ts = m.Time.UTC().Format("2006-01-02 15:04Z")
		}
		where := ""
		if m.CPU >= 0 {
			where += fmt.Sprintf(" CPU %d", m.CPU)
		}
		if m.Bank != "" {
			where += " bank " + m.Bank
		}
		if m.Socket >= 0 {
			where += fmt.Sprintf(" socket %d", m.Socket)
		}
		ev = append(ev, fmt.Sprintf("%s [%s]%s %s: %s", ts, m.Source, where, m.Kind, m.Msg))
	}
	return units.Evidence(ev, 10)
}

func summarizeMsgs(ms []ras.MCE) string {
	cnt := map[string]int{}
	var order []string
	for _, m := range ms {
		k := m.Msg
		if k == "" {
			k = "bank " + m.Bank
		}
		if cnt[k] == 0 {
			order = append(order, k)
		}
		cnt[k]++
	}
	sort.SliceStable(order, func(i, j int) bool { return cnt[order[i]] > cnt[order[j]] })
	var out []string
	for i, k := range order {
		if i == 3 {
			out = append(out, fmt.Sprintf("+%d more", len(order)-3))
			break
		}
		out = append(out, fmt.Sprintf("%d× %s", cnt[k], k))
	}
	return strings.Join(out, "; ")
}
