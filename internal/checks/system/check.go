// Package system is the "system" domain: what the machine is (vendor,
// model, service tag, BIOS, CPU, RAM), how loaded it is (load average,
// pressure stall information, iowait, steal), kernel taint flags that hint
// at hardware trouble, clock synchronisation and pending reboots.
package system

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "system"

// Facts is the typed data of the system domain.
type Facts struct {
	Identity       Identity `json:"identity"`
	Load           *Load    `json:"load,omitempty"`
	Taint          uint64   `json:"taint,omitempty"`
	ClockSynced    *bool    `json:"clockSynced,omitempty"`
	RebootRequired bool     `json:"rebootRequired,omitempty"`
	UptimeSeconds  float64  `json:"uptimeSeconds,omitempty"`
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	switch b.OS {
	case collect.OSLinux:
		if !hasAny(b, "system.") {
			return res
		}
		checkLinux(b, env, &res)
	case collect.OSWindows:
		if !hasAny(b, "system.win_") {
			return res
		}
		checkWindows(b, env, &res)
	}
	return res
}

// HostInfo identifies the machine for the report header.
func HostInfo(b *collect.Bundle, env model.Env) model.HostInfo {
	switch b.OS {
	case collect.OSBMC:
		return bmcHost(b, env)
	case collect.OSWindows:
		return windowsHost(b, env)
	}
	return linuxHost(b, env)
}

func hasAny(b *collect.Bundle, prefix string) bool { return len(b.Prefix(prefix)) > 0 }

func linuxHost(b *collect.Bundle, env model.Env) model.HostInfo {
	id := b.Get("meta.ident").KV()
	h := model.HostInfo{
		Hostname: id["hostname"],
		Kernel:   id["kernel"],
		Arch:     id["arch"],
		Virtual:  env.Virtual,
	}
	osr := collect.ParseOSRelease(b.Get("meta.osrelease").Text())
	h.OS = osr["PRETTY_NAME"]
	if h.OS == "" {
		h.OS = strings.TrimSpace(osr["NAME"] + " " + osr["VERSION"])
	}
	if env.Distro == "proxmox" && !strings.Contains(strings.ToLower(h.OS), "proxmox") {
		h.OS = strings.TrimSpace(h.OS + " (Proxmox VE)")
	}
	ident := linuxIdentity(b)
	h.Vendor, h.Model, h.Serial = ident.Vendor, ident.Model, ident.Serial
	h.BIOS, h.Board, h.CPU, h.MemBytes = ident.biosString(), ident.boardString(), ident.CPU, ident.MemBytes
	h.Uptime = parseUptime(b.Get("system.uptime").Text())
	if h.Uptime == 0 {
		h.Uptime = parseUptime(id["uptime"])
	}
	_, _, btime, _ := parseStat(b.Get("system.stat").Text())
	switch {
	case btime > 0:
		h.BootTime = time.Unix(btime, 0).UTC()
	case h.Uptime > 0 && !env.Now.IsZero():
		h.BootTime = env.Now.Add(-time.Duration(h.Uptime * float64(time.Second))).UTC().Truncate(time.Second)
	}
	return h
}

func windowsHost(b *collect.Bundle, env model.Env) model.HostInfo {
	h := model.HostInfo{Virtual: env.Virtual}
	var mi []struct {
		Hostname, Caption, Version, Build, Arch, LastBoot string
	}
	if collect.DecodeJSON(b.Get("meta.ident").Text(), &mi) == nil && len(mi) > 0 {
		h.Hostname, h.OS, h.Arch = mi[0].Hostname, mi[0].Caption, mi[0].Arch
		h.Kernel = mi[0].Version
		if t, ok := collect.WinTime(mi[0].LastBoot); ok {
			h.BootTime = t
		}
	}
	var wos []struct {
		Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime string
	}
	if collect.DecodeJSON(b.Get("system.win_os").Text(), &wos) == nil && len(wos) > 0 {
		fill(&h.OS, wos[0].Caption)
		fill(&h.Kernel, wos[0].Version)
		if wos[0].OSArchitecture != "" {
			h.Arch = wos[0].OSArchitecture
		}
		if t, ok := collect.WinTime(wos[0].LastBootUpTime); ok {
			h.BootTime = t
		}
	}
	ident := windowsIdentity(b)
	h.Vendor, h.Model, h.Serial = ident.Vendor, ident.Model, ident.Serial
	h.BIOS, h.Board, h.CPU, h.MemBytes = ident.biosString(), ident.boardString(), ident.CPU, ident.MemBytes
	if !h.BootTime.IsZero() && !env.Now.IsZero() && env.Now.After(h.BootTime) {
		h.Uptime = math.Round(env.Now.Sub(h.BootTime).Seconds())
	}
	return h
}

// ---- Linux ----

func checkLinux(b *collect.Bundle, env model.Env, res *model.Result) {
	ident := linuxIdentity(b)
	facts := &Facts{Identity: ident}
	res.Facts = facts
	identityCoverage(b, env, ident, res)
	identityTable(ident, linuxHost(b, env), res)
	if env.Bare() {
		biosAge(ident, env, res)
	}

	facts.UptimeSeconds = parseUptime(b.Get("system.uptime").Text())
	load, loadOK := linuxLoad(b, ident)
	if loadOK {
		facts.Load = load
	}
	loadCoverage(b, env, loadOK, res)
	warned := false
	if loadOK {
		warned = loadFindings(load, env, res)
		loadTable(load, res)
	}
	if t, ok := parseTaint(b.Get("system.tainted").Text()); ok {
		facts.Taint = t
		if taintFindings(t, res) {
			warned = true
		}
	}
	if loadOK && !warned {
		okLoad(load, res)
	}
	synced, known, line := clockSynced(b.Get("system.timedatectl").Text(), b.Get("system.chrony").Text())
	if ts := b.Get("system.timesync").KV(); !known && ts["timesyncd_active"] == "yes" {
		// Only meaningful while timesyncd runs; a missing file then means
		// it has not synchronised yet.
		synced, known, line = ts["synchronized"] == "yes", true, "systemd-timesyncd synchronized="+ts["synchronized"]
	}
	if known {
		facts.ClockSynced = &synced
		if !synced {
			res.Findings = append(res.Findings, model.Finding{
				ID: "system.clock_unsynced", Component: model.CompSystem, Severity: model.Info,
				Title:    model.T("System clock is not synchronised (NTP)", "Đồng hồ hệ thống chưa đồng bộ (NTP)"),
				Detail:   model.T("Timestamps in logs may be wrong, which makes it hard to match events (RAID, disk, BMC) and can break TLS or Kerberos.", "Thời gian trong log có thể sai, khó đối chiếu sự kiện (RAID, ổ cứng, BMC) và có thể làm lỗi TLS hoặc Kerberos."),
				Action:   model.T("Enable time sync: systemctl enable --now chronyd (RHEL) or systemd-timesyncd/chrony (Debian/Ubuntu), then check with timedatectl.", "Bật đồng bộ thời gian: systemctl enable --now chronyd (RHEL) hoặc systemd-timesyncd/chrony (Debian/Ubuntu), rồi kiểm tra bằng timedatectl."),
				Evidence: []string{line},
			})
		}
	}
	rebootLinux(b, facts, res)
}

func identityCoverage(b *collect.Bundle, env model.Env, id Identity, res *model.Result) {
	c := model.Coverage{ID: "system.identity", Component: model.CompSystem,
		Name: model.T("Server identity (vendor, model, service tag, BIOS)", "Thông tin máy chủ (hãng, model, serial/service tag, BIOS)")}
	dmi := b.Get("system.dmidecode")
	switch {
	case id.Source == "dmidecode" || id.Source == "cim":
		c.State = model.CovRan
	case env.Container:
		c.State, c.Reason = model.CovSkipped, hint.Virtual(env)
	case id.Source != "":
		c.State = model.CovPartial
		switch {
		case dmi != nil && dmi.Skipped == "not-root":
			c.Reason = model.T("The serial number (service tag) needs root to read.", "Cần quyền root mới đọc được số serial (service tag).")
			c.Fix = hint.RunAsRoot(env)
		case dmi != nil && dmi.Missing != "":
			c.Reason = model.T("dmidecode is not installed: the serial number (service tag) and chassis details come from SMBIOS.",
				"Chưa cài dmidecode: số serial (service tag) và thông tin chassis lấy từ SMBIOS.")
			c.Fix, c.Cmd = hint.InstallFix(env, "dmidecode")
		default:
			c.Reason = model.T("dmidecode returned no SMBIOS data; identity comes from sysfs only.", "dmidecode không trả về dữ liệu SMBIOS; thông tin chỉ lấy từ sysfs.")
		}
	case dmi != nil && dmi.Missing != "":
		c.State, c.Reason = model.CovSkipped, hint.Missing("dmidecode")
		c.Fix, c.Cmd = hint.InstallFix(env, "dmidecode")
	case dmi != nil && dmi.Skipped == "not-root":
		c.State, c.Reason, c.Fix = model.CovSkipped, hint.NeedRoot(env), hint.RunAsRoot(env)
	case !env.Bare():
		c.State, c.Reason = model.CovSkipped, hint.Virtual(env)
	default:
		c.State = model.CovFailed
		c.Reason = model.T("No SMBIOS/DMI data found on this machine.", "Không tìm thấy dữ liệu SMBIOS/DMI trên máy này.")
		if dmi != nil && strings.TrimSpace(dmi.Err) != "" {
			c.Reason = model.Tf("No SMBIOS/DMI data found: %s", "Không tìm thấy dữ liệu SMBIOS/DMI: %s", firstLine(dmi.Err))
		}
	}
	res.Coverage = append(res.Coverage, c)
}

func identityTable(id Identity, h model.HostInfo, res *model.Result) {
	if id.Source == "" && id.CPU == "" && id.MemBytes == 0 {
		return
	}
	mem, up := "", ""
	if id.MemBytes > 0 {
		mem = units.IEC(id.MemBytes)
	}
	if h.Uptime > 0 {
		up = shortDuration(h.Uptime)
	}
	res.Tables = append(res.Tables, model.Table{
		ID:    "system.identity",
		Title: model.T("Server", "Máy chủ"),
		Columns: []model.Text{
			model.T("Vendor", "Hãng"), model.T("Model", "Model"), model.T("Serial / service tag", "Serial / service tag"),
			model.T("BIOS", "BIOS"), model.T("Mainboard", "Bo mạch chủ"), model.T("CPU", "CPU"),
			model.T("RAM", "RAM"), model.T("Uptime", "Thời gian chạy"),
		},
		Rows: []model.Row{{Cells: []string{id.Vendor, id.Model, id.Serial, id.biosString(), id.boardString(), id.CPU, mem, up}}},
	})
}

// biosAge reports firmware older than five years. Vendors fix hardware
// bugs (memory training, CPU microcode, RAID/NIC option ROMs, BMC
// interaction) in BIOS updates; a five-year-old BIOS has usually missed
// several such fixes and microcode security updates. Only on bare metal:
// virtual BIOS dates (SeaBIOS "04/01/2014") mean nothing.
func biosAge(id Identity, env model.Env, res *model.Result) {
	if id.biosTime.IsZero() || env.Now.IsZero() {
		return
	}
	age := env.Now.Sub(id.biosTime)
	if age < 5*365*24*time.Hour {
		return
	}
	d := units.Duration(age)
	res.Findings = append(res.Findings, model.Finding{
		ID: "system.bios_old", Component: model.CompSystem, Severity: model.Info, Target: "BIOS",
		Title: model.Tf("BIOS %s is %s old (released %s)", "BIOS %s đã cũ %s (phát hành %s)", id.BIOSVersion, d.EN, id.BIOSDate),
		Detail: model.Tf("%s publishes BIOS/firmware updates that fix hardware stability problems (memory, CPU microcode, RAID and NIC firmware interaction).",
			"%s thường phát hành bản cập nhật BIOS/firmware sửa lỗi ổn định phần cứng (RAM, microcode CPU, tương thích firmware RAID/NIC).", vendorOr(id.Vendor)),
		Action: model.Tf("Check the vendor support site for a newer BIOS for %s and plan the update in a maintenance window (update the BMC first if the vendor says so).",
			"Kiểm tra trang hỗ trợ của hãng xem có BIOS mới cho %s không và lên lịch cập nhật trong giờ bảo trì (cập nhật BMC trước nếu hãng yêu cầu).", modelOr(id.Model)),
		Evidence: []string{fmt.Sprintf("BIOS %s %s, release date %s", id.BIOSVendor, id.BIOSVersion, id.BIOSDate)},
	})
	// The Vietnamese title must use Vietnamese duration words.
	f := &res.Findings[len(res.Findings)-1]
	f.Title.VI = fmt.Sprintf("BIOS %s đã cũ %s (phát hành %s)", id.BIOSVersion, d.VI, id.BIOSDate)
}

func vendorOr(v string) string {
	if v == "" {
		return "The vendor"
	}
	return v
}

func modelOr(m string) string {
	if m == "" {
		return "this server"
	}
	return m
}

func linuxLoad(b *collect.Bundle, id Identity) (*Load, bool) {
	l1, l5, l15, ok := parseLoadavg(b.Get("system.loadavg").Text())
	if !ok {
		return nil, false
	}
	// The load average counts tasks on every online CPU, so compare it with
	// the processors listed in /proc/cpuinfo (id.Threads; nproc only when
	// cpuinfo has no count). nproc honours the collector's CPU affinity: in
	// a container started with --cpuset-cpus=0-1 on a 64-core host (or on a
	// host booted with isolcpus) it would make a normal load look like a
	// 30x overload.
	ld := &Load{Load1: l1, Load5: l5, Load15: l15, CPUs: id.Threads}
	ld.IOWaitPct, ld.StealPct, _, ld.ProcsBlocked = parseStat(b.Get("system.stat").Text())
	ld.PSI = parsePSI(b.Get("system.pressure").Text())
	return ld, true
}

func loadCoverage(b *collect.Bundle, env model.Env, ok bool, res *model.Result) {
	c := model.Coverage{ID: "system.load", Component: model.CompSystem,
		Name: model.T("System load and resource pressure", "Tải hệ thống và áp lực tài nguyên")}
	switch {
	case !ok:
		s := b.Get("system.loadavg")
		if b.OS == collect.OSWindows {
			s = b.Get("system.win_perf")
		}
		c.State = model.CovFailed
		c.Reason = model.T("Load data could not be read.", "Không đọc được dữ liệu tải.")
		if s != nil && strings.TrimSpace(s.Err) != "" {
			c.Reason = model.Tf("Load data could not be read: %s", "Không đọc được dữ liệu tải: %s", firstLine(s.Err))
		}
	case b.OS == collect.OSLinux && !b.Get("system.stat").OK():
		c.State = model.CovPartial
		c.Reason = model.T("The CPU time sample (/proc/stat) was not available, so iowait and steal were not measured.", "Không lấy được mẫu thời gian CPU (/proc/stat) nên chưa đo được iowait và steal.")
	default:
		c.State = model.CovRan
	}
	res.Coverage = append(res.Coverage, c)
}

// Thresholds for the load findings. None of them is certain evidence of a
// fault, so they raise Warn at most.
const (
	// Linux load average counts runnable tasks plus tasks in uninterruptible
	// (D state, usually disk/NFS) sleep (Brendan Gregg, "Linux Load
	// Averages: Solving the Mystery", 2017). Above the CPU count work is
	// queueing; 1.5x over both the 5- and 15-minute averages means the
	// overload has lasted, not a short burst (cron, backup start).
	loadPerCPUWarn = 1.5
	// PSI "some" = share of wall time in which at least one task waited for
	// the resource; "full" = all non-idle tasks waited at once
	// (Documentation/accounting/psi.rst). Tasks waiting for a CPU half of the
	// last 5 minutes means the CPUs cannot keep up.
	psiCPUSomeWarn = 50.0
	// The whole machine stalled on memory reclaim/swap 5 % of the last 5
	// minutes (or some task 20 %) is thrashing that users notice.
	psiMemFullWarn = 5.0
	psiMemSomeWarn = 20.0
	// All tasks stalled on I/O 20 % of the last 5 minutes: storage is the
	// bottleneck.
	psiIOFullWarn = 20.0
	psiIOSomeCorr = 20.0
	// %iowait above ~20 % is the usual sysstat/sar rule of thumb for an I/O
	// bound system. A 1-second sample is noisy, so it only counts when PSI
	// agrees or PSI is not available.
	iowaitWarn = 20.0
	// Steal time above 10 % is the threshold cloud/hypervisor guidance
	// commonly uses for a VM that is not getting the CPU it was sold (the
	// host is overcommitted or a noisy neighbour is busy).
	stealWarn = 10.0
	// Windows: a processor queue of more than 2 threads per CPU, sustained,
	// indicates processor congestion (Microsoft performance counter
	// guidance for System\Processor Queue Length), together with a CPU busier
	// than 85 %.
	winQueuePerCPUWarn = 2.0
	winCPUWarn         = 85.0
	// Disk "% Idle Time" under 10 % with an average queue of 2+ requests:
	// the disks are busy all the time and requests wait.
	winDiskIdleWarn  = 10.0
	winDiskQueueWarn = 2.0
)

func psiGet(ld *Load, key string) (PSI, bool) {
	if ld == nil || ld.PSI == nil {
		return PSI{}, false
	}
	p, ok := ld.PSI[key]
	return p, ok
}

// loadFindings adds the overload / memory / I/O / steal findings and
// reports whether any was added.
func loadFindings(ld *Load, env model.Env, res *model.Result) bool {
	added := false
	cpus := ld.CPUs
	var ev []string
	ev = append(ev, fmt.Sprintf("load average: %.2f %.2f %.2f (%d CPUs)", ld.Load1, ld.Load5, ld.Load15, cpus))
	for _, k := range []string{"cpu some", "memory some", "memory full", "io some", "io full"} {
		if p, ok := psiGet(ld, k); ok {
			ev = append(ev, fmt.Sprintf("psi %s avg10=%.2f avg60=%.2f avg300=%.2f", k, p.Avg10, p.Avg60, p.Avg300))
		}
	}
	if ld.IOWaitPct != nil {
		ev = append(ev, fmt.Sprintf("iowait %.1f%%, steal %.1f%% (1 s sample), blocked tasks %d", *ld.IOWaitPct, deref(ld.StealPct), ld.ProcsBlocked))
	}

	// CPU overload
	overLoad := cpus > 0 && ld.Load5 >= loadPerCPUWarn*float64(cpus) && ld.Load15 >= loadPerCPUWarn*float64(cpus)
	cpuPSI, hasCPUPSI := psiGet(ld, "cpu some")
	overPSI := hasCPUPSI && cpuPSI.Avg300 >= psiCPUSomeWarn
	if overLoad || overPSI {
		added = true
		res.Findings = append(res.Findings, model.Finding{
			ID: "system.overloaded", Component: model.CompSystem, Severity: model.Warn,
			Title: model.Tf("Server is overloaded: load %.1f on %d CPUs", "Máy chủ đang quá tải: load %.1f trên %d CPU", ld.Load15, cpus),
			Detail: model.Tf("The 15-minute load average is %.1f for %d CPUs (%.1f per CPU)%s. Tasks are waiting for CPU time, so the server responds slowly. Load also counts tasks stuck waiting for disk or NFS, so check the I/O findings too.",
				"Load trung bình 15 phút là %.1f cho %d CPU (%.1f mỗi CPU)%s. Các tiến trình phải chờ CPU nên máy phản hồi chậm. Load cũng tính cả tiến trình đang chờ ổ cứng hoặc NFS, nên xem thêm mục I/O.",
				ld.Load15, cpus, ld.Load15/float64(max(cpus, 1)), psiNote(cpuPSI, hasCPUPSI, "CPU")),
			Action: model.T("Find what uses the CPU (top, ps aux --sort=-%cpu | head). Stop runaway jobs, move batch work off peak hours, or add CPU/RAM. If the load is mostly tasks in D state (ps -eo state,cmd | grep '^D'), look at the disks instead.",
				"Tìm tiến trình chiếm CPU (top, ps aux --sort=-%cpu | head). Dừng tiến trình bất thường, dời tác vụ nặng ra ngoài giờ cao điểm, hoặc nâng cấp CPU/RAM. Nếu phần lớn là tiến trình trạng thái D (ps -eo state,cmd | grep '^D') thì hãy kiểm tra ổ cứng."),
			Evidence: units.Evidence(ev, 10),
		})
	}

	// Memory pressure
	mFull, hasMF := psiGet(ld, "memory full")
	mSome, hasMS := psiGet(ld, "memory some")
	if (hasMF && mFull.Avg300 >= psiMemFullWarn) || (hasMS && mSome.Avg300 >= psiMemSomeWarn) {
		added = true
		res.Findings = append(res.Findings, model.Finding{
			ID: "system.memory_pressure", Component: model.CompSystem, Severity: model.Warn,
			Title: model.Tf("Memory pressure: tasks stalled on memory %.0f%% of the last 5 minutes", "Thiếu RAM: tiến trình bị treo chờ bộ nhớ %.0f%% thời gian trong 5 phút qua", math.Max(mSome.Avg300, mFull.Avg300)),
			Detail: model.Tf("Pressure stall information: memory some avg300=%.1f%%, full avg300=%.1f%%. The kernel spends time reclaiming memory or swapping, which makes everything slow.",
				"Chỉ số PSI: memory some avg300=%.1f%%, full avg300=%.1f%%. Kernel phải liên tục thu hồi bộ nhớ hoặc swap nên mọi thứ chạy chậm.", mSome.Avg300, mFull.Avg300),
			Action: model.T("Check memory use (free -h, ps aux --sort=-%mem | head) and swap activity (vmstat 1). Reduce the workload or add RAM; check the memory section for failed or missing DIMMs.",
				"Kiểm tra mức dùng RAM (free -h, ps aux --sort=-%mem | head) và swap (vmstat 1). Giảm tải hoặc nâng thêm RAM; xem mục Bộ nhớ để chắc không có thanh RAM bị lỗi hoặc không nhận."),
			Evidence: units.Evidence(ev, 10),
		})
	}

	// Storage bottleneck
	ioFull, hasIOF := psiGet(ld, "io full")
	ioSome, hasIOS := psiGet(ld, "io some")
	ioPSIBad := hasIOF && ioFull.Avg300 >= psiIOFullWarn
	ioWaitBad := ld.IOWaitPct != nil && *ld.IOWaitPct >= iowaitWarn && (!hasIOS || ioSome.Avg60 >= psiIOSomeCorr)
	if ioPSIBad || ioWaitBad {
		added = true
		iow := deref(ld.IOWaitPct)
		res.Findings = append(res.Findings, model.Finding{
			ID: "system.io_bottleneck", Component: model.CompSystem, Severity: model.Warn,
			Title: model.Tf("Storage is the bottleneck: CPUs wait for disk (iowait %.0f%%)", "Ổ cứng đang là điểm nghẽn: CPU phải chờ đọc/ghi đĩa (iowait %.0f%%)", iow),
			Detail: model.Tf("iowait %.1f%% in a 1-second sample%s. Applications wait for the disks, so the server feels slow even when CPU usage is low. A failing disk (retries, reallocations) or a degraded/rebuilding RAID is a common cause.",
				"iowait %.1f%% trong mẫu 1 giây%s. Ứng dụng phải chờ ổ đĩa nên máy chậm dù CPU không cao. Nguyên nhân hay gặp là ổ cứng sắp hỏng (đọc lại nhiều lần, sector bị thay thế) hoặc RAID đang suy giảm/rebuild.",
				iow, psiNote(ioFull, hasIOF, "I/O (full)")),
			Action: model.T("Check the Disks and RAID sections for failing disks or a rebuild first. Then find the busy disk and process: iostat -x 1 (high %util/await) and iotop.",
				"Xem mục Ổ cứng và RAID trước để loại trừ ổ sắp hỏng hoặc RAID đang rebuild. Sau đó tìm ổ và tiến trình đọc/ghi nhiều: iostat -x 1 (%util/await cao) và iotop."),
			Evidence: units.Evidence(ev, 10),
		})
	}

	// Steal (VMs only: bare metal has no hypervisor taking CPU time).
	if env.Virtual != "" && !env.Container && ld.StealPct != nil && *ld.StealPct >= stealWarn {
		added = true
		res.Findings = append(res.Findings, model.Finding{
			ID: "system.cpu_steal", Component: model.CompSystem, Severity: model.Warn,
			Title: model.Tf("Hypervisor is taking %.0f%% of this VM's CPU time (steal)", "Hypervisor đang lấy mất %.0f%% thời gian CPU của máy ảo (steal)", *ld.StealPct),
			Detail: model.Tf("CPU steal was %.1f%% in a 1-second sample: the VM wanted to run but the host gave the CPU to other VMs. The host is overcommitted or another VM is very busy.",
				"CPU steal là %.1f%% trong mẫu 1 giây: máy ảo cần chạy nhưng máy host đang chia CPU cho máy ảo khác. Máy host bị cấp phát quá tải hoặc có máy ảo khác đang dùng rất nhiều CPU.", *ld.StealPct),
			Action: model.T("Ask the hosting provider or the virtualisation admin to check the host's CPU load and overcommit ratio, or move this VM to a less busy host.",
				"Báo nhà cung cấp hoặc người quản trị ảo hoá kiểm tra tải CPU và tỉ lệ cấp phát của máy host, hoặc chuyển máy ảo sang host ít tải hơn."),
			Evidence: units.Evidence(ev, 10),
		})
	}
	return added
}

func psiNote(p PSI, ok bool, what string) string {
	if !ok {
		return ""
	}
	return fmt.Sprintf("; PSI %s avg300=%.1f%%", what, p.Avg300)
}

func deref(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func okLoad(ld *Load, res *model.Result) {
	var en, vi string
	if ld.CPUPct != nil { // Windows
		en = fmt.Sprintf("System load is normal (CPU %.0f%%, queue %.1f per CPU)", *ld.CPUPct, deref(ld.QueuePerCPU))
		vi = fmt.Sprintf("Tải hệ thống bình thường (CPU %.0f%%, hàng đợi %.1f mỗi CPU)", *ld.CPUPct, deref(ld.QueuePerCPU))
	} else {
		en = fmt.Sprintf("System load is normal (load %.2f on %d CPUs", ld.Load15, ld.CPUs)
		vi = fmt.Sprintf("Tải hệ thống bình thường (load %.2f trên %d CPU", ld.Load15, ld.CPUs)
		if ld.IOWaitPct != nil {
			en += fmt.Sprintf(", iowait %.1f%%", *ld.IOWaitPct)
			vi += fmt.Sprintf(", iowait %.1f%%", *ld.IOWaitPct)
		}
		en += ")"
		vi += ")"
	}
	res.Findings = append(res.Findings, model.Finding{
		ID: "system.load_ok", Component: model.CompSystem, Severity: model.OK,
		Title: model.T(en, vi),
	})
}

func loadTable(ld *Load, res *model.Result) {
	f := func(p *float64) string {
		if p == nil {
			return ""
		}
		return fmt.Sprintf("%.1f%%", *p)
	}
	psi := func(k string) string {
		if p, ok := psiGet(ld, k); ok {
			return fmt.Sprintf("%.1f%%", p.Avg300)
		}
		return ""
	}
	res.Tables = append(res.Tables, model.Table{
		ID:    "system.load",
		Title: model.T("Load and pressure", "Tải và áp lực tài nguyên"),
		Columns: []model.Text{
			model.T("Load 1/5/15 min", "Load 1/5/15 phút"), model.T("CPUs", "Số CPU"),
			model.T("iowait", "iowait"), model.T("steal", "steal"),
			model.T("PSI cpu (5 min)", "PSI cpu (5 phút)"), model.T("PSI memory (5 min)", "PSI bộ nhớ (5 phút)"), model.T("PSI io (5 min)", "PSI io (5 phút)"),
		},
		Rows: []model.Row{{Cells: []string{
			fmt.Sprintf("%.2f / %.2f / %.2f", ld.Load1, ld.Load5, ld.Load15), fmt.Sprint(ld.CPUs),
			f(ld.IOWaitPct), f(ld.StealPct), psi("cpu some"), psi("memory some"), psi("io some"),
		}}},
	})
}

// taintFindings explains the kernel taint flags that point at hardware or
// firmware. Bits that only describe software (proprietary or unsigned
// modules, live patching...) are ignored. It reports whether a Warn was
// added.
func taintFindings(t uint64, res *model.Result) bool {
	has := func(bit uint) bool { return t&(1<<bit) != 0 }
	ev := []string{fmt.Sprintf("/proc/sys/kernel/tainted = %d", t)}
	added := false
	add := func(f model.Finding) {
		f.Evidence = ev
		res.Findings = append(res.Findings, f)
		if f.Severity >= model.Warn {
			added = true
		}
	}
	if has(taintMCE) {
		// Bit 4 is set by the x86 machine-check handler when a #MC exception
		// is raised (an uncorrected or action-required hardware error);
		// corrected errors found by polling do not set it. It is evidence of
		// a hardware error since boot, but the CPU/memory sections hold the
		// details (bank, address, DIMM) and decide Crit, so this stays Warn.
		add(model.Finding{
			ID: "system.taint_mce", Component: model.CompCPU, Severity: model.Warn, Target: "kernel",
			Title: model.T("A machine check (hardware error) occurred since boot", "Đã xảy ra lỗi machine check (lỗi phần cứng) kể từ lần khởi động"),
			Detail: model.T("The kernel is tainted with flag M: the CPU reported a machine check exception. This is a hardware error in the CPU, memory, cache or bus, not a software bug.",
				"Kernel bị đánh dấu cờ M: CPU đã báo lỗi machine check. Đây là lỗi phần cứng ở CPU, RAM, cache hoặc bus, không phải lỗi phần mềm."),
			Action: model.T("Check the CPU and Memory sections and the BMC event log for the failing part (CPU socket or DIMM slot). Read the details with: journalctl -k | grep -i -e mce -e 'hardware error', ras-mc-ctl --errors or mcelog. Open a hardware case with the vendor if errors repeat.",
				"Xem mục CPU, Bộ nhớ và log sự kiện BMC để xác định linh kiện lỗi (socket CPU hoặc khe RAM). Xem chi tiết: journalctl -k | grep -i -e mce -e 'hardware error', ras-mc-ctl --errors hoặc mcelog. Nếu lỗi lặp lại, mở case bảo hành với hãng."),
		})
	}
	if has(taintBadPage) {
		add(model.Finding{
			ID: "system.taint_bad_page", Component: model.CompMemory, Severity: model.Warn, Target: "kernel",
			Title: model.T("The kernel found a corrupted memory page since boot", "Kernel phát hiện trang bộ nhớ bị hỏng kể từ lần khởi động"),
			Detail: model.T("The kernel is tainted with flag B (bad page referenced or unexpected page flags). Faulty RAM is a common cause; a kernel/driver bug is the other.",
				"Kernel bị đánh dấu cờ B (truy cập trang bộ nhớ hỏng hoặc cờ trang bất thường). Nguyên nhân hay gặp là RAM lỗi; khả năng khác là lỗi kernel/driver."),
			Action: model.T("Check the Memory section for ECC errors and look for 'Bad page' in the kernel log (journalctl -k | grep -i 'bad page'). If ECC errors point to a DIMM, replace it; otherwise schedule a memory test (memtest86+) in a maintenance window.",
				"Xem mục Bộ nhớ có lỗi ECC không và tìm 'Bad page' trong log kernel (journalctl -k | grep -i 'bad page'). Nếu lỗi ECC chỉ ra thanh RAM nào thì thay thanh đó; nếu không, lên lịch test RAM (memtest86+) trong giờ bảo trì."),
		})
	}
	if has(taintDied) {
		add(model.Finding{
			ID: "system.taint_oops", Component: model.CompSystem, Severity: model.Warn, Target: "kernel",
			Title: model.T("The kernel crashed (OOPS/BUG) since boot", "Kernel đã bị lỗi nghiêm trọng (OOPS/BUG) kể từ lần khởi động"),
			Detail: model.T("The kernel is tainted with flag D. The system kept running, but a kernel thread or process died; the machine may be unstable. Faulty RAM or CPU and buggy drivers are typical causes.",
				"Kernel bị đánh dấu cờ D. Hệ thống vẫn chạy nhưng một luồng kernel hoặc tiến trình đã chết; máy có thể không ổn định. Nguyên nhân thường gặp là RAM/CPU lỗi hoặc driver lỗi."),
			Action: model.T("Read the oops in the kernel log (journalctl -k | grep -i -A30 -e oops -e 'kernel BUG'), check the Logs, CPU and Memory sections, and plan a reboot. Update the kernel and firmware if the oops points to a driver.",
				"Đọc thông báo oops trong log kernel (journalctl -k | grep -i -A30 -e oops -e 'kernel BUG'), xem mục Nhật ký, CPU và Bộ nhớ, và lên lịch khởi động lại. Nếu oops chỉ ra driver, cập nhật kernel và firmware."),
		})
	}
	if has(taintSoftLockup) {
		add(model.Finding{
			ID: "system.taint_soft_lockup", Component: model.CompSystem, Severity: model.Warn, Target: "kernel",
			Title: model.T("A CPU was stuck (soft lockup) since boot", "Có CPU bị treo (soft lockup) kể từ lần khởi động"),
			Detail: model.T("The kernel is tainted with flag L: a CPU ran kernel code for more than 20 seconds without yielding. Causes include storage that stopped answering, extreme overload, a hypervisor pausing the VM, or firmware/hardware faults.",
				"Kernel bị đánh dấu cờ L: một CPU chạy mã kernel hơn 20 giây không nhả. Nguyên nhân có thể là ổ đĩa/controller không phản hồi, quá tải nặng, hypervisor tạm dừng máy ảo, hoặc lỗi firmware/phần cứng."),
			Action: model.T("Find the lockup in the kernel log (journalctl -k | grep -i 'soft lockup') to see which process and driver were involved, then check the Disks, RAID and Logs sections.",
				"Tìm dòng soft lockup trong log kernel (journalctl -k | grep -i 'soft lockup') để biết tiến trình và driver liên quan, rồi xem mục Ổ cứng, RAID và Nhật ký."),
		})
	}
	if has(taintFirmware) {
		add(model.Finding{
			ID: "system.taint_firmware", Component: model.CompSystem, Severity: model.Info, Target: "kernel",
			Title:  model.T("The kernel is working around a firmware (BIOS/ACPI) bug", "Kernel đang phải né một lỗi firmware (BIOS/ACPI)"),
			Detail: model.T("The kernel is tainted with flag I: it applied a workaround for a bug in the platform firmware.", "Kernel bị đánh dấu cờ I: đã áp dụng cách né lỗi firmware của nền tảng."),
			Action: model.T("Check for a BIOS update from the vendor.", "Kiểm tra bản cập nhật BIOS của hãng."),
		})
	}
	if has(taintWarn) {
		// Very common (driver WARN_ON); worth knowing, not a fault by itself.
		add(model.Finding{
			ID: "system.taint_warning", Component: model.CompSystem, Severity: model.Info, Target: "kernel",
			Title:  model.T("The kernel logged a warning (WARN) since boot", "Kernel đã ghi một cảnh báo (WARN) kể từ lần khởi động"),
			Detail: model.T("The kernel is tainted with flag W. Most warnings come from drivers and are harmless, but they can point at a device or firmware problem.", "Kernel bị đánh dấu cờ W. Phần lớn cảnh báo đến từ driver và vô hại, nhưng đôi khi chỉ ra lỗi thiết bị hoặc firmware."),
			Action: model.T("Look at the warning in the kernel log: journalctl -k | grep -A20 'WARNING:'.", "Xem cảnh báo trong log kernel: journalctl -k | grep -A20 'WARNING:'."),
		})
	}
	if has(taintOutOfSpec) {
		add(model.Finding{
			ID: "system.taint_out_of_spec", Component: model.CompSystem, Severity: model.Info, Target: "kernel",
			Title:  model.T("The kernel reports an out-of-specification system", "Kernel báo hệ thống chạy ngoài thông số chuẩn"),
			Detail: model.T("The kernel is tainted with flag S (unsupported CPU combination or out-of-spec platform, e.g. forced CPU features).", "Kernel bị đánh dấu cờ S (tổ hợp CPU không được hỗ trợ hoặc nền tảng ngoài thông số, ví dụ ép bật tính năng CPU)."),
			Action: model.T("Check the BIOS settings and that all CPUs are a supported, matching pair.", "Kiểm tra cấu hình BIOS và các CPU có cùng loại, được hỗ trợ."),
		})
	}
	return added
}

func rebootLinux(b *collect.Bundle, facts *Facts, res *model.Result) {
	var ev []string
	need := false
	if s := b.Get("system.reboot"); s.OK() {
		for _, l := range s.Lines() {
			if k, v, ok := strings.Cut(l, "="); ok {
				switch k {
				case "reboot_required":
					need = true
					ev = append(ev, "found "+v)
				case "pkg":
					ev = append(ev, "package: "+v)
				}
			}
		}
	}
	if s := b.Get("system.needs_restarting"); s.Ran() && !s.Timeout {
		txt := s.Text()
		if (s.RC == 1 && strings.Contains(strings.ToLower(txt), "reboot")) || strings.Contains(txt, "Reboot is required") {
			need = true
			ev = append(ev, "needs-restarting -r: "+firstLine(txt))
		}
	}
	if !need {
		return
	}
	facts.RebootRequired = true
	addReboot(ev, res)
}

func addReboot(ev []string, res *model.Result) {
	res.Findings = append(res.Findings, model.Finding{
		ID: "system.reboot_required", Component: model.CompSystem, Severity: model.Info,
		Title:    model.T("A reboot is pending to finish installing updates", "Cần khởi động lại để hoàn tất cập nhật"),
		Detail:   model.T("Updated kernel, drivers, firmware or core libraries are installed but not in use until the server restarts.", "Kernel, driver, firmware hoặc thư viện lõi đã được cập nhật nhưng chỉ có hiệu lực sau khi khởi động lại."),
		Action:   model.T("Plan a reboot in the next maintenance window.", "Lên lịch khởi động lại trong lần bảo trì tới."),
		Evidence: units.Evidence(ev, 10),
	})
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return strings.TrimSpace(s)
}

// shortDuration formats an uptime for the identity table, whose cells are
// shown as-is in both languages: "41d 6h", "5h 12m", "3m" rather than
// English words.
func shortDuration(sec float64) string {
	d := time.Duration(sec) * time.Second
	days := int64(d / (24 * time.Hour))
	h := int64(d/time.Hour) % 24
	m := int64(d/time.Minute) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	}
	return "<1m"
}
