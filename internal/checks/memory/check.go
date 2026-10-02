// Package memory is the "memory" domain check: DIMM inventory, ECC error
// counters (EDAC, rasdaemon, mcelog), memory capacity lost to disabled
// DIMMs, memory pressure, and memtester / Windows Memory Diagnostic results.
package memory

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/ras"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "memory"

// Facts is the typed data of the memory domain.
type Facts struct {
	ECC            string         `json:"ecc"` // "ecc", "none", "unknown"
	ECCType        string         `json:"eccType,omitempty"`
	Arrays         []Array        `json:"arrays,omitempty"`
	DIMMs          []DIMM         `json:"dimms,omitempty"`
	InstalledBytes uint64         `json:"installedBytes,omitempty"`
	VisibleBytes   uint64         `json:"visibleBytes,omitempty"`
	AvailableBytes uint64         `json:"availableBytes,omitempty"`
	SwapTotal      uint64         `json:"swapTotal,omitempty"`
	SwapUsed       uint64         `json:"swapUsed,omitempty"`
	EDAC           []EDACMC       `json:"edac,omitempty"`
	EDACDrivers    []string       `json:"edacDrivers,omitempty"`
	PSISome        *PSI           `json:"psiSome,omitempty"`
	PSIFull        *PSI           `json:"psiFull,omitempty"`
	OOMKills       uint64         `json:"oomKills,omitempty"`
	Memtest        *Memtest       `json:"memtest,omitempty"`
	MemDiag        []MemDiagEvent `json:"memDiag,omitempty"`
}

var (
	nameInventory = model.T("Memory modules (DIMMs)", "Thanh RAM (DIMM)")
	nameECC       = model.T("ECC memory error counters", "Bộ đếm lỗi RAM ECC")
	nameUsage     = model.T("Memory usage and pressure", "Mức dùng RAM và áp lực bộ nhớ")
	nameMemtest   = model.T("Memory stress test (memtester / Windows Memory Diagnostic)", "Test RAM (memtester / Windows Memory Diagnostic)")
)

// Thresholds.
const (
	// ceWarnPerDay: corrected errors per DIMM per 24 h at which a DIMM is
	// reported as degrading. mcelog's default DIMM trigger is
	// "ce-error-threshold = 10 / 24h" (mcelog.conf); field data (Schroeder,
	// Pinheiro, Weber, "DRAM Errors in the Wild", SIGMETRICS 2009) shows a
	// DIMM with correctable errors is far more likely to have more, and
	// later uncorrectable ones.
	ceWarnPerDay = 10
	// ceWarnTotal: an absolute count that means a persistent (hard) fault
	// whatever the uptime; the same study found most errors come from a
	// small number of DIMMs with repeating, hard errors.
	ceWarnTotal = 1000
	// lowAvailPct: MemAvailable below 10 % of MemTotal, the level of the
	// node_exporter mixin's NodeMemoryHighUtilization alert (> 90 % used).
	lowAvailPct = 10.0
	// heavySwapPct: half of the swap in use.
	heavySwapPct = 50.0
	// PSI (Documentation/accounting/psi.rst): share of time tasks stalled
	// waiting for memory. systemd-oomd starts killing at 60 % "full" over
	// 30 s (DefaultMemoryPressureLimit); 10 % "some" sustained over minutes
	// already means the workload is visibly slowed by lack of RAM.
	psiSomeWarn60  = 10.0
	psiSomeWarn300 = 5.0
	psiFullWarn60  = 5.0
	// memdiagRecentDays: a Windows Memory Diagnostic failure older than
	// this may predate a DIMM replacement: Warn instead of Crit.
	memdiagRecentDays = 90
)

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	if len(b.Prefix("memory.")) == 0 {
		return res
	}
	s := &state{b: b, env: env, res: &res, facts: &Facts{ECC: "unknown"}, virtual: !env.Bare()}
	switch env.OS {
	case collect.OSLinux:
		s.linux()
	case collect.OSWindows:
		s.windows()
	default:
		return res
	}
	res.Facts = s.facts
	return res
}

type state struct {
	b       *collect.Bundle
	env     model.Env
	res     *model.Result
	facts   *Facts
	virtual bool
	dimms   []DIMM
	arrays  []Array
	// eccShort is the error-correction value for the summary table.
	eccShort string
}

func noECCDetail(why model.Text) model.Text {
	return model.Text{
		EN: why.EN + ". Without ECC, a flipped bit is neither corrected nor reported: it silently corrupts data or crashes programs. Servers should use ECC memory.",
		VI: why.VI + ". Không có ECC thì bit bị lỗi không được sửa cũng không được báo: dữ liệu hỏng âm thầm hoặc chương trình bị crash. Máy chủ nên dùng RAM ECC.",
	}
}

func (s *state) add(f model.Finding) {
	if f.Component == "" {
		f.Component = model.CompMemory
	}
	s.res.Findings = append(s.res.Findings, f)
}

func (s *state) cov(id string, name model.Text, state string, reason, fix model.Text) {
	s.covCmd(id, name, state, reason, fix, "")
}

// covCmd records coverage with the one command that enables the check.
func (s *state) covCmd(id string, name model.Text, state string, reason, fix model.Text, cmd string) {
	s.res.Coverage = append(s.res.Coverage, model.Coverage{ID: id, Component: model.CompMemory, Name: name, State: state, Reason: reason, Fix: fix, Cmd: cmd})
}

// sudo prefixes cmd with sudo when the collector did not run as root.
func (s *state) sudo(cmd string) string {
	if s.env.Root {
		return cmd
	}
	return "sudo " + cmd
}

// memtestCmd is the command that runs the opt-in memory test (root only:
// memtester must lock the memory it tests).
func (s *state) memtestCmd(size string) string { return s.sudo("diagward check --memtest " + size) }

func okF(id, en, vi string) model.Finding {
	return model.Finding{ID: id, Component: model.CompMemory, Severity: model.OK, Title: model.T(en, vi)}
}

// ---- Linux ----

func (s *state) linux() {
	b := s.b
	if len(b.Prefix("cpu.cpuinfo")) > 0 && strings.Contains(b.Get("cpu.cpuinfo").Text(), "\thypervisor") {
		s.virtual = true
	}
	mi := parseMeminfo(b.Get("memory.meminfo").Text())
	visible := mi["MemTotal"]

	// Inventory.
	dsec := b.Get("memory.dmidecode")
	s.arrays, s.dimms = dmiMemory(dsec.Text())
	switch {
	case dsec == nil:
	case len(s.dimms) > 0:
		s.cov("memory.inventory", nameInventory, model.CovRan, model.Text{}, model.Text{})
	case dsec.Skipped == "container":
		s.cov("memory.inventory", nameInventory, model.CovSkipped, hint.Virtual(s.env), model.Text{})
	case dsec.Skipped == "not-root":
		s.covCmd("memory.inventory", nameInventory, model.CovSkipped, hint.NeedRoot(s.env), hint.RunAsRoot(s.env), "sudo diagward check")
	case dsec.Missing != "":
		fix, cmd := hint.InstallFix(s.env, "dmidecode")
		s.covCmd("memory.inventory", nameInventory, model.CovSkipped, hint.Missing("dmidecode"), fix, cmd)
	case s.virtual:
		s.cov("memory.inventory", nameInventory, model.CovSkipped, hint.Virtual(s.env), model.Text{})
	default:
		reason := model.T("dmidecode returned no memory devices (no SMBIOS table).", "dmidecode không trả về thanh RAM nào (không có bảng SMBIOS).")
		if dsec.Err != "" && !strings.Contains(dsec.Out, "SMBIOS") {
			reason = model.Tf("dmidecode failed: %s", "dmidecode lỗi: %s", oneLine(dsec.Err))
		}
		s.cov("memory.inventory", nameInventory, model.CovFailed, reason, model.Text{})
	}

	// ECC counters.
	mcs := parseEDAC(b.Get("memory.edac"))
	s.facts.EDAC = mcs
	for _, l := range b.Get("memory.edac_modules").Lines() {
		if l = strings.TrimSpace(l); l != "" {
			s.facts.EDACDrivers = append(s.facts.EDACDrivers, l)
		}
	}
	s.joinEDAC(mcs)
	s.inventoryFindings(visible, "MemTotal")
	s.ecc(mcs)

	// Usage.
	s.usageLinux(mi)

	// memtester.
	s.memtestLinux()

	s.tables(len(mcs) > 0)
}

// joinEDAC copies EDAC counters onto the dmidecode slots whose locator the
// EDAC label names (ghes_edac uses the SMBIOS locators; labels set with
// "ras-mc-ctl --register-labels" usually do too).
func (s *state) joinEDAC(mcs []EDACMC) {
	for _, mc := range mcs {
		for _, e := range mc.DIMMs {
			if i := s.matchDIMM(e.Label); i >= 0 {
				d := &s.dimms[i]
				d.EDACLabel = e.Label
				d.CE = addCount(d.CE, e.CE)
				d.UE = addCount(d.UE, e.UE)
			}
		}
	}
}

func addCount(a, b int64) int64 {
	if b < 0 {
		return a
	}
	if a < 0 {
		return b
	}
	return a + b
}

func (s *state) matchDIMM(label string) int {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return -1
	}
	best := -1
	for i, d := range s.dimms {
		if !d.Populated {
			continue
		}
		loc := strings.ToLower(d.Locator)
		bank := strings.ToLower(d.Bank)
		switch {
		case l == loc, bank != "" && (l == bank+" "+loc || l == bank+"_"+loc || l == loc+" "+bank):
			return i
		case len(loc) >= 2 && (strings.HasSuffix(l, " "+loc) || strings.HasSuffix(l, "_"+loc) || strings.HasSuffix(l, "#"+loc)):
			if best == -1 {
				best = i
			} else {
				best = -2 // ambiguous
			}
		}
	}
	if best < 0 {
		return -1
	}
	return best
}

func (s *state) ecc(mcs []EDACMC) {
	b := s.b
	sec := b.Get("memory.edac")
	ecc, eccText, eccShort := s.eccState()
	s.facts.ECC, s.facts.ECCType, s.eccShort = ecc, eccText.EN, eccShort
	rasRep := s.rasMemory()
	clients := ras.McelogClient(b.Get("cpu.mcelog_client").Text())

	var dimmCE, dimmUE int64
	monitored := 0
	for _, mc := range mcs {
		for _, d := range mc.DIMMs {
			monitored++
			if d.CE > 0 {
				dimmCE += d.CE
			}
			if d.UE > 0 {
				dimmUE += d.UE
			}
		}
		if mc.CENoInfo > 0 {
			dimmCE += mc.CENoInfo
		}
		if mc.UENoInfo > 0 {
			dimmUE += mc.UENoInfo
		}
		if len(mc.DIMMs) == 0 {
			dimmCE += max(mc.CE, 0)
			dimmUE += max(mc.UE, 0)
		}
	}

	switch {
	case sec == nil:
		// older collector: nothing to report
	case len(mcs) > 0:
		s.cov("memory.ecc", nameECC, model.CovRan, model.Text{}, model.Text{})
	case sec.Skipped != "" || s.virtual:
		s.cov("memory.ecc", nameECC, model.CovSkipped, hint.Virtual(s.env), model.Text{})
	case ecc == "none":
		s.cov("memory.ecc", nameECC, model.CovSkipped,
			model.T("The installed RAM has no ECC, so memory errors cannot be detected.", "RAM đang lắp không có ECC nên không phát hiện được lỗi bộ nhớ."), model.Text{})
	default:
		reason, fix, cmd := s.noEDAC()
		if len(rasRep.Mem)+len(rasRep.MemEvents) > 0 || len(clients) > 0 {
			reason = model.Text{EN: reason.EN + " Using the rasdaemon/mcelog history instead.", VI: reason.VI + " Dùng lịch sử của rasdaemon/mcelog thay thế."}
		}
		s.covCmd("memory.ecc", nameECC, model.CovPartial, reason, fix, cmd)
	}

	if len(mcs) > 0 {
		s.edacFindings(mcs, monitored)
	}
	s.rasFindings(rasRep, dimmCE, dimmUE, len(mcs) > 0)
	s.mcelogFindings(clients, dimmCE, dimmUE, len(mcs) > 0)

	if ecc == "none" && !s.virtual && len(s.dimms) > 0 {
		s.add(model.Finding{
			ID: "memory.no_ecc", Severity: model.Info,
			Title:  model.T("The RAM has no ECC", "RAM không có ECC"),
			Detail: noECCDetail(eccText),
			Action: model.T("For a production server, use ECC DIMMs on a board/CPU that supports ECC. Until then, run a memory test (memtester or Memtest86+) when you suspect RAM problems.",
				"Với máy chủ chạy thật, dùng RAM ECC trên bo mạch/CPU hỗ trợ ECC. Trong lúc chưa thay, hãy test RAM (memtester hoặc Memtest86+) khi nghi ngờ lỗi RAM."),
		})
	}
}

// Intel server CPU models (family 6, /proc/cpuinfo "model") and the EDAC
// driver that supports them (CPU match tables in drivers/edac/sb_edac.c,
// skx_base.c and i10nm_base.c).
var intelEDAC = map[int]string{
	// Sandy Bridge-EP, Ivy Bridge-EP, Haswell-EP, Broadwell-EP/DE, Xeon Phi
	45: "sb_edac", 62: "sb_edac", 63: "sb_edac", 79: "sb_edac", 86: "sb_edac", 87: "sb_edac", 133: "sb_edac",
	// Skylake-SP, Cascade Lake, Cooper Lake
	85: "skx_edac",
	// Ice Lake-SP/D, Snow Ridge, Sapphire/Granite/Emerald Rapids, Sierra Forest
	106: "i10nm_edac", 108: "i10nm_edac", 134: "i10nm_edac", 143: "i10nm_edac", 173: "i10nm_edac", 175: "i10nm_edac", 207: "i10nm_edac",
}

var (
	reCPUModel   = regexp.MustCompile(`(?m)(?:\tmodel=|^Model:\s+|"Model:",\s*"data":\s*")(\d+)`)
	reCPUFamily6 = regexp.MustCompile(`(?m)(?:\tcpu family=|^CPU family:\s+|"CPU family:",\s*"data":\s*")6\b`)
)

// edacModule names the EDAC driver for this CPU, or "" when unsure.
func (s *state) edacModule() string {
	ci := s.b.Get("cpu.cpuinfo").Text() + "\n" + s.b.Get("cpu.lscpu_json").Text() + "\n" + s.b.Get("cpu.lscpu").Text()
	l := strings.ToLower(ci)
	if strings.Contains(l, "authenticamd") || strings.Contains(l, "amd epyc") {
		return "amd64_edac"
	}
	if !strings.Contains(l, "genuineintel") || !reCPUFamily6.MatchString(ci) {
		return ""
	}
	if m := reCPUModel.FindStringSubmatch(ci); m != nil {
		n, _ := strconv.Atoi(m[1])
		return intelEDAC[n]
	}
	return ""
}

// noEDAC explains a missing EDAC driver on bare metal, names the module for
// the CPU family and returns the modprobe command when the CPU is known.
func (s *state) noEDAC() (model.Text, model.Text, string) {
	ci := strings.ToLower(s.b.Get("cpu.cpuinfo").Text() + s.b.Get("cpu.lscpu_json").Text() + s.b.Get("cpu.lscpu").Text())
	drv := "skx_edac / i10nm_edac (Intel Xeon), amd64_edac (AMD)"
	mod := s.edacModule()
	switch {
	case mod != "":
		drv = mod
	case strings.Contains(ci, "authenticamd") || strings.Contains(ci, "amd ryzen"):
		drv = "amd64_edac"
	case strings.Contains(ci, "genuineintel"):
		drv = "i10nm_edac (Xeon Ice Lake and newer), skx_edac (Xeon Scalable 1st/2nd gen), sb_edac (Xeon E5/E7 v1-v4), ie31200_edac (Xeon E3)"
	}
	reason := model.Tf("ECC error counters unavailable: no EDAC driver is loaded (for this CPU: %s). Some vendors (Dell, HPE) handle memory errors in firmware and only report them to the BMC.",
		"Không có bộ đếm lỗi ECC: chưa nạp driver EDAC (với CPU này: %s). Một số hãng (Dell, HPE) xử lý lỗi RAM trong firmware và chỉ báo lên BMC.", drv)
	if mod != "" {
		fix := model.Tf("Load the %s driver, then run Diagward again. If it does not load (firmware-first platforms), read the BMC event log (iDRAC/iLO/IPMI SEL) for memory errors.",
			"Nạp driver %s rồi chạy lại Diagward. Nếu không nạp được (máy xử lý lỗi bằng firmware), đọc log sự kiện BMC (iDRAC/iLO/IPMI SEL) để xem lỗi RAM.", mod)
		return reason, fix, s.sudo("modprobe " + mod)
	}
	fix := model.T("Load the EDAC driver for this CPU (modprobe skx_edac, i10nm_edac or amd64_edac) or read the BMC event log (iDRAC/iLO/IPMI SEL) for memory errors.",
		"Nạp driver EDAC phù hợp với CPU (modprobe skx_edac, i10nm_edac hoặc amd64_edac) hoặc đọc log sự kiện BMC (iDRAC/iLO/IPMI SEL) để xem lỗi RAM.")
	return reason, fix, ""
}

// eccState decides whether the memory has ECC: from the modules' widths
// (72/80-bit total for 64 data bits), else from the array's error
// correction type. It returns the state, an explanation and a short value
// for the summary table.
func (s *state) eccState() (string, model.Text, string) {
	widthECC, widthNone := 0, 0
	for _, d := range s.dimms {
		if !d.Populated || d.PMem {
			continue
		}
		if e, ok := d.ECCWidth(); ok {
			if e {
				widthECC++
			} else {
				widthNone++
			}
		}
	}
	arr := ""
	for _, a := range s.arrays {
		if a.ECC != "" {
			arr = a.ECC
			break
		}
	}
	la := strings.ToLower(arr)
	arrECC := strings.Contains(la, "ecc") || la == "crc"
	arrNone := la == "none"
	w := s.firstWidth()
	switch {
	case widthECC > 0 && widthNone == 0:
		v := firstNonEmpty(arr, "ECC")
		return "ecc", model.T(v, v), v
	case widthNone > 0 && widthECC == 0:
		short := fmt.Sprintf("None (%d-bit)", w)
		if arrECC {
			return "none", model.Tf("The board supports %s, but the installed modules are %d-bit without ECC bits",
				"Bo mạch hỗ trợ %s, nhưng các thanh RAM đang lắp là loại %d-bit, không có bit ECC", arr, w), short
		}
		return "none", model.Tf("The SMBIOS table gives error correction type %s, and the modules are %d-bit without ECC bits",
			"Bảng SMBIOS ghi kiểu sửa lỗi là %s, và các thanh RAM là loại %d-bit, không có bit ECC", firstNonEmpty(arr, "None"), w), short
	case widthECC > 0 && widthNone > 0:
		return "unknown", model.T("ECC and non-ECC modules are mixed", "Đang lắp lẫn thanh RAM có ECC và không có ECC"), "ECC + non-ECC"
	case arrECC:
		return "ecc", model.T(arr, arr), arr
	case arrNone:
		return "none", model.T("The SMBIOS table gives error correction type None", "Bảng SMBIOS ghi kiểu sửa lỗi là None"), "None"
	}
	return "unknown", model.T(arr, arr), arr
}

func (s *state) firstWidth() int {
	for _, d := range s.dimms {
		if d.Populated && !d.PMem && d.TotalWidth > 0 {
			return d.TotalWidth
		}
	}
	return 64
}

func (s *state) edacFindings(mcs []EDACMC, monitored int) {
	days := s.days(mcs)
	issues := 0
	for _, mc := range mcs {
		ds := mc.DIMMs
		if len(ds) == 0 {
			// Driver without per-DIMM nodes: treat the controller as one.
			ds = []EDACDimm{{MC: mc.Name, Node: "", Label: mc.Name + " (" + firstNonEmpty(mc.Ctl, "EDAC") + ")", CE: mc.CE, UE: mc.UE,
				Raw: []string{fmt.Sprintf("%s ce_count=%d ue_count=%d", mc.Name, mc.CE, mc.UE)}}}
		}
		for _, e := range ds {
			if e.UE > 0 {
				issues++
				s.ueFinding(e, "EDAC", e.UE)
			}
			if e.CE > 0 {
				issues++
				s.ceFinding(e.Name(), e.CE, days, e.Raw, s.partFor(e.Label), "EDAC")
			}
		}
		if mc.UENoInfo > 0 {
			issues++
			s.add(model.Finding{
				ID: "memory.ecc_uncorrected", Severity: model.Crit, Target: mc.Name,
				Title: model.Tf("%d uncorrected memory error(s) on memory controller %s (DIMM unknown)", "%d lỗi RAM không sửa được trên bộ điều khiển %s (không rõ thanh nào)", mc.UENoInfo, mc.Name),
				Detail: model.T("ECC detected errors it could not correct, but the driver could not tell which DIMM. Data may have been corrupted; the kernel may have killed processes or crashed.",
					"ECC phát hiện lỗi không sửa được nhưng driver không xác định được thanh RAM nào. Dữ liệu có thể đã hỏng; kernel có thể đã kill tiến trình hoặc treo máy."),
				Action: model.T("Back up important data. Read the BMC event log (iDRAC/iLO/IPMI SEL), which names the slot, and replace that DIMM. If the BMC does not say, test the DIMMs of this controller one by one.",
					"Sao lưu dữ liệu quan trọng. Đọc log sự kiện BMC (iDRAC/iLO/IPMI SEL) để biết khe nào và thay thanh RAM đó. Nếu BMC không ghi, test lần lượt các thanh RAM của bộ điều khiển này."),
				Evidence: []string{fmt.Sprintf("/sys/devices/system/edac/mc/%s/ue_noinfo_count=%d", mc.Name, mc.UENoInfo)},
			})
		}
		if mc.CENoInfo > 0 {
			issues++
			s.ceFinding(mc.Name+" (DIMM unknown)", mc.CENoInfo, days,
				[]string{fmt.Sprintf("/sys/devices/system/edac/mc/%s/ce_noinfo_count=%d", mc.Name, mc.CENoInfo)}, nil, "EDAC")
		}
	}
	if issues == 0 {
		drv := ""
		if len(mcs) > 0 && mcs[0].Ctl != "" {
			drv = ", " + mcs[0].Ctl
		}
		n := monitored
		unit, vi := "DIMMs", "thanh RAM"
		ranks := 0
		for _, mc := range mcs {
			for _, d := range mc.DIMMs {
				if strings.HasPrefix(d.Node, "rank") || strings.HasPrefix(d.Node, "csrow") {
					ranks++
				}
			}
		}
		switch {
		case n == 0:
			n, unit, vi = len(mcs), "memory controllers", "bộ điều khiển bộ nhớ"
		case ranks == n: // chip-select based drivers (amd64_edac, old csrow layout) count ranks, not DIMMs
			unit, vi = "memory ranks", "rank RAM"
		}
		s.add(okF("memory.ecc_ok",
			fmt.Sprintf("ECC: no memory errors since boot on %d %s (EDAC%s)", n, unit, drv),
			fmt.Sprintf("ECC: không có lỗi RAM từ lúc khởi động trên %d %s (EDAC%s)", n, vi, drv)))
	}
}

// days is the time the EDAC counters cover: seconds_since_reset, else the
// uptime. At least one day, so that a burst right after boot is not
// over-scaled.
func (s *state) days(mcs []EDACMC) float64 {
	var sec int64
	for _, mc := range mcs {
		sec = max(sec, mc.Seconds)
	}
	d := float64(sec) / 86400
	if sec <= 0 {
		d = cpu.Uptime(s.b).Hours() / 24
	}
	if d < 1 {
		d = 1
	}
	return d
}

func (s *state) partFor(label string) *model.Part {
	if i := s.matchDIMM(label); i >= 0 {
		return dimmPart(s.dimms[i])
	}
	if strings.TrimSpace(label) == "" {
		return nil
	}
	return &model.Part{Kind: "dimm", Location: label}
}

func dimmPart(d DIMM) *model.Part {
	loc := d.Locator
	if d.Bank != "" && !strings.Contains(d.Locator, d.Bank) {
		loc += " / " + d.Bank
	}
	return &model.Part{Kind: "dimm", Vendor: d.Manufacturer, Model: d.PartNumber, Serial: d.Serial, Location: loc, Size: iec(d.SizeBytes)}
}

func (s *state) ueFinding(e EDACDimm, src string, n int64) {
	name := e.Name()
	part := s.partFor(e.Label)
	tgt := name
	if part != nil && part.Location != "" && part.Location != name {
		tgt = name + " (" + part.Location + ")"
	}
	ser := ""
	if part != nil && part.Serial != "" {
		ser = " serial " + part.Serial
	}
	f := model.Finding{
		ID: "memory.ecc_uncorrected", Severity: model.Crit, Target: tgt,
		Title: model.Tf("Uncorrected memory errors on DIMM %s: %d", "Thanh RAM %s có lỗi không sửa được: %d lỗi", tgt, n),
		Detail: model.Tf("%s counted %d memory error(s) that ECC could not correct on this DIMM since boot. Data may have been corrupted; the kernel may have killed processes or crashed. A DIMM with uncorrected errors is failing.",
			"%s đếm được %d lỗi RAM mà ECC không sửa được trên thanh này từ lúc khởi động. Dữ liệu có thể đã hỏng; kernel có thể đã kill tiến trình hoặc treo máy. Thanh RAM có lỗi không sửa được là đang hỏng.", src, n),
		Action: model.Tf("Back up important data. Replace DIMM %[1]s%[2]s as soon as possible (power off first). Check the BMC event log for the same slot; if a new DIMM in that slot also fails, the slot or CPU memory controller is at fault.",
			"Sao lưu dữ liệu quan trọng. Thay thanh RAM %[1]s%[2]s sớm nhất có thể (tắt máy trước). Kiểm tra log sự kiện BMC cho khe này; nếu thanh mới ở khe đó cũng lỗi thì lỗi nằm ở khe hoặc bộ điều khiển bộ nhớ của CPU.", tgt, ser),
		Evidence: units.Evidence(e.Raw, 10),
		Part:     part,
	}
	addWhere(&f, e.Label, part)
	s.add(f)
}

// ceFinding reports corrected errors on one DIMM: Info for a few, Warn
// from ceWarnPerDay per day on average (or ceWarnTotal in total).
func (s *state) ceFinding(name string, n int64, days float64, raw []string, part *model.Part, src string) {
	rate := float64(n) / days
	sev := model.Info
	if (n >= ceWarnPerDay && rate >= ceWarnPerDay) || n >= ceWarnTotal {
		sev = model.Warn
	}
	tgt := name
	if part != nil && part.Location != "" && part.Location != name {
		tgt = name + " (" + part.Location + ")"
	}
	ser := ""
	if part != nil && part.Serial != "" {
		ser = " (serial " + part.Serial + ")"
	}
	f := model.Finding{
		ID: "memory.ecc_corrected", Severity: sev, Target: tgt, Part: part,
		Evidence: units.Evidence(raw, 10),
	}
	period := units.Duration(time.Duration(days * 24 * float64(time.Hour)))
	if sev == model.Warn {
		f.Title = model.Tf("DIMM %s keeps producing corrected memory errors: %d (%.0f per day)", "Thanh RAM %s liên tục bị lỗi (đã được ECC sửa): %d lỗi (%.0f lỗi/ngày)", tgt, n, rate)
		f.Detail = model.Text{
			EN: fmt.Sprintf("%s counted %d corrected errors in about %s. ECC fixed them, so no data was lost yet, but a DIMM that keeps producing corrected errors is wearing out and is much more likely to produce an uncorrectable error (which crashes the server).", src, n, period.EN),
			VI: fmt.Sprintf("%s đếm được %d lỗi đã sửa trong khoảng %s. ECC đã sửa nên chưa mất dữ liệu, nhưng thanh RAM liên tục phát sinh lỗi là đang xuống cấp và dễ phát sinh lỗi không sửa được (làm treo máy) hơn nhiều.", src, n, period.VI),
		}
		f.Action = model.Tf("Plan to replace DIMM %[1]s%[2]s at the next maintenance window. Check the BMC event log for the same slot. If the errors move with the DIMM when you swap two DIMMs, the DIMM is bad; if they stay with the slot, suspect the slot/CPU.",
			"Lên kế hoạch thay thanh RAM %[1]s%[2]s ở lần bảo trì tới. Kiểm tra log sự kiện BMC cho khe này. Nếu đổi chỗ hai thanh mà lỗi đi theo thanh RAM thì thanh RAM hỏng; lỗi ở lại khe thì nghi khe hoặc CPU.", tgt, ser)
	} else {
		f.Title = model.Tf("A few corrected memory errors on DIMM %s: %d since boot", "Thanh RAM %s có vài lỗi đã được ECC sửa: %d lỗi từ lúc khởi động", tgt, n)
		f.Detail = model.Text{
			EN: fmt.Sprintf("%s counted %d corrected errors in about %s. ECC fixed them; an occasional corrected error is normal (cosmic rays, electrical noise). Watch whether the count grows.", src, n, period.EN),
			VI: fmt.Sprintf("%s đếm được %d lỗi đã sửa trong khoảng %s. ECC đã sửa; thỉnh thoảng có lỗi đã sửa là bình thường (bức xạ, nhiễu điện). Theo dõi xem số lỗi có tăng không.", src, n, period.VI),
		}
		f.Action = model.T("No action now. Run Diagward again in a few days; if the count keeps rising on the same DIMM, plan to replace it.",
			"Chưa cần làm gì. Chạy lại Diagward sau vài ngày; nếu số lỗi trên cùng thanh tiếp tục tăng, lên kế hoạch thay thanh đó.")
	}
	addWhere(&f, name, part)
	s.add(f)
}

// reIntelLabel matches the DIMM labels Intel EDAC drivers make up when the
// BIOS gives none: skx_edac/i10nm_edac "CPU_SrcID#0_MC#1_Chan#2_DIMM#0",
// sb_edac "CPU_SrcID#0_Ha#0_Chan#1_DIMM#0" (drivers/edac/*.c).
var reIntelLabel = regexp.MustCompile(`CPU_SrcID#(\d+)_(?:MC|Ha)#(\d+)_Chan#(\d+)_DIMM#(\d+)`)

// addWhere explains a driver-made DIMM label in physical terms, so the
// technician can find the slot on the board's memory map.
func addWhere(f *model.Finding, label string, part *model.Part) {
	if part != nil && part.Serial != "" {
		return // already joined to an SMBIOS slot
	}
	m := reIntelLabel.FindStringSubmatch(label)
	if m == nil {
		return
	}
	sock, _ := strconv.Atoi(m[1])
	f.Detail.EN += fmt.Sprintf(" The label means: CPU socket %d (usually printed as CPU%d on the board), memory controller %s, channel %s, DIMM %s of that channel; match it to a slot with the memory map on the server lid or the BMC, which names the slot.", sock, sock+1, m[2], m[3], m[4])
	f.Detail.VI += fmt.Sprintf(" Nhãn này nghĩa là: socket CPU %d (thường in trên bo mạch là CPU%d), bộ điều khiển bộ nhớ %s, kênh %s, thanh thứ %s của kênh; đối chiếu với sơ đồ khe RAM trên nắp máy hoặc BMC (có ghi tên khe).", sock, sock+1, m[2], m[3], m[4])
}

// rasMemory returns rasdaemon's memory-controller history (from --errors
// when available, else --summary).
func (s *state) rasMemory() ras.Report {
	b := s.b
	if e := b.Get("cpu.ras_errors"); e.Ran() {
		r := ras.Parse(e.Out)
		if r.Recognized {
			return r
		}
	}
	if e := b.Get("cpu.ras_summary"); e.Ran() {
		return ras.Parse(e.Out)
	}
	return ras.Report{}
}

// rasFindings reports rasdaemon memory events that the EDAC counters do not
// show (events from before the last reboot, or no EDAC counters at all).
func (s *state) rasFindings(r ras.Report, edacCE, edacUE int64, haveEDAC bool) {
	now := s.env.Now
	window := time.Duration(cpu.HWWindowDays) * 24 * time.Hour
	type agg struct {
		ce, ue, ce24 int
		ev           []string
		dated        bool
	}
	by := map[string]*agg{}
	var order []string
	get := func(l string) *agg {
		if by[l] == nil {
			by[l] = &agg{}
			order = append(order, l)
		}
		return by[l]
	}
	for _, e := range r.MemEvents {
		if !e.Time.IsZero() && !now.IsZero() && now.Sub(e.Time) > window {
			continue
		}
		a := get(firstNonEmpty(e.Label, e.Location, "?"))
		if e.Uncorrected() {
			a.ue += e.Count
		} else if strings.HasPrefix(strings.ToLower(e.Type), "corrected") {
			a.ce += e.Count
			if !e.Time.IsZero() && now.Sub(e.Time) <= 24*time.Hour {
				a.ce24 += e.Count
			}
		}
		a.dated = a.dated || !e.Time.IsZero()
		a.ev = append(a.ev, e.Raw)
	}
	if len(r.MemEvents) == 0 {
		for _, c := range r.Mem { // summary only: whole history, no dates
			a := get(firstNonEmpty(c.Label, c.Location, "?"))
			if c.Uncorrected() {
				a.ue += c.Count
			} else if strings.HasPrefix(strings.ToLower(c.Type), "corrected") {
				a.ce += c.Count
			}
			a.ev = append(a.ev, c.Raw)
		}
	}
	for _, l := range order {
		a := by[l]
		part := s.partFor(l)
		if a.ue > 0 && (!haveEDAC || edacUE == 0) {
			sev := model.Crit
			title := model.Tf("rasdaemon recorded %d uncorrected memory error(s) on %s in the last %d days", "rasdaemon ghi nhận %d lỗi RAM không sửa được trên %s trong %d ngày qua", a.ue, l, cpu.HWWindowDays)
			if !a.dated {
				sev = model.Warn // no dates (summary): may be old
				title = model.Tf("rasdaemon has recorded %d uncorrected memory error(s) on %s (date unknown, possibly old)", "rasdaemon đã ghi %d lỗi RAM không sửa được trên %s (không rõ thời gian, có thể là lỗi cũ)", a.ue, l)
			}
			s.add(model.Finding{
				ID: "memory.ras_uncorrected", Severity: sev, Target: l, Part: part,
				Title: title,
				Detail: model.T("These errors happened before the last reboot or are not visible in the EDAC counters. ECC could not correct them: the DIMM is failing.",
					"Các lỗi này xảy ra trước lần khởi động gần nhất hoặc không hiện trong bộ đếm EDAC. ECC không sửa được: thanh RAM đang hỏng."),
				Action:   model.Tf("Back up important data and replace DIMM %s. Confirm the slot in the BMC event log.", "Sao lưu dữ liệu quan trọng và thay thanh RAM %s. Xác nhận khe trong log sự kiện BMC.", l),
				Evidence: units.Evidence(a.ev, 10),
			})
		}
		if a.ce > 0 && (!haveEDAC || edacCE == 0) {
			sev := model.Info
			// mcelog's DIMM threshold: 10 corrected errors in 24 h; or the
			// same rate sustained over the whole window.
			if a.ce24 >= ceWarnPerDay || a.ce >= ceWarnPerDay*cpu.HWWindowDays {
				sev = model.Warn
			}
			f := model.Finding{
				ID: "memory.ras_corrected", Severity: sev, Target: l, Part: part,
				Title: model.Tf("rasdaemon recorded %d corrected memory error(s) on %s", "rasdaemon ghi nhận %d lỗi RAM đã được ECC sửa trên %s", a.ce, l),
				Detail: model.T("ECC corrected these errors (no data lost). Many errors on the same DIMM mean it is wearing out.",
					"ECC đã sửa các lỗi này (không mất dữ liệu). Nhiều lỗi trên cùng một thanh nghĩa là thanh đó đang xuống cấp."),
				Evidence: units.Evidence(a.ev, 10),
			}
			if sev == model.Warn {
				f.Action = model.Tf("Plan to replace DIMM %s at the next maintenance window and check the BMC event log for the same slot.",
					"Lên kế hoạch thay thanh RAM %s ở lần bảo trì tới và kiểm tra log sự kiện BMC cho khe này.", l)
			} else {
				f.Action = model.T("Keep watching; if the count keeps growing, plan to replace the DIMM.", "Tiếp tục theo dõi; nếu số lỗi tiếp tục tăng, lên kế hoạch thay thanh RAM.")
			}
			s.add(f)
		}
	}
}

// mcelogFindings reports "mcelog --client" DIMM counters (Intel systems
// with mcelogd), when EDAC does not already show the errors.
func (s *state) mcelogFindings(cl []ras.ClientDIMM, edacCE, edacUE int64, haveEDAC bool) {
	if len(cl) == 0 {
		return
	}
	specific := false
	for _, d := range cl {
		if d.Specific() {
			specific = true
		}
	}
	for _, d := range cl {
		if specific && !d.Specific() {
			continue // skip "CHANNEL any / DIMM any" aggregates
		}
		tgt := d.Target()
		part := s.partFor(d.Name)
		if d.UCTotal > 0 && (!haveEDAC || edacUE == 0) {
			s.add(model.Finding{
				ID: "memory.mcelog_uncorrected", Severity: model.Crit, Target: tgt, Part: part,
				Title: model.Tf("mcelog counted %d uncorrected memory error(s) on %s", "mcelog đếm được %d lỗi RAM không sửa được trên %s", d.UCTotal, tgt),
				Detail: model.T("ECC could not correct these errors (counted by mcelogd since it started). The DIMM is failing.",
					"ECC không sửa được các lỗi này (mcelogd đếm từ lúc chạy). Thanh RAM đang hỏng."),
				Action:   model.Tf("Back up important data and replace the DIMM at %s; confirm the slot in the BMC event log.", "Sao lưu dữ liệu quan trọng và thay thanh RAM ở %s; xác nhận khe trong log sự kiện BMC.", tgt),
				Evidence: units.Evidence(d.Raw, 10),
			})
		}
		if d.CETotal > 0 && (!haveEDAC || edacCE == 0) {
			sev := model.Info
			if d.CE24h >= ceWarnPerDay { // mcelog.conf ce-error-threshold = 10 / 24h
				sev = model.Warn
			}
			f := model.Finding{
				ID: "memory.mcelog_corrected", Severity: sev, Target: tgt, Part: part,
				Title: model.Tf("mcelog counted %d corrected memory error(s) on %s (%d in 24 h)", "mcelog đếm được %d lỗi RAM đã sửa trên %s (%d lỗi trong 24 giờ)", d.CETotal, tgt, d.CE24h),
				Detail: model.T("ECC corrected these errors. mcelog's own alarm level is 10 corrected errors per DIMM in 24 hours.",
					"ECC đã sửa các lỗi này. Ngưỡng cảnh báo mặc định của mcelog là 10 lỗi đã sửa trên một thanh trong 24 giờ."),
				Evidence: units.Evidence(d.Raw, 10),
			}
			if sev == model.Warn {
				f.Action = model.Tf("Plan to replace the DIMM at %s at the next maintenance window.", "Lên kế hoạch thay thanh RAM ở %s ở lần bảo trì tới.", tgt)
			} else {
				f.Action = model.T("Keep watching; if the count keeps growing, plan to replace the DIMM.", "Tiếp tục theo dõi; nếu số lỗi tiếp tục tăng, lên kế hoạch thay thanh RAM.")
			}
			s.add(f)
		}
	}
}

// inventoryFindings: capacity lost (DIMM disabled or not detected), mixed
// modules, speed below rating. visible is what the OS sees.
func (s *state) inventoryFindings(visible uint64, visibleName string) {
	s.facts.DIMMs = s.dimms
	s.facts.Arrays = s.arrays
	s.facts.VisibleBytes = visible
	var installed, volatile, smallest uint64
	var pop []DIMM // populated DRAM modules
	pmemVolatile := false
	for _, d := range s.dimms {
		if !d.Populated {
			continue
		}
		installed += d.SizeBytes
		if d.PMem {
			pmemVolatile = pmemVolatile || d.VolatileBytes > 0
			continue
		}
		pop = append(pop, d)
		volatile += d.VolatileBytes
		if d.VolatileBytes > 0 && (smallest == 0 || d.VolatileBytes < smallest) {
			smallest = d.VolatileBytes
		}
	}
	s.facts.InstalledBytes = installed
	if len(pop) == 0 || s.virtual {
		return
	}
	// Persistent memory in Memory Mode turns the DRAM into a cache and the
	// OS sees the PMem capacity instead: installed and visible RAM cannot be
	// compared. In App Direct mode it is not RAM at all and is left out.
	if visible > 0 && volatile > visible && !pmemVolatile {
		s.capacityFindings(volatile, visible, smallest, len(pop), visibleName)
	}
	s.mixedFindings(pop)
}

// capacityFindings compares the RAM the BIOS lists with what the OS sees.
//
// Firmware, the crash-kernel reservation (RHEL crashkernel=auto takes at
// most 512 MiB on 1 TiB+ machines) and an onboard GPU keep a few percent
// away from the OS, so only a gap of at least ~one module (90 % of the
// smallest DIMM) and at least 5 % of the total counts. Servers can also hold
// memory back on purpose: full mirroring hides half of it, rank sparing one
// rank per channel (a half, a quarter or an eighth). The memory
// controller's own DIMM list (EDAC, when a native driver is loaded) settles
// it; without it, a gap matching those fractions is only Info.
func (s *state) capacityFindings(installed, visible, smallest uint64, n int, visibleName string) {
	gap := installed - visible
	if float64(gap) < 0.9*float64(smallest) || float64(gap) < 0.05*float64(installed) {
		return
	}
	ev := []string{fmt.Sprintf("installed (%d DIMMs): %s", n, units.IEC(installed)), fmt.Sprintf("%s: %s", visibleName, units.IEC(visible))}
	edacN, drv := s.edacDIMMCount()
	if edacN > 0 {
		ev = append(ev, fmt.Sprintf("EDAC (%s) sees %d DIMMs", drv, edacN))
	}
	title := model.Tf("%s of installed RAM is not usable: %s installed, the OS sees %s", "%s RAM đã lắp nhưng không dùng được: lắp %s, hệ điều hành chỉ thấy %s", units.IEC(gap), units.IEC(installed), units.IEC(visible))
	checkLog := model.T("Check the BMC/POST event log (iDRAC Lifecycle Log, iLO IML, IPMI SEL) for a DIMM disabled or \"memory training\" error and note the slot. Reseat that DIMM, follow the vendor's slot population order, and replace it if it is disabled again.",
		"Xem log sự kiện BMC/POST (iDRAC Lifecycle Log, iLO IML, IPMI SEL) có báo thanh RAM bị tắt hoặc lỗi \"memory training\" không, ghi lại khe. Gắn lại thanh đó, cắm đúng thứ tự khe theo hướng dẫn của hãng, và thay nếu nó lại bị tắt.")
	switch {
	case edacN > 0 && edacN >= n:
		s.add(model.Finding{
			ID: "memory.capacity_reserved", Severity: model.Info,
			Title: model.Tf("%s of RAM is held in reserve: %s installed, the OS sees %s", "%s RAM được giữ dự phòng: lắp %s, hệ điều hành thấy %s", units.IEC(gap), units.IEC(installed), units.IEC(visible)),
			Detail: model.Tf("The memory controller (EDAC, %s) has all %d DIMMs in use, so none is missing. The difference is memory the firmware keeps back: usually a RAS mode such as mirroring (half of the RAM) or rank sparing (one rank per channel), set in the BIOS.",
				"Bộ điều khiển bộ nhớ (EDAC, %s) đang dùng đủ %d thanh RAM nên không thiếu thanh nào. Phần chênh lệch là RAM firmware giữ lại: thường là chế độ RAS như mirroring (một nửa RAM) hoặc rank sparing (một rank mỗi kênh), đặt trong BIOS.", drv, edacN),
			Action: model.T("Nothing to replace. If you did not choose mirroring/sparing, check the memory operating mode in the BIOS (Dell: Memory Settings > Memory Operating Mode; HPE: Advanced Memory Protection).",
				"Không cần thay gì. Nếu không cố ý bật mirroring/sparing, kiểm tra chế độ hoạt động của RAM trong BIOS (Dell: Memory Settings > Memory Operating Mode; HPE: Advanced Memory Protection)."),
			Evidence: ev,
		})
	case edacN > 0:
		s.add(model.Finding{
			ID: "memory.capacity_missing", Severity: model.Warn, Title: title,
			Detail: model.Tf("The BIOS lists %d DIMMs (%s), but the memory controller (EDAC, %s) uses only %d and %s is %s. A DIMM was disabled by the BIOS after a memory error at POST, or is not detected (bad seating, wrong slot order).",
				"BIOS liệt kê %d thanh RAM (%s), nhưng bộ điều khiển bộ nhớ (EDAC, %s) chỉ dùng %d thanh và %s chỉ là %s. Có thanh RAM đã bị BIOS tắt do lỗi lúc POST, hoặc không được nhận (cắm lỏng, sai thứ tự khe).",
				n, units.IEC(installed), drv, edacN, visibleName, units.IEC(visible)),
			Action: checkLog, Evidence: ev,
		})
	case rasFraction(float64(visible) / float64(installed)):
		s.add(model.Finding{
			ID: "memory.capacity_missing", Severity: model.Info, Title: title,
			Detail: model.Tf("The DIMMs listed by the BIOS add up to %s, but %s is %s. The ratio matches a memory RAS mode that hides part of the RAM on purpose (mirroring keeps half, rank sparing a half, a quarter or an eighth in reserve); it can also be a DIMM the BIOS disabled after a memory error at POST.",
				"Tổng dung lượng các thanh RAM BIOS liệt kê là %s, nhưng %s chỉ là %s. Tỷ lệ này khớp với chế độ RAS cố ý giữ lại một phần RAM (mirroring giữ một nửa, rank sparing giữ một nửa, một phần tư hoặc một phần tám); cũng có thể BIOS đã tắt một thanh RAM do lỗi lúc POST.",
				units.IEC(installed), visibleName, units.IEC(visible)),
			Action: model.T("Check the memory operating mode in the BIOS (Dell: Memory Settings > Memory Operating Mode; HPE: Advanced Memory Protection). If it is the normal (optimizer) mode, check the BMC/POST event log for a disabled DIMM, reseat it and replace it if it is disabled again.",
				"Kiểm tra chế độ hoạt động của RAM trong BIOS (Dell: Memory Settings > Memory Operating Mode; HPE: Advanced Memory Protection). Nếu đang ở chế độ thường (Optimizer), xem log sự kiện BMC/POST có thanh RAM bị tắt không, gắn lại và thay nếu nó lại bị tắt."),
			Evidence: ev,
		})
	default:
		s.add(model.Finding{
			ID: "memory.capacity_missing", Severity: model.Warn, Title: title,
			Detail: model.Tf("The DIMMs listed by the BIOS add up to %s, but %s is %s. The gap is at least one module: a DIMM may have been disabled by the BIOS after a memory error at POST, or is not detected (bad seating, wrong slot order). A kernel limit (mem=) or a 32-bit OS also cause this.",
				"Tổng dung lượng các thanh RAM BIOS liệt kê là %s, nhưng %s chỉ là %s. Phần thiếu ít nhất bằng một thanh: có thể BIOS đã tắt một thanh RAM do lỗi lúc POST, hoặc thanh RAM không được nhận (cắm lỏng, sai thứ tự khe). Giới hạn kernel (mem=) hoặc hệ điều hành 32-bit cũng gây ra hiện tượng này.",
				units.IEC(installed), visibleName, units.IEC(visible)),
			Action: checkLog, Evidence: ev,
		})
	}
}

// rasFraction reports whether visible/installed matches the share of RAM a
// mirroring or rank-sparing mode leaves to the OS (1/2, 3/4, 7/8), allowing
// for up to 5 % of firmware/kernel reservations below it.
func rasFraction(r float64) bool {
	for _, c := range []float64{0.5, 0.75, 0.875} {
		if r >= c-0.05 && r <= c+0.005 {
			return true
		}
	}
	return false
}

// edacDIMMCount returns how many DIMMs a native Intel EDAC driver
// (skx_edac, i10nm_edac, sb_edac) reports, and the driver's name; 0 when
// unknown. These drivers read DIMM presence from the memory controller's
// own registers (skx_common.c skx_get_dimm_info(), sb_edac.c
// get_dimm_config()), and sysfs only has dimmN nodes for populated DIMMs.
// ghes_edac copies the SMBIOS table, amd64_edac counts chip selects, and
// HBM channels (Xeon Max, label "..._HBMC#...") and NVDIMMs are not
// DIMMs of the DRAM list: none of those can be compared with it.
func (s *state) edacDIMMCount() (int, string) {
	n, drv := 0, ""
	for _, mc := range s.facts.EDAC {
		ctl := strings.TrimSpace(mc.Ctl)
		switch {
		case strings.HasPrefix(ctl, "Skylake Socket"):
			drv = "skx_edac"
		case strings.HasPrefix(ctl, "Intel_10nm Socket"):
			drv = "i10nm_edac"
		case strings.Contains(ctl, " SrcID#") && strings.Contains(ctl, "_Ha#"):
			drv = "sb_edac"
		default:
			return 0, ""
		}
		for _, d := range mc.DIMMs {
			if !strings.HasPrefix(d.Node, "dimm") {
				return 0, ""
			}
			mt := strings.ToLower(d.MemType)
			if d.SizeMB > 0 && !strings.Contains(mt, "nvdimm") && !strings.Contains(mt, "hbm") && !strings.Contains(d.Label, "_HBMC#") {
				n++
			}
		}
	}
	return n, drv
}

func (s *state) mixedFindings(pop []DIMM) {
	sizes, speeds, parts := map[string]int{}, map[string]int{}, map[string]int{}
	for _, d := range pop {
		sizes[units.IEC(d.SizeBytes)]++
		if d.SpeedMT > 0 {
			speeds[strconv.Itoa(d.SpeedMT)+" MT/s"]++
		}
		if d.PartNumber != "" {
			parts[d.PartNumber]++
		}
	}
	if len(sizes) > 1 || len(speeds) > 1 || len(parts) > 1 {
		var en, vi []string
		if len(sizes) > 1 {
			en, vi = append(en, "sizes "+keys(sizes)), append(vi, "dung lượng "+keys(sizes))
		}
		if len(speeds) > 1 {
			en, vi = append(en, "speeds "+keys(speeds)), append(vi, "tốc độ "+keys(speeds))
		}
		if len(parts) > 1 {
			en, vi = append(en, "part numbers "+keys(parts)), append(vi, "mã linh kiện (part number) "+keys(parts))
		}
		s.add(model.Finding{
			ID: "memory.mixed_dimms", Severity: model.Info,
			Title: model.T("The installed DIMMs are not all identical", "Các thanh RAM đang lắp không giống nhau"),
			Detail: model.Text{
				EN: "Different " + strings.Join(en, "; ") + ". It works, but all memory runs at the speed of the slowest module, uneven channels lower bandwidth, and vendors support only matching DIMMs. Keep it in mind when a DIMM has to be replaced or added.",
				VI: "Khác nhau về " + strings.Join(vi, "; ") + ". Vẫn chạy được, nhưng toàn bộ RAM chạy theo tốc độ của thanh chậm nhất, các kênh không đều làm giảm băng thông, và hãng chỉ hỗ trợ RAM đồng bộ. Lưu ý khi cần thay hoặc thêm RAM.",
			},
		})
	}
	var slow []string
	for _, d := range pop {
		if d.ConfiguredMT > 0 && d.SpeedMT > 0 && d.ConfiguredMT < d.SpeedMT {
			slow = append(slow, fmt.Sprintf("%s: rated %d MT/s, running %d MT/s", d.Locator, d.SpeedMT, d.ConfiguredMT))
		}
	}
	if len(slow) > 0 {
		s.add(model.Finding{
			ID: "memory.speed_below_rated", Severity: model.Info,
			Title: model.Tf("%d DIMM(s) run below their rated speed", "%d thanh RAM chạy dưới tốc độ danh định", len(slow)),
			Detail: model.T("This is normal in most servers: the CPU's memory controller may support a lower speed than the DIMM (e.g. Xeon Silver/Bronze), two DIMMs per channel lower the speed, mixed DIMMs run at the slowest one, and power-saving BIOS profiles cap it. It is not a fault.",
				"Điều này bình thường ở hầu hết máy chủ: bộ điều khiển bộ nhớ của CPU có thể chỉ hỗ trợ tốc độ thấp hơn thanh RAM (vd. Xeon Silver/Bronze), cắm 2 thanh mỗi kênh làm giảm tốc độ, RAM lẫn lộn chạy theo thanh chậm nhất, và profile BIOS tiết kiệm điện cũng giới hạn tốc độ. Đây không phải lỗi."),
			Evidence: units.Evidence(slow, 10),
		})
	}
}

func keys(m map[string]int) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, fmt.Sprintf("%s ×%d", k, m[k]))
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

// ---- usage ----

type usage struct {
	total, avail, swapTotal, swapUsed uint64
	commitPct                         float64 // Windows: committed / commit limit
	oom                               uint64
	some, full                        PSI
	evidence                          []string
}

func (s *state) usageLinux(mi meminfo) {
	sec := s.b.Get("memory.meminfo")
	if sec == nil {
		return
	}
	if mi["MemTotal"] == 0 {
		s.cov("memory.usage", nameUsage, model.CovFailed,
			model.Tf("/proc/meminfo could not be read: %s", "Không đọc được /proc/meminfo: %s", firstNonEmpty(oneLine(sec.Err), sec.Missing, "empty")), model.Text{})
		return
	}
	u := usage{total: mi["MemTotal"], swapTotal: mi["SwapTotal"]}
	if v, ok := mi["MemAvailable"]; ok {
		u.avail = v
	} else { // kernels before 3.14 (CentOS 6): rough estimate
		u.avail = mi["MemFree"] + mi["Buffers"] + mi["Cached"]
	}
	if mi["SwapTotal"] >= mi["SwapFree"] {
		u.swapUsed = mi["SwapTotal"] - mi["SwapFree"]
	}
	vm := parseVmstat(s.b.Get("memory.vmstat").Text())
	u.oom = vm["oom_kill"]
	u.some, u.full = parsePSI(s.b.Get("memory.psi").Text())
	u.evidence = []string{
		fmt.Sprintf("MemTotal %s, MemAvailable %s", units.IEC(u.total), units.IEC(u.avail)),
		fmt.Sprintf("SwapTotal %s, swap used %s", units.IEC(u.swapTotal), units.IEC(u.swapUsed)),
	}
	if u.some.Ok {
		u.evidence = append(u.evidence, fmt.Sprintf("PSI memory some avg10=%.2f avg60=%.2f avg300=%.2f; full avg10=%.2f avg60=%.2f avg300=%.2f",
			u.some.Avg10, u.some.Avg60, u.some.Avg300, u.full.Avg10, u.full.Avg60, u.full.Avg300))
		s.facts.PSISome, s.facts.PSIFull = &u.some, &u.full
	}
	if _, ok := vm["pswpin"]; ok {
		u.evidence = append(u.evidence, fmt.Sprintf("since boot: pswpin %d, pswpout %d, oom_kill %d", vm["pswpin"], vm["pswpout"], vm["oom_kill"]))
	}
	s.facts.OOMKills = u.oom
	s.cov("memory.usage", nameUsage, model.CovRan, model.Text{}, model.Text{})
	s.usageFindings(u)

	if hc := mi["HardwareCorrupted"]; hc > 0 {
		s.add(model.Finding{
			ID: "memory.pages_retired", Severity: model.Warn, Target: "HardwareCorrupted",
			Title: model.Tf("The kernel retired %s of RAM after memory errors", "Kernel đã loại bỏ %s RAM do lỗi bộ nhớ", units.IEC(hc)),
			Detail: model.T("/proc/meminfo HardwareCorrupted is not zero: since boot the kernel took memory pages out of use because the hardware reported errors in them (uncorrected errors, or pages with repeated corrected errors). This is a hardware event on a DIMM.",
				"HardwareCorrupted trong /proc/meminfo khác 0: từ lúc khởi động kernel đã ngừng dùng một số trang RAM vì phần cứng báo lỗi trên đó (lỗi không sửa được, hoặc trang bị lỗi đã sửa lặp lại). Đây là sự kiện phần cứng trên thanh RAM."),
			Action: model.T("Find the DIMM in the ECC findings above or in the BMC event log and plan its replacement.",
				"Xác định thanh RAM qua các mục lỗi ECC ở trên hoặc log sự kiện BMC và lên kế hoạch thay."),
			Evidence: []string{fmt.Sprintf("HardwareCorrupted: %d kB", hc/1024)},
		})
	}
}

func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func (s *state) usageFindings(u usage) {
	s.facts.AvailableBytes, s.facts.SwapTotal, s.facts.SwapUsed = u.avail, u.swapTotal, u.swapUsed
	availPct := pct(u.avail, u.total)
	swapPct := pct(u.swapUsed, u.swapTotal)
	low := availPct < lowAvailPct
	heavySwap := u.swapTotal > 0 && swapPct >= heavySwapPct
	psiHigh := (u.some.Ok && u.some.Avg60 >= psiSomeWarn60 && u.some.Avg300 >= psiSomeWarn300) || (u.some.Ok && u.full.Avg60 >= psiFullWarn60)
	commitHigh := u.commitPct >= 90
	switch {
	case psiHigh && availPct >= 2*lowAvailPct:
		// Stalls although plenty of RAM is free: a memory limit on one
		// service (cgroup memory.max) is being hit, not the server's RAM.
		s.add(model.Finding{
			ID: "memory.pressure", Severity: model.Warn,
			Title: model.Tf("Processes are stalling on memory although %s is free", "Tiến trình bị nghẽn bộ nhớ dù còn trống %s", units.IEC(u.avail)),
			Detail: model.Tf("Tasks were stalled waiting for memory %.0f%% of the last minute (PSI), yet %.0f%% of the RAM is available. This usually means a service or container is hitting its own memory limit (systemd MemoryMax, Docker/Kubernetes memory limit, cgroup memory.max) and is being slowed down or OOM-killed. It is not a hardware fault.",
				"Tiến trình phải chờ bộ nhớ %.0f%% thời gian trong phút vừa qua (PSI), trong khi vẫn còn trống %.0f%% RAM. Thường là một dịch vụ hoặc container đang chạm giới hạn RAM riêng của nó (systemd MemoryMax, giới hạn memory của Docker/Kubernetes, cgroup memory.max) nên bị chậm hoặc bị OOM kill. Đây không phải lỗi phần cứng.", u.some.Avg60, availPct),
			Action: model.T("Find the cgroup under pressure (systemd-cgtop, or the memory.pressure files under /sys/fs/cgroup) and raise its memory limit or reduce its usage.",
				"Tìm cgroup đang bị áp lực (systemd-cgtop, hoặc các tệp memory.pressure trong /sys/fs/cgroup) rồi tăng giới hạn RAM hoặc giảm mức dùng của nó."),
			Evidence: u.evidence,
		})
	case (low && (heavySwap || u.swapTotal == 0 || u.oom > 0 || commitHigh)) || psiHigh:
		why := []string{}
		whyVI := []string{}
		if low {
			why = append(why, fmt.Sprintf("only %s (%.0f%%) of %s is available", units.IEC(u.avail), availPct, units.IEC(u.total)))
			whyVI = append(whyVI, fmt.Sprintf("chỉ còn %s (%.0f%%) trên tổng %s", units.IEC(u.avail), availPct, units.IEC(u.total)))
		}
		if heavySwap {
			why = append(why, fmt.Sprintf("%.0f%% of swap is in use", swapPct))
			whyVI = append(whyVI, fmt.Sprintf("đang dùng %.0f%% swap", swapPct))
		}
		if commitHigh {
			why = append(why, fmt.Sprintf("%.0f%% of the commit limit is used", u.commitPct))
			whyVI = append(whyVI, fmt.Sprintf("đã dùng %.0f%% commit limit", u.commitPct))
		}
		if psiHigh {
			why = append(why, fmt.Sprintf("tasks were stalled waiting for memory %.0f%% of the last minute", u.some.Avg60))
			whyVI = append(whyVI, fmt.Sprintf("tiến trình phải chờ bộ nhớ %.0f%% thời gian trong phút vừa qua", u.some.Avg60))
		}
		if u.oom > 0 {
			why = append(why, fmt.Sprintf("the OOM killer ran %d time(s) since boot", u.oom))
			whyVI = append(whyVI, fmt.Sprintf("OOM killer đã chạy %d lần từ lúc khởi động", u.oom))
		}
		s.add(model.Finding{
			ID: "memory.pressure", Severity: model.Warn,
			Title: model.T("RAM is not enough for the workload: the server is short of memory", "RAM không đủ cho tải hiện tại: máy đang thiếu bộ nhớ"),
			Detail: model.Text{
				EN: "Measured: " + strings.Join(why, "; ") + ". When RAM runs out the server swaps to disk and becomes very slow, and the kernel kills processes (OOM). This is a capacity problem, not a hardware fault.",
				VI: "Đo được: " + strings.Join(whyVI, "; ") + ". Khi hết RAM, máy phải dùng swap trên ổ đĩa nên chạy rất chậm, và kernel sẽ kill tiến trình (OOM). Đây là vấn đề dung lượng, không phải lỗi phần cứng.",
			},
			Action: model.T("Find what uses the memory (top/htop sorted by memory, ps aux --sort=-rss | head; Task Manager on Windows). Reduce it (limits for databases/caches, fewer workers, fix leaks) or add RAM. Do not just add swap: it hides the problem and keeps the server slow.",
				"Tìm tiến trình chiếm RAM (top/htop sắp theo bộ nhớ, ps aux --sort=-rss | head; Task Manager trên Windows). Giảm mức dùng (giới hạn RAM cho database/cache, giảm số worker, sửa rò rỉ bộ nhớ) hoặc lắp thêm RAM. Đừng chỉ tăng swap: chỉ che giấu vấn đề và máy vẫn chậm."),
			Evidence: u.evidence,
		})
	case low:
		s.add(model.Finding{
			ID: "memory.low_available", Severity: model.Info,
			Title: model.Tf("Little RAM left: %s (%.0f%%) of %s available", "Còn ít RAM: còn %s (%.0f%%) trên tổng %s", units.IEC(u.avail), availPct, units.IEC(u.total)),
			Detail: model.T("The server is not swapping heavily or stalling yet, but there is little headroom for load peaks.",
				"Máy chưa phải dùng nhiều swap hay bị nghẽn, nhưng không còn nhiều dư địa khi tải tăng đột biến."),
			Evidence: u.evidence,
		})
	default:
		if u.oom > 0 {
			s.add(model.Finding{
				ID: "memory.oom_kills", Severity: model.Info,
				Title: model.Tf("The kernel killed processes for lack of memory %d time(s) since boot", "Kernel đã kill tiến trình vì thiếu RAM %d lần từ lúc khởi động", u.oom),
				Detail: model.T("Memory is fine now, but it ran out at some point since boot (OOM killer). The log section shows which processes were killed.",
					"Hiện tại RAM ổn, nhưng đã có lúc hết RAM từ lúc khởi động (OOM killer). Phần log cho biết tiến trình nào bị kill."),
				Evidence: u.evidence,
			})
			return
		}
		s.add(okF("memory.usage_ok",
			fmt.Sprintf("RAM usage normal: %s available of %s", units.IEC(u.avail), units.IEC(u.total)),
			fmt.Sprintf("Mức dùng RAM bình thường: còn trống %s trên tổng %s", units.IEC(u.avail), units.IEC(u.total))))
	}
}

// ---- memtester (Linux) ----

func (s *state) memtestLinux() {
	sec := s.b.Get("memory.memtest")
	if sec == nil {
		return
	}
	switch {
	case sec.Skipped == "disabled" && s.virtual:
		// On a VM or in a container memtester would only exercise memory
		// the host hands out: test the host instead.
		s.cov("memory.memtest", nameMemtest, model.CovSkipped,
			model.T("Not requested, and of little use here: memtester can only test the memory the host gives this machine.",
				"Không yêu cầu, và cũng ít ý nghĩa ở đây: memtester chỉ test được phần RAM máy host cấp cho máy này."),
			hint.Virtual(s.env))
		return
	case sec.Skipped == "disabled":
		s.covCmd("memory.memtest", nameMemtest, model.CovSkipped,
			model.T("Not requested: memtester runs only on request, because it loads the server and takes several minutes per GB.",
				"Không yêu cầu: memtester chỉ chạy khi được yêu cầu vì nó làm nặng máy và mất vài phút cho mỗi GB."),
			model.T("Run the memory test as root during a maintenance window, with a size the server can spare (it needs twice that much free RAM).",
				"Chạy test RAM với quyền root trong giờ bảo trì, với dung lượng máy có thể dành ra (cần lượng RAM trống gấp đôi)."),
			s.memtestCmd("2G"))
		return
	case sec.Skipped == "low-memory":
		cmd := ""
		if mb := s.facts.AvailableBytes >> 20 / 4 / 64 * 64; mb >= 64 { // a quarter of MemAvailable, in 64 MiB steps
			cmd = s.memtestCmd(strconv.FormatUint(mb, 10) + "M")
		}
		s.covCmd("memory.memtest", nameMemtest, model.CovSkipped,
			model.Tf("Not enough free RAM: memtester needs at least twice the test size available (MemAvailable %s).", "Không đủ RAM trống: memtester cần lượng RAM trống ít nhất gấp đôi dung lượng test (MemAvailable %s).", units.IEC(s.facts.AvailableBytes)),
			model.T("Use a smaller test size, or stop services during a maintenance window.", "Dùng dung lượng test nhỏ hơn, hoặc dừng bớt dịch vụ trong giờ bảo trì."), cmd)
		return
	case sec.Skipped == "not-root":
		s.covCmd("memory.memtest", nameMemtest, model.CovSkipped,
			model.T("Needs root: without it memtester cannot lock that much memory and would test far less than asked.", "Cần quyền root: không có root thì memtester không khoá được lượng RAM đó và sẽ test ít hơn nhiều so với yêu cầu."),
			hint.RunAsRoot(s.env), "sudo diagward check --memtest "+firstNonEmpty(s.b.Options.Memtest, "2G"))
		return
	case sec.Skipped != "":
		s.cov("memory.memtest", nameMemtest, model.CovSkipped, hint.Virtual(s.env), model.Text{})
		return
	case sec.Missing != "":
		fix, cmd := hint.InstallFix(s.env, "memtester")
		s.covCmd("memory.memtest", nameMemtest, model.CovSkipped, hint.Missing("memtester"), fix, cmd)
		return
	}
	m := parseMemtest(sec.Out, sec.Err, sec.RC)
	if sec.Timeout && !m.Killed() {
		m.RC = 124
	}
	s.facts.Memtest = &m
	size := firstNonEmpty(m.Size, "?")
	if m.TestedMB > 0 {
		size = units.IEC(uint64(m.TestedMB) << 20)
	}
	failed := len(m.Failed) > 0 || len(m.Failures) > 0 || (!m.Killed() && m.RC&6 != 0)
	switch {
	case failed:
		s.cov("memory.memtest", nameMemtest, model.CovRan, model.Text{}, model.Text{})
		tests := strings.Join(m.Failed, ", ")
		if tests == "" {
			tests = "?"
		}
		addr, addrVI := "", ""
		if contains(m.Failed, "Stuck Address") || (!m.Killed() && m.RC&2 != 0) {
			addr, addrVI = " (stuck address: possible bad address line)", " (stuck address: có thể hỏng đường địa chỉ)"
		}
		ev := append([]string{fmt.Sprintf("memtester %s, 1 loop: failed %s; exit code %d", size, tests, m.RC)}, m.Failures...)
		s.add(model.Finding{
			ID: "memory.memtest_failed", Severity: model.Crit, Target: "memtester " + size,
			Title: model.Text{EN: fmt.Sprintf("memtester found RAM errors: %s failed%s", tests, addr), VI: fmt.Sprintf("memtester phát hiện lỗi RAM: test %s thất bại%s", tests, addrVI)},
			Detail: model.Tf("memtester wrote patterns to %s of RAM and read back different values. Software cannot cause this: a DIMM (or, less often, the CPU's memory controller or an unstable overclock/voltage setting) is faulty.",
				"memtester ghi mẫu dữ liệu vào %s RAM và đọc lại thì giá trị bị sai. Phần mềm không thể gây ra lỗi này: có thanh RAM hỏng (ít gặp hơn là bộ điều khiển bộ nhớ của CPU hoặc cấu hình ép xung/điện áp không ổn định).", size),
			Action: model.T("Back up important data. Find the DIMM: check the ECC counters and the BMC event log, or run the vendor's diagnostics / Memtest86+ from boot media, or test the DIMMs in halves. Replace the faulty DIMM and run the test again.",
				"Sao lưu dữ liệu quan trọng. Xác định thanh RAM lỗi: xem bộ đếm ECC và log sự kiện BMC, hoặc chạy công cụ chẩn đoán của hãng / Memtest86+ từ USB boot, hoặc test từng nửa số thanh. Thay thanh RAM lỗi rồi test lại."),
			Evidence: units.Evidence(ev, 10),
		})
	case m.Killed():
		passed := firstNonEmpty(strings.Join(m.Passed, ", "), "none")
		passedVI := firstNonEmpty(strings.Join(m.Passed, ", "), "chưa có")
		ranS := sec.MS / 1000
		if sec.MS > 0 && m.TimeoutS > 0 && sec.MS < m.TimeoutS*900 {
			// Stopped well before the time limit: killed by a signal, in
			// practice the OOM killer (the RAM was needed elsewhere).
			s.cov("memory.memtest", nameMemtest, model.CovPartial,
				model.Tf("memtester was killed after %d s, before its %d s limit.", "memtester bị dừng sau %d giây, trước giới hạn %d giây.", ranS, m.TimeoutS), model.Text{})
			s.add(model.Finding{
				ID: "memory.memtest_incomplete", Severity: model.Info, Target: "memtester " + size,
				Title: model.Tf("memtester was killed after %d s (exit code %d); no errors until then", "memtester bị dừng sau %d giây (mã thoát %d); đến lúc đó chưa thấy lỗi", ranS, m.RC),
				Detail: model.Text{
					EN: "It was stopped by a signal well before its time limit, usually by the kernel's OOM killer because other programs needed the memory. Passed before it stopped: " + passed + ". Run it again with a smaller size (diagward check --memtest 1G) when the server is quiet.",
					VI: "Tiến trình bị dừng bởi tín hiệu (signal) trước giới hạn thời gian, thường do OOM killer của kernel vì chương trình khác cần RAM. Các test đã qua trước khi dừng: " + passedVI + ". Chạy lại với dung lượng nhỏ hơn (diagward check --memtest 1G) lúc máy rảnh.",
				},
			})
			break
		}
		s.cov("memory.memtest", nameMemtest, model.CovPartial,
			model.Tf("memtester did not finish within %d s.", "memtester chưa chạy xong trong %d giây.", m.TimeoutS), model.Text{})
		s.add(model.Finding{
			ID: "memory.memtest_incomplete", Severity: model.Info, Target: "memtester " + size,
			Title: model.Tf("memtester did not finish (stopped after %d s); no errors until then", "memtester chưa chạy xong (dừng sau %d giây); đến lúc đó chưa thấy lỗi", m.TimeoutS),
			Detail: model.Text{
				EN: "Passed before it stopped: " + passed + ". Run it again with a smaller size (diagward check --memtest 1G) or a longer limit (--timeout, in seconds).",
				VI: "Các test đã qua trước khi dừng: " + passedVI + ". Chạy lại với dung lượng nhỏ hơn (diagward check --memtest 1G) hoặc thời gian chờ dài hơn (--timeout, tính bằng giây).",
			},
		})
	case m.RC&1 != 0 && len(m.Passed) == 0:
		s.cov("memory.memtest", nameMemtest, model.CovFailed,
			model.Tf("memtester could not start: %s", "memtester không chạy được: %s", firstNonEmpty(oneLine(sec.Err), fmt.Sprintf("exit code %d", m.RC))), model.Text{})
	case m.Done || len(m.Passed) > 0:
		s.cov("memory.memtest", nameMemtest, model.CovRan, model.Text{}, model.Text{})
		lock := ""
		lockVI := ""
		if m.Unlocked || !m.Locked {
			lock, lockVI = ", memory not locked: less reliable", ", không khoá được bộ nhớ: kết quả kém tin cậy hơn"
		}
		f := okF("memory.memtest_ok",
			fmt.Sprintf("memtester passed: %s tested, %d tests, no errors%s", size, len(m.Passed), lock),
			fmt.Sprintf("memtester đạt: đã test %s, %d bài test, không có lỗi%s", size, len(m.Passed), lockVI))
		f.Detail = model.T("memtester only tests the amount of RAM it was given, from inside the running system; it does not prove that the rest of the memory is healthy.",
			"memtester chỉ test đúng lượng RAM được giao, khi hệ thống đang chạy; không chứng minh phần RAM còn lại là tốt.")
		s.add(f)
	default:
		s.cov("memory.memtest", nameMemtest, model.CovFailed,
			model.Tf("memtester output was not understood (exit code %d): %s", "Không hiểu kết quả memtester (mã thoát %d): %s", m.RC, firstNonEmpty(oneLine(sec.Err), "no output")), model.Text{})
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ---- tables ----

func (s *state) tables(edac bool) {
	if len(s.dimms) > 0 {
		t := model.Table{
			ID:    "memory.dimms",
			Title: model.T("Memory modules (DIMMs)", "Thanh RAM (DIMM)"),
			Columns: []model.Text{
				model.T("Slot", "Khe"), model.T("Size", "Dung lượng"), model.T("Type", "Loại"),
				model.T("Speed MT/s (rated/running)", "Tốc độ MT/s (danh định/thực tế)"), model.T("Manufacturer", "Hãng"),
				model.T("Part number", "Mã linh kiện"), model.T("Serial", "Serial"),
				model.T("Corrected errors", "Lỗi đã sửa"), model.T("Uncorrected errors", "Lỗi không sửa được"), model.T("Status", "Trạng thái"),
			},
		}
		hidden := 0
		for _, d := range s.dimms {
			if !d.Populated {
				if s.virtual {
					hidden++
					continue
				}
				t.Rows = append(t.Rows, model.NewRow(model.OK, d.Name(), "", "", "", "", "", "", "", "", model.T("empty", "trống")))
				continue
			}
			st, txt := model.OK, model.T("ok", "ổn")
			switch {
			case d.UE > 0:
				st, txt = model.Crit, model.T("uncorrected errors", "lỗi không sửa được")
			case d.CE > 0:
				st, txt = model.Info, model.T("corrected errors", "có lỗi đã sửa")
			}
			for _, f := range s.res.Findings {
				if f.Part != nil && f.Part.Kind == "dimm" && f.Part.Serial == d.Serial && f.Part.Location == dimmPart(d).Location && f.Severity > st {
					st = f.Severity
				}
			}
			typ := strings.TrimSpace(d.Type + " " + shortDetail(d.TypeDetail))
			sp := ""
			switch {
			case d.SpeedMT > 0 && d.ConfiguredMT > 0:
				sp = fmt.Sprintf("%d/%d", d.SpeedMT, d.ConfiguredMT)
			case d.SpeedMT > 0:
				sp = strconv.Itoa(d.SpeedMT)
			}
			t.Rows = append(t.Rows, model.NewRow(st,
				d.Name(), iec(d.SizeBytes), units.Words(typ), sp, d.Manufacturer, d.PartNumber, d.Serial, cnt(d.CE), cnt(d.UE), txt,
			))
		}
		if hidden > 0 {
			t.Note = model.Tf("%d empty virtual slot(s) not shown.", "Ẩn %d khe RAM ảo trống.", hidden)
		} else if edac && !s.anyJoined() {
			t.Note = model.T("EDAC labels do not match the slot names; the per-DIMM error counters are in the ECC table.", "Nhãn EDAC không khớp với tên khe; số lỗi theo từng thanh nằm ở bảng ECC.")
		}
		s.res.Tables = append(s.res.Tables, t)
	}
	if len(s.facts.EDAC) > 0 && !s.anyJoined() {
		t := model.Table{
			ID:    "memory.edac",
			Title: model.T("ECC error counters (EDAC)", "Bộ đếm lỗi ECC (EDAC)"),
			Columns: []model.Text{
				model.T("Controller", "Bộ điều khiển"), model.T("DIMM (EDAC label)", "Thanh RAM (nhãn EDAC)"), model.T("Location", "Vị trí"),
				model.T("Size", "Dung lượng"), model.T("Corrected errors", "Lỗi đã sửa"), model.T("Uncorrected errors", "Lỗi không sửa được"),
			},
		}
		for _, mc := range s.facts.EDAC {
			ctl := strings.TrimSpace(mc.Name + " " + mc.Ctl)
			for _, d := range mc.DIMMs {
				st := model.OK
				if d.UE > 0 {
					st = model.Crit
				} else if d.CE > 0 {
					st = model.Info
				}
				size := ""
				if d.SizeMB > 0 {
					size = units.IEC(uint64(d.SizeMB) << 20)
				}
				t.Rows = append(t.Rows, model.NewRow(st, ctl, d.Name(), edacLocation(d.Location), size, cnt(d.CE), cnt(d.UE)))
			}
			if len(mc.DIMMs) == 0 || mc.CENoInfo > 0 || mc.UENoInfo > 0 {
				st := model.OK
				if max(mc.UENoInfo, 0) > 0 || (len(mc.DIMMs) == 0 && mc.UE > 0) {
					st = model.Crit
				}
				ce, ue := mc.CENoInfo, mc.UENoInfo
				label := model.T("(DIMM unknown)", "(không rõ thanh RAM)")
				if len(mc.DIMMs) == 0 {
					ce, ue, label = mc.CE, mc.UE, model.T("(whole controller)", "(cả bộ điều khiển)")
				}
				t.Rows = append(t.Rows, model.NewRow(st, ctl, label, "", "", cnt(ce), cnt(ue)))
			}
		}
		s.res.Tables = append(s.res.Tables, t)
	}
	s.summaryTable()
}

func (s *state) anyJoined() bool {
	for _, d := range s.dimms {
		if d.EDACLabel != "" {
			return true
		}
	}
	return false
}

func (s *state) summaryTable() {
	f := s.facts
	t := model.Table{
		ID:      "memory.summary",
		Title:   model.T("Memory summary", "Tổng quan bộ nhớ"),
		Columns: []model.Text{model.T("Item", "Mục"), model.T("Value", "Giá trị")},
	}
	row := func(k model.Text, v any, st model.Severity) {
		switch x := v.(type) {
		case string:
			if x == "" {
				return
			}
		case model.Text:
			if x.IsZero() {
				return
			}
		}
		t.Rows = append(t.Rows, model.NewRow(st, k, v))
	}
	pop, slots := 0, 0
	for _, d := range s.dimms {
		slots++
		if d.Populated {
			pop++
		}
	}
	// Windows lists only populated modules; the arrays know the slot count.
	arraySlots := 0
	for _, a := range s.arrays {
		arraySlots += a.Devices
	}
	slots = max(slots, arraySlots)
	if pop > 0 && !s.virtual {
		row(model.T("Installed", "Đã lắp"), model.Tf("%s, %d/%d slots", "%s, %d/%d khe", iec(f.InstalledBytes), pop, slots), model.OK)
	}
	row(model.T("Visible to the OS", "Hệ điều hành thấy"), iec(f.VisibleBytes), model.OK)
	if f.VisibleBytes > 0 {
		row(model.T("Available", "Còn trống"), fmt.Sprintf("%s (%.0f%%)", units.IEC(f.AvailableBytes), pct(f.AvailableBytes, f.VisibleBytes)), model.OK)
	}
	if f.SwapTotal > 0 {
		row(model.T("Swap / page file used", "Swap / page file đang dùng"), model.Tf("%s of %s", "%s trên %s", units.IEC(f.SwapUsed), units.IEC(f.SwapTotal)), model.OK)
	}
	if !s.virtual && s.eccShort != "" {
		row(model.T("Error correction", "Sửa lỗi (ECC)"), eccCell(s.eccShort), model.OK)
	}
	for i, a := range s.arrays {
		if a.MaxCapacity != "" && !s.virtual {
			row(model.Tf("Max capacity (array %d)", "Dung lượng tối đa (mảng %d)", i+1), model.Tf("%s, %d slots", "%s, %d khe", a.MaxCapacity, a.Devices), model.OK)
		}
	}
	if len(f.EDAC) > 0 {
		var ctl []string
		for _, mc := range f.EDAC {
			ctl = append(ctl, strings.TrimSpace(mc.Name+" "+mc.Ctl))
		}
		row(model.T("EDAC controllers", "Bộ điều khiển EDAC"), strings.Join(ctl, "; "), model.OK)
	}
	if f.PSISome != nil {
		row(model.T("Memory pressure (PSI some avg60/avg300)", "Áp lực bộ nhớ (PSI some avg60/avg300)"), fmt.Sprintf("%.2f%% / %.2f%%", f.PSISome.Avg60, f.PSISome.Avg300), model.OK)
	}
	if len(t.Rows) > 0 {
		s.res.Tables = append(s.res.Tables, t)
	}
}

// eccCell is the error-correction value of the summary table (SMBIOS
// "Error Correction Type": "Multi-bit ECC", "None", "CRC"...) in both
// languages.
func eccCell(s string) model.Text {
	if rest, ok := strings.CutPrefix(s, "None ("); ok {
		return model.T(s, "Không có ("+rest)
	}
	return units.Words(s, map[string]string{
		"multi-bit ecc":  "ECC đa bit",
		"single-bit ecc": "ECC một bit",
		"ecc + non-ecc":  "lẫn ECC và không ECC",
		"none":           "không có",
		"parity":         "parity",
	})
}

// edacLocation is an EDAC dimm_location ("channel 0 slot 0", "branch 0
// channel 1 slot 0", "csrow 2 channel 0") in both languages.
func edacLocation(s string) model.Text {
	r := strings.NewReplacer("channel", "kênh", "slot", "khe", "branch", "nhánh")
	return model.T(s, r.Replace(s))
}

func shortDetail(td string) string {
	l := strings.ToLower(td)
	switch {
	case strings.Contains(l, "lrdimm"), strings.Contains(l, "load reduced"):
		return "LRDIMM"
	case strings.Contains(l, "registered"):
		return "RDIMM"
	case strings.Contains(l, "unbuffered"):
		return "UDIMM"
	}
	return ""
}

func cnt(n int64) string {
	if n < 0 {
		return ""
	}
	return strconv.FormatInt(n, 10)
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
