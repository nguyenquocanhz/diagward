package logs

import (
	"regexp"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// persistFix is the fix text for a journal that forgets everything at reboot
// (the command itself goes in Coverage.Cmd, see persistCmd).
var persistFix = model.T(
	"Make the journal persistent (create /var/log/journal and restart journald) so the next report also covers earlier boots.",
	"Bật lưu journal lâu dài (tạo thư mục /var/log/journal rồi khởi động lại journald) để lần sau báo cáo xem được cả các lần khởi động trước.")

// persistCmd is the copy-paste command that makes the journal persistent.
func persistCmd(env model.Env) string {
	if env.Root {
		return "mkdir -p /var/log/journal && systemctl restart systemd-journald"
	}
	return "sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald"
}

// windowStart is the oldest time the report looks at (with an hour of slack).
func windowStart(env model.Env) time.Time {
	days := env.SinceDays
	if days <= 0 {
		days = 7
	}
	if env.Now.IsZero() {
		return time.Time{}
	}
	return env.Now.Add(-time.Duration(days)*24*time.Hour - time.Hour)
}

func inWindow(t time.Time, env model.Env) bool {
	if t.IsZero() {
		return true // no timestamp: the collector already limited it
	}
	ws := windowStart(env)
	return ws.IsZero() || !t.Before(ws)
}

// buildCtx learns device names from the whole log.
func buildCtx(lines []logLine) *matchCtx {
	ctx := &matchCtx{hctl: map[string]string{}, ata: map[string]*model.Part{}, usbHosts: map[string]bool{}, removable: map[string]bool{}}
	for _, l := range lines {
		if l.Tag != "kernel" {
			continue
		}
		if m := reUSBHost.FindStringSubmatch(l.Msg); m != nil {
			ctx.usbHosts[m[1]] = true
		}
		if m := reRemovable.FindStringSubmatch(l.Msg); m != nil {
			ctx.removable[m[1]] = true
		}
		if m := reHCTL.FindStringSubmatch(l.Msg); m != nil {
			if d := reSdName.FindStringSubmatch(l.Msg); d != nil {
				ctx.hctl[m[1]] = d[1]
			}
		}
		if m := reATAIdent.FindStringSubmatch(l.Msg); m != nil {
			ctx.ata[m[1]] = &model.Part{Kind: "disk", Model: strings.TrimSpace(m[2]), Firmware: m[3], Location: m[1]}
		}
	}
	return ctx
}

// matchLines runs the pattern library over the lines.
func matchLines(lines []logLine, ctx *matchCtx, now time.Time) *grouper {
	gr := newGrouper(now)
	resets := map[string]time.Time{}
	vfio := map[*group]bool{}
	var throttles []time.Time
	for _, l := range lines {
		if l.Tag == "kernel" && !l.T.IsZero() && reThrottle.MatchString(l.Msg) {
			throttles = append(throttles, l.T)
		}
	}
	for i, l := range lines {
		tag := l.Tag
		if tag == "kernel" {
			if m := reMCEBank.FindStringSubmatch(l.Msg); m != nil {
				if uc, ok := mcStatusUC(m[3]); ok {
					sp := spMCECorr
					if uc {
						sp = spMCEUncorr
					}
					gr.add(sp, "CPU", l.T, l.Raw, true)
				}
				continue
			}
			if m := reGHESSev.FindStringSubmatch(l.Msg); m != nil {
				sp, target := ghesRule(lines, i, m)
				gr.add(sp, target, l.T, l.Raw, true)
				continue
			}
		}
		if tag == "smartd" {
			if m := reSmartdReset.FindStringSubmatch(l.Msg); m != nil {
				if l.T.After(resets[m[1]]) {
					resets[m[1]] = l.T
				}
				continue
			}
		}
		for ri := range rules {
			ru := &rules[ri]
			if ruleTag(ru.tag) != tag {
				continue
			}
			m := ru.re.FindStringSubmatch(l.Msg)
			if m == nil {
				continue
			}
			if ru.skip != nil && ru.skip(m, l) {
				break
			}
			if ru.sp == spMCECorr && near(l.T, throttles, 5*time.Second) {
				// Kernels up to 5.x log every thermal throttle event as a
				// machine check record (therm_throt.c, mce_log_therm_throt_event),
				// so "Machine check events logged" right after "temperature
				// above threshold" is the throttle, not a CPU/RAM error.
				gr.add(spThrottle, "CPU", l.T, l.Raw, false)
				break
			}
			target := ""
			if ru.target != nil {
				target = ru.target(m, l, ctx)
			}
			if target == "" && ru.sp.Comp == model.CompDisk {
				var notDisk bool
				if target, notDisk = scsiLookback(lines, i); notDisk {
					break
				}
			}
			g := gr.add(ru.sp, target, l.T, l.Raw, !ru.evidence)
			if g.part == nil {
				g.part = partFor(ru.sp, target, ctx)
			}
			if (ru.sp == spPCIeCorr || ru.sp == spPCIeNonFatal || ru.sp == spPCIeFatal) && len(m) > 1 && m[1] == "vfio-pci" {
				vfio[g] = true
			}
			break
		}
	}
	// A device bound to vfio-pci is passed through to a virtual machine
	// (Proxmox/KVM). Guests resetting or probing it make it log corrected
	// and Unsupported Request errors without a hardware fault (the vfio-pci
	// UnsupReq lines of the Unraid thread in testdata/SOURCES.md): never
	// Crit, corrected ones are only listed.
	for g := range vfio {
		switch g.spec {
		case spPCIeCorr:
			g.limit(model.Info, vfioNote, model.Text{})
		case spPCIeNonFatal:
			g.limit(model.Warn, vfioNote, model.Text{})
		default:
			g.note = joinText(g.note, vfioNote)
		}
	}
	// A smartd pending-sector warning that smartd itself later cleared
	// ("No more ... warning condition reset") is history: the sector was
	// rewritten or reallocated. Keep it as a Warn, not a Crit.
	for _, g := range gr.list() {
		if g.spec != spSmartPending {
			continue
		}
		if rt, ok := resets[g.target]; ok && !rt.Before(g.last) {
			g.limit(model.Warn, model.Tf("smartd reported the condition cleared at %s.", "smartd đã báo hết lỗi này lúc %s.", fmtTime(rt)), model.Text{})
		}
	}
	return gr
}

// ghesRule classifies an APEI/GHES "event severity" line from the
// section_type line that follows it in the same record.
func ghesRule(lines []logLine, i int, m []string) (*spec, string) {
	rec, sev := m[1], m[2]
	section, device := "", ""
	for j := i + 1; j < len(lines) && j <= i+12; j++ {
		msg := lines[j].Msg
		if !strings.Contains(msg, "[Hardware Error]") {
			break
		}
		if rec != "" && !strings.Contains(msg, "{"+rec+"}") {
			break
		}
		if reGHESSev.MatchString(msg) {
			break // next record
		}
		if s := reGHESSection.FindStringSubmatch(msg); s != nil && section == "" {
			section = strings.ToLower(s[1])
			continue
		}
		// CPER PCIe sections name the device: "device_id: 0000:01:00.0"
		// (drivers/firmware/efi/cper.c, cper_print_pcie).
		if d := reGHESDevice.FindStringSubmatch(msg); d != nil && device == "" {
			device = d[1]
		}
	}
	corrected := sev == "corrected"
	switch {
	case strings.Contains(section, "memory"):
		if corrected {
			return spMemCE, "memory"
		}
		return spMemUE, "memory"
	case strings.Contains(section, "pcie"):
		if device == "" {
			device = "PCIe"
		}
		if corrected {
			return spPCIeCorr, device
		}
		if sev == "fatal" {
			return spPCIeFatal, device
		}
		return spPCIeNonFatal, device
	}
	if corrected {
		return spMCECorr, "CPU"
	}
	return spMCEUncorr, "CPU"
}

// partFor gives the part to replace when the target is a disk.
func partFor(sp *spec, target string, ctx *matchCtx) *model.Part {
	if sp.Comp != model.CompDisk || target == "" {
		return nil
	}
	if p, ok := ctx.ata[target]; ok {
		cp := *p
		return &cp
	}
	if dev, ctrl, ok := strings.Cut(target, " ["); ok && strings.HasPrefix(target, "/dev/") {
		// smartd behind a RAID controller: "/dev/bus/0 [megaraid_disk_03]".
		// Every disk of that controller shares /dev/bus/0, so do not let
		// diag match on it (it would attach another disk's serial).
		return &model.Part{Kind: "disk", Location: strings.TrimSuffix(ctrl, "]") + " on " + dev}
	}
	if strings.HasPrefix(target, "/dev/") {
		return &model.Part{Kind: "disk", Location: nvmeNamespace(target)}
	}
	if reNVMeCtrl.MatchString(target) {
		return &model.Part{Kind: "disk", Location: nvmeNamespace("/dev/" + target)}
	}
	return nil
}

var reNVMeCtrl = regexp.MustCompile(`^nvme\d+$`)

// nvmeNamespace turns an NVMe controller (/dev/nvme1, as smartd and the
// nvme driver name it) into its first namespace (/dev/nvme1n1, as lsblk and
// the disk inventory name it), so diag can attach the serial.
func nvmeNamespace(dev string) string {
	if strings.HasPrefix(dev, "/dev/") && reNVMeCtrl.MatchString(dev[5:]) {
		return dev + "n1"
	}
	return dev
}

// linuxKernel analyses the kernel/daemon log sections.
func linuxKernel(b *collect.Bundle, env model.Env, res *model.Result, facts *Facts) {
	secs := []*collect.Section{b.Get("logs.kernel_match"), b.Get("logs.kernel"), b.Get("logs.units")}
	present := false
	for _, s := range secs {
		if s != nil {
			present = true
		}
	}
	if !present {
		return
	}
	cov := model.Coverage{ID: "logs.kernel", Component: model.CompLogs,
		Name: model.T("Kernel log and hardware daemon messages", "Log kernel và thông báo của dịch vụ giám sát phần cứng")}

	// Skipped by the collector (container).
	for _, s := range secs {
		if s != nil && s.Skipped != "" {
			cov.State = model.CovSkipped
			if s.Skipped == "container" || env.Container {
				cov.Reason = hint.Virtual(env)
			} else {
				cov.Reason = model.Tf("Skipped by the collector (%s).", "Bộ thu thập đã bỏ qua (%s).", s.Skipped)
			}
			res.Coverage = append(res.Coverage, cov)
			return
		}
	}

	var meta srcMeta
	var sets [][]logLine
	var errs []string
	for _, s := range secs {
		if s == nil || !s.Ran() {
			continue
		}
		nc := len(meta.Capped)
		sets = append(sets, parseLog(s.Out, env.Now, &meta)...)
		if s.Name == "logs.kernel" {
			// Every warning-level kernel line: capping it on a noisy host is
			// expected; the pattern matches come from logs.kernel_match.
			meta.Capped = meta.Capped[:nc]
		}
		if e := strings.TrimSpace(s.Err); e != "" {
			errs = append(errs, e)
		}
		if s.Timeout {
			meta.TimedOut = true
		}
	}
	all := mergeLines(sets...)
	lines := all[:0:0]
	for _, l := range all {
		if inWindow(l.T, env) {
			lines = append(lines, l)
		}
	}
	facts.LinesChecked = len(lines)
	for src := range meta.Sources {
		facts.Sources = append(facts.Sources, src)
	}
	sortStrings(facts.Sources)
	facts.Persistent = meta.Persistent

	if len(meta.Sources) == 0 {
		cov.State = model.CovSkipped
		switch {
		case !env.Root:
			cov.Reason, cov.Fix = hint.NeedRoot(env), hint.RunAsRoot(env)
		case allMissing(secs):
			cov.Reason = hint.Missing("journalctl/dmesg")
			cov.Fix, cov.Cmd = hint.InstallFix(env, "journalctl")
		default:
			cov.State = model.CovFailed
			cov.Reason = model.Tf("No kernel log could be read: %s", "Không đọc được log kernel: %s", firstLine(strings.Join(errs, "; ")))
		}
		res.Coverage = append(res.Coverage, cov)
		return
	}

	ctx := buildCtx(all)
	gr := matchLines(lines, ctx, env.Now)
	judgeLinuxDevices(gr.list(), readLinuxInv(b), ctx, env.Now)
	noteEarlierBoot(gr.list(), currentBootStart(b, env.Now))
	var vmNote model.Text
	if env.Virtual != "" && !env.Container {
		vmNote = model.T("This is a virtual machine: hardware errors here usually come from the host or its storage — check the host too.",
			"Đây là máy ảo: lỗi phần cứng ở đây thường đến từ máy host hoặc hệ thống lưu trữ của host — hãy kiểm tra cả máy host.")
	}
	findings, efacts := buildFindings(gr.list(), env.Now, vmNote)
	res.Findings = append(res.Findings, findings...)
	facts.Events = append(facts.Events, efacts...)

	// Coverage state.
	cov.State = model.CovRan
	onlyCurrentBoot := !meta.Persistent && !meta.Sources["syslog"]
	switch {
	case onlyCurrentBoot:
		cov.State = model.CovPartial
		cov.Reason = model.T("Only messages since the last boot are available (no persistent journal or syslog files); earlier hardware errors cannot be seen.",
			"Chỉ có log từ lần khởi động gần nhất (journal không lưu lâu dài, không có file syslog); không thấy được lỗi phần cứng trước đó.")
		cov.Fix, cov.Cmd = persistFix, persistCmd(env)
		if !env.Root {
			cov.Fix = joinText(hint.RunAsRoot(env), persistFix)
		}
	case meta.TimedOut:
		cov.State = model.CovPartial
		cov.Reason = model.T("Reading the journal timed out; only part of the period was checked.",
			"Đọc journal bị quá thời gian; chỉ kiểm tra được một phần khoảng thời gian.")
		cov.Fix = model.T("Run Diagward again with a longer per-command timeout (--timeout, in seconds) or a shorter period (--since, in days).",
			"Chạy lại Diagward với thời gian chờ mỗi lệnh dài hơn (--timeout, tính bằng giây) hoặc khoảng thời gian ngắn hơn (--since, tính bằng ngày).")
		cov.Cmd = "diagward check --timeout 120 --since 3"
	case len(meta.Capped) > 0:
		c := meta.Capped[0]
		for _, x := range meta.Capped[1:] {
			if x.Oldest.After(c.Oldest) {
				c = x
			}
		}
		cov.State = model.CovPartial
		cov.Reason = model.Tf("The log is very noisy: %d matching lines from %s, only the newest %d were checked (back to %s). Older hardware errors may be missing.",
			"Log rất nhiều: %d dòng khớp mẫu từ %s, chỉ kiểm tra được %d dòng mới nhất (từ %s trở lại đây). Có thể bỏ sót lỗi phần cứng cũ hơn.",
			c.Total, c.Src, c.Max, fmtTime(c.Oldest))
		cov.Fix = model.T("Find what floods the kernel log (journalctl -k -p warning | sort | uniq -c | sort -rn | head) and fix it, or run Diagward again with a shorter period.",
			"Tìm thông báo đang làm ngập log kernel (journalctl -k -p warning | sort | uniq -c | sort -rn | head) và xử lý, hoặc chạy lại Diagward với khoảng thời gian ngắn hơn.")
		cov.Cmd = "diagward check --since 2"
	}
	if !env.Root && cov.State == model.CovRan && meta.Sources["journal"] {
		// Without root the journal may hide system messages.
		cov.State = model.CovPartial
		cov.Reason = hint.NeedRoot(env)
		cov.Fix = hint.RunAsRoot(env)
	}
	res.Coverage = append(res.Coverage, cov)

	worst := model.OK
	for _, f := range findings {
		worst = model.Worst(worst, f.Severity)
	}
	if worst < model.Warn {
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.kernel_clean", Component: model.CompLogs, Severity: model.OK,
			Title: model.Tf("No hardware errors in the kernel log for the last %d days", "Log kernel %d ngày qua không có lỗi phần cứng", env.SinceDays),
			Detail: model.Tf("%d log lines checked against %d hardware error patterns (disk, RAID, memory, CPU, PCIe, temperature, network).",
				"Đã kiểm tra %d dòng log với %d mẫu lỗi phần cứng (ổ cứng, RAID, RAM, CPU, PCIe, nhiệt độ, mạng).", len(lines), len(rules)),
		})
	}
	if len(efacts) > 0 {
		res.Tables = append(res.Tables, eventTable("logs.events",
			model.T("Hardware-related log events", "Sự kiện log liên quan phần cứng"), efacts,
			model.Tf("Last %d days. Events in the last 24 hours weigh more when deciding severity.",
				"%d ngày gần nhất. Sự kiện trong 24 giờ qua được tính nặng hơn khi đánh giá mức độ.", env.SinceDays)))
	}
}

func allMissing(secs []*collect.Section) bool {
	for _, s := range secs {
		if s != nil && s.Missing == "" {
			return false
		}
	}
	return true
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	if s == "" {
		return "?"
	}
	return s
}

var vfioNote = model.T("The device is bound to vfio-pci (passed through to a virtual machine): guests resetting or probing a passed-through device often cause these errors without any hardware fault. Look at it only if the VM sees problems with the device.",
	"Thiết bị đang gắn driver vfio-pci (passthrough cho máy ảo): máy ảo reset hoặc dò thiết bị passthrough thường gây ra các lỗi này dù phần cứng không hỏng. Chỉ cần xem xét nếu máy ảo gặp sự cố với thiết bị.")

// scsiLookback names the disk of a sense line printed on its own line.
// Kernels before 4.5 print the device and the sense data as separate
// printk lines ("sd 6:0:0:0: [sdb]" then "Sense Key : Medium Error
// [current]", LKML 1404.3/02964), so the disk is on a line just before.
// notDisk is set when that line is a CD/DVD drive or tape: not a disk.
func scsiLookback(lines []logLine, i int) (target string, notDisk bool) {
	for j := i - 1; j >= 0 && j >= i-6; j-- {
		p := lines[j]
		if p.Tag != "kernel" || (!p.T.IsZero() && !lines[i].T.IsZero() && lines[i].T.Sub(p.T) > 2*time.Second) {
			break
		}
		if reSCSINotDisk.MatchString(p.Msg) {
			return "", true
		}
		if m := reSdName.FindStringSubmatch(p.Msg); m != nil {
			return "/dev/" + m[1], false
		}
	}
	return "", false
}
