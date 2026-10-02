package logs

import (
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// persistFix is the fix text for a journal that forgets everything at reboot.
var persistFix = model.T(
	"Make the journal persistent so the next report covers earlier boots: mkdir -p /var/log/journal && systemctl restart systemd-journald",
	"Bật lưu journal lâu dài để lần sau báo cáo xem được các lần khởi động trước: mkdir -p /var/log/journal && systemctl restart systemd-journald")

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
	ctx := &matchCtx{hctl: map[string]string{}, ata: map[string]*model.Part{}}
	for _, l := range lines {
		if l.Tag != "kernel" {
			continue
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
			target := ""
			if ru.target != nil {
				target = ru.target(m, l, ctx)
			}
			g := gr.add(ru.sp, target, l.T, l.Raw, !ru.evidence)
			if g.part == nil {
				g.part = partFor(ru.sp, target, ctx)
			}
			break
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
			g.capped, g.capSev = true, model.Warn
			g.note = model.Tf("smartd reported the condition cleared at %s.", "smartd đã báo hết lỗi này lúc %s.", fmtTime(rt))
		}
	}
	return gr
}

// ghesRule classifies an APEI/GHES "event severity" line from the
// section_type line that follows it in the same record.
func ghesRule(lines []logLine, i int, m []string) (*spec, string) {
	rec, sev := m[1], m[2]
	section := ""
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
		if s := reGHESSection.FindStringSubmatch(msg); s != nil {
			section = strings.ToLower(s[1])
			break
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
		if corrected {
			return spPCIeCorr, "PCIe"
		}
		if sev == "fatal" {
			return spPCIeFatal, "PCIe"
		}
		return spPCIeNonFatal, "PCIe"
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
	if strings.HasPrefix(target, "/dev/") {
		return &model.Part{Kind: "disk", Location: target}
	}
	return nil
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
		sets = append(sets, parseLog(s.Out, env.Now, &meta)...)
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
			cov.Reason, cov.Fix = hint.Missing("journalctl/dmesg"), hint.Install(env, "journalctl")
		default:
			cov.State = model.CovFailed
			cov.Reason = model.Tf("No kernel log could be read: %s", "Không đọc được log kernel: %s", firstLine(strings.Join(errs, "; ")))
		}
		res.Coverage = append(res.Coverage, cov)
		return
	}

	gr := matchLines(lines, buildCtx(all), env.Now)
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
		cov.Fix = persistFix
		if !env.Root {
			cov.Fix = joinText(hint.RunAsRoot(env), persistFix)
		}
	case meta.TimedOut:
		cov.State = model.CovPartial
		cov.Reason = model.T("Reading the journal timed out; only part of the period was checked.",
			"Đọc journal bị quá thời gian; chỉ kiểm tra được một phần khoảng thời gian.")
		cov.Fix = model.T("Run Diagward again with a longer timeout or a shorter period (--since).", "Chạy lại Diagward với timeout dài hơn hoặc khoảng thời gian ngắn hơn (--since).")
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
