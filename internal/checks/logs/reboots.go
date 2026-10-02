package logs

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// BootFact is one boot seen in the journal or wtmp.
type BootFact struct {
	Index  int       `json:"index,omitempty"`
	ID     string    `json:"id,omitempty"`
	Start  time.Time `json:"start,omitzero"`
	End    time.Time `json:"end,omitzero"`
	Ending string    `json:"ending"` // clean, unclean, panic, shutdown_incomplete, unknown, running
	Source string    `json:"source"` // journal, wtmp
}

// CrashDump is one kdump crash directory.
type CrashDump struct {
	Path   string    `json:"path"`
	Time   time.Time `json:"time"`
	Bytes  int64     `json:"bytes"`
	Reason string    `json:"reason,omitempty"`
}

var (
	reBootList = regexp.MustCompile(`^\s*(-?\d+)\s+([0-9a-f]{32})\s+(.*)$`)
	reBootTime = regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
	// The end of a boot whose journal shows the shutdown sequence. Covers
	// systemd 219 (CentOS 7: "Reached target Shutdown", "systemd-journal[..]:
	// Journal stopped") to 259 ("Reached target shutdown.target - System Shutdown").
	reCleanEnd = regexp.MustCompile(`systemd-shutdown|Journal stopped|Reached target (?:\S+\.target - )?(?:System )?(?:Shutdown|Reboot|Power[- ]?Off|Halt|Final Step|Late Shutdown Services)|^Shutting down\.|reboot: (?:Restarting system|Power down|System halted)|Starting (?:Reboot|Power-Off|Halt)\.\.\.|Finished (?:System Reboot|System Power Off|System Halt|systemd-(?:reboot|poweroff|halt|kexec)\.service)`)
	// A shutdown that started but did not get to the end.
	reShutdownStarted = regexp.MustCompile(`Stopped target|Stopping \S*\.?target|Stopping .*[Tt]arget\b`)
	rePanicLine       = regexp.MustCompile(`Kernel panic - not syncing|BUG: unable to handle|Oops: |general protection fault`)
)

type bootInfo struct {
	idx   int
	id    string
	first time.Time
	last  time.Time
	tail  []logLine
}

// parseBoots parses logs.boots: "#list" then journalctl --list-boots, then
// "#boot -N" blocks with the last lines of each previous boot.
func parseBoots(text string, now time.Time) (boots []*bootInfo, persistent bool) {
	loc := time.UTC
	byIdx := map[int]*bootInfo{}
	var cur *bootInfo
	inList := false
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "# "):
			kv := headerKV(l)
			if tz, ok := kv["tz"]; ok {
				loc = parseTZ(tz)
			}
			if kv["persistent"] == "1" {
				persistent = true
			}
			continue
		case l == "#list":
			inList, cur = true, nil
			continue
		case strings.HasPrefix(l, "#boot "):
			inList = false
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "#boot ")))
			if err != nil {
				cur = nil
				continue
			}
			cur = byIdx[n]
			if cur == nil {
				cur = &bootInfo{idx: n}
				byIdx[n] = cur
				boots = append(boots, cur)
			}
			continue
		}
		if inList {
			m := reBootList.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			bi := byIdx[n]
			if bi == nil {
				bi = &bootInfo{idx: n}
				byIdx[n] = bi
				boots = append(boots, bi)
			}
			bi.id = m[2]
			ts := reBootTime.FindAllString(m[3], -1)
			if len(ts) > 0 {
				bi.first, _ = time.ParseInLocation("2006-01-02 15:04:05", ts[0], loc)
			}
			if len(ts) > 1 {
				bi.last, _ = time.ParseInLocation("2006-01-02 15:04:05", ts[1], loc)
			}
			continue
		}
		if cur != nil && strings.TrimSpace(l) != "" {
			if ll, ok := parseLine(l, "journal", loc, now, 0); ok {
				cur.tail = append(cur.tail, ll)
			}
		}
	}
	sort.SliceStable(boots, func(i, j int) bool { return boots[i].idx < boots[j].idx })
	return boots, persistent
}

// classifyTail says how a boot ended, from its last journal lines.
func classifyTail(tail []logLine) string {
	if len(tail) == 0 {
		return "unknown"
	}
	started := false
	for _, l := range tail {
		if rePanicLine.MatchString(l.Msg) {
			return "panic"
		}
	}
	for _, l := range tail {
		if reCleanEnd.MatchString(l.Msg) {
			return "clean"
		}
		if reShutdownStarted.MatchString(l.Msg) {
			started = true
		}
	}
	if started {
		return "shutdown_incomplete"
	}
	return "unclean"
}

// wtmp records from `last -x`.
type wtmpRec struct {
	kind  string // reboot, shutdown, runlevel
	level string // runlevel target, e.g. "6"
	start time.Time
	crash bool
	raw   string
}

var (
	reLastDate  = regexp.MustCompile(`[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}(?::\d{2})?(?: \d{4})?`)
	reLastLevel = regexp.MustCompile(`\(to lvl (\S)\)`)
)

func parseLastDate(s string, loc *time.Location, now time.Time) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"Mon Jan _2 15:04:05 2006", "Mon Jan _2 15:04 2006"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t
		}
	}
	// No year (last without -F): the most recent year that is not in the future.
	for _, layout := range []string{"Mon Jan _2 15:04:05", "Mon Jan _2 15:04"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			if now.IsZero() {
				return time.Time{}
			}
			t = t.AddDate(now.In(loc).Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return time.Time{}
}

// parseLast parses logs.last into records, oldest first.
func parseLast(text string, now time.Time) (recs []wtmpRec, begins time.Time) {
	loc := time.UTC
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(l, "# ") {
			kv := headerKV(l)
			if tz, ok := kv["tz"]; ok {
				loc = parseTZ(tz)
			}
			continue
		}
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if (f[0] == "wtmp" || f[0] == "wtmpdb") && strings.Contains(l, "begins") {
			if d := reLastDate.FindString(l); d != "" {
				begins = parseLastDate(d, loc, now)
			}
			continue
		}
		if f[0] != "reboot" && f[0] != "shutdown" && f[0] != "runlevel" {
			continue
		}
		d := reLastDate.FindStringIndex(l)
		if d == nil {
			continue
		}
		r := wtmpRec{kind: f[0], raw: l, start: parseLastDate(l[d[0]:d[1]], loc, now)}
		r.crash = strings.Contains(l[d[1]:], "crash")
		if m := reLastLevel.FindStringSubmatch(l); m != nil {
			r.level = m[1]
		}
		recs = append(recs, r)
	}
	// last prints newest first.
	for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
		recs[i], recs[j] = recs[j], recs[i]
	}
	return recs, begins
}

// uncleanFromWtmp finds boots that ended without a shutdown record: two boot
// records in a row, or a boot marked "crash". It returns the times the
// machine came back (the start of the boot after each unclean end).
func uncleanFromWtmp(recs []wtmpRec) (incidents []time.Time, evidence []string, boots []BootFact) {
	var open *wtmpRec
	for i := range recs {
		r := &recs[i]
		switch r.kind {
		case "reboot":
			if open != nil || (i > 0 && recs[i-1].kind == "reboot" && recs[i-1].crash) {
				incidents = append(incidents, r.start)
				if open != nil {
					evidence = append(evidence, open.raw)
				}
				evidence = append(evidence, r.raw)
				if len(boots) > 0 {
					boots[len(boots)-1].Ending = "unclean"
					boots[len(boots)-1].End = r.start
				}
			}
			boots = append(boots, BootFact{Start: r.start, Ending: "running", Source: "wtmp"})
			open = r
		case "shutdown":
			open = nil
			if len(boots) > 0 && boots[len(boots)-1].Ending == "running" {
				boots[len(boots)-1].Ending = "clean"
				boots[len(boots)-1].End = r.start
			}
		case "runlevel":
			if r.level == "0" || r.level == "6" {
				open = nil
				if len(boots) > 0 && boots[len(boots)-1].Ending == "running" {
					boots[len(boots)-1].Ending = "clean"
					boots[len(boots)-1].End = r.start
				}
			}
		}
	}
	return incidents, evidence, boots
}

// parseKdump parses logs.kdump.
func parseKdump(text string) (dumps []CrashDump, root bool) {
	byDir := map[string]*CrashDump{}
	var order []string
	reasons := map[string]string{}
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "# "):
			if headerKV(l)["root"] == "1" {
				root = true
			}
		case strings.HasPrefix(l, "f "):
			f := strings.SplitN(l[2:], " ", 3)
			if len(f) != 3 {
				continue
			}
			mt, size := atoi64(f[0]), atoi64(f[1])
			dir := path.Dir(f[2])
			d := byDir[dir]
			if d == nil {
				d = &CrashDump{Path: dir}
				byDir[dir] = d
				order = append(order, dir)
			}
			if t := time.Unix(mt, 0); mt > 0 && t.After(d.Time) {
				d.Time = t
			}
			d.Bytes += size
		case strings.HasPrefix(l, "p "):
			p, line, ok := strings.Cut(l[2:], "\t")
			if !ok {
				continue
			}
			dir := path.Dir(p)
			if _, seen := reasons[dir]; !seen || strings.Contains(line, "Kernel panic") {
				reasons[dir] = strings.TrimSpace(line)
			}
		}
	}
	for _, dir := range order {
		d := byDir[dir]
		d.Reason = reasons[dir]
		dumps = append(dumps, *d)
	}
	sort.SliceStable(dumps, func(i, j int) bool { return dumps[i].Time.After(dumps[j].Time) })
	return dumps, root
}

var actUnclean = model.T(
	"Find out why: check the BMC/iLO/iDRAC event log (ipmitool sel elist) for power loss, PSU, temperature or watchdog events at those times; check the UPS log; look at the last lines before each restart (journalctl -b -1 -n 50). Set up kdump so the next kernel panic leaves a crash dump.",
	"Tìm nguyên nhân: xem log sự kiện BMC/iLO/iDRAC (ipmitool sel elist) có mất điện, lỗi nguồn (PSU), quá nhiệt hoặc watchdog vào các thời điểm đó không; xem log UPS; xem các dòng cuối trước mỗi lần khởi động lại (journalctl -b -1 -n 50). Cấu hình kdump để lần kernel panic sau có file crash dump.")

// linuxReboots analyses logs.boots, logs.last and logs.kdump.
func linuxReboots(b *collect.Bundle, env model.Env, res *model.Result, facts *Facts) {
	bs, ls, ks := b.Get("logs.boots"), b.Get("logs.last"), b.Get("logs.kdump")
	if bs == nil && ls == nil && ks == nil {
		return
	}
	cov := model.Coverage{ID: "logs.reboots", Component: model.CompSystem,
		Name: model.T("Unexpected reboots and kernel crashes", "Khởi động lại bất thường và kernel crash")}
	for _, s := range []*collect.Section{bs, ls, ks} {
		if s != nil && s.Skipped == "container" {
			cov.State, cov.Reason = model.CovSkipped, hint.Virtual(env)
			res.Coverage = append(res.Coverage, cov)
			return
		}
	}
	ws := windowStart(env)
	inWin := func(t time.Time) bool { return !t.IsZero() && (ws.IsZero() || !t.Before(ws)) }

	// Journal: how did each previous boot end?
	var (
		journalBoots []*bootInfo
		persistent   bool
		classified   int
		unclean      []time.Time
		evidence     []string
		incomplete   int
		panics       int
	)
	if bs.Ran() {
		journalBoots, persistent = parseBoots(bs.Out, env.Now)
	}
	for _, bi := range journalBoots {
		if bi.idx >= 0 {
			facts.Boots = append(facts.Boots, BootFact{Index: bi.idx, ID: bi.id, Start: bi.first, End: bi.last, Ending: "running", Source: "journal"})
			continue
		}
		if len(bi.tail) == 0 {
			if inWin(bi.last) {
				facts.Boots = append(facts.Boots, BootFact{Index: bi.idx, ID: bi.id, Start: bi.first, End: bi.last, Ending: "unknown", Source: "journal"})
			}
			continue
		}
		end := bi.last
		if t := bi.tail[len(bi.tail)-1].T; !t.IsZero() {
			end = t
		}
		ending := classifyTail(bi.tail)
		if !inWin(end) {
			continue
		}
		classified++
		facts.Boots = append(facts.Boots, BootFact{Index: bi.idx, ID: bi.id, Start: bi.first, End: end, Ending: ending, Source: "journal"})
		switch ending {
		case "unclean", "panic":
			unclean = append(unclean, end)
			if ending == "panic" {
				panics++
			}
			n := len(bi.tail)
			for _, l := range bi.tail[max(0, n-2):] {
				evidence = append(evidence, l.Raw)
			}
		case "shutdown_incomplete":
			incomplete++
		}
	}
	source := "journal"
	// wtmp when the journal could not tell.
	var wtmpBegins time.Time
	if classified == 0 && ls.Ran() {
		recs, begins := parseLast(ls.Out, env.Now)
		wtmpBegins = begins
		inc, ev, wb := uncleanFromWtmp(recs)
		for _, t := range inc {
			if inWin(t) {
				unclean = append(unclean, t)
			}
		}
		if len(unclean) > 0 {
			evidence = append(evidence, ev...)
		}
		for _, bf := range wb {
			if inWin(bf.Start) || inWin(bf.End) {
				facts.Boots = append(facts.Boots, bf)
				classified++
			}
		}
		source = "wtmp"
	}
	facts.UncleanShutdowns = len(unclean)

	// Crash dumps.
	var recentDumps, oldDumps []CrashDump
	kdumpRoot := false
	if ks.Ran() {
		var dumps []CrashDump
		dumps, kdumpRoot = parseKdump(ks.Out)
		for _, d := range dumps {
			if inWin(d.Time) {
				recentDumps = append(recentDumps, d)
			} else {
				oldDumps = append(oldDumps, d)
			}
		}
		facts.CrashDumps = dumps
	}

	// Coverage.
	cov.State = model.CovRan
	switch {
	case classified == 0 && !persistent && len(journalBoots) <= 1 && !ls.Ran():
		cov.State = model.CovPartial
		cov.Reason = model.T("The journal only holds the current boot and wtmp (last) is not available, so earlier restarts cannot be checked.",
			"Journal chỉ lưu lần khởi động hiện tại và không có wtmp (lệnh last), nên không kiểm tra được các lần khởi động lại trước đó.")
		cov.Fix = persistFix
	case classified == 0 && len(journalBoots) == 0 && !ls.Ran():
		cov.State = model.CovPartial
		cov.Reason = model.T("Neither the journal boot list nor wtmp (last) could be read.", "Không đọc được danh sách boot của journal lẫn wtmp (lệnh last).")
		if !env.Root {
			cov.Fix = hint.RunAsRoot(env)
		}
	case ks != nil && ks.Ran() && !kdumpRoot && !env.Root:
		cov.State = model.CovPartial
		cov.Reason = model.T("Crash dumps in /var/crash may not be readable without root.", "Có thể không đọc được crash dump trong /var/crash khi không có quyền root.")
		cov.Fix = hint.RunAsRoot(env)
	}
	if source == "wtmp" && !wtmpBegins.IsZero() && wtmpBegins.After(ws.Add(25*time.Hour)) && cov.State == model.CovRan {
		cov.State = model.CovPartial
		cov.Reason = model.Tf("wtmp only goes back to %s.", "wtmp chỉ lưu từ %s.", fmtTime(wtmpBegins))
	}
	if source == "journal" && persistent && len(journalBoots) > 0 && cov.State == model.CovRan {
		if oldest := journalBoots[0].first; !oldest.IsZero() && oldest.After(ws.Add(25*time.Hour)) && len(journalBoots) > 1 {
			cov.State = model.CovPartial
			cov.Reason = model.Tf("The journal only goes back to %s (size limit or recent install).", "Journal chỉ lưu từ %s (giới hạn dung lượng hoặc máy mới cài).", fmtTime(oldest))
		}
	}
	res.Coverage = append(res.Coverage, cov)

	// Findings.
	if len(recentDumps) > 0 {
		var ev []string
		hw := false
		for _, d := range recentDumps {
			line := fmt.Sprintf("%s  %s  %s", fmtTime(d.Time), d.Path, units.SI(uint64(max(d.Bytes, 0))))
			ev = append(ev, line)
			if d.Reason != "" {
				ev = append(ev, "  "+d.Reason)
				if lr := strings.ToLower(d.Reason); strings.Contains(lr, "machine check") || strings.Contains(lr, "hardware error") {
					hw = true
				}
			}
		}
		detail := tf("kdump saved %d kernel crash dump(s) in the last %d days, the latest at %s: the kernel panicked and the server rebooted.",
			"kdump đã lưu %d crash dump trong %d ngày qua, gần nhất lúc %s: kernel bị panic và máy chủ đã khởi động lại.",
			len(recentDumps), env.SinceDays, fmtTime(recentDumps[0].Time))
		if hw {
			detail = joinText(detail, model.T("The panic message mentions a machine check / hardware error.", "Thông báo panic có nhắc tới machine check / lỗi phần cứng."))
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.kernel_crash_dump", Component: model.CompSystem, Severity: model.Crit, Target: recentDumps[0].Path,
			Title:  tf("Kernel crashed %d time(s): crash dumps found in /var/crash", "Kernel bị crash %d lần: có crash dump trong /var/crash", len(recentDumps)),
			Detail: detail,
			Action: model.T("Read vmcore-dmesg.txt (or dmesg.<date>) in the crash directory: the lines before \"Kernel panic\" show the cause. Hardware causes (machine check, NMI, I/O errors) need the BMC event log and a vendor case; software causes need a kernel/driver update. Send the vmcore to the OS vendor if unsure, then delete old dumps to free space.",
				"Đọc vmcore-dmesg.txt (hoặc dmesg.<ngày>) trong thư mục crash: các dòng trước \"Kernel panic\" cho biết nguyên nhân. Nguyên nhân phần cứng (machine check, NMI, lỗi I/O) cần xem log sự kiện BMC và mở case với hãng; nguyên nhân phần mềm cần cập nhật kernel/driver. Nếu chưa rõ, gửi vmcore cho hãng hệ điều hành, sau đó xóa dump cũ để giải phóng dung lượng."),
			Evidence: units.Evidence(ev, 10),
		})
	}
	if len(oldDumps) > 0 {
		var total int64
		for _, d := range oldDumps {
			total += d.Bytes
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.old_crash_dumps", Component: model.CompSystem, Severity: model.Info,
			Title:  tf("%d older kernel crash dump(s) in /var/crash (latest %s)", "Có %d crash dump cũ trong /var/crash (gần nhất %s)", len(oldDumps), fmtTime(oldDumps[0].Time)),
			Detail: model.Tf("They use %s. They show the kernel crashed before the report period.", "Chiếm %s. Chúng cho thấy kernel đã từng crash trước khoảng thời gian của báo cáo.", units.SI(uint64(max(total, 0)))),
			Action: model.T("Check whether the cause was resolved, then archive or delete them.", "Kiểm tra nguyên nhân đã được khắc phục chưa, sau đó lưu trữ hoặc xóa chúng."),
		})
	}
	if len(unclean) > 0 {
		sort.Slice(unclean, func(i, j int) bool { return unclean[i].Before(unclean[j]) })
		var times []string
		for _, t := range unclean {
			times = append(times, fmtTime(t))
		}
		srcText := model.T("The journal of each of these boots ends without the shutdown sequence.", "Journal của các lần khởi động này kết thúc mà không có quá trình tắt máy.")
		if source == "wtmp" {
			srcText = model.T("wtmp (last -x) shows a new boot without a shutdown record before it.", "wtmp (last -x) cho thấy máy khởi động lại mà trước đó không có bản ghi tắt máy.")
		}
		detail := joinText(model.Tf("Boots that ended abruptly (time of the last message or of the restart): %s.",
			"Các lần máy dừng đột ngột (thời điểm log cuối hoặc lúc khởi động lại): %s.", strings.Join(times, ", ")), srcText,
			model.T("Causes: power loss, a PSU fault, overheating, a kernel panic/hang, or a watchdog/BMC reset.",
				"Nguyên nhân có thể: mất điện, lỗi bộ nguồn (PSU), quá nhiệt, kernel panic/treo, hoặc watchdog/BMC reset máy."))
		if panics > 0 {
			detail = joinText(detail, model.Tf("%d of them end with a kernel panic/Oops.", "%d lần trong số đó kết thúc bằng kernel panic/Oops.", panics))
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.unexpected_reboot", Component: model.CompSystem, Severity: model.Warn,
			Title: tf("Server restarted without a clean shutdown %d time(s) in the last %d days",
				"Máy chủ khởi động lại mà không tắt máy đúng cách %d lần trong %d ngày qua", len(unclean), env.SinceDays),
			Detail:   detail,
			Action:   actUnclean,
			Evidence: units.Evidence(evidence, 10),
		})
	} else if classified > 0 && len(recentDumps) == 0 {
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.reboots_clean", Component: model.CompSystem, Severity: model.OK,
			Title: model.Tf("No unexpected reboots in the last %d days", "Không có lần khởi động lại bất thường nào trong %d ngày qua", env.SinceDays),
			Detail: tf("%d previous boot(s) checked (%s); all ended with a clean shutdown.",
				"Đã kiểm tra %d lần khởi động trước (%s); tất cả đều tắt máy đúng cách.", classified, source),
		})
	}
	if incomplete > 0 {
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.shutdown_incomplete", Component: model.CompSystem, Severity: model.Info,
			Title: tf("%d shutdown(s) started but the log stops before the end", "%d lần tắt máy đã bắt đầu nhưng log dừng trước khi hoàn tất", incomplete),
			Detail: model.T("The shutdown sequence began (services stopping) but the final messages are missing: the machine may have hung while shutting down and been reset, or the last messages were not written to disk.",
				"Quá trình tắt máy đã bắt đầu (dịch vụ đang dừng) nhưng thiếu các dòng cuối: máy có thể bị treo khi tắt rồi bị reset, hoặc các dòng cuối chưa kịp ghi xuống ổ."),
		})
	}
	if len(facts.Boots) > 0 {
		res.Tables = append(res.Tables, bootTable(facts.Boots))
	}
}

func bootTable(boots []BootFact) model.Table {
	t := model.Table{ID: "logs.boots", Title: model.T("Boots in the report period", "Các lần khởi động trong khoảng thời gian báo cáo"),
		Columns: []model.Text{model.T("Boot", "Lần boot"), model.T("Started", "Bắt đầu"), model.T("Ended", "Kết thúc"),
			model.T("How it ended", "Cách kết thúc"), model.T("Source", "Nguồn")}}
	for _, bf := range boots {
		st := model.OK
		switch bf.Ending {
		case "unclean", "panic":
			st = model.Warn
		case "shutdown_incomplete", "unknown":
			st = model.Info
		}
		idx := ""
		if bf.Source == "journal" {
			idx = strconv.Itoa(bf.Index)
		}
		end := fmtTime(bf.End)
		if bf.Ending == "running" {
			end = "-"
		}
		t.Rows = append(t.Rows, model.Row{Status: st, Cells: []string{idx, fmtTime(bf.Start), end, bf.Ending, bf.Source}})
	}
	return t
}

func sortStrings(s []string) { sort.Strings(s) }
