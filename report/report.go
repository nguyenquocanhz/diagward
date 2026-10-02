// Package report renders a model.Report as terminal text, a self-contained
// HTML page, Markdown for tickets and chat, or JSON.
//
// Every renderer is defensive: a nil or empty Report, findings without a
// component, rows with too few cells and strings full of control characters
// or HTML all render without panicking. Strings that come from the machine
// (evidence lines, targets, table cells, model names) are treated as
// untrusted: Text and Markdown strip control characters (no terminal escape
// injection), HTML escapes everything through html/template.
package report

//go:generate go test -run TestWriteSamples -update

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// RepoURL is the project page shown in report footers. It is the only link
// an HTML report contains.
const RepoURL = "https://github.com/nguyenquocanhz/diagward"

// Options control rendering.
type Options struct {
	Lang    string // "vi" or "en" (anything starting with "vi" is Vietnamese; otherwise English)
	Color   bool   // ANSI colours (Text only)
	ASCII   bool   // Text: no box drawing or symbols outside ASCII
	Width   int    // terminal width for Text (0 = 100)
	Verbose bool   // Text/Markdown: include tables, evidence and full coverage
	// NoHints drops the Text footer's "how to get more" hints (--html,
	// --lang, -v): the CLI sets it when it already wrote the files.
	NoHints bool
}

func (o Options) lang() string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(o.Lang)), "vi") {
		return "vi"
	}
	return "en"
}

// JSON renders the report as indented JSON. Field order follows the model
// structs, so output is stable between runs.
func JSON(w io.Writer, r *model.Report) error {
	if r == nil {
		r = &model.Report{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // keep "<" and "&" in log lines readable
	return enc.Encode(r)
}

// VerdictText is the headline for an overall severity.
func VerdictText(s model.Severity) model.Text {
	switch s {
	case model.Crit:
		return model.T("ACTION NEEDED NOW", "CẦN XỬ LÝ NGAY")
	case model.Warn:
		return model.T("NEEDS ATTENTION", "CẦN CHÚ Ý")
	default:
		return model.T("NO HARDWARE PROBLEMS FOUND", "KHÔNG PHÁT HIỆN LỖI PHẦN CỨNG")
	}
}

var noData = model.T("NOT ENOUGH DATA TO DECIDE", "CHƯA ĐỦ DỮ LIỆU ĐỂ KẾT LUẬN")

// Headline is the verdict text for a whole report. It differs from
// VerdictText when nothing could be checked: "no problems found" would then
// be misleading, so it says there was not enough data.
func Headline(r *model.Report) model.Text {
	if r == nil || (r.Verdict < model.Warn && checkedCount(r) == 0) {
		return noData
	}
	if r.Verdict < model.Warn && guestOnly(r) {
		// The disks, RAM, fans and PSUs belong to the host: "no hardware
		// problems" would reassure about hardware nobody looked at.
		if r.Env.Container {
			return model.T("NO PROBLEMS FOUND IN THIS CONTAINER", "KHÔNG PHÁT HIỆN LỖI TRONG CONTAINER NÀY")
		}
		return model.T("NO PROBLEMS FOUND IN THIS VIRTUAL MACHINE", "KHÔNG PHÁT HIỆN LỖI TRONG MÁY ẢO NÀY")
	}
	return VerdictText(r.Verdict)
}

// guestOnly reports whether the report comes from inside a VM or container,
// where the physical hardware cannot be checked.
func guestOnly(r *model.Report) bool {
	return r != nil && r.Env.OS != "" && r.Env.OS != "bmc" && !r.Env.Bare()
}

// nothingChecked reports whether the banner should say "not enough data".
func nothingChecked(r *model.Report) bool {
	return r == nil || (r.Verdict < model.Warn && checkedCount(r) == 0)
}

// headlineSeverity is the severity the banner is drawn with: a report where
// nothing was checked, or a healthy VM/container (whose hardware belongs to
// the host), is shown as Info, not as a reassuring green; a report with only
// notes is green.
func headlineSeverity(r *model.Report) model.Severity {
	if r.Verdict < model.Warn && (checkedCount(r) == 0 || guestOnly(r)) {
		return model.Info
	}
	if r.Verdict < model.Warn {
		return model.OK
	}
	if r.Verdict > model.Crit {
		return model.Crit
	}
	return r.Verdict
}

// Counts is the number of findings per severity.
type Counts struct{ Crit, Warn, Info, OK int }

// CountFindings counts r's findings by severity.
func CountFindings(r *model.Report) Counts {
	var c Counts
	if r == nil {
		return c
	}
	for _, f := range r.Findings {
		switch {
		case f.Severity >= model.Crit:
			c.Crit++
		case f.Severity == model.Warn:
			c.Warn++
		case f.Severity == model.Info:
			c.Info++
		default:
			c.OK++
		}
	}
	return c
}

// subline is the sentence under the verdict: what was found and how much was
// checked.
func subline(r *model.Report) model.Text {
	c := CountFindings(r)
	var en, vi []string
	if c.Crit > 0 {
		en = append(en, plural(c.Crit, "critical problem", "critical problems"))
		vi = append(vi, fmt.Sprintf("%d lỗi nghiêm trọng", c.Crit))
	}
	if c.Warn > 0 {
		en = append(en, plural(c.Warn, "warning", "warnings"))
		vi = append(vi, fmt.Sprintf("%d cảnh báo", c.Warn))
	}
	if c.Info > 0 {
		en = append(en, plural(c.Info, "note", "notes"))
		vi = append(vi, fmt.Sprintf("%d lưu ý", c.Info))
	}
	n, total, part := checkedCount(r), len(summaryOf(r)), partialCount(r)
	switch {
	case part > 0 && part == n:
		en = append(en, fmt.Sprintf("%d of %d components checked, all of them only partly", n, total))
		vi = append(vi, fmt.Sprintf("đã kiểm tra %d/%d nhóm linh kiện, tất cả chỉ một phần", n, total))
	case part > 0:
		en = append(en, fmt.Sprintf("%d of %d components checked (%d only partly)", n, total, part))
		vi = append(vi, fmt.Sprintf("đã kiểm tra %d/%d nhóm linh kiện (%d nhóm chỉ một phần)", n, total, part))
	default:
		en = append(en, fmt.Sprintf("%d of %d components checked", n, total))
		vi = append(vi, fmt.Sprintf("đã kiểm tra %d/%d nhóm linh kiện", n, total))
	}
	switch {
	case !guestOnly(r):
	case r.Env.Container:
		// "No problems found" in a container or VM says nothing about the
		// physical host.
		en = append(en, "container: the physical hardware was not checked")
		vi = append(vi, "container: phần cứng vật lý chưa được kiểm tra")
	default:
		en = append(en, "virtual machine: the physical hardware was not checked")
		vi = append(vi, "máy ảo: phần cứng vật lý chưa được kiểm tra")
	}
	return model.T(strings.Join(en, " · "), strings.Join(vi, " · "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// summaryOf returns r.Summary, or one unchecked entry per component when the
// report has no summary (an empty or hand-built Report).
func summaryOf(r *model.Report) []model.ComponentSummary {
	if r != nil && len(r.Summary) > 0 {
		return r.Summary
	}
	out := make([]model.ComponentSummary, 0, len(model.Components))
	for _, c := range model.Components {
		out = append(out, model.ComponentSummary{Component: c, Name: model.ComponentName(c)})
	}
	return out
}

func checkedCount(r *model.Report) int {
	n := 0
	for _, s := range summaryOf(r) {
		if s.Checked {
			n++
		}
	}
	return n
}

// partialCount is the number of checked components that were only partly
// checked (ComponentSummary.Partial, set by diag).
func partialCount(r *model.Report) int {
	n := 0
	for _, s := range summaryOf(r) {
		if s.Checked && s.Partial {
			n++
		}
	}
	return n
}

// isPartial reports whether a component tile/cell should be drawn as
// "partly checked": it was checked, some checks were not, and nothing worse
// than a note was found (a warning or critical mark matters more).
func isPartial(s model.ComponentSummary) bool {
	return s.Checked && s.Partial && s.Severity <= model.Info
}

func compName(s model.ComponentSummary) model.Text {
	if !s.Name.IsZero() {
		return s.Name
	}
	return model.ComponentName(s.Component)
}

// SeverityText names a severity.
func SeverityText(s model.Severity) model.Text {
	switch {
	case s >= model.Crit:
		return model.T("Critical", "Nghiêm trọng")
	case s == model.Warn:
		return model.T("Warning", "Cảnh báo")
	case s == model.Info:
		return model.T("Note", "Lưu ý")
	}
	return model.T("OK", "Ổn")
}

// StateText names a coverage state.
func StateText(state string) model.Text {
	switch state {
	case model.CovRan:
		return model.T("checked", "đã kiểm tra")
	case model.CovPartial:
		return model.T("partly checked", "kiểm tra một phần")
	case model.CovSkipped:
		return model.T("not checked", "chưa kiểm tra")
	case model.CovFailed:
		return model.T("check failed", "kiểm tra bị lỗi")
	}
	return model.T(state, state)
}

// PartKindText names a kind of part (model.Part.Kind).
func PartKindText(kind string) model.Text {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "disk", "ssd", "hdd", "nvme":
		return model.T("Disk", "Ổ cứng")
	case "dimm", "memory", "ram":
		return model.T("Memory module (DIMM)", "Thanh RAM")
	case "psu", "power":
		return model.T("Power supply (PSU)", "Bộ nguồn (PSU)")
	case "fan":
		return model.T("Fan", "Quạt")
	case "cpu":
		return model.T("CPU", "CPU")
	case "nic":
		return model.T("Network card", "Card mạng")
	case "controller":
		return model.T("RAID/storage controller", "Card RAID / controller")
	case "battery", "bbu":
		return model.T("Controller battery (BBU)", "Pin card RAID (BBU)")
	case "":
		return model.T("Part", "Linh kiện")
	}
	return model.T(kind, kind)
}

// PartRow is one line of the "parts to replace" (warranty/RMA) list.
type PartRow struct {
	Kind     model.Text     `json:"kind"`
	Vendor   string         `json:"vendor,omitempty"`
	Model    string         `json:"model,omitempty"`
	Serial   string         `json:"serial,omitempty"`
	Location string         `json:"location,omitempty"`
	Firmware string         `json:"firmware,omitempty"`
	Size     string         `json:"size,omitempty"`
	Severity model.Severity `json:"severity"`
	Why      model.Text     `json:"why"`     // the finding title(s) that justify the replacement
	Finding  int            `json:"finding"` // index into Report.Findings of the most severe finding
	IDs      []string       `json:"ids"`     // finding IDs
	Target   string         `json:"target,omitempty"`
}

// Parts lists the parts that warn/crit findings say should be replaced, most
// severe first, one row per physical part (findings about the same serial
// number are merged).
func Parts(r *model.Report) []PartRow {
	if r == nil {
		return nil
	}
	var out []PartRow
	idx := map[string]int{}
	for i, f := range r.Findings {
		if f.Part == nil || f.Severity < model.Warn {
			continue
		}
		p := f.Part
		key := strings.ToLower(strings.TrimSpace(p.Kind)) + "\x00"
		if s := strings.TrimSpace(p.Serial); s != "" {
			key += "s:" + s
		} else {
			key += "l:" + p.Location + "\x00" + p.Model + "\x00" + f.Target
		}
		title := model.T(f.Title.In("en"), f.Title.In("vi"))
		if j, ok := idx[key]; ok {
			row := &out[j]
			row.Why.EN = joinNonEmpty(row.Why.EN, title.EN, "; ")
			row.Why.VI = joinNonEmpty(row.Why.VI, title.VI, "; ")
			if !containsStr(row.IDs, f.ID) {
				row.IDs = append(row.IDs, f.ID)
			}
			if f.Severity > row.Severity {
				row.Severity, row.Finding = f.Severity, i
			}
			continue
		}
		loc := p.Location
		if loc == "" {
			loc = f.Target
		}
		idx[key] = len(out)
		out = append(out, PartRow{
			Kind: PartKindText(p.Kind), Vendor: p.Vendor, Model: p.Model,
			Serial: p.Serial, Location: loc, Firmware: p.Firmware, Size: p.Size,
			Severity: f.Severity, Finding: i, IDs: []string{f.ID}, Target: f.Target,
			Why: title,
		})
	}
	// Crit rows first, otherwise in finding order.
	sorted := make([]PartRow, 0, len(out))
	for _, p := range out {
		if p.Severity >= model.Crit {
			sorted = append(sorted, p)
		}
	}
	for _, p := range out {
		if p.Severity < model.Crit {
			sorted = append(sorted, p)
		}
	}
	return sorted
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// joinNonEmpty joins a and b unless b is empty or already part of a.
func joinNonEmpty(a, b, sep string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	for _, x := range strings.Split(a, sep) {
		if x == b {
			return a
		}
	}
	return a + sep + b
}

// partLine is a part on one line ("Seagate ST4000NM0035 4 TB"), without the
// serial and location.
func partLine(p PartRow) string {
	var s []string
	for _, v := range []string{p.Vendor, p.Model, p.Size} {
		if v = strings.TrimSpace(v); v != "" {
			s = append(s, v)
		}
	}
	return strings.Join(s, " ")
}

// RMAText is the plain-text parts list for a warranty email: the server's
// identity first, then one block per part. It is "" when no part needs
// replacing.
func RMAText(r *model.Report, lang string) string {
	parts := Parts(r)
	if len(parts) == 0 {
		return ""
	}
	L := func(k string) string { return label(k).In(lang) }
	var b strings.Builder
	h := r.Host
	fmt.Fprintf(&b, "%s: %s\n", L("host"), orDash(h.Hostname))
	if v := strings.TrimSpace(h.Vendor + " " + h.Model); v != "" {
		fmt.Fprintf(&b, "%s: %s\n", L("model"), v)
	}
	if h.Serial != "" {
		fmt.Fprintf(&b, "%s: %s\n", L("serialTag"), h.Serial)
	}
	if !r.Collected.IsZero() {
		fmt.Fprintf(&b, "%s: %s\n", L("collected"), fmtTime(r.Collected))
	}
	b.WriteString("\n")
	for i, p := range parts {
		fmt.Fprintf(&b, "%d. %s", i+1, p.Kind.In(lang))
		if l := partLine(p); l != "" {
			fmt.Fprintf(&b, ": %s", l)
		}
		b.WriteString("\n")
		if p.Serial != "" {
			fmt.Fprintf(&b, "   %s: %s\n", L("serial"), p.Serial)
		}
		if p.Location != "" {
			fmt.Fprintf(&b, "   %s: %s\n", L("location"), p.Location)
		}
		if p.Firmware != "" {
			fmt.Fprintf(&b, "   %s: %s\n", L("firmware"), p.Firmware)
		}
		fmt.Fprintf(&b, "   %s: %s\n", L("why"), p.Why.In(lang))
	}
	return clean(b.String(), true)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// splitFix separates a coverage Fix text into the explanation and a command
// that can be copied as is: "Install it: dnf install -y smartmontools" ->
// ("Install it:", "dnf install -y smartmontools"). cmd is "" when the text
// holds no command; the prose is then the whole text.
func splitFix(s string) (prose, cmd string) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], ": ")
		if j < 0 {
			break
		}
		j += i
		if rest := strings.TrimSpace(s[j+2:]); looksLikeCommand(rest) {
			return strings.TrimSpace(s[:j+1]), rest
		}
		i = j + 2
	}
	return s, ""
}

// fixParts returns what a coverage entry says to do: the explanation and the
// command to copy. Coverage.Cmd wins when set (Fix is then all prose);
// otherwise a command is looked for inside the Fix text (older collectors
// and checks that put "Install it: dnf install -y x" in Fix).
func fixParts(fix, cmd string) (prose, command string) {
	fix = strings.TrimSpace(fix)
	if cmd = strings.TrimSpace(cmd); cmd != "" {
		return fix, cmd
	}
	return splitFix(fix)
}

// commandWords are the first words of the commands that hint and the checks
// put in Fix texts.
var commandWords = map[string]bool{
	"sudo": true, "dnf": true, "yum": true, "apt": true, "apt-get": true, "zypper": true,
	"apk": true, "pacman": true, "systemctl": true, "modprobe": true, "sensors-detect": true,
	"smartctl": true, "ipmitool": true, "diagward": true, "mdadm": true, "zpool": true,
	"ras-mc-ctl": true, "mcelog": true, "journalctl": true, "dmesg": true, "nvme": true,
	"storcli": true, "storcli64": true, "perccli": true, "perccli64": true, "ssacli": true,
	"arcconf": true, "edac-util": true, "memtester": true, "lsblk": true, "ethtool": true,
	"winget": true, "choco": true, "powershell": true, "pwsh": true, "pveversion": true,
	"update-pciids": true, "setenforce": true, "dpkg": true, "rpm": true,
}

func looksLikeCommand(s string) bool {
	f := strings.Fields(s)
	if len(f) == 0 || strings.Contains(s, "\n") {
		return false
	}
	first := f[0]
	isCmd := commandWords[first] || strings.HasPrefix(first, "/") || strings.HasPrefix(first, "./") ||
		// PowerShell cmdlets: Verb-Noun
		(len(first) > 4 && strings.Contains(first, "-") && first[0] >= 'A' && first[0] <= 'Z' && !strings.ContainsAny(first, ".,:"))
	if !isCmd {
		return false
	}
	// "sudo is needed." is a sentence, not a command.
	return !strings.HasSuffix(s, ".")
}

// covGroup is one or more coverage entries that share their state, reason
// and fix ("Needs root" for seven checks becomes one item).
type covGroup struct {
	State  string
	Names  []model.Text
	Comps  []string
	Reason model.Text
	Fix    model.Text
	Cmd    string
}

// coverageGroups groups r.Coverage, failed first, then partial, skipped and
// (when withRan) ran.
func coverageGroups(r *model.Report, withRan bool) []covGroup {
	if r == nil {
		return nil
	}
	var out []covGroup
	idx := map[string]int{}
	for _, c := range r.Coverage {
		st := c.State
		switch st {
		case model.CovRan, model.CovPartial, model.CovSkipped, model.CovFailed:
		default:
			st = model.CovFailed // unknown state: never pretend it ran
		}
		if st == model.CovRan && !withRan {
			continue
		}
		key := st
		if st != model.CovRan {
			key += "\x00" + c.Reason.EN + "\x00" + c.Reason.VI + "\x00" + c.Fix.EN + "\x00" + c.Fix.VI
			if c.Reason.IsZero() && c.Fix.IsZero() {
				key += "\x00" + c.ID // nothing shared to say: keep it separate
			}
		}
		name := c.Name
		if name.IsZero() {
			name = model.T(c.ID, c.ID)
		}
		if j, ok := idx[key]; ok {
			out[j].Names = append(out[j].Names, name)
			out[j].Comps = append(out[j].Comps, c.Component)
			continue
		}
		idx[key] = len(out)
		out = append(out, covGroup{State: st, Names: []model.Text{name}, Comps: []string{c.Component}, Reason: c.Reason, Fix: c.Fix, Cmd: c.Cmd})
	}
	sorted := make([]covGroup, 0, len(out))
	for _, st := range []string{model.CovFailed, model.CovPartial, model.CovSkipped, model.CovRan} {
		for _, g := range out {
			if g.State == st {
				sorted = append(sorted, g)
			}
		}
	}
	return sorted
}

// names joins the group's check names, without duplicates.
func (g covGroup) names(lang string) string {
	s := make([]string, 0, len(g.Names))
	seen := map[string]bool{}
	for _, n := range g.Names {
		v := n.In(lang)
		if !seen[v] {
			seen[v] = true
			s = append(s, v)
		}
	}
	return strings.Join(s, ", ")
}

// fmtTime formats a timestamp on the target machine's clock, with its offset.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05 -07:00")
}

func fmtSeconds(sec float64) model.Text {
	switch {
	case !(sec > 0) || sec > 1e9: // also rejects NaN
		return model.Text{}
	case sec < 10:
		return model.Tf("%.1f s", "%.1f giây", sec)
	case sec < 60:
		return model.Tf("%.0f s", "%.0f giây", sec)
	}
	m, s := int(sec)/60, int(sec)%60
	return model.Tf("%d min %d s", "%d phút %d giây", m, s)
}

func fmtUptime(sec float64) model.Text {
	if !(sec > 0) || sec > 1e10 {
		return model.Text{}
	}
	return units.Duration(time.Duration(sec * float64(time.Second)))
}

// virtualText describes whether the machine is virtual.
func virtualText(r *model.Report) model.Text {
	v := r.Host.Virtual
	if v == "" {
		v = r.Env.Virtual
	}
	switch {
	case r.Env.OS == "bmc":
		return model.T("read out-of-band from the BMC", "đọc từ xa qua BMC")
	case r.Env.Container && v != "":
		return model.Tf("container (%s)", "container (%s)", v)
	case r.Env.Container:
		return model.T("container", "container")
	case v != "":
		return model.Tf("yes (%s)", "có (%s)", v)
	}
	return model.T("no (physical machine)", "không (máy vật lý)")
}

// kv is one identity line.
type kv struct {
	Key model.Text
	Val model.Text
}

// identity lists the header facts; extra adds the inventory lines that
// verbose output and the HTML card show.
func identity(r *model.Report, extra bool) []kv {
	h := r.Host
	var out []kv
	add := func(k string, v model.Text) {
		if strings.TrimSpace(v.EN) != "" || strings.TrimSpace(v.VI) != "" {
			out = append(out, kv{label(k), v})
		}
	}
	same := func(s string) model.Text { return model.T(s, s) }
	add("host", same(h.Hostname))
	add("model", same(strings.TrimSpace(h.Vendor+" "+h.Model)))
	add("serialTag", same(h.Serial))
	osName := h.OS
	if osName == "" && r.Env.Distro != "" {
		osName = strings.TrimSpace(r.Env.Distro + " " + r.Env.DistroVer)
	}
	add("os", same(osName))
	add("kernel", same(strings.TrimSpace(h.Kernel+" "+h.Arch)))
	if extra {
		add("cpu", same(h.CPU))
		if h.MemBytes > 0 {
			add("ram", same(units.IEC(h.MemBytes)))
		}
		add("board", same(h.Board))
		add("bios", same(h.BIOS))
		add("bmcAddr", same(h.BMC))
	}
	add("uptime", fmtUptime(h.Uptime))
	if r.Env.OS != "" || h.Virtual != "" {
		add("virtual", virtualText(r))
	}
	if r.Env.OS != "" && r.Env.OS != "bmc" {
		if r.Env.Root {
			add("privilege", label("privRoot"))
		} else {
			add("privilege", label("privUser"))
		}
	}
	add("collected", same(fmtTime(r.Collected)))
	add("duration", fmtSeconds(r.Seconds))
	return out
}

// compMark is the status glyph of a component in the overview: its severity,
// or "partly checked" when nothing worse than a note was found.
func compMark(s model.ComponentSummary, ascii bool) string {
	if isPartial(s) {
		if ascii {
			return "[PART]"
		}
		return "◐"
	}
	return sevMark(s.Severity, s.Checked, ascii)
}

// sevMark is the status glyph for a severity, or for an unchecked component.
func sevMark(s model.Severity, checked, ascii bool) string {
	if ascii {
		switch {
		case !checked:
			return "[--]"
		case s >= model.Crit:
			return "[CRIT]"
		case s == model.Warn:
			return "[WARN]"
		case s == model.Info:
			return "[INFO]"
		}
		return "[OK]"
	}
	switch {
	case !checked:
		return "–"
	case s >= model.Crit:
		return "✗"
	case s == model.Warn:
		return "⚠"
	case s == model.Info:
		return "i"
	}
	return "✓"
}
