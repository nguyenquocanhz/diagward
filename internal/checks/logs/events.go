package logs

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// spec is what one rule says about the events it matches. Linux kernel
// patterns and Windows event IDs share it.
//
// Texts may contain placeholders: {t} target, {n} number of events,
// {first} / {last} first and last time seen, {r} events in the last 24 h.
type spec struct {
	ID   string // finding rule; the finding ID is "logs.<ID>"
	Comp string
	Sev  model.Severity // severity once the rule is reported
	// Min is the weighted count needed to report at Sev (0 or 1 = any
	// event). Below it the group gets Below (OK = listed in the table only).
	Min   int
	Below model.Severity
	// CritAt raises the severity to Crit from this weighted count (0 = never),
	// but only while the last event is less than 72 hours old: a storm that
	// stopped days ago (an unplugged USB disk, a reseated cable, a SAN path
	// that failed over) is history and stays at Sev. Rules whose single
	// event already means "failing now" use Sev: model.Crit instead.
	CritAt int
	// Decay lowers Warn to Info when nothing happened in the last 72 hours:
	// a transient that stopped (a cable that was reseated, a load spike).
	Decay bool
	// CritRecent makes the group Crit while the last event is less than
	// 72 hours old (it is Sev otherwise).
	CritRecent bool

	Title, Detail, Action model.Text
}

// recentWindow is "recent" for weighting: events in the last 24 h count
// three times, so a burst today outranks the same number a week ago.
const recentWindow = 24 * time.Hour

// decayWindow: a Warn rule with Decay drops to Info after 72 h of silence.
const decayWindow = 72 * time.Hour

// group collects the events of one rule and one target.
type group struct {
	spec    *spec
	target  string
	count   int // counted events
	recent  int // counted events in the last 24 h
	first   time.Time
	last    time.Time
	samples []string // raw lines, in order
	capped  bool     // severity is limited to capSev (e.g. a smartd warning that later cleared)
	capSev  model.Severity
	note    model.Text // extra detail appended to the finding
	actNote model.Text // extra action appended to the finding's action
	part    *model.Part
	comp    string     // overrides spec.Comp when set
	action  model.Text // replaces spec.Action when set
	times   []time.Time
	ataDev  string // the disk ("/dev/sda") behind a libata port target, when known
}

// absorb folds the events of o (the same problem seen by another driver)
// into g. An event of o within win of one of g's is the same event: its
// lines become evidence only. Other events are counted.
func (g *group) absorb(o *group, win time.Duration, now time.Time) {
	own := append([]time.Time(nil), g.times...)
	for _, t := range o.times {
		if near(t, own, win) {
			continue
		}
		g.count++
		if !now.IsZero() && now.Sub(t) <= recentWindow {
			g.recent++
		}
		if g.first.IsZero() || t.Before(g.first) {
			g.first = t
		}
		if t.After(g.last) {
			g.last = t
		}
		g.times = append(g.times, t)
	}
	if len(o.times) == 0 && g.count == 0 {
		g.count = o.count // undated events: nothing to compare
	}
	if !o.first.IsZero() && !g.first.IsZero() && o.first.Before(g.first) {
		g.samples = append(append([]string(nil), o.samples...), g.samples...)
	} else {
		g.samples = append(g.samples, o.samples...)
	}
	g.note = joinText(g.note, o.note)
}

// limit caps the group's severity at sev (keeping a lower existing cap) and
// adds note to its detail and act to its action.
func (g *group) limit(sev model.Severity, note, act model.Text) {
	if !g.capped || sev < g.capSev {
		g.capped, g.capSev = true, sev
	}
	g.note = joinText(g.note, note)
	g.actNote = joinText(g.actNote, act)
}

func (g *group) weighted() int { return g.count + 2*g.recent }

type grouper struct {
	now    time.Time
	groups map[string]*group
	order  []string
}

func newGrouper(now time.Time) *grouper {
	return &grouper{now: now, groups: map[string]*group{}}
}

// add records one event. counted=false adds the line as evidence only.
func (gr *grouper) add(sp *spec, target string, t time.Time, raw string, counted bool) *group {
	key := groupKey(sp, target)
	g := gr.groups[key]
	if g == nil {
		g = &group{spec: sp, target: target}
		gr.groups[key] = g
		gr.order = append(gr.order, key)
	}
	if counted {
		g.count++
		if !t.IsZero() && !gr.now.IsZero() && gr.now.Sub(t) <= recentWindow {
			g.recent++
		}
		if !t.IsZero() {
			if g.first.IsZero() || t.Before(g.first) {
				g.first = t
			}
			if t.After(g.last) {
				g.last = t
			}
			g.times = append(g.times, t)
		}
	}
	if raw != "" {
		g.samples = append(g.samples, raw)
	}
	return g
}

func groupKey(sp *spec, target string) string { return sp.ID + "\x00" + target }

// get returns the group of a rule and target, or nil.
func (gr *grouper) get(sp *spec, target string) *group { return gr.groups[groupKey(sp, target)] }

// remove drops a group.
func (gr *grouper) remove(g *group) {
	key := groupKey(g.spec, g.target)
	if gr.groups[key] != g {
		return
	}
	delete(gr.groups, key)
	for i, k := range gr.order {
		if k == key {
			gr.order = append(gr.order[:i:i], gr.order[i+1:]...)
			break
		}
	}
}

// retarget renames a group's target, keeping its place in the order. The
// caller checks that no group has the new name yet.
func (gr *grouper) retarget(g *group, target string) {
	old := groupKey(g.spec, g.target)
	if gr.groups[old] != g {
		return
	}
	key := groupKey(g.spec, target)
	delete(gr.groups, old)
	g.target = target
	gr.groups[key] = g
	for i, k := range gr.order {
		if k == old {
			gr.order[i] = key
		}
	}
}

func (gr *grouper) list() []*group {
	out := make([]*group, 0, len(gr.order))
	for _, k := range gr.order {
		out = append(out, gr.groups[k])
	}
	return out
}

// severity decides how much a group matters.
func (g *group) severity(now time.Time) model.Severity {
	sp := g.spec
	w := g.weighted()
	sev := sp.Sev
	if sp.Min > 1 && w < sp.Min {
		sev = sp.Below
	}
	recent := !g.last.IsZero() && !now.IsZero() && now.Sub(g.last) <= decayWindow
	if sp.CritAt > 0 && w >= sp.CritAt && (recent || g.last.IsZero() || now.IsZero()) {
		sev = model.Crit
	}
	if sp.CritRecent && recent {
		sev = model.Crit
	}
	if sp.Decay && sev == model.Warn && !g.last.IsZero() && !now.IsZero() && !recent {
		sev = model.Info
	}
	if g.capped && sev > g.capSev {
		sev = g.capSev
	}
	return sev
}

func (g *group) component() string {
	if g.comp != "" {
		return g.comp
	}
	return g.spec.Comp
}

var digitsRe = regexp.MustCompile(`[0-9]+`)

// sampleLines keeps up to 8 lines that say different things: the first
// four and the last four distinct messages (numbers ignored when comparing).
func sampleLines(lines []string) []string {
	var uniq, keys []string
	seen := map[string]int{}
	for _, l := range lines {
		k := digitsRe.ReplaceAllString(stripStamp(l), "#")
		seen[k]++
		if seen[k] > 1 {
			continue
		}
		uniq = append(uniq, l)
		keys = append(keys, k)
	}
	for i, k := range keys {
		if n := seen[k]; n > 1 {
			uniq[i] = fmt.Sprintf("%s [x%d]", uniq[i], n)
		}
	}
	if len(uniq) <= 8 {
		return uniq
	}
	out := append([]string{}, uniq[:4]...)
	out = append(out, fmt.Sprintf("... %d more different lines", len(uniq)-8))
	return append(out, uniq[len(uniq)-4:]...)
}

// stripStamp removes the leading timestamp and host so that the same message
// at different times compares equal.
func stripStamp(l string) string {
	if m := reISO.FindStringSubmatch(l); m != nil {
		return m[3]
	}
	if m := reBSD.FindStringSubmatch(l); m != nil {
		return m[7]
	}
	if m := reDmesgT.FindStringSubmatch(l); m != nil {
		return m[2]
	}
	if m := reDmesg.FindStringSubmatch(l); m != nil {
		return m[3]
	}
	return l
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	return t.Format("2006-01-02 15:04")
}

func fill(t model.Text, g *group) model.Text {
	tgt := model.Text{EN: g.target, VI: g.target}
	if p, ok := placeholderTarget(g); ok {
		tgt = p
	}
	rep := func(s, target string) string {
		return strings.NewReplacer(
			"{t}", target,
			"{n}", fmt.Sprint(g.count),
			"{first}", fmtTime(g.first),
			"{last}", fmtTime(g.last),
			"{r}", fmt.Sprint(g.recent),
		).Replace(s)
	}
	return model.Text{EN: rep(t.EN, tgt.EN), VI: rep(t.VI, tgt.VI)}
}

// placeholderTarget is how texts name a target the log did not name: the
// group keys on a placeholder ("memory", "PCIe", "disk") but "Corrected
// memory errors: memory" or "Disk disk" must not reach the report.
func placeholderTarget(g *group) (model.Text, bool) {
	switch {
	case g.target == "memory" && (g.spec == spMemCE || g.spec == spMemUE):
		return model.T("DIMM not named in the log", "thanh RAM không rõ vị trí"), true
	case g.target == "PCIe" && (g.spec == spPCIeCorr || g.spec == spPCIeNonFatal || g.spec == spPCIeFatal):
		return model.T("(not named in the log)", "(log không ghi rõ)"), true
	case (g.target == "disk" || g.target == "volume") && strings.HasPrefix(g.spec.ID, "win_"), g.target == "":
		return model.T("(unknown)", "(không rõ)"), true
	}
	return model.Text{}, false
}

// seenText is the standard "how often, when" sentence of a group.
func seenText(g *group) model.Text {
	switch {
	case g.first.IsZero():
		return model.Tf("Seen %d times.", "Ghi nhận %d lần.", g.count)
	case g.count == 1:
		return model.Tf("Seen once, at %s.", "Ghi nhận 1 lần, lúc %s.", fmtTime(g.last))
	case fmtTime(g.first) == fmtTime(g.last):
		return model.Tf("Seen %d times at %s.", "Ghi nhận %d lần lúc %s.", g.count, fmtTime(g.last))
	case g.recent > 0:
		return model.Tf("Seen %d times between %s and %s (%d in the last 24 hours).",
			"Ghi nhận %d lần từ %s đến %s (%d lần trong 24 giờ qua).", g.count, fmtTime(g.first), fmtTime(g.last), g.recent)
	default:
		return model.Tf("Seen %d times between %s and %s, none in the last 24 hours.",
			"Ghi nhận %d lần từ %s đến %s, không có lần nào trong 24 giờ qua.", g.count, fmtTime(g.first), fmtTime(g.last))
	}
}

func joinText(parts ...model.Text) model.Text {
	var en, vi []string
	for _, p := range parts {
		if p.EN != "" {
			en = append(en, p.EN)
		}
		if p.VI != "" {
			vi = append(vi, p.VI)
		}
	}
	return model.Text{EN: strings.Join(en, " "), VI: strings.Join(vi, " ")}
}

// maxTargetsPerRule caps findings for one rule: a noisy pattern hitting many
// devices becomes 8 findings plus one summary, never hundreds.
const maxTargetsPerRule = 8

// maxFindings caps the findings one source can produce.
const maxFindings = 40

// eventRow is one line of the event summary table (and of the facts).
type EventFact struct {
	Rule      string         `json:"rule"`
	Component string         `json:"component"`
	Severity  model.Severity `json:"severity"`
	Target    string         `json:"target,omitempty"`
	Count     int            `json:"count"`
	Recent    int            `json:"recent24h"`
	First     time.Time      `json:"first,omitzero"`
	Last      time.Time      `json:"last,omitzero"`
}

// buildFindings turns groups into findings and fact rows, most severe first.
// vmNote is appended to hardware actions on virtual machines.
func buildFindings(groups []*group, now time.Time, vmNote model.Text) ([]model.Finding, []EventFact) {
	type scored struct {
		g   *group
		sev model.Severity
	}
	var all []scored
	for _, g := range groups {
		if g.count == 0 {
			continue // evidence-only lines without a counted event
		}
		all = append(all, scored{g, g.severity(now)})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].sev != all[j].sev {
			return all[i].sev > all[j].sev
		}
		if all[i].g.weighted() != all[j].g.weighted() {
			return all[i].g.weighted() > all[j].g.weighted()
		}
		return all[i].g.target < all[j].g.target
	})
	var (
		facts    []EventFact
		findings []model.Finding
		perRule  = map[string]int{}
		overflow = map[string][]*group{}
		ruleSev  = map[string]model.Severity{}
		ruleSpec = map[string]*spec{}
	)
	for _, s := range all {
		g := s.g
		facts = append(facts, EventFact{Rule: g.spec.ID, Component: g.component(), Severity: s.sev,
			Target: g.target, Count: g.count, Recent: g.recent, First: g.first, Last: g.last})
		if s.sev == model.OK {
			continue
		}
		if perRule[g.spec.ID] >= maxTargetsPerRule || len(findings) >= maxFindings {
			overflow[g.spec.ID] = append(overflow[g.spec.ID], g)
			ruleSev[g.spec.ID] = model.Worst(ruleSev[g.spec.ID], s.sev)
			ruleSpec[g.spec.ID] = g.spec
			continue
		}
		perRule[g.spec.ID]++
		f := model.Finding{
			ID:        "logs." + g.spec.ID,
			Component: g.component(),
			Severity:  s.sev,
			Target:    g.target,
			Title:     fill(g.spec.Title, g),
			Detail:    joinText(fill(g.spec.Detail, g), seenText(g), g.note),
			Evidence:  units.Evidence(sampleLines(g.samples), 10),
			Part:      g.part,
		}
		act := g.spec.Action
		if !g.action.IsZero() {
			act = g.action
		}
		if s.sev >= model.Warn || !act.IsZero() || !g.actNote.IsZero() {
			f.Action = joinText(g.actNote, fill(act, g), vmNote)
		}
		findings = append(findings, f)
	}
	// One summary finding per rule that overflowed.
	ids := make([]string, 0, len(overflow))
	for id := range overflow {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		gs := overflow[id]
		var names []string
		total := 0
		for _, g := range gs {
			total += g.count
			if len(names) < 20 {
				names = append(names, g.target)
			}
		}
		sp := ruleSpec[id]
		comp := gs[0].component()
		findings = append(findings, model.Finding{
			ID:        "logs." + id,
			Component: comp,
			Severity:  ruleSev[id],
			Target:    fmt.Sprintf("+%d", len(gs)),
			Title: model.Tf("%d more targets with the same problem (%s)", "Thêm %d đối tượng khác bị cùng lỗi (%s)",
				len(gs), id),
			Detail: model.Tf("%d events in total on: %s.", "Tổng cộng %d sự kiện trên: %s.", total, strings.Join(names, ", ")),
			Action: joinText(model.Text{EN: strings.ReplaceAll(sp.Action.EN, "{t}", "each of them"),
				VI: strings.ReplaceAll(sp.Action.VI, "{t}", "từng thiết bị")}, vmNote),
		})
	}
	return findings, facts
}

// eventTable renders the fact rows.
func eventTable(id string, title model.Text, facts []EventFact, note model.Text) model.Table {
	t := model.Table{
		ID:    id,
		Title: title,
		Columns: []model.Text{
			model.T("Event", "Sự kiện"), model.T("Component", "Thành phần"), model.T("Target", "Đối tượng"),
			model.T("Count", "Số lần"), model.T("Last 24 h", "24 giờ qua"), model.T("First seen", "Lần đầu"),
			model.T("Last seen", "Lần cuối"),
		},
		Note: note,
	}
	for _, f := range facts {
		t.Rows = append(t.Rows, model.NewRow(f.Severity,
			ruleName(f.Rule), model.ComponentName(f.Component), targetCell(f.Target), fmt.Sprint(f.Count), fmt.Sprint(f.Recent), fmtTime(f.First), fmtTime(f.Last),
		))
	}
	return t
}

var rePlural = regexp.MustCompile(`(\d+)([^\d()]*?)\(s\)`)

// tf is model.Tf with English plurals resolved: "1 time(s)" -> "1 time",
// "3 time(s)" -> "3 times".
func tf(en, vi string, args ...any) model.Text {
	t := model.Tf(en, vi, args...)
	t.EN = rePlural.ReplaceAllStringFunc(t.EN, func(s string) string {
		m := rePlural.FindStringSubmatch(s)
		if m[1] == "1" {
			return m[1] + m[2]
		}
		return m[1] + m[2] + "s"
	})
	return t
}
