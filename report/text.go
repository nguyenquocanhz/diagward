package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/nguyenquocanhz/diagward/model"
)

// ANSI styles. They are only written when Options.Color is set, and always
// around text whose width was measured without them.
const (
	stCrit = "1;31" // bold red
	stWarn = "33"   // yellow
	stOK   = "32"   // green
	stInfo = "2"    // dim
	stDim  = "2"
	stBold = "1"
	stCmd  = "36" // cyan: commands to copy
)

func sevStyle(s model.Severity, checked bool) string {
	switch {
	case !checked:
		return stDim
	case s >= model.Crit:
		return stCrit
	case s == model.Warn:
		return stWarn
	case s == model.Info:
		return stInfo
	}
	return stOK
}

// seg is a piece of a line with its style.
type seg struct {
	s     string
	style string
}

type textWriter struct {
	b    strings.Builder
	o    Options
	w    int
	lang string
}

const minWidth = 24

// Text renders the report for a terminal: a header, a verdict banner, the
// component grid, findings with actions, the parts to replace, what could
// not be checked and how to enable it, notes and a footer. No line is wider
// than o.Width cells (0 means 100; widths below 24 are treated as 24).
func Text(w io.Writer, r *model.Report, o Options) error {
	if r == nil {
		r = &model.Report{}
	}
	t := &textWriter{o: o, w: o.Width, lang: o.lang()}
	if t.w <= 0 {
		t.w = 100
	}
	if t.w < minWidth {
		t.w = minWidth
	}
	t.render(r)
	_, err := io.WriteString(w, t.b.String())
	return err
}

func (t *textWriter) tr(x model.Text) string { return clean(x.In(t.lang), true) }
func (t *textWriter) L(k string) string      { return label(k).In(t.lang) }

// emit writes one line made of segments, cut to the width.
func (t *textWriter) emit(segs ...seg) {
	room := t.w
	for _, sg := range segs {
		if room <= 0 {
			break
		}
		s := clean(sg.s, false)
		if t.o.ASCII {
			// Same-width ASCII stand-ins for the separators the renderer uses.
			s = asciiSep.Replace(s)
		}
		if sw := strWidth(s); sw > room {
			s = truncate(s, room, t.o.ASCII)
		}
		room -= strWidth(s)
		if t.o.Color && sg.style != "" && s != "" {
			t.b.WriteString("\x1b[" + sg.style + "m" + s + "\x1b[0m")
		} else {
			t.b.WriteString(s)
		}
	}
	t.b.WriteString("\n")
}

func (t *textWriter) blank() { t.b.WriteString("\n") }

// para writes text wrapped to the width: first is the prefix of the first
// line and indent the width of the following ones' indentation.
func (t *textWriter) para(first string, firstStyle string, text string, indent int, style string) {
	avail := max(t.w-indent, 8)
	// A prefix wider than the indent ("→ What to do: ") makes the first
	// line shorter.
	first1 := max(t.w-max(strWidth(first), indent), 8)
	lines := wrap2(clean(text, true), first1, avail)
	for i, l := range lines {
		if i == 0 {
			t.emit(seg{pad(first, indent), firstStyle}, seg{l, style})
			continue
		}
		t.emit(seg{strings.Repeat(" ", indent), ""}, seg{l, style})
	}
}

// heading writes a section title as a rule: "── TITLE ───────".
func (t *textWriter) heading(title string) {
	t.blank()
	title = strings.ToUpper(clean(title, false))
	lead, fill := "── ", "─"
	if t.o.ASCII {
		lead, fill = "-- ", "-"
	}
	s := lead + title + " "
	if n := t.w - strWidth(s); n > 0 {
		s += strings.Repeat(fill, min(n, 200))
	}
	t.emit(seg{s, stBold})
}

func (t *textWriter) render(r *model.Report) {
	t.header(r)
	t.banner(r)
	t.grid(r)
	t.findings(r)
	t.okFindings(r)
	t.parts(r)
	t.coverage(r)
	if t.o.Verbose {
		t.tables(r)
	}
	t.notes(r)
	t.footer(r)
}

func (t *textWriter) header(r *model.Report) {
	name := "DIAGWARD"
	t.emit(seg{name, stBold}, seg{" · " + t.L("title"), ""})
	ids := identity(r, t.o.Verbose)
	kw := 0
	for _, x := range ids {
		kw = max(kw, strWidth(t.tr(x.Key)))
	}
	kw = min(kw+2, t.w/2)
	for _, x := range ids {
		key := truncate(t.tr(x.Key), kw-2, t.o.ASCII)
		t.para("  "+key, stDim, t.tr(x.Val), kw+2, "")
	}
}

func (t *textWriter) banner(r *model.Report) {
	sev := headlineSeverity(r)
	style := sevStyle(sev, true)
	tl, tr, bl, br, h, v := "╭", "╮", "╰", "╯", "─", "│"
	if t.o.ASCII {
		tl, tr, bl, br, h, v = "+", "+", "+", "+", "-", "|"
	}
	inner := t.w - 4
	mark := sevMark(sev, true, t.o.ASCII)
	if nothingChecked(r) {
		mark = sevMark(model.Info, false, t.o.ASCII) // nothing checked: "–" / "[--]"
	}
	head := mark + "  " + t.tr(Headline(r))
	indent := strWidth(mark) + 2
	t.blank()
	t.emit(seg{tl + strings.Repeat(h, inner+2) + tr, style})
	line := func(s, st string) {
		s = truncate(s, inner, t.o.ASCII)
		t.emit(seg{v + " ", style}, seg{pad(s, inner), st}, seg{" " + v, style})
	}
	line(head, style)
	for _, l := range wrap(t.tr(subline(r)), max(inner-indent, 8)) {
		line(strings.Repeat(" ", indent)+l, "")
	}
	t.emit(seg{bl + strings.Repeat(h, inner+2) + br, style})
}

func (t *textWriter) grid(r *model.Report) {
	sum := summaryOf(r)
	t.heading(t.L("components"))
	type cell struct {
		mark, text string
		style      string
	}
	markW := 1
	if t.o.ASCII {
		markW = 6
	}
	cells := make([]cell, 0, len(sum))
	cw := 0
	anyPartial := false
	for _, s := range sum {
		txt := t.tr(compName(s))
		if n := s.Crit + s.Warn; n > 0 && s.Checked {
			txt += fmt.Sprintf(" (%d)", n)
		}
		c := cell{compMark(s, t.o.ASCII), txt, sevStyle(s.Severity, s.Checked)}
		if isPartial(s) {
			anyPartial = true
		}
		cells = append(cells, c)
		cw = max(cw, markW+1+strWidth(c.text))
	}
	const gap = 3
	avail := t.w - 2
	cw = min(cw, avail)
	cols := max(1, (avail+gap)/(cw+gap))
	for i := 0; i < len(cells); i += cols {
		segs := []seg{{"  ", ""}}
		for j := i; j < i+cols && j < len(cells); j++ {
			c := cells[j]
			m := pad(c.mark, markW)
			txt := truncate(c.text, cw-markW-1, t.o.ASCII)
			if j > i {
				segs = append(segs, seg{strings.Repeat(" ", gap), ""})
			}
			last := j == i+cols-1 || j == len(cells)-1
			if !last {
				txt = pad(txt, cw-markW-1)
			}
			segs = append(segs, seg{m + " ", c.style}, seg{txt, ""})
		}
		t.emit(segs...)
	}
	// legend
	type lg struct {
		sev     model.Severity
		checked bool
		word    model.Text
	}
	var segs []seg
	segs = append(segs, seg{"  ", ""})
	legend := []lg{
		{model.OK, true, SeverityText(model.OK)},
		{model.Warn, true, SeverityText(model.Warn)},
		{model.Crit, true, SeverityText(model.Crit)},
		{model.Info, true, SeverityText(model.Info)},
	}
	for i, x := range legend {
		if i > 0 {
			segs = append(segs, seg{"  ", ""})
		}
		segs = append(segs, seg{sevMark(x.sev, x.checked, t.o.ASCII) + " " + strings.ToLower(x.word.In(t.lang)), stDim})
	}
	if anyPartial {
		segs = append(segs, seg{"  ", ""}, seg{compMark(model.ComponentSummary{Checked: true, Partial: true}, t.o.ASCII) + " " + StateText(model.CovPartial).In(t.lang), stDim})
	}
	segs = append(segs, seg{"  ", ""}, seg{sevMark(model.OK, false, t.o.ASCII) + " " + StateText(model.CovSkipped).In(t.lang), stDim})
	t.emitWrapped(segs)
}

// emitWrapped writes segments, moving whole segments to the next line when
// they do not fit.
func (t *textWriter) emitWrapped(segs []seg) {
	var line []seg
	used := 0
	for _, s := range segs {
		sw := strWidth(s.s)
		if used+sw > t.w && len(line) > 1 {
			t.emit(line...)
			line, used = []seg{{"  ", ""}}, 2
			if strings.TrimSpace(s.s) == "" {
				continue
			}
		}
		line = append(line, s)
		used += sw
	}
	if len(line) > 0 {
		t.emit(line...)
	}
}

func (t *textWriter) findings(r *model.Report) {
	var list []int
	for i, f := range r.Findings {
		if f.Severity > model.OK {
			list = append(list, i)
		}
	}
	t.heading(fmt.Sprintf("%s (%d)", t.L("findings"), len(list)))
	if len(list) == 0 {
		t.para("  ", "", t.L("noFindings"), 2, stOK)
		return
	}
	numW := len(fmt.Sprint(len(list)))
	indent := 2 + numW + 2 // "  12. "
	arrow := "→ "
	if t.o.ASCII {
		arrow = "-> "
	}
	for n, i := range list {
		f := r.Findings[i]
		if n > 0 {
			t.blank()
		}
		st := sevStyle(f.Severity, true)
		num := fmt.Sprintf("  %*d. ", numW, n+1)
		meta := sevMark(f.Severity, true, t.o.ASCII) + " " + SeverityText(f.Severity).In(t.lang)
		if f.Component != "" {
			meta += " · " + t.tr(model.ComponentName(f.Component))
		}
		if f.Target != "" {
			meta += " · " + clean(f.Target, false)
		}
		t.emit(seg{num, ""}, seg{truncate(meta, t.w-indent, t.o.ASCII), st})
		ind := strings.Repeat(" ", indent)
		t.para(ind, "", t.tr(f.Title), indent, stBold)
		if d := t.tr(f.Detail); strings.TrimSpace(d) != "" {
			t.para(ind, "", d, indent, "")
		}
		if a := t.tr(f.Action); strings.TrimSpace(a) != "" {
			prefix := arrow + t.L("action") + ": "
			// The action wraps under its own text, after the arrow.
			t.para(ind+prefix, st, a, indent+strWidth(arrow), "")
		}
		if t.o.Verbose && len(f.Evidence) > 0 {
			t.emit(seg{ind + t.L("evidence") + ":", stDim})
			bar := "│ "
			if t.o.ASCII {
				bar = "| "
			}
			for _, e := range f.Evidence {
				t.emit(seg{ind + "  " + bar + clean(e, false), stDim})
			}
		}
	}
}

func (t *textWriter) okFindings(r *model.Report) {
	var list []model.Finding
	for _, f := range r.Findings {
		if f.Severity <= model.OK {
			list = append(list, f)
		}
	}
	if len(list) == 0 {
		return
	}
	t.heading(fmt.Sprintf("%s (%d)", t.L("okChecked"), len(list)))
	mark := sevMark(model.OK, true, t.o.ASCII) + " "
	for _, f := range list {
		title := t.tr(f.Title)
		if t.o.Verbose {
			t.para("  "+mark, stOK, title, 2+strWidth(mark), "")
			continue
		}
		t.emit(seg{"  " + mark, stOK}, seg{title, ""})
	}
}

func (t *textWriter) parts(r *model.Report) {
	parts := Parts(r)
	if len(parts) == 0 {
		return
	}
	t.heading(t.L("parts") + " · " + t.L("partsSub"))
	numW := len(fmt.Sprint(len(parts)))
	indent := 2 + numW + 2
	ind := strings.Repeat(" ", indent)
	for i, p := range parts {
		if i > 0 {
			t.blank()
		}
		st := sevStyle(p.Severity, true)
		head := sevMark(p.Severity, true, t.o.ASCII) + " " + t.tr(p.Kind)
		if l := partLine(p); l != "" {
			head += ": " + clean(l, false)
		}
		t.para(fmt.Sprintf("  %*d. ", numW, i+1), "", head, indent, st)
		var facts []string
		add := func(k, v string) {
			if v = strings.TrimSpace(clean(v, false)); v != "" {
				facts = append(facts, t.L(k)+": "+v)
			}
		}
		add("serial", p.Serial)
		add("location", p.Location)
		add("firmware", p.Firmware)
		if len(facts) > 0 {
			t.para(ind, "", strings.Join(facts, " · "), indent, "")
		}
		t.para(ind+t.L("why")+": ", stDim, t.tr(p.Why), indent, "")
	}
}

func (t *textWriter) stateMark(state string) string {
	if t.o.ASCII {
		switch state {
		case model.CovFailed:
			return "[FAIL]"
		case model.CovPartial:
			return "[PART]"
		case model.CovRan:
			return "[OK]"
		}
		return "[SKIP]"
	}
	switch state {
	case model.CovFailed:
		return "✗"
	case model.CovPartial:
		return "◐"
	case model.CovRan:
		return "✓"
	}
	return "–"
}

func stateStyle(state string) string {
	switch state {
	case model.CovFailed:
		return stWarn
	case model.CovRan:
		return stOK
	}
	return stDim
}

func (t *textWriter) coverage(r *model.Report) {
	groups := coverageGroups(r, false)
	if len(groups) > 0 {
		n := 0
		for _, g := range groups {
			n += len(g.Names)
		}
		t.heading(fmt.Sprintf("%s (%d)", t.L("notChecked"), n))
		cont := " \\"
		if r.Env.OS == "windows" {
			cont = " `"
		}
		for i, g := range groups {
			if i > 0 {
				t.blank()
			}
			mark := t.stateMark(g.State) + " "
			indent := 2 + strWidth(mark)
			ind := strings.Repeat(" ", indent)
			t.para("  "+mark, stateStyle(g.State), g.names(t.lang)+" ("+StateText(g.State).In(t.lang)+")", indent, stBold)
			if s := t.tr(g.Reason); strings.TrimSpace(s) != "" {
				t.para(ind, "", s, indent, "")
			}
			if s := t.tr(g.Fix); strings.TrimSpace(s) != "" || strings.TrimSpace(g.Cmd) != "" {
				prose, cmd := fixParts(s, g.Cmd)
				if prose != "" {
					t.para(ind, "", prose, indent, stDim)
				}
				if cmd != "" {
					cind := indent + 2
					for _, l := range cmdLines(cmd, t.w-cind, cont) {
						t.emit(seg{strings.Repeat(" ", cind), ""}, seg{l, stCmd})
					}
				}
			}
		}
	}
	if !t.o.Verbose {
		return
	}
	ran := coverageGroups(r, true)
	for _, g := range ran {
		if g.State != model.CovRan {
			continue
		}
		t.heading(fmt.Sprintf("%s (%d)", t.L("covRan"), len(g.Names)))
		mark := t.stateMark(model.CovRan) + " "
		t.para("  "+mark, stOK, g.names(t.lang), 2+strWidth(mark), "")
	}
}

// cmdLines splits a command so each line fits in w cells, joining the pieces
// with a line continuation (" \" for sh, " `" for PowerShell) so the copied
// lines still run. A command that fits is returned unchanged.
func cmdLines(cmd string, w int, cont string) []string {
	cmd = clean(cmd, false)
	if w < 12 {
		w = 12
	}
	if strWidth(cmd) <= w {
		return []string{cmd}
	}
	var out []string
	cur := ""
	for _, word := range strings.Fields(cmd) {
		switch {
		case cur == "":
			cur = word
		case strWidth(cur)+1+strWidth(word)+len(cont) <= w:
			cur += " " + word
		default:
			out = append(out, cur+cont)
			cur = "  " + word
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	// A single word longer than the line cannot be split safely; emit()
	// truncates it, which is visible ("…") rather than silently wrong.
	return out
}

func (t *textWriter) tables(r *model.Report) {
	var tables []model.Table
	for _, res := range r.Results {
		tables = append(tables, res.Tables...)
	}
	if len(tables) == 0 {
		return
	}
	t.heading(t.L("tables"))
	for i, tb := range tables {
		if i > 0 {
			t.blank()
		}
		title := t.tr(tb.Title)
		if strings.TrimSpace(title) == "" {
			title = tb.ID
		}
		t.para("  ", "", title, 2, stBold)
		t.table(tb)
		if n := t.tr(tb.Note); strings.TrimSpace(n) != "" {
			t.para("  ", "", n, 2, stDim)
		}
	}
}

// table writes an aligned table: a status mark column, then the cells.
// Columns shrink (widest first) until the table fits; cut cells end in "…".
func (t *textWriter) table(tb model.Table) {
	ncol := len(tb.Columns)
	for _, row := range tb.Rows {
		ncol = max(ncol, len(row.Cells))
	}
	if ncol == 0 {
		return
	}
	cellAt := func(cells []string, i int) string {
		if i < len(cells) {
			return clean(cells[i], false)
		}
		return ""
	}
	heads := make([]string, ncol)
	for i := range heads {
		if i < len(tb.Columns) {
			heads[i] = t.tr(tb.Columns[i])
		}
	}
	const maxCol = 48
	widths := make([]int, ncol)
	for i := range widths {
		widths[i] = min(strWidth(heads[i]), maxCol)
		for _, row := range tb.Rows {
			widths[i] = max(widths[i], min(strWidth(cellAt(row.Cells, i)), maxCol))
		}
		widths[i] = max(widths[i], 1)
	}
	markW := 1
	if t.o.ASCII {
		markW = 6
	}
	const gap = 2
	avail := t.w - 2 - markW - gap*ncol
	total := func() int {
		s := 0
		for _, w := range widths {
			s += w
		}
		return s
	}
	// Identifiers (the first column, serials, devices, slots) are what
	// people copy into tickets, so other columns shrink first; then
	// everything shrinks, widest first.
	protected := make([]bool, ncol)
	for i := range protected {
		h := ""
		if i < len(tb.Columns) {
			h = strings.ToLower(tb.Columns[i].EN)
		}
		protected[i] = i == 0 || strings.Contains(h, "serial") || strings.Contains(h, "device") ||
			strings.Contains(h, "slot") || strings.Contains(h, "locator") || strings.Contains(h, "location")
	}
	shrink := func(onlyFree bool, floor int) {
		for total() > avail {
			wi := -1
			for i, w := range widths {
				if (onlyFree && protected[i]) || w <= floor {
					continue
				}
				if wi < 0 || w > widths[wi] {
					wi = i
				}
			}
			if wi < 0 {
				return
			}
			widths[wi]--
		}
	}
	shrink(true, 6)
	shrink(false, 3) // emit() cuts whatever still does not fit
	row := func(mark, markStyle string, cells []string, style string) {
		segs := []seg{{"  ", ""}, {pad(mark, markW), markStyle}}
		for i := 0; i < ncol; i++ {
			c := truncate(cellAt(cells, i), widths[i], t.o.ASCII)
			if i < ncol-1 {
				c = pad(c, widths[i])
			}
			segs = append(segs, seg{strings.Repeat(" ", gap), ""}, seg{c, style})
		}
		t.emit(segs...)
	}
	row("", "", heads, stBold)
	rule := "─"
	if t.o.ASCII {
		rule = "-"
	}
	rl := make([]string, ncol)
	for i := range rl {
		rl[i] = strings.Repeat(rule, widths[i])
	}
	row("", "", rl, stDim)
	for _, rw := range tb.Rows {
		row(sevMark(rw.Status, true, t.o.ASCII), sevStyle(rw.Status, true), rw.Cells, "")
	}
}

func (t *textWriter) notes(r *model.Report) {
	var notes []string
	for _, n := range r.Notes {
		if s := strings.TrimSpace(t.tr(n)); s != "" {
			notes = append(notes, s)
		}
	}
	if len(notes) == 0 {
		return
	}
	t.heading(t.L("notes"))
	bullet := "• "
	if t.o.ASCII {
		bullet = "* "
	}
	for _, n := range notes {
		t.para("  "+bullet, "", n, 2+strWidth(bullet), "")
	}
}

func (t *textWriter) footer(r *model.Report) {
	t.blank()
	rule := "─"
	if t.o.ASCII {
		rule = "-"
	}
	t.emit(seg{strings.Repeat(rule, t.w), stDim})
	var hints []string
	if !t.o.NoHints {
		hints = []string{t.L("htmlHint"), t.L("langHint")}
		if !t.o.Verbose {
			hints = append(hints, t.L("verboseHint"))
		}
	}
	ver := "Diagward"
	if r.Version != "" {
		ver += " " + r.Version
	}
	for _, h := range hints {
		t.para("", "", h, 0, stDim)
	}
	t.para("", "", ver+" · "+RepoURL, 0, stDim)
}

var asciiSep = strings.NewReplacer("·", "-", "–", "-", "—", "-")
