package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/nguyenquocanhz/diagward/model"
)

//go:embed html.tmpl
var htmlSource string

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"L": func(k string) model.Text { return bi(label(k)) },
}).Parse(htmlSource))

// HTML renders the report as one self-contained HTML file: inline CSS and a
// little inline JavaScript, no network requests, no web fonts. Both
// languages are in the page; a VI/EN switch (starting at o.Lang) shows one,
// so the same file can go to a customer (Vietnamese) or to the hardware
// vendor (English). It prints to A4 with all details expanded. Every string
// from the report goes through html/template's contextual escaping.
func HTML(w io.Writer, r *model.Report, o Options) error {
	if r == nil {
		r = &model.Report{}
	}
	return htmlTmpl.Execute(w, buildView(r, o))
}

// bi fills both languages of a Text (falling back to the other one) and
// strips control characters, which are invalid in HTML.
func bi(t model.Text) model.Text {
	return model.Text{EN: clean(t.In("en"), true), VI: clean(t.In("vi"), true)}
}

func same(s string) model.Text { s = clean(s, true); return model.Text{EN: s, VI: s} }

type hView struct {
	Lang       string
	Title      model.Text
	Host       string
	HostSub    string
	Identity   []kv
	Class      string
	Mark       string
	Headline   model.Text
	Sub        model.Text
	Components []hComp
	DoNow      []hFinding
	Findings   []hFinding
	OK         []hFinding
	Parts      []hPart
	RMA        model.Text
	Tables     []hTable
	Coverage   []hCovSection
	Ran        []model.Text
	Notes      []model.Text
	Version    string
	Collected  string
	Duration   model.Text
	Repo       string
	TitleVI    string
	TitleEN    string
}

type hComp struct {
	Name   model.Text
	Class  string
	Mark   string
	Status model.Text
	Anchor string
}

type hFinding struct {
	N        int
	Anchor   string
	ID       string
	Class    string
	Mark     string
	Sev      model.Text
	Comp     model.Text
	Target   string
	Title    model.Text
	Detail   model.Text
	Action   model.Text
	Evidence []string
	Part     string
}

type hPart struct {
	Class    string
	Mark     string
	Sev      model.Text
	Kind     model.Text
	Model    string
	Serial   string
	Location string
	Firmware string
	Why      model.Text
	Anchor   string
}

type hTable struct {
	Title   model.Text
	Columns []model.Text
	Rows    []hRow
	Note    model.Text
	Count   int
}

type hRow struct {
	Class string
	Mark  string
	Sev   model.Text
	Cells []string
}

type hCovSection struct {
	State string
	Class string
	Title model.Text
	Items []hCov
}

type hCov struct {
	Names  model.Text
	Reason model.Text
	FixVI  hFix
	FixEN  hFix
	HasFix bool
}

type hFix struct {
	Prose string
	Cmd   string
}

func sevClass(s model.Severity, checked bool) string {
	switch {
	case !checked:
		return "none"
	case s >= model.Crit:
		return "crit"
	case s == model.Warn:
		return "warn"
	case s == model.Info:
		return "info"
	}
	return "ok"
}

// htmlMark is the glyph inside a severity badge.
func htmlMark(s model.Severity, checked bool) string {
	switch {
	case !checked:
		return "–"
	case s >= model.Crit:
		return "✕"
	case s == model.Warn:
		return "!"
	case s == model.Info:
		return "i"
	}
	return "✓"
}

func buildView(r *model.Report, o Options) hView {
	v := hView{
		Lang:    o.lang(),
		Title:   bi(label("title")),
		Host:    clean(r.Host.Hostname, false),
		Version: clean(r.Version, false),
		Repo:    RepoURL,
	}
	if v.Host == "" {
		v.Host = "—"
	}
	v.HostSub = clean(strings.TrimSpace(r.Host.Vendor+" "+r.Host.Model), false)
	v.TitleVI = "Diagward · " + v.Host + " · " + label("title").VI
	v.TitleEN = "Diagward · " + v.Host + " · " + label("title").EN
	for _, x := range identity(r, true) {
		if x.Key == label("host") || (x.Key == label("model") && v.HostSub != "") {
			continue // shown as the card title and subtitle
		}
		v.Identity = append(v.Identity, kv{bi(x.Key), bi(x.Val)})
	}
	sev := headlineSeverity(r)
	checked := sev != model.Info
	v.Class, v.Mark = sevClass(sev, checked), htmlMark(sev, checked)
	v.Headline, v.Sub = bi(Headline(r)), bi(subline(r))
	v.Collected = fmtTime(r.Collected)
	v.Duration = bi(fmtSeconds(r.Seconds))

	// Findings and their anchors.
	firstByComp := map[string]string{}
	n := 0
	for _, f := range r.Findings {
		hf := hFinding{
			ID:     clean(f.ID, false),
			Class:  sevClass(f.Severity, true),
			Mark:   htmlMark(f.Severity, true),
			Sev:    bi(SeverityText(f.Severity)),
			Target: clean(f.Target, false),
			Title:  bi(f.Title),
			Detail: bi(f.Detail),
			Action: bi(f.Action),
		}
		if f.Component != "" {
			hf.Comp = bi(model.ComponentName(f.Component))
		}
		for _, e := range f.Evidence {
			hf.Evidence = append(hf.Evidence, clean(e, false))
		}
		if p := f.Part; p != nil && f.Severity >= model.Warn {
			var s []string
			for _, x := range []string{p.Vendor, p.Model, p.Size} {
				if x = strings.TrimSpace(x); x != "" {
					s = append(s, x)
				}
			}
			if p.Serial != "" {
				s = append(s, "S/N "+p.Serial)
			}
			if p.Location != "" {
				s = append(s, "@ "+p.Location)
			}
			hf.Part = clean(strings.Join(s, " · "), false)
		}
		if f.Severity <= model.OK {
			v.OK = append(v.OK, hf)
			continue
		}
		n++
		hf.N = n
		hf.Anchor = fmt.Sprintf("f-%d", n)
		if _, ok := firstByComp[f.Component]; !ok {
			firstByComp[f.Component] = hf.Anchor
		}
		v.Findings = append(v.Findings, hf)
		if f.Severity >= model.Warn {
			v.DoNow = append(v.DoNow, hf)
		}
	}
	for _, s := range summaryOf(r) {
		c := hComp{
			Name:  bi(compName(s)),
			Class: sevClass(s.Severity, s.Checked),
			Mark:  htmlMark(s.Severity, s.Checked),
		}
		switch {
		case !s.Checked:
			c.Status = bi(StateText(model.CovSkipped))
		case s.Crit > 0 && s.Warn > 0:
			c.Status = model.Tf("%d critical, %d warning(s)", "%d nghiêm trọng, %d cảnh báo", s.Crit, s.Warn)
		case s.Crit > 0:
			c.Status = model.Tf("%d critical", "%d nghiêm trọng", s.Crit)
		case s.Warn > 0:
			c.Status = model.Tf("%d warning(s)", "%d cảnh báo", s.Warn)
		case s.Info > 0:
			c.Status = model.Tf("OK · %d note(s)", "Ổn · %d lưu ý", s.Info)
		default:
			c.Status = bi(SeverityText(model.OK))
		}
		if s.Checked && s.Severity > model.OK {
			c.Anchor = firstByComp[s.Component]
		}
		v.Components = append(v.Components, c)
	}

	// Parts
	for _, p := range Parts(r) {
		hp := hPart{
			Class: sevClass(p.Severity, true), Mark: htmlMark(p.Severity, true),
			Sev: bi(SeverityText(p.Severity)), Kind: bi(p.Kind),
			Model: clean(partLine(p), false), Serial: clean(p.Serial, false),
			Location: clean(p.Location, false), Firmware: clean(p.Firmware, false),
			Why: bi(p.Why),
		}
		// Link to the finding: count non-OK findings up to p.Finding.
		k := 0
		for i := 0; i <= p.Finding && i < len(r.Findings); i++ {
			if r.Findings[i].Severity > model.OK {
				k++
			}
		}
		if k > 0 {
			hp.Anchor = fmt.Sprintf("f-%d", k)
		}
		v.Parts = append(v.Parts, hp)
	}
	if len(v.Parts) > 0 {
		v.RMA = model.Text{EN: RMAText(r, "en"), VI: RMAText(r, "vi")}
	}

	// Tables
	for _, res := range r.Results {
		for _, tb := range res.Tables {
			ht := hTable{Title: bi(tb.Title), Note: bi(tb.Note), Count: len(tb.Rows)}
			if ht.Title.IsZero() {
				ht.Title = same(tb.ID)
			}
			ncol := len(tb.Columns)
			for _, row := range tb.Rows {
				ncol = max(ncol, len(row.Cells))
			}
			for i := 0; i < ncol; i++ {
				if i < len(tb.Columns) {
					ht.Columns = append(ht.Columns, bi(tb.Columns[i]))
				} else {
					ht.Columns = append(ht.Columns, model.Text{})
				}
			}
			for _, row := range tb.Rows {
				hr := hRow{Class: sevClass(row.Status, true), Mark: htmlMark(row.Status, true), Sev: bi(SeverityText(row.Status))}
				for i := 0; i < ncol; i++ {
					c := ""
					if i < len(row.Cells) {
						c = clean(row.Cells[i], false)
					}
					hr.Cells = append(hr.Cells, c)
				}
				ht.Rows = append(ht.Rows, hr)
			}
			v.Tables = append(v.Tables, ht)
		}
	}

	// Coverage
	var cur *hCovSection
	for _, g := range coverageGroups(r, true) {
		if g.State == model.CovRan {
			for _, nm := range g.Names {
				v.Ran = append(v.Ran, bi(nm))
			}
			continue
		}
		if cur == nil || cur.State != g.State {
			cls := "none"
			switch g.State {
			case model.CovFailed:
				cls = "warn"
			case model.CovPartial:
				cls = "info"
			}
			v.Coverage = append(v.Coverage, hCovSection{State: g.State, Class: cls, Title: bi(covLabel(g.State))})
			cur = &v.Coverage[len(v.Coverage)-1]
		}
		it := hCov{
			Names:  model.Text{EN: clean(g.names("en"), false), VI: clean(g.names("vi"), false)},
			Reason: bi(g.Reason),
		}
		if !g.Fix.IsZero() {
			f := bi(g.Fix)
			it.HasFix = true
			it.FixVI.Prose, it.FixVI.Cmd = splitFix(f.VI)
			it.FixEN.Prose, it.FixEN.Cmd = splitFix(f.EN)
		}
		cur.Items = append(cur.Items, it)
	}
	for _, nt := range r.Notes {
		if !nt.IsZero() {
			v.Notes = append(v.Notes, bi(nt))
		}
	}
	return v
}
