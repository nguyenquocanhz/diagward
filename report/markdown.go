package report

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/nguyenquocanhz/diagward/model"
)

// Markdown renders a compact report for tickets and chat apps (Zalo,
// Telegram, Slack, Jira, GitHub): a header line, the verdict, findings with
// actions, the parts to replace and what was not checked with the commands
// that enable it. It uses only headings, bold, bullet lists and inline code
// (no HTML, no tables), so it also reads well where Markdown is shown raw.
// Verbose adds evidence lines and the list of checks that ran.
func Markdown(w io.Writer, r *model.Report, o Options) error {
	if r == nil {
		r = &model.Report{}
	}
	m := &mdWriter{lang: o.lang(), o: o}
	m.render(r)
	_, err := io.WriteString(w, m.b.String())
	return err
}

type mdWriter struct {
	b    strings.Builder
	lang string
	o    Options
}

func (m *mdWriter) L(k string) string { return label(k).In(m.lang) }

// t is a Text in the report language, escaped for Markdown.
func (m *mdWriter) t(x model.Text) string { return mdEsc(x.In(m.lang)) }

func (m *mdWriter) line(format string, args ...any) {
	fmt.Fprintf(&m.b, format, args...)
	m.b.WriteByte('\n')
}

func sevEmoji(s model.Severity, checked bool) string {
	switch {
	case !checked:
		return "⚪"
	case s >= model.Crit:
		return "🔴"
	case s == model.Warn:
		return "🟠"
	case s == model.Info:
		return "🔵"
	}
	return "🟢"
}

func (m *mdWriter) render(r *model.Report) {
	h := r.Host
	host := strings.TrimSpace(h.Hostname)
	if host == "" {
		host = "?"
	}
	m.line("**Diagward · %s**", mdEsc(host))
	var facts []string
	if v := strings.TrimSpace(h.Vendor + " " + h.Model); v != "" {
		facts = append(facts, mdEsc(v))
	}
	if h.Serial != "" {
		facts = append(facts, m.L("serialTag")+": "+mdCode(h.Serial))
	}
	if h.OS != "" {
		facts = append(facts, mdEsc(h.OS))
	}
	if !r.Collected.IsZero() {
		facts = append(facts, mdEsc(fmtTime(r.Collected)))
	}
	if r.Env.OS != "" && r.Env.OS != "bmc" && (r.Env.Virtual != "" || r.Env.Container) {
		facts = append(facts, m.L("virtual")+": "+m.t(virtualText(r)))
	}
	if len(facts) > 0 {
		m.line("%s", strings.Join(facts, " · "))
	}
	m.line("")

	sev := headlineSeverity(r)
	m.line("### %s %s", sevEmoji(sev, sev != model.Info), m.t(Headline(r)))
	m.line("%s", m.t(subline(r)))

	// Findings
	var list []model.Finding
	var oks []model.Finding
	for _, f := range r.Findings {
		if f.Severity > model.OK {
			list = append(list, f)
		} else {
			oks = append(oks, f)
		}
	}
	if len(list) > 0 {
		m.line("")
		m.line("### %s (%d)", mdEsc(m.L("findings")), len(list))
		for i, f := range list {
			num := fmt.Sprintf("%d. ", i+1)
			// Sub-bullets must be indented to the item's content column
			// ("10. " needs 4 spaces) or CommonMark ends the ordered list.
			ind := strings.Repeat(" ", len(num))
			m.line("%s%s **%s**", num, sevEmoji(f.Severity, true), m.t(f.Title))
			var where []string
			if f.Target != "" {
				where = append(where, mdCode(f.Target))
			}
			if f.Component != "" {
				where = append(where, m.t(model.ComponentName(f.Component)))
			}
			if len(where) > 0 {
				m.line(ind+"- %s", strings.Join(where, " · "))
			}
			if d := strings.TrimSpace(f.Detail.In(m.lang)); d != "" {
				m.line(ind+"- %s", mdEsc(d))
			}
			if a := strings.TrimSpace(f.Action.In(m.lang)); a != "" {
				m.line(ind+"- **%s:** %s", mdEsc(m.L("action")), mdEsc(a))
			}
			if m.o.Verbose {
				for j, e := range f.Evidence {
					if j == 5 {
						m.line(ind+"- … %d %s", len(f.Evidence)-5, mdEsc(m.L("more")))
						break
					}
					m.line(ind+"- %s", mdCode(e))
				}
			}
		}
	}
	if len(oks) > 0 {
		m.line("")
		m.line("**%s:**", mdEsc(m.L("okChecked")))
		for _, f := range oks {
			m.line("- %s %s", sevEmoji(model.OK, true), m.t(f.Title))
		}
	}

	// Parts
	if parts := Parts(r); len(parts) > 0 {
		m.line("")
		m.line("### %s (%s)", mdEsc(m.L("parts")), mdEsc(m.L("partsSub")))
		for _, p := range parts {
			s := sevEmoji(p.Severity, true) + " **" + m.t(p.Kind) + "**"
			if l := partLine(p); l != "" {
				s += " " + mdEsc(l)
			}
			if p.Serial != "" {
				s += " · " + mdEsc(m.L("serial")) + ": " + mdCode(p.Serial)
			}
			if p.Location != "" {
				s += " · " + mdEsc(m.L("location")) + ": " + mdCode(p.Location)
			}
			m.line("- %s", s)
			m.line("  - %s: %s", mdEsc(m.L("why")), m.t(p.Why))
		}
	}

	// Not checked
	if groups := coverageGroups(r, false); len(groups) > 0 {
		m.line("")
		m.line("### %s", mdEsc(m.L("notChecked")))
		for _, g := range groups {
			s := "- " + mdEsc(g.names(m.lang)) + " (" + m.t(StateText(g.State)) + ")"
			if reason := strings.TrimSpace(g.Reason.In(m.lang)); reason != "" {
				s += ": " + mdEsc(reason)
			}
			m.line("%s", s)
			if fix := strings.TrimSpace(g.Fix.In(m.lang)); fix != "" {
				prose, cmd := splitFix(fix)
				switch {
				case cmd != "" && prose != "":
					m.line("  - %s %s", mdEsc(prose), mdCode(cmd))
				case cmd != "":
					m.line("  - %s", mdCode(cmd))
				default:
					m.line("  - %s", mdEsc(prose))
				}
			}
		}
	}
	if m.o.Verbose {
		for _, g := range coverageGroups(r, true) {
			if g.State == model.CovRan {
				m.line("")
				m.line("**%s:** %s", mdEsc(m.L("covRan")), mdEsc(g.names(m.lang)))
			}
		}
	}

	// Notes
	var notes []string
	for _, n := range r.Notes {
		if s := strings.TrimSpace(n.In(m.lang)); s != "" {
			notes = append(notes, s)
		}
	}
	if len(notes) > 0 {
		m.line("")
		m.line("### %s", mdEsc(m.L("notes")))
		for _, n := range notes {
			m.line("- %s", mdEsc(n))
		}
	}
	m.line("")
	ver := "Diagward"
	if r.Version != "" {
		ver += " " + r.Version
	}
	m.line("%s · %s", mdEsc(ver), RepoURL)
}

// mdEsc makes s safe as Markdown text on one line: control characters and
// newlines become spaces, and characters that start formatting, links or
// HTML ("<script>" in a log line) are backslash-escaped.
func mdEsc(s string) string {
	s = strings.Join(strings.Fields(clean(s, true)), " ")
	rs := []rune(s)
	alnum := func(i int) bool {
		return i >= 0 && i < len(rs) && (unicode.IsLetter(rs[i]) || unicode.IsDigit(rs[i]))
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i, r := range rs {
		esc := false
		switch r {
		case '`', '*', '<':
			// code spans, emphasis, raw HTML / autolinks
			esc = true
		case '\\':
			// A backslash only escapes ASCII punctuation; before a letter
			// (C:\Windows) it is literal and is left alone.
			esc = i+1 < len(rs) && strings.ContainsRune("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", rs[i+1])
		case '_':
			// Intraword underscores (Current_Pending_Sector) never start
			// emphasis in CommonMark or Slack; leave them readable.
			esc = !(alnum(i-1) && alnum(i+1))
		case '[':
			esc = true // could start a link
		case ']':
			esc = i+1 < len(rs) && (rs[i+1] == '(' || rs[i+1] == '[' || rs[i+1] == ':')
		case '~':
			esc = (i+1 < len(rs) && rs[i+1] == '~') || (i > 0 && rs[i-1] == '~')
		}
		if esc {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mdCode returns s as an inline code span. A span is delimited by more
// backticks than any run inside it, so the content cannot close it early.
func mdCode(s string) string {
	s = strings.Join(strings.Fields(clean(s, true)), " ")
	if s == "" {
		return ""
	}
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if longest > 0 || strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}
