package notify

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
	"github.com/nguyenquocanhz/diagward/report"
)

const stateVersion = 1

// State is what the previous run found. It holds finding IDs, targets,
// severities and titles: nothing secret.
type State struct {
	Version    int            `json:"version"`
	Host       string         `json:"host"`
	Time       time.Time      `json:"time"`
	Verdict    model.Severity `json:"verdict"`
	Incomplete bool           `json:"incomplete,omitempty"`
	Findings   []Fingerprint  `json:"findings"`
	Gaps       []Gap          `json:"gaps,omitempty"`
}

// Fingerprint identifies one finding across runs: ID + Target, with its
// severity. Info findings are kept (so a later change can be compared) but
// never notify on their own.
type Fingerprint struct {
	ID        string         `json:"id"`
	Target    string         `json:"target,omitempty"`
	Severity  model.Severity `json:"severity"`
	Component string         `json:"component,omitempty"`
	Title     model.Text     `json:"title"`
	// Carried: the last run could not look at this (its check did not run,
	// or collection stopped early), so it is kept from an earlier run rather
	// than reported as fixed.
	Carried bool `json:"carried,omitempty"`
	// GapsThen (carried findings only) lists the checks of its component
	// that could not run when the finding was last actually seen. Later
	// runs compare their gaps with this, not with the previous run's,
	// which may itself have been one that could not look.
	GapsThen []string `json:"gapsThen,omitempty"`
}

func (f Fingerprint) key() string { return f.ID + "\x00" + f.Target }

// Gap is a check that could not run (skipped or failed).
type Gap struct {
	ID        string     `json:"id"`
	Component string     `json:"component,omitempty"`
	Name      model.Text `json:"name"`
}

// LoadState reads a state file. A missing file returns (nil, nil): the
// first run. A corrupt or foreign file returns an error; callers treat it
// as a first run and overwrite it.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, errors.New("not a Diagward state file (it will be replaced)")
	}
	if s.Version != stateVersion {
		return nil, errors.New("state file from another Diagward version (it will be replaced)")
	}
	return &s, nil
}

// SaveState writes the state atomically (temp file + rename), readable only
// by its owner.
func SaveState(path string, s *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".diagward-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_ = f.Chmod(0o600)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// DefaultStatePath is where the state lives when --state is not given:
// /var/lib/diagward/state.json for root, $XDG_STATE_HOME/diagward (or
// ~/.local/state/diagward) for other users, %ProgramData%\Diagward on
// Windows. It returns "" when no location can be found.
func DefaultStatePath(goos string, root bool, getenv func(string) string) string {
	if goos == "windows" {
		for _, k := range []string{"ProgramData", "PROGRAMDATA", "LOCALAPPDATA"} {
			if d := getenv(k); d != "" {
				return strings.TrimRight(d, `\/`) + `\Diagward\state.json`
			}
		}
		return `C:\ProgramData\Diagward\state.json`
	}
	if root {
		return "/var/lib/diagward/state.json"
	}
	if d := getenv("XDG_STATE_HOME"); strings.HasPrefix(d, "/") {
		return filepath.Join(d, "diagward", "state.json")
	}
	if h := getenv("HOME"); h != "" {
		return filepath.Join(h, ".local", "state", "diagward", "state.json")
	}
	return ""
}

// Event says why a message is sent.
type Event string

const (
	EventProblem  Event = "problem"  // new or worse problems (or the first run with problems)
	EventRecovery Event = "recovery" // problems resolved, nothing new
	EventStatus   Event = "status"   // nothing changed, sent because of --notify-always
	EventTest     Event = "test"     // diagward notify-test
)

// Item is one problem in a message.
type Item struct {
	ID        string         `json:"id"`
	Target    string         `json:"target,omitempty"`
	Component string         `json:"component,omitempty"`
	Severity  model.Severity `json:"severity"`
	Previous  model.Severity `json:"previous"` // severity in the previous run (OK when new)
	Title     model.Text     `json:"title"`
	Action    model.Text     `json:"action,omitzero"`
	// Part names the part to replace (vendor, model, serial, location) when
	// the title and action do not already give its serial.
	Part string `json:"part,omitempty"`
}

// Message is what every channel renders. It holds no secret.
type Message struct {
	Event    Event
	Lang     string
	Top      int
	Host     string
	Vendor   string
	Model    string
	Serial   string
	Verdict  model.Severity
	Headline model.Text
	Counts   report.Counts
	New      []Item // new problems (all problems on the first run)
	Worsened []Item // same problem, higher severity
	Improved []Item // same problem, lower severity but still a problem
	Resolved []Item // problems gone (or now below min_severity)
	Current  []Item // every current problem, most severe first
	GapsNew  []model.Text
	GapsBack []model.Text
	// Incomplete: the collection stopped early; absent problems were not
	// treated as fixed.
	Incomplete bool
	Collected  time.Time
	Version    string
	Report     *model.Report // for webhooks with include_report
}

// Changed reports whether something worth a notification happened.
func (m *Message) Changed() bool {
	return len(m.New)+len(m.Worsened)+len(m.Resolved) > 0
}

// DiffOptions tunes Diff.
type DiffOptions struct {
	Lang       string
	Top        int
	MinSev     model.Severity // Warn (default) or Crit
	Incomplete bool           // the collection stopped early
	Version    string
}

// Diff compares the report with the previous state. It returns the message
// to send (Changed() tells whether anything changed), and the state to save
// for the next run.
func Diff(rep *model.Report, prev *State, o DiffOptions) (*Message, *State) {
	if o.MinSev < model.Warn {
		o.MinSev = model.Warn
	}
	if o.Top <= 0 {
		o.Top = 5
	}
	host := rep.Host.Hostname
	if prev != nil && prev.Host != host {
		prev = nil // a state file from another machine: start over
	}
	m := &Message{
		Lang: o.Lang, Top: o.Top, Host: host,
		Vendor: rep.Host.Vendor, Model: rep.Host.Model, Serial: rep.Host.Serial,
		Verdict: rep.Verdict, Headline: report.Headline(rep), Counts: report.CountFindings(rep),
		Incomplete: o.Incomplete, Collected: rep.Collected, Version: o.Version, Report: rep,
	}

	// Current findings, one per ID+Target (the worst), in report order
	// (most severe first).
	var curList []Fingerprint
	cur := map[string]int{}
	src := map[string]model.Finding{}
	for _, f := range rep.Findings {
		if f.Severity < model.Info {
			continue
		}
		fp := Fingerprint{ID: f.ID, Target: f.Target, Severity: f.Severity, Component: f.Component, Title: f.Title}
		if i, ok := cur[fp.key()]; ok {
			if fp.Severity > curList[i].Severity {
				curList[i] = fp
				src[fp.key()] = f
			}
			continue
		}
		cur[fp.key()] = len(curList)
		curList = append(curList, fp)
		src[fp.key()] = f
	}
	gaps := gapsOf(rep)

	next := &State{Version: stateVersion, Host: host, Time: rep.Collected, Verdict: rep.Verdict, Incomplete: o.Incomplete, Gaps: gaps}
	next.Findings = append([]Fingerprint{}, curList...)

	prevMap := map[string]Fingerprint{}
	if prev != nil {
		for _, f := range prev.Findings {
			prevMap[f.key()] = f
		}
		// Keep what this run could not look at.
		for _, f := range prev.Findings {
			if _, ok := cur[f.key()]; ok {
				continue
			}
			if !resolvable(f, rep, prev, gaps, o.Incomplete) {
				if !f.Carried {
					f.GapsThen = gapIDs(prev.Gaps, f.Component)
				}
				f.Carried = true
				next.Findings = append(next.Findings, f)
			}
		}
	}

	item := func(f Fingerprint, prevSev model.Severity) Item {
		return Item{ID: f.ID, Target: f.Target, Component: f.Component, Severity: f.Severity, Previous: prevSev, Title: f.Title, Action: src[f.key()].Action, Part: partText(src[f.key()])}
	}
	listed := map[string]bool{}
	for _, f := range curList {
		if f.Severity < o.MinSev {
			continue
		}
		m.Current = append(m.Current, item(f, prevMap[f.key()].Severity))
		p, had := prevMap[f.key()]
		switch {
		case prev == nil || !had || p.Severity < o.MinSev:
			m.New = append(m.New, item(f, p.Severity))
			listed[f.key()] = true
		case f.Severity > p.Severity:
			m.Worsened = append(m.Worsened, item(f, p.Severity))
			listed[f.key()] = true
		case f.Severity < p.Severity:
			m.Improved = append(m.Improved, item(f, p.Severity))
		}
	}
	if prev != nil {
		nextMap := map[string]Fingerprint{}
		for _, f := range next.Findings {
			nextMap[f.key()] = f
		}
		for _, p := range prev.Findings {
			if p.Severity < o.MinSev {
				continue
			}
			n, ok := nextMap[p.key()]
			if ok && (n.Carried || n.Severity >= o.MinSev) {
				continue
			}
			it := Item{ID: p.ID, Target: p.Target, Component: p.Component, Previous: p.Severity, Title: p.Title}
			if ok {
				it.Severity = n.Severity
			}
			m.Resolved = append(m.Resolved, it)
		}
	}
	sortItems(m.New)
	sortItems(m.Worsened)
	sortItems(m.Resolved)

	// What could not be checked, when that changed.
	prevGaps := map[string]bool{}
	if prev != nil {
		for _, g := range prev.Gaps {
			prevGaps[g.ID] = true
		}
	}
	curGaps := map[string]bool{}
	for _, g := range gaps {
		curGaps[g.ID] = true
		if !prevGaps[g.ID] {
			m.GapsNew = append(m.GapsNew, g.Name)
		}
	}
	if prev != nil {
		for _, g := range prev.Gaps {
			if !curGaps[g.ID] {
				m.GapsBack = append(m.GapsBack, g.Name)
			}
		}
	}

	switch {
	case len(m.New)+len(m.Worsened) > 0:
		m.Event = EventProblem
	case len(m.Resolved) > 0:
		m.Event = EventRecovery
	default:
		m.Event = EventStatus
	}
	return m, next
}

// resolvable reports whether a previous finding that is absent now can be
// called fixed: the collection finished, its component was checked, and
// nothing in that component is checked less than when it was found (a
// pending-sector warning found as root must not "recover" in a run without
// root that could not read S.M.A.R.T.).
func resolvable(f Fingerprint, rep *model.Report, prev *State, gaps []Gap, incomplete bool) bool {
	if incomplete {
		return false
	}
	if f.Component == "" {
		return true
	}
	checked := false
	for _, s := range rep.Summary {
		if s.Component == f.Component {
			checked = s.Checked
			break
		}
	}
	if !checked {
		return false
	}
	// The gaps when the finding was last seen: the previous run's, or the
	// ones saved with it when it has been carried since.
	then := f.GapsThen
	if !f.Carried {
		then = gapIDs(prev.Gaps, f.Component)
	}
	had := map[string]bool{}
	for _, id := range then {
		had[id] = true
	}
	for _, g := range gaps {
		if g.Component == f.Component && !had[g.ID] {
			return false
		}
	}
	return true
}

// gapIDs lists the IDs of the gaps in component comp.
func gapIDs(gaps []Gap, comp string) []string {
	var out []string
	for _, g := range gaps {
		if g.Component == comp {
			out = append(out, g.ID)
		}
	}
	return out
}

// gapsOf lists the checks that could not run (not the not-applicable ones).
func gapsOf(rep *model.Report) []Gap {
	var out []Gap
	seen := map[string]bool{}
	for _, c := range rep.Coverage {
		if c.NotApplicable || (c.State != model.CovSkipped && c.State != model.CovFailed) || seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		out = append(out, Gap{ID: c.ID, Component: c.Component, Name: c.Name})
	}
	return out
}

// sortItems puts the most severe first, keeping the report's order within
// a severity.
func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i].Severity, items[j].Severity
		if a == b {
			return items[i].Previous > items[j].Previous
		}
		return a > b
	})
}

// TestMessage is the message of "diagward notify-test".
func TestMessage(host, lang, version string, now time.Time) *Message {
	return &Message{Event: EventTest, Lang: lang, Host: host, Version: version, Collected: now, Top: 5}
}

// partText describes the part to replace for a chat message, which has no
// parts table: "Dell 0PJMDN, serial CN179727, PSU 2". It is empty when the
// finding names no serial, or its texts already quote it.
func partText(f model.Finding) string {
	p := f.Part
	if p == nil || p.Serial == "" {
		return ""
	}
	for _, t := range []string{f.Title.EN, f.Title.VI, f.Action.EN, f.Action.VI} {
		if strings.Contains(t, p.Serial) {
			return ""
		}
	}
	var out []string
	if vm := strings.TrimSpace(p.Vendor + " " + p.Model); vm != "" {
		out = append(out, vm)
	}
	out = append(out, "serial "+p.Serial)
	if p.Location != "" && p.Location != f.Target {
		out = append(out, p.Location)
	}
	return strings.Join(out, ", ")
}
