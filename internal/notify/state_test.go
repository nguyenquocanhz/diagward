package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

func fnd(id, target, comp string, sev model.Severity, title string) model.Finding {
	return model.Finding{ID: id, Target: target, Component: comp, Severity: sev,
		Title:  model.T(title, "VI "+title),
		Action: model.T("Fix "+target, "Sửa "+target)}
}

// rep builds a report on host srv01 where every component is checked
// unless listed in unchecked.
func rep(findings []model.Finding, gaps []model.Coverage, unchecked ...string) *model.Report {
	r := &model.Report{Host: model.HostInfo{Hostname: "srv01", Vendor: "Dell Inc.", Model: "PowerEdge R740", Serial: "8XK2LM2"},
		Collected: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), Findings: findings, Coverage: gaps}
	for _, c := range model.Components {
		checked := true
		for _, u := range unchecked {
			if u == c {
				checked = false
			}
		}
		r.Summary = append(r.Summary, model.ComponentSummary{Component: c, Checked: checked})
	}
	for _, f := range findings {
		r.Verdict = model.Worst(r.Verdict, f.Severity)
	}
	return r
}

var (
	diskPending = fnd("disk.smart_pending", "/dev/sda", model.CompDisk, model.Crit, "Disk /dev/sda is failing")
	diskRealloc = fnd("disk.smart_realloc", "/dev/sdb", model.CompDisk, model.Warn, "Disk /dev/sdb has reallocated sectors")
	psuFailed   = fnd("ipmi.psu_failed", "PSU 2", model.CompPower, model.Crit, "PSU 2 failed")
	ramCE       = fnd("memory.ecc_ce", "DIMM A1", model.CompMemory, model.Warn, "DIMM A1 corrected errors")
	smartdOff   = fnd("disk.smartd_off", "", model.CompDisk, model.Info, "smartd is not running")
	okDisks     = fnd("disk.smart_ok", "", model.CompDisk, model.OK, "4 disks passed")
	smartGap    = model.Coverage{ID: "disk.smart", Component: model.CompDisk, Name: model.T("S.M.A.R.T. health", "Tình trạng S.M.A.R.T."), State: model.CovSkipped}
	ipmiGap     = model.Coverage{ID: "ipmi.sdr", Component: model.CompBMC, Name: model.T("IPMI sensors", "Cảm biến IPMI"), State: model.CovFailed}
	naGap       = model.Coverage{ID: "cpu.throttle", Component: model.CompCPU, Name: model.T("Throttling", "Throttling"), State: model.CovSkipped, NotApplicable: true}
)

func keys(items []Item) string {
	var s []string
	for _, it := range items {
		s = append(s, it.ID+"@"+it.Target)
	}
	return strings.Join(s, ",")
}

func TestDiffFirstRun(t *testing.T) {
	r := rep([]model.Finding{diskPending, ramCE, smartdOff, okDisks}, []model.Coverage{naGap, ipmiGap})
	m, next := Diff(r, nil, DiffOptions{Lang: "vi", Version: "1.0"})
	if !m.Changed() || m.Event != EventProblem {
		t.Fatalf("first run with problems must notify: %+v", m)
	}
	if keys(m.New) != "disk.smart_pending@/dev/sda,memory.ecc_ce@DIMM A1" || len(m.Resolved) != 0 {
		t.Errorf("new %s", keys(m.New))
	}
	if m.New[0].Action.VI != "Sửa /dev/sda" {
		t.Errorf("action %+v", m.New[0].Action)
	}
	if len(next.Findings) != 3 { // crit, warn, info; OK findings are not kept
		t.Errorf("state %+v", next.Findings)
	}
	if len(next.Gaps) != 1 || next.Gaps[0].ID != "ipmi.sdr" { // not-applicable is not a gap
		t.Errorf("gaps %+v", next.Gaps)
	}
	if len(m.GapsNew) != 1 {
		t.Errorf("gaps line %+v", m.GapsNew)
	}

	healthy := rep([]model.Finding{okDisks, smartdOff}, nil)
	if m, _ := Diff(healthy, nil, DiffOptions{}); m.Changed() || m.Event != EventStatus {
		t.Errorf("healthy first run must not notify: %+v", m)
	}
}

func TestDiffChanges(t *testing.T) {
	base := rep([]model.Finding{diskPending, ramCE, smartdOff}, nil)
	_, prev := Diff(base, nil, DiffOptions{})

	// Unchanged (new counts in titles do not matter: ID + target do).
	same := rep([]model.Finding{diskPending, ramCE, smartdOff}, nil)
	same.Findings[1].Title = model.T("DIMM A1 corrected errors: 300", "x")
	if m, _ := Diff(same, prev, DiffOptions{}); m.Changed() {
		t.Errorf("unchanged: %+v", m)
	}

	// New problem.
	m, _ := Diff(rep([]model.Finding{diskPending, psuFailed, ramCE}, nil), prev, DiffOptions{})
	if keys(m.New) != "ipmi.psu_failed@PSU 2" || m.Event != EventProblem || len(m.Current) != 3 {
		t.Errorf("new: %s %s", keys(m.New), m.Event)
	}

	// Worsened: Warn -> Crit.
	worse := ramCE
	worse.Severity = model.Crit
	m, _ = Diff(rep([]model.Finding{diskPending, worse}, nil), prev, DiffOptions{})
	if keys(m.Worsened) != "memory.ecc_ce@DIMM A1" || m.Worsened[0].Previous != model.Warn || len(m.New) != 0 || m.Event != EventProblem {
		t.Errorf("worsened: %+v", m)
	}

	// Improved: Crit -> Warn is shown but does not notify alone.
	better := diskPending
	better.Severity = model.Warn
	m, _ = Diff(rep([]model.Finding{better, ramCE}, nil), prev, DiffOptions{})
	if m.Changed() || keys(m.Improved) != "disk.smart_pending@/dev/sda" {
		t.Errorf("improved: %+v", m)
	}

	// Resolved: the disk finding is gone and the disk checks ran.
	m, next := Diff(rep([]model.Finding{ramCE}, nil), prev, DiffOptions{})
	if keys(m.Resolved) != "disk.smart_pending@/dev/sda" || m.Event != EventRecovery || !m.Changed() {
		t.Errorf("resolved: %+v", m)
	}
	if m.Resolved[0].Title.EN != "Disk /dev/sda is failing" || m.Resolved[0].Previous != model.Crit {
		t.Errorf("resolved item %+v", m.Resolved[0])
	}
	for _, f := range next.Findings {
		if f.ID == "disk.smart_pending" {
			t.Error("resolved finding kept in state")
		}
	}

	// Warn -> Info counts as resolved (no longer a problem).
	info := ramCE
	info.Severity = model.Info
	m, _ = Diff(rep([]model.Finding{diskPending, info}, nil), prev, DiffOptions{})
	if keys(m.Resolved) != "memory.ecc_ce@DIMM A1" || m.Resolved[0].Severity != model.Info {
		t.Errorf("warn->info: %+v", m.Resolved)
	}

	// Info-only change: a new note does not notify.
	note := fnd("logs.reboot", "", model.CompLogs, model.Info, "rebooted")
	if m, _ := Diff(rep([]model.Finding{diskPending, ramCE, note}, nil), prev, DiffOptions{}); m.Changed() {
		t.Errorf("info-only change notified: %+v", m)
	}
	// Info disappearing does not notify either.
	if m, _ := Diff(rep([]model.Finding{diskPending, ramCE}, nil), prev, DiffOptions{}); m.Changed() {
		t.Errorf("info removal notified: %+v", m)
	}
}

func TestDiffNotResolvedWhenNotLooked(t *testing.T) {
	_, prev := Diff(rep([]model.Finding{diskPending, psuFailed}, nil), nil, DiffOptions{})

	// Power not checked this time (no BMC access): PSU 2 is carried, not resolved.
	m, next := Diff(rep([]model.Finding{diskPending}, nil, model.CompPower), prev, DiffOptions{})
	if m.Changed() || len(m.Resolved) != 0 {
		t.Fatalf("unchecked component resolved: %+v", m)
	}
	carried := false
	for _, f := range next.Findings {
		if f.ID == "ipmi.psu_failed" && f.Carried {
			carried = true
		}
	}
	if !carried {
		t.Fatalf("PSU not carried: %+v", next.Findings)
	}
	// Next run checks power again and the PSU is fine: now it is resolved.
	m, _ = Diff(rep([]model.Finding{diskPending}, nil), next, DiffOptions{})
	if keys(m.Resolved) != "ipmi.psu_failed@PSU 2" {
		t.Errorf("carried then resolved: %+v", m.Resolved)
	}

	// S.M.A.R.T. could not be read this time (not root): the disk finding
	// is not "fixed" even though the disk component was checked.
	m, _ = Diff(rep([]model.Finding{psuFailed}, []model.Coverage{smartGap}), prev, DiffOptions{})
	if len(m.Resolved) != 0 || m.Changed() {
		t.Errorf("new gap resolved the disk: %+v", m.Resolved)
	}
	if len(m.GapsNew) != 1 || m.GapsNew[0].EN != "S.M.A.R.T. health" {
		t.Errorf("gaps %+v", m.GapsNew)
	}

	// Collection stopped early: nothing is resolved.
	m, _ = Diff(rep(nil, nil), prev, DiffOptions{Incomplete: true})
	if len(m.Resolved) != 0 || m.Changed() {
		t.Errorf("incomplete resolved: %+v", m.Resolved)
	}
}

func TestDiffGapsAndHostAndMinSev(t *testing.T) {
	_, prev := Diff(rep([]model.Finding{ramCE}, []model.Coverage{ipmiGap}), nil, DiffOptions{})
	m, _ := Diff(rep([]model.Finding{ramCE}, []model.Coverage{smartGap}), prev, DiffOptions{})
	if m.Changed() {
		t.Error("a gap change alone must not notify")
	}
	if len(m.GapsNew) != 1 || len(m.GapsBack) != 1 || m.GapsBack[0].EN != "IPMI sensors" {
		t.Errorf("gaps %+v %+v", m.GapsNew, m.GapsBack)
	}

	other := rep([]model.Finding{ramCE}, nil)
	other.Host.Hostname = "srv02"
	if m, _ := Diff(other, prev, DiffOptions{}); !m.Changed() || len(m.New) != 1 {
		t.Errorf("another host must be a first run: %+v", m)
	}

	// min_severity = crit: a new warning does not notify, a crit does.
	_, p := Diff(rep(nil, nil), nil, DiffOptions{MinSev: model.Crit})
	if m, _ := Diff(rep([]model.Finding{ramCE}, nil), p, DiffOptions{MinSev: model.Crit}); m.Changed() {
		t.Error("warning notified with min crit")
	}
	if m, _ := Diff(rep([]model.Finding{psuFailed}, nil), p, DiffOptions{MinSev: model.Crit}); !m.Changed() {
		t.Error("crit not notified with min crit")
	}

	// Duplicate ID+target: the worst one counts.
	dup := ramCE
	dup.Severity = model.Crit
	m, next := Diff(rep([]model.Finding{dup, ramCE}, nil), nil, DiffOptions{})
	if len(m.New) != 1 || m.New[0].Severity != model.Crit || len(next.Findings) != 1 {
		t.Errorf("dup %+v", m.New)
	}
}

func TestStateFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "state.json")
	if s, err := LoadState(p); s != nil || err != nil {
		t.Fatalf("missing: %v %v", s, err)
	}
	_, next := Diff(rep([]model.Finding{diskPending, ramCE}, []model.Coverage{ipmiGap}), nil, DiffOptions{})
	if err := SaveState(p, next); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(p)
	if err != nil || got.Host != "srv01" || len(got.Findings) != 2 || got.Findings[0].Severity != model.Crit || len(got.Gaps) != 1 {
		t.Fatalf("roundtrip %+v %v", got, err)
	}
	// The state has no temp files left behind.
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Errorf("leftovers: %v", ents)
	}
	if err := os.WriteFile(p, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadState(p); s != nil || err == nil {
		t.Errorf("corrupt: %v %v", s, err)
	}
	if err := os.WriteFile(p, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadState(p); s != nil || err == nil {
		t.Errorf("other version: %v %v", s, err)
	}
}

func TestDefaultStatePath(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		goos string
		root bool
		env  map[string]string
		want string
	}{
		{"linux", true, nil, "/var/lib/diagward/state.json"},
		{"linux", false, map[string]string{"HOME": "/home/an"}, filepath.Join("/home/an", ".local", "state", "diagward", "state.json")},
		{"linux", false, map[string]string{"HOME": "/home/an", "XDG_STATE_HOME": "/srv/state"}, filepath.Join("/srv/state", "diagward", "state.json")},
		{"linux", false, map[string]string{}, ""},
		{"windows", true, map[string]string{"ProgramData": `C:\ProgramData`}, `C:\ProgramData\Diagward\state.json`},
		{"windows", false, map[string]string{}, `C:\ProgramData\Diagward\state.json`},
	} {
		if got := DefaultStatePath(c.goos, c.root, env(c.env)); got != c.want {
			t.Errorf("%s root=%v %v: %q want %q", c.goos, c.root, c.env, got, c.want)
		}
	}
}
