// Package testkit builds bundles and environments for domain tests.
package testkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// S is a section that ran and exited 0 with the given output.
func S(name, out string) *collect.Section { return &collect.Section{Name: name, Out: out} }

// RC is a section that ran and exited rc.
func RC(name string, rc int, out, errOut string) *collect.Section {
	return &collect.Section{Name: name, RC: rc, Out: out, Err: errOut}
}

// Missing is a section whose tool was not installed.
func Missing(name, tool string) *collect.Section {
	return &collect.Section{Name: name, RC: 127, Missing: tool}
}

// Skipped is a section the collector chose not to run.
func Skipped(name, reason string) *collect.Section {
	return &collect.Section{Name: name, Skipped: reason}
}

// Bundle builds a bundle for os from sections.
func Bundle(os string, secs ...*collect.Section) *collect.Bundle {
	b := &collect.Bundle{
		Format:   collect.BundleFormat,
		Tool:     "diagward test",
		OS:       os,
		Host:     "test-host",
		Started:  time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
		Finished: time.Date(2026, 10, 1, 9, 0, 20, 0, time.UTC),
	}
	for _, s := range secs {
		b.Add(s)
	}
	return b
}

// Env is a bare-metal environment run as root: AlmaLinux 9 with dnf on
// Linux, Windows Server as Administrator on Windows.
func Env(os string) model.Env {
	e := model.Env{OS: os, Root: true, SinceDays: 7, Now: time.Date(2026, 10, 1, 9, 0, 20, 0, time.UTC)}
	switch os {
	case collect.OSLinux:
		e.Distro, e.DistroVer, e.Like, e.PM = "almalinux", "9.4", "rhel centos fedora", "dnf"
	case collect.OSWindows:
		e.Distro, e.DistroVer = "windows", "20348"
	case collect.OSBMC:
	}
	return e
}

// Read returns testdata/<name> relative to the calling test's package.
func Read(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// Find returns the first finding with id (and target, when given), or nil.
func Find(res model.Result, id string, target ...string) *model.Finding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.ID != id {
			continue
		}
		if len(target) > 0 && f.Target != target[0] {
			continue
		}
		return f
	}
	return nil
}

// IDs lists "id@target=severity" for every finding, for readable failures.
func IDs(res model.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.ID+"@"+f.Target+"="+f.Severity.String())
	}
	return out
}

// Cov returns the coverage entry with id, or nil.
func Cov(res model.Result, id string) *model.Coverage {
	for i := range res.Coverage {
		if res.Coverage[i].ID == id {
			return &res.Coverage[i]
		}
	}
	return nil
}

// Validate checks the invariants every Result must satisfy: findings have
// an ID with the domain prefix, a known component, both languages for
// title/detail/action, and coverage entries have known states and
// components. It reports problems with t.Errorf.
func Validate(t testing.TB, res model.Result) {
	t.Helper()
	comps := map[string]bool{}
	for _, c := range model.Components {
		comps[c] = true
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.ID, res.Domain+".") {
			t.Errorf("finding %q: id must start with %q", f.ID, res.Domain+".")
		}
		if !comps[f.Component] {
			t.Errorf("finding %q: unknown component %q", f.ID, f.Component)
		}
		if f.Title.EN == "" || f.Title.VI == "" {
			t.Errorf("finding %q: title needs en and vi", f.ID)
		}
		if f.Severity >= model.Warn && (f.Action.EN == "" || f.Action.VI == "") {
			t.Errorf("finding %q: warn/crit findings need an action in en and vi", f.ID)
		}
		if (f.Detail.EN == "") != (f.Detail.VI == "") {
			t.Errorf("finding %q: detail must have both languages or neither", f.ID)
		}
		if len(f.Evidence) > 12 {
			t.Errorf("finding %q: %d evidence lines (max 12)", f.ID, len(f.Evidence))
		}
	}
	for _, c := range res.Coverage {
		switch c.State {
		case model.CovRan, model.CovPartial, model.CovSkipped, model.CovFailed:
		default:
			t.Errorf("coverage %q: bad state %q", c.ID, c.State)
		}
		if !comps[c.Component] {
			t.Errorf("coverage %q: unknown component %q", c.ID, c.Component)
		}
		if !strings.HasPrefix(c.ID, res.Domain+".") {
			t.Errorf("coverage %q: id must start with %q", c.ID, res.Domain+".")
		}
		if c.Name.EN == "" || c.Name.VI == "" {
			t.Errorf("coverage %q: name needs en and vi", c.ID)
		}
		if c.State != model.CovRan && (c.Reason.EN == "" || c.Reason.VI == "") {
			t.Errorf("coverage %q: %s needs a reason in en and vi", c.ID, c.State)
		}
	}
	for _, tb := range res.Tables {
		for i, r := range tb.Rows {
			if len(r.Cells) != len(tb.Columns) {
				t.Errorf("table %q row %d: %d cells for %d columns", tb.ID, i, len(r.Cells), len(tb.Columns))
			}
		}
	}
}
