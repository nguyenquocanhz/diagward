package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
	"github.com/nguyenquocanhz/diagward/report"
)

func analyze(t *testing.T) (*collect.Bundle, *model.Report) {
	t.Helper()
	root, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	b, src, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(src) != len(b.Sections) {
		t.Fatalf("%d sources for %d sections", len(src), len(b.Sections))
	}
	return b, diag.Analyze(b)
}

// The demo report in the README must keep showing the same story as the
// rules evolve: a failing disk, a degraded RAID, a failed PSU, ECC errors on
// one DIMM and a bond on one port.
func TestDemoHeadline(t *testing.T) {
	_, rep := analyze(t)

	for _, res := range rep.Results {
		testkit.Validate(t, res)
	}
	for _, c := range rep.Coverage {
		if strings.HasSuffix(c.ID, ".internal") {
			t.Errorf("domain panicked: %s: %s", c.ID, c.Reason.EN)
		}
		if c.State == model.CovFailed {
			t.Errorf("coverage %s failed: %s", c.ID, c.Reason.EN)
		}
	}

	h := rep.Host
	if h.Hostname != hostname || h.Vendor != "Dell Inc." || h.Model != "PowerEdge R740" || h.OS != "AlmaLinux 9.4 (Seafoam Ocelot)" || h.Kernel != kernel {
		t.Errorf("host %+v", h)
	}
	if rep.Env.Distro != "almalinux" || rep.Env.PM != "dnf" || !rep.Env.Root || !rep.Env.Bare() {
		t.Errorf("env %+v", rep.Env)
	}
	if rep.Verdict != model.Crit {
		t.Errorf("verdict %s", rep.Verdict)
	}

	want := []struct {
		id, target string
		sev        model.Severity
		serial     string // Part serial, "" = no part expected
	}{
		{"disk.unreadable_sectors", "/dev/sda", model.Crit, "S1VZJ9CS712490"},
		{"raid.hw_vd_degraded", "Controller 0 v0", model.Crit, "S1YHNYAG600061"},
		{"raid.hw_pd_failed", "Controller 0 Enclosure 32 Slot 2", model.Crit, "S1YHNYAG600061"},
		{"raid.hw_pd_predictive", "Controller 0 Enclosure 32 Slot 3", model.Crit, "S1YHNXAG804001"},
		{"raid.hw_pd_media_errors", "Controller 0 Enclosure 32 Slot 1", model.Warn, "S1YHNXAG803993"},
		{"ipmi.psu_failed", "PSU 2", model.Crit, "CNDED0003G0O0P"},
		{"ipmi.sel_redundancy_lost", "PSU Redundancy", model.Warn, ""},
		{"memory.ecc_corrected", "CPU_SrcID#1_MC#0_Chan#1_DIMM#0", model.Warn, ""},
		{"network.bond_degraded", "bond0", model.Warn, ""},
	}
	for _, w := range want {
		f := find(rep, w.id, w.target)
		if f == nil {
			t.Errorf("missing %s on %s; have %v", w.id, w.target, ids(rep))
			continue
		}
		if f.Severity != w.sev {
			t.Errorf("%s on %s: severity %s, want %s", w.id, w.target, f.Severity, w.sev)
		}
		if w.serial != "" && (f.Part == nil || f.Part.Serial != w.serial) {
			t.Errorf("%s on %s: part %+v, want serial %s", w.id, w.target, f.Part, w.serial)
		}
	}

	// The kernel log's medium errors on /dev/sda are folded into the
	// S.M.A.R.T. finding for that disk: one problem, two kinds of evidence.
	if f := find(rep, "logs.disk_medium_error", "/dev/sda"); f != nil {
		t.Errorf("kernel-log finding for /dev/sda should be folded into the disk finding")
	}
	if f := find(rep, "disk.unreadable_sectors", "/dev/sda"); f != nil {
		medium := false
		for _, e := range f.Evidence {
			if strings.Contains(e, "Medium Error") || strings.Contains(e, "medium error") {
				medium = true
			}
		}
		if !medium || !strings.Contains(f.Detail.EN, "log confirms") {
			t.Errorf("disk.unreadable_sectors lacks the kernel-log evidence: %+v", f)
		}
	}

	// The healthy parts are confirmed, not just silent.
	for _, id := range []string{"cpu.sockets_ok", "disk.smart_healthy", "ipmi.bmc_ok", "system.load_ok", "filesystem.health_ok"} {
		if f := find(rep, id, ""); f == nil || f.Severity != model.OK {
			t.Errorf("no OK finding %s; have %v", id, ids(rep))
		}
	}

	// Every component is checked; the problem areas carry the worst state.
	worst := map[string]model.Severity{
		model.CompDisk: model.Crit, model.CompRAID: model.Crit, model.CompPower: model.Crit,
		model.CompMemory: model.Warn, model.CompNetwork: model.Warn,
	}
	for _, s := range rep.Summary {
		if !s.Checked {
			t.Errorf("component %s not checked", s.Component)
		}
		if w, ok := worst[s.Component]; ok && s.Severity != w {
			t.Errorf("component %s: %s, want %s", s.Component, s.Severity, w)
		}
	}

	// The RMA list names the failing disk, both failing RAID disks and PSU 2.
	serials := map[string]bool{}
	for _, p := range report.Parts(rep) {
		serials[p.Serial] = true
	}
	for _, s := range []string{"S1VZJ9CS712490", "S1YHNYAG600061", "S1YHNXAG804001", "CNDED0003G0O0P"} {
		if !serials[s] {
			t.Errorf("parts list misses serial %s", s)
		}
	}
}

// The bundle survives the .dwb round trip, and every renderer accepts the
// report in both languages.
func TestDemoRenders(t *testing.T) {
	b, rep := analyze(t)
	var buf bytes.Buffer
	if err := collect.Write(&buf, b); err != nil {
		t.Fatal(err)
	}
	back, err := collect.Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if back.Host != hostname || len(back.Sections) != len(b.Sections) || back.Get("meta.done") == nil {
		t.Fatalf("round trip: host %q, %d sections", back.Host, len(back.Sections))
	}
	for _, lang := range []string{"vi", "en"} {
		o := report.Options{Lang: lang, Verbose: true, Color: true}
		for name, fn := range map[string]func(*bytes.Buffer) error{
			"html": func(w *bytes.Buffer) error { return report.HTML(w, rep, o) },
			"md":   func(w *bytes.Buffer) error { return report.Markdown(w, rep, o) },
			"txt":  func(w *bytes.Buffer) error { return report.Text(w, rep, o) },
		} {
			var out bytes.Buffer
			if err := fn(&out); err != nil {
				t.Fatalf("%s %s: %v", name, lang, err)
			}
			if !strings.Contains(out.String(), hostname) || !strings.Contains(out.String(), "S1VZJ9CS712490") {
				t.Errorf("%s %s: host or disk serial missing", name, lang)
			}
		}
	}
}

func find(rep *model.Report, id, target string) *model.Finding {
	for i := range rep.Findings {
		f := &rep.Findings[i]
		if f.ID == id && (target == "" || f.Target == target) {
			return f
		}
	}
	return nil
}

func ids(rep *model.Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.ID+"@"+f.Target+"="+f.Severity.String())
	}
	return out
}
