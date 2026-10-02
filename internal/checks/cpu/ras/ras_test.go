package ras

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func TestParseEmptyIgnoresSignals(t *testing.T) {
	for _, f := range []string{"ras_summary_empty_ubuntu_0.8.4.txt", "ras_errors_empty_ubuntu_0.8.4.txt"} {
		r := Parse(read(t, f))
		if !r.Recognized {
			t.Fatalf("%s not recognized", f)
		}
		if len(r.Mem)+len(r.MemEvents)+len(r.MCECounts)+len(r.MCEs)+len(r.AER)+len(r.Disk)+len(r.MemFailure) != 0 {
			t.Fatalf("%s: SIGNAL events counted as errors: %+v", f, r)
		}
	}
}

func TestParseSummaryMemory(t *testing.T) {
	r := Parse(read(t, "ras_summary_issue33_ce.txt"))
	if len(r.Mem) != 1 || r.Mem[0].Label != "CPU1_E0" || r.Mem[0].Count != 1987314 || r.Mem[0].Location != "3:1:0:-1" || r.Mem[0].Uncorrected() {
		t.Fatalf("%+v", r.Mem)
	}
	ce, ue := r.MemTotal()
	if ce != 1987314 || ue != 0 {
		t.Fatal(ce, ue)
	}
}

func TestParseSummaryMCE(t *testing.T) {
	r := Parse(read(t, "ras_summary_issue121_amd.txt"))
	if len(r.MCECounts) != 1 || r.MCECounts[0].Count != 1 || SummaryClass(r.MCECounts[0].Msg) != Corrected {
		t.Fatalf("%+v", r.MCECounts)
	}
}

func TestParseErrorsAMD(t *testing.T) {
	r := Parse(read(t, "ras_errors_issue121_amd.txt"))
	if len(r.MCEs) != 1 {
		t.Fatalf("%+v", r)
	}
	m := r.MCEs[0]
	if m.Class != Corrected || !m.Memory || !m.Time.IsZero() || m.Bank != "Unified Memory Controller (bank=21)" || m.CPU != -1 {
		t.Fatalf("%+v", m)
	}
}

func TestParseErrorsIntel(t *testing.T) {
	r := Parse(read(t, "ras_errors_intel_memory.txt"))
	if len(r.MemEvents) != 3 || len(r.MCEs) != 1 {
		t.Fatalf("%+v", r)
	}
	e := r.MemEvents[2]
	if e.Count != 9 || e.Type != "Corrected" || e.Label != "CPU1_E0" || e.Location != "3:1:0:-1" || e.Msg != "memory read error" {
		t.Fatalf("%+v", e)
	}
	if !e.Time.Equal(time.Date(2026, 9, 30, 21, 40, 2, 0, time.UTC)) {
		t.Fatal(e.Time)
	}
	m := r.MCEs[0]
	if m.Class != Corrected || !m.Memory || m.CPU != 24 || m.Socket != 1 || m.Bank != "8" {
		t.Fatalf("%+v", m)
	}
}

func TestParseErrorsCPU(t *testing.T) {
	r := Parse(read(t, "ras_errors_cpu_uncorrected.txt"))
	if len(r.MCEs) != 3 || len(r.AER) != 1 || len(r.Disk) != 1 {
		t.Fatalf("%+v", r)
	}
	if r.MCEs[2].Class != Uncorrected || r.MCEs[2].Memory || r.MCEs[2].CPU != 21 {
		t.Fatalf("%+v", r.MCEs[2])
	}
	if r.MCEs[0].Class != Corrected {
		t.Fatalf("%+v", r.MCEs[0])
	}
}

func TestClassifyMessages(t *testing.T) {
	for msg, want := range map[string]Class{
		"System Fatal error.":                       Fatal,
		"Uncorrected, software restartable error.":  Uncorrected,
		"Uncorrected, software containable error.":  Uncorrected,
		"Deferred error, no action required.":       Deferred,
		"Corrected error, no action required.":      Corrected,
		"Processor 3 heated above trip temperature": Thermal,
		"something else":                            Unknown,
	} {
		if got := classify(msg); got != want {
			t.Errorf("%q: %v, want %v", msg, got, want)
		}
	}
	// Intel: "Processor_context_corrupt" wins over "Uncorrected_error".
	m, ok := parseRasMCE("5 2026-09-30 01:02:03 +0000 error: Internal parity error, bank 0, mci Uncorrected_error Error_enabled Processor_context_corrupt, cpu=0x00000002")
	if !ok || m.Class != Fatal || m.CPU != 2 {
		t.Fatalf("%+v", m)
	}
}

func TestMcelog(t *testing.T) {
	recs := Mcelog(read(t, "mcelog_log_arch_uncorrected.txt"))
	if len(recs) != 1 || recs[0].Class != Fatal || recs[0].CPU != 0 || recs[0].Bank != "5" || recs[0].Socket != 0 ||
		!strings.Contains(recs[0].Msg, "Generic CACHE Level-2 Generic Error") || recs[0].Time.Year() != 2016 {
		t.Fatalf("%+v", recs)
	}
	recs = Mcelog(read(t, "mcelog_syslog_rhel8_srar.txt"))
	if len(recs) != 1 || recs[0].Class != Uncorrected || recs[0].CPU != 21 || recs[0].Msg != "Data CACHE Level-0 Data-Read Error" {
		t.Fatalf("%+v", recs)
	}
	recs = Mcelog(read(t, "mcelog_log_corrected_thermal.txt"))
	if len(recs) != 3 {
		t.Fatalf("%d records", len(recs))
	}
	if !recs[0].Memory || recs[0].Class != Corrected || recs[0].Msg != "MEMORY CONTROLLER RD_CHANNEL1_ERR Transaction: Memory read error" {
		t.Fatalf("%+v", recs[0])
	}
	if recs[1].Class != Thermal || recs[1].CPU != 2 {
		t.Fatalf("%+v", recs[1])
	}
	if recs[2].Class != Corrected || recs[2].Hint == "" || recs[2].Socket != 1 || recs[2].Memory {
		t.Fatalf("%+v", recs[2])
	}
}

func TestMcelogClient(t *testing.T) {
	d := McelogClient(read(t, "mcelog_client_issue16.txt"))
	if len(d) != 3 {
		t.Fatalf("%+v", d)
	}
	if d[2].Socket != "1" || d[2].Channel != "3" || d[2].DIMM != "0" || d[2].CETotal != 1651 || d[2].CE24h != 10 || d[2].UCTotal != 0 || !d[2].Specific() {
		t.Fatalf("%+v", d[2])
	}
	if d[0].Specific() || d[0].Target() != "socket 1" {
		t.Fatalf("%+v %q", d[0], d[0].Target())
	}
	d = McelogClient("SOCKET 0 CHANNEL 1 DIMM 2\nDMI_NAME \"DIMM_B2\" DMI_LOCATION \"NODE 0 CHANNEL 1 DIMM 2\"\nuncorrected memory errors:\n\t3 total\n\t1 in 24h\n")
	if len(d) != 1 || d[0].Name != "DIMM_B2" || d[0].UCTotal != 3 || d[0].UC24h != 1 || d[0].Target() != "DIMM_B2" {
		t.Fatalf("%+v", d)
	}
}

func TestPythonSummary(t *testing.T) {
	// rasdaemon >= 1.0 "ras-mc-ctl database --summary" layout (from
	// util/ras_db.py format_summary; the values are made up).
	in := "Hostname: srv01\n  mc_event:\n    err_type=Uncorrected, label=CPU_SrcID#0_MC#0_Chan#1_DIMM#0: 2 event(s)\n    err_type=Corrected, label=CPU_SrcID#0_MC#0_Chan#1_DIMM#0: 40 event(s)\n  mce_record: 3 event(s)\n"
	r := Parse(in)
	if !r.Recognized || len(r.Mem) != 2 || !r.Mem[0].Uncorrected() || r.Mem[1].Count != 40 || len(r.MCECounts) != 1 || r.MCECounts[0].Count != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestGarbage(t *testing.T) {
	for _, s := range []string{"", "\x00\xff", "MCE events:\n1 2", "Memory controller events:\n1 2026-01-01 00:00:00 +0000 x",
		"CPU 1", "MCE 1\nCPU x BANK y\nTIME z", "SOCKET", "SOCKET 1 CHANNEL 2 DIMM 3\n\tx total", "Hostname:\n  x:\n    : 1 event(s)"} {
		Parse(s)
		Mcelog(s)
		McelogClient(s)
	}
}
