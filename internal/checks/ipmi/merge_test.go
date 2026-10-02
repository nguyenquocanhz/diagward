package ipmi

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// selLines keeps the SEL records with the given IDs from a fixture.
func selLines(t *testing.T, fixture string, ids ...string) string {
	t.Helper()
	var b strings.Builder
	for _, l := range strings.Split(testkit.Read(t, fixture), "\n") {
		id, _, ok := strings.Cut(l, "|")
		if !ok {
			continue
		}
		for _, want := range ids {
			if strings.TrimSpace(id) == want {
				b.WriteString(l + "\n")
			}
		}
	}
	return b.String()
}

func countSev(res model.Result, comp string, sev model.Severity) int {
	n := 0
	for _, f := range res.Findings {
		if f.Component == comp && f.Severity == sev {
			n++
		}
	}
	return n
}

func hasLine(ev []string, sub string) bool {
	for _, e := range ev {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

// The SDR shows PSU 2 failed, redundancy lost, an open chassis, Fan3 at
// 0 RPM and Drive 0 faulted; the SEL logged the same faults. Each is one
// finding: the current-state (SDR) one, with the SEL events as history.
func TestSDRAndSELSameFaultReportedOnce(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sdr", testkit.Read(t, "sdr_dell_faults.txt")),
		testkit.S("ipmi.sel", testkit.Read(t, "sel_recent_faults.txt")),
		testkit.S("ipmi.fru", testkit.Read(t, "fru_dell_r640.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	for _, id := range []string{"ipmi.sel_psu_failed", "ipmi.sel_redundancy_lost", "ipmi.sel_intrusion", "ipmi.sel_drive_fault", "ipmi.sel_sensor_fan"} {
		if f := testkit.Find(res, id); f != nil {
			t.Errorf("duplicate of an SDR finding: %s @ %s %v", id, f.Target, f.Severity)
		}
	}
	// one Critical per failed part
	if n := countSev(res, model.CompPower, model.Crit); n != 1 {
		t.Errorf("power: %d Crit findings, want 1 (PSU 2): %v", n, testkit.IDs(res))
	}
	if n := countSev(res, model.CompPower, model.Warn); n != 1 {
		t.Errorf("power: %d Warn findings, want 1 (redundancy lost): %v", n, testkit.IDs(res))
	}
	if n := countSev(res, model.CompDisk, model.Crit); n != 1 {
		t.Errorf("disk: %d Crit findings, want 1 (Drive 0): %v", n, testkit.IDs(res))
	}
	if n := countSev(res, model.CompFan, model.Crit) + countSev(res, model.CompFan, model.Warn); n != 1 {
		t.Errorf("fan: %d findings, want 1 (Fan3): %v", n, testkit.IDs(res))
	}

	psu := testkit.Find(res, "ipmi.psu_failed", "PSU 2")
	if psu == nil || psu.Severity != model.Crit || psu.Part == nil || psu.Part.Serial != "CNDED0003G0O0P" {
		t.Fatalf("PSU 2: %+v", psu)
	}
	if !strings.Contains(psu.Detail.EN, `Logged in the BMC event log (SEL) once ("Failure detected" on sensor "Power Supply PS2 Status"), on 2026-09-24 11:42.`) ||
		!strings.Contains(psu.Detail.VI, "Nhật ký sự kiện BMC (SEL) đã ghi lỗi này 1 lần") {
		t.Errorf("PSU 2 SEL history: %q / %q", psu.Detail.EN, psu.Detail.VI)
	}
	if !hasLine(psu.Evidence, "PS2 Status       | E1h") || !hasLine(psu.Evidence, "  2a | 09/24/2026") {
		t.Errorf("PSU 2 evidence: %q", psu.Evidence)
	}

	red := testkit.Find(res, "ipmi.redundancy_lost", "PS Redundancy")
	if red == nil || red.Severity != model.Warn || !hasLine(red.Evidence, "  29 | 09/24/2026") || !strings.Contains(red.Detail.EN, "Power Supply PSU Redundancy") {
		t.Errorf("redundancy: %+v", red)
	}
	if f := testkit.Find(res, "ipmi.intrusion", "Intrusion"); f == nil || !hasLine(f.Evidence, "Physical Security Chassis Intru") {
		t.Errorf("intrusion: %+v", f)
	}

	drv := testkit.Find(res, "ipmi.drive_fault", "Drive 0")
	if drv == nil || drv.Severity != model.Crit || drv.Part == nil || drv.Part.Kind != "disk" || drv.Part.Location != "Drive 0" {
		t.Fatalf("drive: %+v", drv)
	}
	if !hasLine(drv.Evidence, "Drive Slot HDD Status") || !strings.Contains(drv.Detail.EN, "on 2026-09-29 01:14") {
		t.Errorf("drive SEL history: %q %q", drv.Detail.EN, drv.Evidence)
	}

	// FAN3 dropped below its critical threshold, the SEL logged it as
	// deasserted, but the SDR reads 0 RPM again now.
	fan := testkit.Find(res, "ipmi.sensor_critical", "Fan3")
	if fan == nil || fan.Severity != model.Crit || !hasLine(fan.Evidence, "Fan FAN3") ||
		!strings.Contains(fan.Detail.EN, "deasserted") || !strings.Contains(fan.Detail.VI, "deasserted") {
		t.Errorf("fan: %+v", fan)
	}

	// SEL-only faults stay as they are; the SEL still counts as faulty.
	for _, id := range []string{"ipmi.sel_memory_ue", "ipmi.sel_memory_ce", "ipmi.sel_cpu_error"} {
		if testkit.Find(res, id) == nil {
			t.Errorf("missing %s: %v", id, testkit.IDs(res))
		}
	}
	if testkit.Find(res, "ipmi.sel_ok") != nil {
		t.Errorf("sel_ok next to faults")
	}
	// the SEL event table still lists every event kind
	for _, tb := range res.Tables {
		if tb.ID == "ipmi.events" && len(tb.Rows) != 11 {
			t.Errorf("events table: %d rows", len(tb.Rows))
		}
	}
}

// A different PSU, a different drive, a DIMM the SEL names and a sensor
// name the SDR uses twice are never folded.
func TestSELNotMergedWithOtherParts(t *testing.T) {
	sdr := testkit.Read(t, "sdr_dell_faults.txt") +
		"ECC Corr Err     | 01h | ok  | 34.1 | Correctable ECC\n"
	sel := strings.Join([]string{
		// PS1 is healthy in the SDR, PS2 failed: PS1's failure is its own history
		"  40 | 09/29/2026 | 10:00:00 | Power Supply PS1 Status | Failure detected () | Asserted",
		// Drive 1 is not Drive 0
		"  41 | 09/29/2026 | 11:00:00 | Drive Slot Drive 1 | Drive Fault () | Asserted",
		// the SEL names the DIMM, the SDR sensor does not
		"  42 | 09/29/2026 | 12:00:00 | Memory ECC Corr Err | Correctable ECC (DIMM_B2) | Asserted",
		// two SDR sensors are named "Temp": which one is unknown
		"  43 | 09/29/2026 | 13:00:00 | Temperature Temp | Upper Critical going high | Asserted",
	}, "\n") + "\n"
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr), testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))

	if f := testkit.Find(res, "ipmi.sel_psu_failed", "PSU 1"); f == nil || f.Severity != model.Warn || !strings.Contains(f.Detail.EN, "healthy now") {
		t.Errorf("PSU 1 SEL: %v %+v", testkit.IDs(res), f)
	}
	if f := testkit.Find(res, "ipmi.psu_failed", "PSU 2"); f == nil || strings.Contains(f.Detail.EN, "SEL") || len(f.Evidence) != 1 {
		t.Errorf("PSU 2 got PSU 1's events: %+v", f)
	}
	if f := testkit.Find(res, "ipmi.sel_drive_fault", "Drive 1"); f == nil || f.Severity != model.Crit || f.Part == nil || f.Part.Location != "Drive 1" {
		t.Errorf("Drive 1: %v %+v", testkit.IDs(res), f)
	}
	if f := testkit.Find(res, "ipmi.drive_fault", "Drive 0"); f == nil || len(f.Evidence) != 1 {
		t.Errorf("Drive 0 got Drive 1's events: %+v", f)
	}
	if f := testkit.Find(res, "ipmi.sel_memory_ce", "DIMM_B2"); f == nil {
		t.Errorf("DIMM_B2: %v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "ipmi.memory_ce"); f == nil || len(f.Evidence) != 1 {
		t.Errorf("SDR ECC sensor: %+v", f)
	}
	// Temp (entity 3.1) is at 98 °C now: the SEL event is neither folded
	// nor lowered (the healthy Temp 3.2 does not prove it recovered)
	if f := testkit.Find(res, "ipmi.sel_sensor_temperature", "Temp"); f == nil || f.Severity != model.Crit {
		t.Errorf("Temp SEL: %v %+v", testkit.IDs(res), f)
	}
	if f := testkit.Find(res, "ipmi.sensor_critical", "Temp (entity 3.1)"); f == nil || len(f.Evidence) != 1 {
		t.Errorf("Temp SDR: %+v", f)
	}
}

// A SEL fault whose sensor the SDR shows healthy again is a lower history
// finding, not folded into anything.
func TestSELFaultRecoveredInSDR(t *testing.T) {
	// Dell R510 SDR: "Drive B" reads "Drive Present", no fault
	sdr := testkit.Read(t, "sdr_dell_r510_idrac6.txt")
	sel := "  50 | 09/29/2026 | 01:14:06 | Drive Slot Drive B | Drive Fault () | Asserted\n"
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr), testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "ipmi.sel_drive_fault", "Drive B")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Detail.EN, "healthy now") || f.Part == nil || f.Part.Location != "Drive B" {
		t.Fatalf("Drive B: %v %+v", testkit.IDs(res), f)
	}
	// An unnamed drive slot on a server with three drive sensors: which
	// drive is unknown, so it stays Crit and names the whole sensor.
	sel = selLines(t, "sel_recent_faults.txt", "30")
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr), testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_drive_fault", "Drive Slot HDD Status"); f == nil || f.Severity != model.Crit || f.Part == nil || f.Part.Kind != "disk" {
		t.Fatalf("HDD Status: %v %+v", testkit.IDs(res), f)
	}

	// PSU redundancy restored: the SDR reads "Fully Redundant" again, so
	// the SEL's "Redundancy Lost" is history (Info), not a Warn.
	sdr = strings.Replace(testkit.Read(t, "sdr_dell_faults.txt"), "Redundancy Lost", "Fully Redundant", 1)
	sdr = strings.Replace(sdr, "Presence detected, Failure detected", "Presence detected", 1)
	sel = selLines(t, "sel_recent_faults.txt", "29")
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr), testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_redundancy_lost"); f != nil {
		t.Errorf("restored redundancy still warns: %+v", f)
	}
	h := testkit.Find(res, "ipmi.sel_history")
	if h == nil || !hasLine(h.Evidence, "Redundancy Lost (last 2026-09-24 11:42, healthy now)") {
		t.Errorf("history: %+v", h)
	}
	// Without the SDR redundancy sensor (the demo bundle) it stays a Warn.
	sdr = strings.Replace(sdr, "PS Redundancy    | 74h | ok  |  7.1 | Fully Redundant\n", "", 1)
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr), testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_redundancy_lost", "PSU Redundancy"); f == nil || f.Severity != model.Warn {
		t.Errorf("no SDR redundancy sensor: %v", testkit.IDs(res))
	}
}

func TestDriveTarget(t *testing.T) {
	cases := []struct{ sensor, name, event, want string }{
		{"Drive Slot HDD Status", "HDD Status", "Drive Fault", "Drive Slot HDD Status"},
		{"Drive Slot Drive 3", "Drive 3", "Drive Fault", "Drive 3"},
		{"Drive Slot HDD Status", "HDD Status", "Drive Fault (Bay 3)", "Drive Slot HDD Status (Bay 3)"},
		{"Drive Slot Drive 3", "Drive 3", "Drive Fault (Drive 3)", "Drive 3"},
	}
	for _, c := range cases {
		if got := driveTarget(c.sensor, c.name, c.event); got != c.want {
			t.Errorf("%q %q: %q, want %q", c.sensor, c.event, got, c.want)
		}
	}
	for name, want := range map[string]bool{"Drive 0": true, "Drive B": true, "FAN3": true, "HDD Status": false, "PSU Redundancy": false, "Chassis Intru": false, "Drive": false} {
		if hasInstance(name) != want {
			t.Errorf("hasInstance(%q) = %v", name, !want)
		}
	}
}
