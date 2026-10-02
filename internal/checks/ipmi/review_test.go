package ipmi

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// ipmitool >= 1.8.19 prints the time column with "%X %Z" (lib/ipmi_time.c
// ipmi_timestamp_time). With TZ=Asia/Ho_Chi_Minh, glibc's %Z is "+07"
// (tzdata dropped the invented "ICT" abbreviation in 2017), so every
// Vietnamese server prints "14:00:00 +07". Such entries must still have a
// time, or recent faults are filed as history.
func TestSELNumericZoneAbbreviation(t *testing.T) {
	for _, z := range []string{"+07", "-03", "+0530", "+05:30", "IST", "CEST"} {
		tm, ok := parseSELTime("09/28/26", "14:00:00 "+z)
		if !ok || fmtTime(tm) != "2026-09-28 14:00" {
			t.Errorf("zone %q: %v %v", z, fmtTime(tm), ok)
		}
	}
	sel := "  1a | 09/28/26 | 14:00:00 +07 | Power Supply PS2 Status | Power Supply AC lost | Asserted\n"
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_psu_ac_lost"); f == nil || f.Severity != model.Crit {
		t.Fatalf("recent AC loss with a +07 zone: %v", testkit.IDs(res))
	}
}

// The out-of-band collector runs ipmitool on the technician's laptop. In a
// day-first locale (vi_VN, en_GB, fr_FR) "%x" prints DD/MM/YYYY; a file with
// any first field > 12 is day-first throughout.
func TestSELDayFirstLocale(t *testing.T) {
	sel := "   1 | 05/09/2026 | 10:00:00 | Memory #0x02 | Uncorrectable ECC | Asserted\n" +
		"   2 | 28/09/2026 | 10:00:00 | Power Supply PS1 Status | Failure detected | Asserted\n"
	now := testkit.Env(collect.OSLinux).Now
	es := parseSEL(sel, now)
	if len(es) != 2 || !es[0].TimeOK || fmtTime(es[0].Time) != "2026-09-05 10:00" || fmtTime(es[1].Time) != "2026-09-28 10:00" {
		for _, e := range es {
			t.Logf("%s %v %v", e.ID, fmtTime(e.Time), e.TimeOK)
		}
		t.Fatalf("day-first dates misread")
	}
	// month-first files are untouched
	es = parseSEL("   1 | 09/05/2026 | 10:00:00 | Memory #0x02 | Uncorrectable ECC | Asserted\n", now)
	if len(es) != 1 || fmtTime(es[0].Time) != "2026-09-05 10:00" {
		t.Fatalf("month-first: %v", fmtTime(es[0].Time))
	}
}

// Dell logs "Redundancy Lost" and, once the PSU is back, "Fully Redundant"
// as a new assertion (no deassertion). HPE logs "Transition to OK" after a
// "Transition to Critical". Both mean the condition is over.
func TestSELRecoveryEvents(t *testing.T) {
	sel := "  20 | 09/20/2026 | 10:00:00 | Power Supply PS Redundancy | Redundancy Lost | Asserted\n" +
		"  21 | 09/20/2026 | 10:30:00 | Power Supply PS Redundancy | Fully Redundant | Asserted\n" +
		"  22 | 09/21/2026 | 08:00:00 | Fan Fan 3 | Transition to Critical from less severe | Asserted\n" +
		"  23 | 09/21/2026 | 08:05:00 | Fan Fan 3 | Transition to OK | Asserted\n"
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_redundancy_lost"); f != nil {
		t.Errorf("redundancy restored but reported: %v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "ipmi.sel_history"); f == nil || !strings.Contains(strings.Join(f.Evidence, "\n"), "Redundancy Lost (last 2026-09-20 10:00, recovered)") {
		t.Errorf("history: %+v", f)
	}
	if f := testkit.Find(res, "ipmi.sel_sensor_fan"); f == nil || f.Severity != model.Warn || !strings.Contains(f.Title.EN, "recovered") {
		t.Errorf("transition to OK: %v", testkit.IDs(res))
	}
	// without the recovery events they stay Warn / Crit
	sel2 := "  20 | 09/20/2026 | 10:00:00 | Power Supply PS Redundancy | Redundancy Lost | Asserted\n" +
		"  22 | 09/21/2026 | 08:00:00 | Fan Fan 3 | Transition to Critical from less severe | Asserted\n"
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", sel2)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_redundancy_lost"); f == nil || f.Severity != model.Warn {
		t.Errorf("redundancy lost: %v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "ipmi.sel_sensor_fan"); f == nil || f.Severity != model.Crit {
		t.Errorf("fan critical: %v", testkit.IDs(res))
	}
}

// A Dell with one PSU and the default "PSU Redundant" policy reports
// "Redundancy Lost" for as long as it runs (Dell community: "Stopping iDRAC
// reporting power supply redundancy is lost as I have moved from 2 PSUs to
// one"). That is a configuration, not a fault: Info with the way out.
func TestSinglePSURedundancy(t *testing.T) {
	sdr := testkit.Read(t, "sdr_dell_single_psu.txt")
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr)), testkit.Env(collect.OSLinux))
	if w := worst(res); w >= model.Warn {
		t.Fatalf("single PSU raised %v: %v", w, testkit.IDs(res))
	}
	f := testkit.Find(res, "ipmi.redundancy_lost")
	if f == nil || f.Severity != model.Info || !strings.Contains(f.Action.EN, "Not Redundant") || !strings.Contains(f.Action.VI, "Not Redundant") {
		t.Fatalf("single PSU redundancy: %+v", f)
	}
	// two PSUs present: redundancy lost is a real Warn
	two := strings.Replace(sdr, "Presence         | 54h | ok  | 10.1 | Absent", "Presence         | 54h | ok  | 10.1 | Present", 1)
	two = strings.Replace(two, "Status           | 64h | ns  | 10.1 | Disabled", "Status           | 64h | ok  | 10.1 | Presence detected", 1)
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", two)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.redundancy_lost"); f == nil || f.Severity != model.Warn {
		t.Fatalf("two PSUs: %v", testkit.IDs(res))
	}
}

// `sdr elist` prints management-controller and FRU locator records
// ("iDRAC | 00h | ok | 7.1 | Dynamic MC @ 20h", ipmitool lib/ipmi_sdr.c
// ipmi_sdr_print_sensor_mc_locator). They are not sensors.
func TestLocatorRecordsAreNotSensors(t *testing.T) {
	sdr := "Inlet Temp       | 04h | ok  |  7.1 | 23 degrees C\n" +
		"iDRAC            | 00h | ok  |  7.1 | Dynamic MC @ 20h\n" +
		"BMC              | 00h | ok  |  6.1 | Static MC @ 20h\n" +
		"PS 1             | 00h | ns  | 10.1 | Logical FRU @02h\n"
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sdr", sdr)), testkit.Env(collect.OSLinux))
	if n := len(facts(t, res).Sensors); n != 1 {
		t.Fatalf("sensors = %d", n)
	}
	if f := testkit.Find(res, "ipmi.sensors_ok"); f == nil || !strings.Contains(f.Title.EN, "All 1 ") {
		t.Fatalf("%v", testkit.IDs(res))
	}
}

// "Timer expired" (offset 0, "status only") means the watchdog expired with no action
// configured: the server was not reset.
func TestWatchdogStatusOnly(t *testing.T) {
	sel := "  30 | 09/25/2026 | 10:00:00 | Watchdog2 #0x81 | Timer expired | Asserted\n" +
		"  31 | 09/26/2026 | 10:00:00 | Watchdog2 #0x81 | Hard reset | Asserted\n"
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	n := 0
	for _, f := range res.Findings {
		if f.ID == "ipmi.sel_watchdog" && f.Severity >= model.Warn {
			n++
			if !strings.Contains(f.Title.EN, "Hard reset") {
				t.Errorf("wrong event: %s", f.Title.EN)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%v", testkit.IDs(res))
	}
}

// `ipmitool sel time get` gives the BMC clock. A BMC whose clock lost years
// (CMOS battery, never set) stamps today's faults with an old date: shift
// the events by the measured offset so the window still works, and say so.
func TestBMCClockOffset(t *testing.T) {
	sel := "  40 | 09/27/19 | 10:00:00 UTC | Power Supply PS2 Status | Failure detected | Asserted\n" +
		"  41 | 09/20/19 | 10:00:00 UTC | Memory #0x02 | Correctable ECC | Asserted\n"
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sel_time", "10/01/19 09:00:20 UTC\n"),
		testkit.S("ipmi.sel", sel))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_psu_failed"); f == nil || f.Severity != model.Crit {
		t.Fatalf("shifted PSU failure: %v", testkit.IDs(res))
	}
	f := testkit.Find(res, "ipmi.bmc_clock")
	if f == nil || f.Severity != model.Info || !strings.Contains(f.Title.EN, "7 years") || !strings.Contains(f.Action.EN, "sel time set") {
		t.Fatalf("bmc_clock: %+v", f)
	}
	// a correct clock (zone offset only) changes nothing and says nothing
	b = testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sel_time", "10/01/26 16:00:20 +07\n"),
		testkit.S("ipmi.sel", strings.ReplaceAll(sel, "/19", "/26")))
	res = run(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "ipmi.bmc_clock") != nil || testkit.Find(res, "ipmi.sel_psu_failed") == nil {
		t.Fatalf("%v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "ipmi.sel_psu_failed"); !strings.Contains(f.Title.EN, "2026-09-27 10:00") {
		t.Errorf("times must stay as the BMC printed them: %s", f.Title.EN)
	}
}

// Coverage.Cmd carries the one command that enables the check.
func TestCoverageCmd(t *testing.T) {
	missing := func(n string) *collect.Section { return testkit.Missing(n, "ipmitool") }
	res := run(t, testkit.Bundle(collect.OSLinux, secs(missing, devices("smbios38=1\n"))...), testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "ipmi.sdr")
	if c == nil || c.Cmd != "dnf install -y ipmitool" || strings.Contains(c.Fix.EN, "dnf install") {
		t.Fatalf("missing tool: %+v", c)
	}
	na := func(n string) *collect.Section { return testkit.Skipped(n, "not-applicable") }
	res = run(t, testkit.Bundle(collect.OSLinux, secs(na, devices("node=\nsmbios38=1\n"))...), testkit.Env(collect.OSLinux))
	c = testkit.Cov(res, "ipmi.sdr")
	if c == nil || c.Cmd != "modprobe ipmi_devintf ipmi_si" || strings.Contains(c.Fix.EN, "modprobe ipmi_devintf ipmi_si,") {
		t.Fatalf("driver: %+v", c)
	}
	// Windows: no package manager command
	res = run(t, testkit.Bundle(collect.OSWindows, secs(missing)...), testkit.Env(collect.OSWindows))
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || c.Cmd != "" || !strings.Contains(c.Fix.EN, "diagward bmc") {
		t.Fatalf("windows: %+v", c)
	}
}

// A SEL read that hit the timeout keeps what was read; coverage says the
// newest entries may be missing.
func TestSELTimeoutPartial(t *testing.T) {
	s := testkit.RC("ipmi.sel", 124, testkit.Read(t, "sel_intel_sr2500_2008.txt"), "")
	s.Timeout = true
	res := run(t, testkit.Bundle(collect.OSLinux, s), testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "ipmi.sel")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "newest") {
		t.Fatalf("%+v", c)
	}
}
