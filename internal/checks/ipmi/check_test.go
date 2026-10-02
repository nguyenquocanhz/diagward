package ipmi

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func run(t *testing.T, b *collect.Bundle, env model.Env) model.Result {
	t.Helper()
	res := Check(b, env)
	testkit.Validate(t, res)
	return res
}

func worst(res model.Result) model.Severity {
	w := model.OK
	for _, f := range res.Findings {
		w = model.Worst(w, f.Severity)
	}
	return w
}

func facts(t *testing.T, res model.Result) Facts {
	t.Helper()
	f, ok := res.Facts.(Facts)
	if !ok {
		t.Fatalf("facts %T", res.Facts)
	}
	return f
}

func devices(kv string) *collect.Section { return testkit.S("ipmi.devices", kv) }

// all eight sections plus devices, healthy Supermicro-style data
func healthy(t *testing.T, sdr string) *collect.Bundle {
	return testkit.Bundle(collect.OSLinux,
		devices("node=/dev/ipmi0\nmodule_ipmi_si=1\nmodule_ipmi_devintf=1\nsmbios38=1\ndmi_interface=KCS (Keyboard Control Style)\nipmitool_version=ipmitool version 1.8.19\n"),
		testkit.S("ipmi.mc", testkit.Read(t, "mc_info_dell.txt")),
		testkit.S("ipmi.chassis", testkit.Read(t, "chassis_supermicro_ok.txt")),
		testkit.S("ipmi.sel_info", testkit.Read(t, "sel_info_ok.txt")),
		testkit.S("ipmi.sdr", testkit.Read(t, sdr)),
		testkit.S("ipmi.sel", testkit.Read(t, "sel_intel_sr2500_2008.txt")),
		testkit.RC("ipmi.fru", 1, testkit.Read(t, "fru_dell_r640.txt"), ""),
		testkit.S("ipmi.lan", testkit.Read(t, "lan_print_huawei_rh1288v3.txt")),
		testkit.RC("ipmi.power", 1, "", "DCMI request failed because: Invalid command (c1)"),
	)
}

func TestAbsent(t *testing.T) {
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("sensors.hwmon", "")), testkit.Env(collect.OSLinux))
	if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 {
		t.Fatalf("expected empty: %v", testkit.IDs(res))
	}
}

// Real SDR dumps from three vendors must come out healthy.
func TestRealSDRHealthy(t *testing.T) {
	for _, f := range []string{"sdr_dell_r510_idrac6.txt", "sdr_hpe_dl360g10_ilo5.txt", "sdr_supermicro_x10srh.txt", "sdr_telegraf_v2.txt"} {
		t.Run(f, func(t *testing.T) {
			res := run(t, healthy(t, f), testkit.Env(collect.OSLinux))
			if w := worst(res); w >= model.Warn {
				t.Fatalf("worst %v: %v", w, testkit.IDs(res))
			}
			if testkit.Find(res, "ipmi.sensors_ok") == nil {
				t.Errorf("no sensors_ok: %v", testkit.IDs(res))
			}
			for _, id := range []string{"ipmi.sdr", "ipmi.sel", "ipmi.chassis"} {
				if c := testkit.Cov(res, id); c == nil || c.State != model.CovRan {
					t.Errorf("%s coverage %+v", id, c)
				}
			}
			if c := testkit.Cov(res, "ipmi.fans"); c == nil {
				t.Errorf("fans coverage missing")
			}
		})
	}
}

func TestDellR510AbsentPSU(t *testing.T) {
	res := run(t, healthy(t, "sdr_dell_r510_idrac6.txt"), testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "ipmi.psu_absent", "PSU 1")
	if f == nil || f.Severity != model.Info {
		t.Fatalf("psu_absent: %v", testkit.IDs(res))
	}
	fs := facts(t, res)
	if len(fs.PSUs) != 2 || fs.PSUs[0].Present == nil || *fs.PSUs[0].Present || fs.PSUs[1].Volts == nil || *fs.PSUs[1].Volts != 118 {
		t.Fatalf("psus: %+v %+v", fs.PSUs[0], fs.PSUs[1])
	}
	// FRU from the R640 fixture attaches to PSU 2 (serial known)
	if fs.PSUs[1].Serial != "CNDED0003G0O0P" {
		t.Errorf("PSU 2 serial %q", fs.PSUs[1].Serial)
	}
}

func TestHPEPSURedundancy(t *testing.T) {
	res := run(t, healthy(t, "sdr_hpe_dl360g10_ilo5.txt"), testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "ipmi.psu_ok")
	if f == nil || !strings.Contains(f.Title.EN, "2 power supplies") || !strings.Contains(f.Title.EN, "Fully Redundant") {
		t.Fatalf("psu_ok: %v", testkit.IDs(res))
	}
	fs := facts(t, res)
	if len(fs.PSUs) != 2 || fs.PSUs[0].Watts == nil || *fs.PSUs[0].Watts != 105 {
		t.Fatalf("%+v", fs.PSUs)
	}
	// entity "32.11" / "44.100" parse
	for _, s := range fs.Sensors {
		if s.Name == "04-P1 DIMM 1-6" && (s.Class != clTemp || s.Value == nil || *s.Value != 29) {
			t.Errorf("%+v", s)
		}
	}
}

func TestSDRFaults(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sdr", testkit.Read(t, "sdr_dell_faults.txt")),
		testkit.S("ipmi.fru", testkit.Read(t, "fru_dell_r640.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	cases := []struct {
		id, target string
		sev        model.Severity
		comp       string
	}{
		{"ipmi.psu_failed", "PSU 2", model.Crit, model.CompPower},
		{"ipmi.redundancy_lost", "PS Redundancy", model.Warn, model.CompPower},
		{"ipmi.sensor_critical", "Fan3", model.Crit, model.CompFan},
		{"ipmi.sensor_critical", "Temp (entity 3.1)", model.Crit, model.CompThermal},
		{"ipmi.intrusion", "Intrusion", model.Warn, model.CompSystem},
		{"ipmi.drive_fault", "Drive 0", model.Crit, model.CompDisk},
	}
	for _, c := range cases {
		f := testkit.Find(res, c.id, c.target)
		if f == nil {
			t.Errorf("missing %s@%s: %v", c.id, c.target, testkit.IDs(res))
			continue
		}
		if f.Severity != c.sev || f.Component != c.comp {
			t.Errorf("%s@%s: %v %s", c.id, c.target, f.Severity, f.Component)
		}
	}
	f := testkit.Find(res, "ipmi.psu_failed", "PSU 2")
	if f == nil || f.Part == nil || f.Part.Kind != "psu" || f.Part.Serial != "CNDED0003G0O0P" || !strings.Contains(f.Part.Model, "750W") {
		t.Fatalf("PSU part: %+v", f)
	}
	if testkit.Find(res, "ipmi.sensors_ok") != nil || testkit.Find(res, "ipmi.psu_ok") != nil {
		t.Errorf("OK findings next to faults")
	}
	// "State Deasserted" on PG FAIL sensors is the healthy state
	if testkit.Find(res, "ipmi.state_asserted") != nil {
		t.Errorf("PG FAIL deasserted flagged")
	}
}

func TestSELRecentFaults(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sel", testkit.Read(t, "sel_recent_faults.txt")),
		testkit.S("ipmi.fru", testkit.Read(t, "fru_dell_r640.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux)) // now = 2026-10-01
	cases := []struct {
		id  string
		sev model.Severity
	}{
		{"ipmi.sel_psu_failed", model.Crit},
		{"ipmi.sel_redundancy_lost", model.Warn},
		{"ipmi.sel_memory_ue", model.Crit},
		{"ipmi.sel_memory_ce", model.Warn},
		{"ipmi.sel_intrusion", model.Warn},
		{"ipmi.sel_sensor_fan", model.Warn}, // Crit threshold event, recovered -> Warn
		{"ipmi.sel_drive_fault", model.Crit},
		{"ipmi.sel_cpu_error", model.Crit},
	}
	for _, c := range cases {
		f := testkit.Find(res, c.id)
		if f == nil {
			t.Errorf("missing %s: %v", c.id, testkit.IDs(res))
			continue
		}
		if f.Severity != c.sev {
			t.Errorf("%s: %v want %v", c.id, f.Severity, c.sev)
		}
	}
	if f := testkit.Find(res, "ipmi.sel_memory_ue"); f != nil && (f.Target != "DIMMD7" || f.Part == nil || f.Part.Kind != "dimm") {
		t.Errorf("UE target/part: %q %+v", f.Target, f.Part)
	}
	if f := testkit.Find(res, "ipmi.sel_cpu_error"); f != nil && f.Target != "CPU 2" {
		t.Errorf("cpu target %q", f.Target)
	}
	if f := testkit.Find(res, "ipmi.sel_psu_failed"); f != nil && (f.Target != "PSU 2" || f.Part == nil || f.Part.Serial != "CNDED0003G0O0P") {
		t.Errorf("psu sel: %q %+v", f.Target, f.Part)
	}
	if f := testkit.Find(res, "ipmi.sel_sensor_fan"); f != nil && !strings.Contains(f.Title.EN, "recovered") {
		t.Errorf("recovered not shown: %s", f.Title.EN)
	}
	// Whole-system AC lost then restored within minutes is history, as are
	// the 2023 PSU AC loss and the undated kernel panic.
	h := testkit.Find(res, "ipmi.sel_history")
	if h == nil || h.Severity != model.Info || len(h.Evidence) != 3 {
		t.Fatalf("history: %+v", h)
	}
	if testkit.Find(res, "ipmi.sel_ok") != nil {
		t.Errorf("sel_ok next to faults")
	}
	if testkit.Find(res, "ipmi.sel_psu_ac_lost") != nil {
		t.Errorf("2023 AC loss must not warn")
	}
}

// Old events (2008, 2010, 2017, 2025) are history only: no Warn/Crit.
func TestSELOldOnly(t *testing.T) {
	for _, f := range []string{"sel_intel_sr2500_2008.txt", "sel_supermicro_2017.txt", "sel_list_supermicro_x8.txt", "sel_nerc_2025.txt"} {
		t.Run(f, func(t *testing.T) {
			res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", testkit.Read(t, f))), testkit.Env(collect.OSLinux))
			if w := worst(res); w >= model.Warn {
				t.Fatalf("%v", testkit.IDs(res))
			}
			if testkit.Find(res, "ipmi.sel_ok") == nil || testkit.Find(res, "ipmi.sel_history") == nil {
				t.Fatalf("%v", testkit.IDs(res))
			}
		})
	}
	// ...but with a 2025-03-01 clock the nerc UE ECC is recent and Crit.
	env := testkit.Env(collect.OSLinux)
	env.Now = time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", testkit.Read(t, "sel_nerc_2025.txt"))), env)
	f := testkit.Find(res, "ipmi.sel_memory_ue")
	if f == nil || f.Severity != model.Crit || f.Target != "DIMMD7" || !strings.Contains(f.Title.EN, "2×") {
		t.Fatalf("%v %+v", testkit.IDs(res), f)
	}
	// a long log window (90 days) also reaches back
	env = testkit.Env(collect.OSLinux)
	env.Now = time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC)
	env.SinceDays = 90
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", testkit.Read(t, "sel_nerc_2025.txt"))), env)
	if testkit.Find(res, "ipmi.sel_memory_ue") == nil {
		t.Fatalf("90-day window: %v", testkit.IDs(res))
	}
}

func TestSELEmptyAndClock(t *testing.T) {
	res := run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", "SEL has no entries\n")), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_ok"); f == nil || !strings.Contains(f.Title.EN, "empty") {
		t.Fatalf("%v", testkit.IDs(res))
	}
	pre := "   1 |  Pre-Init  |0000000013| Power Supply PS1 Status | Failure detected | Asserted\n   2 | 01/01/2000 | 00:00:12 | Fan FAN1 | Lower Critical going low  | Asserted\n"
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", pre)), testkit.Env(collect.OSLinux))
	if worst(res) >= model.Warn || testkit.Find(res, "ipmi.sel_clock") == nil {
		t.Fatalf("%v", testkit.IDs(res))
	}
}

func TestSELTimeFormats(t *testing.T) {
	cases := []struct{ d, t, want string }{
		{"06/14/2023", "10:01:17", "2023-06-14 10:01"},
		{"12/14/22", "23:09:44 CET", "2022-12-14 23:09"},
		{"02/25/2025", "04:50:09 PM EST", "2025-02-25 16:50"},
		{"2024-05-08", "15:09:42 CEST", "2024-05-08 15:09"},
		{"08.05.2024", "15:09:42", "2024-05-08 15:09"},
	}
	for _, c := range cases {
		tm, ok := parseSELTime(c.d, c.t)
		if !ok || fmtTime(tm) != c.want {
			t.Errorf("%s %s -> %v %v", c.d, c.t, fmtTime(tm), ok)
		}
	}
	for _, bad := range [][2]string{{"Pre-Init", "0000000123"}, {"Unspecified", ""}, {"S+ 00/001", "00:00:05"}, {"", ""}, {"13/45/2020", "99:99:99"}} {
		if _, ok := parseSELTime(bad[0], bad[1]); ok {
			t.Errorf("%v parsed", bad)
		}
	}
}

func TestSplitPipes(t *testing.T) {
	f := splitPipes("  10 | 05/01/2017 | 16:39:09 | Processor #0x09 | IERR (CPU 2 | APIC ID 35 ) | Asserted")
	if len(f) != 6 || f[4] != "IERR (CPU 2 | APIC ID 35 )" || f[5] != "Asserted" {
		t.Fatalf("%q", f)
	}
	f = splitPipes("a | (unbalanced | b | c")
	if len(f) != 2 { // never panics; unbalanced parens swallow the rest
		t.Fatalf("%q", f)
	}
}

func TestSELInfoFullAndChassis(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sel_info", testkit.Read(t, "sel_info_full.txt")),
		testkit.S("ipmi.chassis", testkit.Read(t, "chassis_faults.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "ipmi.sel_full")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Action.EN, "ipmitool sel clear") || !strings.Contains(f.Title.VI, "đã tràn") {
		t.Fatalf("sel_full: %+v", f)
	}
	want := map[string]model.Severity{
		"ipmi.chassis_power_fault":   model.Crit,
		"ipmi.chassis_cooling_fault": model.Crit,
		"ipmi.chassis_intrusion":     model.Warn,
		"ipmi.last_power_event":      model.Warn,
	}
	for id, sev := range want {
		if f := testkit.Find(res, id); f == nil || f.Severity != sev {
			t.Errorf("%s: %v", id, testkit.IDs(res))
		}
	}
	if testkit.Find(res, "ipmi.chassis_drive_fault") != nil || testkit.Find(res, "ipmi.chassis_power_overload") != nil {
		t.Errorf("false chassis flags: %v", testkit.IDs(res))
	}
	// healthy chassis + 16 % SEL
	b = testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sel_info", testkit.Read(t, "sel_info_ok.txt")),
		testkit.S("ipmi.chassis", testkit.Read(t, "chassis_supermicro_ok.txt")),
	)
	res = run(t, b, testkit.Env(collect.OSLinux))
	if len(res.Findings) != 0 {
		t.Errorf("%v", testkit.IDs(res))
	}
	fs := facts(t, res)
	if fs.SEL == nil || fs.SEL.Entries != 642 || fs.SEL.PercentUsed == nil || *fs.SEL.PercentUsed != 16 {
		t.Errorf("%+v", fs.SEL)
	}
}

func TestIdentity(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.mc", testkit.Read(t, "mc_info_dell.txt")),
		testkit.S("ipmi.lan", testkit.Read(t, "lan_print_huawei_rh1288v3.txt")),
		testkit.S("ipmi.power", testkit.Read(t, "dcmi_power.txt")),
		testkit.S("ipmi.fru", testkit.Read(t, "fru_hpe_dl360g8.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	fs := facts(t, res)
	if fs.BMC.Firmware != "6.10" || fs.BMC.Address != "12.34.123.111" || fs.BMC.MAC != "d0:ef:c1:00:de:ad" || fs.BMC.Manufacturer != "DELL Inc" {
		t.Errorf("%+v", fs.BMC)
	}
	if fs.PowerWatts == nil || *fs.PowerWatts != 167 {
		t.Errorf("power %v", fs.PowerWatts)
	}
	if fs.System == nil || fs.System.Serial != "USE2236835" || fs.System.Product != "ProLiant DL360p Gen8" {
		t.Errorf("%+v", fs.System)
	}
	if f := testkit.Find(res, "ipmi.bmc_ok"); f == nil || !strings.Contains(f.Title.EN, "12.34.123.111") {
		t.Errorf("%v", testkit.IDs(res))
	}
	// unconfigured LAN + unknown vendor
	b = testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.mc", testkit.Read(t, "mc_info_openbmc.txt")),
		testkit.S("ipmi.lan", testkit.Read(t, "lan_print_sample1.txt")),
	)
	res = run(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "ipmi.bmc_no_ip") == nil {
		t.Errorf("%v", testkit.IDs(res))
	}
	if fs := facts(t, res); fs.BMC.Manufacturer != "manufacturer ID 42817" {
		t.Errorf("%q", fs.BMC.Manufacturer)
	}
}

func TestFRUParse(t *testing.T) {
	frus := parseFRU(testkit.Read(t, "fru_dell_r640.txt"))
	ps := psuFRUs(frus)
	if len(ps) != 2 || ps[1].get("Board Serial") != "CNDED0003G0NQA" || ps[2].get("Board Product") != "PWR SPLY,750W,RDNT,DELTA" {
		t.Fatalf("%+v", ps)
	}
	absent := false
	for _, f := range frus {
		if f.Description == "BP0" && f.Absent {
			absent = true
		}
	}
	if !absent {
		t.Errorf("BP0 'Device not present' not recognised")
	}
	if len(psuFRUs(parseFRU(testkit.Read(t, "fru_hpe_dl360g8.txt")))) != 0 {
		t.Errorf("HPE gen8 FRU has no PSU records")
	}
}

// ---- coverage ----

func secs(state func(name string) *collect.Section, extra ...*collect.Section) []*collect.Section {
	var out []*collect.Section
	for _, n := range []string{"ipmi.mc", "ipmi.chassis", "ipmi.sel_info", "ipmi.sdr", "ipmi.sel", "ipmi.fru", "ipmi.lan", "ipmi.power"} {
		out = append(out, state(n))
	}
	return append(out, extra...)
}

func TestCoverageMissingTool(t *testing.T) {
	missing := func(n string) *collect.Section { return testkit.Missing(n, "ipmitool") }
	// bare metal with a BMC in SMBIOS
	res := run(t, testkit.Bundle(collect.OSLinux, secs(missing, devices("node=\nsmbios38=1\n"))...), testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "ipmi.sdr")
	if c == nil || c.State != model.CovSkipped || !strings.Contains(c.Fix.EN, "dnf install -y ipmitool") || !strings.Contains(c.Reason.EN, "has a BMC") {
		t.Fatalf("%+v", c)
	}
	// VM
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res = run(t, testkit.Bundle(collect.OSLinux, secs(missing, devices("node=\n"))...), env)
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "virtual machine") {
		t.Fatalf("%+v", c)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%v", testkit.IDs(res))
	}
}

func TestCoverageNotRootAndContainer(t *testing.T) {
	nr := func(n string) *collect.Section { return testkit.Skipped(n, "not-root") }
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res := run(t, testkit.Bundle(collect.OSLinux, secs(nr, devices("node=/dev/ipmi0\n"))...), env)
	if c := testkit.Cov(res, "ipmi.sel"); c == nil || c.State != model.CovSkipped || !strings.Contains(c.Fix.EN, "sudo") {
		t.Fatalf("%+v", c)
	}
	ct := func(n string) *collect.Section { return testkit.Skipped(n, "container") }
	env = testkit.Env(collect.OSLinux)
	env.Virtual, env.Container = "wsl", true
	res = run(t, testkit.Bundle(collect.OSLinux, secs(ct, testkit.Skipped("ipmi.devices", "container"))...), env)
	if c := testkit.Cov(res, "ipmi.chassis"); c == nil || c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "container") {
		t.Fatalf("%+v", c)
	}
}

func TestCoverageNoDevice(t *testing.T) {
	na := func(n string) *collect.Section { return testkit.Skipped(n, "not-applicable") }
	// BMC in SMBIOS, driver not loaded -> modprobe fix
	res := run(t, testkit.Bundle(collect.OSLinux, secs(na, devices("node=\nsmbios38=1\ndmi_interface=KCS (Keyboard Control Style)\n"))...), testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "ipmi.sdr")
	if c == nil || c.State != model.CovSkipped || !strings.Contains(c.Fix.EN, "modprobe ipmi_devintf ipmi_si") {
		t.Fatalf("%+v", c)
	}
	// no BMC at all on bare metal (desktop board)
	res = run(t, testkit.Bundle(collect.OSLinux, secs(na, devices("node=\n"))...), testkit.Env(collect.OSLinux))
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "No BMC found") {
		t.Fatalf("%+v", c)
	}
}

func TestCoverageErrors(t *testing.T) {
	open := "Could not open device at /dev/ipmi0 or /dev/ipmi/0 or /dev/ipmidev/0: No such file or directory"
	fail := func(n string) *collect.Section { return testkit.RC(n, 1, "", open) }
	res := run(t, testkit.Bundle(collect.OSLinux, secs(fail, devices("node=/dev/ipmi0\n"))...), testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "ipmi.sdr")
	if c == nil || c.State != model.CovFailed || !strings.Contains(c.Reason.EN, "Could not open device") || !strings.Contains(c.Fix.EN, "modprobe") {
		t.Fatalf("%+v", c)
	}
	// wedged BMC: mc info timed out, the rest skipped
	b := testkit.Bundle(collect.OSLinux,
		&collect.Section{Name: "ipmi.mc", RC: 124, Timeout: true},
		testkit.Skipped("ipmi.sdr", "bmc-timeout"), testkit.Skipped("ipmi.sel", "bmc-timeout"), testkit.Skipped("ipmi.chassis", "bmc-timeout"))
	res = run(t, b, testkit.Env(collect.OSLinux))
	for _, id := range []string{"ipmi.sdr", "ipmi.sel", "ipmi.chassis"} {
		if c := testkit.Cov(res, id); c == nil || c.State != model.CovFailed || !strings.Contains(c.Fix.EN, "mc reset cold") {
			t.Errorf("%s %+v", id, c)
		}
	}
	// SDR partly read: some sensors failed
	b = testkit.Bundle(collect.OSLinux, testkit.RC("ipmi.sdr", 1, testkit.Read(t, "sdr_supermicro_x10srh.txt"), "Unable to send command: Invalid argument"))
	res = run(t, b, testkit.Env(collect.OSLinux))
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || c.State != model.CovPartial {
		t.Errorf("%+v", c)
	}
	// SDR timed out halfway
	b = testkit.Bundle(collect.OSLinux, &collect.Section{Name: "ipmi.sdr", RC: 124, Timeout: true, Out: "CPU Temp         | 01h | ok  |  3.1 | 36 degrees C\n"})
	res = run(t, b, testkit.Env(collect.OSLinux))
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || c.State != model.CovPartial {
		t.Errorf("%+v", c)
	}
}

// Out-of-band bundles (env.OS == "bmc") use the same sections.
func TestBMCBundle(t *testing.T) {
	b := testkit.Bundle(collect.OSBMC,
		testkit.S("ipmi.sdr", testkit.Read(t, "sdr_dell_faults.txt")),
		testkit.S("ipmi.sel", testkit.Read(t, "sel_recent_faults.txt")),
		testkit.S("ipmi.chassis", testkit.Read(t, "chassis_faults.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSBMC))
	if testkit.Find(res, "ipmi.psu_failed") == nil || testkit.Find(res, "ipmi.sel_memory_ue") == nil || testkit.Find(res, "ipmi.chassis_power_fault") == nil {
		t.Fatalf("%v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || c.State != model.CovRan {
		t.Errorf("%+v", c)
	}
}

func TestWindows(t *testing.T) {
	missing := func(n string) *collect.Section { return testkit.Missing(n, "ipmitool") }
	wd := testkit.S("ipmi.win_devices", `[{"pnp":[{"Name":"Microsoft Generic IPMI Compliant Device","Status":"OK","PNPDeviceID":"ACPI\\IPI0001\\0"}],"wmiIpmi":1,"ipmitool":null,"admin":true}]`)
	res := run(t, testkit.Bundle(collect.OSWindows, secs(missing, wd)...), testkit.Env(collect.OSWindows))
	c := testkit.Cov(res, "ipmi.sdr")
	if c == nil || c.State != model.CovSkipped || !strings.Contains(c.Fix.EN, "diagward bmc") || !strings.Contains(c.Reason.EN, "has a BMC") {
		t.Fatalf("%+v", c)
	}
	na := func(n string) *collect.Section { return testkit.Skipped(n, "not-admin") }
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res = run(t, testkit.Bundle(collect.OSWindows, secs(na)...), env)
	if c := testkit.Cov(res, "ipmi.sdr"); c == nil || !strings.Contains(c.Fix.EN, "administrator") {
		t.Fatalf("%+v", c)
	}
	// ipmitool.exe present and working: same parser
	ok := testkit.Bundle(collect.OSWindows, testkit.S("ipmi.sdr", testkit.Read(t, "sdr_hpe_dl360g10_ilo5.txt")))
	res = run(t, ok, testkit.Env(collect.OSWindows))
	if testkit.Find(res, "ipmi.sensors_ok") == nil {
		t.Fatalf("%v", testkit.IDs(res))
	}
}

func TestDiscreteRules(t *testing.T) {
	cases := []struct {
		state, class, name string
		sev                model.Severity
		key                string
	}{
		{"Presence detected", clPSU, "PS1 Status", model.OK, ""},
		{"Failure detected ()", clPSU, "PS1 Status", model.Crit, "psu_failed"},
		{"Power Supply AC lost", clPSU, "PS1 Status", model.Crit, "psu_ac_lost"},
		{"AC out-of-range, but present", clPSU, "PS1", model.Warn, "psu_ac_lost"},
		{"Predictive Failure Deasserted", clDisk, "Drive", model.OK, ""},
		{"Predictive failure", clPSU, "PS2", model.Warn, "psu_predictive"},
		{"Redundancy Degraded from Fully Redundant", clPowerUnit, "PS Redundancy", model.Warn, "redundancy_lost"},
		{"Fully Redundant", clPowerUnit, "PS Redundancy", model.OK, ""},
		{"Non-Redundant: Insufficient Resources", clPowerUnit, "PS Redundancy", model.Crit, "redundancy_lost"},
		{"Correctable ECC @DIMMA1(CPU1)", clMemory, "Memory", model.Warn, "memory_ce"},
		{"Uncorrectable ECC (UnCorrectable ECC |  DIMMD7)", clMemory, "Memory", model.Crit, "memory_ue"},
		{"Correctable ECC logging limit reached", clMemory, "ECC", model.Warn, "memory_ce"},
		{"IERR (CPU 2 | APIC ID 35 )", clCPU, "Processor", model.Crit, "cpu_error"},
		{"General Chassis intrusion", clIntrusion, "Intrusion", model.Warn, "intrusion"},
		{"Drive Fault", clDisk, "HDD Status", model.Crit, "drive_fault"},
		{"Transition to OK", clFan, "Fan 1", model.OK, ""},
		{"Transition to Critical from less severe", clFan, "Fan 1", model.Crit, "sensor_fan"},
		{"Low", clBattery, "CMOS Battery", model.Warn, "battery"},
		{"Low", clSystem, "Speed", model.OK, ""},
		{"State Asserted", clSystem, "PS1 PG FAIL", model.Warn, "state_asserted"},
		{"State Deasserted", clSystem, "PS1 PG FAIL", model.OK, ""},
		{"Limit Not Exceeded", clSystem, "x", model.OK, ""},
		{"Device Absent", clFan, "Fan 7 Presence", model.Info, "fan_absent"},
		{"Log area reset/cleared", clBMC, "SEL", model.Info, "sel_cleared"},
	}
	for _, c := range cases {
		v := judge(c.state, c.class, c.name)
		if v.sev != c.sev || (c.key != "" && v.key != c.key) {
			t.Errorf("%q/%s: %v %q, want %v %q", c.state, c.class, v.sev, v.key, c.sev, c.key)
		}
	}
}

// Garbage and truncated input must never panic.
func TestGarbage(t *testing.T) {
	all := ""
	for _, f := range []string{"sdr_dell_faults.txt", "sdr_hpe_dl360g10_ilo5.txt", "sel_recent_faults.txt", "fru_dell_r640.txt", "chassis_faults.txt", "sel_info_full.txt", "mc_info_dell.txt", "lan_print_sample1.txt"} {
		all += testkit.Read(t, f)
	}
	inputs := []string{"", "|", "||||", "| | | | |", "a|b|c|d|e|f|g", "((((|", ")))|(((", "SEL has no entries", "FRU Device Description : (ID x)",
		"1 | 99/99/9999 | 99:99:99 | x | y | z", " ff | 01/01/26 | 25:00:00 PM | Memory | Correctable ECC | Asserted", "\x00\xff\xfe"}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 300; i++ {
		a, b := rng.Intn(len(all)), rng.Intn(len(all))
		if a > b {
			a, b = b, a
		}
		inputs = append(inputs, all[a:b])
	}
	for _, in := range inputs {
		for _, os := range []string{collect.OSLinux, collect.OSWindows, collect.OSBMC} {
			var ss []*collect.Section
			for _, n := range []string{"ipmi.mc", "ipmi.chassis", "ipmi.sel_info", "ipmi.sdr", "ipmi.sel", "ipmi.fru", "ipmi.lan", "ipmi.power", "ipmi.devices", "ipmi.win_devices"} {
				ss = append(ss, testkit.S(n, in))
			}
			res := Check(testkit.Bundle(os, ss...), testkit.Env(os))
			testkit.Validate(t, res)
		}
	}
}

// A recent Crit SEL event whose part the live SDR shows healthy is lowered
// to Warn: the SEL is history, Crit means failing now.
func TestSELHealthyNow(t *testing.T) {
	sel := "  10 | 09/29/2026 | 10:00:00 | Power Supply Power Supply 2 | Failure detected () | Asserted\n" +
		"  11 | 09/29/2026 | 11:00:00 | Fan Fan 1 DutyCycle | Upper Critical going high | Asserted\n"
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("ipmi.sdr", testkit.Read(t, "sdr_hpe_dl360g10_ilo5.txt")),
		testkit.S("ipmi.sel", sel))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "ipmi.sel_psu_failed")
	if f == nil || f.Severity != model.Warn || f.Target != "PSU 2" || !strings.Contains(f.Detail.EN, "healthy now") {
		t.Fatalf("%v %+v", testkit.IDs(res), f)
	}
	if f := testkit.Find(res, "ipmi.sel_sensor_fan"); f == nil || f.Severity != model.Warn {
		t.Fatalf("%v", testkit.IDs(res))
	}
	// without the SDR it stays Crit
	res = run(t, testkit.Bundle(collect.OSLinux, testkit.S("ipmi.sel", sel)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "ipmi.sel_psu_failed"); f == nil || f.Severity != model.Crit {
		t.Fatalf("%v", testkit.IDs(res))
	}
}
