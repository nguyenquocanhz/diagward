package sensors

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func linux(secs ...*collect.Section) *collect.Bundle { return testkit.Bundle(collect.OSLinux, secs...) }

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
		t.Fatalf("facts type %T", res.Facts)
	}
	return f
}

func TestAbsent(t *testing.T) {
	res := run(t, testkit.Bundle(collect.OSBMC, testkit.S("ipmi.sdr", "")), testkit.Env(collect.OSBMC))
	if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 {
		t.Fatalf("expected empty result, got %v %v", testkit.IDs(res), res.Coverage)
	}
}

// Real laptop data from the lm-sensors test suite: `sensors -j` and the
// matching hwmon tree. Everything is healthy; the bogus acpitz crit of
// 210 °C must be ignored, batteries dropped.
func TestLaptopHealthy(t *testing.T) {
	b := linux(
		testkit.S("sensors.lmsensors_json", testkit.Read(t, "lmsensors_laptop.json")),
		testkit.S("sensors.hwmon", testkit.Read(t, "hwmon_lmsensors_laptop.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	if w := worst(res); w != model.OK {
		t.Fatalf("worst = %v: %v", w, testkit.IDs(res))
	}
	ok := testkit.Find(res, "sensors.temperature_ok")
	if ok == nil || !strings.Contains(ok.Title.EN, "hottest") {
		t.Fatalf("no temperature_ok: %v", testkit.IDs(res))
	}
	f := facts(t, res)
	for _, tt := range f.Temperatures {
		if tt.Source != srcLM {
			t.Errorf("hwmon duplicate of an lm-sensors chip: %+v", tt)
		}
		if strings.HasPrefix(tt.Chip, "BAT") {
			t.Errorf("battery not dropped: %+v", tt)
		}
	}
	if c := testkit.Cov(res, "sensors.temperature"); c == nil || c.State != model.CovRan {
		t.Fatalf("temperature coverage %+v", c)
	}
	// laptops have no fan readings: partial with the sensors-detect advice
	if c := testkit.Cov(res, "sensors.fans"); c == nil || c.State != model.CovPartial || !strings.Contains(c.Fix.EN, "sensors-detect") {
		t.Fatalf("fans coverage %+v", c)
	}
	// coretemp cores are folded into one row
	for _, tb := range res.Tables {
		if tb.ID == "sensors.temperatures" {
			n := 0
			for _, r := range tb.Rows {
				if strings.HasPrefix(r.Cells[1], "Core ") {
					n++
				}
			}
			if n != 0 {
				t.Errorf("core rows not folded: %d", n)
			}
		}
	}
}

// The same laptop where one sensor could not be read (lm-sensors
// laptop-err fixture): empty features must not break anything.
func TestLaptopReadError(t *testing.T) {
	res := run(t, linux(testkit.S("sensors.lmsensors_json", testkit.Read(t, "lmsensors_laptop_err.json"))), testkit.Env(collect.OSLinux))
	if worst(res) != model.OK {
		t.Fatalf("%v", testkit.IDs(res))
	}
}

// Real desktop board (nct6798 + jc42 + k10temp): jc42 has max=crit=0 with
// alarms set, nct6798 voltage inputs have max=0 with alarms set, AUXTIN1
// reads -62 °C and PCH sensors 0 °C. None of it is a fault.
func TestBogusAlarmsIgnored(t *testing.T) {
	res := run(t, linux(testkit.S("sensors.lmsensors_json", testkit.Read(t, "lmsensors_amd_nct6798.json"))), testkit.Env(collect.OSLinux))
	for _, f := range res.Findings {
		if f.Severity >= model.Warn {
			t.Errorf("false alarm: %s %s", f.ID, f.Title.EN)
		}
	}
	if testkit.Find(res, "sensors.fans_ok") == nil {
		t.Errorf("fans_ok missing: %v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "sensors.intrusion"); f == nil || f.Severity != model.Info {
		t.Errorf("intrusion should be info: %v", testkit.IDs(res))
	}
	fs := facts(t, res)
	nc := 0
	for _, f := range fs.Fans {
		if !f.Connected {
			nc++
		}
	}
	if nc == 0 {
		t.Errorf("0 RPM headers without min should be 'not connected'")
	}
}

// Real dual-socket Fujitsu RX300 S7 (`sensors -u -A`, no Adapter lines).
func TestRawServerHealthy(t *testing.T) {
	b := linux(
		testkit.RC("sensors.lmsensors_json", 1, "", "sensors: invalid option -- 'j'"),
		testkit.S("sensors.lmsensors", testkit.Read(t, "lmsensors_u_fujitsu_rx300s7.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	if worst(res) != model.OK {
		t.Fatalf("%v", testkit.IDs(res))
	}
	fs := facts(t, res)
	var pkg1 *Temperature
	for i := range fs.Temperatures {
		if fs.Temperatures[i].Chip == "coretemp-isa-0001" && fs.Temperatures[i].Sensor == "Package id 1" {
			pkg1 = &fs.Temperatures[i]
		}
	}
	if pkg1 == nil || pkg1.Crit == nil || *pkg1.Crit != 91 || *pkg1.Celsius != 35 {
		t.Fatalf("Package id 1 parsed wrong: %+v", pkg1)
	}
	if len(fs.Power) == 0 || fs.Power[0].Value != 116 {
		t.Errorf("power_meter average not read: %+v", fs.Power)
	}
}

// Telegraf's `sensors -A -u` mock: acpitz crit 31.3 °C with an 8.3 °C
// reading (bogus ACPI limits), atk0110 labels with a leading space.
func TestRawTelegraf(t *testing.T) {
	res := run(t, linux(testkit.S("sensors.lmsensors", testkit.Read(t, "lmsensors_u_telegraf.txt"))), testkit.Env(collect.OSLinux))
	if worst(res) != model.OK {
		t.Fatalf("%v", testkit.IDs(res))
	}
	found := false
	for _, v := range facts(t, res).Voltages {
		if v.Sensor == "+3.3 Voltage" && v.Volts != nil && *v.Volts == 3.36 {
			found = true
		}
	}
	if !found {
		t.Errorf("atk0110 +3.3 Voltage not parsed: %+v", facts(t, res).Voltages)
	}
}

// Faults derived from the Fujitsu fixture: CPU package at critical, a core
// over high, a stopped fan with a minimum, a slow fan, a +12 V rail out of
// range; plus an empty header, an unconfigured AVCC alarm and SYSTIN
// alarm with max=0 that must not alarm.
func TestServerFaults(t *testing.T) {
	res := run(t, linux(testkit.S("sensors.lmsensors", testkit.Read(t, "lmsensors_u_server_faults.txt"))), testkit.Env(collect.OSLinux))
	want := map[string]model.Severity{
		"sensors.temp_critical": model.Crit,
		"sensors.temp_high":     model.Warn,
		"sensors.fan_stopped":   model.Crit,
		"sensors.fan_slow":      model.Warn,
		"sensors.voltage_alarm": model.Warn,
	}
	for id, sev := range want {
		f := testkit.Find(res, id)
		if f == nil {
			t.Errorf("missing %s: %v", id, testkit.IDs(res))
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s severity %v, want %v", id, f.Severity, sev)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("%s has no evidence", id)
		}
	}
	if f := testkit.Find(res, "sensors.temp_critical"); f != nil && f.Target != "coretemp-isa-0001 Package id 1" {
		t.Errorf("temp_critical target %q", f.Target)
	}
	if f := testkit.Find(res, "sensors.fan_stopped"); f != nil && (f.Part == nil || f.Part.Kind != "fan" || !strings.Contains(f.Title.EN, "CPU FAN")) {
		t.Errorf("fan_stopped: %+v", f)
	}
	if f := testkit.Find(res, "sensors.voltage_alarm"); f != nil && !strings.Contains(f.Title.EN, "+12V") {
		t.Errorf("voltage alarm should be +12V only: %s", f.Title.EN)
	}
	if testkit.Find(res, "sensors.temperature_ok") != nil || testkit.Find(res, "sensors.fans_ok") != nil {
		t.Errorf("OK findings next to faults: %v", testkit.IDs(res))
	}
	n := 0
	for _, f := range res.Findings {
		if f.ID == "sensors.temp_high" || f.ID == "sensors.temp_alarm" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("SYSTIN max=0 alarm must not count: %v", testkit.IDs(res))
	}
}

// hwmon only (no lm-sensors installed): NVMe over its critical limit and a
// latched coretemp critical alarm; thermal zones are merged without
// duplicating acpitz.
func TestHwmonOnlyFaults(t *testing.T) {
	b := linux(
		testkit.Missing("sensors.lmsensors_json", "sensors"),
		testkit.S("sensors.hwmon", testkit.Read(t, "hwmon_faults.txt")),
		testkit.S("sensors.thermal", testkit.Read(t, "thermal_zones.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "sensors.temp_critical")
	if f == nil || f.Severity != model.Crit || !strings.Contains(f.Target, "nvme") {
		t.Fatalf("nvme critical: %v", testkit.IDs(res))
	}
	if !strings.Contains(f.Action.EN, "drive") {
		t.Errorf("disk action expected: %s", f.Action.EN)
	}
	if f := testkit.Find(res, "sensors.temp_crit_alarm"); f == nil || f.Severity != model.Warn {
		t.Errorf("coretemp crit_alarm: %v", testkit.IDs(res))
	}
	acpitz := 0
	zones := 0
	for _, tt := range facts(t, res).Temperatures {
		if strings.Contains(tt.Chip, "acpitz") || tt.Sensor == "acpitz" {
			acpitz++
		}
		if tt.Source == srcThermal {
			zones++
		}
	}
	if acpitz != 5 { // the 5 hwmon acpitz inputs, no extra thermal zone copy
		t.Errorf("acpitz rows = %d", acpitz)
	}
	if zones != 2 { // x86_pkg_temp and pch_cannonlake
		t.Errorf("thermal zones = %d", zones)
	}
}

func TestThermalZoneCritical(t *testing.T) {
	res := run(t, linux(testkit.S("sensors.thermal", testkit.Read(t, "thermal_zones_hot.txt"))), testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "sensors.temp_critical")
	if f == nil || !strings.Contains(f.Target, "pch_cannonlake") {
		t.Fatalf("%v", testkit.IDs(res))
	}
}

func TestNoSensorsBareMetal(t *testing.T) {
	b := linux(
		testkit.Missing("sensors.lmsensors_json", "sensors"),
		testkit.S("sensors.hwmon", ""),
		testkit.S("sensors.thermal", ""),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "sensors.temperature")
	if c == nil || c.State != model.CovPartial {
		t.Fatalf("coverage %+v", c)
	}
	if !strings.Contains(c.Fix.EN, "dnf install -y lm_sensors") || !strings.Contains(c.Fix.EN, "sensors-detect --auto") || !strings.Contains(c.Fix.EN, "ipmitool") {
		t.Errorf("fix text: %s", c.Fix.EN)
	}
	if !strings.Contains(c.Reason.VI, "lm-sensors") {
		t.Errorf("reason: %s", c.Reason.VI)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings: %v", testkit.IDs(res))
	}
	// Debian family wording
	env := testkit.Env(collect.OSLinux)
	env.Distro, env.Like, env.PM, env.Root = "ubuntu", "debian", "apt", false
	res = run(t, b, env)
	if c := testkit.Cov(res, "sensors.temperature"); !strings.Contains(c.Fix.EN, "sudo apt-get install -y --no-install-recommends lm-sensors") || !strings.Contains(c.Fix.EN, "sudo sensors-detect") {
		t.Errorf("debian fix: %s", c.Fix.EN)
	}
}

// When the OS sees nothing but the BMC SDR has temperatures and fans, the
// gap is covered by IPMI.
func TestNoSensorsButBMC(t *testing.T) {
	b := linux(
		testkit.S("sensors.hwmon", ""),
		testkit.S("ipmi.sdr", "Inlet Temp       | 04h | ok  |  7.1 | 23 degrees C\nFan1A            | 30h | ok  |  7.1 | 3600 RPM\n"),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	for _, id := range []string{"sensors.temperature", "sensors.fans"} {
		if c := testkit.Cov(res, id); c == nil || c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "BMC") {
			t.Errorf("%s: %+v", id, c)
		}
	}
}

func TestContainer(t *testing.T) {
	b := linux(
		testkit.Skipped("sensors.lmsensors_json", "container"),
		testkit.Skipped("sensors.hwmon", "container"),
		testkit.Skipped("sensors.thermal", "container"),
	)
	env := testkit.Env(collect.OSLinux)
	env.Virtual, env.Container = "wsl", true
	res := run(t, b, env)
	for _, c := range res.Coverage {
		if c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "container") {
			t.Errorf("%+v", c)
		}
	}
	// even if meta.virt missed the container, the collector's flags win
	res = run(t, b, testkit.Env(collect.OSLinux))
	for _, c := range res.Coverage {
		if c.State != model.CovSkipped {
			t.Errorf("%+v", c)
		}
	}
}

func TestVMNoSensors(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res := run(t, linux(testkit.S("sensors.hwmon", ""), testkit.S("sensors.thermal", "")), env)
	for _, c := range res.Coverage {
		if c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "virtual machine") {
			t.Errorf("%+v", c)
		}
	}
}

func TestWindows(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("sensors.win_thermalzone", testkit.Read(t, "win_thermalzone.json")),
		testkit.S("sensors.win_fan", testkit.Read(t, "win_fan.json")),
		testkit.S("sensors.win_probe", "[]"),
		testkit.S("sensors.win_lhm", testkit.Read(t, "win_lhm.json")),
		testkit.Missing("sensors.win_ohm", "OpenHardwareMonitor"),
	)
	res := run(t, b, testkit.Env(collect.OSWindows))
	// CPU Package 91.5 °C with no published limit -> Warn (fallback 90 °C)
	f := testkit.Find(res, "sensors.temp_high")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Target, "CPU Package") {
		t.Fatalf("%v", testkit.IDs(res))
	}
	fs := facts(t, res)
	for _, tt := range fs.Temperatures {
		if strings.Contains(tt.Sensor, "Distance") || strings.Contains(tt.Sensor, "Average") {
			t.Errorf("derived LHM value kept: %+v", tt)
		}
		if tt.Sensor == "TZ00_0" && (tt.Celsius == nil || *tt.Celsius < 39.9 || *tt.Celsius > 40.1) {
			t.Errorf("tenths of Kelvin conversion: %+v", tt)
		}
	}
	if c := testkit.Cov(res, "sensors.temperature"); c == nil || c.State != model.CovRan {
		t.Errorf("%+v", c)
	}
	if c := testkit.Cov(res, "sensors.fans"); c == nil || c.State != model.CovRan {
		t.Errorf("%+v", c)
	}
}

func TestWindowsNothing(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows,
		testkit.Skipped("sensors.win_thermalzone", "not-admin"),
		testkit.S("sensors.win_fan", "[]"),
		testkit.S("sensors.win_probe", "[]"),
		testkit.Missing("sensors.win_lhm", "LibreHardwareMonitor"),
		testkit.Missing("sensors.win_ohm", "OpenHardwareMonitor"),
	)
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res := run(t, b, env)
	c := testkit.Cov(res, "sensors.temperature")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Fix.EN, "diagward bmc") || !strings.Contains(c.Fix.EN, "administrator") {
		t.Fatalf("%+v", c)
	}
	// Admin, but the firmware does not implement the ACPI zone (common on servers)
	b = testkit.Bundle(collect.OSWindows,
		testkit.RC("sensors.win_thermalzone", 1, "[]", "Not supported"),
		testkit.S("sensors.win_fan", "[]"),
		testkit.Missing("sensors.win_lhm", "LibreHardwareMonitor"),
	)
	res = run(t, b, testkit.Env(collect.OSWindows))
	c = testkit.Cov(res, "sensors.temperature")
	if c == nil || c.State != model.CovPartial || strings.Contains(c.Fix.EN, "administrator") {
		t.Fatalf("%+v", c)
	}
}

// Garbage, truncated and hostile input must never panic or alarm.
func TestGarbage(t *testing.T) {
	inputs := []string{
		"", "{", "}", "null", "[]", `{"x":`, `{"coretemp-isa-0000":{"Adapter":"ISA adapter",}}`,
		`{"c-isa-0":{"Core 0":{"temp2_input":"hot"}}}`, `{"c-isa-0":{"Core 0":{"temp2_input":1e400}}}`,
		"coretemp-isa-0000\n  temp1_input: abc\n", "\n\n:::\n  fan1_input:\n", "=\n==\n/sys/class/hwmon/hwmon0/temp1_input=\n",
		"/sys/class/hwmon/hwmonX/temp1_input=1\n/sys/class/hwmon/hwmon1/temp99999999999999999999_input=5\n",
		"/sys/class/thermal/thermal_zone0/trip_point_0_temp=abc\n/sys/class/thermal/thermal_zone0/trip_point_0_type=critical\n",
	}
	full := testkit.Read(t, "lmsensors_amd_nct6798.json") + testkit.Read(t, "lmsensors_u_server_faults.txt") + testkit.Read(t, "hwmon_faults.txt")
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		a, b := rng.Intn(len(full)), rng.Intn(len(full))
		if a > b {
			a, b = b, a
		}
		inputs = append(inputs, full[a:b])
	}
	for _, in := range inputs {
		for _, os := range []string{collect.OSLinux, collect.OSWindows} {
			b := testkit.Bundle(os,
				testkit.S("sensors.lmsensors_json", in), testkit.S("sensors.lmsensors", in),
				testkit.S("sensors.hwmon", in), testkit.S("sensors.thermal", in),
				testkit.S("sensors.win_thermalzone", in), testkit.S("sensors.win_lhm", in),
				testkit.S("sensors.win_fan", in), testkit.S("sensors.win_probe", in),
			)
			Check(b, testkit.Env(os)) // must not panic
		}
	}
	// Validate a few
	run(t, linux(testkit.S("sensors.lmsensors_json", `{"coretemp-isa-0000":{"Adapter":"ISA adapter",}}`)), testkit.Env(collect.OSLinux))
}

func TestTrailingCommaJSON(t *testing.T) {
	rs, ok := parseLMJSON("{\n  \"k10temp-pci-00c3\":{\n    \"Adapter\": \"PCI adapter\",\n  },\n  \"nvme-pci-0100\":{\"Composite\":{\"temp1_input\":40.85,\"temp1_crit\":84.85,}}\n}")
	if !ok || len(rs) != 1 || rs[0].Label != "Composite" || *rs[0].Crit != 84.85 {
		t.Fatalf("%v %+v", ok, rs)
	}
}

func TestNewJSONFormat(t *testing.T) {
	rs, ok := parseLMJSON(`{"nvme-pci-0100":{"Adapter":"PCI adapter","Composite":{"input":{"quantity":"temperature","unit":"°C","value":95.5},"crit":{"quantity":"temperature","unit":"°C","value":84.85}}}}`)
	if !ok || len(rs) != 1 || rs[0].Input == nil || *rs[0].Input != 95.5 || rs[0].Crit == nil {
		t.Fatalf("%+v", rs)
	}
	if j := evalTemp(rs[0]); j.sev != model.Crit {
		t.Fatalf("sev %v", j.sev)
	}
}
