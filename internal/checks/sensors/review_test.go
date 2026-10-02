package sensors

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// Contract: drive temperatures belong to the disk domain. The NVMe in
// hwmon_faults.txt is over its critical limit; it stays in the table but
// raises no sensors finding (and is not "the hottest sensor" either).
func TestDiskTemperaturesNotJudgedHere(t *testing.T) {
	b := linux(
		testkit.Missing("sensors.lmsensors_json", "sensors"),
		testkit.S("sensors.hwmon", testkit.Read(t, "hwmon_faults.txt")),
	)
	res := run(t, b, testkit.Env(collect.OSLinux))
	for _, f := range res.Findings {
		if strings.Contains(f.Target+f.Title.EN, "nvme") || strings.Contains(strings.Join(f.Evidence, " "), "nvme") {
			t.Errorf("drive temperature judged by sensors: %s %s", f.ID, f.Title.EN)
		}
	}
	found := false
	for _, tb := range res.Tables {
		for _, r := range tb.Rows {
			if strings.Contains(r.Cells[0], "nvme") {
				found = true
				if !strings.Contains(r.Cells[len(r.Cells)-1], "disk") {
					t.Errorf("nvme row note: %q", r.Cells)
				}
			}
		}
	}
	if !found {
		t.Errorf("nvme row missing from the table")
	}
	// lm-sensors naming (nvme-pci-0100, drivetemp-scsi-0-0)
	js := `{"nvme-pci-0100":{"Adapter":"PCI adapter","Composite":{"temp1_input":96.85,"temp1_max":81.85,"temp1_crit":84.85}},` +
		`"drivetemp-scsi-0-0":{"Adapter":"SCSI adapter","temp1":{"temp1_input":71.0,"temp1_max":60.0,"temp1_crit":70.0}},` +
		`"coretemp-isa-0000":{"Adapter":"ISA adapter","Package id 0":{"temp1_input":45.0,"temp1_max":80.0,"temp1_crit":100.0}}}`
	res = run(t, linux(testkit.S("sensors.lmsensors_json", js)), testkit.Env(collect.OSLinux))
	if w := worst(res); w != model.OK {
		t.Fatalf("drives judged: %v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "sensors.temperature_ok"); f == nil || strings.Contains(f.Title.EN, "nvme") || !strings.Contains(f.Title.EN, "1 sensors") {
		t.Fatalf("temperature_ok: %+v", f)
	}
}

// k10temp reports temp1_max as a constant 70 °C ("*val = 70 * 1000" in
// drivers/hwmon/k10temp.c; visible on Zen with kernels up to ~5.6, e.g.
// RHEL 8 / Ubuntu 18.04 on EPYC). It is not a limit: an EPYC under load at
// 74 °C Tctl is healthy (AMD Tjmax 95 °C on these parts).
func TestK10tempFixedMax(t *testing.T) {
	raw := testkit.Read(t, "lmsensors_u_k10temp_epyc_4.18.txt")
	res := run(t, linux(testkit.S("sensors.lmsensors", raw)), testkit.Env(collect.OSLinux))
	if w := worst(res); w != model.OK {
		t.Fatalf("fixed 70 °C max raised: %v", testkit.IDs(res))
	}
	for _, tt := range facts(t, res).Temperatures {
		if strings.HasPrefix(tt.Chip, "k10temp") && tt.High != nil {
			t.Errorf("k10temp high kept: %v", *tt.High)
		}
	}
	// still judged against AMD's 95 °C
	hot := strings.Replace(raw, "temp1_input: 74.250", "temp1_input: 97.000", 1)
	res = run(t, linux(testkit.S("sensors.lmsensors", hot)), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "sensors.temp_high"); f == nil || f.Severity != model.Warn {
		t.Fatalf("97 °C Tdie: %v", testkit.IDs(res))
	}
}

// lm-sensors 3.5.0 counted unreadable subfeatures when placing commas
// (prog/sensors/chips.c print_chip_json, fixed in 3.6.0 "stray comma bug in
// the JSON output"), so a chip whose first subfeature fails prints
// `{` followed by `,`. printf("%.3f") of a NaN prints "nan".
func TestLMSensors35StrayComma(t *testing.T) {
	js := "{\n   \"coretemp-isa-0000\":{\n      \"Adapter\": \"ISA adapter\",\n      \"Package id 0\":{\n,\n         \"temp1_max\": 80.000,\n         \"temp1_crit\": 100.000,\n         \"temp1_crit_alarm\": 0.000\n      },\n" +
		"      \"Core 0\":{\n         \"temp2_input\": 41.000,\n         \"temp2_max\": 80.000\n      },\n      \"Core 1\":{\n         \"temp3_input\": nan,\n         \"temp3_max\": -nan\n      }\n   }\n}\n"
	rs, ok := parseLMJSON(js)
	if !ok {
		t.Fatalf("3.5.0 JSON rejected")
	}
	n := 0
	for _, r := range rs {
		if r.Label == "Core 0" && r.Input != nil && *r.Input == 41 {
			n++
		}
		if r.Label == "Core 1" && (r.Input != nil || r.Max != nil) {
			t.Errorf("nan became a value: %+v", r)
		}
	}
	if n != 1 {
		t.Fatalf("Core 0 missing: %+v", rs)
	}
}

// power_supply hwmon devices are named after the supply ("AC", "ACAD",
// "BAT0", "ADP1"); real chips that merely start with "ac" are kept.
func TestIgnoredChips(t *testing.T) {
	for _, d := range []string{"AC", "ACAD", "AC0", "BAT0", "BAT1", "ADP1", "ucsi_source_psy_USBC000:001", "iwlwifi_1"} {
		if !ignoredChip(d) {
			t.Errorf("%s should be ignored", d)
		}
	}
	for _, d := range []string{"acbel_fsg032", "acpitz", "acpi_power_meter", "adt7475", "adm1275", "coretemp"} {
		if ignoredChip(d) {
			t.Errorf("%s should be kept", d)
		}
	}
}

// The x86_pkg_temp thermal zone is coretemp's package sensor again (same
// MSR); with coretemp present it only duplicates the row and, having no
// limits, fell back to the 90 °C heuristic next to coretemp's real limit.
func TestPkgTempZoneDuplicate(t *testing.T) {
	js := `{"coretemp-isa-0000":{"Adapter":"ISA adapter","Package id 0":{"temp1_input":92.0,"temp1_max":100.0,"temp1_crit":100.0}}}`
	zones := "/sys/class/thermal/thermal_zone0/type=x86_pkg_temp\n/sys/class/thermal/thermal_zone0/temp=92000\n" +
		"/sys/class/thermal/thermal_zone0/trip_point_0_temp=0\n/sys/class/thermal/thermal_zone0/trip_point_0_type=passive\n"
	res := run(t, linux(testkit.S("sensors.lmsensors_json", js), testkit.S("sensors.thermal", zones)), testkit.Env(collect.OSLinux))
	if w := worst(res); w != model.OK {
		t.Fatalf("%v", testkit.IDs(res))
	}
	for _, tt := range facts(t, res).Temperatures {
		if tt.Source == srcThermal {
			t.Errorf("x86_pkg_temp duplicated: %+v", tt)
		}
	}
	// without coretemp the zone is the only CPU reading and stays
	res = run(t, linux(testkit.S("sensors.thermal", zones)), testkit.Env(collect.OSLinux))
	if len(facts(t, res).Temperatures) != 1 {
		t.Fatalf("zone dropped: %+v", facts(t, res).Temperatures)
	}
}

// A sysfs read that hangs (drivetemp on a dying drive, an ACPI power meter
// that waits on the BMC) is cut by the collector's timeout: say so.
func TestHwmonTimeoutPartial(t *testing.T) {
	s := testkit.RC("sensors.hwmon", 124, testkit.Read(t, "hwmon_lmsensors_laptop.txt"), "")
	s.Timeout = true
	res := run(t, linux(testkit.Missing("sensors.lmsensors_json", "sensors"), s), testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "sensors.temperature")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "time") {
		t.Fatalf("%+v", c)
	}
}

// Coverage.Cmd: the install command, ready to paste; Fix explains.
func TestCoverageCmdLMSensors(t *testing.T) {
	b := linux(testkit.Missing("sensors.lmsensors_json", "sensors"), testkit.S("sensors.hwmon", ""), testkit.S("sensors.thermal", ""))
	res := run(t, b, testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "sensors.temperature")
	if c == nil || c.Cmd != "dnf install -y lm_sensors" || strings.Contains(c.Fix.EN, "dnf install") || !strings.Contains(c.Fix.EN, "sensors-detect") {
		t.Fatalf("%+v", c)
	}
	// lm-sensors installed but no chips: the command is sensors-detect
	b = linux(testkit.RC("sensors.lmsensors_json", 1, "", "No sensors found!"), testkit.S("sensors.hwmon", ""), testkit.S("sensors.thermal", ""))
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res = run(t, b, env)
	if c := testkit.Cov(res, "sensors.temperature"); c == nil || c.Cmd != "sudo sensors-detect --auto" {
		t.Fatalf("%+v", c)
	}
}
