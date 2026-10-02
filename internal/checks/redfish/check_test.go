package redfish

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func run(t *testing.T, b *collect.Bundle) model.Result {
	t.Helper()
	env := collect.EnvOf(b)
	env.Now = testkit.Env(collect.OSBMC).Now // 2026-10-01 09:00:20 UTC
	res := Check(b, env)
	testkit.Validate(t, res)
	if res.Domain != domain {
		t.Fatalf("domain %q", res.Domain)
	}
	return res
}

func mustFind(t *testing.T, res model.Result, id string, sev model.Severity, target ...string) *model.Finding {
	t.Helper()
	f := testkit.Find(res, id, target...)
	if f == nil {
		t.Fatalf("no finding %s %v; have %v", id, target, testkit.IDs(res))
	}
	if f.Severity != sev {
		t.Errorf("%s: severity %s, want %s", id, f.Severity, sev)
	}
	return f
}

func noFinding(t *testing.T, res model.Result, id string) {
	t.Helper()
	if f := testkit.Find(res, id); f != nil {
		t.Errorf("unexpected finding %s@%s (%s): %s", id, f.Target, f.Severity, f.Title.EN)
	}
}

func cov(t *testing.T, res model.Result, id, state string) *model.Coverage {
	t.Helper()
	c := testkit.Cov(res, id)
	if c == nil {
		t.Fatalf("no coverage %s", id)
	}
	if c.State != state {
		t.Errorf("coverage %s: state %s (%s), want %s", id, c.State, c.Reason.EN, state)
	}
	return c
}

func worst(res model.Result) model.Severity {
	w := model.OK
	for _, f := range res.Findings {
		w = model.Worst(w, f.Severity)
	}
	return w
}

func table(t *testing.T, res model.Result, id string) model.Table {
	t.Helper()
	for _, tb := range res.Tables {
		if tb.ID == id {
			return tb
		}
	}
	t.Fatalf("no table %s", id)
	return model.Table{}
}

// DMTF public-localstorage: classic Thermal/Power, Storage with drives and
// RAID volumes. Its only problem is the PSU the mockup rates Warning.
func TestLocalStorageMockup(t *testing.T) {
	res := run(t, loadMockup(t, "localstorage").bundle())
	mustFind(t, res, "redfish.psu_warning", model.Warn, "Power Supply Bay")
	if w := worst(res); w != model.Warn {
		t.Errorf("worst %s, want warn: %v", w, testkit.IDs(res))
	}
	mustFind(t, res, "redfish.thermal_ok", model.OK)
	mustFind(t, res, "redfish.storage_ok", model.OK)
	mustFind(t, res, "redfish.memory_ok", model.OK)
	// The mockup's two SEL entries are from 2012: outside the window.
	mustFind(t, res, "redfish.logs_ok", model.OK)
	for _, id := range []string{"redfish.system", "redfish.thermal", "redfish.power", "redfish.storage", "redfish.memory", "redfish.logs"} {
		cov(t, res, id, model.CovRan)
	}
	f := res.Facts.(*Facts)
	if len(f.Drives) != 4 || len(f.Volumes) != 3 || len(f.DIMMs) != 3 || len(f.Temperatures) != 3 || len(f.Fans) != 2 {
		t.Errorf("inventory: %d drives %d volumes %d dimms %d temps %d fans", len(f.Drives), len(f.Volumes), len(f.DIMMs), len(f.Temperatures), len(f.Fans))
	}
	if f.PowerWatts == nil || *f.PowerWatts != 344 {
		t.Errorf("power watts %v", f.PowerWatts)
	}
	tb := table(t, res, "redfish.drives")
	if len(tb.Rows) != 4 || !strings.Contains(strings.Join(tb.Rows[0].Cells, " "), "Contoso") && tb.Rows[0].Cells[1] == "" {
		t.Errorf("drives table %+v", tb.Rows)
	}
	table(t, res, "redfish.temperatures")
	table(t, res, "redfish.fans")
	table(t, res, "redfish.psus")
	table(t, res, "redfish.dimms")
	table(t, res, "redfish.volumes")
}

// DMTF public-rackmount1 read through the newer schemas only
// (ThermalSubsystem, Sensors, PowerSubsystem), as on BMCs that dropped the
// deprecated Thermal/Power resources.
func TestRackmountNewSchemas(t *testing.T) {
	m := loadMockup(t, "rackmount1")
	m.set(t, "/redfish/v1/Chassis/1U", "Thermal", nil)
	m.set(t, "/redfish/v1/Chassis/1U", "Power", nil)
	res := run(t, m.bundle())
	f := res.Facts.(*Facts)
	if len(f.Fans) != 4 {
		t.Errorf("fans %+v", f.Fans)
	}
	var cpu *Temperature
	for i := range f.Temperatures {
		if f.Temperatures[i].Name == "CPU #1 Temperature" {
			cpu = &f.Temperatures[i]
		}
	}
	if cpu == nil || cpu.Reading == nil || *cpu.Reading != 37 || cpu.Crit == nil || *cpu.Crit != 45 || cpu.Warn == nil || *cpu.Warn != 42 {
		t.Fatalf("CPU sensor thresholds not read: %+v", cpu)
	}
	if len(f.PSUs) != 2 {
		t.Fatalf("psus %+v", f.PSUs)
	}
	if f.PSUs[0].InputV == nil || *f.PSUs[0].InputV != 230.2 {
		t.Errorf("PSU metrics input voltage %v", f.PSUs[0].InputV)
	}
	// Bay1 is Warning in the mockup, Bay2 Absent.
	mustFind(t, res, "redfish.psu_warning", model.Warn, "PSU 1")
	if testkit.Find(res, "redfish.psu_warning", "PSU 2") != nil || testkit.Find(res, "redfish.psu_no_input") != nil {
		t.Errorf("absent bay must not be reported: %v", testkit.IDs(res))
	}
	mustFind(t, res, "redfish.thermal_ok", model.OK)
	cov(t, res, "redfish.thermal", model.CovRan)
	cov(t, res, "redfish.power", model.CovRan)
	// The FPGA is not a CPU.
	for _, c := range f.CPUs {
		if strings.Contains(c.Socket, "FPGA") {
			t.Errorf("FPGA counted as CPU: %+v", c)
		}
	}
}

// The same mockup with both schemas present uses the classic resources.
func TestRackmountClassic(t *testing.T) {
	res := run(t, loadMockup(t, "rackmount1").bundle())
	f := res.Facts.(*Facts)
	if len(f.Temperatures) == 0 || len(f.PSUs) == 0 {
		t.Fatalf("classic thermal/power not read: %v", testkit.IDs(res))
	}
	for _, tt := range f.Temperatures {
		if tt.Name == "CPU #1 Temperature" {
			t.Errorf("Sensors read although Thermal exists")
		}
	}
}

// Dell iDRAC 9 (resources from the telegraf test suite, logs synthesised
// from Dell's message registry): power loss on PSU 2 two days ago.
func TestDellIDRAC(t *testing.T) {
	res := run(t, loadMockup(t, "dell").bundle())
	f := mustFind(t, res, "redfish.event_critical", model.Crit, "PSU0003")
	if f.Component != model.CompPower {
		t.Errorf("PSU0003 component %s", f.Component)
	}
	if !strings.Contains(f.Title.VI, "Nhật ký BMC") || !strings.Contains(f.Title.EN, "power supply 2") {
		t.Errorf("title %+v", f.Title)
	}
	mustFind(t, res, "redfish.event_critical", model.Crit, "RDU0012")
	mustFind(t, res, "redfish.event_warning", model.Warn, "MEM0701")
	// The fan event is 19 days old (history), the drive and inlet ones are
	// older than the 30-day window.
	mustFind(t, res, "redfish.event_history", model.Info)
	for _, g := range res.Facts.(*Facts).Events {
		if g.MessageID == "PDR1016" || g.MessageID == "TMP0120" {
			t.Errorf("event outside the window kept: %+v", g)
		}
		if g.MessageID == "FAN0002" && g.Severity != model.Info {
			t.Errorf("old fan event severity %s", g.Severity)
		}
	}
	mustFind(t, res, "redfish.thermal_ok", model.OK)
	mustFind(t, res, "redfish.power_ok", model.OK)
	// Memory, Storage and Processors return 404 in this mockup.
	c := cov(t, res, "redfish.memory", model.CovSkipped)
	if c.Fix.VI == "" {
		t.Error("skipped coverage needs a fix")
	}
	cov(t, res, "redfish.storage", model.CovSkipped)
	cov(t, res, "redfish.logs", model.CovRan)

	h := HostInfo(loadMockup(t, "dell").bundle())
	if h.Serial != "CLFV7M2" || h.Model != "PowerEdge R640" || h.Vendor != "Dell Inc." || h.BIOS != "2.3.10" || h.Hostname != "tpa-hostname" {
		t.Errorf("host %+v", h)
	}
	if !strings.Contains(h.BMC, "4.40.00.00") {
		t.Errorf("bmc %q", h.BMC)
	}
}

// HPE iLO 5 (telegraf captures + Oem SmartStorage and IML synthesised from
// HPE's iLO 5 API reference): a failed SSD in a RAID 1, IML entries with
// the Repaired flag, the "0000-00-00" timestamp and a count.
func TestHPEILO(t *testing.T) {
	res := run(t, loadMockup(t, "hpe").bundle())
	d := mustFind(t, res, "redfish.drive_failed", model.Crit, "1I:1:2")
	if d.Part == nil || d.Part.Serial != "S4NANA0M800124" || d.Part.Kind != "disk" || d.Part.Model != "VK000480GWSRR" {
		t.Errorf("part %+v", d.Part)
	}
	if !strings.Contains(d.Action.VI, "S4NANA0M800124") || !strings.Contains(d.Action.VI, "Sao lưu") {
		t.Errorf("action %q", d.Action.VI)
	}
	mustFind(t, res, "redfish.raid_warning", model.Warn, "OS")
	ev := mustFind(t, res, "redfish.event_critical", model.Crit)
	if !strings.Contains(ev.Title.EN, "3×") || ev.Component != model.CompDisk {
		t.Errorf("IML event %+v / %s", ev.Title, ev.Component)
	}
	mustFind(t, res, "redfish.event_warning", model.Warn)
	var repaired bool
	for _, g := range res.Facts.(*Facts).Events {
		if g.Repaired {
			repaired = true
			if g.Severity != model.Info {
				t.Errorf("repaired IML entry severity %s", g.Severity)
			}
		}
		if strings.Contains(g.Message, "Browser login") {
			t.Errorf("OK entry kept: %+v", g)
		}
	}
	if !repaired {
		t.Error("repaired IML entry missing")
	}
	f := res.Facts.(*Facts)
	if len(f.DIMMs) != 1 || f.DIMMs[0].Slot != "PROC 1 DIMM 1" {
		t.Errorf("dimms %+v (absent slot must be skipped)", f.DIMMs)
	}
	if len(f.PSUs) != 2 || f.PSUs[0].Name == f.PSUs[1].Name {
		t.Errorf("HPE PSU names must differ: %+v", f.PSUs)
	}
	for _, dr := range f.Drives {
		if dr.LifeLeftPercent == nil || *dr.LifeLeftPercent < 90 {
			t.Errorf("SSD endurance not converted: %+v", dr.LifeLeftPercent)
		}
	}
	h := HostInfo(loadMockup(t, "hpe").bundle())
	if h.Model != "ProLiant DL360 Gen10" || !strings.Contains(h.BMC, "iLO 5") {
		t.Errorf("host %+v", h)
	}
}

func TestFailureVariants(t *testing.T) {
	const (
		power   = "/redfish/v1/Chassis/1U/Power"
		thermal = "/redfish/v1/Chassis/1U/Thermal"
		sys     = "/redfish/v1/Systems/437XR1138R2"
		drive   = "/redfish/v1/Chassis/1U/Drives/32ADF365C6C1B7BD"
		volume  = "/redfish/v1/Systems/437XR1138R2/Storage/1/Volumes/1"
		dimm    = "/redfish/v1/Systems/437XR1138R2/Memory/DIMM2"
		entries = "/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries"
		mgr     = "/redfish/v1/Managers/BMC"
	)
	secondPSU := func(m mockup) {
		p := m[power]
		list := p["PowerSupplies"].([]any)
		cp := map[string]any{}
		b, _ := json.Marshal(list[0])
		_ = json.Unmarshal(b, &cp)
		cp["Name"] = "Power Supply Bay 2"
		cp["SerialNumber"] = "1Z0000002"
		cp["MemberId"] = "1"
		p["PowerSupplies"] = append(list, cp)
		m.set(t, power, "PowerSupplies.0.Status.Health", "OK")
		m.set(t, power, "PowerSupplies.1.Status.Health", "OK")
	}
	cases := []struct {
		name   string
		mutate func(m mockup)
		id     string
		sev    model.Severity
		target string
		check  func(t *testing.T, f *model.Finding, res model.Result)
	}{
		{"psu critical", func(m mockup) { m.set(t, power, "PowerSupplies.0.Status.Health", "Critical") },
			"redfish.psu_failed", model.Crit, "Power Supply Bay", func(t *testing.T, f *model.Finding, _ model.Result) {
				if f.Part == nil || f.Part.Serial != "1Z0000001" || f.Part.Kind != "psu" {
					t.Errorf("part %+v", f.Part)
				}
			}},
		{"psu no input", func(m mockup) {
			secondPSU(m)
			m.set(t, power, "PowerSupplies.1.LineInputVoltage", 0.0)
		}, "redfish.psu_no_input", model.Crit, "Power Supply Bay 2", func(t *testing.T, f *model.Finding, res model.Result) {
			if !strings.Contains(f.Action.VI, "1Z0000002") {
				t.Errorf("action %q", f.Action.VI)
			}
			if testkit.Find(res, "redfish.psu_no_input", "Power Supply Bay") != nil {
				t.Error("the PSU with input must not be reported")
			}
		}},
		{"psu redundancy lost", func(m mockup) {
			secondPSU(m)
			m[power]["Redundancy"] = []any{map[string]any{"Name": "PSU Redundancy", "Mode": "N+m", "Status": map[string]any{"State": "Enabled", "Health": "Critical"}}}
		}, "redfish.psu_redundancy_lost", model.Warn, "PSU Redundancy", nil},
		{"fan failed", func(m mockup) {
			m.set(t, thermal, "Fans.0.Status.Health", "Critical")
			m.set(t, thermal, "Fans.0.Reading", 0.0)
		}, "redfish.fan_failed", model.Crit, "BaseBoard System Fan", func(t *testing.T, f *model.Finding, _ model.Result) {
			if f.Part == nil || f.Part.Kind != "fan" {
				t.Errorf("part %+v", f.Part)
			}
		}},
		{"fan zero rpm but BMC says OK", func(m mockup) { m.set(t, thermal, "Fans.1.Reading", 0.0) },
			"redfish.fan_warning", model.Warn, "BaseBoard System Fan Backup", nil},
		{"fan redundancy", func(m mockup) { m.set(t, thermal, "Redundancy.0.Status.Health", "Warning") },
			"redfish.fan_redundancy_lost", model.Warn, "BaseBoard System Fans", nil},
		{"temp critical", func(m mockup) { m.set(t, thermal, "Temperatures.0.ReadingCelsius", 46.0) },
			"redfish.temp_critical", model.Crit, "CPU1 Temp", func(t *testing.T, f *model.Finding, _ model.Result) {
				if !strings.Contains(f.Title.EN, "45 °C") || !strings.Contains(f.Title.VI, "nguy hiểm") {
					t.Errorf("title %+v", f.Title)
				}
			}},
		{"temp high", func(m mockup) { m.set(t, thermal, "Temperatures.0.ReadingCelsius", 43.0) },
			"redfish.temp_high", model.Warn, "CPU1 Temp", nil},
		{"drive failure predicted", func(m mockup) { m.set(t, drive, "FailurePredicted", true) },
			"redfish.drive_predicted_failure", model.Crit, "Drive Sample", func(t *testing.T, f *model.Finding, _ model.Result) {
				if f.Part == nil || f.Part.Serial != "1234570" || f.Part.Size != "900 GB" {
					t.Errorf("part %+v", f.Part)
				}
			}},
		{"drive critical", func(m mockup) { m.set(t, drive, "Status.Health", "Critical") },
			"redfish.drive_failed", model.Crit, "Drive Sample", nil},
		{"ssd worn out", func(m mockup) {
			m.set(t, drive, "MediaType", "SSD")
			m.set(t, drive, "PredictedMediaLifeLeftPercent", 8.0)
		}, "redfish.ssd_wear", model.Crit, "Drive Sample", nil},
		{"ssd wearing", func(m mockup) {
			m.set(t, drive, "MediaType", "SSD")
			m.set(t, drive, "PredictedMediaLifeLeftPercent", 15.0)
		}, "redfish.ssd_wear", model.Warn, "Drive Sample", nil},
		{"volume degraded", func(m mockup) { m.set(t, volume, "Status.Health", "Critical") },
			"redfish.raid_degraded", model.Crit, "Virtual Disk 1", nil},
		{"volume warning with failed member", func(m mockup) {
			m.set(t, volume, "Status.Health", "Warning")
			m.set(t, "/redfish/v1/Chassis/1U/Drives/3F5A8C54207B7233", "Status.Health", "Critical")
		}, "redfish.raid_degraded", model.Crit, "Virtual Disk 1", nil},
		{"volume rebuilding", func(m mockup) {
			m.set(t, volume, "Status.Health", "Warning")
			m.set(t, volume, "Operations", []any{map[string]any{"OperationName": "Rebuild", "PercentageComplete": 42.0}})
		}, "redfish.raid_rebuilding", model.Warn, "Virtual Disk 1", func(t *testing.T, f *model.Finding, _ model.Result) {
			if !strings.Contains(f.Title.EN, "42%") {
				t.Errorf("title %q", f.Title.EN)
			}
		}},
		{"dell raid status degraded", func(m mockup) {
			m.set(t, volume, "Oem", map[string]any{"Dell": map[string]any{"DellVolume": map[string]any{"RaidStatus": "Degraded"}}})
		}, "redfish.raid_degraded", model.Crit, "Virtual Disk 1", nil},
		{"controller cache", func(m mockup) {
			m.set(t, "/redfish/v1/Systems/437XR1138R2/Storage/1", "StorageControllers.0.CacheSummary.Status.Health", "Warning")
		}, "redfish.controller_cache", model.Warn, "Contoso Integrated RAID", nil},
		{"dimm failed", func(m mockup) { m.set(t, dimm, "Status.Health", "Critical") },
			"redfish.dimm_failed", model.Crit, "", func(t *testing.T, f *model.Finding, _ model.Result) {
				if f.Part == nil || f.Part.Kind != "dimm" || f.Part.Size != "16 GiB" && f.Part.Size != "32 GiB" && f.Part.Size == "" {
					t.Errorf("part %+v", f.Part)
				}
			}},
		{"critical SEL recent", func(m mockup) {
			m.set(t, entries, "Members.0.Created", "2026-09-30T14:44:00Z")
			m.set(t, entries, "Members.1.Created", "2026-09-30T14:45:00Z")
		}, "redfish.event_critical", model.Crit, "0x592A28", func(t *testing.T, f *model.Finding, _ model.Result) {
			if f.Component != model.CompThermal {
				t.Errorf("component %s", f.Component)
			}
		}},
		{"critical SEL unknown time", func(m mockup) { m.set(t, entries, "Members.0.Created", "1970-01-01T00:00:10Z") },
			"redfish.event_warning", model.Warn, "0x592A28", nil},
		{"bmc unhealthy", func(m mockup) { m.set(t, mgr, "Status.Health", "Critical") },
			"redfish.bmc_health", model.Crit, "", nil},
		{"unexplained rollup", func(m mockup) {
			m.set(t, sys, "Status.HealthRollup", "Critical")
			m.set(t, power, "PowerSupplies.0.Status.Health", "OK")
		}, "redfish.system_health", model.Crit, "", nil},
		{"voltage out of range", func(m mockup) {
			m.set(t, power, "Voltages.0.ReadingVolts", 10.8)
			m.set(t, power, "Voltages.0.Status.Health", "Critical")
		}, "redfish.voltage_critical", model.Crit, "VRM1 Voltage", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := loadMockup(t, "localstorage")
			tc.mutate(m)
			res := run(t, m.bundle())
			var f *model.Finding
			if tc.target != "" {
				f = mustFind(t, res, tc.id, tc.sev, tc.target)
			} else {
				f = mustFind(t, res, tc.id, tc.sev)
			}
			if tc.sev >= model.Warn && (f.Action.EN == "" || f.Action.VI == "") {
				t.Errorf("no action")
			}
			if len(f.Evidence) == 0 && !strings.HasPrefix(tc.id, "redfish.system") {
				t.Errorf("no evidence")
			}
			if tc.check != nil {
				tc.check(t, f, res)
			}
		})
	}
}

// A rollup explained by a specific finding is not reported twice.
func TestRollupExplained(t *testing.T) {
	m := loadMockup(t, "localstorage")
	m.set(t, "/redfish/v1/Systems/437XR1138R2", "Status.HealthRollup", "Critical")
	m.set(t, "/redfish/v1/Chassis/1U/Drives/32ADF365C6C1B7BD", "Status.Health", "Critical")
	res := run(t, m.bundle())
	mustFind(t, res, "redfish.drive_failed", model.Crit)
	noFinding(t, res, "redfish.system_health")
}

func TestPoweredOff(t *testing.T) {
	m := loadMockup(t, "localstorage")
	m.set(t, "/redfish/v1/Systems/437XR1138R2", "PowerState", "Off")
	m.set(t, "/redfish/v1/Chassis/1U/Thermal", "Fans.0.Reading", 0.0)
	m.set(t, "/redfish/v1/Chassis/1U/Thermal", "Fans.1.Reading", 0.0)
	m.set(t, "/redfish/v1/Chassis/1U/Power", "Voltages.0.ReadingVolts", 0.0)
	res := run(t, m.bundle())
	mustFind(t, res, "redfish.power_off", model.Info)
	noFinding(t, res, "redfish.fan_failed")
	noFinding(t, res, "redfish.fan_warning")
	noFinding(t, res, "redfish.voltage_critical")
	noFinding(t, res, "redfish.voltage_warning")
	cov(t, res, "redfish.thermal", model.CovPartial)
}

func TestCoverageStates(t *testing.T) {
	m := loadMockup(t, "localstorage")
	b := m.bundle()
	// The account may not read memory (403) and the storage collection
	// failed with a server error.
	for _, s := range b.Sections {
		switch s.Name {
		case SectionPrefix + "/redfish/v1/Systems/437XR1138R2/Memory":
			s.RC, s.Out = 403, `{"error":{}}`
		case SectionPrefix + "/redfish/v1/Systems/437XR1138R2/Storage":
			s.RC, s.Out, s.Err = -1, "", "Get \"https://10.0.0.5/redfish/v1/Systems/437XR1138R2/Storage\": context deadline exceeded"
		}
	}
	res := run(t, b)
	c := cov(t, res, "redfish.memory", model.CovFailed)
	if !strings.Contains(c.Reason.EN, "403") || c.Fix.VI == "" {
		t.Errorf("memory coverage %+v", c)
	}
	c = cov(t, res, "redfish.storage", model.CovFailed)
	if !strings.Contains(c.Reason.EN, "deadline") {
		t.Errorf("storage coverage %+v", c)
	}
	cov(t, res, "redfish.thermal", model.CovRan)

	// One DIMM refused: partial.
	b = loadMockup(t, "localstorage").bundle()
	b.Get(SectionPrefix + "/redfish/v1/Systems/437XR1138R2/Memory/DIMM3").RC = 401
	res = run(t, b)
	cov(t, res, "redfish.memory", model.CovPartial)
}

func TestServiceRootFailed(t *testing.T) {
	b := testkit.Bundle(collect.OSBMC, &collect.Section{Name: SectionPrefix + "/redfish/v1", RC: -1, Err: "dial tcp 10.0.0.5:443: connect: connection refused"})
	res := run(t, b)
	c := cov(t, res, "redfish.service", model.CovFailed)
	if !strings.Contains(c.Reason.EN, "connection refused") {
		t.Errorf("reason %+v", c.Reason)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings %v", testkit.IDs(res))
	}
}

func TestNotARedfishBundle(t *testing.T) {
	for _, b := range []*collect.Bundle{
		testkit.Bundle(collect.OSLinux, testkit.S("disk.lsblk", "{}")),
		testkit.Bundle(collect.OSBMC, testkit.S("ipmi.sdr", "Fan1 | 30h | ok | 29.1 | 4200 RPM")),
		testkit.Bundle(collect.OSBMC),
	} {
		res := Check(b, collect.EnvOf(b))
		if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 || res.Facts != nil {
			t.Errorf("expected empty result, got %+v", res)
		}
	}
	if res := Check(nil, model.Env{}); res.Domain != domain {
		t.Error("nil bundle")
	}
}

// Truncated and garbage bodies must never panic and must keep the result
// valid.
func TestGarbageInput(t *testing.T) {
	for _, name := range []string{"localstorage", "rackmount1", "dell", "hpe"} {
		base := loadMockup(t, name).bundle()
		clone := func() *collect.Bundle {
			b := testkit.Bundle(collect.OSBMC)
			b.Options = base.Options
			for _, s := range base.Sections {
				cp := *s
				b.Add(&cp)
			}
			return b
		}
		for i := range base.Sections {
			for _, cut := range []int{0, 1, 7, 40, 200} {
				b := clone()
				s := b.Sections[i]
				if cut < len(s.Out) {
					s.Out = s.Out[:cut]
				}
				res := run(t, b)
				_ = HostInfo(b)
				_ = res
			}
		}
		// Wrong types everywhere.
		b := loadMockup(t, name).bundle()
		for _, s := range b.Sections {
			s.Out = strings.NewReplacer(`"OK"`, `5`, `"Enabled"`, `[]`, `"@odata.id": "`, `"@odata.id": "x`).Replace(s.Out)
		}
		run(t, b)
		b = loadMockup(t, name).bundle()
		for _, s := range b.Sections {
			s.Out = `{"Members":[1,"a",null,{"@odata.id":5}],"Status":"bad","Temperatures":"x","Fans":[null,{"Reading":"fast"}],"PowerSupplies":[{"LineInputVoltage":"n/a"}]}`
		}
		run(t, b)
	}
}

func TestHostInfoIPMIOnly(t *testing.T) {
	b := testkit.Bundle(collect.OSBMC,
		testkit.S("ipmi.fru", testkit.Read(t, "fru_dell_r640.txt")),
		testkit.S("ipmi.mc", testkit.Read(t, "mc_info_dell.txt")),
		testkit.S("ipmi.lan", testkit.Read(t, "lan_print_sample1.txt")),
		testkit.S("meta.bmc", "address=10.0.0.50\nprotocol=ipmi"),
	)
	b.Host = "10.0.0.50"
	h := HostInfo(b)
	if h.Vendor != "DELL" || h.Model != "PowerEdge R640" || h.Serial != "2RJF153" {
		t.Errorf("host %+v", h)
	}
	if !strings.Contains(h.BMC, "6.10") || !strings.Contains(h.BMC, "10.0.0.50") {
		t.Errorf("bmc %q", h.BMC)
	}
	if h := HostInfo(nil); h.Hostname != "" {
		t.Error("nil")
	}
	if h := HostInfo(testkit.Bundle(collect.OSBMC)); h.Hostname != "test-host" {
		t.Errorf("empty %+v", h)
	}
}

func TestStatusAndHelpers(t *testing.T) {
	if (Status{State: "Absent", Health: "Critical"}).Sev() != model.OK {
		t.Error("absent part has no health")
	}
	if (Status{State: "Disabled", Health: "Critical"}).Sev() != model.Crit {
		t.Error("a disabled failed DIMM is still failed")
	}
	if _, ok := parseTime("0000-00-00T00:00:00Z"); ok {
		t.Error("zero date accepted")
	}
	if tt, ok := parseTime("2026-09-30T22:14:05-05:00"); !ok || tt.UTC().Day() != 1 {
		t.Errorf("time %v", tt)
	}
	for in, want := range map[string]string{
		"/redfish/v1/Systems/1/":                                  "/redfish/v1/Systems/1",
		"https://10.0.0.5/redfish/v1/Chassis/1#/Fans/0":           "/redfish/v1/Chassis/1",
		"/redfish/v1/Managers/1/LogServices/IEL/Entries?$skip=50": "/redfish/v1/Managers/1/LogServices/IEL/Entries?$skip=50",
		"relative": "",
	} {
		if got := normKey(in); got != want {
			t.Errorf("normKey(%q) = %q, want %q", in, got, want)
		}
	}
	if eventComponent("The power input for power supply 2 is lost. PSU0003") != model.CompPower ||
		eventComponent("Correctable memory error rate exceeded for DIMM_A1") != model.CompMemory ||
		eventComponent("Something odd") != model.CompLogs {
		t.Error("eventComponent")
	}
}
