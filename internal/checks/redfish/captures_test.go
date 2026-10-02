package redfish

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// loadCapture reads testdata/captures/<name>.json: real BMC responses
// captured with the DMTF Redfish Mockup Creator (see SOURCES.md), stored as
// one JSON object {"/redfish/v1/...": resource} because several Dell paths
// contain ':' and cannot be file names on Windows.
func loadCapture(t testing.TB, name string) mockup {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "captures", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	m := mockup{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

// runAt analyses b as if it were collected at now (the capture dates are in
// 2023/2024; events are judged against the time of collection).
func runAt(t *testing.T, b *collect.Bundle, now time.Time) model.Result {
	t.Helper()
	env := collect.EnvOf(b)
	env.Now = now
	res := Check(b, env)
	testkit.Validate(t, res)
	return res
}

func allRan(t *testing.T, res model.Result) {
	t.Helper()
	for _, a := range areaDefs {
		cov(t, res, domain+"."+a.id, model.CovRan)
	}
}

// Dell PowerEdge R750, iDRAC9 6.00.30.00. Healthy. Its Lifecycle log holds a
// Critical "SecureBoot Certificate Export operation cannot be completed"
// (SWC9005, Category Configuration) logged a day before: a failed
// configuration job, not a hardware fault. Its three NVMe drives are also
// listed as "RawDevice" volumes, which are not RAID volumes.
func TestCaptureDellR750(t *testing.T) {
	m := loadCapture(t, "dell")
	b := m.bundle()
	res := runAt(t, b, time.Date(2024, 8, 9, 12, 0, 0, 0, time.UTC))
	allRan(t, res)
	if w := worst(res); w != model.OK {
		t.Errorf("healthy R750 rated %s: %v", w, testkit.IDs(res))
	}
	noFinding(t, res, "redfish.event_critical")
	f := mustFind(t, res, "redfish.storage_ok", model.OK)
	if f.Title.EN != "3 drives are healthy" || f.Title.VI != "3 ổ cứng đều bình thường" {
		t.Errorf("storage_ok title %+v", f.Title)
	}
	mustFind(t, res, "redfish.logs_ok", model.OK)
	facts := res.Facts.(*Facts)
	if len(facts.Volumes) != 0 || len(facts.Drives) != 3 || len(facts.DIMMs) != 16 || len(facts.PSUs) != 2 || len(facts.Fans) != 6 {
		t.Errorf("inventory: %d volumes, %d drives, %d DIMMs, %d PSUs, %d fans", len(facts.Volumes), len(facts.Drives), len(facts.DIMMs), len(facts.PSUs), len(facts.Fans))
	}
	h := HostInfo(b)
	if h.Vendor != "Dell Inc." || h.Model != "PowerEdge R750" || h.Serial != "F54P1G3" || h.Board != "PowerEdge R750" || !strings.Contains(h.BMC, "6.00.30.00") {
		t.Errorf("host %+v", h)
	}
}

// HPE ProLiant DL385 Gen10 Plus v2, iLO 5 2.72. One NVMe SSD (Box 2:Bay 5,
// serial S6C1NA0TA04209) is Critical with FailurePredicted: a real failure.
// iLO lists it again as its own "NVMe Storage Controller" (same serial),
// and lists the Smart Array drives and RAID 1 in both Storage and the Oem
// SmartStorage tree.
func TestCaptureHPEDL385(t *testing.T) {
	m := loadCapture(t, "hpe")
	b := m.bundle()
	res := runAt(t, b, time.Date(2024, 8, 16, 12, 0, 0, 0, time.UTC))
	allRan(t, res)
	f := mustFind(t, res, "redfish.drive_failed", model.Crit, "Box 2:Bay 5")
	if f.Part == nil || f.Part.Serial != "S6C1NA0TA04209" || f.Part.Model != "MZXLR6T4HALA-000H3" || f.Part.Kind != "disk" {
		t.Errorf("part %+v", f.Part)
	}
	noFinding(t, res, "redfish.controller_failed")
	// The rollup (system Critical) is explained by the drive.
	noFinding(t, res, "redfish.system_health")
	facts := res.Facts.(*Facts)
	if len(facts.Drives) != 18 || len(facts.Volumes) != 1 {
		t.Errorf("drives %d (want 18, no SmartStorage duplicates), volumes %d (want 1)", len(facts.Drives), len(facts.Volumes))
	}
	// Security-state and login events are not hardware; the reset event
	// from the "Event" log has no Message and is named from its MessageId.
	for _, g := range facts.Events {
		if strings.Contains(g.MessageID, "SecState") || strings.Contains(g.Message, "login") {
			t.Errorf("non-hardware event kept: %+v", g)
		}
		if g.MessageID == "iLOEvents.3.7.ServerResetDetected" && g.Message != "Server Reset Detected" {
			t.Errorf("message %q", g.Message)
		}
	}
	h := HostInfo(b)
	if h.Vendor != "HPE" || h.Serial != "MXQ302099S" || h.BMC != "iLO 5 v2.72 (test-host)" {
		t.Errorf("host %+v", h)
	}
}

// Lenovo ThinkSystem SR670 V2, XClarity Controller 2.83. Healthy; four
// direct-attached NVMe drives and no RAID volume. Its audit and maintenance
// logs are not hardware logs.
func TestCaptureLenovoSR670(t *testing.T) {
	m := loadCapture(t, "lenovo")
	b := m.bundle()
	res := runAt(t, b, time.Date(2024, 8, 3, 12, 0, 0, 0, time.UTC))
	allRan(t, res)
	if w := worst(res); w != model.OK {
		t.Errorf("healthy SR670 rated %s: %v", w, testkit.IDs(res))
	}
	if f := mustFind(t, res, "redfish.storage_ok", model.OK); f.Title.EN != "4 drives are healthy" {
		t.Errorf("title %q", f.Title.EN)
	}
	s := newStore(b)
	w := &walker{s: s, f: &Facts{}, areas: map[string]*area{"logs": {}}}
	w.logServices("/redfish/v1/Systems/1/LogServices")
	var ids []string
	for _, l := range w.logs {
		ids = append(ids, l.id)
	}
	// AuditLog, MaintenanceLog and DiagnosticLog are skipped; this XCC's SEL
	// service has no Entries link.
	if got := strings.Join(ids, ","); got != "PlatformLog,ActiveLog,SaLog" {
		t.Errorf("logs read %s", got)
	}
	h := HostInfo(b)
	if h.Vendor != "Lenovo" || h.Serial != "J105958B" || h.Hostname != "XCC-7Z23-J105958B" {
		t.Errorf("host %+v", h)
	}
}

// Supermicro SYS-821GE-TNHR (X13DEG-OAD), BMC 11.01.01. Healthy now. Both
// of its logs are called "Log1": the maintenance log (logins, account
// changes) must be skipped, the health event log read. PS1 lost input on
// 2023-10-11 and the SEL "Deassert" seven seconds later ends it; PS2, PS3
// and PS5 lost input the day before and were never deasserted.
func TestCaptureSupermicroX13(t *testing.T) {
	m := loadCapture(t, "supermicro")
	b := m.bundle()
	res := runAt(t, b, time.Date(2023, 10, 12, 12, 0, 0, 0, time.UTC))
	allRan(t, res)
	facts := res.Facts.(*Facts)
	var ps1, ps2 *EventGroup
	for i, g := range facts.Events {
		if strings.Contains(g.Message, "Maintenance") || strings.Contains(g.Message, "attempted to access") {
			t.Errorf("maintenance log entry kept: %+v", g)
		}
		if strings.Contains(g.Message, "PS1 Status, Power Supply input lost") {
			ps1 = &facts.Events[i]
		}
		if strings.Contains(g.Message, "PS2 Status, Power Supply input lost") {
			ps2 = &facts.Events[i]
		}
	}
	if ps1 == nil || !ps1.Cleared || ps1.Severity != model.Info {
		t.Errorf("PS1 deasserted event: %+v", ps1)
	}
	if ps2 == nil || ps2.Cleared || ps2.Severity != model.Crit || ps2.Component != model.CompPower {
		t.Errorf("PS2 event: %+v", ps2)
	}
	// A month later, with only root-of-trust and "First AC Power on"
	// warnings in the last week, nothing is raised.
	res = runAt(t, b, time.Date(2023, 12, 1, 12, 0, 0, 0, time.UTC))
	if w := worst(res); w > model.Info {
		t.Errorf("healthy X13 rated %s: %v", w, testkit.IDs(res))
	}
	h := HostInfo(b)
	if h.Vendor != "Supermicro" || h.Model != "SYS-821GE-TNHR" || h.Board != "X13DEG-OAD" || h.Serial != "S889914X3710910" {
		t.Errorf("host %+v", h)
	}
}

// HPE iLO 4 reports fan speed as CurrentReading/Units (telegraf testdata).
func TestILO4FanCurrentReading(t *testing.T) {
	m := loadMockup(t, "hpe")
	thermal := "/redfish/v1/Chassis/1/Thermal"
	m[thermal]["Fans"] = []any{map[string]any{"CurrentReading": 17.0, "FanName": "Fan 1", "Units": "Percent", "Status": map[string]any{"Health": "OK", "State": "Enabled"}}}
	res := run(t, m.bundle())
	facts := res.Facts.(*Facts)
	if len(facts.Fans) != 1 || facts.Fans[0].Name != "Fan 1" || facts.Fans[0].Reading == nil || *facts.Fans[0].Reading != 17 || facts.Fans[0].Units != "Percent" {
		t.Errorf("fans %+v", facts.Fans)
	}
	noFinding(t, res, "redfish.fan_failed")
}

// Placeholder serials ("To be filled by O.E.M.", Supermicro "0123456789")
// are not serial numbers.
func TestHostInfoPlaceholders(t *testing.T) {
	m := loadCapture(t, "supermicro")
	m.set(t, "/redfish/v1/Systems/1", "SerialNumber", "0123456789")
	m.set(t, "/redfish/v1/Systems/1", "Manufacturer", "To be filled by O.E.M.")
	h := HostInfo(m.bundle())
	if h.Serial != "C8010MM21A30331" || h.Vendor != "Supermicro" {
		t.Errorf("host %+v (want the chassis serial and vendor)", h)
	}
}

// An HDD that reports 0 % life left (no flash) is not worn out; 0 V on a
// rail the BMC rates OK is "no reading".
func TestNoFalseWearOrVoltage(t *testing.T) {
	m := loadMockup(t, "localstorage")
	b := m.bundle()
	res := run(t, b)
	facts := res.Facts.(*Facts)
	var hdd string
	for _, d := range facts.Drives {
		if strings.EqualFold(d.MediaType, "HDD") {
			hdd = d.ref
		}
	}
	if hdd == "" {
		t.Skip("mockup has no HDD")
	}
	m.set(t, hdd, "PredictedMediaLifeLeftPercent", 0.0)
	res = run(t, m.bundle())
	noFinding(t, res, "redfish.ssd_wear")

	v := Voltage{Name: "CPU2 VCORE", Reading: new(float64), LowerCrit: ptr(0.6), UpperCrit: ptr(1.5), Status: Status{State: "Enabled", Health: "OK"}}
	if sev, _ := voltSev(v, false); sev != model.OK {
		t.Errorf("0 V with health OK: %s", sev)
	}
	v.Status.Health = "Critical"
	if sev, _ := voltSev(v, false); sev != model.Crit {
		t.Errorf("0 V with health Critical: %s", sev)
	}
}

func ptr(f float64) *float64 { return &f }

// A log with only dump/diagnostic services, or a chassis without Thermal,
// must not be reported as checked.
func TestCoverageNoData(t *testing.T) {
	m := loadMockup(t, "dell")
	delete(m, "/redfish/v1/Chassis/System.Embedded.1/Thermal")
	m.set(t, "/redfish/v1/Chassis/System.Embedded.1", "Thermal", nil)
	res := run(t, m.bundle())
	c := cov(t, res, "redfish.thermal", model.CovSkipped)
	if c.Cmd != "diagward bmc test-host --protocol ipmi" || c.Fix.EN == "" || strings.Contains(c.Fix.EN, "diagward") {
		t.Errorf("fix %q cmd %q", c.Fix.EN, c.Cmd)
	}
	noFinding(t, res, "redfish.thermal_ok")
}

// Non-hardware entries and deasserted SEL events.
func TestEntryClassification(t *testing.T) {
	for _, c := range []struct {
		in    string
		nonHW bool
	}{
		{`{"Oem":{"Dell":{"Category":"Audit"}},"Severity":"Warning","Message":"Login failed"}`, true},
		{`{"Oem":{"Dell":{"Category":"System Health"}},"Severity":"Critical","Message":"PSU lost"}`, false},
		{`{"Oem":{"Hpe":{"Categories":["Security","Administration","Configuration"]}},"Severity":"Warning"}`, true},
		{`{"Oem":{"Hpe":{"Categories":["Power"]}},"Severity":"Warning"}`, false},
		{`{"Oem":{"Hpe":{"Categories":["Configuration"]}},"Severity":"Warning"}`, false},
		{`{"Links":{"OriginOfCondition":{"@odata.id":"/redfish/v1/Managers/1/SecurityService/SecurityDashboard"}},"Severity":"Warning"}`, true},
		{`{"OemSensorType":"PFR (RoT)","Severity":"Warning"}`, true},
		{`{"Severity":"Critical","Message":"Fan 1 failed"}`, false},
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.in), &m); err != nil {
			t.Fatal(err)
		}
		if e := entryOf(m); e.nonHW != c.nonHW {
			t.Errorf("%s: nonHW %v", c.in, e.nonHW)
		}
	}
	if !entryOf(map[string]any{"EntryCode": "Deassert"}).deassert {
		t.Error("deassert")
	}
	if messageFromID("7e012790") != "" || messageFromID("Event.1.0.AttemptConnect") != "Attempt Connect" {
		t.Error("messageFromID")
	}
}

// HPE ProLiant ML350 Gen9, iLO 4 2.77 (real captures, see SOURCES.md): the
// pre-1.0 schema. Memory is linked only under Oem.Hp.links and uses the
// HpMemory schema (SizeMB, DIMMStatus, no Status); Processors only under
// "links"; IML pages are chained by links.NextPage ("?page=N") with the
// entries in Items and links only in Members; Oem is "Hp", not "Hpe". The
// Smart Storage Battery has failed (Oem.Hp.Battery Condition "Failed"),
// which only shows in the system's Oem block.
func TestCaptureILO4(t *testing.T) {
	m := loadCapture(t, "ilo4")
	page6, _ := json.Marshal(m["/redfish/v1/Systems/1/LogServices/IML/Entries?page=6"])
	b := m.bundle()
	// The capture has pages 1, 2 and 6 of the IML; the collector would
	// chain 2 → 3 → ...; page 6 is added as if collected.
	b.Add(&collect.Section{Name: SectionPrefix + "/redfish/v1/Systems/1/LogServices/IML/Entries?page=6", RC: 200, Out: string(page6)})
	res := runAt(t, b, time.Date(2026, 9, 11, 15, 0, 0, 0, time.UTC))
	facts := res.Facts.(*Facts)
	if len(facts.DIMMs) != 2 || facts.DIMMs[0].Slot != "PROC 1 DIMM 1" || facts.DIMMs[0].CapacityMiB != 16384 || facts.DIMMs[0].Status.Health != "OK" {
		t.Errorf("iLO 4 DIMMs %+v", facts.DIMMs)
	}
	if len(facts.CPUs) != 1 || len(facts.PSUs) != 2 || facts.PSUs[0].Name != "Power Supply Bay 1" || facts.PSUs[1].Name != "Power Supply Bay 2" {
		t.Errorf("cpus %+v psus %+v", facts.CPUs, facts.PSUs)
	}
	nfans := 0
	for _, f := range facts.Fans {
		if !f.Status.Absent() {
			nfans++
			if f.Reading == nil || f.Units != "Percent" {
				t.Errorf("fan %+v", f)
			}
		}
	}
	if nfans != 3 {
		t.Errorf("%d fans present, want 3", nfans)
	}
	f := mustFind(t, res, "redfish.storage_battery", model.Warn)
	if f.Part == nil || f.Part.Model != "727258-B21" || f.Part.Serial != "6EZBN0CWY9ITDR" || !strings.Contains(f.Action.EN, "815983-001") {
		t.Errorf("battery finding %+v %+v", f, f.Part)
	}
	noFinding(t, res, "redfish.system_health") // the Warning rollup is the battery
	// The battery failure logged on 2026-09-10 (page 6, Oem.Hp) is current.
	var bat *EventGroup
	for i, g := range facts.Events {
		if strings.Contains(g.Message, "Smart Storage Battery failure") {
			bat = &facts.Events[i]
		}
	}
	if bat == nil || bat.Severity < model.Warn || !strings.HasPrefix(bat.MessageID, "HPE-") {
		t.Errorf("battery IML event %+v", bat)
	}
	// Entries without Created (15 on this iLO) use Oem.Hp.Updated.
	for _, g := range facts.Events {
		if g.Unknown {
			t.Errorf("event without time: %+v", g)
		}
	}
	h := HostInfo(b)
	if h.Vendor != "HPE" || h.Model != "ProLiant ML350 Gen9" || h.Serial != "CZ255205TJ" || h.MemBytes != 80<<30 {
		t.Errorf("host %+v", h)
	}
}

// The same iLO 4 powered off, with the Smart Array tree: eight healthy
// HDDs, no logical drive, the battery failed; thresholds of 0 are "none".
func TestCaptureILO4Degraded(t *testing.T) {
	res := runAt(t, loadCapture(t, "ilo4-degraded").bundle(), time.Date(2026, 9, 11, 3, 0, 0, 0, time.UTC))
	facts := res.Facts.(*Facts)
	if len(facts.Drives) != 8 || len(facts.Volumes) != 0 || len(facts.Controllers) != 1 {
		t.Errorf("drives %d volumes %d controllers %d", len(facts.Drives), len(facts.Volumes), len(facts.Controllers))
	}
	mustFind(t, res, "redfish.storage_battery", model.Warn)
	mustFind(t, res, "redfish.power_off", model.Info)
	noFinding(t, res, "redfish.psu_no_input") // 0 V on both PSUs of a server that is off
	cov(t, res, "redfish.thermal", model.CovPartial)
	for _, r := range table(t, res, "redfish.temperatures").Rows {
		if r.Cells[0] == "10-P/S 1" && r.Cells[3] != "-" {
			t.Errorf("threshold 0 shown as %q", r.Cells[3])
		}
	}
}

func TestRerunCmds(t *testing.T) {
	b := testkit.Bundle(collect.OSBMC)
	for host, want := range map[string]string{
		"10.0.0.5":                 "diagward bmc 10.0.0.5 --protocol ipmi",
		"https://[fe80::1%25eth0]": "diagward bmc https://[fe80::1%25eth0] --protocol ipmi",
		"bmc.example; rm -rf /":    "",
		"$(id)":                    "",
	} {
		b.Host = host
		if got, _ := rerunCmds(b); got != want {
			t.Errorf("%q: %q, want %q", host, got, want)
		}
	}
}
