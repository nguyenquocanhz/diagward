package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func TestStorcliHealthy(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_praid_ep420i.json")),
		testkit.S("raid.storcli_vd", testkit.Read(t, "storcli_vd_praid.json")),
		testkit.S("raid.storcli_pd", testkit.Read(t, "storcli_pd_praid_ep420i.json")),
		testkit.S("raid.storcli_rebuild", ""),
		testkit.S("raid.storcli_bbu", ""),
		testkit.S("raid.storcli_cv", ""))
	noWorseThan(t, res, model.OK)
	ok := want(t, res, "raid.hw_ok", "", model.OK)
	if !strings.Contains(ok.Title.EN, "PRAID EP420i") || !strings.Contains(ok.Title.EN, "1 volumes, 4 disks") {
		t.Errorf("ok: %q", ok.Title.EN)
	}
	cov(t, res, "raid.hw", model.CovRan)
	ct := res.Facts.(*Facts).Controllers[0]
	if ct.Serial != "0000000061913681" || ct.Firmware != "24.21.0-0076" || ct.Battery != "Optimal" || ct.BatteryModel != "CVPM02" {
		t.Errorf("controller: %+v", ct)
	}
	if len(ct.Volumes) != 1 || ct.Volumes[0].Level != "RAID6" || len(ct.Volumes[0].Members) != 4 {
		t.Errorf("volumes: %+v", ct.Volumes)
	}
	d := ct.Drives[0]
	if d.ID != "252:0" || d.Serial != "20032656D641" || d.Model != "Micron_5200_MTFDDAK960TDC" || d.MediaErr != 0 || d.Location != "Enclosure 252 Slot 0" {
		t.Errorf("drive: %+v", d)
	}
	if tb := table(t, res, "raid.hw_drives"); len(tb.Rows) != 4 || tb.Rows[0].Cells[6] != "0" {
		t.Errorf("drive table: %+v", tb.Rows)
	}
	table(t, res, "raid.controllers")
}

func TestStorcliM5015AndHBA(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_m5015.json")),
		testkit.S("raid.storcli_pd", testkit.Read(t, "storcli_pd_m5015.json")))
	noWorseThan(t, res, model.OK)
	ct := res.Facts.(*Facts).Controllers[0]
	if ct.BatteryModel != "iBBU08" || ct.Battery != "Optimal" || len(ct.Drives) != 6 || ct.Drives[0].Serial != "ZL2PVFA8" {
		t.Errorf("m5015: %+v drives=%d %+v", ct, len(ct.Drives), ct.Drives[0])
	}
	res = run(t, collect.OSLinux, testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_hba9500.json")))
	noWorseThan(t, res, model.OK)
	if ct := res.Facts.(*Facts).Controllers[0]; ct.Model != "HBA 9500-8i" || ct.Status != "OK" {
		t.Errorf("hba: %+v", ct)
	}
}

func TestStorcliDegraded(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_degraded.json")),
		testkit.S("raid.storcli_pd", testkit.Read(t, "storcli_pd_praid_ep420i.json")))
	label := "Controller 0 (PRAID EP420i)"
	vd := want(t, res, "raid.hw_vd_degraded", label+" v0", model.Crit)
	if vd.Part == nil || vd.Part.Location != label+", Enclosure 252 Slot 5" {
		t.Errorf("vd part: %+v", vd.Part)
	}
	pd := want(t, res, "raid.hw_pd_failed", label+" Enclosure 252 Slot 5", model.Crit)
	if pd.Part == nil || pd.Part.Model != "Micron_5200_MTFDDAK960TDC" || pd.Part.Serial == "" {
		t.Errorf("pd part: %+v", pd.Part)
	}
	// "Needs Attention" alone is a warning, not a critical alarm.
	want(t, res, "raid.hw_ctrl_status", label, model.Warn)
	none(t, res, "raid.hw_ok")
}

func TestStorcliRebuildAndBattery(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_rebuild.json")),
		testkit.S("raid.storcli_rebuild", testkit.Read(t, "storcli_rebuild.json")),
		testkit.S("raid.storcli_cv", testkit.Read(t, "storcli_cv_failed.json")))
	label := "Controller 0 (PRAID EP420i)"
	f := want(t, res, "raid.hw_vd_rebuilding", label+" v0", model.Warn)
	if !strings.Contains(f.Title.EN, "36%") || !strings.Contains(f.Title.EN, "1 Hours 13 Minutes") {
		t.Errorf("title: %q", f.Title.EN)
	}
	none(t, res, "raid.hw_vd_degraded", "raid.hw_pd_rebuilding")
	b := want(t, res, "raid.hw_battery", label, model.Warn)
	if !strings.Contains(b.Title.EN, "Replacement required") || b.Part == nil || b.Part.Kind != "battery" || b.Part.Model != "CVPM02" {
		t.Errorf("battery: %q %+v", b.Title.EN, b.Part)
	}
}

func TestStorcliDriveErrors(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_praid_ep420i.json")),
		testkit.S("raid.storcli_pd", testkit.Read(t, "storcli_pd_errors.json")))
	label := "Controller 0 (PRAID EP420i)"
	m := want(t, res, "raid.hw_pd_media_errors", label+" Enclosure 252 Slot 0", model.Warn)
	if m.Part == nil || m.Part.Serial != "20032656D641" {
		t.Errorf("part: %+v", m.Part)
	}
	p := want(t, res, "raid.hw_pd_predictive", label+" Enclosure 252 Slot 1", model.Crit)
	if p.Part == nil || p.Part.Serial != "20032656D63C" {
		t.Errorf("part: %+v", p.Part)
	}
}

func TestPerccliSameParserAndDedup(t *testing.T) {
	ctrl := testkit.Read(t, "storcli_ctrl_praid_ep420i.json")
	res := run(t, collect.OSLinux, testkit.S("raid.storcli_ctrl", ctrl), testkit.S("raid.perccli_ctrl", ctrl))
	if n := len(res.Facts.(*Facts).Controllers); n != 1 {
		t.Errorf("the same controller seen by storcli and perccli must be reported once, got %d", n)
	}
	res = run(t, collect.OSWindows, testkit.S("raid.perccli_ctrl", testkit.Read(t, "storcli_ctrl_degraded.json")))
	if ct := res.Facts.(*Facts).Controllers[0]; ct.Tool != "perccli" {
		t.Errorf("tool: %s", ct.Tool)
	}
	want(t, res, "raid.hw_vd_degraded", "Controller 0 (PRAID EP420i) v0", model.Crit)
}

func TestStorcliFailureStatus(t *testing.T) {
	js := `{"Controllers":[{"Command Status":{"Controller":0,"Status":"Failure","Description":"Un-supported command"}}]}`
	res := run(t, collect.OSLinux, testkit.RC("raid.storcli_ctrl", 1, js, ""))
	c := cov(t, res, "raid.hw", model.CovFailed)
	if !strings.Contains(c.Reason.EN, "Un-supported command") {
		t.Errorf("reason: %q", c.Reason.EN)
	}
	// No controller at all: silent.
	js = `{"Controllers":[{"Command Status":{"Controller":0,"Status":"Failure","Description":"Controller 0 not found"}}]}`
	res = run(t, collect.OSLinux, testkit.RC("raid.storcli_ctrl", 0, js, ""))
	if len(res.Coverage)+len(res.Findings) != 0 {
		t.Errorf("expected silence, got %v %+v", testkit.IDs(res), res.Coverage)
	}
}

func TestSsacliHealthyFixtures(t *testing.T) {
	for _, f := range []string{"ssacli-P212_P410i.txt", "ssacli-P400ar.txt", "ssacli-P408i-a.txt"} {
		res := run(t, collect.OSLinux, testkit.S("raid.ssacli_config", testkit.Read(t, f)))
		noWorseThan(t, res, model.Info)
		want(t, res, "raid.hw_ok", "", model.OK)
		cts := res.Facts.(*Facts).Controllers
		if len(cts) == 0 || len(cts[0].Volumes) == 0 || len(cts[0].Drives) == 0 {
			t.Errorf("%s: parsed %+v", f, cts)
		}
	}
	res := run(t, collect.OSLinux, testkit.S("raid.ssacli_config", testkit.Read(t, "ssacli-P212_P410i.txt")))
	cts := res.Facts.(*Facts).Controllers
	if len(cts) != 2 || cts[0].Model != "Smart Array P212" || cts[1].ID != "Slot 0" || len(cts[0].Drives) != 12 || cts[0].Volumes[0].Level != "RAID 5" {
		t.Errorf("P212/P410i: %d controllers %+v", len(cts), cts[0])
	}
	if d := cts[0].Drives[0]; d.ID != "2E:1:1" || d.Model != "MB1000EBZQB" || d.Vendor != "ATA" || d.State != "OK" {
		t.Errorf("drive: %+v", d)
	}
	res = run(t, collect.OSLinux, testkit.S("raid.ssacli_config", testkit.Read(t, "ssacli-P400i-unassigned.txt")))
	want(t, res, "raid.hw_spares", "", model.Info)
	// This real P400i output has a failed battery and the cache disabled.
	want(t, res, "raid.hw_battery", "Slot 0 (Smart Array P400i)", model.Warn)
	none(t, res, "raid.hw_cache")
}

func TestSsacliFailed(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.ssacli_config", testkit.Read(t, "ssacli-P440ar-failed.txt")),
		testkit.S("raid.ssacli_status", testkit.Read(t, "ssacli-status-failed.txt")))
	label := "Slot 0 (Smart Array P440ar)"
	want(t, res, "raid.hw_vd_degraded", label+" LD 1", model.Crit)
	want(t, res, "raid.hw_pd_failed", label+" port 1I:box 1:bay 2", model.Crit)
	want(t, res, "raid.hw_pd_predictive", label+" port 2I:box 1:bay 6", model.Crit)
	b := want(t, res, "raid.hw_battery", label, model.Warn)
	// The cache is disabled because of the battery: one finding, not two.
	if !strings.Contains(b.Detail.EN, "Temporarily Disabled") {
		t.Errorf("battery detail should mention the cache state: %q", b.Detail.EN)
	}
	none(t, res, "raid.hw_cache")
}

func TestSsacliRecovering(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.ssacli_config", testkit.Read(t, "ssacli-config-recovering.txt")))
	f := want(t, res, "raid.hw_vd_rebuilding", "Slot 0 (Smart Array P410i) LD 1", model.Warn)
	if !strings.Contains(f.Title.EN, "26%") {
		t.Errorf("title: %q", f.Title.EN)
	}
	none(t, res, "raid.hw_vd_degraded", "raid.hw_pd_failed")
	want(t, res, "raid.hw_spares", "", model.Info) // unassigned 1I:1:3
}

func TestArcconf(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.arcconf_list", "Controllers found: 1\n"), testkit.S("raid.arcconf:1", testkit.Read(t, "arcconf-getconfig-al-synth.txt")))
	noWorseThan(t, res, model.OK)
	ct := res.Facts.(*Facts).Controllers[0]
	if ct.Model != "Adaptec ASR8805" || ct.Status != "Optimal" || len(ct.Volumes) != 1 || len(ct.Drives) != 4 || ct.Volumes[0].Level != "RAID 10" {
		t.Errorf("arcconf: %+v", ct)
	}
	if ct.Volumes[0].Members[0] != "Device #0" || ct.Drives[0].Serial != "7CS009RP" {
		t.Errorf("members %v drive %+v", ct.Volumes[0].Members, ct.Drives[0])
	}

	res = run(t, collect.OSLinux, testkit.S("raid.arcconf:1", testkit.Read(t, "arcconf-getconfig-al-degraded.txt")))
	label := "Controller 1 (Adaptec ASR8805)"
	want(t, res, "raid.hw_vd_degraded", label+" LD 0", model.Crit)
	f := want(t, res, "raid.hw_pd_failed", label+" Connector 0, Device 1", model.Crit)
	if f.Part == nil || f.Part.Serial != "7CS009RQ" {
		t.Errorf("part: %+v", f.Part)
	}
	want(t, res, "raid.hw_pd_smart_warnings", label+" Connector 0, Device 2", model.Warn)
	want(t, res, "raid.hw_battery", label, model.Warn)
	none(t, res, "raid.hw_ctrl_status") // Controller Status stays Optimal

	// Real netdata fragments (LD-only / PD-only outputs) parse too.
	for _, f := range []string{"arcconf-getconfig-ld-current.txt", "arcconf-getconfig-pd-with-enclosure.txt", "arcconf-getconfig-pd-current.txt"} {
		res = run(t, collect.OSLinux, testkit.S("raid.arcconf:1", testkit.Read(t, f)))
		noWorseThan(t, res, model.Info) // pd-with-enclosure has two Global Hot-Spares
	}
}

func TestMegaCli(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.megacli_ld", testkit.Read(t, "megacli-ldpdinfo.txt")),
		testkit.S("raid.megacli_pd", testkit.Read(t, "megacli-ldpdinfo.txt")),
		testkit.S("raid.megacli_bbu", testkit.Read(t, "megacli-bbu-recent.txt")))
	noWorseThan(t, res, model.OK)
	ct := res.Facts.(*Facts).Controllers[0]
	if len(ct.Volumes) != 1 || ct.Volumes[0].Level != "RAID1" || ct.Volumes[0].State != "Optimal" || ct.Battery != "Optimal" || ct.BatteryModel != "iBBU08" {
		t.Errorf("megacli: %+v %+v", ct, ct.Volumes)
	}
	d := ct.Drives[0]
	if d.ID != "32:0" || d.Serial != "S1YHNXAG804005" || d.Model != "SAMSUNG MZ7LM960HCHP-00003" || d.Firmware != "GXT3003Q" || d.Group != "0" {
		t.Errorf("drive: %+v", d)
	}

	res = run(t, collect.OSLinux,
		testkit.S("raid.megacli_pd", testkit.Read(t, "megacli-ldpdinfo-degraded.txt")),
		testkit.S("raid.megacli_bbu", testkit.Read(t, "megacli-bbu-degraded.txt")))
	label := "Controller 0"
	want(t, res, "raid.hw_vd_degraded", label+" v0", model.Crit)
	f := want(t, res, "raid.hw_pd_failed", label+" Enclosure 32 Slot 2", model.Crit)
	if f.Part == nil || f.Part.Serial != "S1YHNYAG600061" {
		t.Errorf("part: %+v", f.Part)
	}
	want(t, res, "raid.hw_pd_media_errors", label+" Enclosure 32 Slot 1", model.Warn)
	want(t, res, "raid.hw_pd_predictive", label+" Enclosure 32 Slot 3", model.Crit)
	want(t, res, "raid.hw_battery", label, model.Warn)
}

func TestMcInquirySAS(t *testing.T) {
	v, m, s, f := mcInquiry("SEAGATE ST600MM0006     LS0AS0M1ABCD", "SAS")
	if v != "SEAGATE" || m != "ST600MM0006" || f != "LS0A" || s != "S0M1ABCD" {
		t.Errorf("got %q %q %q %q", v, m, s, f)
	}
}

func TestDetectMissingCLI(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.pci", testkit.Read(t, "pci_perc_hba.txt")))
	f := want(t, res, "raid.hw_cli_missing", "", model.Info)
	if !strings.Contains(f.Title.EN, "PERC H730P Mini") || !strings.Contains(f.Title.EN, "perccli") || !strings.Contains(f.Action.EN, "dell.com") {
		t.Errorf("finding: %q / %q", f.Title.EN, f.Action.EN)
	}
	c := cov(t, res, "raid.hw", model.CovSkipped)
	if !strings.Contains(c.Fix.VI, "perccli") {
		t.Errorf("fix: %q", c.Fix.VI)
	}
	det := res.Facts.(*Facts).Detected
	if len(det) != 1 {
		t.Errorf("HBA330 (mpt3sas) and PVSCSI must not be treated as RAID controllers: %+v", det)
	}

	res = run(t, collect.OSLinux, testkit.S("raid.pci", testkit.Read(t, "pci_smartarray.txt")))
	f = want(t, res, "raid.hw_cli_missing", "", model.Info)
	if !strings.Contains(f.Title.EN, "ssacli") {
		t.Errorf("title: %q", f.Title.EN)
	}

	// Controller detected and its CLI ran: covered.
	res = run(t, collect.OSLinux, testkit.S("raid.pci", testkit.Read(t, "pci_perc_hba.txt")), testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_praid_ep420i.json")))
	none(t, res, "raid.hw_cli_missing")
	cov(t, res, "raid.hw", model.CovRan)
}

func TestClassifyController(t *testing.T) {
	cases := []struct{ vendor, sub, class, drv, name, want string }{
		{"0x1000", "0x1028", "0x010400", "megaraid_sas", "", "perccli"},
		{"0x1000", "0x1734", "0x010400", "megaraid_sas", "", "storcli"},
		{"0x1000", "0x1028", "0x010700", "mpt3sas", "HBA330", ""},
		{"0x103c", "0x103c", "0x010400", "hpsa", "", "ssacli"},
		{"0x9005", "0x1590", "0x010700", "smartpqi", "", "ssacli"},
		{"0x9005", "0x9005", "0x010700", "smartpqi", "", "arcconf"},
		{"0x9005", "0x9005", "0x010400", "aacraid", "", "arcconf"},
		{"0x8086", "", "0x010400", "ahci", "", ""},
		{"1028", "", "", "megasr", "PERC S140", ""},
		{"8086", "1025", "", "iaStorAC", "Intel(R) Chipset SATA/PCIe RST Premium Controller", ""},
		{"1000", "1028", "", "percsas3i", "PERC H740P Mini", "perccli"},
		{"103c", "", "", "HpCISSs3", "HPE Smart Array P408i-a SR Gen10", "ssacli"},
	}
	for _, c := range cases {
		if got := classifyController(c.vendor, c.sub, c.class, c.drv, c.name); got != c.want {
			t.Errorf("%+v: got %q", c, got)
		}
	}
}
