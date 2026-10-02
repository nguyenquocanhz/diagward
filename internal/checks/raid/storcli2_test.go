package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// Real StorCLI2 8.5 output of a MegaRAID 9660-16i (mpi3mr) with 24 single
// drive RAID0 volumes: everything healthy.
func TestStorcli2Healthy(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660.json")),
		testkit.S("raid.storcli2_vd", testkit.Read(t, "storcli2_vd_9660.json")),
		testkit.S("raid.storcli2_pd", testkit.Read(t, "storcli2_pd_9660.json")),
		testkit.S("raid.storcli2_rebuild", ""),
		testkit.S("raid.storcli2_ep", ""))
	noWorseThan(t, res, model.OK)
	ok := want(t, res, "raid.hw_ok", "", model.OK)
	if !strings.Contains(ok.Title.EN, "MegaRAID 9660-16i") || !strings.Contains(ok.Title.EN, "24 volumes, 24 disks") {
		t.Errorf("ok: %q", ok.Title.EN)
	}
	cov(t, res, "raid.hw", model.CovRan)
	ct := res.Facts.(*Facts).Controllers[0]
	if ct.Tool != "storcli2" || ct.ID != "0" || ct.Serial != "SPE4912106" || ct.Firmware != "8.12.1.0-00000-00003" || ct.Status != "Optimal" {
		t.Errorf("controller: %+v", ct)
	}
	if ct.Battery != "Optimal" || ct.BatteryModel != "Supercap FBU345" {
		t.Errorf("energy pack: %q %q", ct.Battery, ct.BatteryModel)
	}
	if len(ct.Volumes) != 24 || ct.Volumes[0].ID != "v1" || ct.Volumes[0].Level != "RAID0" || len(ct.Volumes[0].Members) != 1 || ct.Volumes[0].Members[0] != "306:0" {
		t.Errorf("volumes: %d %+v", len(ct.Volumes), ct.Volumes[0])
	}
	d := ct.Drives[0]
	if d.ID != "306:0" || d.Serial != "WP00MLCA0000E2426EZU" || d.Model != "ST10000NM018B" || d.Vendor != "SEAGATE" ||
		d.Firmware != "E001" || d.MediaErr != 0 || d.OtherErr != 0 || d.PredFail != 0 || d.Class != stOK || d.State != "Conf, Online" ||
		d.Location != "Enclosure 306 Slot 0" || d.Group != "0" {
		t.Errorf("drive: %+v", d)
	}
	tb := table(t, res, "raid.hw_drives")
	if len(tb.Rows) != 24 || tb.Rows[0].Cells[6] != "0" {
		t.Errorf("drive table: %d rows, %+v", len(tb.Rows), tb.Rows[0])
	}
	if c := tb.Rows[0].Cell(5, "vi"); c != "Đã cấu hình, hoạt động" {
		t.Errorf("state cell: %+v", c)
	}
	table(t, res, "raid.controllers")
}

// Real output with one drive taken out of its volume (UConf, Good): an
// unused disk, reported as Info.
func TestStorcli2UnconfiguredGood(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660_ugood.json")))
	noWorseThan(t, res, model.Info)
	f := want(t, res, "raid.hw_spares", "", model.Info)
	if !strings.Contains(f.Title.EN, "unused") || !strings.Contains(f.Title.EN, "Enclosure 320 Slot 11") {
		t.Errorf("spares: %q", f.Title.EN)
	}
	want(t, res, "raid.hw_ok", "", model.OK)
}

func TestStorcli2FailedDriveAndEnergyPack(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660_failed.json")),
		testkit.S("raid.storcli2_pd", testkit.Read(t, "storcli2_pd_9660.json")))
	label := "Controller 0 (MegaRAID 9660-16i Tri-Mode Storage Adapter)"
	want(t, res, "raid.hw_vd_failed", label+" v4", model.Crit)
	pd := want(t, res, "raid.hw_pd_failed", label+" Enclosure 306 Slot 3", model.Crit)
	if pd.Part == nil || pd.Part.Serial == "" || pd.Part.Model != "ST10000NM018B" {
		t.Errorf("pd part: %+v", pd.Part)
	}
	// "Need Attention" is a warning; the failed drive is the critical part.
	want(t, res, "raid.hw_ctrl_status", label, model.Warn)
	b := want(t, res, "raid.hw_battery", label, model.Warn)
	if b.Part == nil || b.Part.Model != "Supercap FBU345" || !strings.Contains(b.Title.EN, "Critical") {
		t.Errorf("battery: %q %+v", b.Title.EN, b.Part)
	}
	none(t, res, "raid.hw_ok")
	if n := len(findAll(res, "raid.hw_pd_failed")); n != 1 {
		t.Errorf("the failed drive is listed, so the failed-drive count must not add a second finding: %d", n)
	}
}

func TestStorcli2DriveErrors(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660.json")),
		testkit.S("raid.storcli2_pd", testkit.Read(t, "storcli2_pd_9660_errors.json")))
	label := "Controller 0 (MegaRAID 9660-16i Tri-Mode Storage Adapter)"
	m := want(t, res, "raid.hw_pd_media_errors", label+" Enclosure 306 Slot 0", model.Warn)
	if m.Part == nil || m.Part.Serial != "WP00MLCA0000E2426EZU" || !strings.Contains(m.Title.EN, "7 media errors") {
		t.Errorf("media: %q %+v", m.Title.EN, m.Part)
	}
	want(t, res, "raid.hw_pd_predictive", label+" Enclosure 306 Slot 1", model.Crit)
	want(t, res, "raid.hw_pd_other_errors", label+" Enclosure 306 Slot 2", model.Info)
}

func TestStorcli2RebuildSpareShielded(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_raid50_rebuild_synth.json")),
		testkit.S("raid.storcli2_rebuild", testkit.Read(t, "storcli2_rebuild_synth.json")),
		testkit.S("raid.storcli2_ep", testkit.Read(t, "storcli2_ep_critical_synth.json")))
	label := "Controller 0 (MegaRAID 9660-16i Tri-Mode Storage Adapter)"
	f := want(t, res, "raid.hw_vd_rebuilding", label+" v2", model.Warn)
	if !strings.Contains(f.Title.EN, "2%") || !strings.Contains(f.Title.EN, "19 Minutes") {
		t.Errorf("rebuild title: %q", f.Title.EN)
	}
	none(t, res, "raid.hw_vd_degraded", "raid.hw_pd_failed")
	want(t, res, "raid.hw_pd_state", label+" Enclosure 326 Slot 21", model.Warn) // ConfShld
	sp := want(t, res, "raid.hw_spares", label, model.Info)
	if !strings.Contains(sp.Title.EN, "hot spare") || !strings.Contains(sp.Title.EN, "Enclosure 326 Slot 20") {
		t.Errorf("spares: %q", sp.Title.EN)
	}
	b := want(t, res, "raid.hw_battery", label, model.Warn)
	if b.Part == nil || b.Part.Model != "CVPM05" || !strings.Contains(b.Title.EN, "Cannot support cache offload") {
		t.Errorf("battery: %q %+v", b.Title.EN, b.Part)
	}
}

func TestStorcli2PDClass(t *testing.T) {
	cases := []struct{ state, status, want string }{
		{"Conf", "Online", stOK},
		{"JBOD", "Online", stOK},
		{"UConf", "Good", stUnconfigured},
		{"GHS", "Good", stSpare},
		{"DHS", "Online", stSpare},
		{"Conf", "Failed", stFailed},
		{"UConf", "Bad", stFailed},
		{"Conf", "Offline", stFailed},
		{"UConfUnsp", "Unusable", stFailed},
		{"Conf", "Missing", stMissing},
		{"Conf", "Rebuild", stRebuilding},
		{"Conf", "Replace", stPredictive},
		{"ConfShld", "Online", stUnknown},
		{"UConfSntz", "Good", stBusy},
		{"ConfDgrd", "Online", stUnknown},
		{"UConfUnsp", "Good", stUnknown},
		{"Conf", "Various", stUnknown},
		{"", "", stUnknown},
	}
	for _, c := range cases {
		if got := storcli2PDClass(c.state, c.status); got != c.want {
			t.Errorf("%s/%s: got %s, want %s", c.state, c.status, got, c.want)
		}
	}
}

func TestStorcli2FailuresAndGarbage(t *testing.T) {
	// Real "Controller 5 not found" answer: no controller, no noise.
	js := `{"Controllers":[{"Command Status":{"CLI Version":"008.0005.0000.0010 Feb 22, 2023","Controller":5,"Status":"Failure","Description":"Controller 5 not found"}}]}`
	res := run(t, collect.OSLinux, testkit.RC("raid.storcli2_ctrl", 0, js, ""))
	if len(res.Coverage)+len(res.Findings) != 0 {
		t.Errorf("expected silence, got %v %+v", testkit.IDs(res), res.Coverage)
	}
	// Real "Number of Controllers : 0" (storcli2 installed, no MPI3 card).
	js = `{"Controllers":[{"Command Status":{"Status Code":0,"Status":"Success","Description":"None"},"Response Data":{"Number of Controllers":0,"Host Name":"application-node"}}]}`
	res = run(t, collect.OSLinux, testkit.S("raid.storcli2_ctrl", js))
	if len(res.Coverage)+len(res.Findings) != 0 {
		t.Errorf("expected silence, got %v %+v", testkit.IDs(res), res.Coverage)
	}
	// An unsupported command is a failed check, with the CLI's reason.
	js = `{"Controllers":[{"Command Status":{"Controller":"0","Status":"Failure","Description":"Un-supported command"}}]}`
	res = run(t, collect.OSLinux, testkit.RC("raid.perccli2_ctrl", 1, js, ""))
	c := cov(t, res, "raid.hw", model.CovFailed)
	if !strings.Contains(c.Reason.EN, "perccli2") || !strings.Contains(c.Reason.EN, "Un-supported command") {
		t.Errorf("reason: %q", c.Reason.EN)
	}
	// Truncated JSON and a drive "not found" answer never panic.
	full := testkit.Read(t, "storcli2_ctrl_9660.json")
	res = run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", full[:len(full)/2]),
		testkit.S("raid.storcli2_pd", testkit.Read(t, "storcli2_pd_notfound.json")))
	cov(t, res, "raid.hw", model.CovFailed)
}

// PERCCLI2 prints the StorCLI2 JSON; the same controller seen by storcli2
// and perccli2 is reported once.
func TestPerccli2SameParserAndDedup(t *testing.T) {
	ctrl := testkit.Read(t, "storcli2_ctrl_9660.json")
	res := run(t, collect.OSLinux, testkit.S("raid.storcli2_ctrl", ctrl), testkit.S("raid.perccli2_ctrl", ctrl))
	if n := len(res.Facts.(*Facts).Controllers); n != 1 {
		t.Errorf("controllers: %d", n)
	}
	res = run(t, collect.OSWindows, testkit.S("raid.perccli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660_failed.json")))
	ct := res.Facts.(*Facts).Controllers[0]
	if ct.Tool != "perccli2" {
		t.Errorf("tool: %s", ct.Tool)
	}
	f := want(t, res, "raid.hw_ctrl_status", "", model.Warn)
	if !strings.Contains(f.Action.EN, "perccli2 /c0 show events") {
		t.Errorf("event log command: %q", f.Action.EN)
	}
}

func TestDetectMPI3(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.pci", testkit.Read(t, "pci_mpi3mr.txt")))
	det := res.Facts.(*Facts).Detected
	if len(det) != 3 || det[0].Tool != "perccli2" || det[1].Tool != "storcli2" || det[2].Tool != "perccli" {
		t.Fatalf("detected: %+v", det)
	}
	var tools []string
	for _, f := range findAll(res, "raid.hw_cli_missing") {
		tools = append(tools, f.Title.EN)
	}
	all := strings.Join(tools, "\n")
	if len(tools) != 3 || !strings.Contains(all, "PERC H965i Adapter") || !strings.Contains(all, "(perccli2)") || !strings.Contains(all, "(storcli2)") {
		t.Errorf("findings: %s", all)
	}
	f := testkit.Find(res, "raid.hw_cli_missing", det[0].Name)
	if f == nil || !strings.Contains(f.Action.EN, "PERC CLI 2") || !strings.Contains(f.Action.VI, "PERC 12") {
		t.Errorf("perccli2 hint: %+v", f)
	}

	// storcli (v1) ran and covers the PERC H730P, but not the MPI3 cards.
	res = run(t, collect.OSLinux, testkit.S("raid.pci", testkit.Read(t, "pci_mpi3mr.txt")),
		testkit.S("raid.perccli_ctrl", testkit.Read(t, "storcli_ctrl_praid_ep420i.json")))
	if n := len(findAll(res, "raid.hw_cli_missing")); n != 2 {
		t.Errorf("storcli must not cover the MPI3 controllers: %v", testkit.IDs(res))
	}
	cov(t, res, "raid.hw", model.CovPartial)

	// storcli2 ran: the 9660 is covered; the PERC H965i still needs
	// perccli2 or storcli2... both are the "megaraid2" family, so it is
	// covered too (storcli2 also manages Dell-branded MPI3 cards).
	res = run(t, collect.OSLinux, testkit.S("raid.pci", testkit.Read(t, "pci_mpi3mr.txt")),
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660.json")))
	if n := len(findAll(res, "raid.hw_cli_missing")); n != 1 {
		t.Errorf("only the PERC H730P (perccli) should remain uncovered: %v", testkit.IDs(res))
	}
}

func TestMPI3Tool(t *testing.T) {
	cases := []struct{ vendor, device, sub, class, drv, name, want string }{
		{"0x1000", "0x00a5", "0x1028", "0x010400", "mpi3mr", "Broadcom / LSI Fusion-MPT 24GSAS/PCIe SAS40xx/41xx / Dell PERC H965i Front", "perccli2"},
		{"0x1000", "0x00a5", "0x1000", "0x010400", "mpi3mr", "Broadcom / LSI Fusion-MPT 24GSAS/PCIe SAS40xx/41xx / Broadcom / LSI MegaRAID 9670-24i Tri-Mode Storage Adapter", "storcli2"},
		{"0x1000", "0x00a5", "0x1000", "0x010700", "mpi3mr", "Broadcom / LSI Fusion-MPT 24GSAS/PCIe SAS40xx/41xx / Broadcom / LSI eHBA 9600-24i Tri-Mode Storage Adapter", ""},
		{"0x1000", "0x00a5", "0x1028", "0x010700", "mpi3mr", "x / Dell HBA465i Front", ""},
		{"0x1000", "0x00b3", "0x1000", "0x010400", "mpi3mr", "Broadcom / LSI Fusion-MPT 24G SAS/PCIe SAS50xx/SAS51xx / Broadcom / LSI MegaRAID 9760W-16i 24G SAS/PCIe Storage Adapter", "storcli2"},
		{"0x1000", "0x00a5", "0x1000", "0x010400", "mpi3mr", "PCI 0x1000:0x00a5", "storcli2"},
		{"0x1000", "0x00a5", "0x1000", "0x010700", "mpi3mr", "PCI 0x1000:0x00a5", ""},
		{"1000", "00a5", "1028", "", "", "PERC H965i Front", "perccli2"},             // Windows
		{"1000", "00a5", "1000", "", "", "MegaRAID 9660-16i", "storcli2"},            // Windows
		{"0x1000", "0x005d", "0x1028", "0x010400", "megaraid_sas", "PERC H730P", ""}, // SAS3108: perccli
		{"0x1000", "0x00e6", "0x1000", "0x010700", "mpt3sas", "HBA 9500-8i", ""},
	}
	for _, c := range cases {
		if got := mpi3Tool(c.vendor, c.device, c.sub, c.class, c.drv, c.name); got != c.want {
			t.Errorf("%+v: got %q", c, got)
		}
	}
	// Windows: a PERC 12 is perccli2, an eHBA on the same chip is not
	// claimed by the generic MegaRAID rules for storcli either.
	res := run(t, collect.OSWindows, testkit.S("raid.win_controllers",
		`[{"Name":"PERC H965i Front","Manufacturer":"Broadcom","DriverName":"mr3x","PNPDeviceID":"PCI\\VEN_1000&DEV_00A5&SUBSYS_21151028&REV_00\\5&1","Status":"OK"},`+
			`{"Name":"Broadcom eHBA 9600-16i Tri-Mode Storage Adapter","Manufacturer":"Broadcom","DriverName":"mpi3x","PNPDeviceID":"PCI\\VEN_1000&DEV_00A5&SUBSYS_46701000&REV_00\\5&2","Status":"OK"}]`))
	det := res.Facts.(*Facts).Detected
	if len(det) != 1 || det[0].Tool != "perccli2" {
		t.Errorf("windows detected: %+v", det)
	}
}

func findAll(res model.Result, id string) []*model.Finding {
	var out []*model.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == id {
			out = append(out, &res.Findings[i])
		}
	}
	return out
}

// "Not in progress" rows (real StorCLI wording for idle drives) are not
// rebuilds, in StorCLI and StorCLI2 alike.
func TestRebuildNotInProgress(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.storcli_ctrl", testkit.Read(t, "storcli_ctrl_rebuild.json")),
		testkit.S("raid.storcli_rebuild", testkit.Read(t, "storcli_rebuild.json")))
	ct := res.Facts.(*Facts).Controllers[0]
	for _, d := range ct.Drives {
		if d.ID == "252:0" && (d.Class != stOK || d.Rebuild != "") {
			t.Errorf("252:0 is not rebuilding: %+v", d)
		}
	}
	res = run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_raid50_rebuild_synth.json")),
		testkit.S("raid.storcli2_rebuild", testkit.Read(t, "storcli2_rebuild_synth.json")))
	if n := len(findAll(res, "raid.hw_pd_rebuilding")) + len(findAll(res, "raid.hw_vd_rebuilding")); n != 1 {
		t.Errorf("one rebuild expected: %v", testkit.IDs(res))
	}
	// A rebuild row for a drive the controller does not list is ignored.
	res = run(t, collect.OSLinux,
		testkit.S("raid.storcli2_ctrl", testkit.Read(t, "storcli2_ctrl_9660.json")),
		testkit.S("raid.storcli2_rebuild", testkit.Read(t, "storcli2_rebuild_synth.json")))
	noWorseThan(t, res, model.OK)
	if n := len(res.Facts.(*Facts).Controllers[0].Drives); n != 24 {
		t.Errorf("drives: %d", n)
	}
}
