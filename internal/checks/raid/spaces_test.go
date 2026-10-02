package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func TestSpacesPrimordialOnlyIsSilent(t *testing.T) {
	// Real output of the dev machine: no pool, RST controller (software
	// RAID, not managed by a vendor RAID CLI).
	res := run(t, collect.OSWindows,
		testkit.S("raid.win_pools", testkit.Read(t, "win_pools_local.json")),
		testkit.S("raid.win_controllers", testkit.Read(t, "win_controllers_local.json")))
	if len(res.Findings)+len(res.Coverage) != 0 {
		t.Errorf("expected no output, got %v %+v", testkit.IDs(res), res.Coverage)
	}
}

func TestSpacesHealthyNumericEnums(t *testing.T) {
	res := run(t, collect.OSWindows,
		testkit.S("raid.win_pools", testkit.Read(t, "win_pools_healthy.json")),
		testkit.S("raid.win_vdisks", testkit.Read(t, "win_vdisks_healthy.json")),
		testkit.S("raid.win_pdisks", "[]"), testkit.S("raid.win_jobs", "[]"))
	noWorseThan(t, res, model.OK)
	want(t, res, "raid.spaces_ok", "Pool01, Data", model.OK)
	cov(t, res, "raid.spaces", model.CovRan)
}

func TestSpacesDegraded(t *testing.T) {
	res := run(t, collect.OSWindows,
		testkit.S("raid.win_pools", testkit.Read(t, "win_pools_degraded.json")),
		testkit.S("raid.win_vdisks", testkit.Read(t, "win_vdisks_degraded.json")),
		testkit.S("raid.win_pdisks", testkit.Read(t, "win_pdisks_degraded.json")),
		testkit.S("raid.win_jobs", "[]"))
	want(t, res, "raid.spaces_pool", "Pool01", model.Warn)
	want(t, res, "raid.spaces_vdisk_degraded", "Data", model.Crit)
	want(t, res, "raid.spaces_vdisk_degraded", "Archive", model.Crit)
	f := want(t, res, "raid.spaces_disk_failed", "PhysicalDisk2", model.Crit)
	if f.Part == nil || f.Part.Serial != "ZC1A9X8Y" || !strings.Contains(f.Part.Location, "Slot 2") {
		t.Errorf("part: %+v", f.Part)
	}
	want(t, res, "raid.spaces_disk_retired", "PhysicalDisk3", model.Warn)
	want(t, res, "raid.spaces_ok", "Backup", model.OK)
	tb := table(t, res, "raid.hw_drives")
	if len(tb.Rows) != 3 {
		t.Errorf("drive rows: %d", len(tb.Rows))
	}
}

func TestSpacesRepairJob(t *testing.T) {
	res := run(t, collect.OSWindows,
		testkit.S("raid.win_pools", testkit.Read(t, "win_pools_degraded.json")),
		testkit.S("raid.win_vdisks", testkit.Read(t, "win_vdisks_degraded.json")),
		testkit.S("raid.win_jobs", testkit.Read(t, "win_jobs_repair.json")))
	// A repair is running: the degraded mirror is being fixed (Warn), the
	// incomplete parity space is still critical.
	want(t, res, "raid.spaces_vdisk_repairing", "Data", model.Warn)
	want(t, res, "raid.spaces_vdisk_degraded", "Archive", model.Crit)
	j := want(t, res, "raid.spaces_job", "Data-Repair", model.Warn)
	if !strings.Contains(j.Title.EN, "42%") {
		t.Errorf("job title: %q", j.Title.EN)
	}
}

func TestWindowsControllerDetection(t *testing.T) {
	res := run(t, collect.OSWindows, testkit.S("raid.win_controllers", testkit.Read(t, "win_controllers_perc.json")))
	f := want(t, res, "raid.hw_cli_missing", "PERC H740P Mini", model.Info)
	if !strings.Contains(f.Action.EN, "perccli64") {
		t.Errorf("action: %q", f.Action.EN)
	}
	cov(t, res, "raid.hw", model.CovSkipped)
	// With perccli output the controller is covered.
	res = run(t, collect.OSWindows,
		testkit.S("raid.win_controllers", testkit.Read(t, "win_controllers_perc.json")),
		testkit.S("raid.perccli_ctrl", testkit.Read(t, "storcli_ctrl_praid_ep420i.json")))
	none(t, res, "raid.hw_cli_missing")
	cov(t, res, "raid.hw", model.CovRan)
}

func TestPnpIDs(t *testing.T) {
	v, s := pnpIDs(`PCI\VEN_1000&DEV_0016&SUBSYS_1F471028&REV_01\00000500EB008C4D00`)
	if v != "1000" || s != "1028" {
		t.Errorf("got %q %q", v, s)
	}
	if v, s := pnpIDs(`ROOT\SPACEPORT\0000`); v != "" || s != "" {
		t.Errorf("root device: %q %q", v, s)
	}
}
