package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// Two RAID1 arrays on partitions of the same disks: md95 recovers, md96
// waits ("resync=DELAYED") although a spare is already rebuilding into it.
// Real WSL capture. Without root there is no mdadm --detail: sysfs
// sync_action=recover must still say "rebuild queued", not "replace a disk".
func TestMDDelayedRecoveryNoRoot(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_delayed.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_delayed.txt")),
		testkit.Skipped("raid.mdadm_scan", "not-root"),
	)
	want(t, res, "raid.md_rebuilding", "md95", model.Warn)
	f := want(t, res, "raid.md_rebuilding", "md96", model.Warn)
	if !strings.Contains(f.Title.EN, "queued") || !strings.Contains(f.Title.VI, "chờ") {
		t.Errorf("md96 title should say the rebuild is queued: %q / %q", f.Title.EN, f.Title.VI)
	}
	none(t, res, "raid.md_degraded", "raid.md_sync_pending")
}

func TestMDDelayedRecoveryRoot(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_delayed.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_delayed.txt")),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md95", testkit.Read(t, "wsl_mdadm_detail_delayed_md95.txt")),
		testkit.S("raid.mdadm:/dev/md96", testkit.Read(t, "wsl_mdadm_detail_delayed_md96.txt")),
	)
	want(t, res, "raid.md_rebuilding", "md95", model.Warn)
	want(t, res, "raid.md_rebuilding", "md96", model.Warn)
	none(t, res, "raid.md_degraded")
}

// Kernel >= 5.x prints "broken" instead of "active" for an array with
// MD_BROKEN set (raid0/linear member gone; raid1/10 on its last device).
// Real WSL capture: degraded RAID1s in auto-read-only with an idle spare.
func TestMDBrokenIsNotInactive(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_broken.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_broken.txt")),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md95", testkit.Read(t, "wsl_mdadm_detail_broken_md95.txt")),
	)
	none(t, res, "raid.md_inactive")
	f := want(t, res, "raid.md_degraded", "md95", model.Crit)
	if !strings.Contains(f.Action.EN, "mdadm --readwrite /dev/md95") || !strings.Contains(f.Action.VI, "mdadm --readwrite /dev/md95") {
		t.Errorf("spare waiting in auto-read-only: action should start the rebuild: %q", f.Action.EN)
	}
	want(t, res, "raid.md_degraded", "md96", model.Crit)

	// raid0 marked broken: a member is gone, the data is not readable.
	res = run(t, collect.OSLinux, testkit.S("raid.mdstat",
		"Personalities : [raid0]\nmd0 : broken raid0 sdb1[1]\n      1953260544 blocks super 1.2 512k chunks\n\nunused devices: <none>\n"))
	want(t, res, "raid.md_failed", "md0", model.Crit)
	none(t, res, "raid.md_inactive")
}

// dRAID sequential resilver onto the distributed spare (OpenZFS dRAID
// howto): the scan line is "resilver (draid1:...) in progress".
func TestZFSDraidResilver(t *testing.T) {
	res := zfs(t, "zpool_status_draid_resilver.txt")
	f := want(t, res, "raid.zfs_resilver", "tank", model.Warn)
	if !strings.Contains(f.Title.EN, "57.2%") {
		t.Errorf("title: %q", f.Title.EN)
	}
	none(t, res, "raid.zfs_pool_degraded")
	// sdg itself is dead and still has to be replaced.
	want(t, res, "raid.zfs_device_failed", "tank/sdg", model.Crit)
	// The distributed spare in use is not a problem.
	if f := testkit.Find(res, "raid.zfs_device_failed", "tank/draid1-0-0"); f != nil {
		t.Errorf("INUSE spare flagged: %+v", f)
	}
}

// A device that vanished shows as its GUID with "was <old path>"
// (openzfs/zfs#4299): the Part must come from the old by-id path.
func TestZFSWasPath(t *testing.T) {
	res := zfs(t, "zpool_status_was_path.txt")
	d := want(t, res, "raid.zfs_device_failed", "clintards/5332611342296232703", model.Warn)
	if d.Part == nil || d.Part.Serial != "S246J9EC432652" || d.Part.Model != "ST1000DM005 HD103SJ" {
		t.Errorf("part: %+v", d.Part)
	}
	if !strings.Contains(d.Title.EN, "/dev/disk/by-id/ata-ST1000DM005_HD103SJ_S246J9EC432652-part1") {
		t.Errorf("title should name the old path: %q", d.Title.EN)
	}
	want(t, res, "raid.zfs_resilver", "clintards", model.Warn)
	want(t, res, "raid.zfs_data_errors", "clintards", model.Crit)
	none(t, res, "raid.zfs_pool_degraded")
}

// "expand:" (RAIDZ expansion, OpenZFS 2.3) is its own field, not part of
// the scan text.
func TestZFSExpandField(t *testing.T) {
	st := "  pool: tank\n state: ONLINE\n  scan: scrub repaired 0B in 01:00:00 with 0 errors on Sun Sep 13 01:00:00 2026\nexpand: expansion of raidz1-0 in progress since Sat Sep 26 10:00:00 2026\n\t1.2T / 4.0T copied at 300M/s, 30.00% done, 02:40:00 to go\nconfig:\n\n\tNAME        STATE     READ WRITE CKSUM\n\ttank        ONLINE       0     0     0\n\t  raidz1-0  ONLINE       0     0     0\n\t    sda     ONLINE       0     0     0\n\t    sdb     ONLINE       0     0     0\n\t    sdc     ONLINE       0     0     0\n\nerrors: No known data errors\n"
	res := run(t, collect.OSLinux, testkit.S("raid.zpool_status", st))
	p := res.Facts.(*Facts).ZFS[0]
	if strings.Contains(p.Scan, "expansion") {
		t.Errorf("scan swallowed the expand field: %q", p.Scan)
	}
	noWorseThan(t, res, model.Info)
}

// Older MegaCli prints "Battery State: Operational" for a healthy BBU and
// "Non Operational" for a dead one (Oracle Exadata BBU docs; karellen.
// blogspot.com 2012 MegaSAS 9260 output).
func TestMegaCliOperationalBattery(t *testing.T) {
	bbu := strings.Replace(testkit.Read(t, "megacli-bbu-recent.txt"), "Battery State: Optimal", "Battery State: Operational", 1)
	if !strings.Contains(bbu, "Operational") {
		t.Fatal("fixture changed")
	}
	res := run(t, collect.OSLinux,
		testkit.S("raid.megacli_pd", testkit.Read(t, "megacli-ldpdinfo.txt")),
		testkit.S("raid.megacli_bbu", bbu))
	none(t, res, "raid.hw_battery")

	bbu = strings.Replace(bbu, "Battery State: Operational", "Battery State     : Non Operational", 1)
	res = run(t, collect.OSLinux,
		testkit.S("raid.megacli_pd", testkit.Read(t, "megacli-ldpdinfo.txt")),
		testkit.S("raid.megacli_bbu", bbu))
	want(t, res, "raid.hw_battery", "Controller 0", model.Warn)
}

// Smart HBA / Smart Array in HBA mode: the disks belong to the OS, they
// are not "unused" (real output, Proxmox forum thread 118035).
func TestSsacliHBAMode(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.ssacli_config", testkit.Read(t, "ssacli-H240ar-hba.txt")))
	none(t, res, "raid.hw_spares")
	noWorseThan(t, res, model.OK)
	if n := len(res.Facts.(*Facts).Controllers[0].Drives); n != 8 {
		t.Errorf("drives: %d", n)
	}
	// Detail form: "Drive Type: HBA Mode Drive".
	det := "Smart HBA H240 in Slot 1\n   Controller Status: OK\n\n   HBA Drives\n\n      physicaldrive 1I:1:1\n         Port: 1I\n         Status: OK\n         Drive Type: HBA Mode Drive\n         Serial Number: ABC123\n         Model: ATA     MB2000GCWDA\n"
	res = run(t, collect.OSLinux, testkit.S("raid.ssacli_config", det))
	none(t, res, "raid.hw_spares")
}

// A degraded logical drive that also lists unrecoverable media errors is
// still degraded (Crit), not "rebuilding".
func TestSsacliDegradedWithMediaErrors(t *testing.T) {
	cfg := strings.Replace(testkit.Read(t, "ssacli-P440ar-failed.txt"),
		"Status: Interim Recovery Mode\n", "Status: Interim Recovery Mode\n         Unrecoverable Media Errors: Detected\n", 1)
	res := run(t, collect.OSLinux, testkit.S("raid.ssacli_config", cfg))
	label := "Slot 0 (Smart Array P440ar)"
	want(t, res, "raid.hw_vd_degraded", label+" LD 1", model.Crit)
	none(t, res, "raid.hw_vd_rebuilding")
	want(t, res, "raid.hw_vd_media_errors", label+" LD 1", model.Warn)
}

func TestArcconfDegradedWithFailedStripes(t *testing.T) {
	cfg := testkit.Read(t, "arcconf-getconfig-al-degraded.txt")
	if !strings.Contains(cfg, "Failed stripes                           : No") {
		t.Fatal("fixture changed")
	}
	cfg = strings.Replace(cfg, "Failed stripes                           : No", "Failed stripes                           : Yes", 1)
	res := run(t, collect.OSLinux, testkit.S("raid.arcconf:1", cfg))
	label := "Controller 1 (Adaptec ASR8805)"
	want(t, res, "raid.hw_vd_degraded", label+" LD 0", model.Crit)
	none(t, res, "raid.hw_vd_rebuilding")
	want(t, res, "raid.hw_vd_media_errors", label+" LD 0", model.Warn)
}

// Storage Spaces names written without spaces (enum names instead of the
// type data's display strings) must classify the same.
func TestSpacesEnumNamesWithoutSpaces(t *testing.T) {
	pools := `[{"FriendlyName":"Pool1","HealthStatus":"Warning","OperationalStatus":"Degraded","IsPrimordial":false,"IsReadOnly":false,"Size":4000,"AllocatedSize":2000}]`
	pd := `[{"FriendlyName":"Disk2","SerialNumber":"Z1","HealthStatus":"Warning","OperationalStatus":"LostCommunication","Usage":"AutoSelect","PoolName":"Pool1","DeviceId":"2","Size":1000}]`
	res := run(t, collect.OSWindows, testkit.S("raid.win_pools", pools), testkit.S("raid.win_pdisks", pd))
	want(t, res, "raid.spaces_disk_failed", "Disk2", model.Crit)
}

// Installable tools put the command in Coverage.Cmd (hint.InstallFix).
func TestCoverageCmd(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_clean.txt")), testkit.Missing("raid.mdadm_scan", "mdadm"))
	c := cov(t, res, "raid.md", model.CovPartial)
	if c.Cmd != "dnf install -y mdadm" || strings.Contains(c.Fix.EN, "dnf install") {
		t.Errorf("md coverage: cmd %q fix %q", c.Cmd, c.Fix.EN)
	}
	res = run(t, collect.OSLinux, testkit.Missing("raid.zpool_status", "zpool"))
	if c := cov(t, res, "raid.zfs", model.CovSkipped); c.Cmd != "dnf install -y zfs" {
		t.Errorf("zfs cmd %q", c.Cmd)
	}
	res = run(t, collect.OSLinux, testkit.Missing("raid.lvs", "lvs"))
	if c := cov(t, res, "raid.lvm", model.CovSkipped); c.Cmd != "dnf install -y lvm2" {
		t.Errorf("lvm cmd %q", c.Cmd)
	}
	res = run(t, collect.OSLinux, testkit.Missing("raid.btrfs_show", "btrfs"))
	if c := cov(t, res, "raid.btrfs", model.CovSkipped); c.Cmd != "dnf install -y btrfs-progs" {
		t.Errorf("btrfs cmd %q", c.Cmd)
	}
}

// Adaptec "Impacted" (Microchip KB: needs Verify with Fix) is neither a
// rebuild nor a lost disk.
func TestArcconfImpacted(t *testing.T) {
	cfg := strings.Replace(testkit.Read(t, "arcconf-getconfig-al-synth.txt"),
		"Status of Logical Device                 : Optimal", "Status of Logical Device                 : Impacted", 1)
	if !strings.Contains(cfg, "Impacted") {
		t.Fatal("fixture changed")
	}
	res := run(t, collect.OSLinux, testkit.S("raid.arcconf:1", cfg))
	f := want(t, res, "raid.hw_vd_needs_verify", "Controller 1 (Adaptec ASR8805) LD 0", model.Warn)
	if !strings.Contains(f.Action.EN, "arcconf task start 1 logicaldrive 0 verify_fix") {
		t.Errorf("action: %q", f.Action.EN)
	}
	none(t, res, "raid.hw_vd_rebuilding", "raid.hw_vd_degraded")
}
