package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func TestParseMdstatProcfs(t *testing.T) {
	arrays := parseMdstat(testkit.Read(t, "mdstat_procfs.txt"))
	if len(arrays) != 18 {
		t.Fatalf("parsed %d arrays, want 18", len(arrays))
	}
	by := map[string]*MDArray{}
	for _, a := range arrays {
		by[a.Name] = a
	}
	if a := by["md6"]; a.Status != "U_" || a.SyncOp != "recovery" || a.SyncPct != 8.5 || a.Finish != "17.0min" || a.Want != 2 || a.Have != 1 {
		t.Errorf("md6: %+v", a)
	}
	if a := by["md4"]; a.Active || a.Level != "raid1" || len(a.Members) != 2 || a.Members[0].Flags != "F" {
		t.Errorf("md4: %+v", a)
	}
	if a := by["md219"]; !a.Container || a.Active {
		t.Errorf("md219 should be an IMSM container: %+v", a)
	}
	if a := by["md11"]; a.ReadOnly != "auto-read-only" || a.Pending != "resync=PENDING" {
		t.Errorf("md11: %+v", a)
	}
	if a := by["md9"]; a.Pending != "resync=DELAYED" || len(mdFailedMembers(a)) != 2 || len(mdSpares(a)) != 1 {
		t.Errorf("md9: %+v", a)
	}
	if a := by["md42"]; a.SyncOp != "reshape" || a.Status != "UU_" {
		t.Errorf("md42: %+v", a)
	}
	if a := by["md201"]; a.SyncOp != "check" {
		t.Errorf("md201: %+v", a)
	}
	if a := by["md3"]; a.Blocks != 5853468288 || a.Level != "raid6" {
		t.Errorf("md3: %+v", a)
	}
}

func TestMDProcfsFindings(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.mdstat", testkit.Read(t, "mdstat_procfs.txt")), testkit.Missing("raid.mdadm_scan", "mdadm"))
	want(t, res, "raid.md_inactive", "md4", model.Crit)
	want(t, res, "raid.md_rebuilding", "md6", model.Warn)
	want(t, res, "raid.md_member_failed", "md6/sdb2", model.Crit)
	want(t, res, "raid.md_degraded", "md7", model.Crit)
	want(t, res, "raid.md_resync", "md8", model.Warn)
	want(t, res, "raid.md_check", "md201", model.Info)
	want(t, res, "raid.md_member_failed", "md9/sde", model.Crit)
	want(t, res, "raid.md_member_failed", "md9/sdf", model.Crit)
	want(t, res, "raid.md_sync_pending", "md9", model.Info)
	want(t, res, "raid.md_readonly", "md101", model.Info)
	want(t, res, "raid.md_rebuilding", "md42", model.Warn) // degraded while reshaping
	want(t, res, "raid.md_spare", "md3", model.Info)
	// IMSM container md219 is inactive by design: no alarm.
	if f := testkit.Find(res, "raid.md_inactive", "md219"); f != nil {
		t.Errorf("IMSM container must not be reported inactive")
	}
	ok := want(t, res, "raid.md_ok", "", model.OK)
	for _, n := range []string{"md127 raid1 [UU]", "md0 raid1 [UU]", "md10 raid0"} {
		if !strings.Contains(ok.Target, n) {
			t.Errorf("OK finding should list %q: %q", n, ok.Target)
		}
	}
	c := cov(t, res, "raid.md", model.CovPartial)
	if c.Cmd != "dnf install -y mdadm" || c.Fix.IsZero() {
		t.Errorf("fix: %q cmd: %q", c.Fix.EN, c.Cmd)
	}
	tb := table(t, res, "raid.arrays")
	if len(tb.Rows) != 18 {
		t.Errorf("table rows %d", len(tb.Rows))
	}
}

func TestMDHealthyWSL(t *testing.T) {
	secs := []*collect.Section{
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_clean.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_clean.txt")),
		testkit.S("raid.mdadm_scan", testkit.Read(t, "wsl_mdadm_detail_scan.txt")),
		testkit.S("raid.mdadm:/dev/md90", testkit.Read(t, "wsl_mdadm_detail_clean_raid1.txt")),
		testkit.S("raid.mdadm:/dev/md91", testkit.Read(t, "wsl_mdadm_detail_clean_raid5_spare.txt")),
	}
	res := run(t, collect.OSLinux, secs...)
	noWorseThan(t, res, model.Info)
	want(t, res, "raid.md_ok", "md91 raid5 [UUU], md90 raid1 [UU]", model.OK)
	want(t, res, "raid.md_spare", "md91", model.Info)
	cov(t, res, "raid.md", model.CovRan)
	f := res.Facts.(*Facts)
	if f.MD[1].UUID != "878d1e52:792ab0c1:bf176ccf:0d162be6" || f.MD[1].State != "clean" || f.MD[1].Mismatch != 0 {
		t.Errorf("md90 facts: %+v", f.MD[1])
	}
}

func TestMDFailedMemberWSL(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_failed.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_failed.txt")),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md90", testkit.Read(t, "wsl_mdadm_detail_failed.txt")),
		testkit.S("raid.byid", "ata-ST4000NM0035-1V4107_ZC1A2B3C ../../loop1\n"),
	)
	f := want(t, res, "raid.md_degraded", "md90", model.Crit)
	if f.Part == nil || f.Part.Serial != "ZC1A2B3C" || !strings.Contains(f.Part.Location, "loop1") {
		t.Errorf("part: %+v", f.Part)
	}
	if !strings.Contains(f.Action.EN, "mdadm --manage /dev/md90 --remove") || !strings.Contains(f.Action.VI, "Sao lưu ngay") {
		t.Errorf("action: %q", f.Action.EN)
	}
	if !strings.Contains(f.Title.EN, "loop1") {
		t.Errorf("title should name the failed member: %q", f.Title.EN)
	}
	// sysfs says sync_action=recover right after the failure although no
	// spare exists: that must not be reported as a rebuild.
	none(t, res, "raid.md_rebuilding", "raid.md_member_failed")
	want(t, res, "raid.md_ok", "md91 raid5 [UUU]", model.OK)
}

func TestMDRemovedMemberWSL(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", "Personalities : [raid1]\nmd90 : active raid1 loop0[0]\n      130048 blocks super 1.2 [2/1] [U_]\n      \nunused devices: <none>\n"),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md90", testkit.Read(t, "wsl_mdadm_detail_removed.txt")))
	f := want(t, res, "raid.md_degraded", "md90", model.Crit)
	if f.Part != nil {
		t.Errorf("no failed member known, part should be nil: %+v", f.Part)
	}
}

func TestMDRecoveryWSL(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_recovery.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_recovery.txt")),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md91", testkit.Read(t, "wsl_mdadm_detail_recovery.txt")),
	)
	f := want(t, res, "raid.md_rebuilding", "md91", model.Warn)
	if !strings.Contains(f.Title.EN, "2.3%") || !strings.Contains(f.Title.EN, "1 minute") || !strings.Contains(f.Title.VI, "đang rebuild") {
		t.Errorf("title: %q / %q", f.Title.EN, f.Title.VI)
	}
	if !strings.Contains(f.Action.EN, "Do not reboot") {
		t.Errorf("action: %q", f.Action.EN)
	}
	want(t, res, "raid.md_member_failed", "md91/loop3", model.Crit)
	want(t, res, "raid.md_degraded", "md90", model.Crit) // md90 still lacks its removed member
}

func TestMDResyncAndCheckWSL(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_resync.txt")),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md90", testkit.Read(t, "wsl_mdadm_detail_resync.txt")))
	want(t, res, "raid.md_resync", "md90", model.Warn)

	res = run(t, collect.OSLinux,
		testkit.S("raid.mdstat", testkit.Read(t, "wsl_mdstat_check.txt")),
		testkit.S("raid.md_sysfs", testkit.Read(t, "wsl_md_sysfs_check.txt")),
		testkit.S("raid.mdadm_scan", ""),
		testkit.S("raid.mdadm:/dev/md91", testkit.Read(t, "wsl_mdadm_detail_check.txt")))
	want(t, res, "raid.md_check", "md91", model.Info)
	// A spare took over: the array is complete but loop3 is still dead.
	want(t, res, "raid.md_member_failed", "md91/loop3", model.Crit)
	none(t, res, "raid.md_resync", "raid.md_mismatch")
}

func TestMDMismatch(t *testing.T) {
	mdstat := "md0 : active raid1 sda1[0] sdb1[1]\n      1000 blocks [2/2] [UU]\n\nmd1 : active raid5 sdc1[0] sdd1[1] sde1[2]\n      2000 blocks level 5, 64k chunk, algorithm 2 [3/3] [UUU]\n"
	sys := "/sys/block/md0/md/mismatch_cnt=128\n/sys/block/md0/md/sync_action=idle\n/sys/block/md1/md/mismatch_cnt=8\n/sys/block/md1/md/sync_action=idle\n/sys/block/md1/md/dev-sdd1/state=in_sync,write_error\n/sys/block/md1/md/dev-sde1/errors=4\n"
	res := run(t, collect.OSLinux, testkit.S("raid.mdstat", mdstat), testkit.S("raid.md_sysfs", sys), testkit.Skipped("raid.mdadm_scan", "not-root"))
	want(t, res, "raid.md_mismatch", "md0", model.Info) // RAID1: benign
	want(t, res, "raid.md_mismatch", "md1", model.Warn) // parity RAID
	want(t, res, "raid.md_member_errors", "md1/sdd1", model.Warn)
	want(t, res, "raid.md_member_read_errors", "md1/sde1", model.Info)
	c := cov(t, res, "raid.md", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "root") {
		t.Errorf("reason: %q", c.Reason.EN)
	}
}

func TestMDSysfsProcfsFixture(t *testing.T) {
	attrs, devs := parseMdSysfs(testkit.S("raid.md_sysfs", testkit.Read(t, "md_sysfs_procfs.txt")))
	if attrs["md6"]["sync_action"] != "recover" || attrs["md7"]["level"] != "container" || devs["md5"]["sdp"]["state"] != "faulty" {
		t.Errorf("sysfs: %v %v", attrs["md6"], devs["md5"])
	}
	// md5 is degraded with a faulty member according to sysfs alone.
	mdstat := "md5 : active raid5 sdaa[3](S) sdn[0] sdo[1] sdp[2](F)\n      100 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/2] [UU_]\n\nmd7 : inactive sdb[0](S)\n      100 blocks super external:imsm\n"
	res := run(t, collect.OSLinux, testkit.S("raid.mdstat", mdstat), testkit.S("raid.md_sysfs", testkit.Read(t, "md_sysfs_procfs.txt")), testkit.Missing("raid.mdadm_scan", "mdadm"))
	f := want(t, res, "raid.md_degraded", "md5", model.Crit)
	if f.Part == nil || !strings.Contains(f.Part.Location, "sdp") {
		t.Errorf("part: %+v", f.Part)
	}
	none(t, res, "raid.md_inactive")
}

func TestDiskOf(t *testing.T) {
	for in, out := range map[string]string{"sdb1": "sdb", "/dev/sdab12": "sdab", "nvme0n1p2": "nvme0n1", "nvme0n1": "nvme0n1", "mmcblk0p1": "mmcblk0", "loop3": "loop3", "vda": "vda", "xvdb1": "xvdb"} {
		if got := diskOf(in); got != out {
			t.Errorf("diskOf(%q)=%q want %q", in, got, out)
		}
	}
}

func TestByID(t *testing.T) {
	ids := parseByID(testkit.S("raid.byid", testkit.Read(t, "byid_sdb_sdc.txt")))
	if ids["sdb"].Serial != "ZC1A2B3C" || ids["sdb"].Model != "ST4000NM0035-1V4107" {
		t.Errorf("sdb: %+v", ids["sdb"])
	}
	if ids["sdc"].Serial != "WD-WCC7K0123456" || ids["sdc"].Model != "WDC WD40EFRX-68N32N0" {
		t.Errorf("sdc: %+v", ids["sdc"])
	}
	if ids["nvme0n1"].Serial != "S4EWNX0N123456" {
		t.Errorf("nvme: %+v", ids["nvme0n1"])
	}
	p := ids.diskPart("/dev/disk/by-id/ata-WDC_WD40EFRX-68N32N0_WD-WCC7K0654321-part3", "x")
	if p.Serial != "WD-WCC7K0654321" {
		t.Errorf("by-id path part: %+v", p)
	}
}
