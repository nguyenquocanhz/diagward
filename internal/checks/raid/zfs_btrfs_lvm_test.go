package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func zfs(t *testing.T, status string, extra ...*collect.Section) model.Result {
	t.Helper()
	secs := append([]*collect.Section{testkit.S("raid.zpool_status", testkit.Read(t, status))}, extra...)
	return run(t, collect.OSLinux, secs...)
}

func TestZFSHealthy(t *testing.T) {
	res := zfs(t, "zpool_status_scrub_recent.txt", testkit.S("raid.zpool_list", testkit.Read(t, "zpool_list_rpool.txt")))
	noWorseThan(t, res, model.OK)
	want(t, res, "raid.zfs_ok", "rpool", model.OK)
	cov(t, res, "raid.zfs", model.CovRan)
	tb := table(t, res, "raid.arrays")
	r := tb.Rows[0].Cells
	if r[0] != "rpool" || r[1] != "zfs mirror" || r[2] != "3.62T" || !strings.Contains(r[3], "41% used") {
		t.Errorf("row: %v", r)
	}
	p := res.Facts.(*Facts).ZFS[0]
	if len(p.Vdevs) != 4 || !p.Vdevs[2].Leaf || !p.Vdevs[3].Leaf || p.Vdevs[1].Leaf || p.Vdevs[2].Parent != "mirror-0" {
		t.Errorf("vdevs: %+v", p.Vdevs)
	}
}

func TestZFSScrubOld(t *testing.T) {
	// Completed resilver only (no scrub date): no age note; then a scrub
	// line older than 35 days.
	res := zfs(t, "zpool_status_healthy.txt")
	want(t, res, "raid.zfs_ok", "testpool", model.OK)
	none(t, res, "raid.zfs_scrub_old")

	old := strings.Replace(testkit.Read(t, "zpool_status_scrub_recent.txt"), "Sun Sep 13 00:36:42 2026", "Sun Jul  5 00:36:42 2026", 1)
	res = run(t, collect.OSLinux, testkit.S("raid.zpool_status", old))
	f := want(t, res, "raid.zfs_scrub_old", "rpool", model.Info)
	if !strings.Contains(f.Title.EN, "2 months") {
		t.Errorf("title: %q", f.Title.EN)
	}
	want(t, res, "raid.zfs_ok", "rpool", model.OK)
}

func TestZFSOffline(t *testing.T) {
	res := zfs(t, "zpool_status_offline.txt")
	want(t, res, "raid.zfs_pool_degraded", "testpool", model.Crit)
	want(t, res, "raid.zfs_device_offline", "testpool//mnt/poolfiles/file0", model.Warn)
}

func TestZFSUnavail(t *testing.T) {
	res := zfs(t, "zpool_status_unavail.txt")
	want(t, res, "raid.zfs_pool_degraded", "testpool", model.Crit)
	f := want(t, res, "raid.zfs_device_failed", "testpool//mnt/poolfiles/file0", model.Crit)
	if f.Part == nil || f.Part.Kind != "disk" || !strings.Contains(f.Detail.EN, "corrupted data") {
		t.Errorf("finding: %+v", f)
	}
}

func TestZFSFaultedOldFormat(t *testing.T) {
	res := zfs(t, "zpool_status_faulted_2q.txt")
	want(t, res, "raid.zfs_pool_degraded", "test", model.Crit)
	want(t, res, "raid.zfs_device_failed", "test/sdb", model.Crit)
	// "scrub: none requested" is only mentioned for otherwise healthy pools.
	none(t, res, "raid.zfs_scrub_old")
}

func TestZFSDataErrors(t *testing.T) {
	res := zfs(t, "zpool_status_data_errors.txt")
	want(t, res, "raid.zfs_data_errors", "test", model.Crit)
	want(t, res, "raid.zfs_device_errors", "test/sda", model.Warn)
	none(t, res, "raid.zfs_ok", "raid.zfs_pool_degraded")
}

func TestZFSResilver(t *testing.T) {
	res := zfs(t, "zpool_status_resilver.txt")
	f := want(t, res, "raid.zfs_resilver", "rpool", model.Warn)
	if !strings.Contains(f.Title.EN, "6.9%") || !strings.Contains(f.Title.EN, "0 days 00:28:33") {
		t.Errorf("title: %q", f.Title.EN)
	}
	// The old disk is being replaced (replacing-1): Warn, with its serial.
	d := want(t, res, "raid.zfs_device_failed", "rpool/ata-Crucial_CT256MX100SSD1_15010E47F61C-part2", model.Warn)
	if d.Part == nil || d.Part.Serial != "15010E47F61C" || d.Part.Model != "Crucial CT256MX100SSD1" {
		t.Errorf("part: %+v", d.Part)
	}
	want(t, res, "raid.zfs_device_errors", "rpool/ata-CT500MX500SSD1_2004E2856102-part4", model.Warn)
	want(t, res, "raid.zfs_data_errors", "rpool", model.Crit)
	none(t, res, "raid.zfs_pool_degraded")
}

func TestZFSListOnlyFaulted(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.zpool_status", testkit.Read(t, "zpool_status_healthy.txt")),
		testkit.S("raid.zpool_list", testkit.Read(t, "zpool_list_faulted.txt")))
	want(t, res, "raid.zfs_pool_faulted", "zion", model.Crit)
	want(t, res, "raid.zfs_ok", "testpool", model.OK)
}

func TestZFSNoPoolsAndMissing(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.RC("raid.zpool_status", 0, "no pools available\n", ""))
	if len(res.Coverage)+len(res.Findings) != 0 {
		t.Errorf("no pools must be silent: %v", res.Coverage)
	}
	res = run(t, collect.OSLinux, testkit.Missing("raid.zpool_status", "zpool"))
	c := cov(t, res, "raid.zfs", model.CovSkipped)
	if c.Cmd != "dnf install -y zfs" || c.Fix.IsZero() {
		t.Errorf("fix: %q cmd: %q", c.Fix.EN, c.Cmd)
	}
	res = run(t, collect.OSLinux, testkit.RC("raid.zpool_status", 1, "", "internal error: something broke"))
	cov(t, res, "raid.zfs", model.CovFailed)
}

func TestBtrfsHealthyAndMissing(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.btrfs_show", testkit.Read(t, "wsl_btrfs_show_ok.txt")),
		testkit.S("raid.btrfs_stats:/root/dwmnt", testkit.Read(t, "wsl_btrfs_stats_ok.txt")))
	noWorseThan(t, res, model.OK)
	want(t, res, "raid.btrfs_ok", "dwdata (/root/dwmnt)", model.OK)
	cov(t, res, "raid.btrfs", model.CovRan)

	res = run(t, collect.OSLinux, testkit.S("raid.btrfs_show", testkit.Read(t, "wsl_btrfs_show_missing.txt")))
	want(t, res, "raid.btrfs_missing", "dwdata", model.Crit)

	res = run(t, collect.OSLinux,
		testkit.S("raid.btrfs_show", testkit.Read(t, "wsl_btrfs_show_degraded_mounted.txt")),
		testkit.S("raid.btrfs_stats:/root/dwmnt", testkit.Read(t, "wsl_btrfs_stats_degraded.txt")))
	want(t, res, "raid.btrfs_missing", "dwdata (/root/dwmnt)", model.Crit)
	fs := res.Facts.(*Facts).Btrfs[0]
	if len(fs.Devices) != 2 || !fs.Devices[1].Missing || fs.Devices[1].Stats == nil {
		t.Errorf("devices: %+v %+v", fs.Devices[0], fs.Devices[1])
	}
}

func TestBtrfsErrors(t *testing.T) {
	res := run(t, collect.OSLinux,
		testkit.S("raid.btrfs_show", testkit.Read(t, "btrfs_show_sdb_sdc.txt")),
		testkit.S("raid.btrfs_stats:/srv/data", testkit.Read(t, "btrfs_stats_errors.txt")),
		testkit.S("raid.byid", testkit.Read(t, "byid_sdb_sdc.txt")))
	f := want(t, res, "raid.btrfs_dev_errors", "/dev/sdc", model.Warn)
	if f.Part == nil || f.Part.Serial != "WD-WCC7K0123456" || !strings.Contains(f.Title.EN, "read_io_errs=17") || !strings.Contains(f.Action.EN, "btrfs device stats -z /srv/data") {
		t.Errorf("finding: %+v / %+v", f.Title, f.Part)
	}
	none(t, res, "raid.btrfs_ok", "raid.btrfs_missing")
}

func TestBtrfsToolAndRoot(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.Missing("raid.btrfs_show", "btrfs"))
	c := cov(t, res, "raid.btrfs", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "btrfs-progs") {
		t.Errorf("fix: %q", c.Fix.EN)
	}
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res = runEnv(t, env, testkit.Skipped("raid.btrfs_show", "not-root"))
	c = cov(t, res, "raid.btrfs", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "sudo") {
		t.Errorf("fix: %q", c.Fix.EN)
	}
}

func TestLVMJson(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.lvs", testkit.Read(t, "wsl_lvs_json_ok.txt")))
	noWorseThan(t, res, model.OK)
	want(t, res, "raid.lvm_ok", "dwvg/dwlv", model.OK)
	cov(t, res, "raid.lvm", model.CovRan)
	if n := len(res.Facts.(*Facts).LVM); n != 1 {
		t.Errorf("only the top-level raid LV should be listed, got %d", n)
	}
	if lv := res.Facts.(*Facts).LVM[0]; strings.Join(lv.PVs, " ") != "/dev/loop2 /dev/loop3" {
		t.Errorf("pvs: %v", lv.PVs)
	}

	res = run(t, collect.OSLinux, testkit.S("raid.lvs", testkit.Read(t, "wsl_lvs_json_sync.txt")))
	f := want(t, res, "raid.lvm_syncing", "dwvg/dwlv", model.Warn)
	if !strings.Contains(f.Title.EN, "12.6%") {
		t.Errorf("title: %q", f.Title.EN)
	}

	res = run(t, collect.OSLinux, testkit.S("raid.lvs", testkit.Read(t, "wsl_lvs_json_check.txt")))
	want(t, res, "raid.lvm_check", "dwvg/dwlv", model.Info)
	none(t, res, "raid.lvm_syncing")

	res = run(t, collect.OSLinux, testkit.S("raid.lvs", testkit.Read(t, "wsl_lvs_json_partial.txt")))
	p := want(t, res, "raid.lvm_partial", "dwvg/dwlv", model.Crit)
	if p.Part == nil || !strings.Contains(p.Part.Location, "/dev/loop3") || !strings.Contains(p.Detail.EN, "/dev/loop3") {
		t.Errorf("partial: %+v %+v", p.Detail, p.Part)
	}
}

func TestLVMTextFallback(t *testing.T) {
	// The collector's old-LVM fallback: copy_percent, no health column.
	var b strings.Builder
	b.WriteString("#fields=lv_name,vg_name,segtype,copy_percent,lv_attr,devices\n")
	for _, l := range lines(testkit.Read(t, "wsl_lvs_text_partial.txt")) {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) != 8 {
			continue
		}
		b.WriteString("  " + strings.Join([]string{f[0], f[1], f[2], f[4], f[6], f[7]}, "|") + "\n")
	}
	errOut := "  WARNING: VG dwvg is missing PV 3Kx4vM-JpV9-SPsF-mpk6-btDj-XVKX-zgzF6G (last written to /dev/loop3).\n"
	res := run(t, collect.OSLinux, testkit.RC("raid.lvs", 0, b.String(), errOut))
	want(t, res, "raid.lvm_partial", "dwvg/dwlv", model.Crit) // from lv_attr bit 9 'p'

	res = run(t, collect.OSLinux, testkit.S("raid.lvs", "#fields=lv_name,vg_name,segtype,copy_percent,lv_attr,devices\n  mir|vg0|mirror|45.00|mwi-a-m---|mir_mimage_0(0),mir_mimage_1(0)\n"))
	want(t, res, "raid.lvm_syncing", "vg0/mir", model.Warn)
}

func TestLVMRefreshAndToolStates(t *testing.T) {
	js := strings.Replace(testkit.Read(t, "wsl_lvs_json_ok.txt"), `"lv_health_status":"", "sync_percent":"100.00", "raid_mismatch_count":"0"`, `"lv_health_status":"refresh needed", "sync_percent":"100.00", "raid_mismatch_count":"16"`, 1)
	res := run(t, collect.OSLinux, testkit.S("raid.lvs", js))
	want(t, res, "raid.lvm_refresh_needed", "dwvg/dwlv", model.Crit)
	want(t, res, "raid.lvm_mismatch", "dwvg/dwlv", model.Info)

	res = run(t, collect.OSLinux, testkit.Missing("raid.lvs", "lvs"))
	cov(t, res, "raid.lvm", model.CovSkipped)
	res = run(t, collect.OSLinux, testkit.RC("raid.lvs", 5, "", "  Unrecognised field: raid_sync_action"))
	cov(t, res, "raid.lvm", model.CovFailed)
}
