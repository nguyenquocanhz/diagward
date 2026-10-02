package filesystem

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func check(t *testing.T, b *collect.Bundle, env model.Env) model.Result {
	t.Helper()
	res := Check(b, env)
	testkit.Validate(t, res)
	return res
}

func load(t *testing.T, name string) *collect.Bundle {
	t.Helper()
	b, err := collect.Read(strings.NewReader(testkit.Read(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Real collector output from WSL (kernel 6.18) with three loop-mounted ext4
// filesystems: one filled to 100 %, one with error counters set in the
// superblock, one remounted read-only by the kernel after a real lookup
// error (shown as "emergency_ro" by kernels >= 6.6).
func TestWSLLoopFilesystems(t *testing.T) {
	b := load(t, "wsl_loopfs.json")
	env := collect.EnvOf(b)
	res := check(t, b, env)

	if f := testkit.Find(res, "filesystem.space_low", "/mnt/dwfull"); f == nil || f.Severity != model.Crit {
		t.Errorf("full fs: %v", testkit.IDs(res))
	}
	ro := testkit.Find(res, "filesystem.readonly", "/mnt/dwro")
	if ro == nil || ro.Severity != model.Crit || !strings.Contains(ro.Detail.EN, "emergency_ro") || !strings.Contains(ro.Detail.EN, "1 error") {
		t.Errorf("emergency_ro: %v %+v", testkit.IDs(res), ro)
	}
	if testkit.Find(res, "filesystem.ext4_errors", "/mnt/dwro") != nil {
		t.Error("read-only fs reported twice")
	}
	e := testkit.Find(res, "filesystem.ext4_errors", "/mnt/dwerr")
	if e == nil || e.Severity != model.Crit || !strings.Contains(strings.Join(e.Evidence, "\n"), "clean with errors") {
		t.Errorf("ext4 errors: %+v", e)
	}
	// "/" is fine; /mnt/wslg/distro is a read-only second view of /dev/sdd.
	for _, f := range res.Findings {
		if f.Target == "/" || f.Target == "/mnt/wslg/distro" {
			t.Errorf("false finding %s on %s", f.ID, f.Target)
		}
	}
	for _, id := range []string{"filesystem.space", "filesystem.health"} {
		if c := testkit.Cov(res, id); c == nil || c.State != model.CovRan {
			t.Errorf("%s: %+v", id, c)
		}
	}
	// A month later the recorded (not recent) errors are a Warn.
	env.Now = env.Now.Add(30 * 24 * time.Hour)
	res = check(t, b, env)
	if e := testkit.Find(res, "filesystem.ext4_errors", "/mnt/dwerr"); e == nil || e.Severity != model.Warn {
		t.Errorf("old errors: %+v", e)
	}
	fa := res.Facts.(*Facts)
	if len(fa.Filesystems) != 4 {
		t.Errorf("filesystems %+v", fa.Filesystems)
	}
}

func rhelBundle(t *testing.T, mounts string, extra ...*collect.Section) *collect.Bundle {
	secs := append([]*collect.Section{testkit.S("filesystem.mounts", mounts)}, extra...)
	return testkit.Bundle(collect.OSLinux, secs...)
}

func TestReadOnlyOldKernel(t *testing.T) {
	// Kernels before 6.6 flip the mount to "ro".
	b := rhelBundle(t, testkit.Read(t, "proc_mounts_rhel6_var_ro.txt"))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "filesystem.readonly", "/var"); f == nil || f.Severity != model.Crit {
		t.Fatalf("findings %v", testkit.IDs(res))
	}
	// read-only on purpose in fstab: nothing
	b = rhelBundle(t, testkit.Read(t, "proc_mounts_rhel6_var_ro.txt"),
		testkit.S("filesystem.fstab", "/dev/mapper/rootvg-varlv /var ext4 ro,defaults 1 2\n"))
	if f := testkit.Find(check(t, b, testkit.Env(collect.OSLinux)), "filesystem.readonly"); f != nil {
		t.Errorf("intentional ro flagged: %+v", f)
	}
	// healthy original
	b = rhelBundle(t, testkit.Read(t, "proc_mounts_rhel6.txt"))
	res = check(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "filesystem.health_ok") == nil {
		t.Errorf("healthy: %v", testkit.IDs(res))
	}
	// a non-system mount, not in fstab: Info
	m := testkit.Read(t, "proc_mounts_rhel6.txt") + "\n/dev/sdz1 /mnt/rescue ext4 ro,relatime 0 0"
	res = check(t, rhelBundle(t, m), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "filesystem.mounted_ro", "/mnt/rescue"); f == nil || f.Severity != model.Info {
		t.Errorf("rescue mount: %v", testkit.IDs(res))
	}
	// in a container a read-only data mount is normal
	m = testkit.Read(t, "proc_mounts_rhel6.txt") + "\n/dev/sdz1 /data ext4 ro,relatime 0 0"
	env := testkit.Env(collect.OSLinux)
	env.Container, env.Virtual = true, "docker"
	if f := testkit.Find(check(t, rhelBundle(t, m), env), "filesystem.readonly"); f != nil {
		t.Errorf("container ro mount flagged Crit: %+v", f)
	}
}

func TestFstabUnmounted(t *testing.T) {
	mounts := strings.Join([]string{
		"/dev/mapper/rhel_hadoop--test--1-root / xfs rw,relatime,attr2,inode64,noquota 0 0",
		"/dev/sda1 /boot xfs rw,relatime,attr2,inode64,noquota 0 0",
		"/dev/mapper/rhel_hadoop--test--1-home /home xfs rw,relatime,attr2,inode64,noquota 0 0",
		"/dev/sdb1 /hdfs/data1 xfs rw,relatime,seclabel,attr2,inode64,noquota 0 0",
		"/dev/sdc1 /hdfs/data2 xfs rw,relatime,seclabel,attr2,inode64,noquota 0 0",
		"proc /proc proc rw,relatime 0 0",
	}, "\n")
	b := rhelBundle(t, mounts, testkit.S("filesystem.fstab", testkit.Read(t, "fstab_rhel7_hadoop.txt")))
	res := check(t, b, testkit.Env(collect.OSLinux))
	want := map[string]model.Severity{"/hdfs/data3": model.Warn, "/test1": model.Warn, "/mnt/hdfs": model.Info, "/srv/rdu/data/000": model.Info}
	for p, sev := range want {
		if f := testkit.Find(res, "filesystem.fstab_unmounted", p); f == nil || f.Severity != sev {
			t.Errorf("%s: %v", p, testkit.IDs(res))
		}
	}
	for _, f := range res.Findings {
		if f.ID == "filesystem.fstab_unmounted" {
			if _, ok := want[f.Target]; !ok {
				t.Errorf("unexpected %s", f.Target)
			}
		}
	}
	if testkit.Find(res, "filesystem.health_ok") != nil {
		t.Error("health_ok despite a missing disk mount")
	}
}

func TestDFParsers(t *testing.T) {
	rows, unit := parseDF(testkit.Read(t, "df_busybox_wsl.txt"))
	if unit != 1024 || len(rows) < 25 {
		t.Fatalf("busybox: unit %d rows %d", unit, len(rows))
	}
	irows, iunit := parseDF(testkit.Read(t, "df_i_busybox_wsl.txt"))
	if iunit != 1 {
		t.Errorf("inode unit %d", iunit)
	}
	for _, r := range irows {
		if r.Point == "/mnt/c" || r.Point == "/usr/lib/wsl/drivers" {
			t.Errorf("garbage 9p inode row kept: %+v", r)
		}
	}
	rows, _ = parseDF(testkit.Read(t, "df_alP_insights.txt"))
	if len(rows) != 9 || rows[0].Point != "/" || rows[0].Total != 98571884 {
		t.Errorf("df -alP: %d rows %+v", len(rows), rows)
	}
	rows, _ = parseDF(testkit.Read(t, "df_li_insights.txt"))
	found := false
	for _, r := range rows {
		if r.Point == "/V M T o o l s" && r.Avail == 1499678 {
			found = true
		}
	}
	if !found {
		t.Errorf("mount point with spaces lost: %+v", rows)
	}
}

func TestBusyBoxDF(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("filesystem.df", testkit.Read(t, "df_busybox_wsl.txt")),
		testkit.S("filesystem.df_inodes", testkit.Read(t, "df_i_busybox_wsl.txt")),
		testkit.S("filesystem.mounts", testkit.Read(t, "proc_mounts_busybox_wsl.txt")))
	env := testkit.Env(collect.OSLinux)
	env.Container, env.Virtual = true, "wsl"
	res := check(t, b, env)
	if f := testkit.Find(res, "filesystem.space_low", "/mnt/dwfull"); f == nil || f.Severity != model.Crit {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	fa := res.Facts.(*Facts)
	var mounts []string
	for _, fs := range fa.Filesystems {
		mounts = append(mounts, fs.Mount)
	}
	if strings.Join(mounts, ",") != "/,/mnt/dwerr,/mnt/dwfull,/mnt/dwro" {
		t.Errorf("filesystems %v (tmpfs, 9p and duplicate views must be filtered)", mounts)
	}
	if fa.Filesystems[0].SizeBytes != 1055762868*1024 {
		t.Errorf("size %d", fa.Filesystems[0].SizeBytes)
	}
}

func dfLine(dev, typ, point string, total, used, avail uint64) string {
	return strings.Join([]string{dev, typ, u64(total), u64(used), u64(avail), "0%", point}, " ")
}

func u64(n uint64) string {
	s := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestSpaceThresholds(t *testing.T) {
	const GB = 1000 * 1000 * 1000
	df := "Filesystem Type 1-blocks Used Available Capacity Mounted on\n" +
		dfLine("/dev/sda2", "xfs", "/", 50*GB, 45.5*GB, 4.5*GB) + "\n" + // 91 %
		dfLine("/dev/sdb1", "ext4", "/var/lib/mysql", 500*GB, 480*GB, 10*GB) + "\n" + // 98 %
		dfLine("/dev/md0", "xfs", "/backup", 100000*GB, 98000*GB, 2000*GB) + "\n" + // 98 % but 2 TB free
		dfLine("/dev/sdc1", "ext4", "/srv", 100*GB, 10*GB, 90*GB)
	ino := "Filesystem Type Inodes IUsed IFree IUse% Mounted on\n" +
		dfLine("/dev/sda2", "xfs", "/", 1000000, 100000, 900000) + "\n" +
		dfLine("/dev/sdc1", "ext4", "/srv", 6553600, 6200000, 353600)
	b := testkit.Bundle(collect.OSLinux, testkit.S("filesystem.df", df), testkit.S("filesystem.df_inodes", ino),
		testkit.S("filesystem.mounts", "/dev/sda2 / xfs rw 0 0\n/dev/sdb1 /var/lib/mysql ext4 rw 0 0\n/dev/md0 /backup xfs rw 0 0\n/dev/sdc1 /srv ext4 rw 0 0"))
	res := check(t, b, testkit.Env(collect.OSLinux))
	want := map[string]model.Severity{"/": model.Warn, "/var/lib/mysql": model.Crit, "/backup": model.Warn}
	for p, sev := range want {
		if f := testkit.Find(res, "filesystem.space_low", p); f == nil || f.Severity != sev {
			t.Errorf("%s: %v", p, testkit.IDs(res))
		}
	}
	if testkit.Find(res, "filesystem.space_low", "/srv") != nil {
		t.Error("/srv flagged")
	}
	if f := testkit.Find(res, "filesystem.inodes_low", "/srv"); f == nil || f.Severity != model.Warn {
		t.Errorf("inodes: %v", testkit.IDs(res))
	}
	if testkit.Find(res, "filesystem.space_ok") != nil {
		t.Error("space_ok with full filesystems")
	}
	if len(res.Tables) != 1 || len(res.Tables[0].Rows) != 4 {
		t.Errorf("table %+v", res.Tables)
	}
}

func TestCoverageStates(t *testing.T) {
	mounts := "/dev/sda1 / ext4 rw,relatime 0 0"
	b := testkit.Bundle(collect.OSLinux, testkit.S("filesystem.mounts", mounts), testkit.Skipped("filesystem.tune2fs", "not-root"),
		&collect.Section{Name: "filesystem.df", RC: 124, Timeout: true})
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res := check(t, b, env)
	if c := testkit.Cov(res, "filesystem.health"); c == nil || c.State != model.CovPartial {
		t.Errorf("health %+v", c)
	}
	if c := testkit.Cov(res, "filesystem.space"); c == nil || c.State != model.CovFailed || !strings.Contains(c.Reason.EN, "timed out") {
		t.Errorf("space %+v", c)
	}
	b = testkit.Bundle(collect.OSLinux, testkit.S("filesystem.mounts", mounts), testkit.Missing("filesystem.tune2fs", "tune2fs"))
	if c := testkit.Cov(check(t, b, testkit.Env(collect.OSLinux)), "filesystem.health"); c == nil || c.State != model.CovPartial || !strings.Contains(c.Fix.EN, "e2fsprogs") {
		t.Errorf("missing tune2fs %+v", c)
	}
}

func TestWindowsReal(t *testing.T) {
	b := load(t, "win10.json")
	res := check(t, b, collect.EnvOf(b))
	f := testkit.Find(res, "filesystem.space_low", "C:")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Action.EN, "cleanmgr") {
		t.Errorf("C: %v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "filesystem.health"); c == nil || c.State != model.CovPartial {
		t.Errorf("health %+v", c)
	}
	for _, fs := range res.Facts.(*Facts).Filesystems {
		if fs.Mount == ":" || fs.Mount == "" {
			t.Error("volume without a drive letter included")
		}
	}
}

func TestWindowsSynthetic(t *testing.T) {
	vols := `[` +
		`{"DriveLetter":"C","FileSystemLabel":"OS","FileSystem":"NTFS","DriveType":"Fixed","HealthStatus":"Healthy","OperationalStatus":["OK"],"Size":239511891968,"SizeRemaining":120000000000},` +
		`{"DriveLetter":"D","FileSystemLabel":"DATA","FileSystem":"NTFS","DriveType":3,"HealthStatus":2,"OperationalStatus":[53263],"Size":4000000000000,"SizeRemaining":2000000000000},` +
		`{"DriveLetter":"E","FileSystemLabel":"LOGS","FileSystem":"ReFS","DriveType":"Fixed","HealthStatus":"Warning","OperationalStatus":["Scan Needed"],"Size":100000000000,"SizeRemaining":50000000000},` +
		`{"DriveLetter":"F","FileSystemLabel":"USB","FileSystem":"FAT32","DriveType":"Removable","HealthStatus":"Healthy","Size":16000000000,"SizeRemaining":10000},` +
		`{"DriveLetter":"","FileSystemLabel":"Recovery","FileSystem":"NTFS","DriveType":"Fixed","HealthStatus":"Healthy","Size":688910336,"SizeRemaining":88145920}` +
		`]`
	dirty := `[{"DriveLetter":"C:","Name":"C:\\","DirtyBitSet":true},{"DriveLetter":"D:","Name":"D:\\","DirtyBitSet":false}]`
	b := testkit.Bundle(collect.OSWindows, testkit.S("filesystem.win_volume", vols), testkit.S("filesystem.win_dirty", dirty))
	res := check(t, b, testkit.Env(collect.OSWindows))
	want := map[string]string{"filesystem.volume_unhealthy@D:": "crit", "filesystem.volume_unhealthy@E:": "warn", "filesystem.dirty@C:": "warn"}
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.ID+"@"+f.Target] = f.Severity.String()
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q (all: %v)", k, got[k], testkit.IDs(res))
		}
	}
	if f := testkit.Find(res, "filesystem.volume_unhealthy", "D:"); f != nil && !strings.Contains(f.Title.EN, "Full Repair Needed") {
		t.Errorf("numeric operational status not mapped: %s", f.Title.EN)
	}
	for _, f := range res.Findings {
		if f.Target == "F:" {
			t.Error("removable drive analysed")
		}
	}
	if c := testkit.Cov(res, "filesystem.health"); c == nil || c.State != model.CovRan {
		t.Errorf("health %+v", c)
	}
}

func TestGarbage(t *testing.T) {
	if res := Check(testkit.Bundle(collect.OSLinux), testkit.Env(collect.OSLinux)); len(res.Coverage) != 0 {
		t.Errorf("coverage without sections")
	}
	files := []string{"df_busybox_wsl.txt", "df_alP_insights.txt", "proc_mounts_rhel6_var_ro.txt", "fstab_rhel7_hadoop.txt", "win10.json"}
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 400; i++ {
		src := testkit.Read(t, files[rng.Intn(len(files))])
		cut := src[:rng.Intn(len(src)+1)]
		junk := make([]byte, rng.Intn(300))
		for j := range junk {
			junk[j] = byte(rng.Intn(256))
		}
		pick := func() string {
			if rng.Intn(2) == 0 {
				return cut
			}
			return string(junk) + "\n/dev/sda1 / ext4 ro,emergency_ro 0 0\n/sys/fs/ext4/sda1/errors_count=" + string(junk[:min(len(junk), 5)])
		}
		b := testkit.Bundle(collect.OSLinux,
			testkit.S("filesystem.df", pick()), testkit.S("filesystem.df_inodes", pick()), testkit.S("filesystem.mounts", pick()),
			testkit.S("filesystem.fstab", pick()), testkit.S("filesystem.ext4", pick()), testkit.S("filesystem.tune2fs:/dev/sda1", pick()))
		check(t, b, testkit.Env(collect.OSLinux))
		wb := testkit.Bundle(collect.OSWindows, testkit.S("filesystem.win_volume", pick()), testkit.S("filesystem.win_dirty", pick()))
		check(t, wb, testkit.Env(collect.OSWindows))
	}
}
