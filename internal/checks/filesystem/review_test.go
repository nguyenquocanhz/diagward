package filesystem

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// No template may put a colon straight after a Windows drive letter
// ("Giải phóng dung lượng trên C:: ...").
func TestNoDoubleColonAfterDriveLetter(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows, testkit.S("filesystem.win_volume", testkit.Read(t, "win_volume_win10_mountpath.json")))
	res := check(t, b, testkit.Env(collect.OSWindows))
	f := testkit.Find(res, "filesystem.space_low", "C:")
	if f == nil {
		t.Fatalf("C: at 92%% not reported: %v", testkit.IDs(res))
	}
	for _, f := range res.Findings {
		for _, s := range []string{f.Title.EN, f.Title.VI, f.Detail.EN, f.Detail.VI, f.Action.EN, f.Action.VI} {
			if strings.Contains(s, "::") {
				t.Errorf("%s: %q", f.ID, s)
			}
		}
	}
	if !strings.HasPrefix(f.Title.VI, "Ổ C: đã đầy") || !strings.Contains(f.Action.EN, "StartComponentCleanup") {
		t.Errorf("boot drive wording: %q / %q", f.Title.VI, f.Action.EN)
	}
	// D: is a data drive: no Dism/cleanmgr advice
	b = testkit.Bundle(collect.OSWindows, testkit.S("filesystem.win_volume",
		`[{"DriveLetter":"D","FileSystemLabel":"SQL","FileSystem":"NTFS","DriveType":"Fixed","HealthStatus":"Healthy","Size":1000000000000,"SizeRemaining":20000000000,"Path":"\\\\?\\Volume{1}\\","MountPath":"D:\\","BootVolume":false},`+
			`{"DriveLetter":"C","FileSystemLabel":"","FileSystem":"NTFS","DriveType":"Fixed","HealthStatus":"Healthy","Size":100000000000,"SizeRemaining":50000000000,"Path":"\\\\?\\Volume{2}\\","MountPath":"C:\\","BootVolume":true}]`))
	res = check(t, b, testkit.Env(collect.OSWindows))
	if f := testkit.Find(res, "filesystem.space_low", "D:"); f == nil || strings.Contains(f.Action.EN, "Dism") || strings.Contains(f.Action.VI, "::") {
		t.Errorf("data drive: %+v", f)
	}
}

// Mounted-folder and CSV volumes have no drive letter but are real data
// volumes; System Reserved / Recovery partitions are nearly full by design.
func TestWindowsVolumesWithoutLetter(t *testing.T) {
	vols := `[` +
		`{"DriveLetter":"C","FileSystemLabel":"","FileSystem":"NTFS","DriveType":"Fixed","HealthStatus":"Healthy","OperationalStatus":["OK"],"Size":239511891968,"SizeRemaining":120000000000,"Path":"\\\\?\\Volume{c}\\","MountPath":"C:\\","BootVolume":true},` +
		`{"DriveLetter":"","FileSystemLabel":"Volume1","FileSystem":"CSVFS","DriveType":"Fixed","HealthStatus":"Healthy","OperationalStatus":["OK"],"Size":4000000000000,"SizeRemaining":40000000000,"Path":"\\\\?\\Volume{csv}\\","MountPath":"C:\\ClusterStorage\\Volume1\\"},` +
		`{"DriveLetter":"","FileSystemLabel":"LOGS","FileSystem":"ReFS","DriveType":"Fixed","HealthStatus":"Unhealthy","OperationalStatus":["Full Repair Needed"],"Size":500000000000,"SizeRemaining":250000000000,"Path":"\\\\?\\Volume{logs}\\","MountPath":"\\\\?\\Volume{logs}\\"},` +
		`{"DriveLetter":"E","FileSystemLabel":"System Reserved","FileSystem":"NTFS","DriveType":"Fixed","HealthStatus":"Healthy","OperationalStatus":["OK"],"Size":524288000,"SizeRemaining":10000000,"Path":"\\\\?\\Volume{sr}\\","MountPath":"E:\\","SystemVolume":true},` +
		`{"DriveLetter":"","FileSystemLabel":"","FileSystem":"FAT32","DriveType":"Fixed","HealthStatus":"Healthy","OperationalStatus":["OK"],"Size":100663296,"SizeRemaining":1000000,"Path":"\\\\?\\Volume{efi}\\","MountPath":"\\\\?\\Volume{efi}\\","SystemVolume":true}` +
		`]`
	dirty := `[{"DriveLetter":null,"Name":"C:\\ClusterStorage\\Volume1\\","DeviceID":"\\\\?\\Volume{csv}\\","DirtyBitSet":true}]`
	b := testkit.Bundle(collect.OSWindows, testkit.S("filesystem.win_volume", vols), testkit.S("filesystem.win_dirty", dirty))
	res := check(t, b, testkit.Env(collect.OSWindows))
	csv := `C:\ClusterStorage\Volume1`
	if f := testkit.Find(res, "filesystem.space_low", csv); f == nil || f.Severity != model.Crit || !strings.HasPrefix(f.Title.EN, "Volume "+csv) {
		t.Errorf("CSV volume at 99%%: %v", testkit.IDs(res))
	}
	if f := testkit.Find(res, "filesystem.dirty", csv); f == nil || !strings.Contains(f.Action.EN, "chkdsk "+csv+" /scan") {
		t.Errorf("dirty CSV: %v", testkit.IDs(res))
	}
	f := testkit.Find(res, "filesystem.volume_unhealthy", "LOGS")
	if f == nil || f.Severity != model.Crit || !strings.Contains(f.Action.EN, `Repair-Volume -Path '\\?\Volume{logs}\'`) {
		t.Errorf("unhealthy letter-less volume: %v %+v", testkit.IDs(res), f)
	}
	for _, f := range res.Findings {
		if f.ID == "filesystem.space_low" && (f.Target == "E:" || strings.Contains(f.Target, "efi") || f.Target == "LOGS") {
			t.Errorf("space alarm on %s", f.Target)
		}
	}
}

// Real Proxmox case (forum.proxmox.com thread 139255): the pool is 96 %
// full and VMs stopped, but df shows "/" at 52 % and the other datasets at
// 1 %. The pool must be reported once, not missed and not per dataset.
func TestZFSPoolFull(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("filesystem.df", testkit.Read(t, "df_zfs_pve_pool96.txt")),
		testkit.S("filesystem.mounts", testkit.Read(t, "proc_mounts_pve_zfs.txt")),
		testkit.S("raid.zpool_list", testkit.Read(t, "zpool_list_pve_pool96.txt")))
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "filesystem.space_low", "rpool")
	if f == nil || f.Severity != model.Crit || !strings.Contains(f.Title.EN, "96%") {
		t.Fatalf("pool: %v", testkit.IDs(res))
	}
	n := 0
	for _, f := range res.Findings {
		if f.ID == "filesystem.space_low" {
			n++
		}
	}
	if n != 1 || testkit.Find(res, "filesystem.space_ok") != nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "filesystem.space"); c == nil || strings.Contains(c.Reason.EN, "ZFS") {
		t.Errorf("coverage %+v", c)
	}
	fa := res.Facts.(*Facts)
	if len(fa.ZPools) != 1 || fa.ZPools[0].FreeBytes != 239<<30 {
		t.Errorf("zpools %+v", fa.ZPools)
	}
	// Without zpool list the space check says it is incomplete.
	b = testkit.Bundle(collect.OSLinux,
		testkit.S("filesystem.df", testkit.Read(t, "df_zfs_pve_pool96.txt")),
		testkit.S("filesystem.mounts", testkit.Read(t, "proc_mounts_pve_zfs.txt")))
	res = check(t, b, testkit.Env(collect.OSLinux))
	if c := testkit.Cov(res, "filesystem.space"); c == nil || c.State != model.CovPartial {
		t.Errorf("no zpool list: %+v", c)
	}
	// A quota-limited dataset on a roomy pool keeps its own check.
	df := "Filesystem Type 1-blocks Used Available Capacity Mounted on\n" +
		dfLine("tank/home", "zfs", "/home", 100<<30, 98<<30, 2<<30) + "\n" +
		dfLine("tank", "zfs", "/tank", 3000<<30, 1<<20, 3000<<30)
	b = testkit.Bundle(collect.OSLinux, testkit.S("filesystem.df", df),
		testkit.S("filesystem.mounts", "tank/home /home zfs rw 0 0\ntank /tank zfs rw 0 0"),
		testkit.S("raid.zpool_list", "tank\t7.25T\t2.10T\t5.15T\tONLINE\t3%\t28%\n"))
	res = check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "filesystem.space_low", "/home"); f == nil || f.Severity != model.Crit {
		t.Errorf("quota dataset: %v", testkit.IDs(res))
	}
	if testkit.Find(res, "filesystem.space_low", "tank") != nil {
		t.Errorf("pool at 28%% flagged")
	}
}

func TestZpoolListParse(t *testing.T) {
	p := parseZpoolList("rpool\t7.25T\t7.02T\t239G\tONLINE\t82%\t96%\nNAME SIZE\ngarbage\nbad\t1\t2\t3\tONLINE\t-\tx%\n")
	if len(p) != 1 || p[0].CapPct != 96 || p[0].SizeBytes != uint64(7.25*(1<<40)) {
		t.Errorf("%+v", p)
	}
	for in, want := range map[string]uint64{"512": 512, "1.5K": 1536, "-": 0, "": 0, "10M": 10 << 20, "x": 0} {
		if got := humanBytes(in); got != want {
			t.Errorf("%q = %d, want %d", in, got, want)
		}
	}
}

// GNU df prints "no file systems processed" (rc 1) when every mount is
// excluded (container on overlay): that is not a failed check.
func TestDFNothingLocal(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux,
		testkit.RC("filesystem.df", 1, "", "df: no file systems processed\n"),
		testkit.S("filesystem.mounts", "overlay / overlay rw,relatime,lowerdir=/x 0 0\ntmpfs /dev tmpfs rw 0 0"))
	env := testkit.Env(collect.OSLinux)
	env.Container, env.Virtual = true, "docker"
	res := check(t, b, env)
	if c := testkit.Cov(res, "filesystem.space"); c == nil || c.State != model.CovSkipped {
		t.Errorf("space %+v", c)
	}
}

func TestFstabNofailAndCmd(t *testing.T) {
	mounts := "/dev/sda1 / xfs rw 0 0"
	fstab := "UUID=2c839365-37c7-4bd5-ac47-040fba761735 /data xfs defaults,nofail 0 2\n" +
		"//nas/backup /mnt/nas cifs credentials=/root/.smb,nofail 0 0\n" +
		"LABEL=usb /mnt/usb ext4 noauto 0 0\n"
	b := rhelBundle(t, mounts, testkit.S("filesystem.fstab", fstab), testkit.Missing("filesystem.tune2fs", "tune2fs"))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "filesystem.fstab_unmounted", "/data"); f == nil || f.Severity != model.Info || !strings.Contains(f.Detail.EN, "nofail") {
		t.Errorf("nofail data disk: %v", testkit.IDs(res))
	}
	if testkit.Find(res, "filesystem.fstab_unmounted", "/mnt/nas") != nil || testkit.Find(res, "filesystem.fstab_unmounted", "/mnt/usb") != nil {
		t.Errorf("nofail share / noauto reported: %v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "filesystem.health"); c == nil || c.Cmd != "dnf install -y e2fsprogs" || strings.Contains(c.Fix.EN, "dnf") {
		t.Errorf("cmd %+v", c)
	}
}

// health_ok counts filesystems, not the second read-only view WSL mounts.
func TestHealthOKCountsFilesystems(t *testing.T) {
	m := "/dev/sdd / ext4 rw,relatime 0 0\n/dev/sdd /mnt/wslg/distro ext4 ro,relatime 0 0"
	res := check(t, rhelBundle(t, m), testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "filesystem.health_ok"); f == nil || !strings.HasPrefix(f.Title.EN, "1 filesystem") {
		t.Errorf("%+v", f)
	}
}
