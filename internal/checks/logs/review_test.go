package logs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// journal builds a logs.kernel_match section in the collector's format.
func journal(lines ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# source=journal persistent=1 tz=+0000 max=3000 total=%d\n", len(lines))
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString("# rc=0\n# source=journal persistent=1 tz=+0000 max=3000 total=0 class=noise\n")
	return b.String()
}

// at formats a journal timestamp relative to the test clock.
func at(env model.Env, ago time.Duration) string {
	return env.Now.Add(-ago).UTC().Format("2006-01-02T15:04:05+00:00")
}

// Real CPER record (IBM ESS 3500 support page, see SOURCES.md): the GHES
// PCIe section names the device, so the finding must too.
func TestGHESPCIeDeviceNamed(t *testing.T) {
	env := linuxEnv()
	env.Now = time.Unix(1790700000+3600, 0).UTC()
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", testkit.Read(t, "linux_ghes_pcie_ibm.txt")))
	f := want(t, res, "logs.pcie_corrected", "0000:02:00.0", model.Info)
	if strings.Contains(f.Title.EN, "PCIe device PCIe") {
		t.Errorf("title %s", f.Title.EN)
	}
}

// A GHES PCIe record without device_id must not read "PCIe device PCIe".
func TestGHESPCIeUnnamed(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.kernel_match", testkit.Read(t, "linux_ghes.txt")))
	f := want(t, res, "logs.pcie_uncorrected", "PCIe", model.Warn)
	if !strings.Contains(f.Title.EN, "(not named in the log)") || !strings.Contains(f.Title.VI, "(log không ghi rõ)") {
		t.Errorf("title %s / %s", f.Title.EN, f.Title.VI)
	}
	m := want(t, res, "logs.memory_corrected", "memory", model.Warn)
	if strings.Contains(m.Title.EN, ": memory") {
		t.Errorf("title %s", m.Title.EN)
	}
}

// Real lines of a USB disk failing on a 3.x kernel (LKML, "Buffer I/O error
// after s2ram with usb storage"): I/O errors on a USB disk are a Warn, with
// no server part to replace.
func TestLinuxUSBDiskFromLog(t *testing.T) {
	env := linuxEnv()
	env.Now = time.Unix(1790700000+600, 0).UTC()
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", testkit.Read(t, "linux_usb_dmesg.txt")))
	f := want(t, res, "logs.disk_io_error", "/dev/sdb", model.Warn)
	if f.Part != nil || !strings.Contains(f.Detail.EN, "USB disk") || !strings.Contains(f.Action.VI, "ổ USB") {
		t.Errorf("usb disk: part %+v, %s / %s", f.Part, f.Detail.EN, f.Action.VI)
	}
}

// Arch Linux forum (bbs.archlinux.org 207447) attach lines of a USB stick
// on a 4.x+ kernel ("scsi host11: usb-storage", "Attached SCSI removable
// disk"), then I/O errors in the current block-layer format.
func TestLinuxUSBRemovable(t *testing.T) {
	env := linuxEnv()
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(
		at(env, 2*time.Hour)+" h kernel: usb-storage 2-1.6:1.0: USB Mass Storage device detected",
		at(env, 2*time.Hour)+" h kernel: scsi host11: usb-storage 2-1.6:1.0",
		at(env, 2*time.Hour)+" h kernel: sd 11:0:0:0: [sdc] Attached SCSI removable disk",
		at(env, time.Hour)+" h kernel: I/O error, dev sdc, sector 2048 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 2",
		at(env, time.Hour)+" h kernel: Buffer I/O error on dev sdc1, logical block 0, async page read",
		// A UAS enclosure on the same host: "scsi host7: uas".
		at(env, 2*time.Hour)+" h kernel: scsi host7: uas",
		at(env, 2*time.Hour)+" h kernel: sd 7:0:0:0: [sdd] Attached SCSI disk",
		at(env, time.Hour)+" h kernel: blk_update_request: critical medium error, dev sdd, sector 4096 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0",
		// An internal SATA disk stays Crit.
		at(env, 3*time.Hour)+" h kernel: sd 0:0:0:0: [sda] Attached SCSI disk",
		at(env, time.Hour)+" h kernel: I/O error, dev sda, sector 777 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2",
	)))
	want(t, res, "logs.disk_io_error", "/dev/sdc", model.Warn)
	want(t, res, "logs.disk_medium_error", "/dev/sdd", model.Warn)
	sda := want(t, res, "logs.disk_io_error", "/dev/sda", model.Crit)
	if sda.Part == nil || sda.Part.Location != "/dev/sda" {
		t.Errorf("sda part %+v", sda.Part)
	}
}

func lsblkJSON(devs ...[2]string) string {
	var nodes []map[string]any
	for _, d := range devs {
		nodes = append(nodes, map[string]any{"name": d[0], "kname": d[0], "type": "disk", "tran": d[1],
			"children": []map[string]any{{"name": d[0] + "1", "kname": d[0] + "1", "type": "part", "tran": nil}}})
	}
	b, _ := json.Marshal(map[string]any{"blockdevices": nodes})
	return string(b)
}

func TestLinuxUSBFromLsblk(t *testing.T) {
	env := linuxEnv()
	res := check(t, env, collect.OSLinux,
		testkit.S("disk.lsblk", lsblkJSON([2]string{"sda", "sata"}, [2]string{"sdb", "usb"})),
		testkit.S("logs.kernel_match", journal(
			at(env, time.Hour)+" h kernel: I/O error, dev sdb, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2",
			at(env, time.Hour)+" h kernel: EXT4-fs error (device sdb1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0",
		)))
	want(t, res, "logs.disk_io_error", "/dev/sdb", model.Warn)
	want(t, res, "logs.fs_error", "/dev/sdb1", model.Warn)
	// lsblk -P (util-linux < 2.27), real WSL capture from the disk domain.
	res = check(t, env, collect.OSLinux,
		testkit.S("disk.lsblk", `NAME="sdb" KNAME="sdb" TYPE="disk" SIZE="1000" ROTA="1" TRAN="usb" PKNAME=""`+"\n"+
			`NAME="sdb1" KNAME="sdb1" TYPE="part" SIZE="1000" ROTA="1" TRAN="" PKNAME="sdb"`),
		testkit.S("logs.kernel_match", journal(at(env, time.Hour)+" h kernel: Buffer I/O error on dev sdb1, logical block 0, async page read")))
	want(t, res, "logs.disk_io_error", "/dev/sdb", model.Warn)
}

func TestLinuxGoneDisk(t *testing.T) {
	env := linuxEnv()
	inv := testkit.S("disk.lsblk", lsblkJSON([2]string{"sda", "sata"}))
	old := check(t, env, collect.OSLinux, inv, testkit.S("logs.kernel_match", journal(
		at(env, 5*24*time.Hour)+" h kernel: I/O error, dev sdc, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2")))
	f := want(t, old, "logs.disk_io_error", "/dev/sdc", model.Warn)
	if !strings.Contains(f.Detail.EN, "no longer") || f.Part == nil {
		t.Errorf("gone: %s / %+v", f.Detail.EN, f.Part)
	}
	recent := check(t, env, collect.OSLinux, inv, testkit.S("logs.kernel_match", journal(
		at(env, 2*time.Hour)+" h kernel: I/O error, dev sdc, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2")))
	f = want(t, recent, "logs.disk_io_error", "/dev/sdc", model.Crit) // just dropped off
	if !strings.Contains(f.Detail.EN, "dropped off") {
		t.Errorf("gone recent: %s", f.Detail.EN)
	}
	present := check(t, env, collect.OSLinux, inv, testkit.S("logs.kernel_match", journal(
		at(env, 5*24*time.Hour)+" h kernel: I/O error, dev sda, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2")))
	want(t, present, "logs.disk_io_error", "/dev/sda", model.Crit) // a bad sector stays bad
}

// AER from devices passed through to VMs (vfio-pci) must never be Crit;
// the same flood from a host device is.
func TestVfioPassthroughAER(t *testing.T) {
	env := linuxEnv()
	var vf, host, corr []string
	for i := 0; i < 15; i++ {
		ts := at(env, time.Duration(i)*time.Minute)
		vf = append(vf, ts+" h kernel: vfio-pci 0000:01:00.0: PCIe Bus Error: severity=Uncorrected (Non-Fatal), type=Transaction Layer, (Requester ID)")
		host = append(host, ts+" h kernel: nvme 0000:41:00.0: AER: PCIe Bus Error: severity=Uncorrected (Non-Fatal), type=Transaction Layer, (Requester ID)")
		corr = append(corr, ts+" h kernel: vfio-pci 0000:02:00.0: AER: PCIe Bus Error: severity=Corrected, type=Physical Layer, (Receiver ID)")
	}
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(append(append(vf, host...), corr...)...)))
	f := want(t, res, "logs.pcie_uncorrected", "0000:01:00.0", model.Warn)
	if !strings.Contains(f.Detail.EN, "vfio-pci") {
		t.Errorf("vfio detail: %s", f.Detail.EN)
	}
	want(t, res, "logs.pcie_uncorrected", "0000:41:00.0", model.Crit)
	want(t, res, "logs.pcie_corrected", "0000:02:00.0", model.Info)
}

func TestNVMeStatusCodes(t *testing.T) {
	env := linuxEnv()
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(
		at(env, time.Hour)+" h kernel: nvme0n1: Read(0x2) @ LBA 0, 8 blocks, Deallocated or Unwritten Logical Block (sct 0x2 / sc 0x87) DNR",
		at(env, time.Hour)+" h kernel: nvme0n1: Read(0x2) @ LBA 16, 8 blocks, Access Denied (sct 0x2 / sc 0x86) DNR",
		at(env, time.Hour)+" h kernel: nvme1n1: Read(0x2) @ LBA 1234, 8 blocks, Unrecovered Read Error (sct 0x2 / sc 0x81) DNR",
	)))
	none(t, res, "logs.disk_medium_error", "/dev/nvme0n1")
	f := want(t, res, "logs.disk_medium_error", "/dev/nvme1n1", model.Crit)
	if f.Part == nil || f.Part.Location != "/dev/nvme1n1" {
		t.Errorf("part %+v", f.Part)
	}
}

// NVMe controller-level findings name the first namespace in Part, the way
// the disk inventory names the drive, so diag can attach the serial.
func TestNVMeControllerPart(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.kernel_match", testkit.Read(t, "linux_failing_match.txt")))
	f := want(t, res, "logs.nvme_controller_down", "nvme1", model.Crit)
	if f.Part == nil || f.Part.Location != "/dev/nvme1n1" {
		t.Errorf("part %+v", f.Part)
	}
}

// A very noisy host: the collector kept only the newest lines, so the
// coverage must say so. A capped noise block does not matter.
func TestLogCappedPartial(t *testing.T) {
	env := linuxEnv()
	l := at(env, time.Hour) + " h kernel: ata1.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x0"
	capped := "# source=journal persistent=1 tz=+0000 max=1 total=58000\n" + l + "\n# rc=0\n"
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", capped))
	c := testkit.Cov(res, "logs.kernel")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "58000") || c.Cmd == "" {
		t.Errorf("coverage = %+v", c)
	}
	noise := "# source=journal persistent=1 tz=+0000 max=3000 total=1\n" + l + "\n# rc=0\n" +
		"# source=journal persistent=1 tz=+0000 max=1 total=90000 class=noise\n" +
		at(env, time.Hour) + " h kernel: ACPI Error: AE_NOT_FOUND, Evaluating _PMC (20190816/psparse-529)\n"
	res = check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", noise))
	if c := testkit.Cov(res, "logs.kernel"); c == nil || c.State != model.CovRan {
		t.Errorf("noise coverage = %+v", c)
	}
}

// Old storms weigh less: a burst that crossed CritAt 5 days ago and never
// came back is a Warn, the same burst today is Crit.
func TestCritAtNeedsRecentEvents(t *testing.T) {
	env := linuxEnv()
	burst := func(ago time.Duration) []string {
		var ls []string
		for i := 0; i < 12; i++ {
			ls = append(ls, at(env, ago+time.Duration(i)*time.Second)+" h kernel: nvme 0000:41:00.0: AER: PCIe Bus Error: severity=Uncorrected (Non-Fatal), type=Transaction Layer, (Requester ID)")
		}
		return ls
	}
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(burst(5*24*time.Hour)...)))
	want(t, res, "logs.pcie_uncorrected", "0000:41:00.0", model.Warn)
	res = check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(burst(time.Hour)...)))
	want(t, res, "logs.pcie_uncorrected", "0000:41:00.0", model.Crit)
}

// On a VM an unclean end is usually the hypervisor's forced stop: Info.
func TestVMUncleanRebootIsInfo(t *testing.T) {
	env := linuxEnv()
	env.Virtual = "kvm"
	res := check(t, env, collect.OSLinux,
		testkit.S("logs.boots", testkit.Read(t, "boots_unclean.txt")),
		testkit.S("logs.last", testkit.Read(t, "last_ungraceful.txt")))
	f := want(t, res, "logs.unexpected_reboot", "", model.Info)
	if !strings.Contains(f.Detail.EN, "hypervisor") || !strings.Contains(f.Action.VI, "hypervisor") {
		t.Errorf("%s / %s", f.Detail.EN, f.Action.VI)
	}
}

// ---- Windows ----

func winEnv() model.Env {
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	env.Now = time.Date(2026, 10, 2, 7, 50, 0, 0, time.UTC)
	return env
}

// The real laptop run with the disk/volume inventory of the same machine:
// PhysicalDrive1 and G: no longer exist (they were a USB disk).
func TestWindowsRealWithInventory(t *testing.T) {
	res := check(t, winEnv(), collect.OSWindows,
		testkit.S("logs.win_events", testkit.Read(t, "real_win_events.json")),
		testkit.S("logs.win_summary", testkit.Read(t, "real_win_summary.json")),
		testkit.S("logs.win_boots", testkit.Read(t, "real_win_boots.json")),
		testkit.S("logs.win_meta", testkit.Read(t, "real_win_meta.json")),
		testkit.S("disk.win_physical", testkit.Read(t, "real_win_physical.json")),
		testkit.S("disk.win_diskdrive", testkit.Read(t, "real_win_diskdrive.json")),
		testkit.S("filesystem.win_volume", testkit.Read(t, "real_win_volume.json")),
	)
	for _, f := range res.Findings {
		if f.Severity == model.Crit && f.ID != "logs.win_bugcheck" {
			t.Errorf("Crit from a USB disk that is gone: %s@%s %s", f.ID, f.Target, f.Detail.EN)
		}
	}
	p := want(t, res, "logs.win_disk_paging_error", "PhysicalDrive1", model.Warn)
	if !strings.Contains(p.Detail.EN, "USB disk") {
		t.Errorf("paging: %s", p.Detail.EN)
	}
	// Not elevated, but the System log is readable by users; no cap was hit.
	if c := testkit.Cov(res, "logs.windows"); c == nil || c.State != model.CovRan {
		t.Errorf("coverage %+v", c)
	}
}

// winEvent JSON line for tests.
func wev(t time.Time, p string, id, level int, x ...string) string {
	b, _ := json.Marshal(map[string]any{"t": t.UTC().Format(time.RFC3339Nano), "p": p, "id": id, "l": level, "m": "localised text", "x": x})
	return string(b)
}

func disk51(env model.Env, n int, ago time.Duration, disk int) string {
	var evs []string
	for i := 0; i < n; i++ {
		evs = append(evs, wev(env.Now.Add(-ago-time.Duration(i)*time.Minute), "disk", 51, 3, fmt.Sprintf(`\Device\Harddisk%d\DR%d`, disk, disk), ""))
	}
	return "[" + strings.Join(evs, ",") + "]"
}

func TestWindowsInternalDisk(t *testing.T) {
	env := winEnv()
	inv := testkit.S("disk.win_physical", `[{"FriendlyName":"ST4000NM0035","BusType":"SATA","DeviceId":"0"},{"FriendlyName":"USB","BusType":"USB","DeviceId":"2"}]`)
	res := check(t, env, collect.OSWindows, inv, testkit.S("logs.win_events", disk51(env, 25, time.Hour, 0)))
	f := want(t, res, "logs.win_disk_paging_error", "PhysicalDrive0", model.Crit)
	if f.Part == nil || f.Part.Location != "PhysicalDrive0" {
		t.Errorf("part %+v", f.Part)
	}
	res = check(t, env, collect.OSWindows, inv, testkit.S("logs.win_events", disk51(env, 25, 5*24*time.Hour, 0)))
	want(t, res, "logs.win_disk_paging_error", "PhysicalDrive0", model.Warn) // old storm
	res = check(t, env, collect.OSWindows, inv, testkit.S("logs.win_events", disk51(env, 25, time.Hour, 2)))
	u := want(t, res, "logs.win_disk_paging_error", "PhysicalDrive2", model.Warn) // BusType USB
	if !strings.Contains(u.Detail.VI, "ổ USB") || u.Part != nil {
		t.Errorf("usb: %s %+v", u.Detail.VI, u.Part)
	}
	// Win32_DiskDrive says USB (USBSTOR PNP id) even without Get-PhysicalDisk.
	res = check(t, env, collect.OSWindows,
		testkit.S("disk.win_diskdrive", `[{"Index":3,"InterfaceType":"USB","PNPDeviceID":"USBSTOR\\DISK&VEN_SEAGATE&PROD_BACKUP+\\NA8F1234&0"}]`),
		testkit.S("logs.win_events", disk51(env, 25, time.Hour, 3)))
	want(t, res, "logs.win_disk_paging_error", "PhysicalDrive3", model.Warn)
}

func TestWindowsGoneDisk(t *testing.T) {
	env := winEnv()
	inv := testkit.S("disk.win_physical", `[{"BusType":"SAS","DeviceId":"0"}]`)
	bad := func(ago time.Duration) *collect.Section {
		return testkit.S("logs.win_events", "["+wev(env.Now.Add(-ago), "disk", 7, 2, `\Device\Harddisk3\DR3`)+"]")
	}
	res := check(t, env, collect.OSWindows, inv, bad(5*24*time.Hour))
	f := want(t, res, "logs.win_disk_bad_block", "PhysicalDrive3", model.Warn)
	if !strings.Contains(f.Detail.EN, "no longer attached") || f.Part == nil {
		t.Errorf("gone: %s %+v", f.Detail.EN, f.Part)
	}
	res = check(t, env, collect.OSWindows, inv, bad(2*time.Hour))
	f = want(t, res, "logs.win_disk_bad_block", "PhysicalDrive3", model.Crit)
	if !strings.Contains(f.Detail.EN, "dropped off") {
		t.Errorf("gone recent: %s", f.Detail.EN)
	}
}

func TestWinMetaCapped(t *testing.T) {
	res := check(t, winEnv(), collect.OSWindows,
		testkit.S("logs.win_events", "[]"),
		testkit.S("logs.win_meta", `[{"read":50000,"readMax":50000,"wanted":12,"wantedMax":3000,"oldest":"2026-09-30T01:00:00.0000000Z"}]`))
	for _, id := range []string{"logs.windows", "logs.reboots"} {
		c := testkit.Cov(res, id)
		if c == nil || c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "2026-09-30 01:00") {
			t.Errorf("%s coverage = %+v", id, c)
		}
	}
	none(t, res, "logs.windows_clean")
}

// Kernel-Power 41 on Windows Server 2008 R2: SleepInProgress reads "false"
// and PowerButtonTimestamp is 0 — not a power-button reset. On a VM the
// unclean restart is Info.
func TestKernelPower41Properties(t *testing.T) {
	env := winEnv()
	ev := `[{"t":"2026-10-01T02:00:00.0000000Z","p":"Microsoft-Windows-Kernel-Power","id":41,"l":1,"m":"x","x":["0","0x0","0x0","0x0","0x0","false","0"]}]`
	res := check(t, env, collect.OSWindows, testkit.S("logs.win_events", ev))
	f := want(t, res, "logs.unexpected_reboot", "", model.Warn)
	if strings.Contains(f.Detail.EN, "power button") {
		t.Errorf("SleepInProgress mistaken for PowerButtonTimestamp: %s", f.Detail.EN)
	}
	env.Virtual = "microsoft"
	res = check(t, env, collect.OSWindows, testkit.S("logs.win_events", ev))
	want(t, res, "logs.unexpected_reboot", "", model.Info)
}

func TestKernelFormatVariants(t *testing.T) {
	env := linuxEnv()
	ts := at(env, time.Hour)
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(
		// Kernels < 4.5 print the device and the sense data on separate
		// lines (LKML 1404.3/02964 layout).
		ts+" h kernel: sd 2:0:0:0: [sdc]",
		ts+" h kernel: Sense Key : Medium Error [current] [descriptor]",
		ts+" h kernel: Add. Sense: Unrecovered read error - auto reallocate failed",
		// A scratched disc in a (virtual) DVD drive is not a disk failure.
		ts+" h kernel: sr 1:0:0:0: [sr0]",
		ts+" h kernel: Sense Key : Medium Error [current]",
		ts+" h kernel: sr 1:0:0:0: [sr0] tag#0 Sense Key : Medium Error [current]",
		// btrfs >= 6.x adds the filesystem state (fs/btrfs/messages.c).
		ts+" h kernel: BTRFS: error (device dm-3: state EA) in btrfs_run_delayed_refs:2150: errno=-5 IO failure",
		ts+" h kernel: BTRFS info (device dm-3: state EA): forced readonly",
		ts+" h kernel: BTRFS info (device loop7: state EA): forced readonly",
	)))
	want(t, res, "logs.disk_medium_error", "/dev/sdc", model.Crit)
	none(t, res, "logs.disk_medium_error", "")
	want(t, res, "logs.fs_error", "/dev/dm-3", model.Crit)
	want(t, res, "logs.fs_readonly", "/dev/dm-3", model.Crit)
	none(t, res, "logs.fs_readonly", "/dev/loop7")
	for _, f := range res.Findings {
		if strings.Contains(f.Target, "state") || f.Target == "" && f.Severity >= model.Warn {
			t.Errorf("bad target %q for %s", f.Target, f.ID)
		}
	}
}

// Kernels up to 5.x log thermal throttling as a machine check record:
// "Machine check events logged" right after it is the throttle.
func TestThermalMCEIsThrottle(t *testing.T) {
	env := linuxEnv()
	ts := at(env, time.Hour)
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(
		ts+" h kernel: CPU3: Core temperature above threshold, cpu clock throttled (total events = 1)",
		ts+" h kernel: CPU1: Package temperature above threshold, cpu clock throttled (total events = 1)",
		ts+" h kernel: mce: [Hardware Error]: Machine check events logged",
	)))
	want(t, res, "logs.cpu_thermal_throttle", "CPU", model.Warn)
	none(t, res, "logs.mce_corrected")
}

// smartd names disks behind a MegaRAID controller "/dev/bus/0
// [megaraid_disk_03]"; the part must not be keyed on the shared /dev/bus/0.
func TestSmartdMegaraidPart(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.units", testkit.Read(t, "linux_units.txt")))
	f := want(t, res, "logs.smartd_failure", "/dev/bus/0 [megaraid_disk_03]", model.Crit)
	if f.Part == nil || f.Part.Location != "megaraid_disk_03 on /dev/bus/0" {
		t.Errorf("part %+v", f.Part)
	}
	n := want(t, res, "logs.smartd_failure", "/dev/nvme0", model.Crit)
	if n.Part == nil || n.Part.Location != "/dev/nvme0n1" {
		t.Errorf("nvme part %+v", n.Part)
	}
}

// Disk names of an earlier boot may now be another disk: say so.
func TestEarlierBootDiskNameNote(t *testing.T) {
	env := linuxEnv()
	boots := "# persistent=1 tz=+0000\n#list\n" +
		" -1 8a1c6e0f4f2b4b7f9a8f0d0c3e5b6a71 Mon 2026-09-21 08:00:00 UTC Wed 2026-09-30 08:00:00 UTC\n" +
		"  0 26a4a2ff48594778850d917a7e2ad195 Wed 2026-09-30 08:05:00 UTC Thu 2026-10-01 09:00:00 UTC\n"
	res := check(t, env, collect.OSLinux, testkit.S("logs.boots", boots), testkit.S("logs.kernel_match", journal(
		at(env, 3*24*time.Hour)+" h kernel: I/O error, dev sda, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2",
		at(env, time.Hour)+" h kernel: I/O error, dev sdb, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2")))
	if f := want(t, res, "logs.disk_io_error", "/dev/sda", model.Crit); !strings.Contains(f.Detail.EN, "smartctl -i /dev/sda") {
		t.Errorf("no boot note: %s", f.Detail.EN)
	}
	if f := want(t, res, "logs.disk_io_error", "/dev/sdb", model.Crit); strings.Contains(f.Detail.EN, "before the last boot") {
		t.Errorf("note on a current-boot event: %s", f.Detail.EN)
	}
}
