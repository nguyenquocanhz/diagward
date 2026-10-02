package logs

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func linuxEnv() model.Env { return testkit.Env(collect.OSLinux) } // now = 2026-10-01 09:00:20Z

func check(t *testing.T, env model.Env, os string, secs ...*collect.Section) model.Result {
	t.Helper()
	res := Check(testkit.Bundle(os, secs...), env)
	testkit.Validate(t, res)
	checkTexts(t, res)
	return res
}

func want(t *testing.T, res model.Result, id, target string, sev model.Severity) *model.Finding {
	t.Helper()
	f := testkit.Find(res, id, target)
	if f == nil {
		t.Fatalf("missing %s@%s; have %v", id, target, testkit.IDs(res))
	}
	if f.Severity != sev {
		t.Errorf("%s@%s: severity %s, want %s (%s)", id, target, f.Severity, sev, f.Detail.EN)
	}
	return f
}

func none(t *testing.T, res model.Result, id string, target ...string) {
	t.Helper()
	if f := testkit.Find(res, id, target...); f != nil {
		t.Errorf("unexpected %s@%s=%s", f.ID, f.Target, f.Severity)
	}
}

func TestLinuxFailingDisks(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.S("logs.kernel_match", testkit.Read(t, "linux_failing_match.txt")),
		testkit.S("logs.kernel", "# source=journal persistent=1 tz=+0700\n# rc=0\n"),
	)
	want(t, res, "logs.disk_medium_error", "/dev/sda", model.Crit)
	want(t, res, "logs.disk_medium_error", "ata1", model.Crit) // { UNC }
	io := want(t, res, "logs.disk_io_error", "/dev/sda", model.Crit)
	if io.Part == nil || io.Part.Location != "/dev/sda" {
		t.Errorf("disk_io_error part = %+v", io.Part)
	}
	ata := want(t, res, "logs.disk_ata_error", "ata1", model.Warn)
	if ata.Part == nil || ata.Part.Model != "ST4000NM0035-1V4107" || ata.Part.Firmware != "TN03" {
		t.Errorf("ata part = %+v", ata.Part)
	}
	none(t, res, "logs.disk_ata_error", "ata5") // empty port at boot
	none(t, res, "logs.disk_io_error", "/dev/fd0")
	want(t, res, "logs.nvme_controller_down", "nvme1", model.Crit)
	want(t, res, "logs.nvme_timeout", "nvme1", model.Warn)
	want(t, res, "logs.disk_io_error", "/dev/nvme1n1", model.Crit)
	want(t, res, "logs.fs_error", "/dev/nvme1n1p1", model.Crit)
	want(t, res, "logs.fs_readonly", "/dev/nvme1n1p1", model.Crit)
	want(t, res, "logs.fs_error", "/dev/dm-0", model.Crit)
	ce := want(t, res, "logs.memory_corrected", "CPU_SrcID#1_Ha#0_Chan#1_DIMM#0", model.Warn)
	if !strings.Contains(ce.Detail.EN, "2 times") {
		t.Errorf("CE detail: %s", ce.Detail.EN)
	}
	want(t, res, "logs.mce_corrected", "CPU", model.Warn) // 61 h ago: still within the 72 h decay window
	want(t, res, "logs.pcie_uncorrected", "0000:01:00.0", model.Warn)
	want(t, res, "logs.pcie_corrected", "0000:04:00.0", model.Info)
	want(t, res, "logs.cpu_thermal_throttle", "CPU", model.Warn)
	want(t, res, "logs.nic_link_down", "eno1", model.Warn) // 4 drops, 3 in the last 24 h
	want(t, res, "logs.nic_link_down", "eth0", model.Info) // once, a week ago
	want(t, res, "logs.soft_lockup", "CPU", model.Warn)
	want(t, res, "logs.hung_task", "I/O", model.Warn)
	want(t, res, "logs.oom_kill", "RAM", model.Warn)
	want(t, res, "logs.raid_member_failed", "/dev/md0", model.Crit)
	none(t, res, "logs.kernel_oops")       // "traps: ... general protection fault" is a user-space crash
	none(t, res, "logs.firmware_messages") // one ACPI error is noise
	none(t, res, "logs.kernel_clean")
	if c := testkit.Cov(res, "logs.kernel"); c == nil || c.State != model.CovRan {
		t.Errorf("coverage = %+v", c)
	}
	f := res.Facts.(*Facts)
	if !f.Persistent || len(f.Events) == 0 {
		t.Errorf("facts = %+v", f)
	}
	if len(res.Tables) == 0 || res.Tables[0].ID != "logs.events" {
		t.Errorf("tables = %+v", res.Tables)
	}
}

func TestLinuxUnits(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.units", testkit.Read(t, "linux_units.txt")))
	want(t, res, "logs.smartd_pending_sectors", "/dev/sdb", model.Crit)
	sdc := want(t, res, "logs.smartd_pending_sectors", "/dev/sdc", model.Warn) // cleared later
	if !strings.Contains(sdc.Detail.EN, "cleared") {
		t.Errorf("sdc detail: %s", sdc.Detail.EN)
	}
	want(t, res, "logs.smartd_warning", "/dev/sdd", model.Warn)
	want(t, res, "logs.smartd_failure", "/dev/bus/0 [megaraid_disk_03]", model.Crit)
	want(t, res, "logs.smartd_failure", "/dev/nvme0", model.Crit)
	want(t, res, "logs.smartd_temperature", "/dev/sda", model.Warn)
	want(t, res, "logs.raid_member_failed", "/dev/md0", model.Crit)
	none(t, res, "logs.raid_member_failed", "/dev/md5") // outside the window
	none(t, res, "logs.raid_member_failed", "/dev/md1") // rebuild finished is good news
}

func TestLinuxGHESandMCE(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.kernel_match", testkit.Read(t, "linux_ghes.txt")))
	want(t, res, "logs.memory_corrected", "memory", model.Warn)
	want(t, res, "logs.pcie_uncorrected", "PCIe", model.Warn)
	want(t, res, "logs.mce_uncorrected", "CPU", model.Crit) // be00... has UC set
	want(t, res, "logs.memory_page_offlined", "RAM", model.Crit)
}

func TestMCStatusUC(t *testing.T) {
	for _, c := range []struct {
		hex    string
		uc, ok bool
	}{
		{"be00000000800400", true, true},  // VAL|UC|EN|...
		{"cc00008000010090", false, true}, // VAL|OVER, corrected
		{"0000000000000000", false, false},
		{"zz", false, false},
	} {
		uc, ok := mcStatusUC(c.hex)
		if uc != c.uc || ok != c.ok {
			t.Errorf("%s: uc=%v ok=%v", c.hex, uc, ok)
		}
	}
}

func TestSyslogFallbackAndYear(t *testing.T) {
	env := linuxEnv()
	env.Now = time.Date(2027, 1, 2, 1, 0, 0, 0, time.UTC) // 08:00 +07
	res := check(t, env, collect.OSLinux,
		testkit.S("logs.kernel_match", testkit.Read(t, "rhel7_messages_match.txt")),
		testkit.S("logs.kernel", "# source=dmesg-T tz=+0700\n"),
	)
	want(t, res, "logs.disk_hardware_error", "/dev/sdc", model.Crit)
	want(t, res, "logs.disk_offline", "/dev/sdc", model.Crit) // sd 2:0:1:0 mapped to sdc
	want(t, res, "logs.fs_readonly", "/dev/sdc1", model.Crit)
	want(t, res, "logs.controller_fault", "megaraid_sas 0000:02:00.0", model.Crit) // Dec 30 2026, not 2027
	want(t, res, "logs.controller_reset", "megaraid_sas 0000:02:00.0", model.Warn)
	want(t, res, "logs.soft_lockup", "CPU", model.Warn)
	none(t, res, "logs.disk_io_error", "/dev/sdz") // Nov 20 2026: outside the window
	f := res.Facts.(*Facts)
	if strings.Join(f.Sources, ",") != "dmesg,syslog" {
		t.Errorf("sources = %v", f.Sources)
	}
	if c := testkit.Cov(res, "logs.kernel"); c.State != model.CovRan {
		t.Errorf("coverage %+v", c)
	}
}

func TestBSDTimeYear(t *testing.T) {
	ref := time.Date(2027, 1, 2, 1, 0, 0, 0, time.UTC)
	m := reBSD.FindStringSubmatch("Dec 31 23:59:58 host kernel: x")
	got := bsdTime(m, parseTZ("+0700"), ref)
	if got.Year() != 2026 {
		t.Errorf("year = %d", got.Year())
	}
	m = reBSD.FindStringSubmatch("Jan  2 07:41:01 host kernel: x")
	if got := bsdTime(m, parseTZ("+0700"), ref); got.Year() != 2027 || got.Hour() != 7 {
		t.Errorf("got %v", got)
	}
}

func TestDmesgOnlyIsPartial(t *testing.T) {
	env := linuxEnv()
	env.Now = time.Unix(1790700000+10100, 0).UTC()
	res := check(t, env, collect.OSLinux,
		testkit.S("logs.kernel", testkit.Read(t, "dmesg_plain.txt")),
		testkit.S("logs.kernel_match", testkit.Read(t, "dmesg_plain.txt")),
	)
	want(t, res, "logs.disk_link_crc", "ata2", model.Warn)
	want(t, res, "logs.disk_ata_error", "ata2", model.Warn)
	none(t, res, "logs.disk_ata_error", "ata3")
	want(t, res, "logs.nic_tx_timeout", "eno1np0", model.Warn)
	want(t, res, "logs.nic_tx_timeout", "eno2", model.Warn)
	want(t, res, "logs.nmi_hardware", "NMI", model.Warn)
	want(t, res, "logs.hard_lockup", "CPU", model.Crit)
	want(t, res, "logs.kernel_oops", "kernel", model.Warn)
	c := testkit.Cov(res, "logs.kernel")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Fix.EN, "/var/log/journal") {
		t.Errorf("coverage = %+v", c)
	}
	// The same lines in two sections are counted once.
	f := testkit.Find(res, "logs.nmi_hardware", "NMI")
	if !strings.Contains(f.Detail.EN, "2 times") {
		t.Errorf("dedupe: %s", f.Detail.EN)
	}
}

func TestRealWSLHealthy(t *testing.T) {
	env := linuxEnv()
	env.Now = time.Date(2026, 10, 2, 7, 50, 0, 0, time.UTC)
	env.Virtual, env.Container = "", false
	res := check(t, env, collect.OSLinux,
		testkit.S("logs.kernel", testkit.Read(t, "wsl_kernel.txt")),
		testkit.S("logs.kernel_match", testkit.Read(t, "wsl_kernel_match.txt")),
		testkit.S("logs.units", testkit.Read(t, "wsl_units.txt")),
		testkit.S("logs.boots", testkit.Read(t, "wsl_boots.txt")),
		testkit.Missing("logs.last", "last"),
		testkit.S("logs.kdump", testkit.Read(t, "wsl_kdump.txt")),
	)
	// Other test suites on this WSL created md arrays, bonds and broken loop
	// filesystems; loop devices are not hardware and must be ignored.
	none(t, res, "logs.fs_error")
	none(t, res, "logs.fs_readonly")
	want(t, res, "logs.raid_member_failed", "/dev/md91", model.Crit)
	none(t, res, "logs.raid_member_failed", "/dev/md90") // only DeviceDisappeared (array stopped)
	want(t, res, "logs.bond_no_active_link", "bond9", model.Crit)
	want(t, res, "logs.reboots_clean", "", model.OK)
	none(t, res, "logs.unexpected_reboot")
	for _, id := range []string{"logs.kernel", "logs.reboots"} {
		if c := testkit.Cov(res, id); c == nil || c.State != model.CovRan {
			t.Errorf("%s coverage = %+v", id, c)
		}
	}
	f := res.Facts.(*Facts)
	if len(f.Boots) < 5 || f.UncleanShutdowns != 0 {
		t.Errorf("boots=%d unclean=%d", len(f.Boots), f.UncleanShutdowns)
	}
}

func TestBootsUnclean(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.S("logs.boots", testkit.Read(t, "boots_unclean.txt")),
		testkit.S("logs.last", testkit.Read(t, "last_ungraceful.txt")),
	)
	f := want(t, res, "logs.unexpected_reboot", "", model.Warn)
	if !strings.Contains(f.Title.EN, "1 time") || !strings.Contains(f.Detail.EN, "2026-09-28 08:29") {
		t.Errorf("unexpected reboot: %s / %s", f.Title.EN, f.Detail.EN)
	}
	want(t, res, "logs.shutdown_incomplete", "", model.Info)
	facts := res.Facts.(*Facts)
	endings := map[string]int{}
	for _, b := range facts.Boots {
		endings[b.Ending]++
	}
	if endings["clean"] != 1 || endings["unclean"] != 1 || endings["shutdown_incomplete"] != 1 || endings["running"] != 1 {
		t.Errorf("endings = %v", endings)
	}
}

func TestWtmpUngraceful(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.Skipped("logs.boots", "not-applicable"),
		testkit.S("logs.last", testkit.Read(t, "last_ungraceful.txt")),
	)
	f := want(t, res, "logs.unexpected_reboot", "", model.Warn)
	if !strings.Contains(f.Detail.EN, "wtmp") || !strings.Contains(f.Title.EN, "1 time") {
		t.Errorf("%s / %s", f.Title.EN, f.Detail.EN)
	}
}

func TestWtmpGraceful(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.Skipped("logs.boots", "not-applicable"),
		testkit.S("logs.last", testkit.Read(t, "last_graceful.txt")),
	)
	want(t, res, "logs.reboots_clean", "", model.OK)
}

func TestKdump(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.kdump", testkit.Read(t, "kdump.txt")))
	f := want(t, res, "logs.kernel_crash_dump", "/var/crash/127.0.0.1-2026-09-30-03:12:44", model.Crit)
	if !strings.Contains(f.Detail.EN, "machine check") || len(f.Evidence) < 2 {
		t.Errorf("crash dump finding: %s %v", f.Detail.EN, f.Evidence)
	}
	want(t, res, "logs.old_crash_dumps", "", model.Info)
}

func TestVolatileJournal(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.S("logs.kernel", "# source=journal persistent=0 tz=+0000\n2026-10-01T08:00:00+00:00 h kernel: hello\n# rc=0\n"),
		testkit.S("logs.boots", "# persistent=0 tz=+0000\n#list\n  0 26a4a2ff48594778850d917a7e2ad195 Thu 2026-10-01 07:00:00 UTC Thu 2026-10-01 09:00:00 UTC\n"),
		testkit.Missing("logs.last", "last"),
	)
	for _, id := range []string{"logs.kernel", "logs.reboots"} {
		c := testkit.Cov(res, id)
		if c == nil || c.State != model.CovPartial || c.Cmd != "mkdir -p /var/log/journal && systemctl restart systemd-journald" ||
			strings.Contains(c.Fix.EN, "mkdir") {
			t.Errorf("%s coverage = %+v", id, c)
		}
	}
	want(t, res, "logs.kernel_clean", "", model.OK)
}

func TestContainerSkipped(t *testing.T) {
	env := linuxEnv()
	env.Virtual, env.Container = "lxc", true
	var secs []*collect.Section
	for _, n := range []string{"kernel", "kernel_match", "units", "boots", "last", "kdump"} {
		secs = append(secs, testkit.Skipped("logs."+n, "container"))
	}
	res := check(t, env, collect.OSLinux, secs...)
	if len(res.Findings) != 0 {
		t.Errorf("findings in a container: %v", testkit.IDs(res))
	}
	for _, id := range []string{"logs.kernel", "logs.reboots"} {
		if c := testkit.Cov(res, id); c == nil || c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "container") {
			t.Errorf("%s coverage = %+v", id, c)
		}
	}
}

func TestNotRootNoData(t *testing.T) {
	env := linuxEnv()
	env.Root = false
	res := check(t, env, collect.OSLinux,
		testkit.RC("logs.kernel", 1, "", "dmesg: read kernel buffer failed: Operation not permitted"),
		testkit.RC("logs.kernel_match", 1, "", "cannot read /var/log/messages"),
		testkit.RC("logs.units", 1, "", ""),
	)
	c := testkit.Cov(res, "logs.kernel")
	if c == nil || c.State != model.CovSkipped || !strings.Contains(c.Fix.EN, "sudo") {
		t.Errorf("coverage = %+v", c)
	}
}

func TestToolsMissing(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.Missing("logs.kernel", "dmesg"), testkit.Missing("logs.kernel_match", "dmesg"), testkit.Missing("logs.units", "journalctl"))
	if c := testkit.Cov(res, "logs.kernel"); c == nil || c.State != model.CovSkipped {
		t.Errorf("coverage = %+v", c)
	}
}

func TestTimeoutPartial(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.S("logs.kernel_match", "# source=journal persistent=1 tz=+0000\n2026-10-01T08:00:00+00:00 h kernel: x\n# rc=124\n"))
	if c := testkit.Cov(res, "logs.kernel"); c == nil || c.State != model.CovPartial {
		t.Errorf("coverage = %+v", c)
	}
}

func TestNoSections(t *testing.T) {
	for _, os := range []string{collect.OSLinux, collect.OSWindows, collect.OSBMC} {
		res := Check(testkit.Bundle(os), testkit.Env(os))
		if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 || res.Facts != nil {
			t.Errorf("%s: %+v", os, res)
		}
	}
}

// A noisy pattern on hundreds of devices must not produce hundreds of findings.
func TestNoiseIsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("# source=journal persistent=1 tz=+0000\n")
	for i := 0; i < 300; i++ {
		for j := 0; j < 5; j++ {
			fmt.Fprintf(&b, "2026-10-01T08:%02d:%02d+00:00 h kernel: igb 0000:%02x:00.0 eno%d: igb: eno%d NIC Link is Down\n", j, i%60, i%256, i, i)
			// Container and VM interfaces flap with their guests: ignored.
			fmt.Fprintf(&b, "2026-10-01T08:%02d:%02d+00:00 h kernel: veth%x: Link is Down\n", j, i%60, i)
			fmt.Fprintf(&b, "2026-10-01T08:%02d:%02d+00:00 h kernel: fwpr%dp0: Link is Down\n", j, i%60, i)
		}
	}
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "2026-10-01T07:%02d:%02d+00:00 h kernel: ACPI Error: Method parse/execution failed \\_SB.PMI0._GHL, AE_NOT_EXIST (20190816/psparse-529)\n", i/60%60, i%60)
	}
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.kernel_match", b.String()))
	n := 0
	for _, f := range res.Findings {
		if f.ID == "logs.nic_link_down" {
			n++
		}
	}
	if n > maxTargetsPerRule+1 {
		t.Errorf("%d link-down findings", n)
	}
	if testkit.Find(res, "logs.nic_link_down", "+292") == nil {
		t.Errorf("no overflow summary: %v", testkit.IDs(res))
	}
	want(t, res, "logs.firmware_messages", "BIOS/ACPI", model.Info)
	for _, f := range res.Findings {
		if len(f.Evidence) > 10 {
			t.Errorf("%s: %d evidence lines", f.ID, len(f.Evidence))
		}
	}
}

func TestWindowsReal(t *testing.T) {
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	env.Now = time.Date(2026, 10, 2, 7, 50, 0, 0, time.UTC)
	res := check(t, env, collect.OSWindows,
		testkit.S("logs.win_events", testkit.Read(t, "real_win_events.json")),
		testkit.S("logs.win_summary", testkit.Read(t, "real_win_summary.json")),
		testkit.S("logs.win_boots", testkit.Read(t, "real_win_boots.json")),
	)
	f := want(t, res, "logs.win_bugcheck", "0x000000BE ATTEMPTED_WRITE_TO_READONLY_MEMORY", model.Crit)
	// Real run: the detail read "Mã này thường do thường do driver."
	if !strings.Contains(f.Detail.VI, "Mã này thường do driver lỗi.") || strings.Contains(f.Detail.EN, "usually points to usually") {
		t.Errorf("bugcheck detail: %s / %s", f.Detail.VI, f.Detail.EN)
	}
	none(t, res, "logs.unexpected_reboot") // the 6008 belongs to the blue screen
	// The USB disk storm of 2026-09-26 is 6 days old with no recurrence:
	// resets decay to Info, the paging errors (20 in one burst) are Warn,
	// and everything about that disk says it is a USB disk.
	want(t, res, "logs.win_storage_reset", "RaidPort2 (UASPStor)", model.Info)
	p := want(t, res, "logs.win_disk_paging_error", "PhysicalDrive1", model.Warn)
	if !strings.Contains(p.Detail.EN, "USB disk") || !strings.Contains(p.Detail.VI, "ổ USB") || p.Part != nil {
		t.Errorf("paging: %s / part %+v", p.Detail.EN, p.Part)
	}
	ch := want(t, res, "logs.win_ntfs_needs_chkdsk", "G:", model.Warn) // G: logged NTFS 140 during the USB resets
	if !strings.Contains(ch.Detail.EN, "USB disk") || !strings.Contains(ch.Action.VI, "ổ USB") {
		t.Errorf("chkdsk: %s / %s", ch.Detail.EN, ch.Action.VI)
	}
	for _, id := range []string{"logs.windows", "logs.reboots"} {
		if c := testkit.Cov(res, id); c == nil || c.State != model.CovRan {
			t.Errorf("%s coverage = %+v", id, c)
		}
	}
	facts := res.Facts.(*Facts)
	if len(facts.WinProviders) == 0 {
		t.Error("no provider summary")
	}
}

func TestWindowsHardwareEvents(t *testing.T) {
	res := check(t, testkit.Env(collect.OSWindows), collect.OSWindows,
		testkit.S("logs.win_events", testkit.Read(t, "win_hw_events.json")),
		testkit.S("logs.win_boots", testkit.Read(t, "win_boots.json")),
	)
	want(t, res, "logs.win_whea_fatal", "CPU", model.Crit)
	mem := want(t, res, "logs.win_whea_corrected", "memory", model.Warn)
	if mem.Component != model.CompMemory {
		t.Errorf("component %s", mem.Component)
	}
	want(t, res, "logs.win_whea_pcie_corrected", "PCIe", model.Info)
	bad := want(t, res, "logs.win_disk_bad_block", "PhysicalDrive2", model.Crit)
	if bad.Part == nil || bad.Part.Location != "PhysicalDrive2" {
		t.Errorf("part %+v", bad.Part)
	}
	want(t, res, "logs.win_disk_smart_predict", "PhysicalDrive2", model.Crit)
	want(t, res, "logs.win_storage_reset", "RaidPort0 (storahci)", model.Warn)
	want(t, res, "logs.win_nic_link_down", "e1dexpress", model.Warn) // 3 drops, 1 in 24 h: weighted 5
	want(t, res, "logs.win_nic_reset", "10400", model.Warn)
	want(t, res, "logs.win_cpu_firmware_throttle", "CPU", model.Info)
	none(t, res, "logs.win_disk_bad_block", "PhysicalDrive5") // outside the window
	bc := want(t, res, "logs.win_bugcheck", "0x00000124 WHEA_UNCORRECTABLE_ERROR", model.Crit)
	if !strings.Contains(bc.Action.EN, "WHEA") {
		t.Errorf("0x124 action: %s", bc.Action.EN)
	}
	ur := want(t, res, "logs.unexpected_reboot", "", model.Warn)
	if !strings.Contains(ur.Title.EN, "1 time") || !strings.Contains(ur.Detail.EN, "power button") {
		t.Errorf("%s / %s", ur.Title.EN, ur.Detail.EN)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.ID, "Memory") {
			t.Errorf("memory diagnostics leaked: %s", f.ID)
		}
	}
}

func TestWindowsClean(t *testing.T) {
	res := check(t, testkit.Env(collect.OSWindows), collect.OSWindows,
		testkit.S("logs.win_events", "[]"),
		testkit.S("logs.win_summary", "[]"),
		testkit.S("logs.win_boots", testkit.Read(t, "win_boots.json")))
	want(t, res, "logs.windows_clean", "", model.OK)
	f := want(t, res, "logs.reboots_clean", "", model.OK)
	if !strings.Contains(f.Detail.EN, "1 planned") {
		t.Errorf("%s", f.Detail.EN)
	}
}

func TestWindowsBroken(t *testing.T) {
	res := check(t, testkit.Env(collect.OSWindows), collect.OSWindows,
		testkit.RC("logs.win_events", 1, "[{\"t\":", "Get-WinEvent : The RPC server is unavailable"))
	if c := testkit.Cov(res, "logs.windows"); c == nil || c.State != model.CovFailed {
		t.Errorf("coverage = %+v", c)
	}
	res = check(t, testkit.Env(collect.OSWindows), collect.OSWindows,
		testkit.RC("logs.win_events", 0, "[]", "Get-WinEvent : Access is denied"))
	if c := testkit.Cov(res, "logs.windows"); c == nil || c.State != model.CovFailed {
		t.Errorf("coverage = %+v", c)
	}
}

// Truncated and garbled versions of every fixture must never panic and must
// always produce a valid Result.
func TestGarbageNeverPanics(t *testing.T) {
	files := map[string]string{
		"linux_failing_match.txt": "logs.kernel_match", "linux_units.txt": "logs.units", "linux_ghes.txt": "logs.kernel_match",
		"rhel7_messages_match.txt": "logs.kernel_match", "dmesg_plain.txt": "logs.kernel", "boots_unclean.txt": "logs.boots",
		"last_ungraceful.txt": "logs.last", "last_graceful.txt": "logs.last", "kdump.txt": "logs.kdump", "wsl_boots.txt": "logs.boots",
		"win_hw_events.json": "logs.win_events", "real_win_summary.json": "logs.win_summary", "win_boots.json": "logs.win_boots",
	}
	rng := rand.New(rand.NewSource(1))
	for file, sec := range files {
		data := testkit.Read(t, file)
		os := collect.OSLinux
		if strings.HasSuffix(file, ".json") {
			os = collect.OSWindows
		}
		variants := []string{"", "\x00\xff\xfe", data[:len(data)/2], data[:len(data)/3]}
		for i := 0; i < 20; i++ {
			bs := []byte(data)
			for j := 0; j < 1+len(bs)/50; j++ {
				bs[rng.Intn(len(bs))] = byte(rng.Intn(256))
			}
			variants = append(variants, string(bs))
		}
		for _, v := range variants {
			secs := []*collect.Section{testkit.S(sec, v)}
			if os == collect.OSWindows && sec != "logs.win_events" {
				secs = append(secs, testkit.S("logs.win_events", "[]"))
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s: panic %v", file, r)
					}
				}()
				res := Check(testkit.Bundle(os, secs...), testkit.Env(os))
				testkit.Validate(t, res)
			}()
		}
	}
}

func TestDiskOf(t *testing.T) {
	for in, out := range map[string]string{
		"sda1": "/dev/sda", "sdab": "/dev/sdab", "nvme0n1p2": "/dev/nvme0n1", "nvme0n1": "/dev/nvme0n1",
		"mmcblk0p1": "/dev/mmcblk0", "vda3": "/dev/vda", "dm-0": "/dev/dm-0", "/dev/sdb,": "/dev/sdb", "md127": "/dev/md127",
	} {
		if got := diskOf(in); got != out {
			t.Errorf("diskOf(%q) = %q, want %q", in, got, out)
		}
	}
	for _, d := range []string{"sr0", "fd0", "loop3", "loop3p1", "zram0", "nbd0"} {
		if !notDiskRe.MatchString(d) {
			t.Errorf("%s should not count as a disk", d)
		}
	}
}

func TestParseTZ(t *testing.T) {
	for in, off := range map[string]int{"+0700": 25200, "+07:00": 25200, "-0430": -16200, "Z": 0, "": 0, "junk": 0, "+9999": 0} {
		_, got := time.Date(2026, 1, 1, 0, 0, 0, 0, parseTZ(in)).Zone()
		if got != off {
			t.Errorf("parseTZ(%q) offset %d, want %d", in, got, off)
		}
	}
}

func TestMergeLines(t *testing.T) {
	a := []logLine{{Tag: "kernel", Msg: "x"}, {Tag: "kernel", Msg: "x"}}
	b := []logLine{{Tag: "kernel", Msg: "x"}, {Tag: "kernel", Msg: "x"}, {Tag: "kernel", Msg: "x"}, {Tag: "kernel", Msg: "y"}}
	if n := len(mergeLines(a, b)); n != 4 {
		t.Errorf("merged %d lines, want 4", n)
	}
}

// rsyslog's RFC 3339 file format (Ubuntu 24.04+), real lines from the dev
// WSL, merged with the same events from the journal: counted once.
func TestRsyslogRFC3339AndMerge(t *testing.T) {
	env := linuxEnv()
	env.Now = time.Date(2026, 10, 2, 7, 50, 0, 0, time.UTC)
	file := testkit.Read(t, "wsl_kernlog_rfc3339.txt")
	res := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", file))
	f := want(t, res, "logs.bond_no_active_link", "bond9", model.Crit)
	n1 := f.Detail.EN
	none(t, res, "logs.fs_error") // loop devices
	both := check(t, env, collect.OSLinux,
		testkit.S("logs.kernel_match", testkit.Read(t, "wsl_kernel_match.txt")+"\n"+file))
	jr := check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", testkit.Read(t, "wsl_kernel_match.txt")))
	if a, b := testkit.Find(both, "logs.bond_no_active_link", "bond9").Detail.EN, testkit.Find(jr, "logs.bond_no_active_link", "bond9").Detail.EN; a != b {
		t.Errorf("journal+file counted differently from journal alone:\n%s\n%s\n(file alone: %s)", a, b, n1)
	}
}

// Lines every healthy server logs must not produce findings.
func TestBenignLinesStayQuiet(t *testing.T) {
	benign := []string{
		"ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)",
		"ata3: SATA link down (SStatus 0 SControl 300)",
		"EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null)",
		"XFS (dm-0): Mounting V5 Filesystem",
		"XFS (dm-0): Ending clean mount",
		"e1000e 0000:00:19.0 eth0: NIC Link is Up 1000 Mbps Full Duplex, Flow Control: Rx/Tx",
		"IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready",
		"nvme nvme0: 8/0/0 default/read/poll queues",
		"EDAC MC: Ver: 3.0.0",
		"EDAC MC0: Giving out device to module skx_edac controller Skylake Socket#0 IMC#0: DEV 0000:3a:0a.0 (INTERRUPT)",
		"mce: CPU0: Thermal monitoring enabled (TM1)",
		"pcieport 0000:00:1c.0: AER: enabled with IRQ 122",
		"NMI watchdog: Enabled. Permanently consumes one hw-PMU counter.",
		"BTRFS info (device sda2): disk space caching is enabled",
		"md/raid1:md0: active with 2 out of 2 mirrors",
		"bond0: (slave eno1): link status definitely up, 1000 Mbps full duplex",
		"tg3 0000:02:00.0 eno1: Link is up at 1000 Mbps, full duplex",
		"sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA",
		"sd 6:0:0:0: [sdb] Synchronize Cache(10) failed: Result: hostbyte=DID_BAD_TARGET driverbyte=DRIVER_OK",
		"blk_update_request: I/O error, dev sr0, sector 0 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 0",
		"Buffer I/O error on dev loop0, logical block 0, async page read",
		"GHES: APEI firmware first mode is enabled by APEI bit and WHEA _OSC.",
		"ERST: Error Record Serialization Table (ERST) support is initialized.",
		"[Firmware Bug]: TSC_DEADLINE disabled due to Errata; please update microcode to version: 0x52 (or later)",
		"md: data-check of RAID array md0",
		"md: md0: data-check done.",
		"CPU3: Core temperature/speed normal",
		"thermal_sys: Registered thermal governor 'step_wise'",
		"usb 1-1: new high-speed USB device number 2 using xhci_hcd",
		"EXT4-fs (dm-0): re-mounted. Opts: errors=remount-ro",
	}
	var b strings.Builder
	b.WriteString("# source=journal persistent=1 tz=+0000\n")
	for i, l := range benign {
		fmt.Fprintf(&b, "2026-10-01T08:%02d:00+00:00 srv kernel: %s\n", i, l)
	}
	res := check(t, linuxEnv(), collect.OSLinux, testkit.S("logs.kernel_match", b.String()))
	for _, f := range res.Findings {
		if f.Severity != model.OK {
			t.Errorf("benign line raised %s@%s=%s: %v", f.ID, f.Target, f.Severity, f.Evidence)
		}
	}
	want(t, res, "logs.kernel_clean", "", model.OK)
}
