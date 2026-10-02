package disk

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// SandForce SSDs (Kingston SV300 here) report 177/233 with flags 0x0000 and
// VALUE/WORST/THRESH 000 when the drive database does not know them: the
// normalised value is not "life remaining". Power_On_Hours is packed and
// meaningless without a drivedb entry (raw 166060615532548).
func TestSandForceNoFalseWear(t *testing.T) {
	b := linux(scanOf("/dev/sda -d sat"), testkit.S("disk.smart:/dev/sda", testkit.Read(t, "text_sandforce_kingston_sv300.txt")))
	res := check(t, b, testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	if f := testkit.Find(res, "disk.old_disk"); f != nil {
		t.Errorf("absurd power-on hours reported: %s", f.Title.EN)
	}
	d := fact(t, res, "/dev/sda")
	if d.PercentUsed != nil || d.PowerOnHours != nil {
		t.Errorf("fact: used %v poh %v", d.PercentUsed, d.PowerOnHours)
	}
	if d.TemperatureC == nil || *d.TemperatureC != 39 {
		t.Errorf("temperature: %v", d.TemperatureC)
	}
	// A genuinely worn Intel drive (flags 0x0032, value 001) still counts (value 001 = 99 % used).
	worn := strings.Replace(testkit.Read(t, "text_sandforce_kingston_sv300.txt"),
		"233 Media_Wearout_Indicator 0x0000   000   000   000", "233 Media_Wearout_Indicator 0x0032   001   001   000", 1)
	res = check(t, linux(scanOf("/dev/sda -d sat"), testkit.S("disk.smart:/dev/sda", worn)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.ssd_wear", model.Warn, "/dev/sda")
}

// The ATA error log stores a 16-bit power-on timestamp (ACS "Life
// Timestamp", one word), so on a disk with more than 65535 hours a fresh
// error looks ancient unless the wrap is taken into account.
func TestErrorLogTimestampWraps(t *testing.T) {
	poh, last, cnt := uint64(70000), uint64(70000-65536-10), 3
	d := &diskInfo{Dev: "/dev/sda", SmartDev: "/dev/sda", WinIndex: -1,
		Smart: &smartData{Protocol: "ATA", Exit: 64, RPM: 7200, POH: &poh, ErrLogCount: &cnt, ErrLogLastPOH: &last,
			Attrs: []ataAttr{{ID: 9, Name: "Power_On_Hours", Raw: poh, RawStr: "70000"}}}}
	var got *model.Finding
	for _, f := range ataRules(d) {
		if f.ID == "disk.ata_error_log" {
			f := f
			got = &f
		}
	}
	if got == nil || got.Severity != model.Warn {
		t.Fatalf("error 10 h ago on a 70000 h disk must be recent (Warn): %+v", got)
	}
}

func TestHexRawValue(t *testing.T) {
	a := &ataAttr{ID: 5, Raw: 10, RawStr: "0x00000000000a"}
	if a.count() != 10 {
		t.Errorf("hex48 raw: %d", a.count())
	}
}

// Dell BOSS-S1/S2 presents its M.2 RAID 1 as an ATA disk "DELLBOSS VD"
// without S.M.A.R.T. (smartctl output quoted in forums.freebsd.org thread
// 73878): a RAID volume, not an unreadable disk.
func TestDellBOSSVolume(t *testing.T) {
	boss := `smartctl 7.2 2020-12-30 r5155 [x86_64-linux-5.15.0] (local build)
=== START OF INFORMATION SECTION ===
Device Model:     DELLBOSS VD
Serial Number:    2427d781f8c60010
Firmware Version: MV.R00-0
User Capacity:    480,036,847,616 bytes [480 GB]
Sector Sizes:     512 bytes logical, 4096 bytes physical
SMART support is: Unavailable - device lacks SMART capability.
`
	b := linux(
		testkit.S("disk.lsblk", `{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":480036847616,"rota":false,"tran":"sata","model":"DELLBOSS VD","serial":"2427d781f8c60010","vendor":"ATA     ","rev":"0","state":"running","hctl":"15:0:0:0","wwn":null,"mountpoint":null,"fstype":null,"pkname":null}]}`),
		scanOf("/dev/sda -d sat # /dev/sda [SAT], ATA device"),
		testkit.RC("disk.smart:/dev/sda", 4, boss, ""))
	res := check(t, b, testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	c := covState(t, res, "disk.smart", model.CovPartial)
	if strings.Contains(c.Reason.EN, "could not be read") || !strings.Contains(c.Fix.EN, "BOSS") {
		t.Errorf("coverage: %+v", c)
	}
	if d := fact(t, res, "/dev/sda"); !d.RAIDVolume {
		t.Errorf("fact: %+v", d)
	}
}

// iDRAC virtual media (vendor "iDRAC", models "LCDRIVE"/"Virtual Floppy",
// as udev reports them in Red Hat bugzilla 1111693) are not disks.
func TestBMCVirtualMediaIgnored(t *testing.T) {
	b := linux(
		testkit.S("disk.lsblk", `{"blockdevices":[
{"name":"sda","path":"/dev/sda","type":"disk","size":4000787030016,"rota":true,"tran":"sata","model":"WDC WD40EFRX-68N32N0","serial":"WD-WCC7K0000000","vendor":"ATA     "},
{"name":"sdb","path":"/dev/sdb","type":"disk","size":0,"rota":true,"tran":"usb","model":"LCDRIVE","serial":"","vendor":"iDRAC   "},
{"name":"sdc","path":"/dev/sdc","type":"disk","size":0,"rota":true,"tran":"usb","model":"Virtual Floppy","serial":"","vendor":"iDRAC   "}]}`),
		scanOf("/dev/sda -d sat # /dev/sda [SAT], ATA device",
			"# /dev/sdb -d scsi # /dev/sdb, SCSI device open failed: No medium found",
			"# /dev/sdc -d scsi # /dev/sdc, SCSI device open failed: No medium found"),
		smartSec(t, "/dev/sda", "ata_hdd_wd_healthy.json", 0))
	res := check(t, b, testkit.Env(collect.OSLinux))
	covState(t, res, "disk.smart", model.CovRan)
	for _, d := range facts(t, res).Disks {
		if d.Device == "/dev/sdb" || d.Device == "/dev/sdc" {
			t.Errorf("virtual media listed as a disk: %+v", d)
		}
	}
}

// smartctl on Windows names Intel RST/CSMI ports "/dev/csmi0,1"; the comma
// belongs to the device name, not to a -d type.
func TestCSMISectionName(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows, testkit.S("disk.smart_scan", "/dev/csmi0,1 -d ata # /dev/csmi0,1, ATA device"),
		smartSec(t, "/dev/csmi0,1", "ata_hdd_wd_healthy.json", 0))
	res := check(t, b, testkit.Env(collect.OSWindows))
	d := facts(t, res).Disks
	if len(d) != 1 || !strings.HasPrefix(d[0].SmartDevice, "/dev/csmi0,1") || d[0].BehindRAID {
		t.Errorf("disks: %+v", d)
	}
	if dev, typ := splitSmartInstance("/dev/bus/0,sat+megaraid,1"); dev != "/dev/bus/0" || typ != "sat+megaraid,1" {
		t.Errorf("megaraid split: %q %q", dev, typ)
	}
	if dev, typ := splitSmartInstance("/dev/sg2,areca,1/1"); dev != "/dev/sg2" || typ != "areca,1/1" {
		t.Errorf("areca split: %q %q", dev, typ)
	}
}

// Windows shows many NVMe serials as the namespace EUI-64
// ("0000_0000_0000_0000_0026_B738_4082_5615."), smartctl prints the real
// serial; the EUI-64 in smartctl's namespace data ties them together.
func TestWindowsNVMeMatchedByEUI64(t *testing.T) {
	nv := `{"smartctl":{"version":[7,4],"exit_status":0},"device":{"name":"/dev/nvme0","info_name":"/dev/nvme0","type":"nvme","protocol":"NVMe"},
"model_name":"KINGSTON SNV3S500G","serial_number":"50026B7686A0B123","firmware_version":"P3AR2B12",
"nvme_namespaces":[{"id":1,"eui64":{"oui":9911,"ext_id":241600452117}}],
"smart_status":{"passed":true,"nvme":{"value":0}},
"nvme_smart_health_information_log":{"critical_warning":0,"temperature":44,"available_spare":100,"available_spare_threshold":10,"percentage_used":2,"power_on_hours":900,"media_errors":0,"num_err_log_entries":0}}`
	b := winBundle(t, true, testkit.S("disk.smart_scan", "/dev/nvme0 -d nvme # /dev/nvme0, NVMe device"), testkit.S("disk.smart:/dev/nvme0", nv))
	res := check(t, b, testkit.Env(collect.OSWindows))
	if n := len(facts(t, res).Disks); n != 3 {
		t.Errorf("NVMe smartctl data must merge into PhysicalDisk2, got %d disks", n)
	}
	if d := fact(t, res, "PhysicalDisk2"); d.SmartDevice != "/dev/nvme0 -d nvme" {
		t.Errorf("fact: %+v", d)
	}
}

// A temperature-only NVMe critical warning is a cooling problem: the action
// must not lead with "replace the disk".
func TestNVMeTemperatureOnlyWarning(t *testing.T) {
	cw, temp := 2, 82
	d := &diskInfo{Dev: "/dev/nvme0", SmartDev: "/dev/nvme0", WinIndex: -1,
		Smart: &smartData{Protocol: "NVMe", Exit: 0, RPM: -1, TempC: &temp, Passed: boolp(false), NVMe: &nvmeLog{CriticalWarning: &cw}}}
	fs := nvmeRules(d)
	if len(fs) != 1 || fs[0].ID != "disk.nvme_critical_warning" {
		t.Fatalf("findings: %+v", fs)
	}
	if strings.Contains(fs[0].Action.EN, "Replace the disk") || !strings.Contains(fs[0].Action.EN, "cooling") {
		t.Errorf("action: %s", fs[0].Action.EN)
	}
}

func TestCoverageCommands(t *testing.T) {
	res := check(t, linux(testkit.Skipped("disk.bench", "disabled"), testkit.S("disk.lsblk", `{"blockdevices":[]}`)), testkit.Env(collect.OSLinux))
	c := covState(t, res, "disk.bench", model.CovSkipped)
	if c.Cmd != "diagward check --bench /var/tmp" || strings.Contains(c.Fix.EN, "bench-dir") || strings.Contains(c.Fix.VI, "bench-dir") ||
		!strings.Contains(c.Fix.EN, "--bench-size") {
		t.Errorf("bench coverage: %+v", c)
	}
	env := testkit.Env(collect.OSLinux)
	env.PM, env.Root = "apt", true
	res = check(t, linux(testkit.Missing("disk.smart_scan", "smartctl")), env)
	c = covState(t, res, "disk.smart", model.CovSkipped)
	if c.Cmd != "apt-get install -y --no-install-recommends smartmontools" || strings.Contains(c.Fix.EN, "apt-get") {
		t.Errorf("smart coverage: %+v", c)
	}
	res = check(t, testkit.Bundle(collect.OSWindows, testkit.Skipped("disk.bench", "not-applicable"), testkit.S("disk.win_physical", "[]")), testkit.Env(collect.OSWindows))
	c = covState(t, res, "disk.bench", model.CovSkipped)
	if strings.Contains(c.Reason.EN, "not-applicable") {
		t.Errorf("windows bench reason: %+v", c.Reason)
	}
}

// SVN builds of smartmontools print "smartctl pre-7.5 ..." (still JSON-capable).
func TestPreReleaseVersion(t *testing.T) {
	res := check(t, linux(testkit.S("disk.smart_version", "smartctl pre-7.5 2024-12-01 r5640 [x86_64-linux-6.8.0] (local build)")), testkit.Env(collect.OSLinux))
	if f := facts(t, res); f.SmartctlVersion != "7.5" || !f.SmartctlJSON {
		t.Errorf("version: %+v", f)
	}
}
