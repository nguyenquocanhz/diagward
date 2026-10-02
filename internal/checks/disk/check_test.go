package disk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func check(t *testing.T, b *collect.Bundle, env model.Env) model.Result {
	t.Helper()
	res := Check(b, env)
	testkit.Validate(t, res)
	if res.Domain != "disk" {
		t.Fatalf("domain %q", res.Domain)
	}
	return res
}

func linux(secs ...*collect.Section) *collect.Bundle {
	return testkit.Bundle(collect.OSLinux, secs...)
}

// smartSec builds a disk.smart:<inst> section from a fixture, with the
// exit status smartctl reported (the collector records it as rc).
func smartSec(t *testing.T, inst, file string, rc int) *collect.Section {
	return testkit.RC("disk.smart:"+inst, rc, testkit.Read(t, file), "")
}

func scanOf(lines ...string) *collect.Section {
	return testkit.S("disk.smart_scan", strings.Join(lines, "\n"))
}

func mustFind(t *testing.T, res model.Result, id string, sev model.Severity, target ...string) *model.Finding {
	t.Helper()
	f := testkit.Find(res, id, target...)
	if f == nil {
		t.Fatalf("finding %s %v not found; have %v", id, target, testkit.IDs(res))
	}
	if f.Severity != sev {
		t.Fatalf("finding %s: severity %s, want %s (%s)", id, f.Severity, sev, f.Title.EN)
	}
	if sev >= model.Warn && f.Part == nil && f.Target != "" && !strings.HasPrefix(id, "disk.bench") {
		t.Errorf("finding %s: problem finding without Part", id)
	}
	return f
}

func noWorse(t *testing.T, res model.Result, max model.Severity) {
	t.Helper()
	for _, f := range res.Findings {
		if f.Severity > max {
			t.Errorf("unexpected %s finding %s on %s: %s", f.Severity, f.ID, f.Target, f.Title.EN)
		}
	}
}

func covState(t *testing.T, res model.Result, id, want string) *model.Coverage {
	t.Helper()
	c := testkit.Cov(res, id)
	if c == nil {
		t.Fatalf("coverage %s missing; have %+v", id, res.Coverage)
	}
	if c.State != want {
		t.Fatalf("coverage %s: state %s, want %s (reason %q)", id, c.State, want, c.Reason.EN)
	}
	return c
}

func facts(t *testing.T, res model.Result) *Facts {
	t.Helper()
	f, ok := res.Facts.(*Facts)
	if !ok {
		t.Fatalf("facts are %T", res.Facts)
	}
	return f
}

func fact(t *testing.T, res model.Result, device string) DiskFact {
	t.Helper()
	for _, d := range facts(t, res).Disks {
		if d.Device == device {
			return d
		}
	}
	t.Fatalf("no disk fact %q in %+v", device, facts(t, res).Disks)
	return DiskFact{}
}

func TestNoDiskSections(t *testing.T) {
	res := check(t, linux(testkit.S("meta.ident", "uid=0")), testkit.Env(collect.OSLinux))
	if len(res.Findings) != 0 || len(res.Coverage) != 0 || len(res.Tables) != 0 {
		t.Fatalf("expected empty result, got %+v", res)
	}
	if res := check(t, testkit.Bundle(collect.OSBMC), testkit.Env(collect.OSBMC)); len(res.Coverage) != 0 {
		t.Fatal("bmc bundle should be empty")
	}
}

func TestHealthyATA(t *testing.T) {
	b := linux(
		scanOf("/dev/sdb -d sat # /dev/sdb [SAT], ATA device"),
		testkit.S("disk.smart_version", "smartctl 7.0 2018-12-30 r4883 [x86_64-linux-5.4.0] (local build)"),
		smartSec(t, "/dev/sdb", "ata_hdd_wd_healthy.json", 0),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	f := mustFind(t, res, "disk.smart_healthy", model.OK)
	if !strings.Contains(f.Detail.EN, "/dev/sdb") {
		t.Errorf("detail: %s", f.Detail.EN)
	}
	covState(t, res, "disk.smart", model.CovRan)
	d := fact(t, res, "/dev/sdb")
	if d.Kind != "HDD" || d.Vendor != "Western Digital" || d.Serial == "" || d.Health != "PASSED" || d.TemperatureC == nil || *d.TemperatureC != 32 {
		t.Errorf("fact: %+v", d)
	}
	if facts(t, res).SmartctlVersion != "7.0" || !facts(t, res).SmartctlJSON {
		t.Errorf("version facts: %+v", facts(t, res))
	}
}

func TestFailedATA(t *testing.T) {
	b := linux(scanOf("/dev/sdc -d usbjmicron # /dev/sdc [USB JMicron], ATA device"),
		smartSec(t, "/dev/sdc", "ata_hdd_hitachi_failed.json", 216))
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.smart_failed", model.Crit, "/dev/sdc")
	if f.Part == nil || f.Part.Serial != "MSK423Y20S3HBC" || f.Part.Kind != "disk" || f.Part.Vendor != "Hitachi" || f.Part.Size != "500 GB" {
		t.Errorf("part: %+v", f.Part)
	}
	if !strings.Contains(f.Action.VI, "MSK423Y20S3HBC") || !strings.Contains(f.Action.VI, "Sao lưu") {
		t.Errorf("action vi: %s", f.Action.VI)
	}
	if !strings.Contains(strings.Join(f.Evidence, "\n"), "Reallocated_Sector_Ct") {
		t.Errorf("evidence should list the failing attribute: %v", f.Evidence)
	}
	if testkit.Find(res, "disk.smart_attr_failing") != nil {
		t.Error("failing attributes are already in smart_failed")
	}
	u := mustFind(t, res, "disk.unreadable_sectors", model.Crit)
	if !strings.Contains(u.Title.VI, "8 sector") {
		t.Errorf("title: %s", u.Title.VI)
	}
	mustFind(t, res, "disk.reallocated_sectors", model.Crit) // 1975 >= 100
	mustFind(t, res, "disk.selftest_failed", model.Crit)     // extended read failure, no newer extended pass
	mustFind(t, res, "disk.ata_error_log", model.Info)       // last error 3635 h before now
	mustFind(t, res, "disk.old_disk", model.Info)
	if d := fact(t, res, "/dev/sdc"); d.Interface != "USB" || d.Status != model.Crit || d.Pending == nil || *d.Pending != 8 {
		t.Errorf("fact: %+v", d)
	}
}

func TestReallocatedThresholds(t *testing.T) {
	// 304 reallocated on a 7200 rpm disk: Crit (>= 100).
	res := check(t, linux(scanOf("/dev/sda -d sat"), smartSec(t, "/dev/sda", "ata_hdd_seagate_realloc304.json", 0)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.reallocated_sectors", model.Crit, "/dev/sda")
	if testkit.Find(res, "disk.smart_failed") != nil {
		t.Error("smart passed: no smart_failed expected")
	}

	// A handful of reallocated sectors: Warn.
	txt := strings.Replace(testkit.Read(t, "text64_sat_hdd.txt"),
		"  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0",
		"  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       8", 1)
	if !strings.Contains(txt, "-       8\n") {
		t.Fatal("fixture edit failed")
	}
	res = check(t, linux(scanOf("/dev/sg2 -d sat"), testkit.S("disk.smart:/dev/sg2", txt)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.reallocated_sectors", model.Warn)
}

func TestMegaraidPassthrough(t *testing.T) {
	b := linux(
		testkit.S("disk.lsblk", `{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":3998614552576,"rota":true,"tran":null,"model":"MR9361-8i","serial":"00c2a1b3","vendor":"AVAGO","rev":"4.68","state":"running","hctl":"0:2:0:0","wwn":"0x600605b00a1b2c3d","mountpoint":null,"fstype":null,"pkname":null}]}`),
		scanOf("/dev/sda -d scsi # /dev/sda, SCSI device", "/dev/bus/0 -d sat+megaraid,0 # /dev/bus/0 [megaraid_disk_00] [SAT], ATA device", "/dev/bus/0 -d sat+megaraid,1 # /dev/bus/0 [megaraid_disk_01] [SAT], ATA device"),
		testkit.RC("disk.smart:/dev/sda", 4, strings.Replace(testkit.Read(t, "text71_megaraid_vd_intel.txt"), "Intel", "AVAGO", 1), ""),
		smartSec(t, "/dev/bus/0,sat+megaraid,0", "ata_megaraid14_seagate_healthy.json", 4),
		smartSec(t, "/dev/bus/0,sat+megaraid,1", "ata_megaraid_realloc387.json", 4),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.reallocated_sectors", model.Crit, "/dev/bus/0 [sat+megaraid,1]")
	if !strings.Contains(f.Part.Location, "megaraid") || !strings.Contains(f.Part.Location, "device ID 1") {
		t.Errorf("location: %q", f.Part.Location)
	}
	mustFind(t, res, "disk.smart_healthy", model.OK)
	// The RAID volume itself is not a disk problem, and the passthrough
	// disks were read, so coverage is complete.
	covState(t, res, "disk.smart", model.CovRan)
	if d := fact(t, res, "/dev/sda"); !d.RAIDVolume || d.Status != model.OK {
		t.Errorf("volume fact: %+v", d)
	}
	if d := fact(t, res, "/dev/bus/0 [sat+megaraid,0]"); !d.BehindRAID || d.Serial != "ZAD2C11G" {
		t.Errorf("passthrough fact: %+v", d)
	}
}

func TestRAIDVolumeHidesDisks(t *testing.T) {
	b := linux(scanOf("/dev/sdb -d scsi # /dev/sdb, SCSI device"),
		smartSec(t, "/dev/sdb", "scsi_intel_raid_volume.json", 4))
	res := check(t, b, testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	c := covState(t, res, "disk.smart", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "behind the hardware RAID") || !strings.Contains(c.Fix.EN, "megaraid,N") {
		t.Errorf("coverage: %+v", c)
	}
	// text form, AVAGO MegaRAID volume
	b = linux(scanOf("/dev/sda -d scsi"), testkit.RC("disk.smart:/dev/sda", 4, testkit.Read(t, "text71_megaraid_vd_intel.txt"), ""))
	res = check(t, b, testkit.Env(collect.OSLinux))
	covState(t, res, "disk.smart", model.CovPartial)
	if d := fact(t, res, "/dev/sda"); !d.RAIDVolume || d.Health != "n/a (RAID volume)" {
		t.Errorf("fact: %+v", d)
	}
}

func TestCRCAndOldErrorLog(t *testing.T) {
	res := check(t, linux(scanOf("/dev/sdb -d sat"), smartSec(t, "/dev/sdb", "ata_hdd_hgst_crc_errlog.json", 64)), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.crc_errors", model.Warn)
	if !strings.Contains(f.Action.VI, "cáp") {
		t.Errorf("crc action: %s", f.Action.VI)
	}
	e := mustFind(t, res, "disk.ata_error_log", model.Info)
	if !strings.Contains(e.Detail.EN, "ICRC") {
		t.Errorf("errlog detail: %s", e.Detail.EN)
	}
	mustFind(t, res, "disk.old_disk", model.Info)
	if testkit.Find(res, "disk.smart_healthy") != nil {
		t.Error("a disk with a Warn must not be counted healthy")
	}

	res = check(t, linux(scanOf("/dev/sdb -d sat"), smartSec(t, "/dev/sdb", "ata_hdd_seagate_old_errlog.json", 64)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.ata_error_log", model.Info) // 98 errors, last at 7042 h of 100161 h
	noWorse(t, res, model.Info)
}

func TestSSDWear(t *testing.T) {
	res := check(t, linux(scanOf("/dev/sdf -d sat"), smartSec(t, "/dev/sdf", "ata_ssd_intel_s3500_wear85.json", 0)), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.ssd_wear", model.Warn)
	if !strings.Contains(f.Title.EN, "85%") || !strings.Contains(f.Evidence[0], "Media_Wearout_Indicator") {
		t.Errorf("wear: %s %v", f.Title.EN, f.Evidence)
	}
	if d := fact(t, res, "/dev/sdf"); d.Kind != "SSD" || d.PercentUsed == nil || *d.PercentUsed != 85 {
		t.Errorf("fact %+v", d)
	}

	// Device statistics (19%) take precedence and are below the threshold.
	res = check(t, linux(scanOf("/dev/sda -d sat"), smartSec(t, "/dev/sda", "ata_ssd_samsung860_devstats.json", 0)), testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	if d := fact(t, res, "/dev/sda"); d.PercentUsed == nil || *d.PercentUsed != 19 {
		t.Errorf("devstats wear: %+v", d)
	}

	// Samsung 840 with 108 CRC errors.
	res = check(t, linux(scanOf("/dev/sda -d sat"), smartSec(t, "/dev/sda", "ata_ssd_samsung840_crc.json", 0)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.crc_errors", model.Warn)
	if testkit.Find(res, "disk.temperature") != nil {
		t.Error("33 °C must not raise a temperature finding")
	}
}

func TestNVMe(t *testing.T) {
	res := check(t, linux(scanOf("/dev/nvme0 -d nvme"), smartSec(t, "/dev/nvme0", "nvme_sabrent_healthy.json", 0)), testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK) // 4871 error-log entries ("Invalid Field in Command") are benign
	mustFind(t, res, "disk.smart_healthy", model.OK)
	d := fact(t, res, "/dev/nvme0")
	if d.Kind != "NVMe" || d.NVMeErrorLogEntries == nil || *d.NVMeErrorLogEntries != 4871 || d.PercentUsed == nil || *d.PercentUsed != 4 {
		t.Errorf("fact: %+v", d)
	}

	res = check(t, linux(scanOf("/dev/nvme0 -d nvme"), smartSec(t, "/dev/nvme0", "nvme_samsung970_media_errors.json", 0)), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.nvme_media_errors", model.Warn)
	if f.Part == nil || f.Part.Vendor != "Samsung" || f.Part.Serial != "S466NX0M776250H" {
		t.Errorf("part: %+v", f.Part)
	}

	res = check(t, linux(scanOf("/dev/nvme0 -d nvme"), smartSec(t, "/dev/nvme0", "nvme_samsung_critical_warning.json", 8)), testkit.Env(collect.OSLinux))
	c := mustFind(t, res, "disk.nvme_critical_warning", model.Crit)
	if !strings.Contains(c.Detail.EN, "volatile memory backup") || !strings.Contains(c.Detail.VI, "power-loss protection") {
		t.Errorf("decoded bits: %s / %s", c.Detail.EN, c.Detail.VI)
	}
	if testkit.Find(res, "disk.smart_failed") != nil {
		t.Error("critical warning must not be reported twice")
	}
}

func TestNVMeWearAndSpare(t *testing.T) {
	js := testkit.Read(t, "nvme_sabrent_healthy.json")
	js = strings.Replace(js, `"percentage_used": 4`, `"percentage_used": 104`, 1)
	js = strings.Replace(js, `"available_spare": 100`, `"available_spare": 3`, 1)
	res := check(t, linux(scanOf("/dev/nvme0 -d nvme"), testkit.S("disk.smart:/dev/nvme0", js)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.ssd_wear", model.Crit)
	mustFind(t, res, "disk.nvme_spare_low", model.Crit) // 3% < threshold 5%

	js = strings.Replace(testkit.Read(t, "nvme_sabrent_healthy.json"), `"percentage_used": 4`, `"percentage_used": 85`, 1)
	res = check(t, linux(scanOf("/dev/nvme0 -d nvme"), testkit.S("disk.smart:/dev/nvme0", js)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.ssd_wear", model.Warn)
}

func TestSCSI(t *testing.T) {
	res := check(t, linux(scanOf("/dev/sdb -d scsi"), smartSec(t, "/dev/sdb", "scsi_seagate_healthy.json", 0)), testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	d := fact(t, res, "/dev/sdb")
	if d.Vendor != "SEAGATE" || d.Model != "ST1200MM0088" || d.Kind != "HDD" {
		t.Errorf("fact: %+v", d)
	}

	res = check(t, linux(scanOf("/dev/sdaa -d scsi"), smartSec(t, "/dev/sdaa", "scsi_extended_selftests.json", 0)), testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)

	res = check(t, linux(scanOf("/dev/sdb -d scsi"), smartSec(t, "/dev/sdb", "scsi_seagate_defects_uncorrected.json", 0)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.grown_defects", model.Crit) // 260
	u := mustFind(t, res, "disk.scsi_uncorrected", model.Crit)
	if !strings.Contains(strings.Join(u.Evidence, "\n"), "write: 535") {
		t.Errorf("evidence: %v", u.Evidence)
	}
	mustFind(t, res, "disk.old_disk", model.Info)

	// SAS text output (smartctl 7.1, whitespace collapsed by the source).
	res = check(t, linux(scanOf("/dev/sdc -d scsi"), testkit.S("disk.smart:/dev/sdc", testkit.Read(t, "text71_sas_hgst.txt"))), testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	d = fact(t, res, "/dev/sdc")
	if d.Health != "PASSED" || d.TemperatureC == nil || *d.TemperatureC != 32 || d.GrownDefects == nil || d.UncorrectedErrors == nil {
		t.Errorf("sas text fact: %+v", d)
	}
}

func TestSCSIFailurePredictionAndTemperature(t *testing.T) {
	js := testkit.Read(t, "scsi_seagate_healthy.json")
	js = strings.Replace(js, `"smart_status": {
    "passed": true
  }`, `"smart_status": {"passed": false, "scsi": {"asc": 93, "ascq": 16, "ie_string": "HARDWARE IMPENDING FAILURE GENERAL HARD DRIVE FAILURE"}}`, 1)
	js = strings.Replace(js, `"current": 31`, `"current": 61`, 1)
	if !strings.Contains(js, "IMPENDING") {
		t.Fatal("fixture edit failed")
	}
	res := check(t, linux(scanOf("/dev/sdb -d scsi"), testkit.S("disk.smart:/dev/sdb", js)), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.smart_failed", model.Crit)
	if !strings.Contains(f.Title.EN, "IMPENDING") {
		t.Errorf("title: %s", f.Title.EN)
	}
	mustFind(t, res, "disk.temperature", model.Crit) // trip 60
}

func TestTextFallback(t *testing.T) {
	b := linux(testkit.S("disk.smart_version", "smartctl 6.2 2017-02-27 r4394 [x86_64-linux-3.10.0-1160.el7.x86_64] (local build)"),
		scanOf("/dev/sda -d sat"), testkit.RC("disk.smart:/dev/sda", 216, testkit.Read(t, "text62_ata_failed.txt"), ""))
	res := check(t, b, testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.smart_failed", model.Crit)
	u := mustFind(t, res, "disk.unreadable_sectors", model.Crit)
	if !strings.Contains(u.Title.EN, "656") {
		t.Errorf("title %s", u.Title.EN)
	}
	mustFind(t, res, "disk.reallocated_sectors", model.Crit)
	mustFind(t, res, "disk.reported_uncorrect", model.Warn)
	mustFind(t, res, "disk.command_timeout", model.Info) // "0 0 2"
	mustFind(t, res, "disk.smart_attr_failed_past", model.Info)
	s := mustFind(t, res, "disk.selftest_failed", model.Crit)
	if !strings.Contains(s.Evidence[0], "1953524992") {
		t.Errorf("selftest evidence %v", s.Evidence)
	}
	mustFind(t, res, "disk.ata_error_log", model.Warn) // 4 h ago
	if facts(t, res).SmartctlJSON {
		t.Error("6.2 has no JSON")
	}
	d := fact(t, res, "/dev/sda")
	if d.Serial != "Z4Z1ABCD" || d.SizeBytes != 2000398934016 || d.Kind != "HDD" || d.PowerOnHours == nil || *d.PowerOnHours != 34512 {
		t.Errorf("fact: %+v", d)
	}

	// smartctl 5.40 output with 81 pending sectors (Thomas-Krenn example).
	res = check(t, linux(scanOf("/dev/sdb -d sat"), testkit.S("disk.smart:/dev/sdb", testkit.Read(t, "text540_ata_pending_selftest.txt"))), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.unreadable_sectors", model.Crit)
	mustFind(t, res, "disk.reported_uncorrect", model.Warn)
	mustFind(t, res, "disk.crc_errors", model.Warn)
	if testkit.Find(res, "disk.smart_failed") != nil {
		t.Error("overall PASSED: no smart_failed expected")
	}

	// Healthy text outputs of several versions and formats.
	for _, f := range []string{"text64_sat_hdd.txt", "text66_ata_ssd.txt", "text71_ata_hdd_selftest_running.txt"} {
		res := check(t, linux(scanOf("/dev/sda -d sat"), testkit.S("disk.smart:/dev/sda", testkit.Read(t, f))), testkit.Env(collect.OSLinux))
		noWorse(t, res, model.OK)
		if testkit.Find(res, "disk.smart_healthy") == nil {
			t.Errorf("%s: no OK finding; %v", f, testkit.IDs(res))
		}
	}
}

func TestTextNVMe(t *testing.T) {
	res := check(t, linux(scanOf("/dev/nvme0 -d nvme"), testkit.S("disk.smart:/dev/nvme0", testkit.Read(t, "text72_nvme_toshiba.txt"))), testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	d := fact(t, res, "/dev/nvme0")
	if d.Kind != "NVMe" || d.PercentUsed == nil || *d.PercentUsed != 28 || d.PowerOnHours == nil || *d.PowerOnHours != 5809 ||
		d.NVMeErrorLogEntries == nil || *d.NVMeErrorLogEntries != 1356 || d.SizeBytes != 256060514304 {
		t.Errorf("fact: %+v", d)
	}
	// 42 °C against the drive's own 82 °C warning threshold: fine; at 83 °C it warns, at 85 it is Crit.
	hot := strings.Replace(testkit.Read(t, "text72_nvme_toshiba.txt"), "Temperature:                        42 Celsius", "Temperature:                        85 Celsius", 1)
	res = check(t, linux(scanOf("/dev/nvme0 -d nvme"), testkit.S("disk.smart:/dev/nvme0", hot)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.temperature", model.Crit)
}

func TestTemperatureNoDeviceLimitNeverCrit(t *testing.T) {
	js := strings.Replace(testkit.Read(t, "ata_hdd_wd_healthy.json"), `"temperature": {
    "current": 32
  }`, `"temperature": {"current": 75}`, 1)
	if !strings.Contains(js, `"current": 75`) {
		t.Fatal("fixture edit failed")
	}
	res := check(t, linux(scanOf("/dev/sdb -d sat"), testkit.S("disk.smart:/dev/sdb", js)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.temperature", model.Warn) // no device limit: HDD 60 °C default, never Crit
}

func TestStandby(t *testing.T) {
	for _, f := range []string{"json_standby.json", "text_standby.txt"} {
		res := check(t, linux(scanOf("/dev/sdc -d sat"), testkit.RC("disk.smart:/dev/sdc", 2, testkit.Read(t, f), "")), testkit.Env(collect.OSLinux))
		noWorse(t, res, model.OK)
		d := fact(t, res, "/dev/sdc")
		if !d.Standby || d.Health != "standby" {
			t.Errorf("%s: fact %+v", f, d)
		}
		if res.Tables[0].Note.EN == "" || res.Tables[0].Rows[0].Cells[10] != "standby" {
			t.Errorf("%s: table %+v", f, res.Tables[0])
		}
		if c := covState(t, res, "disk.smart", model.CovPartial); !strings.Contains(c.Reason.EN, "standby") || !strings.Contains(c.Reason.EN, "/dev/sdc") {
			t.Errorf("%s: coverage %+v", f, c.Reason)
		}
	}
}

func TestVirtualMachine(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "microsoft"
	b := linux(
		testkit.S("disk.lsblk", testkit.Read(t, "lsblk_wsl_msft.json")),
		testkit.S("disk.smart_scan", testkit.Read(t, "scan_wsl.txt")),
		smartSec(t, "/dev/sda", "scsi_msft_virtual_disk.json", 2),
		testkit.RC("disk.smart:/dev/sdb", 2, testkit.Read(t, "text75_msft_virtual_disk.txt"), ""),
	)
	res := check(t, b, env)
	noWorse(t, res, model.OK)
	c := covState(t, res, "disk.smart", model.CovSkipped)
	if !strings.Contains(c.Reason.VI, "máy ảo") {
		t.Errorf("reason: %s", c.Reason.VI)
	}
	covState(t, res, "disk.inventory", model.CovRan)
	if len(facts(t, res).Disks) != 4 {
		t.Errorf("want the 4 virtual disks, got %+v", facts(t, res).Disks)
	}
	for _, d := range facts(t, res).Disks {
		if !d.Virtual {
			t.Errorf("%s should be virtual", d.Device)
		}
	}
}

func TestCoverageStates(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	res := check(t, linux(testkit.Missing("disk.smart_scan", "smartctl")), env)
	c := covState(t, res, "disk.smart", model.CovSkipped)
	if c.Cmd != "dnf install -y smartmontools" || !strings.Contains(c.Fix.EN, "smartmontools") {
		t.Errorf("fix: %s, cmd %q", c.Fix.EN, c.Cmd)
	}

	env.Root = false
	res = check(t, linux(testkit.S("disk.smart_version", "smartctl 7.4 2023-08-01 r5530"), testkit.Skipped("disk.smart_scan", "not-root")), env)
	c = covState(t, res, "disk.smart", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "sudo") {
		t.Errorf("fix: %s", c.Fix.EN)
	}

	env = testkit.Env(collect.OSLinux)
	env.Virtual, env.Container = "lxc", true
	res = check(t, linux(testkit.Skipped("disk.smart_scan", "container"), testkit.Skipped("disk.smartd", "container")), env)
	covState(t, res, "disk.smart", model.CovSkipped)
	covState(t, res, "disk.smartd", model.CovSkipped)

	// scan failed outright
	res = check(t, linux(testkit.RC("disk.smart_scan", 1, "", "smartctl: permission denied")), testkit.Env(collect.OSLinux))
	covState(t, res, "disk.smart", model.CovFailed)

	// lsblk missing: sysfs fallback, partial
	res = check(t, linux(testkit.Missing("disk.lsblk", "lsblk"),
		testkit.S("disk.sysblock", "/sys/block/sda/size=7814037168\n/sys/block/sda/queue/rotational=1\n/sys/block/sda/device/model=ST4000NM0035-1V4\n/sys/block/sda/device/vendor=ATA\n/sys/block/loop0/size=0\n")), testkit.Env(collect.OSLinux))
	covState(t, res, "disk.inventory", model.CovPartial)
	if d := fact(t, res, "/dev/sda"); d.SizeBytes != 7814037168*512 || d.Kind != "HDD" || d.Vendor != "Seagate" {
		t.Errorf("sysfs fact: %+v", d)
	}

	// one disk unreadable, scan with an open failure
	b := linux(testkit.S("disk.smart_scan", testkit.Read(t, "scan_megaraid_vd.txt")),
		smartSec(t, "/dev/nvme0", "nvme_sabrent_healthy.json", 0),
		testkit.RC("disk.smart:/dev/bus/0,megaraid,8", 2, `{"smartctl":{"version":[7,3],"exit_status":2,"messages":[{"string":"Smartctl open device: /dev/bus/0 [megaraid_disk_08] failed: INQUIRY failed","severity":"error"}]}}`, ""))
	res = check(t, b, testkit.Env(collect.OSLinux))
	c = covState(t, res, "disk.smart", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "/dev/bus/0 [megaraid,8]") || !strings.Contains(c.Reason.EN, "could not open: /dev/sdb") {
		t.Errorf("reason: %s", c.Reason.EN)
	}
}

func TestSmartTimeout(t *testing.T) {
	s := &collect.Section{Name: "disk.smart:/dev/sdd", RC: 124, Timeout: true}
	res := check(t, linux(scanOf("/dev/sdd -d sat"), s), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.smart_timeout", model.Warn, "/dev/sdd")
	if !strings.Contains(f.Action.EN, "dmesg") {
		t.Errorf("action: %s", f.Action.EN)
	}
	covState(t, res, "disk.smart", model.CovPartial)
}

func TestLsblkFormats(t *testing.T) {
	for _, f := range []string{"lsblk_wsl_msft.json", "lsblk_wsl_msft_P.txt"} {
		ds, err := parseLsblk(testkit.Read(t, f))
		if err != nil || len(ds) != 4 {
			t.Fatalf("%s: %v %d", f, err, len(ds))
		}
		if ds[3].Path != "/dev/sdd" || ds[3].Bytes != 1099511627776 || ds[3].Vendor != "Msft" || ds[3].HCTL != "0:0:0:3" || ds[3].Rota == nil || !*ds[3].Rota {
			t.Errorf("%s: %+v", f, ds[3])
		}
	}
	ds, err := parseLsblk(testkit.Read(t, "lsblk_old_strings.json"))
	if err != nil || len(ds) != 3 {
		t.Fatalf("old: %v %+v", err, ds)
	}
	if ds[0].Bytes != 4000787030016 || ds[0].Vendor != "ATA" || ds[0].Path != "/dev/sda" || len(ds[0].Mounts) != 1 || ds[0].Mounts[0] != "/boot" {
		t.Errorf("old sda: %+v", ds[0])
	}
	if ds[2].Rota == nil || *ds[2].Rota || ds[2].Tran != "nvme" {
		t.Errorf("old nvme: %+v", ds[2])
	}
	ds, _ = parseLsblk(`NAME="sda" KNAME="sda" TYPE="disk" SIZE="500107862016" ROTA="0" MODEL="Samsung\x20SSD\x20860" MOUNTPOINT="" FSTYPE=""` + "\n" +
		`NAME="sda1" KNAME="sda1" TYPE="part" SIZE="500106813440" ROTA="0" MODEL="" MOUNTPOINT="/" FSTYPE="ext4" PKNAME="sda"`)
	if len(ds) != 1 || ds[0].Model != "Samsung SSD 860" {
		t.Errorf("pairs: %+v", ds)
	}
	if _, err := parseLsblk("garbage"); err == nil {
		t.Error("garbage must fail")
	}

	// Merge: lsblk NVMe namespace + smartctl controller.
	b := linux(testkit.S("disk.lsblk", testkit.Read(t, "lsblk_old_strings.json")),
		scanOf("/dev/sda -d sat", "/dev/sdb -d sat", "/dev/nvme0 -d nvme"),
		smartSec(t, "/dev/nvme0", "nvme_sabrent_healthy.json", 0))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if n := len(facts(t, res).Disks); n != 3 {
		t.Fatalf("want 3 merged disks, got %d: %+v", n, facts(t, res).Disks)
	}
	if d := fact(t, res, "/dev/nvme0n1"); d.SmartDevice != "/dev/nvme0 -d nvme" || d.Vendor != "Sabrent" || d.Model != "Sabrent Rocket 4.0 1TB" {
		t.Errorf("merge: %+v", d)
	}
	// sda and sdb have no SMART section: coverage partial.
	covState(t, res, "disk.smart", model.CovPartial)
}

func TestScan(t *testing.T) {
	es := parseScan(testkit.Read(t, "scan_megaraid_nvme.txt"))
	if len(es) != 3 || es[2].Dev != "/dev/bus/0" || es[2].Type != "sat+megaraid,60" {
		t.Fatalf("%+v", es)
	}
	es = parseScan(testkit.Read(t, "scan_megaraid_json.json"))
	if len(es) != 10 || es[9].Type != "megaraid,14" {
		t.Fatalf("json: %+v", es)
	}
	es = parseScan(testkit.Read(t, "scan_megaraid_vd.txt"))
	if len(es) != 5 || !es[4].OpenFailed || es[4].Reason != "INQUIRY failed" || es[4].Dev != "/dev/sdb" {
		t.Fatalf("open failed: %+v", es)
	}
}

func TestSmartd(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Distro, env.Like, env.PM = "ubuntu", "debian", "apt"
	res := check(t, linux(testkit.S("disk.smartd", testkit.Read(t, "smartd_ubuntu_inactive.txt"))), env)
	f := mustFind(t, res, "disk.smartd_not_running", model.Info)
	if !strings.Contains(f.Action.EN, "systemctl enable --now smartmontools") {
		t.Errorf("action: %s", f.Action.EN)
	}
	covState(t, res, "disk.smartd", model.CovRan)
	if sf := facts(t, res).Smartd; sf == nil || sf.Running || !sf.Installed || len(sf.Config) != 1 {
		t.Errorf("facts: %+v", sf)
	}

	res = check(t, linux(testkit.S("disk.smartd", "installed=1\nactive_smartd=active\nenabled_smartd=enabled\nactive_smartmontools=inactive\nenabled_smartmontools=\nprocess=1\n")), testkit.Env(collect.OSLinux))
	if testkit.Find(res, "disk.smartd_not_running") != nil {
		t.Error("smartd is running")
	}

	res = check(t, linux(testkit.S("disk.smartd", "process=0\n")), testkit.Env(collect.OSLinux))
	f = mustFind(t, res, "disk.smartd_not_running", model.Info)
	if !strings.Contains(f.Action.EN, "dnf install -y smartmontools") || !strings.Contains(f.Action.EN, "enable --now smartd") {
		t.Errorf("rhel action: %s", f.Action.EN)
	}

	// Not on a VM.
	env = testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res = check(t, linux(testkit.S("disk.smartd", "process=0\n")), env)
	if testkit.Find(res, "disk.smartd_not_running") != nil {
		t.Error("no smartd advice on a VM")
	}
}

func TestBench(t *testing.T) {
	gnu := "dir=/root\nmb=128\nfs=ext2/ext3\nsource=/dev/sdd\nfree_kb=998362460\nwrite_direct=1\nwrite_line=134217728 bytes (134 MB, 128 MiB) copied, 0.227606 s, 591 MB/s\nread_direct=1\nread_line=134217728 bytes (134 MB, 128 MiB) copied, 0.0840307 s, 1.6 GB/s\ncleaned=1\n"
	res := check(t, linux(testkit.S("disk.bench", gnu)), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.bench", model.OK, "/root")
	if !strings.Contains(f.Title.EN, "write 590 MB/s") || !strings.Contains(f.Title.EN, "read 1597 MB/s") {
		t.Errorf("title: %s", f.Title.EN)
	}
	covState(t, res, "disk.bench", model.CovRan)
	if bf := facts(t, res).Bench; bf == nil || bf.WriteMBps != 589.7 {
		t.Errorf("bench facts: %+v", bf)
	}

	slow := "dir=/data\nmb=256\nfs=xfs\nsource=/dev/md0\nwrite_direct=1\nwrite_line=268435456 bytes (268 MB) copied, 21.5 s, 12.5 MB/s\nread_direct=1\nread_line=268435456 bytes (268 MB) copied, 2.1 s, 128 MB/s\n"
	res = check(t, linux(testkit.S("disk.bench", slow)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.bench_slow", model.Warn, "/data")

	busybox := "dir=/data\nmb=64\nfs=ext2/ext3\nwrite_direct=0\nwrite_line=67108864 bytes (64.0MB) copied, 0.512 seconds, 125.0MB/s\nread_direct=0\nread_line=67108864 bytes (64.0MB) copied, 4.1 seconds, 15.6MB/s\n"
	res = check(t, linux(testkit.S("disk.bench", busybox)), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.bench", model.OK) // slow read was cached/non-direct: not judged
	if r, ok := ddRate("67108864 bytes (64.0MB) copied, 0.512 seconds, 125.0MB/s"); !ok || r < 131 || r > 131.1 {
		t.Errorf("busybox rate %v %v", r, ok)
	}

	tmpfs := strings.Replace(slow, "fs=xfs", "fs=tmpfs", 1)
	res = check(t, linux(testkit.S("disk.bench", tmpfs)), testkit.Env(collect.OSLinux))
	f = mustFind(t, res, "disk.bench", model.OK)
	if !strings.Contains(f.Detail.EN, "RAM") {
		t.Errorf("tmpfs note: %s", f.Detail.EN)
	}

	res = check(t, linux(testkit.RC("disk.bench", 3, "dir=/data\nmb=256\nfs=xfs\nfree_kb=1000\nerror=no-space\n", "")), testkit.Env(collect.OSLinux))
	covState(t, res, "disk.bench", model.CovSkipped)
	res = check(t, linux(testkit.RC("disk.bench", 2, "dir=/nope\nmb=256\nerror=not-a-directory\n", "")), testkit.Env(collect.OSLinux))
	covState(t, res, "disk.bench", model.CovFailed)
	res = check(t, linux(testkit.RC("disk.bench", 124, "dir=/data\nmb=4096\nwrite_direct=1\nerror=write-timeout\n", "")), testkit.Env(collect.OSLinux))
	mustFind(t, res, "disk.bench_slow", model.Warn)
	res = check(t, linux(testkit.Skipped("disk.bench", "disabled")), testkit.Env(collect.OSLinux))
	c := covState(t, res, "disk.bench", model.CovSkipped)
	if c.Fix.EN == "" {
		t.Error("disabled bench needs a fix text")
	}
}

func winBundle(t *testing.T, admin bool, extra ...*collect.Section) *collect.Bundle {
	secs := []*collect.Section{
		testkit.S("disk.win_physical", testkit.Read(t, "win_physical.json")),
		testkit.S("disk.win_diskdrive", testkit.Read(t, "win_diskdrive.json")),
	}
	if admin {
		secs = append(secs, testkit.S("disk.win_reliability", testkit.Read(t, "win_reliability.json")),
			testkit.S("disk.win_predict", testkit.Read(t, "win_predict.json")))
	} else {
		secs = append(secs, testkit.Skipped("disk.win_reliability", "not-admin"), testkit.Skipped("disk.win_predict", "not-admin"),
			testkit.Skipped("disk.smart_scan", "not-admin"))
	}
	return testkit.Bundle(collect.OSWindows, append(secs, extra...)...)
}

func TestWindowsAdmin(t *testing.T) {
	b := winBundle(t, true, testkit.Missing("disk.smart_scan", "smartctl"))
	res := check(t, b, testkit.Env(collect.OSWindows))
	h := mustFind(t, res, "disk.win_health", model.Crit, "PhysicalDisk1")
	if h.Part == nil || h.Part.Serial != "ZC11ABCD0000C8121234" || h.Part.Vendor != "SEAGATE" || !strings.Contains(h.Part.Location, "Port 4") {
		t.Errorf("part: %+v", h.Part)
	}
	mustFind(t, res, "disk.win_predict_failure", model.Crit, "PhysicalDisk1")
	mustFind(t, res, "disk.win_uncorrected_errors", model.Crit, "PhysicalDisk1")
	mustFind(t, res, "disk.win_latency", model.Warn, "PhysicalDisk1")
	mustFind(t, res, "disk.old_disk", model.Info, "PhysicalDisk1")
	mustFind(t, res, "disk.ssd_wear", model.Warn, "PhysicalDisk0")
	ok := mustFind(t, res, "disk.smart_healthy", model.OK)
	if !strings.Contains(ok.Detail.EN, "PhysicalDisk2") {
		t.Errorf("ok: %s", ok.Detail.EN)
	}
	c := covState(t, res, "disk.smart", model.CovPartial)
	if !strings.Contains(c.Fix.EN, "smartmontools") {
		t.Errorf("fix: %s", c.Fix.EN)
	}
	if d := fact(t, res, "PhysicalDisk2"); d.Serial != "0000_0000_0000_0000_0026_B738_4082_5615" || d.Kind != "NVMe" || d.TemperatureC == nil || *d.TemperatureC != 44 {
		t.Errorf("fact: %+v", d)
	}
}

func TestWindowsNotAdmin(t *testing.T) {
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res := check(t, winBundle(t, false), env)
	mustFind(t, res, "disk.win_health", model.Crit, "PhysicalDisk1") // HealthStatus needs no admin
	c := covState(t, res, "disk.smart", model.CovPartial)
	if !strings.Contains(c.Fix.EN, "Run as administrator") {
		t.Errorf("fix: %s", c.Fix.EN)
	}
	if testkit.Find(res, "disk.win_predict_failure") != nil {
		t.Error("no predict data without admin")
	}
}

func TestWindowsNumericEnumsAndVirtual(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows, testkit.S("disk.win_physical", testkit.Read(t, "win_physical_numeric.json")))
	res := check(t, b, testkit.Env(collect.OSWindows))
	f := mustFind(t, res, "disk.win_health", model.Warn, "PhysicalDisk1")
	if !strings.Contains(f.Detail.EN, "Abnormal Latency") {
		t.Errorf("detail: %s", f.Detail.EN)
	}
	if d := fact(t, res, "PhysicalDisk0"); !d.Virtual {
		t.Errorf("virtual: %+v", d)
	}
	if d := fact(t, res, "PhysicalDisk1"); d.Kind != "HDD" || d.Interface != "SATA" || d.Vendor != "Western Digital" {
		t.Errorf("fact: %+v", d)
	}
}

func TestWindowsSmartctlMerge(t *testing.T) {
	if winSmartIndex("/dev/sda") != 0 || winSmartIndex("/dev/sdb") != 1 || winSmartIndex("/dev/sdaa") != 26 || winSmartIndex("/dev/nvme0") != -1 {
		t.Fatal("winSmartIndex")
	}
	b := winBundle(t, true,
		testkit.S("disk.smart_scan", "/dev/sda -d ata # /dev/sda, ATA device\n/dev/sdb -d scsi # /dev/sdb, SCSI device\n"),
		smartSec(t, "/dev/sdb", "scsi_seagate_defects_uncorrected.json", 0))
	res := check(t, b, testkit.Env(collect.OSWindows))
	mustFind(t, res, "disk.scsi_uncorrected", model.Crit, "PhysicalDisk1")
	if testkit.Find(res, "disk.win_uncorrected_errors") != nil {
		t.Error("Windows uncorrected counters must not repeat smartctl's")
	}
	if n := len(facts(t, res).Disks); n != 3 {
		t.Errorf("smartctl data should merge into PhysicalDisk1, got %d disks", n)
	}
	covState(t, res, "disk.smart", model.CovRan)
}

func TestWindowsLiveShape(t *testing.T) {
	// The exact output of 30-disk.ps1 on the (non-admin) dev machine.
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("disk.win_physical", `[{"FriendlyName":"KINGSTON SNV3S500G","SerialNumber":"0000_0000_0000_0000_0026_B738_4082_5615.","MediaType":"SSD","BusType":"RAID","Size":500107862016,"HealthStatus":"Healthy","OperationalStatus":"OK","FirmwareVersion":"P3AR2B12","DeviceId":"0","SpindleSpeed":0,"Model":"KINGSTON SNV3S500G","Manufacturer":null,"PhysicalLocation":"Integrated : Bus 0 : Device 23 : Function 0 : Adapter 0 : Port 2 : Target 0 : LUN 0"}]`),
		testkit.S("disk.win_diskdrive", `[{"Index":0,"Model":"NVMe KINGSTON SNV3S50","SerialNumber":"0000_0000_0000_0000_0026_B738_4082_5615.","Status":"OK","InterfaceType":"SCSI","PNPDeviceID":"SCSI\\DISK&VEN_NVME&PROD_KINGSTON_SNV3S50\\4&76E01B6&0&020000","Size":500105249280,"FirmwareRevision":"P3AR2B12"}]`),
		testkit.Skipped("disk.win_reliability", "not-admin"), testkit.Skipped("disk.win_predict", "not-admin"),
		testkit.Missing("disk.smart_scan", "smartctl"))
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res := check(t, b, env)
	f := mustFind(t, res, "disk.smart_healthy", model.OK)
	if !strings.Contains(f.Detail.EN, "Windows reports") {
		t.Errorf("detail: %s", f.Detail.EN)
	}
	if d := fact(t, res, "PhysicalDisk0"); d.RAIDVolume || !strings.HasPrefix(d.Interface, "NVMe") {
		t.Errorf("VMD NVMe: %+v", d)
	}
}

// TestGarbage feeds every fixture truncated at many points, plus junk, to
// every section the check reads. Nothing may panic and every result must
// stay valid.
func TestGarbage(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*"))
	junk := []string{"", "{", "}", "[", "null", "[]", "{}", `{"smartctl":`, "\x00\xff\xfe", "ID# ATTRIBUTE_NAME\n  5 Reallocated_Sector_Ct 0x0033 abc",
		"==DW:x:BEGIN disk.smart:/dev/sda", strings.Repeat("9", 400), `{"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":-1}}]}}`,
		`{"nvme_smart_health_information_log":{"critical_warning":"x"}}`, `[{"DeviceId":null,"HealthStatus":{"a":1}}]`,
		"write_line=1 bytes copied, 0 s\nread_line=x", "Error 1 occurred at disk power-on lifetime: 99999999999999999999999 hours"}
	var inputs []string
	for _, f := range files {
		if strings.HasSuffix(f, "SOURCES.md") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, frac := range []int{1, 3, 7, 10, 25, 50, 75, 90, 99} {
			inputs = append(inputs, s[:len(s)*frac/100])
		}
		inputs = append(inputs, s)
	}
	inputs = append(inputs, junk...)
	names := []string{"disk.lsblk", "disk.sysblock", "disk.smart_scan", "disk.smart:/dev/sda", "disk.smart:/dev/bus/0,megaraid,1", "disk.smartd", "disk.bench", "disk.smart_version"}
	winNames := []string{"disk.win_physical", "disk.win_reliability", "disk.win_predict", "disk.win_diskdrive", "disk.smart:/dev/sda"}
	for i, in := range inputs {
		var secs []*collect.Section
		for _, n := range names {
			secs = append(secs, testkit.RC(n, i%3, in, in[:min(len(in), 20)]))
		}
		res := Check(linux(secs...), testkit.Env(collect.OSLinux))
		testkit.Validate(t, res)
		secs = nil
		for _, n := range winNames {
			secs = append(secs, testkit.S(n, in))
		}
		res = Check(testkit.Bundle(collect.OSWindows, secs...), testkit.Env(collect.OSWindows))
		testkit.Validate(t, res)
	}
}

func TestParsersEdgeCases(t *testing.T) {
	for in, want := range map[string]uint64{"5,809": 5809, "5.809": 5809, "29.426.647 [15,0 TB]": 29426647, "0": 0, "12 000 138 625 024 bytes": 12000138625024} {
		if got, ok := digitsUint(in); !ok || got != want {
			t.Errorf("digitsUint(%q) = %d %v", in, got, ok)
		}
	}
	if _, ok := digitsUint("abc"); ok {
		t.Error("digitsUint(abc)")
	}
	if b, ok := capacityBytes("500,107,862,016 bytes [500 GB]"); !ok || b != 500107862016 {
		t.Errorf("capacity %d", b)
	}
	for raw, want := range map[string]uint64{"0 0 2": 2, "0": 0, "4295032833": 3, "12": 12} {
		a := &ataAttr{ID: 188, RawStr: raw}
		a.Raw, _ = leadingUint(raw)
		if got := commandTimeouts(a); got != want {
			t.Errorf("commandTimeouts(%q) = %d, want %d", raw, got, want)
		}
	}
	if (&ataAttr{RawStr: "32 (Min/Max 24/38)", Raw: 163210330144}).count() != 32 {
		t.Error("count must use the printed raw value")
	}
	if nvmeController("/dev/nvme10n1") != "/dev/nvme10" || nvmeController("/dev/sda") != "/dev/sda" {
		t.Error("nvmeController")
	}
	if normSerial(" 0000_0000_0026_B738. ") != normSerial("00000000 0026B738") {
		t.Error("normSerial")
	}
	if !raidVolume("DELL", "PERC H730P Mini") || !raidVolume("HP", "LOGICAL VOLUME") || raidVolume("SEAGATE", "ST4000NM0025") || !raidVolume("AVAGO", "MR9361-16i") {
		t.Error("raidVolume")
	}
	if !lessDev("/dev/sdb", "/dev/sdaa") || !lessDev("/dev/nvme2", "/dev/nvme10") {
		t.Error("lessDev")
	}
	if standbyFromMessage("Device is in SLEEP mode, exit(2)") != "SLEEP" || standbyFromMessage("Device is in ACTIVE mode") != "" {
		t.Error("standby")
	}
}

func TestSmartOpenFailedJSON(t *testing.T) {
	// Windows smartctl without access: exit 2, error message, no device data.
	b := testkit.Bundle(collect.OSWindows, testkit.S("disk.smart_scan", "/dev/sda -d ata"), smartSec(t, "/dev/sda", "smart_open_failed_windows.json", 2))
	res := check(t, b, testkit.Env(collect.OSWindows))
	noWorse(t, res, model.OK)
	d := fact(t, res, "/dev/sda")
	if !strings.Contains(d.SmartError, "Open failed") {
		t.Errorf("error: %+v", d)
	}
}

func TestAttributeFailingWhilePassed(t *testing.T) {
	// A pre-fail attribute at its threshold while the overall verdict still
	// says PASSED (the verdict is cached on some drives): Crit on its own.
	js := strings.Replace(testkit.Read(t, "ata_hdd_wd_healthy.json"), `"when_failed": ""`, `"when_failed": "now"`, 1)
	res := check(t, linux(scanOf("/dev/sdb -d sat"), testkit.RC("disk.smart:/dev/sdb", 16, js, "")), testkit.Env(collect.OSLinux))
	f := mustFind(t, res, "disk.smart_attr_failing", model.Crit)
	if !strings.Contains(f.Evidence[0], "Raw_Read_Error_Rate") || !strings.Contains(f.Evidence[0], "when_failed=now") {
		t.Errorf("evidence: %v", f.Evidence)
	}
	if testkit.Find(res, "disk.smart_failed") != nil {
		t.Error("verdict was PASSED")
	}
}

func TestSANLun(t *testing.T) {
	b := linux(testkit.S("disk.lsblk", `{"blockdevices":[{"name":"sdc","kname":"sdc","path":"/dev/sdc","type":"disk","size":"1099511627776","rota":"1","tran":"iscsi","model":"VIRTUAL-DISK","serial":"","vendor":"LIO-ORG ","rev":"4.0","state":"running","hctl":"7:0:0:0","wwn":null,"mountpoint":null,"fstype":null,"pkname":null}]}`),
		scanOf("/dev/sdc -d scsi"), testkit.RC("disk.smart:/dev/sdc", 4, "smartctl 7.2\n=== START OF INFORMATION SECTION ===\nVendor:               LIO-ORG\nProduct:              VIRTUAL-DISK\nSMART support is:     Unavailable - device lacks SMART capability.\n", ""))
	res := check(t, b, testkit.Env(collect.OSLinux))
	noWorse(t, res, model.OK)
	c := covState(t, res, "disk.smart", model.CovSkipped)
	if !strings.Contains(c.Reason.EN, "SAN") {
		t.Errorf("reason: %s", c.Reason.EN)
	}
	if d := fact(t, res, "/dev/sdc"); d.Kind != "SAN LUN" {
		t.Errorf("fact: %+v", d)
	}
}

func TestHPESmartArray(t *testing.T) {
	lv := "smartctl 7.2 2020-12-30 r5155\n=== START OF INFORMATION SECTION ===\nVendor:               HP\nProduct:              LOGICAL VOLUME\nRevision:             7.00\nUser Capacity:        599,934,840,832 bytes [599 GB]\nSMART support is:     Unavailable - device lacks SMART capability.\n"
	res := check(t, linux(scanOf("/dev/sda -d scsi"), testkit.RC("disk.smart:/dev/sda", 4, lv, "")), testkit.Env(collect.OSLinux))
	c := covState(t, res, "disk.smart", model.CovPartial)
	if !strings.Contains(c.Fix.EN, "cciss,N") {
		t.Errorf("fix: %s", c.Fix.EN)
	}
	// With the drives found by the collector's cciss probe.
	res = check(t, linux(scanOf("/dev/sda -d scsi"), testkit.RC("disk.smart:/dev/sda", 4, lv, ""),
		smartSec(t, "/dev/sda,cciss,0", "scsi_seagate_healthy.json", 0)), testkit.Env(collect.OSLinux))
	covState(t, res, "disk.smart", model.CovRan)
	if d := fact(t, res, "/dev/sda [cciss,0]"); !d.BehindRAID || d.Model != "ST1200MM0088" {
		t.Errorf("fact: %+v", d)
	}
}
