package cpu

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

const svcRunning = "rasdaemon.installed=1\nrasdaemon.active=active\nrasdaemon.enabled=enabled\nrasdaemon.running=1\nmcelog.installed=0\nmcelog.active=inactive\nmcelog.enabled=not-found\nmcelog.running=0\n"

func ident(uptime string) *collect.Section {
	return testkit.S("meta.ident", "hostname=srv01\nuid=0\nuptime="+uptime+"\n")
}

// server builds a healthy two-socket Dell R740 bundle; extra sections
// replace same-named defaults (later duplicates win in Bundle.Get).
func server(t *testing.T, extra ...*collect.Section) *collect.Bundle {
	secs := []*collect.Section{
		ident("864000.12"),
		testkit.S("cpu.cpuinfo", testkit.Read(t, "cpuinfo_summary_xeon_2s.txt")),
		testkit.S("cpu.sysfs", "/sys/devices/system/cpu/online=0-39\n/sys/devices/system/cpu/offline=\n/sys/devices/system/cpu/present=0-39\n/sys/devices/system/cpu/smt/control=on\n"),
		testkit.S("cpu.dmidecode", testkit.Read(t, "dmidecode_processor_dell_r740.txt")),
		testkit.S("cpu.throttle", testkit.Read(t, "throttle_sysfs_zero.txt")),
		testkit.S("cpu.services", svcRunning),
		testkit.RC("cpu.ras_status", 1, testkit.Read(t, "ras_status_not_loaded.txt"), ""),
		testkit.S("cpu.ras_summary", testkit.Read(t, "ras_summary_empty_ubuntu_0.8.4.txt")),
		testkit.S("cpu.ras_errors", testkit.Read(t, "ras_errors_empty_ubuntu_0.8.4.txt")),
		testkit.Missing("cpu.mcelog_log", "/var/log/mcelog"),
		testkit.Missing("cpu.mcelog_client", "mcelog"),
	}
	return testkit.Bundle(collect.OSLinux, append(secs, extra...)...)
}

func run(t *testing.T, b *collect.Bundle, env model.Env) model.Result {
	t.Helper()
	res := Check(b, env)
	testkit.Validate(t, res)
	if res.Domain != "cpu" {
		t.Fatalf("domain %q", res.Domain)
	}
	return res
}

func worst(res model.Result) model.Severity {
	w := model.OK
	for _, f := range res.Findings {
		w = model.Worst(w, f.Severity)
	}
	return w
}

func must(t *testing.T, res model.Result, id string, sev model.Severity) *model.Finding {
	t.Helper()
	f := testkit.Find(res, id)
	if f == nil {
		t.Fatalf("missing finding %s; have %v", id, testkit.IDs(res))
	}
	if f.Severity != sev {
		t.Fatalf("%s: severity %s, want %s (%s)", id, f.Severity, sev, f.Title.EN)
	}
	return f
}

func covState(t *testing.T, res model.Result, id, state string) *model.Coverage {
	t.Helper()
	c := testkit.Cov(res, id)
	if c == nil {
		t.Fatalf("missing coverage %s", id)
	}
	if c.State != state {
		t.Fatalf("coverage %s: %s, want %s (%s)", id, c.State, state, c.Reason.EN)
	}
	return c
}

func TestHealthyServer(t *testing.T) {
	res := run(t, server(t), testkit.Env(collect.OSLinux))
	if w := worst(res); w != model.OK {
		t.Fatalf("worst %s: %v", w, testkit.IDs(res))
	}
	must(t, res, "cpu.sockets_ok", model.OK)
	must(t, res, "cpu.throttle_ok", model.OK)
	must(t, res, "cpu.mce_ok", model.OK)
	covState(t, res, "cpu.inventory", model.CovRan)
	covState(t, res, "cpu.mce", model.CovRan)
	covState(t, res, "cpu.throttle", model.CovRan)
	f := res.Facts.(*Facts)
	if len(f.Processors) != 2 || f.Processors[0].Cores != 18 || f.Processors[0].Model != "Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz" {
		t.Fatalf("processors: %+v", f.Processors)
	}
	if f.Logical != 40 || f.Sockets != 2 {
		t.Fatalf("facts: %+v", f)
	}
}

// cpuinfo1s is what /proc/cpuinfo shows when the second CPU of the
// two-socket server is off: one physical package.
const cpuinfo1s = "20\tprocessors\n20\tvendor_id=GenuineIntel\n20\tmodel name=Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz\n20\tphysical id=0\n"

func TestSocketDisabledByBIOS(t *testing.T) {
	b := server(t, testkit.S("cpu.dmidecode", testkit.Read(t, "dmidecode_processor_r740_cpu2_disabled.txt")),
		testkit.S("cpu.cpuinfo", cpuinfo1s))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.socket_disabled", model.Crit)
	if f.Target != "CPU2" || f.Part == nil || f.Part.Kind != "cpu" || f.Part.Location != "CPU2" {
		t.Fatalf("target/part: %q %+v", f.Target, f.Part)
	}
	if testkit.Find(res, "cpu.sockets_ok") != nil {
		t.Fatal("sockets_ok must not be reported with a disabled socket")
	}
	if !strings.Contains(f.Action.VI, "BMC") {
		t.Fatal("action should point to the BMC log")
	}
}

func TestStaleDisabledSocketStatus(t *testing.T) {
	// The BIOS still says "Disabled By BIOS" but Linux runs both packages:
	// the processor works, the SMBIOS table is out of date.
	b := server(t, testkit.S("cpu.dmidecode", testkit.Read(t, "dmidecode_processor_r740_cpu2_disabled.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "cpu.socket_disabled") != nil {
		t.Fatalf("no Crit when the OS sees every socket: %v", testkit.IDs(res))
	}
	f := must(t, res, "cpu.socket_status_stale", model.Info)
	if f.Target != "CPU2" || !strings.Contains(f.Detail.VI, "2 socket") {
		t.Fatalf("%q %q", f.Target, f.Detail.VI)
	}
	if w := worst(res); w > model.Info {
		t.Fatalf("worst %s", w)
	}
}

func TestVMwareDisabledSocketsAreNormal(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "vmware"
	b := server(t, testkit.S("cpu.dmidecode", testkit.Read(t, "dmidecode_processor_vmware.txt")))
	res := run(t, b, env)
	if w := worst(res); w > model.Info {
		t.Fatalf("VM sockets must not alarm: %v", testkit.IDs(res))
	}
	for _, tb := range res.Tables {
		if tb.ID == "cpu.sockets" {
			if len(tb.Rows) != 2 || !strings.Contains(tb.Note.EN, "62") {
				t.Fatalf("rows %d note %q", len(tb.Rows), tb.Note.EN)
			}
		}
	}
}

func TestHypervisorFlagCountsAsVirtual(t *testing.T) {
	// Detection failed in env, but /proc/cpuinfo has the hypervisor flag.
	b := server(t,
		testkit.S("cpu.cpuinfo", "4\tprocessors\n4\thypervisor\n4\tmodel name=QEMU Virtual CPU\n"),
		testkit.S("cpu.dmidecode", testkit.Read(t, "dmidecode_processor_vmware.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "cpu.socket_disabled") != nil {
		t.Fatal("hypervisor flag present: no socket alarm")
	}
}

func TestIdleSocketIsNotAFault(t *testing.T) {
	// Real HP DL360 Gen8 dump: CPU 2 reports "Populated, Idle".
	b := server(t, testkit.S("cpu.dmidecode", testkit.Read(t, "dmidecode_processor_hp_dl360g8.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if w := worst(res); w != model.OK {
		t.Fatalf("worst %s: %v", w, testkit.IDs(res))
	}
	must(t, res, "cpu.sockets_ok", model.OK)
}

func TestOtherDMIDumps(t *testing.T) {
	for _, f := range []string{"dmidecode_processor_hpe_dl380g10.txt", "dmidecode_processor_qemu.txt"} {
		res := run(t, server(t, testkit.S("cpu.dmidecode", testkit.Read(t, f))), testkit.Env(collect.OSLinux))
		if w := worst(res); w != model.OK {
			t.Errorf("%s: worst %s: %v", f, w, testkit.IDs(res))
		}
	}
}

func TestOfflineCPU(t *testing.T) {
	b := server(t,
		testkit.S("cpu.lscpu", testkit.Read(t, "lscpu_text_centos7_offline.txt")),
		testkit.S("cpu.sysfs", testkit.Read(t, "sysfs_cpu_one_offline.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.cpus_offline", model.Warn)
	if !strings.Contains(f.Title.EN, "1 of 40") {
		t.Fatalf("title %q", f.Title.EN)
	}
	// SMT turned off: offline siblings are expected.
	b = server(t, testkit.S("cpu.sysfs", "/sys/devices/system/cpu/online=0-19\n/sys/devices/system/cpu/offline=20-39\n/sys/devices/system/cpu/present=0-39\n/sys/devices/system/cpu/smt/control=off\n"))
	res = run(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "cpu.cpus_offline") != nil {
		t.Fatal("SMT off must not report offline CPUs")
	}
}

func TestHotplugSlotsAreNotOfflineCPUs(t *testing.T) {
	// possible=0-127 but present=0-31: "offline" lists the empty hot-plug
	// slots the ACPI tables announce, not CPUs that were turned off.
	b := server(t, testkit.S("cpu.sysfs", testkit.Read(t, "sysfs_cpu_hotplug_slots.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "cpu.cpus_offline"); f != nil {
		t.Fatalf("false alarm: %s", f.Title.EN)
	}
	// One present CPU offline among the hot-plug slots: only it counts.
	b = server(t, testkit.S("cpu.sysfs", "/sys/devices/system/cpu/online=0-6,8-31\n/sys/devices/system/cpu/offline=7,32-127\n/sys/devices/system/cpu/present=0-31\n/sys/devices/system/cpu/possible=0-127\n"))
	res = run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.cpus_offline", model.Warn)
	if f.Target != "CPU 7" || !strings.Contains(f.Title.EN, "1 of 32") || !strings.Contains(f.Detail.VI, "CPU 7 đang offline") {
		t.Fatalf("%q %q %q", f.Target, f.Title.EN, f.Detail.VI)
	}
}

func TestLscpuOnlyWithoutSysfs(t *testing.T) {
	b := testkit.Bundle(collect.OSLinux, ident("100"),
		testkit.S("cpu.lscpu", testkit.Read(t, "lscpu_text_centos7_offline.txt")),
		testkit.Skipped("cpu.dmidecode", "not-root"))
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res := run(t, b, env)
	must(t, res, "cpu.cpus_offline", model.Warn)
	c := covState(t, res, "cpu.inventory", model.CovPartial)
	if !strings.Contains(c.Fix.EN, "sudo") {
		t.Fatalf("fix %q", c.Fix.EN)
	}
	if f := res.Facts.(*Facts); f.Sockets != 2 || f.Model != "Intel(R) Xeon(R) CPU E5-2630 v4 @ 2.20GHz" {
		t.Fatalf("facts %+v", f)
	}
}

func TestLscpuJSON(t *testing.T) {
	m := lscpuFields(testkit.Read(t, "lscpu_json_wsl.json"), "")
	if m["Model name"] != "Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz" || m["Hypervisor vendor"] != "Microsoft" || m["Socket(s)"] != "1" {
		t.Fatalf("%v", m)
	}
	// util-linux >= 2.38 nests fields under "children".
	nested := `{"lscpu":[{"field":"Vendor ID:","data":"AuthenticAMD","children":[{"field":"Model name:","data":"AMD EPYC 7302 16-Core Processor","children":[{"field":"Socket(s):","data":"2"}]}]}]}`
	m = lscpuFields(nested, "")
	if m["Model name"] != "AMD EPYC 7302 16-Core Processor" || m["Socket(s)"] != "2" {
		t.Fatalf("%v", m)
	}
}

func TestThrottle(t *testing.T) {
	b := server(t, testkit.S("cpu.throttle", testkit.Read(t, "throttle_sysfs_hot.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.throttle", model.Warn)
	if f.Target != "package 0" || !strings.Contains(f.Title.EN, "152") || !strings.Contains(f.Title.EN, "often") {
		t.Fatalf("target %q title %q", f.Target, f.Title.EN)
	}
	if !strings.Contains(f.Detail.EN, "48.2 s") {
		t.Fatalf("detail %q", f.Detail.EN)
	}
	ft := res.Facts.(*Facts).Throttle
	if len(ft) != 2 || ft[0].PackageEvents != 152 || ft[0].CoreEventsMax != 3 || ft[0].CPUsAffected != 2 || ft[1].PackageEvents != 0 {
		t.Fatalf("throttle facts %+v", ft)
	}
	// Older kernels: counts without times.
	b = server(t, testkit.S("cpu.throttle", testkit.Read(t, "throttle_sysfs_counts_only.txt")))
	res = run(t, b, testkit.Env(collect.OSLinux))
	must(t, res, "cpu.throttle", model.Warn)
}

func TestBriefThrottleIsInfo(t *testing.T) {
	// A couple of short episodes in 10 days (boot, turbo peaks): normal.
	b := server(t, testkit.S("cpu.throttle", testkit.Read(t, "throttle_sysfs_boot_blip.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.throttle", model.Info)
	if !strings.Contains(f.Title.EN, "briefly") || f.Action.VI == "" {
		t.Fatalf("%q", f.Title.EN)
	}
	if w := worst(res); w > model.Info {
		t.Fatalf("worst %s: %v", w, testkit.IDs(res))
	}
	// Ten minutes throttled in total is Warn even with few episodes.
	b = server(t, testkit.S("cpu.throttle", "/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count=12\n/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_total_time_ms=600000\n/sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count=0\n/sys/devices/system/cpu/cpu0/topology/physical_package_id=0\n"))
	must(t, run(t, b, testkit.Env(collect.OSLinux)), "cpu.throttle", model.Warn)
}

func TestThrottleUnavailable(t *testing.T) {
	// AMD / no therm_throt: only topology files.
	b := server(t, testkit.S("cpu.throttle", "/sys/devices/system/cpu/cpu0/topology/physical_package_id=0\n"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	c := covState(t, res, "cpu.throttle", model.CovSkipped)
	if !strings.Contains(c.Reason.EN, "AMD") {
		t.Fatalf("reason %q", c.Reason.EN)
	}
	b = server(t, testkit.Skipped("cpu.throttle", "container"))
	res = run(t, b, testkit.Env(collect.OSLinux))
	covState(t, res, "cpu.throttle", model.CovSkipped)
}

func TestRasdaemonCPUErrors(t *testing.T) {
	b := server(t, testkit.S("cpu.ras_errors", testkit.Read(t, "ras_errors_cpu_uncorrected.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.mce_uncorrected", model.Crit)
	if f.Target != "socket 0" || !strings.Contains(f.Detail.EN, "Data CACHE Level-0 Data-Read Error") {
		t.Fatalf("target %q detail %q", f.Target, f.Detail.EN)
	}
	if !strings.Contains(f.Detail.VI, "không phải lỗi phần mềm") {
		t.Fatal("must say it is a hardware event")
	}
	must(t, res, "cpu.mce_corrected", model.Info) // 1 recent corrected
	must(t, res, "cpu.mce_history", model.Info)   // June event, outside 30 days
	must(t, res, "cpu.ras_other_events", model.Info)
	if testkit.Find(res, "cpu.mce_ok") != nil {
		t.Fatal("no OK with errors")
	}
}

func TestManyCorrectedIsWarn(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("MCE events:\n")
	for i := 1; i <= 12; i++ {
		sb.WriteString(strings.ReplaceAll("N 2026-09-29 22:14:05 +0700 error: Generic CACHE Level-2 Generic Error, bank 2, mcg mcgstatus=0, mci Corrected_error Error_enabled, cpu=0x00000003, socketid=0x00000001, bank=0x00000002\n", "N", string(rune('0'+i%10))))
	}
	res := run(t, server(t, testkit.S("cpu.ras_errors", sb.String())), testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.mce_corrected", model.Warn)
	if f.Target != "socket 1" {
		t.Fatalf("target %q", f.Target)
	}
}

func TestRasdaemonMemoryMCEGoesToMemoryDomain(t *testing.T) {
	b := server(t, testkit.S("cpu.ras_errors", testkit.Read(t, "ras_errors_intel_memory.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "cpu.mce_memory_corrected") != nil || testkit.Find(res, "cpu.mce_corrected") != nil {
		t.Fatalf("memory MCE must be left to the memory domain: %v", testkit.IDs(res))
	}
	f := must(t, res, "cpu.mce_ok", model.OK)
	if !strings.Contains(f.Title.EN, "memory section") {
		t.Fatalf("title %q", f.Title.EN)
	}
}

func TestAMDMemoryMCEWithoutEDAC(t *testing.T) {
	// Real rasdaemon issue #121: Zen 4 corrected UMC error, no EDAC events.
	b := server(t,
		testkit.S("cpu.ras_summary", testkit.Read(t, "ras_summary_issue121_amd.txt")),
		testkit.S("cpu.ras_errors", testkit.Read(t, "ras_errors_issue121_amd.txt")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.mce_memory_corrected", model.Info)
	if f.Component != model.CompMemory {
		t.Fatalf("component %q", f.Component)
	}
	if worst(res) > model.Info {
		t.Fatalf("one corrected error must not warn: %v", testkit.IDs(res))
	}
}

func TestSummaryOnly(t *testing.T) {
	b := server(t,
		testkit.S("cpu.ras_summary", testkit.Read(t, "ras_summary_issue121_amd.txt")),
		testkit.RC("cpu.ras_errors", 1, "", "DBD::SQLite::db prepare failed: no such table"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	must(t, res, "cpu.mce_corrected", model.Info)
	covState(t, res, "cpu.mce", model.CovRan)
}

func TestOldRasdaemonPartialFailure(t *testing.T) {
	// Real rasdaemon issue #33: ras-mc-ctl 0.6.6 dies on a missing table
	// after printing the memory summary.
	b := server(t,
		testkit.RC("cpu.ras_summary", 255, testkit.Read(t, "ras_summary_issue33_ce.txt"), testkit.Read(t, "ras_summary_issue33_ce.err")),
		testkit.RC("cpu.ras_errors", 255, "", testkit.Read(t, "ras_summary_issue33_ce.err")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	covState(t, res, "cpu.mce", model.CovRan)
	must(t, res, "cpu.mce_ok", model.OK)
}

func TestRasFailed(t *testing.T) {
	b := server(t,
		testkit.RC("cpu.ras_summary", 2, "", "Can't connect to database /var/lib/rasdaemon/ras-mc_event.db"),
		testkit.RC("cpu.ras_errors", 2, "", "Can't connect to database"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	c := covState(t, res, "cpu.mce", model.CovFailed)
	if !strings.Contains(c.Reason.EN, "database") {
		t.Fatalf("reason %q", c.Reason.EN)
	}
}

func TestMcelogOldEventsAreHistory(t *testing.T) {
	// Real records from 2016 (Arch forum) and 2019 (mcelog issue #74):
	// uncorrected, but years old: history only, never Crit.
	for _, fx := range []string{"mcelog_log_arch_uncorrected.txt", "mcelog_syslog_rhel8_srar.txt"} {
		b := server(t,
			testkit.Missing("cpu.ras_status", "ras-mc-ctl"), testkit.Missing("cpu.ras_summary", "ras-mc-ctl"), testkit.Missing("cpu.ras_errors", "ras-mc-ctl"),
			testkit.S("cpu.services", "rasdaemon.installed=0\nmcelog.installed=1\nmcelog.active=active\nmcelog.running=1\n"),
			testkit.S("cpu.mcelog_log", testkit.Read(t, fx)))
		res := run(t, b, testkit.Env(collect.OSLinux))
		must(t, res, "cpu.mce_history", model.Info)
		if w := worst(res); w > model.Info {
			t.Errorf("%s: worst %s %v", fx, w, testkit.IDs(res))
		}
		covState(t, res, "cpu.mce", model.CovRan)
	}
}

func TestMcelogRecentUncorrectedIsCrit(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Now = time.Unix(1548833366, 0).Add(48 * time.Hour)
	b := server(t, testkit.S("cpu.mcelog_log", testkit.Read(t, "mcelog_syslog_rhel8_srar.txt")),
		testkit.S("cpu.ras_errors", "No MCE errors.\n"))
	res := run(t, b, env)
	f := must(t, res, "cpu.mce_uncorrected", model.Crit)
	if f.Target != "socket 0" || !strings.Contains(f.Evidence[0], "CPU 21 bank 1") {
		t.Fatalf("target %q evidence %v", f.Target, f.Evidence)
	}
}

func TestMcelogCorrectedThermal(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	b := server(t,
		testkit.Missing("cpu.ras_status", "ras-mc-ctl"), testkit.Missing("cpu.ras_summary", "ras-mc-ctl"), testkit.Missing("cpu.ras_errors", "ras-mc-ctl"),
		testkit.S("cpu.services", "rasdaemon.installed=0\nmcelog.installed=1\nmcelog.active=active\nmcelog.running=1\n"),
		testkit.S("cpu.mcelog_log", testkit.Read(t, "mcelog_log_corrected_thermal.txt")),
		testkit.S("cpu.throttle", "/sys/devices/system/cpu/cpu0/topology/physical_package_id=0\n"))
	res := run(t, b, env)
	must(t, res, "cpu.mce_memory_corrected", model.Info)
	f := must(t, res, "cpu.mce_corrected", model.Warn) // "yellow" threshold
	if f.Target != "socket 1" || !strings.Contains(f.Evidence[0], "Large number of corrected cache errors") {
		t.Fatalf("target %q evidence %v", f.Target, f.Evidence)
	}
	must(t, res, "cpu.throttle", model.Info) // one thermal event: brief
	covState(t, res, "cpu.throttle", model.CovPartial)
}

func TestNoLogger(t *testing.T) {
	b := server(t,
		testkit.S("cpu.services", "rasdaemon.installed=0\nrasdaemon.active=inactive\nmcelog.installed=0\nmcelog.active=inactive\n"),
		testkit.Missing("cpu.ras_status", "ras-mc-ctl"), testkit.Missing("cpu.ras_summary", "ras-mc-ctl"), testkit.Missing("cpu.ras_errors", "ras-mc-ctl"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	f := must(t, res, "cpu.no_mce_logger", model.Info)
	if !strings.Contains(f.Action.EN, "dnf install -y rasdaemon") {
		t.Fatalf("action %q", f.Action.EN)
	}
	c := covState(t, res, "cpu.mce", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "rasdaemon") {
		t.Fatalf("fix %q", c.Fix.EN)
	}
	// On a VM no nagging finding.
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res = run(t, b, env)
	if testkit.Find(res, "cpu.no_mce_logger") != nil {
		t.Fatal("no logger finding on VMs")
	}
}

func TestLoggerStopped(t *testing.T) {
	b := server(t, testkit.S("cpu.services", "rasdaemon.installed=1\nrasdaemon.active=inactive\nrasdaemon.enabled=disabled\nrasdaemon.running=0\nmcelog.installed=0\n"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	must(t, res, "cpu.mce_logger_stopped", model.Info)
	covState(t, res, "cpu.mce", model.CovPartial)
}

func TestRasdaemonNeverRan(t *testing.T) {
	// Real ras-mc-ctl 0.8.4 output when /var/lib/rasdaemon/ras-mc_event.db
	// has no tables: rasdaemon was installed but never started.
	b := server(t,
		testkit.S("cpu.services", "rasdaemon.installed=1\nrasdaemon.active=inactive\nrasdaemon.enabled=disabled\nrasdaemon.running=0\nmcelog.installed=0\n"),
		testkit.RC("cpu.ras_summary", 2, "", testkit.Read(t, "ras_summary_nodb_ubuntu_0.8.4.err")),
		testkit.RC("cpu.ras_errors", 255, "", testkit.Read(t, "ras_errors_nodb_ubuntu_0.8.4.err")))
	res := run(t, b, testkit.Env(collect.OSLinux))
	c := covState(t, res, "cpu.mce", model.CovSkipped)
	if c.Cmd != "systemctl enable --now rasdaemon" || strings.Contains(c.Reason.EN, "DBD") {
		t.Fatalf("cmd %q reason %q", c.Cmd, c.Reason.EN)
	}
	must(t, res, "cpu.mce_logger_stopped", model.Info)
	if testkit.Find(res, "cpu.mce_ok") != nil {
		t.Fatal("no history: must not claim no errors")
	}
	// New collector: the database file is absent, ras-mc-ctl was not run.
	b = server(t,
		testkit.S("cpu.services", "rasdaemon.installed=1\nrasdaemon.active=inactive\nrasdaemon.running=0\n"),
		testkit.Missing("cpu.ras_summary", "/var/lib/rasdaemon/ras-mc_event.db"),
		testkit.Missing("cpu.ras_errors", "/var/lib/rasdaemon/ras-mc_event.db"))
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	c = covState(t, run(t, b, env), "cpu.mce", model.CovSkipped)
	if c.Cmd != "sudo systemctl enable --now rasdaemon" {
		t.Fatalf("cmd %q", c.Cmd)
	}
}

func TestCoverageCommands(t *testing.T) {
	b := server(t, testkit.S("cpu.services", "rasdaemon.installed=0\nmcelog.installed=0\n"),
		testkit.Missing("cpu.ras_status", "ras-mc-ctl"), testkit.Missing("cpu.ras_summary", "ras-mc-ctl"), testkit.Missing("cpu.ras_errors", "ras-mc-ctl"),
		testkit.Missing("cpu.dmidecode", "dmidecode"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	if c := covState(t, res, "cpu.mce", model.CovSkipped); c.Cmd != "dnf install -y rasdaemon && systemctl enable --now rasdaemon" || strings.Contains(c.Fix.EN, "dnf") {
		t.Fatalf("mce cmd %q fix %q", c.Cmd, c.Fix.EN)
	}
	if c := covState(t, res, "cpu.inventory", model.CovPartial); c.Cmd != "dnf install -y dmidecode" {
		t.Fatalf("inventory cmd %q", c.Cmd)
	}
}

func TestNotRoot(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	b := server(t, testkit.Skipped("cpu.ras_summary", "not-root"), testkit.Skipped("cpu.ras_errors", "not-root"),
		testkit.Skipped("cpu.dmidecode", "not-root"))
	res := run(t, b, env)
	c := covState(t, res, "cpu.mce", model.CovSkipped)
	if !strings.Contains(c.Fix.EN, "sudo") {
		t.Fatalf("fix %q", c.Fix.EN)
	}
	covState(t, res, "cpu.inventory", model.CovPartial)
}

func TestContainer(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Virtual, env.Container = "lxc", true
	var secs []*collect.Section
	secs = append(secs, ident("100"), testkit.S("cpu.cpuinfo", testkit.Read(t, "cpuinfo_summary_wsl.txt")))
	for _, n := range []string{"cpu.dmidecode", "cpu.throttle", "cpu.services", "cpu.ras_status", "cpu.ras_summary", "cpu.ras_errors", "cpu.mcelog_log", "cpu.mcelog_client"} {
		secs = append(secs, testkit.Skipped(n, "container"))
	}
	res := run(t, testkit.Bundle(collect.OSLinux, secs...), env)
	covState(t, res, "cpu.mce", model.CovSkipped)
	covState(t, res, "cpu.throttle", model.CovSkipped)
	covState(t, res, "cpu.inventory", model.CovRan)
	if len(res.Findings) != 0 {
		t.Fatalf("container findings: %v", testkit.IDs(res))
	}
}

func TestNoSMBIOS(t *testing.T) {
	b := server(t, testkit.S("cpu.dmidecode", "# dmidecode 3.6\nScanning /dev/mem for entry point.\n# No SMBIOS nor DMI entry point found, sorry.\n"))
	res := run(t, b, testkit.Env(collect.OSLinux))
	c := covState(t, res, "cpu.inventory", model.CovPartial)
	if !strings.Contains(c.Reason.EN, "SMBIOS") {
		t.Fatalf("reason %q", c.Reason.EN)
	}
}

func TestWindows(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows, testkit.S("cpu.win_processor", testkit.Read(t, "win_processor_laptop.json")))
	res := run(t, b, testkit.Env(collect.OSWindows))
	must(t, res, "cpu.sockets_ok", model.OK)
	covState(t, res, "cpu.inventory", model.CovRan)
	covState(t, res, "cpu.throttle", model.CovSkipped)
	covState(t, res, "cpu.mce", model.CovSkipped)

	b = testkit.Bundle(collect.OSWindows, testkit.S("cpu.win_processor", testkit.Read(t, "win_processor_2s_disabled.json")))
	res = run(t, b, testkit.Env(collect.OSWindows))
	f := must(t, res, "cpu.socket_disabled", model.Crit)
	if f.Target != "CPU2" {
		t.Fatalf("target %q", f.Target)
	}
	must(t, res, "cpu.cores_disabled", model.Info)
	if testkit.Find(res, "cpu.sockets_ok") != nil {
		t.Fatal("no OK with a disabled CPU")
	}
	// Single object instead of an array, and garbage.
	b = testkit.Bundle(collect.OSWindows, testkit.S("cpu.win_processor", `{"DeviceID":"CPU0","Name":"Xeon","CpuStatus":1,"Status":"OK","NumberOfCores":4}`))
	run(t, b, testkit.Env(collect.OSWindows))
	b = testkit.Bundle(collect.OSWindows, testkit.RC("cpu.win_processor", 1, "[{", "Get-CimInstance : Access denied"))
	res = run(t, b, testkit.Env(collect.OSWindows))
	covState(t, res, "cpu.inventory", model.CovFailed)
}

func TestEmptyAndForeignBundles(t *testing.T) {
	res := run(t, testkit.Bundle(collect.OSLinux), testkit.Env(collect.OSLinux))
	if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 {
		t.Fatalf("empty bundle produced output: %+v", res)
	}
	res = run(t, testkit.Bundle(collect.OSBMC, testkit.S("redfish.systems", "{}")), testkit.Env(collect.OSBMC))
	if len(res.Coverage) != 0 {
		t.Fatal("bmc bundle produced coverage")
	}
}

// TestGarbage feeds truncated and random input to every section.
func TestGarbage(t *testing.T) {
	names := []string{"cpu.lscpu_json", "cpu.lscpu", "cpu.cpuinfo", "cpu.sysfs", "cpu.dmidecode", "cpu.throttle", "cpu.services",
		"cpu.ras_status", "cpu.ras_summary", "cpu.ras_errors", "cpu.mcelog_log", "cpu.mcelog_client"}
	fixtures := []string{"dmidecode_processor_dell_r740.txt", "ras_errors_cpu_uncorrected.txt", "mcelog_log_corrected_thermal.txt",
		"throttle_sysfs_hot.txt", "lscpu_json_wsl.json", "ras_errors_intel_memory.txt", "mcelog_client_issue16.txt", "win_processor_2s_disabled.json"}
	rng := rand.New(rand.NewSource(1))
	for _, fx := range fixtures {
		data := testkit.Read(t, fx)
		for i := 0; i < 30; i++ {
			cut := data[:rng.Intn(len(data)+1)]
			var secs []*collect.Section
			for _, n := range names {
				secs = append(secs, testkit.S(n, cut))
			}
			run(t, testkit.Bundle(collect.OSLinux, secs...), testkit.Env(collect.OSLinux))
			run(t, testkit.Bundle(collect.OSWindows, testkit.S("cpu.win_processor", cut)), testkit.Env(collect.OSWindows))
		}
	}
	junk := make([]byte, 4096)
	for i := 0; i < 50; i++ {
		rng.Read(junk)
		var secs []*collect.Section
		for _, n := range names {
			secs = append(secs, testkit.S(n, string(junk[:rng.Intn(len(junk))])))
		}
		run(t, testkit.Bundle(collect.OSLinux, secs...), testkit.Env(collect.OSLinux))
	}
	// Hostile numbers.
	run(t, testkit.Bundle(collect.OSLinux, testkit.S("cpu.sysfs", "/sys/devices/system/cpu/offline=0-99999999999\n"),
		testkit.S("cpu.throttle", "/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count=18446744073709551615\n"),
		testkit.S("meta.ident", "uptime=1e400\n")), testkit.Env(collect.OSLinux))
}

func TestCPUList(t *testing.T) {
	for in, want := range map[string]int{"": 0, "0": 1, "0-3": 4, "0-3,8,10-11": 7, "x": -1, "3-1": -1, "0-": -1} {
		if got := cpuList(in); got != want {
			t.Errorf("cpuList(%q) = %d, want %d", in, got, want)
		}
	}
}
