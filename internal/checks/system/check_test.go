package system

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func loadBundle(t *testing.T, name string) *collect.Bundle {
	t.Helper()
	b, err := collect.Read(strings.NewReader(testkit.Read(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func linuxBase(extra ...*collect.Section) *collect.Bundle {
	secs := []*collect.Section{
		testkit.S("meta.ident", "hostname=srv01\nuid=0\nkernel=5.14.0-427.13.1.el9_4.x86_64\narch=x86_64\nnow=2026-10-01T09:00:20Z\nuptime=86400.5"),
		testkit.S("meta.osrelease", "NAME=\"AlmaLinux\"\nVERSION=\"9.4 (Seafoam Ocelot)\"\nID=\"almalinux\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"AlmaLinux 9.4 (Seafoam Ocelot)\""),
		testkit.S("system.uptime", "86400.50 1300000.00"),
		testkit.S("system.loadavg", "0.52 0.48 0.40 1/512 12345"),
		testkit.S("system.nproc", "16"),
		testkit.S("system.tainted", "0"),
	}
	return testkit.Bundle(collect.OSLinux, append(secs, extra...)...)
}

func TestDMIDecodeVendors(t *testing.T) {
	cases := []struct {
		file                               string
		vendor, model, serial, bios, board string
	}{
		{"dmidecode_dell_r740.txt", "Dell Inc.", "PowerEdge R740", "", "2.22.1 (2024-08-09)", "Dell Inc. 01YM03"},
		{"dmidecode_supermicro_sys6029p.txt", "Supermicro", "SYS-6029P-TR", "", "3.5 (2021-06-29)", "Supermicro X11DPi-N"},
		{"dmidecode_lenovo_sn550.txt", "Lenovo", "ThinkSystem SN550 (7X16CTO1WW)", "", "IVE182H-4.10 (2023-04-19)", "Lenovo 7X16CTO1WW"},
		{"dmidecode_hpe_bl460c_gen10.txt", "HPE", "ProLiant BL460c Gen10", "", "I41 (2019-04-18)", "HPE ProLiant BL460c Gen10"},
		{"dmidecode_hp_dl380p_gen8.txt", "HP", "ProLiant DL380p Gen8", "2M23360006", "P70 (2013-03-01)", ""},
		{"dmidecode_vmware.txt", "VMware, Inc.", "VMware Virtual Platform", "VMware-42 10 e9 13 1e 11 e2 21-13 c5 c8 1f 11 42 7c cb", "6.00 (2014-04-14)", ""},
		{"dmidecode_rhev_kvm.txt", "Red Hat", "RHEV Hypervisor", "34353737-3035-4E43-3734-353130425732", "1.9.1-5.el7_3.2 (2014-04-01)", ""},
		{"dmidecode_aws_xen.txt", "Xen", "HVM domU", "ec2f58af-2dad-c57e-88c0-a81cb6084290", "4.2.amazon (2016-12-09)", ""},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			b := linuxBase(testkit.S("system.dmidecode", testkit.Read(t, c.file)))
			id := linuxIdentity(b)
			if id.Vendor != c.vendor || id.Model != c.model || id.Serial != c.serial || id.biosString() != c.bios || id.boardString() != c.board {
				t.Errorf("got vendor=%q model=%q serial=%q bios=%q board=%q", id.Vendor, id.Model, id.Serial, id.biosString(), id.boardString())
			}
			if id.Source != "dmidecode" {
				t.Errorf("source %q", id.Source)
			}
			res := Check(b, testkit.Env(collect.OSLinux))
			testkit.Validate(t, res)
			if c := testkit.Cov(res, "system.identity"); c == nil || c.State != model.CovRan {
				t.Errorf("identity coverage %+v", c)
			}
		})
	}
}

// The linuxhw dumps have their serials anonymised as "--"; a real service
// tag must come through, from the system record first.
func TestDellServiceTag(t *testing.T) {
	d := testkit.Read(t, "dmidecode_dell_r740.txt")
	d = strings.Replace(d, "System Information\n\tManufacturer: Dell Inc.\n\tProduct Name: PowerEdge R740\n\tVersion: Not Specified\n\tSerial Number: --",
		"System Information\n\tManufacturer: Dell Inc.\n\tProduct Name: PowerEdge R740\n\tVersion: Not Specified\n\tSerial Number: 7XK2QX2", 1)
	h := HostInfo(linuxBase(testkit.S("system.dmidecode", d)), testkit.Env(collect.OSLinux))
	if h.Serial != "7XK2QX2" || h.Vendor != "Dell Inc." || h.Model != "PowerEdge R740" {
		t.Errorf("host %+v", h)
	}
	// Supermicro often leaves the system serial as a placeholder and fills the chassis.
	s := testkit.Read(t, "dmidecode_supermicro_sys6029p.txt")
	s = strings.Replace(s, "Serial Number: --", "Serial Number: 0123456789", 1)
	s = strings.Replace(s, "Chassis Information\n\tManufacturer: Supermicro\n\tType: Other\n\tLock: Not Present\n\tVersion: 123456789\n\tSerial Number: --",
		"Chassis Information\n\tManufacturer: Supermicro\n\tType: Other\n\tLock: Not Present\n\tVersion: 123456789\n\tSerial Number: C2190KL01A12345", 1)
	h = HostInfo(linuxBase(testkit.S("system.dmidecode", s)), testkit.Env(collect.OSLinux))
	if h.Serial != "C2190KL01A12345" {
		t.Errorf("supermicro serial %q", h.Serial)
	}
	if h.Serial == "0123456789" {
		t.Errorf("placeholder serial leaked")
	}
}

func TestNoSMBIOS(t *testing.T) {
	b := linuxBase(testkit.S("system.dmidecode", testkit.Read(t, "dmidecode_nodmi.txt")), testkit.Missing("system.dmi", "/sys/class/dmi/id"))
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	c := testkit.Cov(res, "system.identity")
	if c == nil || c.State != model.CovFailed {
		t.Errorf("bare metal without SMBIOS: %+v", c)
	}
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res = Check(b, env)
	if c := testkit.Cov(res, "system.identity"); c == nil || c.State != model.CovSkipped {
		t.Errorf("vm without SMBIOS: %+v", c)
	}
}

func TestNotRootUsesSysfs(t *testing.T) {
	dmi := strings.Join([]string{
		"/sys/class/dmi/id/sys_vendor=Dell Inc.",
		"/sys/class/dmi/id/product_name=PowerEdge R650",
		"/sys/class/dmi/id/bios_vendor=Dell Inc.",
		"/sys/class/dmi/id/bios_version=1.13.1",
		"/sys/class/dmi/id/bios_date=03/07/2024",
		"/sys/class/dmi/id/board_name=0Y2K8N",
		"/sys/class/dmi/id/board_vendor=Dell Inc.",
		"/sys/class/dmi/id/chassis_type=23",
		"/sys/class/dmi/id/modalias=dmi:bvnDellInc.:bvr1.13.1:",
	}, "\n")
	b := linuxBase(testkit.Skipped("system.dmidecode", "not-root"), testkit.S("system.dmi", dmi))
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res := Check(b, env)
	testkit.Validate(t, res)
	c := testkit.Cov(res, "system.identity")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Fix.EN, "root") {
		t.Fatalf("coverage %+v", c)
	}
	h := HostInfo(b, env)
	if h.Model != "PowerEdge R650" || h.BIOS != "1.13.1 (2024-03-07)" || h.Serial != "" {
		t.Errorf("host %+v", h)
	}
	f := res.Facts.(*Facts)
	if f.Identity.ChassisType != "Rack Mount Chassis" {
		t.Errorf("chassis %q", f.Identity.ChassisType)
	}
}

func TestDmidecodeMissing(t *testing.T) {
	b := linuxBase(testkit.Missing("system.dmidecode", "dmidecode"), testkit.Missing("system.dmi", "/sys/class/dmi/id"))
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	c := testkit.Cov(res, "system.identity")
	if c == nil || c.State != model.CovSkipped || c.Cmd != "dnf install -y dmidecode" || strings.Contains(c.Fix.EN, "dnf") {
		t.Errorf("coverage %+v", c)
	}
}

func TestHostnamectlFallback(t *testing.T) {
	b := linuxBase(testkit.Skipped("system.dmidecode", "not-root"), testkit.S("system.hostnamectl", testkit.Read(t, "hostnamectl_dell_fedora40.txt")))
	h := HostInfo(b, testkit.Env(collect.OSLinux))
	if h.Vendor != "Dell Inc." || h.Model != "Latitude 9440 2-in-1" || h.BIOS != "1.10.0 (2024-03-06)" {
		t.Errorf("host %+v", h)
	}
}

func TestCPUInfo(t *testing.T) {
	c := parseCPUInfo(testkit.Read(t, "cpuinfo_2x_e5-2670.txt"))
	if got := cpuSummary(c.model, c.sockets, c.cores, c.threads); got != "2 × Intel Xeon E5-2670 0 (16 cores, 32 threads)" {
		t.Errorf("2-socket: %q", got)
	}
	c = parseCPUInfo(testkit.Read(t, "cpuinfo_epyc4464p.txt"))
	if got := cpuSummary(c.model, c.sockets, c.cores, c.threads); got != "AMD EPYC 4464P 12-Core (12 cores, 24 threads)" {
		t.Errorf("epyc: %q", got)
	}
	if got := cleanCPUName("Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz"); got != "Intel Xeon Silver 4214" {
		t.Errorf("clean: %q", got)
	}
}

func TestWSLRealBundle(t *testing.T) {
	b := loadBundle(t, "wsl.json")
	env := collect.EnvOf(b)
	h := HostInfo(b, env)
	if h.Hostname != "dw-testhost" || h.OS != "Ubuntu 26.04.1 LTS" || h.Virtual != "wsl" {
		t.Errorf("host %+v", h)
	}
	if h.CPU != "Intel Core i5-10300H (1 core, 2 threads)" || h.MemBytes != 1952476*1024 {
		t.Errorf("cpu %q mem %d", h.CPU, h.MemBytes)
	}
	if h.BootTime.IsZero() || h.Uptime <= 0 {
		t.Errorf("boot %v uptime %v", h.BootTime, h.Uptime)
	}
	res := Check(b, env)
	testkit.Validate(t, res)
	if c := testkit.Cov(res, "system.identity"); c == nil || c.State != model.CovSkipped {
		t.Errorf("identity in WSL: %+v", c)
	}
	if c := testkit.Cov(res, "system.load"); c == nil || c.State != model.CovRan {
		t.Errorf("load: %+v", c)
	}
	if testkit.Find(res, "system.load_ok") == nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	f := res.Facts.(*Facts)
	if f.Load == nil || f.Load.IOWaitPct == nil || f.Load.PSI["io some"].Avg300 <= 0 {
		t.Errorf("load facts %+v", f.Load)
	}
}

func TestOverloaded(t *testing.T) {
	b := linuxBase()
	b.Get("system.loadavg").Out = "40.12 38.50 35.10 41/900 9999"
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	f := testkit.Find(res, "system.overloaded")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Title.EN, "16 CPUs") {
		t.Fatalf("findings %v", testkit.IDs(res))
	}
	if testkit.Find(res, "system.load_ok") != nil {
		t.Error("load_ok together with overloaded")
	}
	// A short burst (1-minute load only) is not an overload.
	b.Get("system.loadavg").Out = "60.0 10.0 5.0 2/900 1"
	res = Check(b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "system.overloaded") != nil {
		t.Errorf("burst flagged: %v", testkit.IDs(res))
	}
}

func TestPressure(t *testing.T) {
	psi := "cpu some avg10=70.00 avg60=65.00 avg300=62.50 total=1\ncpu full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n" +
		"io some avg10=40.00 avg60=38.00 avg300=35.00 total=1\nio full avg10=30.00 avg60=28.00 avg300=25.00 total=1\n" +
		"memory some avg10=30.00 avg60=25.00 avg300=22.00 total=1\nmemory full avg10=8.00 avg60=7.00 avg300=6.00 total=1"
	b := linuxBase(testkit.S("system.pressure", psi))
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	for _, id := range []string{"system.overloaded", "system.io_bottleneck", "system.memory_pressure"} {
		if f := testkit.Find(res, id); f == nil || f.Severity != model.Warn {
			t.Errorf("%s missing: %v", id, testkit.IDs(res))
		}
	}
	if got := parsePSI("garbage\ncpu some avg10=x avg60=1 avg300=2\nio some avg10=101 avg60=1 avg300=1"); got != nil {
		t.Errorf("garbage psi parsed: %v", got)
	}
}

func stat(user, iowait, steal, idle uint64) string {
	return fmt.Sprintf("cpu %d 0 100 %d %d 0 10 %d 0 0", user, idle, iowait, steal)
}

func TestIOWaitAndSteal(t *testing.T) {
	// 1 s, 1600 ticks over 16 CPUs: +480 iowait (30 %), +240 steal (15 %).
	s := stat(1000, 500, 100, 50000) + "\nbtime 1790000000\nprocs_running 3\nprocs_blocked 12\n" + stat(1600, 980, 340, 50300)
	io, st, btime, blocked := parseStat(s)
	if io == nil || st == nil || btime != 1790000000 || blocked != 12 {
		t.Fatalf("parse: %v %v %d %d", io, st, btime, blocked)
	}
	if *io < 29 || *io > 31 || *st < 14 || *st > 16 {
		t.Errorf("iowait %.1f steal %.1f", *io, *st)
	}
	b := linuxBase(testkit.S("system.stat", s))
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	if testkit.Find(res, "system.io_bottleneck") == nil {
		t.Errorf("no io finding without PSI: %v", testkit.IDs(res))
	}
	if testkit.Find(res, "system.cpu_steal") != nil {
		t.Error("steal reported on bare metal")
	}
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res = Check(b, env)
	if f := testkit.Find(res, "system.cpu_steal"); f == nil || f.Severity != model.Warn {
		t.Errorf("no steal finding on VM: %v", testkit.IDs(res))
	}
	// PSI says I/O is fine: a 1-second iowait spike alone is not reported.
	b = linuxBase(testkit.S("system.stat", s), testkit.S("system.pressure", "io some avg10=1.00 avg60=2.00 avg300=1.00 total=5\nio full avg10=0.50 avg60=1.00 avg300=0.50 total=1"))
	res = Check(b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "system.io_bottleneck") != nil {
		t.Errorf("iowait spike contradicted by PSI flagged: %v", testkit.IDs(res))
	}
	// counters going backwards / single sample
	if io, st, _, _ := parseStat(stat(10, 10, 10, 10)); io != nil || st != nil {
		t.Error("single sample gave a value")
	}
	if io, _, _, _ := parseStat(stat(100, 100, 0, 100) + "\n" + stat(50, 50, 0, 50)); io != nil {
		t.Error("backwards counters gave a value")
	}
}

func TestTaint(t *testing.T) {
	cases := []struct {
		v    string
		ids  []string
		comp string
	}{
		{"16", []string{"system.taint_mce"}, model.CompCPU},
		{"32", []string{"system.taint_bad_page"}, model.CompMemory},
		{"128", []string{"system.taint_oops"}, model.CompSystem},
		{"16384", []string{"system.taint_soft_lockup"}, model.CompSystem},
		{"512", []string{"system.taint_warning"}, model.CompSystem},
		{"2048", []string{"system.taint_firmware"}, model.CompSystem},
		{"4097", nil, ""},  // proprietary + out-of-tree module: software only
		{"12288", nil, ""}, // O + E
	}
	for _, c := range cases {
		b := linuxBase()
		b.Get("system.tainted").Out = c.v
		res := Check(b, testkit.Env(collect.OSLinux))
		testkit.Validate(t, res)
		var got []string
		for _, f := range res.Findings {
			if strings.HasPrefix(f.ID, "system.taint_") {
				got = append(got, f.ID)
				if f.Component != c.comp {
					t.Errorf("%s: component %s", f.ID, f.Component)
				}
			}
		}
		if strings.Join(got, ",") != strings.Join(c.ids, ",") {
			t.Errorf("taint %s: got %v want %v", c.v, got, c.ids)
		}
	}
}

func TestClock(t *testing.T) {
	for _, c := range []struct {
		sec, file string
		want      bool
	}{
		{"system.timedatectl", "timedatectl_unsynced_openshift.txt", true},
		{"system.timedatectl", "timedatectl_centos7_unsynced.txt", true},
		{"system.timedatectl", "timedatectl_synced_wsl.txt", false},
		{"system.chrony", "chronyc_tracking_unsynced.txt", true},
	} {
		b := linuxBase(testkit.S(c.sec, testkit.Read(t, c.file)))
		res := Check(b, testkit.Env(collect.OSLinux))
		testkit.Validate(t, res)
		f := testkit.Find(res, "system.clock_unsynced")
		if (f != nil) != c.want {
			t.Errorf("%s: got %v", c.file, testkit.IDs(res))
		}
		if f != nil && f.Severity != model.Info {
			t.Errorf("clock severity %v", f.Severity)
		}
	}
	// timedatectl failing (no systemd as PID 1) says nothing
	b := linuxBase(testkit.RC("system.timedatectl", 1, "", "System has not been booted with systemd as init system (PID 1). Can't operate."))
	if testkit.Find(Check(b, testkit.Env(collect.OSLinux)), "system.clock_unsynced") != nil {
		t.Error("failed timedatectl produced a finding")
	}
}

func TestReboot(t *testing.T) {
	b := linuxBase(testkit.S("system.reboot", "reboot_required=/var/run/reboot-required\npkg=linux-image-6.8.0-45-generic\npkg=linux-base"))
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	if f := testkit.Find(res, "system.reboot_required"); f == nil || f.Severity != model.Info || len(f.Evidence) != 3 {
		t.Errorf("debian: %v", testkit.IDs(res))
	}
	b = linuxBase(testkit.RC("system.needs_restarting", 1, "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943", ""))
	if testkit.Find(Check(b, testkit.Env(collect.OSLinux)), "system.reboot_required") == nil {
		t.Error("rhel: no finding")
	}
	b = linuxBase(testkit.S("system.needs_restarting", "No core libraries or services have been updated since boot-up.\nReboot should not be necessary."))
	if testkit.Find(Check(b, testkit.Env(collect.OSLinux)), "system.reboot_required") != nil {
		t.Error("rhel: false positive")
	}
}

func TestBIOSAge(t *testing.T) {
	gen8 := linuxBase(testkit.S("system.dmidecode", testkit.Read(t, "dmidecode_hp_dl380p_gen8.txt")))
	res := Check(gen8, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "system.bios_old")
	if f == nil || f.Severity != model.Info || !strings.Contains(f.Title.VI, "năm") {
		t.Fatalf("gen8 bios: %v", testkit.IDs(res))
	}
	dell := linuxBase(testkit.S("system.dmidecode", testkit.Read(t, "dmidecode_dell_r740.txt")))
	if testkit.Find(Check(dell, testkit.Env(collect.OSLinux)), "system.bios_old") != nil {
		t.Error("2024 BIOS flagged")
	}
	vm := linuxBase(testkit.S("system.dmidecode", testkit.Read(t, "dmidecode_rhev_kvm.txt")))
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	if testkit.Find(Check(vm, env), "system.bios_old") != nil {
		t.Error("virtual BIOS flagged")
	}
}

func TestWindowsReal(t *testing.T) {
	b := loadBundle(t, "win10.json")
	env := collect.EnvOf(b)
	h := HostInfo(b, env)
	if h.Vendor != "Acer" || h.Model != "AN515-55" || h.CPU != "Intel Core i5-10300H (4 cores, 8 threads)" || h.MemBytes != 17002713088 {
		t.Errorf("host %+v", h)
	}
	if h.Serial != "" {
		t.Errorf("placeholder serial leaked: %q", h.Serial)
	}
	if h.BIOS != "V1.10 (2020-11-19)" || h.BootTime.IsZero() || h.Uptime <= 0 {
		t.Errorf("bios %q boot %v uptime %v", h.BIOS, h.BootTime, h.Uptime)
	}
	res := Check(b, env)
	testkit.Validate(t, res)
	if c := testkit.Cov(res, "system.identity"); c == nil || c.State != model.CovRan {
		t.Errorf("identity %+v", c)
	}
	if testkit.Find(res, "system.load_ok") == nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	// PendingFileRenameOperations alone (true in this capture) is not a pending reboot.
	if testkit.Find(res, "system.reboot_required") != nil {
		t.Error("PendingFileRenameOperations alone flagged")
	}
}

func TestWindowsSynthetic(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("meta.ident", `[{"hostname":"SRV-SQL01","admin":true,"caption":"Microsoft Windows Server 2022 Standard","version":"10.0.20348","build":"20348","arch":"AMD64","lastBoot":"2026-09-01T02:00:00.0000000Z","now":"2026-10-01T09:00:20.0000000Z"}]`),
		testkit.S("system.win_computer", `[{"Manufacturer":"HPE","Model":"ProLiant DL380 Gen10","TotalPhysicalMemory":274877906944,"NumberOfProcessors":2}]`),
		testkit.S("system.win_bios", `[{"Manufacturer":"HPE","SerialNumber":"CZJ1234ABC","SMBIOSBIOSVersion":"U30","ReleaseDate":"2023-02-20T00:00:00.0000000Z"}]`),
		testkit.S("system.win_enclosure", `{"Manufacturer":"HPE","SerialNumber":"CZJ1234ABC","SMBIOSAssetTag":"","ChassisTypes":[23]}`),
		testkit.S("system.win_cpu", `[{"Name":"Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz","NumberOfCores":24,"NumberOfLogicalProcessors":48},{"Name":"Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz","NumberOfCores":24,"NumberOfLogicalProcessors":48}]`),
		testkit.S("system.win_perf", `[{"ProcessorQueueLength":250,"PercentProcessorTime":97,"DiskPercentIdleTime":3,"DiskAvgQueueLength":12,"SystemUpTime":2600000},{"ProcessorQueueLength":230,"PercentProcessorTime":99,"DiskPercentIdleTime":2,"DiskAvgQueueLength":15,"SystemUpTime":2600002},{"ProcessorQueueLength":260,"PercentProcessorTime":98,"DiskPercentIdleTime":5,"DiskAvgQueueLength":9,"SystemUpTime":2600004}]`),
		testkit.S("system.win_reboot", `[{"cbsRebootPending":true,"wuRebootRequired":false,"pendingFileRename":true}]`),
	)
	env := collect.EnvOf(b)
	h := HostInfo(b, env)
	if h.Serial != "CZJ1234ABC" || h.CPU != "2 × Intel Xeon Gold 6248R (48 cores, 96 threads)" || h.OS != "Microsoft Windows Server 2022 Standard" {
		t.Errorf("host %+v", h)
	}
	if h.Uptime < 30*24*3600 {
		t.Errorf("uptime %v", h.Uptime)
	}
	res := Check(b, env)
	testkit.Validate(t, res)
	for _, id := range []string{"system.overloaded", "system.io_bottleneck", "system.reboot_required"} {
		if testkit.Find(res, id) == nil {
			t.Errorf("%s missing: %v", id, testkit.IDs(res))
		}
	}
}

func TestBMCHost(t *testing.T) {
	b := testkit.Bundle(collect.OSBMC)
	b.Host = "10.0.0.50"
	if h := HostInfo(b, testkit.Env(collect.OSBMC)); h.Hostname != "10.0.0.50" {
		t.Errorf("bmc host %+v", h)
	}
	b.Add(testkit.S("meta.bmc", `{"HostName":"esx01","Manufacturer":"Dell Inc.","Model":"PowerEdge R640","SerialNumber":"5KL9QX2","BiosVersion":"2.19.1","MemorySummary":{"TotalSystemMemoryGiB":384}}`))
	h := HostInfo(b, testkit.Env(collect.OSBMC))
	if h.Hostname != "esx01" || h.Serial != "5KL9QX2" || h.MemBytes != 384<<30 {
		t.Errorf("bmc host %+v", h)
	}
	if res := Check(b, testkit.Env(collect.OSBMC)); len(res.Coverage) != 0 || len(res.Findings) != 0 {
		t.Errorf("bmc check produced %v", testkit.IDs(res))
	}
}

func TestEmptyAndGarbage(t *testing.T) {
	if res := Check(testkit.Bundle(collect.OSLinux, testkit.S("meta.ident", "uid=0")), testkit.Env(collect.OSLinux)); len(res.Coverage) != 0 {
		t.Errorf("no system sections but coverage %v", res.Coverage)
	}
	_ = HostInfo(testkit.Bundle(collect.OSLinux), testkit.Env(collect.OSLinux))
	_ = HostInfo(testkit.Bundle(collect.OSWindows), testkit.Env(collect.OSWindows))

	files := []string{"dmidecode_dell_r740.txt", "dmidecode_hp_dl380p_gen8.txt", "cpuinfo_2x_e5-2670.txt", "timedatectl_unsynced_openshift.txt", "hostnamectl_dell_fedora40.txt"}
	names := []string{"system.dmidecode", "system.dmi", "system.cpuinfo", "system.loadavg", "system.stat", "system.pressure", "system.tainted",
		"system.timedatectl", "system.hostnamectl", "system.meminfo", "system.uptime", "system.nproc", "system.reboot", "system.needs_restarting"}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 400; i++ {
		src := testkit.Read(t, files[rng.Intn(len(files))])
		cut := src[:rng.Intn(len(src)+1)]
		garbage := make([]byte, rng.Intn(200))
		for j := range garbage {
			garbage[j] = byte(rng.Intn(256))
		}
		var secs []*collect.Section
		for _, n := range names {
			switch rng.Intn(3) {
			case 0:
				secs = append(secs, testkit.S(n, cut))
			case 1:
				secs = append(secs, testkit.S(n, string(garbage)))
			}
		}
		b := testkit.Bundle(collect.OSLinux, secs...)
		res := Check(b, testkit.Env(collect.OSLinux))
		testkit.Validate(t, res)
		_ = HostInfo(b, testkit.Env(collect.OSLinux))
		wb := testkit.Bundle(collect.OSWindows,
			testkit.S("system.win_computer", cut), testkit.S("system.win_perf", string(garbage)),
			testkit.S("system.win_bios", `[{"ReleaseDate":"`+string(garbage)+`"}]`), testkit.S("meta.ident", cut))
		testkit.Validate(t, Check(wb, testkit.Env(collect.OSWindows)))
		_ = HostInfo(wb, testkit.Env(collect.OSWindows))
	}
}
