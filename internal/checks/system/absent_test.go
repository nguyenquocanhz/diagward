package system

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// without returns b minus the named sections (an older or partial bundle).
func without(b *collect.Bundle, names ...string) *collect.Bundle {
	drop := map[string]bool{}
	for _, n := range names {
		drop[n] = true
	}
	out := testkit.Bundle(b.OS)
	for _, s := range b.Sections {
		if !drop[s.Name] {
			out.Add(s)
		}
	}
	return out
}

// A section that is absent from the bundle (older collector, partial run)
// did not fail: the coverage must say "skipped, not collected", never
// "failed — could not be read". "failed" is kept for a section that ran
// and produced unusable output.
func TestLoadCoverageAbsentVsFailed(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	cases := []struct {
		name   string
		b      *collect.Bundle
		state  string
		reason string // substring of Reason.EN
	}{
		{"absent", without(linuxBase(), "system.loadavg"), model.CovSkipped, "not collected"},
		{"file missing", linuxBase(testkit.Missing("system.loadavg", "/proc/loadavg")), model.CovSkipped, "/proc/loadavg"},
		{"skipped", linuxBase(testkit.Skipped("system.loadavg", "disabled")), model.CovSkipped, "disabled"},
		{"garbage", linuxBase(testkit.S("system.loadavg", "\x00\x01 not a load line")), model.CovFailed, "could not be read"},
		{"error", linuxBase(testkit.RC("system.loadavg", 1, "", "cat: /proc/loadavg: Input/output error")), model.CovFailed, "Input/output error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Check(c.b, env)
			testkit.Validate(t, res)
			cv := testkit.Cov(res, "system.load")
			if cv == nil || cv.State != c.state || !strings.Contains(cv.Reason.EN, c.reason) || cv.Reason.VI == "" {
				t.Errorf("coverage %+v", cv)
			}
		})
	}
	// Windows: no performance counters in the bundle at all.
	wb := testkit.Bundle(collect.OSWindows,
		testkit.S("system.win_computer", `[{"Manufacturer":"HPE","Model":"ProLiant DL380 Gen10","TotalPhysicalMemory":274877906944}]`))
	res := Check(wb, testkit.Env(collect.OSWindows))
	testkit.Validate(t, res)
	if cv := testkit.Cov(res, "system.load"); cv == nil || cv.State != model.CovSkipped || !strings.Contains(cv.Reason.EN, "not collected") {
		t.Errorf("windows load coverage %+v", cv)
	}
	wb.Add(testkit.S("system.win_perf", "garbage"))
	res = Check(wb, testkit.Env(collect.OSWindows))
	if cv := testkit.Cov(res, "system.load"); cv == nil || cv.State != model.CovFailed {
		t.Errorf("windows load coverage with garbage %+v", cv)
	}
}

// Absent /proc/stat: partial, and the reason says it was not collected.
func TestLoadCoverageStatAbsent(t *testing.T) {
	res := Check(linuxBase(), testkit.Env(collect.OSLinux))
	cv := testkit.Cov(res, "system.load")
	if cv == nil || cv.State != model.CovPartial || !strings.Contains(cv.Reason.EN, "/proc/stat") || !strings.Contains(cv.Reason.EN, "not collected") {
		t.Errorf("coverage %+v", cv)
	}
}

// Identity: no dmidecode and no sysfs DMI section in the bundle is not "No
// SMBIOS/DMI data found on this machine" — nothing looked.
func TestIdentityCoverageAbsent(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	res := Check(linuxBase(), env)
	testkit.Validate(t, res)
	cv := testkit.Cov(res, "system.identity")
	if cv == nil || cv.State != model.CovSkipped || !strings.Contains(cv.Reason.EN, "not collected") {
		t.Errorf("identity coverage %+v", cv)
	}
	// sysfs DMI present, dmidecode section absent: partial, and the reason
	// must not claim dmidecode returned nothing.
	dmi := "/sys/class/dmi/id/sys_vendor=Dell Inc.\n/sys/class/dmi/id/product_name=PowerEdge R650\n"
	res = Check(linuxBase(testkit.S("system.dmi", dmi)), env)
	cv = testkit.Cov(res, "system.identity")
	if cv == nil || cv.State != model.CovPartial || strings.Contains(cv.Reason.EN, "returned no") || !strings.Contains(cv.Reason.EN, "not collected") {
		t.Errorf("identity coverage (sysfs only) %+v", cv)
	}
	// dmidecode ran and printed nothing useful: that is a real failure.
	res = Check(linuxBase(testkit.S("system.dmidecode", testkit.Read(t, "dmidecode_nodmi.txt")), testkit.Missing("system.dmi", "/sys/class/dmi/id")), env)
	if cv := testkit.Cov(res, "system.identity"); cv == nil || cv.State != model.CovFailed {
		t.Errorf("identity coverage (no SMBIOS) %+v", cv)
	}
	// Windows: Win32_ComputerSystem absent from the bundle.
	wb := testkit.Bundle(collect.OSWindows, testkit.S("system.win_perf", `[{"PercentProcessorTime":5}]`))
	res = Check(wb, testkit.Env(collect.OSWindows))
	testkit.Validate(t, res)
	if cv := testkit.Cov(res, "system.identity"); cv == nil || cv.State != model.CovSkipped || !strings.Contains(cv.Reason.EN, "not collected") {
		t.Errorf("windows identity coverage %+v", cv)
	}
}

// An unknown CPU count must not be shown as "0 CPUs".
func TestLoadUnknownCPUCount(t *testing.T) {
	b := without(linuxBase(), "system.nproc")
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	f := testkit.Find(res, "system.load_ok")
	if f == nil || strings.Contains(f.Title.EN, "0 CPUs") || strings.Contains(f.Title.VI, "0 CPU") {
		t.Errorf("load ok %+v", f)
	}
	for _, tb := range res.Tables {
		if tb.ID == "system.load" && tb.Rows[0].Cells[1] != "" {
			t.Errorf("CPU cell %q, want empty", tb.Rows[0].Cells[1])
		}
	}
	// Windows: queue per CPU is unknown without a CPU count.
	wb := testkit.Bundle(collect.OSWindows,
		testkit.S("system.win_computer", `[{"Manufacturer":"HPE","Model":"ProLiant DL380 Gen10"}]`),
		testkit.S("system.win_perf", `[{"ProcessorQueueLength":1,"PercentProcessorTime":12}]`))
	res = Check(wb, testkit.Env(collect.OSWindows))
	f = testkit.Find(res, "system.load_ok")
	if f == nil || strings.Contains(f.Title.EN, "queue 0.0") {
		t.Errorf("windows load ok %+v", f)
	}
}

// The kernel release of RHEL/Fedora/SUSE kernels already ends with the
// architecture; the header must not show it twice.
func TestHostInfoArchNotRepeated(t *testing.T) {
	h := HostInfo(linuxBase(), testkit.Env(collect.OSLinux))
	if h.Kernel != "5.14.0-427.13.1.el9_4.x86_64" || strings.Contains(strings.TrimSpace(h.Kernel+" "+h.Arch), "x86_64 x86_64") {
		t.Errorf("kernel %q arch %q", h.Kernel, h.Arch)
	}
	b := linuxBase()
	b.Get("meta.ident").Out = "hostname=srv01\nkernel=5.15.0-91-generic\narch=x86_64\n"
	if h := HostInfo(b, testkit.Env(collect.OSLinux)); h.Kernel != "5.15.0-91-generic" || h.Arch != "x86_64" {
		t.Errorf("ubuntu kernel %q arch %q", h.Kernel, h.Arch)
	}
	b.Get("meta.ident").Out = "hostname=srv01\nkernel=5.14.0-362.8.1.el9_3.aarch64\narch=aarch64\n"
	if h := HostInfo(b, testkit.Env(collect.OSLinux)); h.Arch != "" {
		t.Errorf("aarch64 kernel %q arch %q", h.Kernel, h.Arch)
	}
}
