package system

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// The identity table is shown as-is in the Vietnamese report too, so the
// uptime cell must not be English words ("1 day 5 hours").
func TestUptimeCellLanguageNeutral(t *testing.T) {
	b := linuxBase()
	res := Check(b, testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	var cell string
	for _, tb := range res.Tables {
		if tb.ID == "system.identity" {
			cell = tb.Rows[0].Cells[len(tb.Rows[0].Cells)-1]
		}
	}
	if cell != "1d 0h" {
		t.Errorf("uptime cell %q", cell)
	}
	for in, want := range map[float64]string{30: "<1m", 125: "2m", 3*3600 + 720: "3h 12m", 41*86400 + 6*3600 + 59: "41d 6h"} {
		if got := shortDuration(in); got != want {
			t.Errorf("%v = %q, want %q", in, got, want)
		}
	}
}

func TestLoadOKWording(t *testing.T) {
	b := linuxBase(testkit.S("system.stat", "cpu  1053 0 1017 19120 320 0 98 0 0 0\nbtime 1790932804\ncpu  1054 0 1017 19319 320 0 98 0 0 0"))
	res := Check(b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "system.load_ok")
	if f == nil || !strings.HasSuffix(f.Title.EN, "iowait 0.0%)") || !strings.HasSuffix(f.Title.VI, "iowait 0.0%)") {
		t.Errorf("%+v", f)
	}
}

// A container limited with --cpuset-cpus sees the host's load average but
// nproc counts only its own CPUs: the host's CPU count from /proc/cpuinfo
// must be used, or a normal host load looks like a 20x overload.
func TestLoadUsesOnlineCPUsNotAffinity(t *testing.T) {
	b := linuxBase(testkit.S("system.cpuinfo", testkit.Read(t, "cpuinfo_2x_e5-2670.txt")))
	b.Get("system.nproc").Out = "2"
	b.Get("system.loadavg").Out = "20.10 19.80 19.50 21/900 9999" // 32 CPUs: 0.6 per CPU
	env := testkit.Env(collect.OSLinux)
	env.Container, env.Virtual = true, "docker"
	res := Check(b, env)
	testkit.Validate(t, res)
	if f := testkit.Find(res, "system.overloaded"); f != nil {
		t.Errorf("false overload: %s", f.Title.EN)
	}
	if ld := res.Facts.(*Facts).Load; ld == nil || ld.CPUs != 32 {
		t.Errorf("cpus %+v", ld)
	}
}

// Firmware placeholders are not serial numbers.
func TestPlaceholderSerials(t *testing.T) {
	for _, s := range []string{"To Be Filled By O.E.M.", "To be filled by O.E.M", "Default string", "0123456789", "Not Specified",
		"NotSpecified", "Not Present", "No Asset Tag", "System Serial Number", "Chassis Serial Number", "1234567890123456789012",
		"0000000000000000", "Unknow", "  ", "\x00\x00"} {
		if got := clean(s); got != "" {
			t.Errorf("clean(%q) = %q", s, got)
		}
	}
	for _, s := range []string{"7X06CTO1WW", "CZJ5130BKD", "S4BR1234", "VMware-42 1a 2b"} {
		if clean(s) != s {
			t.Errorf("real value %q dropped", s)
		}
	}
	// Supermicro boards with every serial left at the default
	dmi := "Handle 0x0001, DMI type 1, 27 bytes\nSystem Information\n\tManufacturer: Supermicro\n\tProduct Name: Super Server\n\tSerial Number: 0123456789\n" +
		"Handle 0x0002, DMI type 2, 15 bytes\nBase Board Information\n\tManufacturer: Supermicro\n\tProduct Name: X11DPi-N\n\tSerial Number: To be filled by O.E.M\n" +
		"Handle 0x0003, DMI type 3, 22 bytes\nChassis Information\n\tManufacturer: Supermicro\n\tType: Main Server Chassis\n\tSerial Number: Default string\n\tAsset Tag: To be filled by O.E.M\n"
	id := linuxIdentity(testkit.Bundle(collect.OSLinux, testkit.S("system.dmidecode", dmi)))
	if id.Serial != "" || id.BoardSerial != "" || id.AssetTag != "" || id.BoardModel != "X11DPi-N" {
		t.Errorf("%+v", id)
	}
	res := Check(testkit.Bundle(collect.OSLinux, testkit.S("system.dmidecode", dmi)), testkit.Env(collect.OSLinux))
	testkit.Validate(t, res)
	if c := testkit.Cov(res, "system.identity"); c == nil || c.State != model.CovRan {
		t.Errorf("%+v", c)
	}
}
