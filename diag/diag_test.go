package diag

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/disk"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func TestDeviceKeys(t *testing.T) {
	cases := map[string][]string{
		"/dev/sda":                {"sda"},
		"sda1":                    {"sda1", "sda"},
		"/dev/nvme0n1p2":          {"nvme0n1p2", "nvme0n1"},
		"nvme0n1":                 {"nvme0n1"},
		"PhysicalDrive1":          {"win:1"},
		`\\.\PHYSICALDRIVE3`:      {"win:3"},
		"PhysicalDisk3":           {"win:3"},
		"md0":                     {"md0"},
		"/dev/bus/0 [megaraid,3]": {"bus/0#megaraid,3"},
		"/dev/bus/0,megaraid,3":   {"bus/0#megaraid,3"},
		"/dev/sda [cciss,1]":      {"sda#cciss,1"},
		"/dev/sda [SAT]":          {"sda"},
		"nvme0":                   {"nvme0", "nvme0n1"},
		"":                        nil,
	}
	for in, want := range cases {
		if got := deviceKeys(in); !reflect.DeepEqual(got, want) {
			t.Errorf("deviceKeys(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEnrichParts(t *testing.T) {
	res := []model.Result{
		{Domain: "disk", Facts: disk.Facts{Disks: []disk.DiskFact{
			{Device: "/dev/sda", Vendor: "Seagate", Model: "ST4000NM0035", Serial: "ZC1234", SizeBytes: 4000787030016},
			{Device: "PhysicalDisk1", Model: "Samsung SSD", Serial: "S5XYZ"},
			{Device: "/dev/bus/0 [megaraid,0]", Serial: "MR0"},
			{Device: "/dev/bus/0 [megaraid,1]", Serial: "MR1"},
		}}},
		{Domain: "logs", Findings: []model.Finding{
			{ID: "logs.disk_io", Target: "sda", Part: &model.Part{Kind: "disk", Location: "/dev/sda"}},
			{ID: "logs.win_disk", Target: "PhysicalDrive1", Part: &model.Part{Kind: "disk", Location: "PhysicalDrive1"}},
			{ID: "logs.unknown", Target: "sdz", Part: &model.Part{Kind: "disk", Location: "/dev/sdz"}},
			{ID: "raid.pd", Target: "slot 0", Part: &model.Part{Kind: "disk", Location: "/dev/bus/0 [megaraid,0]"}},
			{ID: "raid.bus", Target: "bus/0", Part: &model.Part{Kind: "disk", Location: "/dev/bus/0"}},
		}},
	}
	enrichParts(res)
	f := res[1].Findings
	if p := f[0].Part; p.Serial != "ZC1234" || p.Model != "ST4000NM0035" || p.Size != "4 TB" {
		t.Errorf("sda part: %+v", p)
	}
	if p := f[1].Part; p.Serial != "S5XYZ" {
		t.Errorf("PhysicalDrive1 part: %+v", p)
	}
	if p := f[2].Part; p.Serial != "" {
		t.Errorf("unknown disk got a serial: %+v", p)
	}
	if p := f[3].Part; p.Serial != "MR0" {
		t.Errorf("megaraid,0 part: %+v", p)
	}
	if p := f[4].Part; p.Serial != "" {
		t.Errorf("a bare controller path must not pick one of its disks: %+v", p)
	}
}

// TestAnalyzeEmptyBundles makes sure every domain copes with bundles that
// have no sections at all, for every OS, and that the report is complete.
func TestAnalyzeEmptyBundles(t *testing.T) {
	for _, os := range []string{collect.OSLinux, collect.OSWindows, collect.OSBMC} {
		b := testkit.Bundle(os)
		rep := Analyze(b)
		if rep.Findings == nil || len(rep.Summary) != len(model.Components) {
			t.Fatalf("%s: incomplete report", os)
		}
		for _, c := range rep.Coverage {
			if c.State == model.CovFailed && strings.HasSuffix(c.ID, ".internal") {
				t.Errorf("%s: domain panicked: %s", os, c.Reason.EN)
			}
		}
		if _, err := json.Marshal(rep); err != nil {
			t.Fatalf("%s: %v", os, err)
		}
	}
}

// TestAnalyzeGarbage feeds every known section name garbage and truncated
// output; no domain may panic.
func TestAnalyzeGarbage(t *testing.T) {
	names := []string{}
	for _, os := range []string{collect.OSLinux, collect.OSWindows} {
		s, err := collect.Script(os, "B", collect.Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(s, "\n") {
			for _, f := range strings.Fields(l) {
				f = strings.Trim(f, `'"`)
				if i := strings.IndexByte(f, '.'); i > 2 && i < 12 && !strings.ContainsAny(f, "$/(){}[]=") {
					names = append(names, f)
				}
			}
		}
	}
	junk := []string{"", "{", "[", "null", "[{\"a\":", "\x00\xff garbage ====", strings.Repeat("x|", 5000), "[]", "{}", "-1"}
	for _, os := range []string{collect.OSLinux, collect.OSWindows, collect.OSBMC} {
		for i, j := range junk {
			var secs []*collect.Section
			for _, n := range names {
				secs = append(secs, testkit.S(n, j))
			}
			rep := Analyze(testkit.Bundle(os, secs...))
			for _, c := range rep.Coverage {
				if strings.HasSuffix(c.ID, ".internal") {
					t.Errorf("%s junk #%d: %s", os, i, c.Reason.EN)
				}
			}
		}
	}
}

func TestFoldDiskLogFindings(t *testing.T) {
	res := []model.Result{
		{Domain: "disk", Findings: []model.Finding{
			{ID: "disk.reallocated_sectors", Component: model.CompDisk, Severity: model.Warn, Target: "/dev/sda",
				Title: model.T("t", "t"), Detail: model.T("SMART.", "SMART."), Part: &model.Part{Kind: "disk", Location: "/dev/sda"}},
			{ID: "disk.smart_healthy", Component: model.CompDisk, Severity: model.OK, Target: "/dev/sdb"},
		}},
		{Domain: "logs", Findings: []model.Finding{
			{ID: "logs.disk_medium_error", Component: model.CompDisk, Severity: model.Crit, Target: "/dev/sda",
				Title:    model.T("Disk /dev/sda has unreadable sectors", "Ổ /dev/sda có sector không đọc được"),
				Evidence: []string{"sd 0:0:0:0: [sda] Sense Key : Medium Error"}, Part: &model.Part{Kind: "disk", Location: "/dev/sda"}},
			{ID: "logs.disk_io_error", Component: model.CompDisk, Severity: model.Crit, Target: "/dev/sdb",
				Title: model.T("x", "x"), Part: &model.Part{Kind: "disk", Location: "/dev/sdb"}},
			{ID: "logs.oom", Component: model.CompMemory, Severity: model.Warn},
		}},
	}
	foldDiskLogFindings(res)
	if len(res[1].Findings) != 2 || res[1].Findings[0].ID != "logs.disk_io_error" {
		t.Fatalf("log findings after fold: %+v", res[1].Findings)
	}
	d := res[0].Findings[0]
	if d.Severity != model.Crit || len(d.Evidence) != 1 || !strings.Contains(d.Detail.VI, "Log hệ thống cũng xác nhận") {
		t.Fatalf("merged disk finding: %+v", d)
	}
}
