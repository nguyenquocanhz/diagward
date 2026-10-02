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
		"/dev/sda":           {"sda"},
		"sda1":               {"sda1", "sda"},
		"/dev/nvme0n1p2":     {"nvme0n1p2", "nvme0n1"},
		"nvme0n1":            {"nvme0n1"},
		"PhysicalDrive1":     {"win:1"},
		`\\.\PHYSICALDRIVE3`: {"win:3"},
		"PhysicalDisk3":      {"win:3"},
		"md0":                {"md0"},
		"":                   nil,
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
		}}},
		{Domain: "logs", Findings: []model.Finding{
			{ID: "logs.disk_io", Target: "sda", Part: &model.Part{Kind: "disk", Location: "/dev/sda"}},
			{ID: "logs.win_disk", Target: "PhysicalDrive1", Part: &model.Part{Kind: "disk", Location: "PhysicalDrive1"}},
			{ID: "logs.unknown", Target: "sdz", Part: &model.Part{Kind: "disk", Location: "/dev/sdz"}},
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
