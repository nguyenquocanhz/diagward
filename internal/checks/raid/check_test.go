package raid

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func run(t *testing.T, os string, secs ...*collect.Section) model.Result {
	t.Helper()
	res := Check(testkit.Bundle(os, secs...), testkit.Env(os))
	testkit.Validate(t, res)
	return res
}

func runEnv(t *testing.T, env model.Env, secs ...*collect.Section) model.Result {
	t.Helper()
	res := Check(testkit.Bundle(env.OS, secs...), env)
	testkit.Validate(t, res)
	return res
}

func want(t *testing.T, res model.Result, id, target string, sev model.Severity) *model.Finding {
	t.Helper()
	var f *model.Finding
	if target == "" {
		f = testkit.Find(res, id)
	} else {
		f = testkit.Find(res, id, target)
	}
	if f == nil {
		t.Fatalf("missing finding %s@%s; have %v", id, target, testkit.IDs(res))
	}
	if f.Severity != sev {
		t.Errorf("%s@%s: severity %s, want %s", id, target, f.Severity, sev)
	}
	return f
}

func none(t *testing.T, res model.Result, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if f := testkit.Find(res, id); f != nil {
			t.Errorf("unexpected finding %s@%s=%s; all: %v", id, f.Target, f.Severity, testkit.IDs(res))
		}
	}
}

func noWorseThan(t *testing.T, res model.Result, max model.Severity) {
	t.Helper()
	for _, f := range res.Findings {
		if f.Severity > max {
			t.Errorf("finding %s@%s is %s, want at most %s", f.ID, f.Target, f.Severity, max)
		}
	}
}

func cov(t *testing.T, res model.Result, id, state string) *model.Coverage {
	t.Helper()
	c := testkit.Cov(res, id)
	if c == nil {
		t.Fatalf("missing coverage %s; have %+v", id, res.Coverage)
	}
	if c.State != state {
		t.Errorf("coverage %s: state %s, want %s (reason %q)", id, c.State, state, c.Reason.EN)
	}
	return c
}

func table(t *testing.T, res model.Result, id string) model.Table {
	t.Helper()
	for _, tb := range res.Tables {
		if tb.ID == id {
			return tb
		}
	}
	t.Fatalf("missing table %s", id)
	return model.Table{}
}

func TestNoSectionsNoNoise(t *testing.T) {
	for _, os := range []string{collect.OSLinux, collect.OSWindows, collect.OSBMC} {
		res := run(t, os)
		if len(res.Findings)+len(res.Coverage)+len(res.Tables) != 0 || res.Facts != nil {
			t.Errorf("%s: empty bundle produced output: %+v", os, res)
		}
	}
}

func TestMdstatWithoutArraysIsSilent(t *testing.T) {
	res := run(t, collect.OSLinux, testkit.S("raid.mdstat", "Personalities : [raid1] [raid4] [raid5] [raid6] \nunused devices: <none>\n"))
	if len(res.Findings)+len(res.Coverage) != 0 {
		t.Errorf("no arrays should give no output, got %v %+v", testkit.IDs(res), res.Coverage)
	}
}

func TestContainerHW(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Virtual, env.Container = "wsl", true
	res := runEnv(t, env, testkit.Skipped("raid.hw", "container"))
	c := cov(t, res, "raid.hw", model.CovSkipped)
	if !strings.Contains(c.Reason.EN, "container") {
		t.Errorf("reason should mention container: %q", c.Reason.EN)
	}
}

func TestHWNotRoot(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	env.Root = false
	res := runEnv(t, env, testkit.S("raid.pci", testkit.Read(t, "pci_perc_hba.txt")), testkit.Skipped("raid.hw", "not-root"))
	cov(t, res, "raid.hw", model.CovSkipped)
}

func TestWindowsNotAdmin(t *testing.T) {
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res := runEnv(t, env, testkit.Skipped("raid.hw", "not-admin"))
	c := cov(t, res, "raid.hw", model.CovSkipped)
	if !strings.Contains(c.Reason.EN, "Administrator") {
		t.Errorf("reason: %q", c.Reason.EN)
	}
}

// Garbage, truncated and empty input for every section must never panic
// and must still produce a valid Result.
func TestGarbageNeverPanics(t *testing.T) {
	names := []string{
		"raid.mdstat", "raid.md_sysfs", "raid.mdadm:/dev/md0", "raid.mdadm_scan", "raid.byid",
		"raid.zpool_status", "raid.zpool_list", "raid.btrfs_show", "raid.btrfs_stats:/", "raid.lvs",
		"raid.pci", "raid.storcli_ctrl", "raid.storcli_vd", "raid.storcli_pd", "raid.storcli_rebuild",
		"raid.storcli_bbu", "raid.storcli_cv", "raid.perccli_ctrl", "raid.ssacli_config", "raid.ssacli_status",
		"raid.arcconf:1", "raid.megacli_ld", "raid.megacli_pd", "raid.megacli_bbu",
		"raid.win_pools", "raid.win_vdisks", "raid.win_pdisks", "raid.win_jobs", "raid.win_controllers",
	}
	samples := []string{
		"", "\n\n", "garbage ::: [[[ }}}", "{", "[", "null", `{"Controllers":[null,{"Response Data":7}]}`,
		`{"Controllers":[{"Command Status":{"Controller":"x","Status":"Success"},"Response Data":{"VD LIST":[1,"a",null],"PD LIST":{"x":1},"Basics":[]}}]}`,
		"md0 : active raid1 sda1[0](F) sdb1[\n      100 blocks [2/1] [U_\n      [==>  recovery = 12.%",
		"  pool: p\n state: DEGRADED\nconfig:\n\n\tNAME STATE\n\tp\n\t  x FAULTED 1 2\nerrors: 3 data errors",
		"Label: 'x'  uuid: y\n\tTotal devices 9 FS bytes used\n\tdevid\n[/dev/sda].read_io_errs notanumber",
		"#fields=lv_name,segtype,lv_attr\n|||\nx|raid1|r",
		"Smart Array X in Slot 1\n   Array: A\n      Logical Drive: 1\n         Status:\n      physicaldrive 1I:1:1 (\n",
		"Logical Device number 0\n   Status of Logical Device : \nDevice #0\n   State : \n   S.M.A.R.T. warnings : x",
		"Adapter #0\nVirtual Drive: 0 (Target Id: 0)\nState: \nEnclosure Device ID: 32\nSlot Number:\nInquiry Data:\n",
		`[{"FriendlyName":null,"HealthStatus":[1,2],"OperationalStatus":{"a":1},"IsPrimordial":"no","Size":"big"}]`,
	}
	var full []byte
	for i := 0; i < 2000; i++ {
		full = append(full, "md1 : active raid5 sdc1[2](F)\n"...)
	}
	samples = append(samples, string(full))
	for _, os := range []string{collect.OSLinux, collect.OSWindows} {
		for _, s := range samples {
			var secs []*collect.Section
			for _, n := range names {
				secs = append(secs, testkit.S(n, s))
			}
			run(t, os, secs...)
			// Truncated at every few bytes of a real fixture.
		}
	}
	for _, f := range []string{"mdstat_procfs.txt", "zpool_status_resilver.txt", "storcli_ctrl_praid_ep420i.json", "ssacli-P400ar.txt", "arcconf-getconfig-al-degraded.txt", "megacli-ldpdinfo.txt", "wsl_lvs_json_partial.txt"} {
		data := testkit.Read(t, f)
		for cut := 0; cut < len(data); cut += 97 {
			part := data[:cut]
			run(t, collect.OSLinux,
				testkit.S("raid.mdstat", part), testkit.S("raid.zpool_status", part), testkit.S("raid.storcli_ctrl", part),
				testkit.S("raid.storcli_pd", part), testkit.S("raid.ssacli_config", part), testkit.S("raid.arcconf:1", part),
				testkit.S("raid.megacli_pd", part), testkit.S("raid.lvs", part), testkit.S("raid.btrfs_show", part))
		}
	}
}
