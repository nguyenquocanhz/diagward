package logs

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// noATASmartctl fails when an action tells the reader to run smartctl on a
// libata port name ("smartctl -a ata1"): smartctl needs a device path.
func noATASmartctl(t *testing.T, res model.Result) {
	t.Helper()
	for _, f := range res.Findings {
		for _, s := range []string{f.Action.EN, f.Action.VI} {
			if reATASmartctl.MatchString(s) {
				t.Errorf("%s@%s: action names an ATA port as a device: %s", f.ID, f.Target, s)
			}
		}
	}
}

func countFindings(res model.Result, id, target string) int {
	n := 0
	for _, f := range res.Findings {
		if f.ID == id && f.Target == target {
			n++
		}
	}
	return n
}

// The "ata1.00: error: { UNC }" line and the "sd 0:0:0:0: [sda] ... Medium
// Error" lines of linux_failing_match.txt are one read error, seen by libata
// and by the SCSI disk driver. With the sysfs map (ata1 is sda) the report
// shows one medium-error finding for /dev/sda, not a second one for "ata1".
func TestATAMergedIntoDisk(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.S("logs.kernel_match", testkit.Read(t, "linux_failing_match.txt")),
		testkit.S("logs.kernel", "# source=journal persistent=1 tz=+0700\n# rc=0\n"),
		testkit.S("logs.blockdevs", testkit.Read(t, "blockdevs_ata.txt")),
	)
	none(t, res, "logs.disk_medium_error", "ata1")
	sda := want(t, res, "logs.disk_medium_error", "/dev/sda", model.Crit)
	if n := countFindings(res, "logs.disk_medium_error", "/dev/sda"); n != 1 {
		t.Errorf("%d medium-error findings for /dev/sda", n)
	}
	if sda.Part == nil || sda.Part.Location != "/dev/sda" || sda.Part.Model != "ST4000NM0035-1V4107" {
		t.Errorf("part = %+v", sda.Part)
	}
	if !strings.Contains(sda.Detail.EN, "ata1") || !strings.Contains(sda.Detail.VI, "ata1") {
		t.Errorf("detail does not name the port: %s / %s", sda.Detail.EN, sda.Detail.VI)
	}
	// The same event: the UNC line is evidence, not a third count.
	if !strings.Contains(sda.Detail.EN, "Seen 2 times") {
		t.Errorf("detail: %s", sda.Detail.EN)
	}
	if !strings.Contains(strings.Join(sda.Evidence, "\n"), "{ UNC }") {
		t.Errorf("evidence misses the libata line: %v", sda.Evidence)
	}
	if !strings.Contains(sda.Action.EN, "smartctl -a /dev/sda") {
		t.Errorf("action: %s", sda.Action.EN)
	}
	// The port-level finding keeps its port but points at the disk.
	ata := want(t, res, "logs.disk_ata_error", "ata1", model.Warn)
	if ata.Part == nil || ata.Part.Location != "/dev/sda" || ata.Part.Model != "ST4000NM0035-1V4107" || ata.Part.Firmware != "TN03" {
		t.Errorf("ata part = %+v", ata.Part)
	}
	if !strings.Contains(ata.Detail.EN, "/dev/sda") {
		t.Errorf("ata detail: %s", ata.Detail.EN)
	}
	noATASmartctl(t, res)
	for _, e := range res.Facts.(*Facts).Events {
		if e.Rule == "disk_medium_error" && e.Target == "ata1" {
			t.Errorf("event table still lists ata1: %+v", e)
		}
	}
}

// Without the map (an older collector, or a port whose disk is gone) the
// port stays the target, but the action says how to find the disk instead
// of "smartctl -a ata1".
func TestATAUnmapped(t *testing.T) {
	res := check(t, linuxEnv(), collect.OSLinux,
		testkit.S("logs.kernel_match", testkit.Read(t, "linux_failing_match.txt")),
		testkit.S("logs.kernel", "# source=journal persistent=1 tz=+0700\n# rc=0\n"),
	)
	f := want(t, res, "logs.disk_medium_error", "ata1", model.Crit)
	for _, s := range []string{f.Action.EN, f.Action.VI} {
		if !strings.Contains(s, "ls -l /sys/class/block/ | grep /ata1/") || !strings.Contains(s, "smartctl -a /dev/sdX") {
			t.Errorf("action: %s", s)
		}
	}
	if !strings.HasPrefix(f.Action.EN, "Back up") {
		t.Errorf("most urgent step first: %s", f.Action.EN)
	}
	ata := want(t, res, "logs.disk_ata_error", "ata1", model.Warn)
	if !strings.Contains(ata.Action.EN, "grep /ata1/") || !strings.Contains(ata.Action.VI, "grep /ata1/") {
		t.Errorf("ata action: %s", ata.Action.EN)
	}
	if ata.Part == nil || ata.Part.Location != "ata1" {
		t.Errorf("ata part = %+v", ata.Part)
	}
	want(t, res, "logs.disk_medium_error", "/dev/sda", model.Crit)
	noATASmartctl(t, res)
}

func TestATAMapping(t *testing.T) {
	env := linuxEnv()
	map_ := testkit.S("logs.blockdevs", testkit.Read(t, "blockdevs_ata.txt"))
	run := func(lines ...string) model.Result {
		return check(t, env, collect.OSLinux, testkit.S("logs.kernel_match", journal(lines...)), map_)
	}

	t.Run("libata only", func(t *testing.T) {
		// Some kernels log only the libata side: the finding moves to the disk.
		res := run(at(env, 2*time.Hour)+" h kernel: ata2.00: error: { UNC }",
			at(env, 2*time.Hour)+" h kernel: ata2.00: disabled")
		none(t, res, "logs.disk_medium_error", "ata2")
		f := want(t, res, "logs.disk_medium_error", "/dev/sdb", model.Crit)
		if f.Part == nil || f.Part.Location != "/dev/sdb" {
			t.Errorf("part = %+v", f.Part)
		}
		if !strings.Contains(f.Detail.EN, "ata2") {
			t.Errorf("detail: %s", f.Detail.EN)
		}
		want(t, res, "logs.disk_offline", "/dev/sdb", model.Crit)
		noATASmartctl(t, res)
	})

	t.Run("port multiplier", func(t *testing.T) {
		// ata3 has two disks behind a port multiplier: ata3.01 is link 1
		// (SCSI channel 1, 2:1:0:0 = sde). A port-wide reset cannot be
		// pinned to one disk.
		res := run(at(env, time.Hour)+" h kernel: ata3.01: error: { UNC }",
			at(env, time.Hour)+" h kernel: ata3: hard resetting link")
		want(t, res, "logs.disk_medium_error", "/dev/sde", model.Crit)
		ata := want(t, res, "logs.disk_ata_error", "ata3", model.Warn)
		if ata.Part != nil && ata.Part.Location != "ata3" {
			t.Errorf("ata3 pinned to one disk: %+v", ata.Part)
		}
		if !strings.Contains(ata.Action.EN, "grep /ata3/") {
			t.Errorf("action: %s", ata.Action.EN)
		}
	})

	t.Run("different events", func(t *testing.T) {
		// A libata read error two days before the SCSI one is another
		// event on the same disk: still one finding, counted.
		res := run(at(env, 48*time.Hour)+" h kernel: ata1.00: error: { UNC }",
			at(env, time.Hour)+" h kernel: sd 0:0:0:0: [sda] tag#3 Sense Key : Medium Error [current]")
		none(t, res, "logs.disk_medium_error", "ata1")
		f := want(t, res, "logs.disk_medium_error", "/dev/sda", model.Crit)
		if !strings.Contains(f.Detail.EN, "Seen 2 times between") {
			t.Errorf("detail: %s", f.Detail.EN)
		}
	})

	t.Run("hctl", func(t *testing.T) {
		// "sd 6:0:0:0:" without [sdX]: the sysfs path of sdc ends in 6:0:0:0.
		res := run(at(env, time.Hour) + " h kernel: sd 6:0:0:0: rejecting I/O to offline device")
		want(t, res, "logs.disk_offline", "/dev/sdc", model.Crit)
		res = check(t, env, collect.OSLinux, testkit.S("logs.kernel_match",
			journal(at(env, time.Hour)+" h kernel: sd 6:0:0:0: rejecting I/O to offline device")))
		want(t, res, "logs.disk_offline", "scsi 6:0:0:0", model.Crit)
	})

	t.Run("log names win", func(t *testing.T) {
		// The log said 0:0:0:0 was sdb at the time: keep that over sysfs.
		res := run(at(env, time.Hour)+" h kernel: sd 0:0:0:0: [sdb] Attached SCSI disk",
			at(env, time.Hour)+" h kernel: sd 0:0:0:0: rejecting I/O to offline device")
		want(t, res, "logs.disk_offline", "/dev/sdb", model.Crit)
	})
}

func TestReadBlockDevs(t *testing.T) {
	ctx := &matchCtx{hctl: map[string]string{}}
	addBlockDevs(ctx, testkit.S("logs.blockdevs", testkit.Read(t, "blockdevs_ata.txt")))
	for line, want := range map[string]string{
		"ata1.00: error: { UNC }":       "/dev/sda",
		"ata1: hard resetting link":     "/dev/sda",
		"ata2.00: exception Emask 0x0":  "/dev/sdb",
		"ata3.00: error: { UNC }":       "/dev/sdd",
		"ata3.01: error: { UNC }":       "/dev/sde",
		"ata3: hard resetting link":     "",
		"ata3.02: error: { UNC }":       "",
		"ata4.00: error: { UNC }":       "",
		"ata10.00: error: { UNC }":      "",
		"nvme nvme0: I/O 448 QID 5 x":   "",
		"sd 6:0:0:0: [sdc] something x": "",
	} {
		if got := ctx.ataDisk(line); got != want {
			t.Errorf("%q -> %q, want %q", line, got, want)
		}
	}
	if ctx.hctl["6:0:0:0"] != "sdc" || ctx.hctl["2:1:0:0"] != "sde" {
		t.Errorf("hctl = %v", ctx.hctl)
	}
	if _, ok := ctx.hctl["nvme0n1"]; ok {
		t.Errorf("hctl = %v", ctx.hctl)
	}

	// Real capture (WSL2, Hyper-V storvsc): no libata, four LUNs.
	ctx = &matchCtx{hctl: map[string]string{}}
	addBlockDevs(ctx, testkit.S("logs.blockdevs", testkit.Read(t, "wsl_blockdevs.txt")))
	if len(ctx.ataDisks) != 0 || ctx.hctl["0:0:0:1"] != "sdb" || ctx.hctl["0:0:0:3"] != "sdd" {
		t.Errorf("wsl: ata=%v hctl=%v", ctx.ataDisks, ctx.hctl)
	}

	// Skipped / missing / garbage sections.
	for _, s := range []*collect.Section{nil, {Name: "logs.blockdevs", Skipped: "container"}, testkit.S("logs.blockdevs", "\x00\xff=\n=\nsda\nsda=/ata1/\n")} {
		ctx = &matchCtx{hctl: map[string]string{}}
		addBlockDevs(ctx, s)
	}
}

func TestATAGarbageMap(t *testing.T) {
	data := testkit.Read(t, "blockdevs_ata.txt")
	match := testkit.Read(t, "linux_failing_match.txt")
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 30; i++ {
		bs := []byte(data)
		for j := 0; j < 1+len(bs)/40; j++ {
			bs[rng.Intn(len(bs))] = byte(rng.Intn(256))
		}
		res := Check(testkit.Bundle(collect.OSLinux, testkit.S("logs.kernel_match", match), testkit.S("logs.blockdevs", string(bs[:rng.Intn(len(bs))]))), linuxEnv())
		testkit.Validate(t, res)
		noATASmartctl(t, res)
	}
}

var reATASmartctl = regexp.MustCompile(`smartctl -a ata\d`)
