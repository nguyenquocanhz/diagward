package disk

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
)

// TestLive runs the real collector on this machine (Windows locally, Linux
// through WSL when started on Windows) and prints the disk sections and the
// analysis. It is skipped unless DISK_LIVE is set to "linux" or "windows":
//
//	DISK_LIVE=linux go test -run TestLive -v ./internal/checks/disk/
func TestLive(t *testing.T) {
	osName := os.Getenv("DISK_LIVE")
	if osName == "" {
		t.Skip("set DISK_LIVE=linux|windows to run the collector on this machine")
	}
	bnd := collect.NewBoundary()
	o := collect.Options{BenchDir: os.Getenv("DISK_LIVE_BENCH"), BenchMB: 64}
	s, err := collect.Script(osName, bnd, o)
	if err != nil {
		t.Fatal(err)
	}
	name, args := collect.Command(osName)
	if osName == collect.OSLinux && runtime.GOOS == "windows" {
		name, args = "wsl.exe", append([]string{"-e"}, append([]string{name}, args...)...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(s)
	start := time.Now()
	out, err := cmd.Output()
	if err != nil {
		t.Logf("collector: %v", err)
	}
	secs, noise := collect.ParseFramed(string(out), bnd)
	b := &collect.Bundle{Format: collect.BundleFormat, OS: osName, Started: start, Finished: time.Now(), Options: o, Sections: secs, Noise: noise}
	for _, sec := range b.Prefix("disk.") {
		o := sec.Out
		if len(o) > 1500 {
			o = o[:1500] + "\n..."
		}
		t.Logf("==== %s rc=%d missing=%q skipped=%q timeout=%v ms=%d\n%s\n---- stderr: %s", sec.Name, sec.RC, sec.Missing, sec.Skipped, sec.Timeout, sec.MS, o, sec.Err)
	}
	if noise != "" {
		t.Logf("NOISE: %s", noise)
	}
	env := collect.EnvOf(b)
	res := Check(b, env)
	testkit.Validate(t, res)
	t.Logf("env=%+v", env)
	for _, f := range res.Findings {
		t.Logf("FINDING %s %s %s | %s | %s", f.Severity, f.ID, f.Target, f.Title.EN, f.Title.VI)
	}
	for _, c := range res.Coverage {
		t.Logf("COVERAGE %s %s | %s | %s", c.ID, c.State, c.Reason.EN, c.Fix.EN)
	}
	for _, tb := range res.Tables {
		for _, r := range tb.Rows {
			t.Logf("ROW %s %q", r.Status, r.Cells)
		}
	}
	if os.Getenv("DISK_LIVE_JSON") != "" {
		j, _ := json.MarshalIndent(res, "", "  ")
		t.Logf("%s", j)
	}
}
