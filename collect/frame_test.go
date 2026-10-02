package collect

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestParseFramedRoundTrip(t *testing.T) {
	b := "abc123"
	out := "banner noise\n" +
		"==DW:abc123:BEGIN one\n" + "line1\nline2\n" + "\n" +
		"==DW:abc123:ERR\n" + "warn\n" +
		"==DW:abc123:END rc=0 ms=5\n" +
		"==DW:abc123:BEGIN empty\n\n==DW:abc123:ERR\n\n==DW:abc123:END rc=127 ms=0 missing=smartctl\n" +
		"==DW:abc123:BEGIN nonl\nno newline\n==DW:abc123:ERR\n\n==DW:abc123:END rc=2 ms=1000 timeout truncated\n" +
		"==DW:other:BEGIN fake\n" + // a different boundary is just output
		"==DW:abc123:BEGIN cut\npartial"
	secs, noise := ParseFramed(out, b)
	// A marker with another boundary outside any section is plain noise.
	if noise != "banner noise\n==DW:other:BEGIN fake" {
		t.Errorf("noise=%q", noise)
	}
	if len(secs) != 4 {
		t.Fatalf("got %d sections", len(secs))
	}
	if s := secs[0]; s.Name != "one" || s.Out != "line1\nline2\n" || s.Err != "warn" || s.RC != 0 || s.MS != 5 {
		t.Errorf("one: %+v", s)
	}
	if s := secs[1]; s.Out != "" || s.Missing != "smartctl" || s.Ran() {
		t.Errorf("empty: %+v", s)
	}
	if s := secs[2]; s.Out != "no newline" || !s.Timeout || !s.Truncated || s.RC != 2 {
		t.Errorf("nonl: %+v", s)
	}
	if s := secs[3]; s.Name != "cut" || s.Out != "partial" || s.RC != -1 || !s.Timeout {
		t.Errorf("cut: %+v", s)
	}
}

func TestParseFramedCRLF(t *testing.T) {
	out := "==DW:b:BEGIN w\r\n[1,2]\r\n\r\n==DW:b:ERR\r\n\r\n==DW:b:END rc=0 ms=3\r\n"
	secs, _ := ParseFramed(out, "b")
	if len(secs) != 1 || secs[0].Out != "[1,2]\n" {
		t.Fatalf("%+v", secs)
	}
}

func TestBundleReadWrite(t *testing.T) {
	b := &Bundle{Format: BundleFormat, OS: OSLinux, Host: "x"}
	b.Add(&Section{Name: "disk.lsblk", Out: "{}"})
	b.Add(&Section{Name: "disk.smart:/dev/sda", Out: "a"})
	b.Add(&Section{Name: "disk.smart:/dev/sdb", Out: "b"})
	var buf bytes.Buffer
	if err := Write(&buf, b); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("disk.lsblk").Out != "{}" || len(got.Prefix("disk.smart:")) != 2 {
		t.Fatalf("%+v", got)
	}
	if _, err := Read(strings.NewReader(`{"format":99}`)); err == nil {
		t.Fatal("expected format error")
	}
}

func TestScriptAssembles(t *testing.T) {
	for _, os := range []string{OSLinux, OSWindows} {
		s, err := Script(os, "b0", Options{BenchDir: "/var/tmp/it's"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s, "00-common") || !strings.Contains(s, "99-end") {
			t.Fatalf("%s script misses snippets", os)
		}
	}
	if _, err := Script(OSLinux, "b", Options{Memtest: "1G; rm -rf /"}); err == nil {
		t.Fatal("expected memtest validation error")
	}
}

// TestLinuxScriptRuns runs the real collector under sh when one is
// available (Linux, macOS, or Git Bash on Windows is skipped: its sh is not
// a Linux userland).
func TestLinuxScriptRuns(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs a Linux userland")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	bnd := NewBoundary()
	s, err := Script(OSLinux, bnd, Options{Timeout: 20})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(s)
	out, _ := cmd.Output()
	secs, noise := ParseFramed(string(out), bnd)
	b := &Bundle{Format: BundleFormat, OS: OSLinux, Sections: secs}
	if b.Get("meta.ident") == nil || b.Get("meta.done") == nil {
		t.Fatalf("missing meta sections; noise=%q", noise)
	}
	env := EnvOf(b)
	t.Logf("env: %+v", env)
}

// TestWindowsScriptRuns runs the real PowerShell collector on Windows.
func TestWindowsScriptRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("needs Windows")
	}
	bnd := NewBoundary()
	s, err := Script(OSWindows, bnd, Options{Timeout: 20})
	if err != nil {
		t.Fatal(err)
	}
	name, args := Command(OSWindows)
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("powershell: %v", err)
	}
	secs, noise := ParseFramed(string(out), bnd)
	b := &Bundle{Format: BundleFormat, OS: OSWindows, Sections: secs}
	if b.Get("meta.ident") == nil || b.Get("meta.done") == nil {
		t.Fatalf("missing meta sections; noise=%q", noise)
	}
	if noise != "" {
		t.Errorf("unexpected noise: %q", noise)
	}
	t.Logf("ident: %s", b.Get("meta.ident").Out)
	t.Logf("env: %+v", EnvOf(b))
}
