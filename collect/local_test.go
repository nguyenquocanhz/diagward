package collect

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Real stderr of `powershell.exe -NoProfile -NonInteractive -EncodedCommand`
// with redirected streams, running Write-Progress and Write-Error
// (captured on Windows 10 22H2, PowerShell 5.1.19041).
const realCLIXML = "#< CLIXML\r\n" +
	`<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">0</I64><PR N="Record"><AV>Doing</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Processing</T><SR>-1</SR><SD>x</SD></PR></MS></Obj><S S="Error">Write-Progress -Activity "Doing" -Status "x"; Write-Error "boom &lt;here&gt; &amp; there"; Write-Output "out" : boom &lt;here&gt; &amp; _x000D__x000A_</S><S S="Error">there_x000D__x000A_</S><S S="Error">    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs>`

func TestCleanStderr(t *testing.T) {
	got := cleanStderr(realCLIXML)
	if strings.Contains(got, "CLIXML") || strings.Contains(got, "<Obj") || strings.Contains(got, "Preparing modules") {
		t.Fatalf("CLIXML not removed:\n%s", got)
	}
	if !strings.Contains(got, `boom <here> &`) || !strings.Contains(got, "WriteErrorException") {
		t.Fatalf("error records lost:\n%s", got)
	}
	// Progress only: nothing left.
	prog := "#< CLIXML\n" + `<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV></PR></MS></Obj></Objs>`
	if got := cleanStderr(prog); got != "" {
		t.Fatalf("progress-only stderr should be empty, got %q", got)
	}
	// Plain stderr is kept; mixed plain + CLIXML keeps the plain lines.
	if got := cleanStderr("sh: 1: foo: not found\n"); got != "sh: 1: foo: not found" {
		t.Fatalf("plain stderr changed: %q", got)
	}
	if got := cleanStderr("warning: x\n" + prog); got != "warning: x" {
		t.Fatalf("mixed: %q", got)
	}
	// Garbage and truncation never panic.
	for i := 0; i < len(realCLIXML); i += 7 {
		_ = cleanStderr(realCLIXML[:i])
	}
	_ = cleanStderr(`<Objs><S S="Error">_x00ZZ_ _x0041_</S>`)
}

func TestStreamWriterSplitWrites(t *testing.T) {
	bnd := "abc123"
	out := "noise\n==DW:abc123:BEGIN meta.ident\nhostname=x\n\n==DW:abc123:ERR\n\n==DW:abc123:END rc=0 ms=1\n" +
		"==DW:abc123:BEGIN disk.lsblk\r\n{}\n\n==DW:abc123:ERR\n\n==DW:abc123:END rc=0 ms=2\n" +
		"text ==DW:abc123:BEGIN not.a.marker\n==DW:other:BEGIN wrong.boundary\n==DW:abc123:BEGIN last"
	for _, chunk := range []int{1, 2, 3, 5, 8, 13, 1000} {
		var got []string
		w := &streamWriter{marker: []byte("==DW:" + bnd + ":BEGIN "), progress: func(s string) { got = append(got, s) }}
		for i := 0; i < len(out); i += chunk {
			j := min(i+chunk, len(out))
			if n, err := w.Write([]byte(out[i:j])); err != nil || n != j-i {
				t.Fatal(n, err)
			}
		}
		// "last" has no newline yet: not reported until the line ends.
		if strings.Join(got, ",") != "meta.ident,disk.lsblk" {
			t.Fatalf("chunk %d: progress %q", chunk, got)
		}
		if w.String() != out {
			t.Fatalf("chunk %d: output changed", chunk)
		}
	}
}

func TestCappedBuffer(t *testing.T) {
	c := &cappedBuffer{max: 5}
	c.Write([]byte("abc"))
	c.Write([]byte("defgh"))
	if n, _ := c.Write([]byte("xyz")); n != 3 || c.String() != "abcde" {
		t.Fatalf("%q", c.String())
	}
}

func TestParseProcStat(t *testing.T) {
	for _, c := range []struct {
		in        string
		pid, ppid int
		ok        bool
	}{
		{"1234 (sh) S 1200 1234 1200 0 -1 4194560 108 0 0 0", 1234, 1200, true},
		{"77 (weird ) name) R 5 77 77 0", 77, 5, true},
		{"77 (x", 0, 0, false},
		{"", 0, 0, false},
		{"abc (x) S 1", 0, 0, false},
		{"5 (x) S", 0, 0, false},
	} {
		pid, ppid, ok := parseProcStat(c.in)
		if pid != c.pid || ppid != c.ppid || ok != c.ok {
			t.Errorf("%q: got %d %d %v", c.in, pid, ppid, ok)
		}
	}
}

func TestRunLocalUnsupported(t *testing.T) {
	if runtime.GOOS == OSLinux || runtime.GOOS == OSWindows {
		t.Skip("supported OS")
	}
	_, err := RunLocal(context.Background(), Options{}, nil)
	if !errors.Is(err, ErrUnsupportedOS) || !strings.Contains(err.Error(), "diagward bmc") {
		t.Fatalf("got %v", err)
	}
}

// TestRunScriptCancelKillsTree starts a collector-like script that runs a
// long child (on Linux through coreutils `timeout`, which moves the child
// into its own process group), cancels, and checks that runScript returns
// promptly and the child is gone.
func TestRunScriptCancelKillsTree(t *testing.T) {
	if runtime.GOOS != OSLinux && runtime.GOOS != OSWindows {
		t.Skip("no collector on this OS")
	}
	bnd := NewBoundary()
	var script string
	name, args := Command(runtime.GOOS)
	switch runtime.GOOS {
	case OSLinux:
		if _, err := exec.LookPath("timeout"); err != nil {
			t.Skip("no timeout(1)")
		}
		script = "printf '==DW:" + bnd + ":BEGIN first\\n'\n" +
			"timeout 120 sleep 120 &\necho \"PID=$!\"\ntimeout 120 sleep 121\n"
	case OSWindows:
		script = "[Console]::Out.Write(\"==DW:" + bnd + ":BEGIN first`n\")\n" +
			"$p = Start-Process -FilePath ping.exe -ArgumentList '-n','120','127.0.0.1' -PassThru -WindowStyle Hidden\n" +
			"[Console]::Out.Write(\"PID=$($p.Id)`n\"); [Console]::Out.Flush()\n" +
			"Start-Sleep -Seconds 120\n"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	pidSeen := make(chan struct{})
	start := time.Now()
	var out string
	var err error
	go func() {
		// Cancel once the child pid has been printed.
		select {
		case <-pidSeen:
		case <-time.After(60 * time.Second):
		}
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	progress := func(s string) { once.Do(func() { close(pidSeen) }) }
	out, _, err = runScript(ctx, name, args, script, bnd, progress)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected an exit error after cancel, got nil (out=%q)", out)
	}
	if elapsed > 45*time.Second {
		t.Fatalf("runScript took %v after cancel", elapsed)
	}
	m := regexp.MustCompile(`PID=(\d+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no child pid in output %q", out)
	}
	pid, _ := strconv.Atoi(m[1])
	deadline := time.Now().Add(10 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("child %d still running after cancel", pid)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("returned %v after start; child %d gone", elapsed, pid)
}

func alive(pid int) bool {
	switch runtime.GOOS {
	case OSLinux:
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return false
		}
		_, _, ok := parseProcStat(string(data))
		// A zombie ("Z") has exited; it only waits to be reaped.
		return ok && !strings.Contains(string(data), ") Z ")
	case OSWindows:
		out, _ := exec.Command("tasklist.exe", "/FI", "PID eq "+strconv.Itoa(pid), "/NH").Output()
		return strings.Contains(strings.ToLower(string(out)), "ping")
	}
	return false
}

// TestRunLocalReal runs the real collector for this OS (about 10-40 s).
func TestRunLocalReal(t *testing.T) {
	if runtime.GOOS != OSLinux && runtime.GOOS != OSWindows {
		t.Skip("no collector on this OS")
	}
	if testing.Short() {
		t.Skip("-short")
	}
	var mu sync.Mutex
	var seen []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	b, err := RunLocal(ctx, Options{SinceDays: 2}, func(s string) {
		mu.Lock()
		seen = append(seen, s)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("RunLocal: %v", err)
	}
	if b.Format != BundleFormat || b.OS != runtime.GOOS || !strings.HasPrefix(b.Tool, "diagward ") ||
		b.Host == "" || b.Started.IsZero() || !b.Finished.After(b.Started) || b.Options.SinceDays != 2 || b.Options.Timeout != 30 {
		t.Fatalf("bundle metadata: %+v", b)
	}
	for _, n := range []string{"meta.ident", "meta.virt", "meta.done"} {
		if b.Get(n) == nil {
			t.Errorf("missing section %s", n)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(b.Sections) {
		t.Errorf("progress saw %d sections, bundle has %d", len(seen), len(b.Sections))
	}
	if len(seen) > 0 && seen[0] != "meta.ident" {
		t.Errorf("first progress %q", seen[0])
	}
	if strings.Contains(b.Noise, "CLIXML") {
		t.Errorf("CLIXML left in noise: %s", b.Noise)
	}
	if b.Noise != "" {
		t.Logf("noise: %s", b.Noise)
	}
	env := EnvOf(b)
	t.Logf("%d sections in %v; env %+v", len(b.Sections), b.Finished.Sub(b.Started).Round(time.Millisecond), env)
}

// TestRunLocalCancelPartial cancels a real run after a few sections and
// expects the partial bundle back with a context error.
func TestRunLocalCancelPartial(t *testing.T) {
	if runtime.GOOS != OSLinux && runtime.GOOS != OSWindows {
		t.Skip("no collector on this OS")
	}
	if testing.Short() {
		t.Skip("-short")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	start := time.Now()
	b, err := RunLocal(ctx, Options{}, func(string) {
		n++
		if n == 5 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if b == nil || len(b.Sections) < 5 || b.Get("meta.ident") == nil {
		t.Fatalf("partial bundle: %+v", b)
	}
	if b.Get("meta.done") != nil {
		t.Fatalf("meta.done present after cancel")
	}
	if d := time.Since(start); d > 45*time.Second {
		t.Fatalf("cancel took %v", d)
	}
	t.Logf("partial: %d sections, err=%v", len(b.Sections), err)
}
