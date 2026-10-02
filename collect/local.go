package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxLocalOutput caps how much collector output RunLocal keeps in memory.
// Every section is capped at 4 MiB by the scripts and a run has ~150
// sections, so a real run stays far below this; the cap only protects
// against a runaway command.
const maxLocalOutput = 256 << 20

// maxStderr caps the collector's own stderr (outside any section).
const maxStderr = 64 << 10

// killGrace is how long the collector gets after the polite stop signal
// (SIGTERM, so the script's trap removes its temporary files and benchmark
// file) before the whole process tree is killed.
const killGrace = 3 * time.Second

// ErrUnsupportedOS is returned by RunLocal on an operating system that has
// no collector script.
var ErrUnsupportedOS = errors.New("local collection runs on Linux and Windows servers only")

// RunLocal runs the collector for this machine (runtime.GOOS) and returns
// the bundle.
//
// progress, when not nil, is called with each section name as soon as the
// section's BEGIN marker has been read — that is, when the command behind
// it has finished. It is called from another goroutine, one call at a
// time.
//
// When ctx is cancelled the collector's whole process tree is stopped and
// the partial bundle is returned together with an error wrapping
// ctx.Err(). If the collector exits before writing its final meta.done
// section, the bundle is returned with an error that includes its stderr.
func RunLocal(ctx context.Context, o Options, progress func(section string)) (*Bundle, error) {
	osName := runtime.GOOS
	if osName != OSLinux && osName != OSWindows {
		return nil, fmt.Errorf("%w (this is %s). Run Diagward on the server itself; \"diagward bmc\" and \"diagward analyze\" work everywhere", ErrUnsupportedOS, osName)
	}
	o = o.WithDefaults()
	boundary := NewBoundary()
	script, err := Script(osName, boundary, o)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	b := &Bundle{
		Format:  BundleFormat,
		Tool:    "diagward " + CollectorVersion,
		OS:      osName,
		Host:    host,
		Options: o,
	}
	name, args := Command(osName)
	b.Started = time.Now()
	out, stderr, err := runScript(ctx, name, args, script, boundary, progress)
	b.Finished = time.Now()
	b.Sections, b.Noise = ParseFramed(out, boundary)
	if stderr != "" {
		b.Noise = joinNoise(b.Noise, "stderr:\n"+stderr)
	}
	b.reindex()
	switch {
	case ctx.Err() != nil:
		return b, fmt.Errorf("collection interrupted after %d sections: %w", len(b.Sections), ctx.Err())
	case err != nil && b.Get("meta.done") == nil:
		return b, fmt.Errorf("collector failed: %w%s", err, stderrTail(stderr))
	case b.Get("meta.done") == nil:
		return b, fmt.Errorf("collector stopped before the end (%d sections)%s", len(b.Sections), stderrTail(stderr))
	}
	return b, nil
}

// runScript runs name/args with script on stdin. It returns stdout, the
// cleaned stderr and the exit error. It is separate from RunLocal so tests
// can run small scripts.
func runScript(ctx context.Context, name string, args []string, script, boundary string, progress func(string)) (string, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(script)
	sw := &streamWriter{marker: []byte("==DW:" + boundary + ":BEGIN "), progress: progress}
	ew := &cappedBuffer{max: maxStderr}
	cmd.Stdout = sw
	cmd.Stderr = ew
	// If the collector exits but something it started keeps stdout open,
	// do not wait for it forever.
	cmd.WaitDelay = 5 * time.Second
	prepareTree(cmd)
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("cannot start %s: %w", name, err)
	}
	tree := attachTree(cmd)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-done:
			return
		case <-ctx.Done():
		}
		tree.stop()
		select {
		case <-done:
		case <-time.After(killGrace):
			tree.kill()
		}
	}()
	err := cmd.Wait()
	close(done)
	wg.Wait()
	tree.close()
	return sw.String(), cleanStderr(ew.String()), err
}

// streamWriter keeps the collector's stdout and reports each section name
// as its BEGIN line arrives. Writes may split lines anywhere.
type streamWriter struct {
	marker   []byte
	progress func(string)

	mu        sync.Mutex
	buf       bytes.Buffer
	scan      int // start of the first line not yet examined
	truncated bool
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len()+len(p) > maxLocalOutput {
		// Drop the excess but keep draining the pipe, so the collector
		// is not blocked or killed by SIGPIPE.
		w.truncated = true
		return len(p), nil
	}
	w.buf.Write(p)
	data := w.buf.Bytes()
	for {
		i := bytes.IndexByte(data[w.scan:], '\n')
		if i < 0 {
			break
		}
		line := data[w.scan : w.scan+i]
		w.scan += i + 1
		if w.progress != nil && bytes.HasPrefix(line, w.marker) {
			name := strings.TrimSpace(string(bytes.TrimSuffix(line[len(w.marker):], []byte("\r"))))
			if name != "" {
				w.progress(name)
			}
		}
	}
	return len(p), nil
}

func (w *streamWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

var (
	clixmlErrRe = regexp.MustCompile(`(?s)<S S="Error">(.*?)</S>`)
	clixmlEscRe = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)
)

// cleanStderr removes PowerShell's CLIXML serialisation from stderr.
// powershell.exe started with -EncodedCommand and redirected streams writes
// progress records as "#< CLIXML" followed by <Objs> XML; error records in
// that XML (<S S="Error">) are kept as plain text, everything else is
// dropped.
func cleanStderr(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.Contains(s, "#< CLIXML") && !strings.Contains(s, "<Objs ") {
		return strings.TrimSpace(s)
	}
	var keep []string
	inXML := false
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "#< CLIXML":
			inXML = true
			continue
		case strings.HasPrefix(t, "<Objs"):
			inXML = !strings.Contains(t, "</Objs>")
			keep = append(keep, clixmlErrors(t)...)
			continue
		case inXML:
			if strings.Contains(t, "</Objs>") {
				inXML = false
			}
			keep = append(keep, clixmlErrors(t)...)
			continue
		}
		if t != "" {
			keep = append(keep, l)
		}
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

func clixmlErrors(s string) []string {
	var out []string
	var cur strings.Builder
	for _, m := range clixmlErrRe.FindAllStringSubmatch(s, -1) {
		cur.WriteString(m[1])
	}
	if cur.Len() == 0 {
		return nil
	}
	t := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(cur.String())
	t = clixmlEscRe.ReplaceAllStringFunc(t, func(e string) string {
		var r rune
		fmt.Sscanf(e[2:6], "%04x", &r)
		return string(r)
	})
	for _, l := range strings.Split(strings.ReplaceAll(t, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func joinNoise(a, b string) string {
	s := strings.TrimSpace(a + "\n" + b)
	if len(s) > maxNoise {
		s = s[:maxNoise]
	}
	return s
}

func stderrTail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 600 {
		s = "..." + s[len(s)-600:]
	}
	return ": " + s
}

// procTree stops a collector and everything it started.
type procTree interface {
	stop()  // polite: let the script clean up
	kill()  // forced
	close() // release resources
}

// parseProcStat reads pid and ppid from a Linux /proc/<pid>/stat line:
// "123 (comm with spaces) S 45 ...". comm may contain ")" so the last ")"
// ends it.
func parseProcStat(s string) (pid, ppid int, ok bool) {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open <= 0 || end < open {
		return 0, 0, false
	}
	var err error
	if pid, err = strconv.Atoi(strings.TrimSpace(s[:open])); err != nil {
		return 0, 0, false
	}
	f := strings.Fields(s[end+1:])
	if len(f) < 2 {
		return 0, 0, false
	}
	if ppid, err = strconv.Atoi(f[1]); err != nil {
		return 0, 0, false
	}
	return pid, ppid, true
}
