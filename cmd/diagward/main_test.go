package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/bmc"
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

type testApp struct {
	*app
	out, err *bytes.Buffer
	env      map[string]string
}

func newTestApp(goos string) *testApp {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := map[string]string{}
	a := &app{
		stdin:        strings.NewReader(""),
		stdout:       out,
		stderr:       errb,
		getenv:       func(k string) string { return env[k] },
		goos:         goos,
		con:          consoleState{utf8: true, vt: true},
		isTerm:       func(any) bool { return false },
		termWidth:    func(any) int { return 100 },
		privileged:   func() bool { return true },
		readPassword: func() (string, error) { return "", errors.New("no tty") },
		openBrowser:  func(string) error { return nil },
		now:          func() time.Time { return time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC) },
		exeDir:       func() string { return "" },
		consoleCount: func() (uint32, error) { return 2, nil },
		runLocal: func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
			return nil, errors.New("runLocal not set")
		},
		collectBMC: func(context.Context, bmc.Options) (*collect.Bundle, error) {
			return nil, errors.New("collectBMC not set")
		},
	}
	return &testApp{app: a, out: out, err: errb, env: env}
}

// linuxBundle is a small but complete Linux bundle (meta sections only).
func linuxBundle() *collect.Bundle {
	return testkit.Bundle(collect.OSLinux,
		testkit.S("meta.ident", "hostname=srv01\nuid=0\nkernel=5.14.0-427.el9.x86_64\nnow=2026-10-01T09:00:20Z\n"),
		testkit.S("meta.osrelease", "ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n"),
		testkit.S("meta.virt", "vm=none\ncontainer=none\n"),
		testkit.S("meta.pm", "dnf=1\n"),
		testkit.S("meta.done", "now=2026-10-01T09:00:20Z"),
	)
}

func TestDetectLang(t *testing.T) {
	for _, c := range []struct {
		env    map[string]string
		locale string
		want   string
	}{
		{map[string]string{}, "", "en"},
		{map[string]string{"DIAGWARD_LANG": "vi"}, "", "vi"},
		{map[string]string{"DIAGWARD_LANG": "en", "LANG": "vi_VN.UTF-8"}, "vi-VN", "en"},
		{map[string]string{"DIAGWARD_LANG": "klingon", "LANG": "vi_VN.UTF-8"}, "", "vi"},
		{map[string]string{"LC_ALL": "vi_VN.UTF-8"}, "", "vi"},
		{map[string]string{"LC_MESSAGES": "vi_VN"}, "", "vi"},
		{map[string]string{"LANG": "en_US.UTF-8"}, "", "en"},
		{map[string]string{"LANG": "en_US.UTF-8"}, "vi-VN", "vi"},
		{map[string]string{}, "vi-VN", "vi"},
		{map[string]string{}, "en-US", "en"},
	} {
		got := detectLang(func(k string) string { return c.env[k] }, func() string { return c.locale })
		if got != c.want {
			t.Errorf("%v locale=%q: got %s want %s", c.env, c.locale, got, c.want)
		}
	}
	if detectLang(func(string) string { return "" }, nil) != "en" {
		t.Error("nil locale")
	}
}

func TestParseLangAndPreScan(t *testing.T) {
	for in, want := range map[string]string{"vi": "vi", "VI": "vi", "vi-VN": "vi", "vi_VN.UTF-8": "vi", "en": "en", "en-US": "en", "English": "en"} {
		if got, err := parseLang(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "fr", "v"} {
		if _, err := parseLang(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, c := range []struct {
		args []string
		want string
		ok   bool
	}{
		{[]string{"check", "--lang", "vi"}, "vi", true},
		{[]string{"--lang=en", "check"}, "en", true},
		{[]string{"-lang", "vi"}, "vi", true},
		{[]string{"check", "--", "--lang", "vi"}, "", false},
		{[]string{"check", "--lang"}, "", false},
	} {
		got, ok := preScanLang(c.args)
		if got != c.want || ok != c.ok {
			t.Errorf("%v: %q %v", c.args, got, ok)
		}
	}
}

func TestParseValues(t *testing.T) {
	since := map[string]int{"7": 7, "7d": 7, "30D": 30, " 1 ": 1, "3650": 3650}
	for in, want := range since {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("since %q: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"0", "-1", "3651", "x", "7w", "", "1.5"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("since %q accepted", bad)
		}
	}
	bench := map[string]int{"256M": 256, "256m": 256, "1G": 1024, "1GiB": 1024, "512": 512, "16M": 16, "64G": 65536, "65536k": 64, "2gb": 2048}
	for in, want := range bench {
		if got, err := parseBenchSize(in); err != nil || got != want {
			t.Errorf("bench %q: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"8M", "65G", "1T", "abc", "", "-5M", "1.5G", "999999999999G"} {
		if _, err := parseBenchSize(bad); err == nil {
			t.Errorf("bench %q accepted", bad)
		}
	}
	mem := map[string]string{"512M": "512M", "512m": "512M", "2G": "2G", "2gb": "2G", "1024": "1024M", "2048K": "2048K", "1M": "1M"}
	for in, want := range mem {
		if got, err := normMemtest(in); err != nil || got != want {
			t.Errorf("memtest %q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"0", "0M", "512K", "1T", "abc", "", "1000000M", "1.5G", "-1G"} {
		if _, err := normMemtest(bad); err == nil {
			t.Errorf("memtest %q accepted", bad)
		}
	}
}

func TestParseCheckFlags(t *testing.T) {
	a := newTestApp("linux")
	o, err := a.parseCheck([]string{"--html", "r.html", "-v", "--since", "30d", "--json=-", "--timeout", "60", "--memtest", "1g", "--lang", "vi", "-q", "--no-color", "--ascii", "--save", "x.dwb", "--md", "r.md"})
	if err != nil {
		t.Fatal(err)
	}
	if o.out.html != "r.html" || o.out.json != "-" || o.out.md != "r.md" || !o.out.verbose || !o.out.quiet || !o.out.noColor ||
		!o.out.ascii || o.out.save != "x.dwb" || o.col.since.days != 30 || o.col.timeout != 60 || o.col.memtest != "1G" || a.lang != "vi" {
		t.Fatalf("%+v %+v lang=%s", o.out, o.col, a.lang)
	}
	opts := o.col.options()
	if opts.SinceDays != 30 || opts.Timeout != 60 || opts.Memtest != "1G" || opts.BenchDir != "" {
		t.Fatalf("options %+v", opts)
	}
	dir := t.TempDir()
	o, err = a.parseCheck([]string{"--bench", dir, "--bench-size", "1G"})
	if err != nil {
		t.Fatal(err)
	}
	if opts := o.col.options(); opts.BenchMB != 1024 || !filepath.IsAbs(opts.BenchDir) {
		t.Fatalf("bench options %+v", opts)
	}
	for _, bad := range [][]string{
		{"--html", "-", "--json", "-"},
		{"--bench-size", "1G"},
		{"--bench", dir, "--bench-size", "4M"},
		{"--timeout", "2"},
		{"--since", "0"},
		{"--memtest", "lots"},
		{"--lang", "fr"},
		{"--nope"},
		{"stray"},
		{"--save", "-"},
	} {
		if _, err := newTestApp("linux").parseCheck(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestFlagErrorVietnamese(t *testing.T) {
	a := newTestApp("linux")
	a.lang = "vi"
	if rc := a.main([]string{"check", "--nope", "--lang", "vi"}); rc != exitError {
		t.Fatalf("rc %d", rc)
	}
	if !strings.Contains(a.err.String(), "không có tùy chọn -nope") || !strings.Contains(a.err.String(), "diagward help check") {
		t.Fatalf("stderr: %s", a.err.String())
	}
}

func TestExitFor(t *testing.T) {
	for sev, want := range map[model.Severity]int{model.OK: 0, model.Info: 0, model.Warn: 1, model.Crit: 2, model.Severity(9): 2} {
		if got := exitFor(sev); got != want {
			t.Errorf("%v: %d", sev, got)
		}
	}
}

func TestIsDoubleClick(t *testing.T) {
	cnt := func(n uint32, err error) func() (uint32, error) { return func() (uint32, error) { return n, err } }
	cases := []struct {
		count   func() (uint32, error)
		console bool
		noPause string
		want    bool
	}{
		{cnt(1, nil), true, "", true},              // Explorer: our own console
		{cnt(2, nil), true, "", false},             // cmd.exe / PowerShell
		{cnt(3, nil), true, "", false},             // go run, Windows Terminal + shell
		{cnt(1, nil), false, "", false},            // stdin redirected
		{cnt(1, nil), true, "1", false},            // DIAGWARD_NO_PAUSE
		{cnt(0, errors.New("x")), true, "", false}, // no console
		{nil, true, "", false},
	}
	for i, c := range cases {
		if got := isDoubleClick(c.count, c.console, c.noPause); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestDispatchDoubleClick(t *testing.T) {
	a := newTestApp("windows")
	a.consoleCount = func() (uint32, error) { return 1, nil }
	a.isTerm = func(f any) bool { return f == a.stdin }
	a.stdin = strings.NewReader("\n")
	dir := t.TempDir()
	a.exeDir = func() string { return dir }
	var opened string
	a.openBrowser = func(p string) error { opened = p; return nil }
	a.runLocal = func(_ context.Context, _ collect.Options, p func(string)) (*collect.Bundle, error) {
		b := linuxBundle()
		b.OS = collect.OSWindows
		return b, nil
	}
	rc := a.main(nil)
	if rc < 0 || rc > 2 {
		t.Fatalf("rc %d, stderr %s", rc, a.err.String())
	}
	if opened == "" || filepath.Dir(opened) != dir || !strings.HasSuffix(opened, ".html") {
		t.Fatalf("opened %q", opened)
	}
	if fi, err := os.Stat(opened); err != nil || fi.Size() == 0 {
		t.Fatalf("html not written: %v", err)
	}
	if !strings.Contains(a.out.String(), "Press Enter") {
		t.Fatalf("no pause prompt:\n%s", a.out.String())
	}
}

func TestCheckFlow(t *testing.T) {
	a := newTestApp("linux")
	a.privileged = func() bool { return false }
	var gotOpts collect.Options
	a.runLocal = func(_ context.Context, o collect.Options, p func(string)) (*collect.Bundle, error) {
		gotOpts = o
		b := linuxBundle()
		for _, s := range b.Sections {
			p(s.Name)
		}
		return b, nil
	}
	dir := t.TempDir()
	html, md, js, save := filepath.Join(dir, "r.html"), filepath.Join(dir, "r.md"), filepath.Join(dir, "r.json"), filepath.Join(dir, "b.dwb")
	rc := a.main([]string{"check", "--since", "3", "--html", html, "--md", md, "--json", js, "--save", save})
	rep := diag.Analyze(linuxBundle())
	if rc != exitFor(rep.Verdict) {
		t.Fatalf("rc %d want %d; stderr %s", rc, exitFor(rep.Verdict), a.err.String())
	}
	if gotOpts.SinceDays != 3 {
		t.Fatalf("opts %+v", gotOpts)
	}
	if !strings.Contains(a.err.String(), "sudo diagward") {
		t.Fatalf("no root note on stderr: %s", a.err.String())
	}
	for _, f := range []string{html, md, js, save} {
		if fi, err := os.Stat(f); err != nil || fi.Size() == 0 {
			t.Fatalf("%s not written: %v", f, err)
		}
		if !strings.Contains(a.out.String(), f) {
			t.Fatalf("%s not listed in output:\n%s", f, a.out.String())
		}
	}
	if b, err := loadBundle(save); err != nil || b.Get("meta.done") == nil {
		t.Fatalf("saved bundle: %v", err)
	}
	var r model.Report
	data, _ := os.ReadFile(js)
	if err := json.Unmarshal(data, &r); err != nil || r.Host.Hostname == "" {
		t.Fatalf("json: %v %+v", err, r.Host)
	}
}

func TestCheckJSONToStdout(t *testing.T) {
	a := newTestApp("linux")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	a.main([]string{"check", "--json", "-"})
	var r model.Report
	if err := json.Unmarshal(a.out.Bytes(), &r); err != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%s", err, a.out.String())
	}
	if a.err.Len() == 0 {
		t.Fatal("text report should go to stderr")
	}
}

func TestCheckQuiet(t *testing.T) {
	a := newTestApp("linux")
	a.privileged = func() bool { return false }
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	a.main([]string{"check", "-q", "--lang", "vi"})
	lines := strings.Split(strings.TrimSpace(a.out.String()), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "srv01: ") || !strings.Contains(lines[0], "cảnh báo") {
		t.Fatalf("quiet output: %q", a.out.String())
	}
	if a.err.Len() != 0 {
		t.Fatalf("quiet wrote to stderr: %q", a.err.String())
	}
}

func TestQuietLine(t *testing.T) {
	rep := &model.Report{Host: model.HostInfo{Hostname: "srv01"}, Verdict: model.Crit, Findings: []model.Finding{
		{ID: "disk.x", Severity: model.Crit, Title: model.T("Disk /dev/sda is failing", "Ổ /dev/sda sắp hỏng")},
		{ID: "disk.y", Severity: model.Warn, Title: model.T("w", "w")},
	}, Coverage: []model.Coverage{{ID: "disk.smart", State: model.CovRan, Component: model.CompDisk}}}
	got := quietLine(rep, "vi", false)
	if got != "srv01: CẦN XỬ LÝ NGAY (1 lỗi nghiêm trọng, 1 cảnh báo): Ổ /dev/sda sắp hỏng" {
		t.Fatalf("%q", got)
	}
	if got := quietLine(rep, "en", false); !strings.HasPrefix(got, "srv01: ACTION NEEDED NOW (1 critical, 1 warnings): Disk /dev/sda") {
		t.Fatalf("%q", got)
	}
	_ = quietLine(&model.Report{}, "en", false)
}

func TestCheckInterrupted(t *testing.T) {
	a := newTestApp("linux")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		b := linuxBundle()
		b.Sections = b.Sections[:3]
		return b, fmt.Errorf("collection interrupted after 3 sections: %w", context.Canceled)
	}
	rc := a.main([]string{"check", "--lang", "vi"})
	if rc != exitError {
		t.Fatalf("rc %d", rc)
	}
	if !strings.Contains(a.err.String(), "Ctrl+C") || a.out.Len() == 0 {
		t.Fatalf("stderr %q stdout len %d", a.err.String(), a.out.Len())
	}
}

func TestCheckUnsupportedOS(t *testing.T) {
	a := newTestApp("darwin")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return nil, fmt.Errorf("%w (this is darwin)", collect.ErrUnsupportedOS)
	}
	if rc := a.main([]string{"--lang", "vi"}); rc != exitError {
		t.Fatalf("rc %d", rc)
	}
	if !strings.Contains(a.err.String(), "diagward bmc") || !strings.Contains(a.err.String(), "Linux và Windows") {
		t.Fatalf("%s", a.err.String())
	}
}

func TestWindowsTestFlags(t *testing.T) {
	a := newTestApp("windows")
	var got collect.Options
	a.runLocal = func(_ context.Context, o collect.Options, _ func(string)) (*collect.Bundle, error) {
		got = o
		return linuxBundle(), nil
	}
	a.main([]string{"check", "--bench", t.TempDir(), "--memtest", "1G"})
	if got.BenchDir != "" || got.Memtest != "" {
		t.Fatalf("windows should drop bench/memtest: %+v", got)
	}
	if !strings.Contains(a.err.String(), "mdsched.exe") {
		t.Fatalf("%s", a.err.String())
	}
}

func TestBenchDirMustExist(t *testing.T) {
	a := newTestApp("linux")
	if rc := a.main([]string{"check", "--bench", filepath.Join(t.TempDir(), "nope")}); rc != exitError {
		t.Fatalf("rc %d", rc)
	}
}

func TestAnalyze(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.dwb")
	if err := saveBundle(p, linuxBundle()); err != nil {
		t.Fatal(err)
	}
	a := newTestApp("darwin")
	md := filepath.Join(dir, "x.md")
	rc := a.main([]string{"analyze", p, "--md", md, "--lang", "en"})
	if rc != exitFor(diag.Analyze(linuxBundle()).Verdict) {
		t.Fatalf("rc %d: %s", rc, a.err.String())
	}
	if _, err := os.Stat(md); err != nil {
		t.Fatal(err)
	}
	// Missing, garbage and truncated files.
	os.WriteFile(filepath.Join(dir, "bad.dwb"), []byte("\x1f\x8bgarbage"), 0o600)
	data, _ := os.ReadFile(p)
	os.WriteFile(filepath.Join(dir, "trunc.dwb"), data[:len(data)/2], 0o600)
	for _, f := range []string{"missing.dwb", "bad.dwb", "trunc.dwb"} {
		a := newTestApp("linux")
		if rc := a.main([]string{"analyze", filepath.Join(dir, f)}); rc != exitError {
			t.Errorf("%s: rc %d", f, rc)
		}
	}
	if rc := newTestApp("linux").main([]string{"analyze"}); rc != exitError {
		t.Error("no file accepted")
	}
	// Unwritable output file.
	a = newTestApp("linux")
	if rc := a.main([]string{"analyze", p, "--html", filepath.Join(dir, "no", "such", "dir.html")}); rc != exitError {
		t.Errorf("unwritable html: rc %d", rc)
	}
}

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "srv.dwb")
	a := newTestApp("linux")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	if rc := a.main([]string{"collect", "-o", out, "--since", "14", "--lang", "vi"}); rc != exitOK {
		t.Fatalf("rc %d %s", rc, a.err.String())
	}
	if !strings.Contains(a.out.String(), "Đã lưu") || !strings.Contains(a.out.String(), "diagward analyze srv.dwb") {
		t.Fatalf("%s", a.out.String())
	}
	if b, err := loadBundle(out); err != nil || len(b.Sections) != 5 {
		t.Fatalf("%v", err)
	}
	// Positional .dwb works too; -o - is refused.
	a = newTestApp("linux")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	if rc := a.main([]string{"collect", filepath.Join(dir, "b.dwb"), "-q"}); rc != exitOK || !strings.HasSuffix(strings.TrimSpace(a.out.String()), "b.dwb") {
		t.Fatalf("rc %d out %q", rc, a.out.String())
	}
	if rc := newTestApp("linux").main([]string{"collect", "-o", "-"}); rc != exitError {
		t.Fatal("-o - accepted")
	}
}

func TestBMC(t *testing.T) {
	a := newTestApp("linux")
	a.env["DIAGWARD_BMC_PASSWORD"] = "s3cret"
	var got bmc.Options
	a.collectBMC = func(_ context.Context, o bmc.Options) (*collect.Bundle, error) {
		got = o
		b := testkit.Bundle(collect.OSBMC)
		b.Host = o.Host
		return b, nil
	}
	rc := a.main([]string{"bmc", "10.0.0.5", "--user", "root", "--insecure", "--protocol", "redfish", "--since", "60", "--timeout", "90", "--port", "8443"})
	if rc > exitCrit {
		t.Fatalf("rc %d: %s", rc, a.err.String())
	}
	if got.Host != "10.0.0.5" || got.User != "root" || got.Password != "s3cret" || !got.Insecure || got.Protocol != "redfish" ||
		got.SinceDays != 60 || got.Timeout != 90*time.Second || got.Port != 8443 {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(a.out.String()+a.err.String(), "s3cret") {
		t.Fatal("password printed")
	}

	// Default since/timeout are left to the bmc package.
	a = newTestApp("linux")
	a.env["DIAGWARD_BMC_PASSWORD"] = "x"
	a.env["DIAGWARD_BMC_USER"] = "ADMIN"
	a.collectBMC = func(_ context.Context, o bmc.Options) (*collect.Bundle, error) {
		got = o
		return testkit.Bundle(collect.OSBMC), nil
	}
	a.main([]string{"bmc", "bmc.example"})
	if got.SinceDays != 0 || got.Timeout != 0 || got.User != "ADMIN" || got.Protocol != "auto" {
		t.Fatalf("%+v", got)
	}

	// No password and no terminal.
	a = newTestApp("linux")
	if rc := a.main([]string{"bmc", "10.0.0.5", "--user", "root"}); rc != exitError || !strings.Contains(a.err.String(), "DIAGWARD_BMC_PASSWORD") {
		t.Fatalf("rc %d %s", rc, a.err.String())
	}
	// Interactive prompt.
	a = newTestApp("linux")
	a.isTerm = func(f any) bool { return f == a.stdin }
	a.readPassword = func() (string, error) { return "typed", nil }
	a.collectBMC = func(_ context.Context, o bmc.Options) (*collect.Bundle, error) {
		got = o
		return testkit.Bundle(collect.OSBMC), nil
	}
	a.main([]string{"bmc", "10.0.0.5", "-u", "root"})
	if got.Password != "typed" {
		t.Fatalf("%+v", got)
	}
	// Password flags are refused.
	for _, bad := range [][]string{{"bmc", "h", "--password", "x"}, {"bmc", "h", "--password=x"}, {"bmc", "-p", "x", "h"}, {"bmc", "h", "-PASS", "x"}} {
		a := newTestApp("linux")
		if rc := a.main(bad); rc != exitError || !strings.Contains(a.err.String(), "DIAGWARD_BMC_PASSWORD") {
			t.Errorf("%v: rc %d %s", bad, rc, a.err.String())
		}
	}
	for _, bad := range [][]string{{"bmc"}, {"bmc", "a", "b"}, {"bmc", "h", "--protocol", "snmp"}, {"bmc", "h", "--port", "70000"}} {
		if rc := newTestApp("linux").main(bad); rc != exitError {
			t.Errorf("%v: rc %d", bad, rc)
		}
	}
}

func TestBMCTLSHint(t *testing.T) {
	a := newTestApp("linux")
	a.env["DIAGWARD_BMC_PASSWORD"] = "x"
	a.collectBMC = func(context.Context, bmc.Options) (*collect.Bundle, error) {
		return nil, fmt.Errorf("redfish: Get \"https://10.0.0.5/redfish/v1\": %w", x509.UnknownAuthorityError{})
	}
	if rc := a.main([]string{"bmc", "10.0.0.5", "--user", "root", "--lang", "vi"}); rc != exitError {
		t.Fatalf("rc %d", rc)
	}
	if !strings.Contains(a.err.String(), "chứng chỉ tự ký") || !strings.Contains(a.err.String(), "--insecure") {
		t.Fatalf("%s", a.err.String())
	}
	a.lang = "en"
	if s := a.bmcErrorText(errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority (use --insecure)")); strings.Count(s, "--insecure") != 1 {
		t.Fatalf("english hint duplicated: %s", s)
	}
	if s := a.bmcErrorText(errors.New("connection refused")); s != "connection refused" {
		t.Fatal(s)
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, lang := range []string{"en", "vi"} {
		for _, topic := range []string{"", "check", "collect", "analyze", "bmc", "install-tools", "version", "help"} {
			a := newTestApp("linux")
			args := []string{"help"}
			if topic != "" {
				args = append(args, topic)
			}
			args = append(args, "--lang", lang)
			if rc := a.main(args); rc != exitOK {
				t.Errorf("help %s: rc %d", topic, rc)
			}
			want := "Exit codes:"
			if lang == "vi" {
				want = "Mã thoát"
			}
			out := a.out.String()
			switch topic {
			case "version", "help":
				if strings.Contains(out, want) {
					t.Errorf("help %s %s: exit codes are not relevant here", topic, lang)
				}
			default:
				if !strings.Contains(out, want) || !strings.Contains(out, "3  ") {
					t.Errorf("help %s %s: no exit codes", topic, lang)
				}
			}
			// The verdict codes (1 warnings, 2 critical) only belong to
			// commands that analyse.
			if verdict := strings.Contains(out, "\n  2  "); verdict != (topic == "" || topic == "check" || topic == "analyze" || topic == "bmc") {
				t.Errorf("help %s %s: verdict exit codes shown=%v", topic, lang, verdict)
			}
			if strings.Contains(out, "\n\n\n") {
				t.Errorf("help %s %s: double blank line", topic, lang)
			}
		}
	}
	a := newTestApp("linux")
	if rc := a.main([]string{"check", "--help"}); rc != exitOK || !strings.Contains(a.out.String(), "--bench-size") {
		t.Fatalf("check --help: %d %s", rc, a.out.String())
	}
	if rc := newTestApp("linux").main([]string{"help", "nope"}); rc != exitError {
		t.Fatal("help nope")
	}
	a = newTestApp("linux")
	if a.main([]string{"version"}) != exitOK || !strings.HasPrefix(a.out.String(), "diagward ") {
		t.Fatal(a.out.String())
	}
	a = newTestApp("linux")
	if rc := a.main([]string{"frobnicate"}); rc != exitError || !strings.Contains(a.err.String(), "frobnicate") {
		t.Fatal(rc)
	}
}

func TestUseColor(t *testing.T) {
	a := newTestApp("linux")
	a.isTerm = func(any) bool { return true }
	if !a.useColor(a.stdout, false) {
		t.Fatal("terminal should get colour")
	}
	if a.useColor(a.stdout, true) {
		t.Fatal("--no-color")
	}
	a.env["NO_COLOR"] = "1"
	if a.useColor(a.stdout, false) {
		t.Fatal("NO_COLOR")
	}
	delete(a.env, "NO_COLOR")
	a.con.vt = false
	if a.useColor(a.stdout, false) {
		t.Fatal("no VT")
	}
}

func TestUnixConsole(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		utf8 bool
	}{
		{map[string]string{}, true},
		{map[string]string{"LANG": "en_US.UTF-8"}, true},
		{map[string]string{"LANG": "C.utf8"}, true},
		{map[string]string{"LANG": "C"}, false},
		{map[string]string{"LC_ALL": "POSIX", "LANG": "en_US.UTF-8"}, false},
		{map[string]string{"LANG": "en_US.UTF-8", "TERM": "linux"}, false},
	} {
		if got := unixConsole(func(k string) string { return c.env[k] }); got.utf8 != c.utf8 {
			t.Errorf("%v: %+v", c.env, got)
		}
	}
}

func TestLabelsAndHelpers(t *testing.T) {
	if l := sectionLabel("disk.smart:/dev/sda"); l.VI == "" || !strings.Contains(l.EN, "S.M.A.R.T.") {
		t.Error(l)
	}
	for _, n := range []string{"meta.ident", "system.dmi", "cpu.lscpu", "memory.edac", "raid.mdstat", "sensors.hwmon", "ipmi.sdr", "network.ip", "filesystem.df", "logs.kernel", "weird", "", "memory.memtest", "disk.bench", "disk.smart_scan"} {
		if l := sectionLabel(n); l.EN == "" || l.VI == "" {
			t.Errorf("%q: %+v", n, l)
		}
	}
	if got := asciiFold("Đang kiểm tra ổ cứng · 3 mục…"); got != "Dang kiem tra o cung - 3 muc." {
		t.Error(got)
	}
	if got := defaultName("srv 01/../x", time.Date(2026, 10, 2, 9, 5, 0, 0, time.UTC), ".dwb"); got != "diagward-srv_01_.._x-20261002-0905.dwb" {
		t.Error(got)
	}
	if got := defaultName("", time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC), ".html"); got != "diagward-host-20260102-0304.html" {
		t.Error(got)
	}
	if !isYes("có") || !isYes("Y") || isYes("") || isYes("n") || isYes("không") {
		t.Error("isYes")
	}
	if quoteArg("a b.dwb") != `"a b.dwb"` || quoteArg("ab.dwb") != "ab.dwb" {
		t.Error("quoteArg")
	}
	if truncRunes("Ổ cứng Ổ cứng Ổ cứng", 10) != "Ổ cứng Ổ …" {
		t.Error(truncRunes("Ổ cứng Ổ cứng Ổ cứng", 10))
	}
}

func TestSpinnerSilentWhenNotTerminal(t *testing.T) {
	a := newTestApp("linux")
	sp := a.newSpinner(a.stderr, false)
	sp.Start(model.T("x", "x"))
	sp.Section("disk.lsblk")
	sp.Stop()
	if a.err.Len() != 0 {
		t.Fatalf("spinner wrote %q", a.err.String())
	}
	// On a terminal it draws and erases.
	a.isTerm = func(any) bool { return true }
	sp = a.newSpinner(a.stderr, false)
	sp.Start(model.T("Starting", "Đang khởi động"))
	sp.Section("disk.lsblk")
	time.Sleep(300 * time.Millisecond)
	sp.Stop()
	if s := a.err.String(); !strings.Contains(s, "Checking disks") || !strings.HasSuffix(s, "\r\x1b[K") {
		t.Fatalf("spinner output %q", s)
	}
}

// TestPlatformProbes calls the real console/locale/privilege probes; they
// must not fail or panic whatever the environment (no console under CI).
func TestPlatformProbes(t *testing.T) {
	n, err := consoleProcessCount()
	t.Logf("console processes=%d err=%v locale=%q privileged=%v width=%d term=%v",
		n, err, userLocale(), isPrivileged(), terminalWidth(os.Stdout), isTerminal(os.Stdout))
	if n == 1 && err == nil {
		t.Log("only this process on the console")
	}
	st, restore := setupConsole()
	restore()
	t.Logf("console state %+v", st)
}

func TestSpinnerOptionLabels(t *testing.T) {
	a := newTestApp("linux")
	sp := a.newSpinner(a.stderr, false)
	sp.memtest = true
	sp.Section("memory.edac")
	if !strings.Contains(sp.label.EN, "memtester") {
		t.Fatal(sp.label)
	}
	sp.bench = true
	sp.Section("disk.lsblk")
	if !strings.Contains(sp.label.VI, "đo tốc độ") {
		t.Fatal(sp.label)
	}
	sp.Section("raid.mdstat")
	if sp.label.EN != "Checking RAID" || sp.count != 3 {
		t.Fatal(sp.label, sp.count)
	}
}
