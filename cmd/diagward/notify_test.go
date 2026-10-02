package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/notify"
	"github.com/nguyenquocanhz/diagward/model"
)

// hook is a webhook receiver for the CLI tests.
type hook struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    []notify.Payload
	status int
}

func newHook(t *testing.T) *hook {
	h := &hook{status: 200}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var p notify.Payload
		_ = json.Unmarshal(b, &p)
		h.mu.Lock()
		h.got = append(h.got, p)
		st := h.status
		h.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) payloads() []notify.Payload {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]notify.Payload(nil), h.got...)
}

// writeConfig writes a notify config readable only by its owner (on
// Windows the mode is not checked).
func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "notify.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// notifyTestApp runs "check" on linuxBundle with this OS's file-mode rules.
func notifyTestApp() *testApp {
	ta := newTestApp(runtime.GOOS)
	ta.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	ta.notifyOpts = notify.Options{Attempts: 2, Backoff: time.Millisecond}
	ta.hostname = func() (string, error) { return "srv01", nil }
	return ta
}

func TestCheckNotifyFlow(t *testing.T) {
	dir := t.TempDir()
	h := newHook(t)
	cfg := writeConfig(t, dir, "[webhook]\nurl="+h.srv.URL+"/hook/secretPathToken123\n")
	state := filepath.Join(dir, "state", "state.json")

	plain := notifyTestApp()
	want := plain.main([]string{"check", "-q"})

	// First run, no problem: nothing sent, state saved.
	ta := notifyTestApp()
	if code := ta.main([]string{"check", "--notify-config", cfg, "--state", state}); code != want {
		t.Fatalf("exit %d want %d\n%s", code, want, ta.err)
	}
	if len(h.payloads()) != 0 {
		t.Errorf("sent on a healthy first run: %+v", h.payloads())
	}
	if !strings.Contains(ta.err.String(), "first run") {
		t.Errorf("stderr: %s", ta.err)
	}
	st, err := notify.LoadState(state)
	if err != nil || st == nil || st.Host != "srv01" {
		t.Fatalf("state %+v %v", st, err)
	}

	// Second run, unchanged: nothing sent.
	ta = notifyTestApp()
	ta.main([]string{"check", "--notify-config", cfg, "--state", state})
	if len(h.payloads()) != 0 || !strings.Contains(ta.err.String(), "nothing changed") {
		t.Errorf("unchanged run: %s", ta.err)
	}

	// --notify-always sends a status message; the config comes from the
	// environment this time.
	ta = notifyTestApp()
	ta.env["DIAGWARD_NOTIFY_CONFIG"] = cfg
	if code := ta.main([]string{"check", "--notify-always", "--state", state, "--lang", "vi"}); code != want {
		t.Fatalf("exit %d", code)
	}
	p := h.payloads()
	if len(p) != 1 || p[0].Event != notify.EventStatus || p[0].Host != "srv01" || p[0].Lang != "vi" {
		t.Fatalf("payloads %+v", p)
	}
	if !strings.Contains(ta.err.String(), "Đã gửi thông báo tới 1/1 kênh") {
		t.Errorf("stderr: %s", ta.err)
	}

	// The receiver fails: a warning, the same exit code, no secret.
	h.mu.Lock()
	h.status = 500
	h.mu.Unlock()
	before, _ := os.ReadFile(state)
	ta = notifyTestApp()
	if code := ta.main([]string{"check", "-q", "--notify-config", cfg, "--state", state, "--notify-always"}); code != want {
		t.Fatalf("notification failure changed the exit code: %d want %d", code, want)
	}
	if !strings.Contains(ta.err.String(), "Warning: notification not sent: webhook: HTTP 500") || strings.Contains(ta.err.String(), "secretPathToken123") {
		t.Errorf("stderr: %s", ta.err)
	}
	if after, _ := os.ReadFile(state); string(after) != string(before) {
		t.Error("state updated although nothing was delivered")
	}
}

func TestNotifyAfterCheckChanges(t *testing.T) {
	dir := t.TempDir()
	h := newHook(t)
	cfg := writeConfig(t, dir, "lang = vi\n[webhook]\nurl="+h.srv.URL+"/hook\n")
	state := filepath.Join(dir, "state.json")
	ta := notifyTestApp()
	s, ok := ta.loadNotify(notifyOpts{config: cfg, state: state}, ta.err)
	if !ok || s.lang != "vi" { // the config's lang beats the environment
		t.Fatalf("load: %v %+v\n%s", ok, s, ta.err)
	}
	pend := model.Finding{ID: "disk.smart_pending", Target: "/dev/sda", Component: model.CompDisk, Severity: model.Crit,
		Title: model.T("Disk /dev/sda is failing", "Ổ /dev/sda sắp hỏng"), Action: model.T("Back up now", "Sao lưu ngay")}
	report := func(fs ...model.Finding) *model.Report {
		r := &model.Report{Host: model.HostInfo{Hostname: "srv01"}}
		for _, c := range model.Components {
			r.Summary = append(r.Summary, model.ComponentSummary{Component: c, Checked: true})
		}
		for _, f := range fs {
			r.Findings = append(r.Findings, f)
			r.Verdict = model.Worst(r.Verdict, f.Severity)
		}
		return r
	}
	ta.notifyAfterCheck(s, report(pend), false, false, ta.err)
	ta.notifyAfterCheck(s, report(pend), false, false, ta.err)
	ta.notifyAfterCheck(s, report(), false, false, ta.err)
	p := h.payloads()
	if len(p) != 2 || p[0].Event != notify.EventProblem || p[0].New[0].Title != "Ổ /dev/sda sắp hỏng" ||
		p[1].Event != notify.EventRecovery || len(p[1].Resolved) != 1 {
		t.Fatalf("payloads %+v\n%s", p, ta.err)
	}

	// --lang beats the config.
	ta = notifyTestApp()
	ta.main([]string{"version", "--lang", "en"})
	if s, _ := ta.loadNotify(notifyOpts{config: cfg}, ta.err); s.lang != "en" {
		t.Errorf("explicit --lang lost: %s", s.lang)
	}
}

func TestNotifyUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"check", "--state", "x.json"},
		{"check", "--notify-always"},
		{"check", "--force"},
		{"check", "--notify-config", "-q"},
		{"notify-test"},
		{"notify-test", "extra", "--notify-config", "x"},
	} {
		ta := notifyTestApp()
		called := false
		ta.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
			called = true
			return linuxBundle(), nil
		}
		if code := ta.main(args); code != exitError || called {
			t.Errorf("%v: exit %d, collected=%v\n%s", args, code, called, ta.err)
		}
		if !strings.Contains(ta.err.String(), "diagward help") {
			t.Errorf("%v: %s", args, ta.err)
		}
	}
	// A missing config fails before the collection.
	ta := notifyTestApp()
	called := false
	ta.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		called = true
		return linuxBundle(), nil
	}
	if code := ta.main([]string{"check", "--notify-config", filepath.Join(t.TempDir(), "none.conf"), "--lang", "vi"}); code != exitError || called {
		t.Errorf("missing config: %d %v", code, called)
	}
	if !strings.Contains(ta.err.String(), "cấu hình thông báo: không có tệp") {
		t.Errorf("stderr: %s", ta.err)
	}
}

func TestNotifyConfigPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notify.conf")
	if err := os.WriteFile(p, []byte("[slack]\nurl=https://hooks.slack.com/services/T0/B0/permSecretToken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(p, 0o644)
	}
	// Unix rules: 0644 (and every file on Windows, reported as 0666) is refused.
	ta := newTestApp("linux")
	called := false
	ta.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		called = true
		return linuxBundle(), nil
	}
	if code := ta.main([]string{"check", "--notify-config", p}); code != exitError || called {
		t.Fatalf("insecure config accepted: %d", code)
	}
	if !strings.Contains(ta.err.String(), "chmod 600") || strings.Contains(ta.err.String(), "permSecretToken") {
		t.Errorf("stderr: %s", ta.err)
	}
	// --force accepts it with a warning (the run then fails to send to the
	// unreachable Slack URL only if a change happens; here none does).
	ta = newTestApp("linux")
	ta.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	ta.main([]string{"check", "--notify-config", p, "--force", "--state", filepath.Join(dir, "s.json")})
	if !strings.Contains(ta.err.String(), "Warning:") || !strings.Contains(ta.err.String(), "chmod 600") {
		t.Errorf("force: %s", ta.err)
	}
}

func TestNotifyTestCommand(t *testing.T) {
	dir := t.TempDir()
	h := newHook(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer bad.Close()
	ok := writeConfig(t, dir, "[webhook]\nurl="+h.srv.URL+"/hook\n")
	ta := notifyTestApp()
	if code := ta.main([]string{"notify-test", "--notify-config", ok, "--lang", "vi"}); code != exitOK {
		t.Fatalf("exit %d\n%s%s", code, ta.out, ta.err)
	}
	if !strings.Contains(ta.out.String(), "Tin nhắn thử từ srv01") || !strings.Contains(ta.out.String(), "✓ webhook: đã gửi") {
		t.Errorf("stdout: %s", ta.out)
	}
	if p := h.payloads(); len(p) != 1 || p[0].Event != notify.EventTest || p[0].Host != "srv01" {
		t.Errorf("payload %+v", p)
	}

	mixed := filepath.Join(dir, "mixed.conf")
	if err := os.WriteFile(mixed, []byte("[webhook ok]\nurl="+h.srv.URL+"/hook\n[slack]\nurl="+bad.URL+"/services/T0/B0/slackSecretToken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ta = notifyTestApp()
	if code := ta.main([]string{"notify-test", "--notify-config", mixed}); code != exitError {
		t.Errorf("exit %d", code)
	}
	out := ta.out.String()
	if !strings.Contains(out, "✓ webhook ok: sent") || !strings.Contains(out, "✗ slack: HTTP 404") || strings.Contains(out, "slackSecretToken") {
		t.Errorf("stdout: %s", out)
	}
}
