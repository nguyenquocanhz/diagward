package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
)

// English words that must not appear in a Vietnamese usage error.
var englishLeftover = regexp.MustCompile(`(?:^|[\s:(])(use|needs|unexpected|argument|invalid|flag|for|value|seconds|language|size|which)\b`)

func TestVietnameseUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"check", "--since", "abc"},
		{"check", "--since", "0"},
		{"check", "--bench-size", "1G"},
		{"check", "--bench", dir, "--bench-size", "4M"},
		{"check", "--memtest", "5T"},
		{"check", "--memtest", "lots"},
		{"check", "--timeout", "2"},
		{"check", "--timeout", "abc"},
		{"check", "extra"},
		{"check", "--json", "-", "--md", "-"},
		{"check", "--save", "-"},
		{"check", "--html", "-v"},
		{"check", "--html", filepath.Join(dir, "nope", "r.html")},
		{"collect", "-o", "-"},
		{"collect", "-o", filepath.Join(dir, "nope", "x.dwb")},
		{"collect", "--timeout", "1"},
		{"analyze"},
		{"analyze", "a.dwb", "b.dwb"},
		{"bmc"},
		{"bmc", "h", "--protocol", "x"},
		{"bmc", "h", "--port", "70000"},
		{"bmc", "h", "--timeout", "1"},
		{"bmc", "a b"},
		{"install-tools", "extra"},
	} {
		a := newTestApp("linux")
		called := false
		a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
			called = true
			return linuxBundle(), nil
		}
		rc := a.main(append(args, "--lang", "vi"))
		if rc != exitError {
			t.Errorf("%v: rc %d", args, rc)
		}
		if called {
			t.Errorf("%v: collected despite the usage error", args)
		}
		first := strings.SplitN(a.err.String(), "\n", 2)[0]
		if m := englishLeftover.FindString(first); m != "" {
			t.Errorf("%v: English %q in Vietnamese error: %s", args, m, first)
		}
		// The English text stays English.
		a = newTestApp("linux")
		a.main(append(args, "--lang", "en"))
		if strings.ContainsAny(strings.SplitN(a.err.String(), "\n", 2)[0], "ạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹđ") {
			t.Errorf("%v: Vietnamese in English error: %s", args, a.err.String())
		}
	}
}

// "--html -v" used to write the HTML report to a file called "-v".
func TestFileFlagWithoutName(t *testing.T) {
	for _, args := range [][]string{{"--html", "-v"}, {"--md", "--ascii"}, {"--json", "-q"}, {"--save", "--json"}} {
		if _, err := newTestApp("linux").parseCheck(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if _, err := newTestApp("linux").parseCheck([]string{"--json", "-"}); err != nil {
		t.Errorf("--json - refused: %v", err)
	}
}

func TestNoHintsWhenFilesWritten(t *testing.T) {
	const hint = "add --html"
	run := func(args ...string) string {
		a := newTestApp("linux")
		a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
			return linuxBundle(), nil
		}
		a.main(append([]string{"check", "--lang", "en"}, args...))
		return a.out.String() + a.err.String()
	}
	if out := run(); !strings.Contains(out, hint) {
		t.Fatalf("plain run lost the hints:\n%s", out)
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"--html", filepath.Join(dir, "r.html")},
		{"--save", filepath.Join(dir, "b.dwb")},
		{"--json", "-"},
	} {
		if out := run(args...); strings.Contains(out, hint) {
			t.Errorf("%v: footer hints shown although files were written", args)
		}
	}
}

func TestIncompleteBundle(t *testing.T) {
	b := linuxBundle()
	b.Sections = b.Sections[:3] // no meta.done
	dir := t.TempDir()
	p := filepath.Join(dir, "part.dwb")
	if err := saveBundle(p, b); err != nil {
		t.Fatal(err)
	}
	a := newTestApp("linux")
	if rc := a.main([]string{"analyze", p, "-q", "--lang", "vi"}); rc != exitError {
		t.Fatalf("incomplete bundle: rc %d", rc)
	}
	if !strings.Contains(a.out.String(), "chưa đầy đủ") {
		t.Fatalf("quiet line hides the incomplete collection: %q", a.out.String())
	}
	// collect after Ctrl+C says the file is incomplete.
	a = newTestApp("linux")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return b, fmt.Errorf("collection interrupted after 3 sections: %w", context.Canceled)
	}
	if rc := a.main([]string{"collect", "-o", filepath.Join(dir, "c.dwb"), "--lang", "en"}); rc != exitError {
		t.Fatalf("rc %d", rc)
	}
	if !strings.Contains(a.out.String(), "incomplete") {
		t.Fatalf("collect output: %s", a.out.String())
	}
}

func TestCollectSaveFallsBackToTemp(t *testing.T) {
	dir := t.TempDir()
	// A directory where the bundle file should be makes the save fail.
	target := filepath.Join(dir, "x.dwb")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	a := newTestApp("linux")
	a.runLocal = func(context.Context, collect.Options, func(string)) (*collect.Bundle, error) {
		return linuxBundle(), nil
	}
	rc := a.main([]string{"collect", "-o", target, "-q"})
	saved := strings.TrimSpace(a.out.String())
	if rc != exitError || !strings.HasPrefix(saved, os.TempDir()) {
		t.Fatalf("rc %d saved %q stderr %s", rc, saved, a.err.String())
	}
	defer os.Remove(saved)
	if b, err := loadBundle(saved); err != nil || b.Get("meta.done") == nil {
		t.Fatalf("fallback bundle: %v", err)
	}
}

func TestDetectLangPrecedence(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"LC_ALL": "C", "LANG": "vi_VN.UTF-8"}, "en"},
		{map[string]string{"LC_ALL": "en_US.UTF-8", "LANG": "vi_VN.UTF-8"}, "en"},
		{map[string]string{"LC_MESSAGES": "vi_VN.UTF-8", "LANG": "en_US.UTF-8"}, "vi"},
		{map[string]string{"LANG": "vi_VN.UTF-8"}, "vi"},
	} {
		if got := detectLang(func(k string) string { return c.env[k] }, nil); got != c.want {
			t.Errorf("%v: %s, want %s", c.env, got, c.want)
		}
	}
}
