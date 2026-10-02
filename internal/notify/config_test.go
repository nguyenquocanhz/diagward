package notify

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

const fullConfig = `# Diagward notifications
lang = vi
top = 3
min_severity = warn
timeout = 10

[telegram]
token = 123456789:AAHsecretTelegramToken_xyz
chat_id = -1001234567890
thread_id = 42

[telegram personal]
token = "987654321:BBsecondTokenValue"
chat_id = @mychannel

[zalo]
token = 1234567890:zaloSecretToken
chat_id = abcdef0123456789

[slack]
url = https://hooks.slack.com/services/T000/B000/slackSecretPath

[discord]
url = https://discord.com/api/webhooks/123/discordSecretPath
username = Server Bot

[webhook]
url = https://monitor.example.com/hook?key=webhookQuerySecret
header = Authorization: Bearer headerSecretValue
header = X-Team: ops
secret = hmacSecretValue
include_report = true

[email]
host = smtp.example.com
port = 587
user = alerts@example.com
password = mailPasswordSecret
from = Diagward <alerts@example.com>
to = ops@example.com, "Trực ca" <oncall@example.com>
`

func TestParseFull(t *testing.T) {
	c, err := Parse(strings.NewReader(fullConfig), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if c.Lang != "vi" || c.Top != 3 || c.MinSev != model.Warn || c.Timeout != 10*time.Second {
		t.Errorf("globals: %+v", c)
	}
	var names []string
	for _, ch := range c.Channels {
		names = append(names, ch.Name())
	}
	want := "telegram,telegram personal,zalo,slack,discord,webhook,email"
	if strings.Join(names, ",") != want {
		t.Errorf("channels %v", names)
	}
	tg := c.Channels[0].(*telegram)
	if tg.thread != 42 || tg.api != "https://api.telegram.org" || tg.chat != "-1001234567890" {
		t.Errorf("telegram %+v", tg)
	}
	if c.Channels[1].(*telegram).token != "987654321:BBsecondTokenValue" {
		t.Error("quoted value not unquoted")
	}
	if z := c.Channels[2].(*zalo); z.api != "https://bot-api.zaloplatforms.com" {
		t.Errorf("zalo api %q", z.api)
	}
	w := c.Channels[5].(*webhook)
	if len(w.headers) != 2 || w.headers[0] != [2]string{"Authorization", "Bearer headerSecretValue"} || !w.report || w.secret != "hmacSecretValue" {
		t.Errorf("webhook %+v", w)
	}
	e := c.Channels[6].(*email)
	if e.mode != "starttls" || e.port != 587 || len(e.to) != 2 || e.to[1].Name != "Trực ca" {
		t.Errorf("email %+v", e)
	}
	// Every secret is redacted, including the parts of URLs and headers.
	for _, s := range []string{"AAHsecretTelegramToken_xyz", "slackSecretPath", "discordSecretPath", "webhookQuerySecret",
		"headerSecretValue", "hmacSecretValue", "mailPasswordSecret", "zaloSecretToken", "BBsecondTokenValue"} {
		if got := c.Redact("error near " + s + " here"); strings.Contains(got, s) {
			t.Errorf("not redacted: %s", got)
		}
	}
	if got := c.Redact("ops@example.com"); got != "ops@example.com" {
		t.Errorf("non-secret redacted: %s", got)
	}
}

func TestParseDefaults(t *testing.T) {
	c, err := Parse(strings.NewReader(string(rune(0xFEFF))+"[slack]\nurl=https://hooks.slack.com/services/x/y/z\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Lang != "" || c.Top != 5 || c.MinSev != model.Warn || c.Timeout != 15*time.Second {
		t.Errorf("defaults %+v", c)
	}
	c, err = Parse(strings.NewReader("min_severity = crit\n[email]\nhost=127.0.0.1\ntls=none\nfrom=a@b.c\nto=d@e.f\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.MinSev != model.Crit {
		t.Error("min_severity crit")
	}
	if e := c.Channels[0].(*email); e.port != 25 || e.mode != "none" {
		t.Errorf("email %+v", e)
	}
	c, err = Parse(strings.NewReader("[email]\nhost=smtp.example.com\ntls=tls\nfrom=a@b.c\nto=d@e.f\n"), nil)
	if err != nil || c.Channels[0].(*email).port != 465 {
		t.Errorf("implicit tls: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, c := range []struct {
		name, cfg, want string
		line            int
	}{
		{"empty", "# nothing\n", "no channel", 0},
		{"unknown section", "[pager]\n", "unknown channel", 1},
		{"bad header", "[telegram\n", "bad section header", 1},
		{"no equals", "[slack]\nurl https://x\n", "key = value", 2},
		{"unknown key", "[slack]\ntoken = abc\n", `unknown key "token" in [slack]`, 2},
		{"global key", "url = https://x\n[slack]\n", "top of the file", 1},
		{"dup key", "[slack]\nurl=https://a.b/c\nurl=https://a.b/d\n", "set twice", 3},
		{"dup section", "[slack]\nurl=https://a.b/c\n[slack]\nurl=https://a.b/d\n", "give each one a name", 3},
		{"missing chat", "[telegram]\ntoken=123:abcdefgh\n", "needs chat_id", 1},
		{"bad token", "[telegram]\ntoken=123/../abc\nchat_id=1\n", "not a bot token", 2},
		{"http remote", "[slack]\nurl=http://hooks.slack.com/services/SECRETPATH\n", "https://", 2},
		{"bad url", "[discord]\nurl=::not a url\n", "not a valid URL", 2},
		{"user in url", "[webhook]\nurl=https://user:SECRETPW@x.example/\n", "not a valid URL", 2},
		{"tls none remote", "[email]\nhost=smtp.gmail.com\ntls=none\nfrom=a@b.c\nto=d@e.f\n", "only allowed", 3},
		{"user without password", "[email]\nhost=smtp.gmail.com\nuser=me\nfrom=a@b.c\nto=d@e.f\n", "go together", 1},
		{"bad to", "[email]\nhost=h\nfrom=a@b.c\nto=not an address\n", "addresses", 4},
		{"bad top", "top = 0\n[slack]\nurl=https://a.b/c\n", "1 to 50", 1},
		{"bad lang", "lang = fr\n[slack]\nurl=https://a.b/c\n", "vi or en", 1},
		{"bad header line", "[webhook]\nurl=https://a.b/c\nheader = NoColonSECRET\n", "Name: value", 1},
		{"bad bool", "[webhook]\nurl=https://a.b/c\ninclude_report = maybe\n", "true or false", 3},
		{"bad thread", "[telegram]\ntoken=123:abcdefgh\nchat_id=1\nthread_id=x\n", "positive number", 4},
		{"env missing", "[slack]\nurl=env:DW_TEST_UNSET\n", "DW_TEST_UNSET is not set", 2},
		{"file missing", "[slack]\nurl=file:/nonexistent/dw-secret\n", "cannot read /nonexistent/dw-secret", 2},
	} {
		_, err := Parse(strings.NewReader(c.cfg), func(string) string { return "" })
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		var ce *ConfigError
		if !errors.As(err, &ce) {
			t.Errorf("%s: %T", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || ce.Line != c.line {
			t.Errorf("%s: %q (line %d), want %q line %d", c.name, err, ce.Line, c.want, c.line)
		}
		if ce.VI == "" || ce.VI == ce.EN {
			t.Errorf("%s: no Vietnamese text: %q", c.name, ce.VI)
		}
		// Errors never quote secret values.
		for _, s := range []string{"SECRETPATH", "SECRETPW", "NoColonSECRET"} {
			if strings.Contains(err.Error(), s) || strings.Contains(ce.In("vi"), s) {
				t.Errorf("%s: error leaks a value: %q", c.name, err)
			}
		}
	}
}

func TestParseEnvAndFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("555:fileTokenValue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "[telegram]\ntoken = file:" + p + "\nchat_id = env:DW_CHAT\n[slack]\nurl = env:DW_SLACK\n"
	env := map[string]string{"DW_CHAT": "-100", "DW_SLACK": "https://hooks.slack.com/services/envSecret"}
	c, err := Parse(strings.NewReader(cfg), func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	tg := c.Channels[0].(*telegram)
	if tg.token != "555:fileTokenValue" || tg.chat != "-100" {
		t.Errorf("%+v", tg)
	}
	if strings.Contains(c.Redact("x 555:fileTokenValue https://hooks.slack.com/services/envSecret"), "Secret") ||
		strings.Contains(c.Redact("555:fileTokenValue"), "fileToken") {
		t.Error("resolved secrets not redacted")
	}
}

func TestInsecureMode(t *testing.T) {
	for _, c := range []struct {
		mode os.FileMode
		goos string
		want bool
	}{
		{0o600, "linux", false},
		{0o400, "linux", false},
		{0o640, "linux", true},
		{0o644, "linux", true},
		{0o604, "freebsd", true},
		{0o666, "windows", false},
	} {
		if got := insecureMode(c.mode, c.goos); got != c.want {
			t.Errorf("%o %s: %v", c.mode, c.goos, got)
		}
	}
}

func TestLoadPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notify.conf")
	if err := os.WriteFile(p, []byte("[slack]\nurl=https://hooks.slack.com/services/a/b/permSecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 0644 on Unix (and 0666 as Go reports any Windows file) is refused
	// when the rules of a Unix system apply.
	_, _, err := Load(p, LoadOptions{GOOS: "linux"})
	if !errors.Is(err, ErrInsecureMode) {
		t.Fatalf("want ErrInsecureMode, got %v", err)
	}
	if !strings.Contains(err.Error(), "chmod 600") || !strings.Contains(Text(err, "vi"), "chmod 600") || strings.Contains(err.Error(), "permSecret") {
		t.Errorf("message: %v / %s", err, Text(err, "vi"))
	}
	c, warns, err := Load(p, LoadOptions{GOOS: "linux", Force: true})
	if err != nil || c == nil || len(warns) != 1 || !strings.Contains(warns[0].VI, "chmod 600") {
		t.Errorf("force: %v %v", err, warns)
	}
	if _, warns, err := Load(p, LoadOptions{GOOS: "windows"}); err != nil || len(warns) != 0 {
		t.Errorf("windows: %v %v", err, warns)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, warns, err := Load(p, LoadOptions{GOOS: runtime.GOOS}); err != nil || len(warns) != 0 {
			t.Errorf("0600: %v %v", err, warns)
		}
	}
	if _, _, err := Load(filepath.Join(dir, "missing.conf"), LoadOptions{GOOS: "linux"}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing: %v", err)
	}
	if _, _, err := Load(dir, LoadOptions{GOOS: "linux"}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("dir: %v", err)
	}
}
