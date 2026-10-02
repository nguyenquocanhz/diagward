package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// A failing disk found by a root run must stay open through every later
// run without root, not only the first one: the second non-root run used
// to compare its gaps with the first non-root run's (identical), and sent a
// false "resolved" message.
func TestDiffCarriedStaysCarried(t *testing.T) {
	_, s1 := Diff(rep([]model.Finding{diskPending}, nil), nil, DiffOptions{})
	nonRoot := func() *model.Report { return rep(nil, []model.Coverage{smartGap}) }
	m, s2 := Diff(nonRoot(), s1, DiffOptions{})
	if m.Changed() {
		t.Fatalf("run 2 resolved: %+v", m.Resolved)
	}
	m, s3 := Diff(nonRoot(), s2, DiffOptions{})
	if m.Changed() || len(m.Resolved) != 0 {
		t.Fatalf("run 3 (still no S.M.A.R.T.) resolved the disk: %s", keys(m.Resolved))
	}
	m, s4 := Diff(nonRoot(), s3, DiffOptions{})
	if m.Changed() {
		t.Fatalf("run 4 resolved: %s", keys(m.Resolved))
	}
	// A root run that reads S.M.A.R.T. again and sees no problem resolves it.
	m, _ = Diff(rep(nil, nil), s4, DiffOptions{})
	if keys(m.Resolved) != "disk.smart_pending@/dev/sda" {
		t.Fatalf("root run did not resolve: %s", keys(m.Resolved))
	}
	// A root run that sees it again does not call it new.
	m, _ = Diff(rep([]model.Finding{diskPending}, nil), s4, DiffOptions{})
	if m.Changed() {
		t.Fatalf("seen again after carry: new %s", keys(m.New))
	}
}

// An interrupted run carries everything; the next complete run without
// root must still not resolve the disk found by root.
func TestDiffCarriedThroughIncomplete(t *testing.T) {
	_, s1 := Diff(rep([]model.Finding{diskPending}, nil), nil, DiffOptions{})
	_, s2 := Diff(rep(nil, []model.Coverage{smartGap, ipmiGap}), s1, DiffOptions{Incomplete: true})
	m, _ := Diff(rep(nil, []model.Coverage{smartGap}), s2, DiffOptions{})
	if m.Changed() {
		t.Fatalf("resolved after an interrupted run: %s", keys(m.Resolved))
	}
}

// The config example in docs/notify.md must parse as written.
func TestDocsConfigExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "notify.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	i := strings.Index(doc, "```ini\n# /etc/diagward/notify.conf")
	if i < 0 {
		t.Fatal("example not found")
	}
	ex := doc[i+len("```ini\n"):]
	ex = ex[:strings.Index(ex, "```")]
	env := func(string) string { return "" }
	c, err := Parse(strings.NewReader(ex), env)
	if err != nil {
		t.Fatalf("docs example: %v", err)
	}
	if c.Top != 5 || c.Lang != "vi" || len(c.Channels) != 6 {
		t.Errorf("parsed %+v", c)
	}
}

// Slack and Discord bold markers must wrap the test message's first line
// as one span: "*Diagward: test message from *" (a space before the
// closing marker) is shown with literal asterisks in Slack.
func TestRenderTestMessageBold(t *testing.T) {
	m := TestMessage("srv01", "en", "0.1.0", time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	for name, c := range map[string]struct {
		d    dialect
		want string
	}{
		"slack":    {slackDialect, "*Diagward: test message from srv01*\n"},
		"discord":  {discordDialect, `**Diagward\: test message from srv01**` + "\n"},
		"telegram": {telegramDialect, "<b>Diagward: test message from srv01</b>\n"},
	} {
		if s := render(m, c.d); !strings.HasPrefix(s, c.want) {
			t.Errorf("%s: %q", name, s)
		}
	}
}
