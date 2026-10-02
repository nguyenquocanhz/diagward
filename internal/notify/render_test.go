package notify

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/model"
)

func bigMessage(lang string, n int) *Message {
	var fs []model.Finding
	for i := range n {
		f := fnd(fmt.Sprintf("disk.smart_pending_%d", i), fmt.Sprintf("/dev/sd%d", i), model.CompDisk, model.Crit,
			fmt.Sprintf("Disk /dev/sd%d <failing> & *bold* _x_ @everyone", i))
		f.Action = model.T(strings.Repeat("Back up the data now and replace the disk. ", 20), strings.Repeat("Sao lưu dữ liệu ngay rồi thay ổ. ", 20))
		fs = append(fs, f)
	}
	m, _ := Diff(rep(fs, nil), nil, DiffOptions{Lang: lang, Top: 50, Version: "0.1.0"})
	return m
}

func TestRenderTelegramEscapingAndLimit(t *testing.T) {
	m := bigMessage("vi", 3)
	s := render(m, telegramDialect)
	if !strings.Contains(s, "&lt;failing&gt; &amp;") || strings.Contains(s, "<failing>") {
		t.Errorf("not escaped:\n%s", s)
	}
	if strings.Count(s, "<b>") != strings.Count(s, "</b>") || strings.Count(s, "<b>") < 2 {
		t.Errorf("unbalanced tags:\n%s", s)
	}
	for _, want := range []string{"srv01", "CẦN XỬ LÝ NGAY", "Dell Inc. PowerEdge R740 · serial 8XK2LM2", "Vấn đề mới (3):", "Nghiêm trọng", "→ Sao lưu", "Diagward 0.1.0"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	// Long actions are clipped.
	if !strings.Contains(s, "…") {
		t.Error("action not clipped")
	}

	m = bigMessage("vi", 200)
	s = render(m, telegramDialect)
	if n := utf8.RuneCountInString(s); n > 4000 {
		t.Errorf("telegram message %d characters", n)
	}
	if !strings.Contains(s, "… và ") || strings.Count(s, "<b>") != strings.Count(s, "</b>") {
		t.Errorf("no 'and N more' or broken tags:\n%s", s)
	}
	if !strings.HasSuffix(s, m.Collected.Format("2006-01-02 15:04 -07:00")) {
		t.Error("footer cut")
	}
}

func TestRenderOtherDialects(t *testing.T) {
	m := bigMessage("en", 200)
	for name, d := range map[string]dialect{"discord": discordDialect, "zalo": zaloDialect, "slack": slackDialect} {
		s := render(m, d)
		if n := utf8.RuneCountInString(s); n > d.limit {
			t.Errorf("%s: %d > %d", name, n, d.limit)
		}
		if !strings.Contains(s, "… and ") || !strings.Contains(s, "New problems (200):") && !strings.Contains(s, `New problems \(200\)\:`) {
			t.Errorf("%s:\n%s", name, s)
		}
	}
	d := render(bigMessage("en", 1), discordDialect)
	if !strings.Contains(d, `\*bold\*`) || !strings.Contains(d, `\@everyone`) || !strings.Contains(d, `\_x\_`) {
		t.Errorf("discord escaping:\n%s", d)
	}
	sl := render(bigMessage("en", 1), slackDialect)
	if !strings.Contains(sl, "&lt;failing&gt; &amp;") {
		t.Errorf("slack escaping:\n%s", sl)
	}
	z := render(bigMessage("vi", 1), zaloDialect)
	if strings.Contains(z, "&lt;") || !strings.Contains(z, "<failing>") {
		t.Errorf("zalo is plain text:\n%s", z)
	}
	// E-mail: no limit, all items, full actions.
	e := bigMessage("vi", 60).Render()
	if strings.Count(e, "✗ Nghiêm trọng") != 50 || !strings.Contains(e, "… và 10 mục khác") {
		t.Errorf("email items: %d", strings.Count(e, "✗ Nghiêm trọng"))
	}
}

func TestRenderKinds(t *testing.T) {
	_, prev := Diff(rep([]model.Finding{diskPending, ramCE, psuFailed}, nil), nil, DiffOptions{})
	m, _ := Diff(rep([]model.Finding{ramCE}, nil, model.CompPower), prev, DiffOptions{Lang: "vi"})
	s := m.Render()
	for _, want := range []string{"Đã hết lỗi (1):", "✓ VI Disk /dev/sda is failing"} {
		if !strings.Contains(s, want) {
			t.Errorf("recovery missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "PSU 2") {
		t.Errorf("carried PSU shown as resolved:\n%s", s)
	}
	if !strings.Contains(m.Subject(), "đã hết 1 vấn đề") {
		t.Errorf("subject %q", m.Subject())
	}

	// Status (--notify-always, nothing changed).
	m, _ = Diff(rep([]model.Finding{diskPending, ramCE, psuFailed}, nil), prev, DiffOptions{Lang: "en"})
	s = m.Render()
	if !strings.Contains(s, "Current problems (3):") || !strings.Contains(s, "Nothing changed") {
		t.Errorf("status:\n%s", s)
	}

	// A new problem with older ones still open.
	_, p2 := Diff(rep([]model.Finding{ramCE}, nil), nil, DiffOptions{})
	m, _ = Diff(rep([]model.Finding{diskPending, ramCE}, []model.Coverage{smartGap}), p2, DiffOptions{Lang: "en", Incomplete: true})
	s = m.Render()
	for _, want := range []string{"New problems (1):", "1 other problem is still open", "Could not be checked this time: S.M.A.R.T. health", "did not finish"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	if !strings.Contains(m.Subject(), "1 new problem") {
		t.Errorf("subject %q", m.Subject())
	}

	tm := TestMessage("srv01", "vi", "0.1.0", prev.Time)
	if s := render(tm, telegramDialect); !strings.Contains(s, "tin nhắn thử") || !strings.Contains(s, "<b>Diagward: tin nhắn thử từ srv01</b>") {
		t.Errorf("test message:\n%s", s)
	}
}

func TestRenderPart(t *testing.T) {
	psu := psuFailed
	psu.Action = model.T("Replace the PSU: open a warranty case with the serial below.", "Thay bộ nguồn: mở bảo hành kèm số serial bên dưới.")
	psu.Part = &model.Part{Kind: "psu", Vendor: "Dell", Model: "0PJMDN", Serial: "CN1797278B0123", Location: "PSU 2"}
	quoted := diskPending
	quoted.Action = model.T("Replace disk (serial S1VZJ9)", "Thay ổ (serial S1VZJ9)")
	quoted.Part = &model.Part{Kind: "disk", Serial: "S1VZJ9"}
	m, _ := Diff(rep([]model.Finding{psu, quoted}, nil), nil, DiffOptions{Lang: "vi"})
	s := render(m, telegramDialect)
	if !strings.Contains(s, "Linh kiện: Dell 0PJMDN, serial CN1797278B0123") || strings.Count(s, "Linh kiện:") != 1 {
		t.Errorf("part line:\n%s", s)
	}
	if p := BuildPayload(m, false); p.New[0].Part != "Dell 0PJMDN, serial CN1797278B0123" || p.New[1].Part != "" {
		t.Errorf("payload parts %+v", p.New)
	}
}
