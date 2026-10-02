package units

import (
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

func TestShort(t *testing.T) {
	for _, c := range []struct {
		d      time.Duration
		en, vi string
	}{
		{30 * time.Second, "<1m", "<1 phút"},
		{125 * time.Second, "2m", "2 phút"},
		{3*time.Hour + 12*time.Minute, "3h 12m", "3 giờ 12 phút"},
		{41*24*time.Hour + 6*time.Hour + 59*time.Second, "41d 6h", "41 ngày 6 giờ"},
		{-5 * time.Minute, "5m", "5 phút"},
	} {
		if got := Short(c.d); got != model.T(c.en, c.vi) {
			t.Errorf("Short(%v) = %+v, want %q / %q", c.d, got, c.en, c.vi)
		}
	}
	if got := ShortSeconds(86400 + 6*3600); got.VI != "1 ngày 6 giờ" || got.EN != "1d 6h" {
		t.Errorf("ShortSeconds = %+v", got)
	}
}

func TestWords(t *testing.T) {
	raid := NewPhrases(map[string]string{"spun up": "đang quay", "active": "đang chạy", "clean": "sạch"})
	for in, want := range map[string]string{
		"":                         "",
		"Online, Spun Up":          "Hoạt động, đang quay",
		"active [clean, degraded]": "đang chạy [sạch, suy giảm]",
		"FAILED":                   "Hỏng",
		"Predictive Failure":       "Sắp hỏng",
		"Okay":                     "Okay",               // whole words only
		"ONLINE(sdb) ok3":          "Hoạt động(sdb) ok3", // "ok3" is one word
		"Healthy OK 45% allocated": "Tốt ổn 45% allocated",
		"Vendor code 0x1f":         "Vendor code 0x1f",
	} {
		if got := raid.Text(in); got.EN != in || got.VI != want {
			t.Errorf("%q → %q, want %q", in, got.VI, want)
		}
	}
	if got := Words("Not Present"); got.VI != "Không lắp" {
		t.Errorf("Words: %+v", got)
	}
	if got := Words("down (unused)", map[string]string{"down": "mất link"}); got.VI != "mất link (không dùng)" {
		t.Errorf("Words with dict: %+v", got)
	}
}

func TestWhole(t *testing.T) {
	p := NewPhrases(map[string]string{"power": "công suất", "redundancy lost": "mất dự phòng", "degrees c": "°C"})
	for in, want := range map[string]string{
		"":                     "",
		"Redundancy Lost":      "Mất dự phòng",
		"23 degrees C":         "23 °C",
		"Power Button pressed": "Power Button pressed", // one unknown word: no translation at all
		"Soft-power failure":   "Soft-power failure",
		"0x1f":                 "0x1f",
		"42 %":                 "42 %",
	} {
		if got := p.Whole(in); got.EN != in || got.VI != want {
			t.Errorf("Whole(%q) = %q, want %q", in, got.VI, want)
		}
	}
}
