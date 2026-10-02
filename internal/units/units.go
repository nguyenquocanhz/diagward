// Package units formats sizes, durations and counts for reports.
package units

import (
	"fmt"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// SI formats bytes with decimal units, the way disk vendors label capacity
// (4.0 TB).
func SI(b uint64) string {
	return format(float64(b), 1000, []string{"B", "kB", "MB", "GB", "TB", "PB"})
}

// IEC formats bytes with binary units, the way memory is sized (16 GiB).
func IEC(b uint64) string {
	return format(float64(b), 1024, []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"})
}

func format(v, base float64, u []string) string {
	i := 0
	for v >= base && i < len(u)-1 {
		v /= base
		i++
	}
	switch {
	case i == 0:
		return fmt.Sprintf("%.0f %s", v, u[i])
	case v >= 100:
		return fmt.Sprintf("%.0f %s", v, u[i])
	case v >= 10:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + " " + u[i]
	default:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".") + " " + u[i]
	}
}

// Duration formats a duration in words, coarsely (the two largest units).
func Duration(d time.Duration) model.Text {
	if d < 0 {
		d = -d
	}
	type unit struct {
		d      time.Duration
		en, vi string
	}
	units := []unit{
		{365 * 24 * time.Hour, "year", "năm"},
		{30 * 24 * time.Hour, "month", "tháng"},
		{24 * time.Hour, "day", "ngày"},
		{time.Hour, "hour", "giờ"},
		{time.Minute, "minute", "phút"},
	}
	var en, vi []string
	for _, u := range units {
		if n := int64(d / u.d); n > 0 {
			s := ""
			if n > 1 {
				s = "s"
			}
			en = append(en, fmt.Sprintf("%d %s%s", n, u.en, s))
			vi = append(vi, fmt.Sprintf("%d %s", n, u.vi))
			d -= time.Duration(n) * u.d
			if len(en) == 2 {
				break
			}
		} else if len(en) > 0 {
			break
		}
	}
	if len(en) == 0 {
		return model.T("less than a minute", "chưa tới 1 phút")
	}
	return model.T(strings.Join(en, " "), strings.Join(vi, " "))
}

// Hours formats a power-on-hours counter ("3 years 2 months (27,900 h)").
func Hours(h uint64) model.Text {
	d := Duration(time.Duration(h) * time.Hour)
	return model.Text{EN: fmt.Sprintf("%s (%s h)", d.EN, Thousands(h)), VI: fmt.Sprintf("%s (%s giờ)", d.VI, ThousandsVI(h))}
}

// Thousands formats n with thousands separators (27,900).
func Thousands(n uint64) string {
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// ThousandsVI formats n the Vietnamese way, with dots (27.900).
func ThousandsVI(n uint64) string { return strings.ReplaceAll(Thousands(n), ",", ".") }

// Count formats n for both languages (27,900 / 27.900).
func Count(n uint64) model.Text { return model.Text{EN: Thousands(n), VI: ThousandsVI(n)} }

// Evidence trims a list of raw lines for Finding.Evidence: at most max lines,
// each at most 300 characters, with a final "... N more" line.
func Evidence(lines []string, max int) []string {
	out := make([]string, 0, min(len(lines), max+1))
	for i, l := range lines {
		if i == max {
			out = append(out, fmt.Sprintf("... %d more", len(lines)-max))
			break
		}
		l = strings.TrimRight(l, "\r\n")
		if r := []rune(l); len(r) > 300 {
			l = string(r[:300]) + "…"
		}
		out = append(out, l)
	}
	return out
}
