package report

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Terminal layout helpers. Widths are measured in terminal cells: most runes
// (including precomposed Vietnamese letters such as "ố" or "ự") take one
// cell, combining marks take none and East Asian wide/fullwidth runes take
// two. This is a compact version of the Unicode East Asian Width property
// (UAX #11), enough for server names, model numbers and log lines.

// runeWidth returns the number of terminal cells r occupies.
func runeWidth(r rune) int {
	switch {
	case r == 0:
		return 0
	case r < 0x20 || (r >= 0x7f && r < 0xa0):
		return 0 // control characters are stripped by clean(); count them as nothing
	case r < 0x300:
		return 1
	case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r), unicode.Is(unicode.Cf, r):
		return 0 // combining marks (decomposed Vietnamese tones), ZWJ, BOM
	case r >= 0xfe00 && r <= 0xfe0f:
		return 0 // variation selectors
	}
	if isWide(r) {
		return 2
	}
	return 1
}

// wideRanges lists the East Asian Wide (W) and Fullwidth (F) blocks plus the
// emoji blocks most terminals draw two cells wide.
var wideRanges = [][2]rune{
	{0x1100, 0x115f},   // Hangul Jamo initial consonants
	{0x231a, 0x231b},   // watch, hourglass
	{0x2329, 0x232a},   // angle brackets
	{0x23e9, 0x23ec},   // media buttons
	{0x23f0, 0x23f0},   // alarm clock
	{0x23f3, 0x23f3},   // hourglass
	{0x25fd, 0x25fe},   // small squares
	{0x2614, 0x2615},   // umbrella, hot beverage
	{0x2648, 0x2653},   // zodiac
	{0x267f, 0x267f},   // wheelchair
	{0x2693, 0x2693},   // anchor
	{0x26a1, 0x26a1},   // high voltage
	{0x26aa, 0x26ab},   // circles
	{0x26bd, 0x26be},   // balls
	{0x26c4, 0x26c5},   // snowman, sun
	{0x26ce, 0x26ce},   // ophiuchus
	{0x26d4, 0x26d4},   // no entry
	{0x26ea, 0x26ea},   // church
	{0x26f2, 0x26f3},   // fountain, golf
	{0x26f5, 0x26f5},   // sailboat
	{0x26fa, 0x26fa},   // tent
	{0x26fd, 0x26fd},   // fuel pump
	{0x2705, 0x2705},   // white heavy check mark (emoji)
	{0x270a, 0x270b},   // fists
	{0x2728, 0x2728},   // sparkles
	{0x274c, 0x274c},   // cross mark (emoji)
	{0x274e, 0x274e},   // negative squared cross mark
	{0x2753, 0x2755},   // question marks
	{0x2757, 0x2757},   // exclamation mark
	{0x2795, 0x2797},   // plus, minus, divide
	{0x27b0, 0x27b0},   // curly loop
	{0x27bf, 0x27bf},   // double curly loop
	{0x2b1b, 0x2b1c},   // large squares
	{0x2b50, 0x2b50},   // star
	{0x2b55, 0x2b55},   // circle
	{0x2e80, 0x303e},   // CJK radicals, punctuation
	{0x3041, 0x33ff},   // Hiragana .. CJK compatibility
	{0x3400, 0x4dbf},   // CJK extension A
	{0x4e00, 0x9fff},   // CJK unified ideographs
	{0xa000, 0xa4cf},   // Yi
	{0xa960, 0xa97f},   // Hangul Jamo extended A
	{0xac00, 0xd7a3},   // Hangul syllables
	{0xf900, 0xfaff},   // CJK compatibility ideographs
	{0xfe10, 0xfe19},   // vertical forms
	{0xfe30, 0xfe6f},   // CJK compatibility forms, small forms
	{0xff00, 0xff60},   // fullwidth forms
	{0xffe0, 0xffe6},   // fullwidth signs
	{0x16fe0, 0x16fe4}, // ideographic symbols
	{0x17000, 0x18cff}, // Tangut
	{0x1b000, 0x1b2ff}, // Kana supplement
	{0x1f004, 0x1f004}, // mahjong
	{0x1f0cf, 0x1f0cf}, // joker
	{0x1f18e, 0x1f18e}, // AB button
	{0x1f191, 0x1f19a}, // squared words
	{0x1f200, 0x1f2ff}, // enclosed ideographic supplement
	{0x1f300, 0x1f64f}, // misc symbols & pictographs, emoticons
	{0x1f680, 0x1f6ff}, // transport & map
	{0x1f7e0, 0x1f7eb}, // coloured circles/squares
	{0x1f90c, 0x1f9ff}, // supplemental symbols & pictographs
	{0x1fa70, 0x1faff}, // symbols & pictographs extended A
	{0x20000, 0x2fffd}, // CJK extension B..F
	{0x30000, 0x3fffd}, // CJK extension G..
}

func isWide(r rune) bool {
	lo, hi := 0, len(wideRanges)-1
	for lo <= hi {
		m := (lo + hi) / 2
		switch {
		case r < wideRanges[m][0]:
			hi = m - 1
		case r > wideRanges[m][1]:
			lo = m + 1
		default:
			return true
		}
	}
	return false
}

// strWidth returns the display width of s (s must not contain ANSI escapes).
func strWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

// clean makes an untrusted string safe and predictable for a terminal or a
// Markdown message: invalid UTF-8 becomes U+FFFD, tabs become spaces, and
// every other control character (including ESC, so log lines cannot inject
// terminal escape sequences) becomes a space. Newlines are kept only when
// keepNL is set.
func clean(s string, keepNL bool) string {
	ok := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c >= 0x80 {
			ok = false
			break
		}
	}
	if ok {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteRune('�')
		case r == '\n' && keepNL:
			b.WriteByte('\n')
		case r == '\t':
			b.WriteString("    ")
		case r == '\r':
			// drop: CRLF line endings from Windows tools
		case r < 0x20 || (r >= 0x7f && r < 0xa0) || r == 0x2028 || r == 0x2029:
			b.WriteByte(' ')
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			// bidi overrides could visually reorder a line; drop them
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncate shortens s to at most w cells, ending with an ellipsis when it
// had to cut.
func truncate(s string, w int, ascii bool) string {
	if strWidth(s) <= w {
		return s
	}
	ell, ellW := "…", 1
	if ascii {
		ell, ellW = "...", 3
	}
	if w <= ellW {
		return cut(s, w)
	}
	return cut(s, w-ellW) + ell
}

// cut returns the longest prefix of s that fits in w cells.
func cut(s string, w int) string {
	n := 0
	for i, r := range s {
		rw := runeWidth(r)
		if n+rw > w {
			return s[:i]
		}
		n += rw
	}
	return s
}

// pad right-pads s with spaces to w cells.
func pad(s string, w int) string {
	if d := w - strWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// wrap breaks s into lines of at most w cells, at spaces where possible and
// hard-breaking words longer than a line (long paths, hex dumps). Existing
// newlines start new lines. It always returns at least one line.
func wrap(s string, w int) []string { return wrap2(s, w, w) }

// wrap2 is wrap with a different width for the first line (w1) than for the
// following ones (w).
func wrap2(s string, w1, w int) []string {
	if w < 1 {
		w = 1
	}
	if w1 < 1 {
		w1 = 1
	}
	full := w
	w = w1
	var out []string
	push := func(l string) {
		out = append(out, l)
		w = full
	}
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			push("")
			continue
		}
		line, lw := "", 0
		for _, word := range words {
			ww := strWidth(word)
			if lw > 0 && lw+1+ww <= w {
				line += " " + word
				lw += 1 + ww
				continue
			}
			if lw > 0 {
				push(line)
				line, lw = "", 0
			}
			for ww > w {
				head := cut(word, w)
				if head == "" { // a single rune wider than w
					_, size := utf8.DecodeRuneInString(word)
					head = word[:size]
				}
				push(head)
				word = word[len(head):]
				ww = strWidth(word)
			}
			line, lw = word, ww
		}
		push(line)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}
