package units

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/model"
)

// Common holds Vietnamese for the status words that many tools print
// (controller, sensor and CIM states). Keys are lower case. Words that mean
// different things per domain ("up", "active") belong in the domain's own
// dictionary, passed to Words or NewPhrases.
var Common = map[string]string{
	"ok":                 "ổn",
	"good":               "tốt",
	"healthy":            "tốt",
	"normal":             "bình thường",
	"optimal":            "bình thường",
	"warning":            "cảnh báo",
	"critical":           "nghiêm trọng",
	"error":              "lỗi",
	"errors":             "lỗi",
	"failed":             "hỏng",
	"failure":            "hỏng",
	"fail":               "hỏng",
	"faulty":             "hỏng",
	"predictive failure": "sắp hỏng",
	"degraded":           "suy giảm",
	"rebuild":            "đang rebuild",
	"rebuilding":         "đang rebuild",
	"enabled":            "đang bật",
	"disabled":           "đã tắt",
	"present":            "có lắp",
	"not present":        "không lắp",
	"absent":             "không lắp",
	"missing":            "bị thiếu",
	"unknown":            "không rõ",
	"online":             "hoạt động",
	"offline":            "ngừng hoạt động",
	"inactive":           "không hoạt động",
	"running":            "đang chạy",
	"stopped":            "đã dừng",
	"standby":            "chờ",
	"idle":               "rảnh",
	"empty":              "trống",
	"unused":             "không dùng",
	"none":               "không có",
	"yes":                "có",
	"no":                 "không",
	"other":              "khác",
	"lost":               "mất",
	"redundant":          "có dự phòng",
	"non-redundant":      "không dự phòng",
	"redundancy lost":    "mất dự phòng",
	"recovered":          "đã hết",
	"read-only":          "chỉ đọc",
	"hot spare":          "dự phòng nóng (hot spare)",
	"spare":              "dự phòng",
}

// Phrases translates status strings by replacing known words and phrases.
// Build one with NewPhrases (once, at package level) and call Text per
// cell.
type Phrases struct {
	m    map[string]string
	keys []string // longest first
}

// NewPhrases builds a translator from Common and the given dictionaries
// (keys lower case); later dictionaries override earlier ones and Common.
func NewPhrases(dicts ...map[string]string) *Phrases {
	p := &Phrases{m: map[string]string{}}
	for k, v := range Common {
		p.m[k] = v
	}
	for _, d := range dicts {
		for k, v := range d {
			p.m[strings.ToLower(k)] = v
		}
	}
	for k := range p.m {
		p.keys = append(p.keys, k)
	}
	sort.Slice(p.keys, func(i, j int) bool {
		if len(p.keys[i]) != len(p.keys[j]) {
			return len(p.keys[i]) > len(p.keys[j])
		}
		return p.keys[i] < p.keys[j]
	})
	return p
}

// Text returns s in both languages: English as given, Vietnamese with every
// known phrase replaced. Phrases match case-insensitively on whole words
// (longest first); everything else (numbers, names, unknown vendor codes,
// punctuation) is kept, so "Online, Spun Up" becomes "Hoạt động, đang
// quay" and "active [clean, degraded]" "đang chạy [sạch, suy giảm]". The
// Vietnamese starts with a capital letter when the original does.
func (p *Phrases) Text(s string) model.Text {
	vi, _ := p.replace(s)
	return model.Text{EN: s, VI: vi}
}

// Whole is Text for free text such as event descriptions, where a known
// word inside an unknown sentence must not be translated on its own: s is
// translated only when every word of it belongs to a known phrase, and is
// otherwise kept as is in both languages ("Power Button pressed" never
// becomes half Vietnamese). Numbers and punctuation need no translation;
// a word with a letter (including hex values and codes) does.
func (p *Phrases) Whole(s string) model.Text {
	vi, complete := p.replace(s)
	if !complete {
		vi = s
	}
	return model.Text{EN: s, VI: vi}
}

// replace translates the known phrases of s. complete reports whether
// every letter of s was part of a translated phrase.
func (p *Phrases) replace(s string) (out string, complete bool) {
	if s == "" || p == nil {
		return s, s == ""
	}
	lower := strings.ToLower(s)
	if len(lower) != len(s) { // a rune changes length when lower-cased: give up rather than misalign
		return s, false
	}
	var b strings.Builder
	complete = true
	i := 0
	for i < len(s) {
		if k := p.match(lower, i); k != "" {
			v := p.m[k]
			if strings.TrimSpace(s[:i]) == "" {
				v = matchCase(s[i:i+len(k)], v)
			}
			b.WriteString(v)
			i += len(k)
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if unicode.IsLetter(r) {
			complete = false
		}
		b.WriteString(s[i : i+n])
		i += n
	}
	return b.String(), complete
}

// match returns the longest key found at i that starts and ends on a word
// boundary (a key that begins or ends with punctuation needs none there).
func (p *Phrases) match(lower string, i int) string {
	if i > 0 && wordBefore(lower, i) && wordAt(lower, i) {
		return ""
	}
	for _, k := range p.keys {
		if !strings.HasPrefix(lower[i:], k) {
			continue
		}
		end := i + len(k)
		if end == len(lower) || !wordAt(lower, end) || !wordBefore(lower, end) {
			return k
		}
	}
	return ""
}

func isWord(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

// wordAt reports whether the rune starting at byte i is a letter or digit.
func wordAt(s string, i int) bool {
	r, _ := utf8.DecodeRuneInString(s[i:])
	return isWord(r)
}

// wordBefore reports whether the rune ending at byte i is a letter or digit.
func wordBefore(s string, i int) bool {
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return isWord(r)
}

// matchCase capitalises v when orig starts with an upper-case letter
// ("Failed" and "FAILED" → "Hỏng", "failed" → "hỏng").
func matchCase(orig, v string) string {
	r, _ := utf8.DecodeRuneInString(orig)
	if !unicode.IsUpper(r) || v == "" {
		return v
	}
	f, n := utf8.DecodeRuneInString(v)
	return string(unicode.ToUpper(f)) + v[n:]
}

var commonPhrases = NewPhrases()

// Words translates a short status string for a table cell with Common and
// the given dictionaries (see Phrases.Text). For a dictionary used on every
// row, build a Phrases once with NewPhrases instead.
func Words(s string, dicts ...map[string]string) model.Text {
	if len(dicts) == 0 {
		return commonPhrases.Text(s)
	}
	return NewPhrases(dicts...).Text(s)
}
