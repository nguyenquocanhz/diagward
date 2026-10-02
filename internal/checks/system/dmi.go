package system

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// dmiRecord is one structure from `dmidecode` text output.
type dmiRecord struct {
	Type   int
	Title  string
	Fields map[string]string // lower-case key -> value
}

// parseDMIDecode parses `dmidecode` text output into records. It accepts
// any subset of types and ignores nested list lines (characteristics,
// features). It returns nil for "No SMBIOS nor DMI entry point found".
func parseDMIDecode(s string) []dmiRecord {
	var (
		out []dmiRecord
		cur *dmiRecord
	)
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := strings.TrimRight(raw, " \t")
		if strings.HasPrefix(line, "Handle ") {
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &dmiRecord{Type: -1, Fields: map[string]string{}}
			if i := strings.Index(line, "DMI type "); i >= 0 {
				rest := line[i+len("DMI type "):]
				if j := strings.IndexAny(rest, ", "); j > 0 {
					rest = rest[:j]
				}
				if n, err := strconv.Atoi(rest); err == nil {
					cur.Type = n
				}
			}
			continue
		}
		if cur == nil || line == "" {
			continue
		}
		switch {
		case !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " "):
			if cur.Title == "" {
				cur.Title = strings.TrimSpace(line)
			}
		case strings.HasPrefix(line, "\t\t"):
			// list item of the previous key (Characteristics:, Features:)
		default:
			k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			if _, dup := cur.Fields[k]; !dup {
				cur.Fields[k] = strings.TrimSpace(v)
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// first returns the first record of type t, or nil.
func firstDMI(recs []dmiRecord, t int) *dmiRecord {
	for i := range recs {
		if recs[i].Type == t {
			return &recs[i]
		}
	}
	return nil
}

func (r *dmiRecord) get(k string) string {
	if r == nil {
		return ""
	}
	return clean(r.Fields[k])
}

// junkValues are the placeholders vendors leave in SMBIOS fields. They are
// not identifiers and must never be shown as a serial number.
var junkValues = map[string]bool{
	"": true, "not specified": true, "not available": true, "not applicable": true,
	"to be filled by o.e.m.": true, "to be filled by oem": true, "o.e.m.": true, "oem": true,
	"system serial number": true, "chassis serial number": true, "base board serial number": true,
	"system product name": true, "system manufacturer": true, "system version": true,
	"default string": true, "none": true, "n/a": true, "na": true, "unknown": true,
	"0123456789": true, "123456789": true, "1234567890": true, "1234567890123456789012": true,
	"serial": true, "serial number": true, "--": true, "-": true, ".": true,
	"not settable": true, "invalid": true, "empty": true, "type1productconfigid": true,
	"type1family": true, "type2 - board serial number": true, "chassis manufacture": true,
}

// clean trims a DMI/CIM value and returns "" for placeholders.
func clean(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "\x00"))
	if junkValues[strings.ToLower(s)] {
		return ""
	}
	// All one character (0000000, XXXXXXX, FFFFFFFF, spaces): not a value.
	if len(s) > 0 && strings.Count(s, s[:1]) == len(s) {
		return ""
	}
	return s
}

var bracketRe = regexp.MustCompile(`\s*:?\s*-?\[([^\]]+)\]-?\s*`)

// cleanModel turns Lenovo/IBM style "ThinkSystem SR650 -[7X06CTO1WW]-" into
// "ThinkSystem SR650 (7X06CTO1WW)".
func cleanModel(s string) string {
	s = clean(s)
	m := bracketRe.FindStringSubmatchIndex(s)
	if m == nil {
		return s
	}
	inner := s[m[2]:m[3]]
	base := strings.TrimSpace(s[:m[0]] + " " + s[m[1]:])
	if base == "" {
		return inner
	}
	return base + " (" + inner + ")"
}

// cleanVersion turns "-[IVE182H-4.10]-" into "IVE182H-4.10".
func cleanVersion(s string) string {
	s = clean(s)
	if m := bracketRe.FindStringSubmatch(s); m != nil && strings.TrimSpace(bracketRe.ReplaceAllString(s, "")) == "" {
		return m[1]
	}
	return s
}

// parseBIOSDate parses SMBIOS release dates: "MM/DD/YYYY", "MM/DD/YY",
// ISO dates and hostnamectl's "Tue 2021-07-09".
func parseBIOSDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if f := strings.Fields(s); len(f) == 2 && len(f[0]) == 3 {
		s = f[1] // "Tue 2021-07-09"
	}
	for _, layout := range []string{"01/02/2006", "1/2/2006", "01/02/06", "2006-01-02", time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Year() < 1980 || t.Year() > 2100 {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// chassisTypes maps SMBIOS chassis type numbers (DSP0134 7.4.1) to names.
var chassisTypes = map[int]string{
	1: "Other", 2: "Unknown", 3: "Desktop", 4: "Low Profile Desktop", 6: "Mini Tower", 7: "Tower",
	8: "Portable", 9: "Laptop", 10: "Notebook", 13: "All in One", 17: "Main Server Chassis",
	23: "Rack Mount Chassis", 24: "Sealed-case PC", 25: "Multi-system chassis", 28: "Blade",
	29: "Blade Enclosure", 30: "Tablet", 31: "Convertible", 35: "Mini PC", 36: "Stick PC",
}

func chassisName(n int) string {
	if s, ok := chassisTypes[n]; ok {
		return s
	}
	if n <= 0 {
		return ""
	}
	return "type " + strconv.Itoa(n)
}
