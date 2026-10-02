package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// logLine is one parsed log line.
type logLine struct {
	T   time.Time // zero when the line has no usable timestamp
	Tag string    // syslog identifier: "kernel", "smartd", "mdadm", ...
	Msg string    // the message, without timestamp, host and tag
	Raw string    // the original line (for Evidence)
	Src string    // where it came from: "journal", "syslog", "dmesg"
}

// srcMeta is what the "# key=value" header lines of a section said.
type srcMeta struct {
	Sources    map[string]bool // journal, syslog, dmesg
	Persistent bool            // journal on disk (survives reboots)
	Volatile   bool            // journal seen and not persistent
	TimedOut   bool            // a journalctl run hit the timeout (# rc=124)
	Files      []string        // syslog files read
	// Capped lists the blocks (not the "class=noise" ones) where the
	// collector kept only the newest max= of total= lines.
	Capped []capInfo
}

// capInfo is one log block the collector cut to its newest lines.
type capInfo struct {
	Src        string
	Total, Max int
	Oldest     time.Time // oldest line kept
}

var (
	// 2026-10-02T14:28:21+07:00 host tag[pid]: msg (journalctl -o short-iso,
	// also rsyslog's RFC 3339 file format on Ubuntu 24.04+ / Debian 12+).
	reISO = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(.*)$`)
	// Jan 15 10:23:45 host tag[pid]: msg (traditional syslog, no year).
	reBSD = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$`)
	// [Mon Jan 15 10:23:45 2024] msg (dmesg -T).
	reDmesgT = regexp.MustCompile(`^\[([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})\]\s?(.*)$`)
	// [12345.678901] msg (plain dmesg; seconds since boot).
	reDmesg = regexp.MustCompile(`^(?:<\d+>)?\[\s*(\d+)\.(\d+)\]\s?(.*)$`)
	// tag[pid]: msg
	reTag = regexp.MustCompile(`^([^\s:\[]+)(?:\[\d+\])?:\s?(.*)$`)
	// printk timestamps some syslog setups keep inside the message.
	rePrintkTS = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s?`)
)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April,
	"May": time.May, "Jun": time.June, "Jul": time.July, "Aug": time.August,
	"Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// parseTZ turns "+0700" / "+07:00" / "Z" into a fixed zone (UTC when unknown).
func parseTZ(s string) *time.Location {
	s = strings.TrimSpace(s)
	if s == "" || s == "Z" {
		return time.UTC
	}
	sign := 1
	switch s[0] {
	case '+':
	case '-':
		sign = -1
	default:
		return time.UTC
	}
	d := strings.ReplaceAll(s[1:], ":", "")
	if len(d) != 4 {
		return time.UTC
	}
	h, err1 := strconv.Atoi(d[:2])
	m, err2 := strconv.Atoi(d[2:])
	if err1 != nil || err2 != nil || h > 14 || m > 59 {
		return time.UTC
	}
	off := sign * (h*3600 + m*60)
	if off == 0 {
		return time.UTC
	}
	return time.FixedZone(s, off)
}

// headerKV parses "# a=1 b=two" into a map.
func headerKV(l string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Fields(strings.TrimPrefix(l, "#")) {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = v
		}
	}
	return m
}

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// parseLog parses a logs.* section: "# source=..." headers switch the line
// format; other lines are log lines. now is used for year inference when a
// syslog file's mtime is unknown. Each "# source=" block is returned as its
// own set so that the same event read from two sources can be merged.
func parseLog(text string, now time.Time, meta *srcMeta) [][]logLine {
	var (
		sets  [][]logLine
		out   []logLine
		src   = "journal"
		loc   = time.UTC
		ref   = now // reference for year inference
		boot  int64
		lines = strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	)
	if meta.Sources == nil {
		meta.Sources = map[string]bool{}
	}
	var capped *capInfo
	closeCap := func() {
		if capped == nil {
			return
		}
		for _, l := range out {
			if !l.T.IsZero() && (capped.Oldest.IsZero() || l.T.Before(capped.Oldest)) {
				capped.Oldest = l.T
			}
		}
		meta.Capped = append(meta.Capped, *capped)
		capped = nil
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if strings.HasPrefix(l, "# ") {
			kv := headerKV(l)
			if rc, ok := kv["rc"]; ok {
				if rc == "124" || rc == "137" {
					meta.TimedOut = true
				}
				continue
			}
			if tz, ok := kv["tz"]; ok {
				loc = parseTZ(tz)
			}
			if s, ok := kv["source"]; ok {
				closeCap()
				if len(out) > 0 {
					sets = append(sets, out)
					out = nil
				}
				if total, max := atoi64(kv["total"]), atoi64(kv["max"]); max > 0 && total > max && kv["class"] != "noise" {
					capped = &capInfo{Src: srcFamily(s), Total: int(total), Max: int(max)}
				}
				src = s
				ref = now
				boot = atoi64(kv["boot"])
				switch {
				case s == "journal":
					meta.Sources["journal"] = true
					if kv["persistent"] == "1" {
						meta.Persistent = true
					} else {
						meta.Volatile = true
					}
				case s == "syslog":
					meta.Sources["syslog"] = true
					if f := kv["file"]; f != "" {
						meta.Files = append(meta.Files, f)
					}
					if mt := atoi64(kv["mtime"]); mt > 0 {
						ref = time.Unix(mt, 0)
					}
				case strings.HasPrefix(s, "dmesg"):
					meta.Sources["dmesg"] = true
				}
			}
			continue
		}
		if ll, ok := parseLine(l, src, loc, ref, boot); ok {
			out = append(out, ll)
		}
	}
	closeCap()
	if len(out) > 0 {
		sets = append(sets, out)
	}
	return sets
}

// parseLine parses one line in any of the supported formats.
func parseLine(l, src string, loc *time.Location, ref time.Time, boot int64) (logLine, bool) {
	raw := strings.TrimRight(l, "\r")
	ll := logLine{Raw: raw, Src: srcFamily(src)}
	rest := ""
	switch {
	case reISO.MatchString(raw):
		m := reISO.FindStringSubmatch(raw)
		ll.T = parseISO(m[1], loc)
		rest = m[3]
	case reBSD.MatchString(raw):
		m := reBSD.FindStringSubmatch(raw)
		ll.T = bsdTime(m, loc, ref)
		rest = m[7]
	case reDmesgT.MatchString(raw):
		m := reDmesgT.FindStringSubmatch(raw)
		if t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", m[1], loc); err == nil {
			ll.T = t
		}
		ll.Tag, ll.Msg = "kernel", m[2]
		return ll, true
	case reDmesg.MatchString(raw):
		m := reDmesg.FindStringSubmatch(raw)
		if boot > 0 {
			ll.T = time.Unix(boot+atoi64(m[1]), 0).In(loc)
		}
		ll.Tag, ll.Msg = "kernel", m[3]
		return ll, true
	default:
		if strings.HasPrefix(src, "dmesg") {
			// busybox/odd dmesg without timestamps.
			ll.Tag, ll.Msg = "kernel", raw
			return ll, true
		}
		return ll, false
	}
	if m := reTag.FindStringSubmatch(rest); m != nil {
		ll.Tag, ll.Msg = m[1], m[2]
	} else {
		ll.Tag, ll.Msg = "", rest
	}
	if ll.Tag == "kernel" {
		ll.Msg = rePrintkTS.ReplaceAllString(ll.Msg, "")
	}
	return ll, true
}

func srcFamily(s string) string {
	if strings.HasPrefix(s, "dmesg") {
		return "dmesg"
	}
	return s
}

func parseISO(s string, loc *time.Location) time.Time {
	s = strings.Replace(s, ",", ".", 1)
	for _, layout := range []string{"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999Z0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05.999999999", s, loc); err == nil {
		return t
	}
	return time.Time{}
}

// bsdTime builds a time from a year-less syslog timestamp: the year is the
// one that puts the line at or before ref (the file's mtime, or now) + 1 day.
func bsdTime(m []string, loc *time.Location, ref time.Time) time.Time {
	mon, ok := months[m[1]]
	if !ok || ref.IsZero() {
		return time.Time{}
	}
	day, _ := strconv.Atoi(m[2])
	h, _ := strconv.Atoi(m[3])
	mi, _ := strconv.Atoi(m[4])
	s, _ := strconv.Atoi(m[5])
	if day < 1 || day > 31 || h > 23 || mi > 59 || s > 60 {
		return time.Time{}
	}
	r := ref.In(loc)
	t := time.Date(r.Year(), mon, day, h, mi, s, 0, loc)
	if t.After(r.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// lineKey identifies the same event read from two sources (journal and a
// syslog file write the same message with the same second).
func lineKey(l logLine) string {
	ts := ""
	if !l.T.IsZero() {
		ts = strconv.FormatInt(l.T.Unix(), 10)
	}
	return ts + "\x00" + l.Tag + "\x00" + strings.TrimSpace(l.Msg)
}

// mergeLines combines line sets: a line already present (same second, tag
// and message) in an earlier set is not added again, but genuine repeats
// within one set are kept (union by multiplicity).
func mergeLines(sets ...[]logLine) []logLine {
	seen := map[string]int{}
	var out []logLine
	for _, set := range sets {
		local := map[string]int{}
		for _, l := range set {
			k := lineKey(l)
			local[k]++
			if local[k] <= seen[k] {
				continue
			}
			out = append(out, l)
		}
		for k, n := range local {
			if n > seen[k] {
				seen[k] = n
			}
		}
	}
	return out
}
