package ipmi

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// selEntry is one line of `ipmitool sel elist`:
//
//	   1 | 06/14/2023 | 10:01:17 | Power Supply PS2 Status | Power Supply AC lost | Asserted
//	  3a | 12/14/22 | 23:09:44 CET | Memory #0x88 | Correctable ECC (CPU0_G1) | Asserted
//	  34 | 02/25/2025 | 04:50:09 PM EST | Memory #0x02 | Uncorrectable ECC (UnCorrectable ECC |  DIMMD7) | Asserted
//	   5 |  Pre-Init  |0000000123| System Event #0x01 | Timestamp Clock Sync | Asserted
//	fe3c | 04/10/2008 | 14:50:13 | Power Unit Power Redundancy | Fully Redundant
//	   9 | Linux kernel panic: Fatal excep
//
// ipmitool >= 1.8.19 prints the date with %x and the time with "%X %Z", so
// the year can have two digits and the time a zone (and AM/PM in non-C
// locales); older releases print 06/14/2023 | 10:01:17. Record IDs are hex.
type selEntry struct {
	ID         string
	Time       time.Time
	TimeOK     bool // parsed and plausible
	PreInit    bool
	Sensor     string // full sensor column
	SensorType string // "Power Supply"
	SensorName string // "PS2 Status"
	Class      string
	Event      string // "Power Supply AC lost"
	Deasserted bool
	Line       string
}

// splitPipes splits on '|' but keeps pipes inside parentheses, which
// ipmitool's OEM decoding prints ("IERR (CPU 2 | APIC ID 35 )", ipmitool
// bug #489).
func splitPipes(line string) []string {
	raw := strings.Split(line, "|")
	var out []string
	cur, depth := "", 0
	for i, p := range raw {
		if i > 0 && depth > 0 {
			cur += "|" + p
		} else {
			if i > 0 {
				out = append(out, cur)
			}
			cur = p
		}
		depth = strings.Count(cur, "(") - strings.Count(cur, ")")
	}
	out = append(out, cur)
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

var selIDRe = regexp.MustCompile(`^[0-9a-fA-F]{1,8}$`)

func parseSEL(out string, now time.Time) []*selEntry {
	return parseSELShift(out, now, 0, dayFirstDates(out))
}

var slashDateRe = regexp.MustCompile(`^\s*([0-9]{1,2})/([0-9]{1,2})/[0-9]{2,4}\s*$`)

// dayFirstDates reports whether the slashed dates in a SEL listing are
// DD/MM: ipmitool >= 1.8.19 prints the date with strftime("%x"), which
// follows LC_TIME. The in-band collectors run under LC_ALL=C (MM/DD/YY),
// but ipmitool run by hand or on a laptop with vi_VN/en_GB/fr_FR prints
// DD/MM/YYYY. A file is day-first when some first field is > 12 and no
// second field is.
func dayFirstDates(out string) bool {
	first, second := false, false
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(line, "|", 3)
		if len(f) < 3 {
			continue
		}
		m := slashDateRe.FindStringSubmatch(f[1])
		if m == nil {
			continue
		}
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		if a > 12 && b <= 12 {
			first = true
		}
		if b > 12 {
			second = true
		}
	}
	return first && !second
}

// parseSELShift parses the listing; shift is subtracted from every time
// stamp (the measured BMC clock error, see checker.bmcClock).
func parseSELShift(out string, now time.Time, shift time.Duration, dayFirst bool) []*selEntry {
	var list []*selEntry
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		f := splitPipes(line)
		if len(f) < 2 || !selIDRe.MatchString(f[0]) {
			continue
		}
		e := &selEntry{ID: strings.ToLower(f[0]), Line: strings.TrimRight(line, " ")}
		if len(f) == 2 {
			if strings.HasPrefix(f[1], "Linux kernel panic") {
				e.Event, e.Class, e.Sensor = "Linux kernel panic", clSystem, "OS"
				list = append(list, e)
			}
			continue
		}
		if len(f) < 5 {
			continue
		}
		if strings.EqualFold(f[1], "Pre-Init") {
			e.PreInit = true
		} else {
			e.Time, e.TimeOK = parseSELTimeOrder(f[1], f[2], dayFirst)
			e.Time = e.Time.Add(-shift)
			if e.TimeOK && (e.Time.Year() < 2008 || e.Time.After(now.Add(48*time.Hour))) {
				e.TimeOK = false // BMC clock not set (01/01/2000, 2007...) or wrong
			}
		}
		e.Sensor = f[3]
		e.Event = f[4]
		if len(f) >= 6 {
			e.Deasserted = strings.EqualFold(f[5], "Deasserted")
		}
		if strings.HasPrefix(e.Sensor, "OEM record") {
			e.Class = clOther
			e.Event = ""
		} else {
			e.SensorType, e.SensorName, e.Class = splitSELSensor(e.Sensor)
		}
		list = append(list, e)
	}
	return list
}

// tzRe matches what glibc's %Z prints: a name ("UTC", "CEST", "IST") or,
// for the many zones without an established abbreviation, a numeric one
// ("+07" for Asia/Ho_Chi_Minh, "-03", "+0530", "+0545").
var tzRe = regexp.MustCompile(`^[A-Za-z]{2,6}$|^[+-][0-9]{2}(:?[0-9]{2})?$`)

// parseSELTime parses ipmitool's date and time columns (month-first dates).
func parseSELTime(d, t string) (time.Time, bool) { return parseSELTimeOrder(d, t, false) }

// parseSELTimeOrder parses ipmitool's date and time columns. The zone name
// is dropped: the BMC clock is usually local time and a few hours do not
// matter for a 30-day window.
func parseSELTimeOrder(d, t string, dayFirst bool) (time.Time, bool) {
	d = strings.TrimSpace(d)
	fs := strings.Fields(t)
	if len(fs) > 1 {
		last := strings.ToUpper(fs[len(fs)-1])
		if last != "AM" && last != "PM" && tzRe.MatchString(fs[len(fs)-1]) {
			fs = fs[:len(fs)-1]
		}
	}
	t = strings.Join(fs, " ")
	if d == "" || t == "" || strings.HasPrefix(d, "S+") || strings.EqualFold(d, "Unspecified") {
		return time.Time{}, false
	}
	layouts := []string{"01/02/2006", "01/02/06", "2006-01-02", "02.01.2006", "2006/01/02"}
	if dayFirst {
		layouts[0], layouts[1] = "02/01/2006", "02/01/06"
	}
	for _, dl := range layouts {
		for _, tl := range []string{"15:04:05", "03:04:05 PM", "3:04:05 PM", "15:04"} {
			if tm, err := time.Parse(dl+" "+tl, d+" "+t); err == nil {
				return tm, true
			}
		}
	}
	return time.Time{}, false
}

// selGroup is one kind of event on one sensor: all assertions of
// "Power Supply AC lost" on "Power Supply PS2 Status".
type selGroup struct {
	Sensor, Event string
	Class         string
	v             verdict
	Count         int // assertions
	Recent        int // assertions inside the window
	First, Last   time.Time
	Unknown       int // assertions with no usable time
	lastAssert    int
	lastDeassert  int
	lines         []string
	dimms         []string
	Severity      model.Severity
	healthyNow    bool // the live SDR shows the part healthy
}

// Recovered: the last assertion was followed by a deassertion.
func (g *selGroup) Recovered() bool { return g.lastDeassert > g.lastAssert }

var dimmRe = regexp.MustCompile(`(?i)\b(?:CPU[0-9]+[_ ]?)?(?:P[0-9][_ -]?)?DIMM[_ -]?[A-Z]{0,2}[0-9]{1,2}\b|\bCPU[0-9]+_[A-Z][0-9]{1,2}\b`)

// groupSEL groups events and applies the window: assertions within the
// window drive Warn/Crit, a deassertion after the last assertion lowers the
// severity one step ("recovered"), older events only feed an Info summary.
func groupSEL(entries []*selEntry, now time.Time, window time.Duration) []*selGroup {
	idx := map[string]*selGroup{}
	var order []*selGroup
	since := now.Add(-window)
	for i, e := range entries {
		if e.Event == "" {
			continue
		}
		k := e.Sensor + "\x00" + normEvent(e.Event)
		g := idx[k]
		if g == nil {
			name := e.SensorName
			if name == "" {
				name = e.Sensor
			}
			g = &selGroup{Sensor: e.Sensor, Event: cleanEvent(e.Event), Class: e.Class, v: judge(e.Event, e.Class, name), lastAssert: -1, lastDeassert: -1}
			idx[k] = g
			order = append(order, g)
		}
		if e.Deasserted {
			g.lastDeassert = i
			continue
		}
		g.lastAssert = i
		g.Count++
		if len(g.lines) < 10 {
			g.lines = append(g.lines, e.Line)
		} else {
			g.lines[9] = e.Line // keep the newest as the last evidence line
		}
		if m := dimmRe.FindString(e.Event + " " + e.SensorName); m != "" && !contains(g.dimms, m) {
			g.dimms = append(g.dimms, m)
		}
		if !e.TimeOK {
			g.Unknown++
			continue
		}
		if g.First.IsZero() || e.Time.Before(g.First) {
			g.First = e.Time
		}
		if e.Time.After(g.Last) {
			g.Last = e.Time
		}
		if !e.Time.Before(since) {
			g.Recent++
		}
	}
	// Recovery logged as a new assertion rather than a deassertion: Dell
	// asserts "Fully Redundant" when a lost PSU comes back, HPE asserts
	// "Transition to OK" after "Transition to Critical..." (generic event
	// types 0Bh and 07h, IPMI 2.0 table 42-2).
	for _, g := range order {
		n := normEvent(g.Event)
		var r int
		switch {
		case g.v.key == "redundancy_lost":
			r = recoveredAt(entries, g.Sensor, "fully redundant")
		case strings.HasPrefix(n, "transition to ") && n != "transition to ok":
			r = recoveredAt(entries, g.Sensor, "transition to ok")
		default:
			continue
		}
		if r > g.lastAssert && r > g.lastDeassert {
			g.lastDeassert = r
		}
	}
	var out []*selGroup
	for _, g := range order {
		if g.Count == 0 {
			continue // only deassertions in the kept part of the log
		}
		if g.v.ok && g.v.sev >= model.Warn && g.Recent > 0 {
			g.Severity = g.v.sev
			if g.Recovered() && g.v.key != "memory_ue" {
				g.Severity--
			}
		} else if g.v.ok && g.v.sev > model.OK {
			g.Severity = model.Info
		}
		out = append(out, g)
	}
	return out
}

// recoveredAt is the index of the last asserted event on sensor whose text
// is recovery, or -1.
func recoveredAt(entries []*selEntry, sensor, recovery string) int {
	at := -1
	for i, e := range entries {
		if e.Sensor == sensor && !e.Deasserted && normEvent(e.Event) == recovery {
			at = i
		}
	}
	return at
}

func cleanEvent(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "()") {
		s = strings.TrimSpace(strings.TrimSuffix(s, "()"))
	}
	return s
}

// SELInfo is `ipmitool sel info`.
type SELInfo struct {
	Entries     int    `json:"entries"`
	PercentUsed *int   `json:"percentUsed,omitempty"`
	FreeBytes   *int   `json:"freeBytes,omitempty"`
	Overflow    bool   `json:"overflow,omitempty"`
	LastAdd     string `json:"lastAdd,omitempty"`
	LastDel     string `json:"lastDel,omitempty"`
}

func parseSELInfo(out string) (SELInfo, bool) {
	kv := colonKV(out)
	var si SELInfo
	if len(kv) == 0 {
		return si, false
	}
	si.Entries = atoiPrefix(kv["Entries"])
	if v := strings.TrimSpace(kv["Percent Used"]); strings.HasSuffix(v, "%") {
		n := atoiPrefix(v)
		si.PercentUsed = &n
	}
	if v := kv["Free Space"]; v != "" && v[0] >= '0' && v[0] <= '9' {
		n := atoiPrefix(v)
		si.FreeBytes = &n
	}
	si.Overflow = strings.EqualFold(strings.TrimSpace(kv["Overflow"]), "true")
	si.LastAdd = kv["Last Add Time"]
	si.LastDel = kv["Last Del Time"]
	_, ok := kv["Entries"]
	return si, ok
}

// colonKV parses "Key   : value" lines (sel info, chassis status, mc
// info, lan print). Continuation lines with an empty key are ignored.
func colonKV(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, dup := m[k]; !dup {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func atoiPrefix(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			break
		}
	}
	return n
}
