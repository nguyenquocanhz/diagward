// Package ras parses machine-check and memory-error history recorded by
// rasdaemon (ras-mc-ctl --summary / --errors) and mcelog (/var/log/mcelog,
// mcelog --client). The cpu domain reports processor machine checks; the
// memory domain reports the memory-controller events.
//
// Formats follow the tools' source code:
//   - ras-mc-ctl (Perl, rasdaemon <= 0.8.x): util/ras-mc-ctl.in, subs
//     summary() and errors().
//   - rasdaemon MCE decoding: mce-intel.c / mce-amd*.c (mcistatus_msg words
//     such as "Corrected_error", "Uncorrected_error", "CECC", "UECC").
//   - mcelog: mcelog.c dump_mce(), p4.c decode_mci(), memdb.c
//     dump_memory_errors().
package ras

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Class is the severity class of one hardware error record.
type Class int

const (
	Unknown     Class = iota
	Corrected         // corrected by hardware (ECC, retry): no data lost
	Deferred          // AMD: uncorrectable data found but not yet consumed
	Uncorrected       // data lost or poisoned; the OS may have killed a process
	Fatal             // processor context corrupt / system fatal
	Thermal           // thermal-throttle notification, not an error
)

func (c Class) String() string {
	return [...]string{"unknown", "corrected", "deferred", "uncorrected", "fatal", "thermal"}[c]
}

// MCE is one machine-check record.
type MCE struct {
	Source string    `json:"source"`         // "rasdaemon" or "mcelog"
	Time   time.Time `json:"time,omitzero"`  // zero when the record has no usable time
	CPU    int       `json:"cpu"`            // logical CPU, -1 when unknown
	Socket int       `json:"socket"`         // -1 when unknown
	Bank   string    `json:"bank,omitempty"` // "5", "Unified Memory Controller (bank=21)"
	Class  Class     `json:"-"`
	Kind   string    `json:"class"`
	Memory bool      `json:"memory"`         // memory-controller error (a DIMM, not the CPU)
	Msg    string    `json:"msg,omitempty"`  // decoded error text
	Hint   string    `json:"hint,omitempty"` // e.g. "Large number of corrected cache errors"
	Raw    string    `json:"-"`              // one-line evidence
}

func (m *MCE) finish() {
	if m.Class == Unknown {
		m.Class = classify(m.Msg)
	}
	m.Kind = m.Class.String()
	low := strings.ToLower(m.Msg + " " + m.Bank)
	if strings.Contains(low, "memory controller") || strings.Contains(low, "memory_channel=") ||
		strings.Contains(low, "memory read error") || strings.Contains(low, "memory scrubbing error") {
		m.Memory = true
	}
}

func classify(msg string) Class {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "heated above trip temperature") || strings.Contains(l, "below trip temperature"):
		return Thermal
	case strings.Contains(l, "system fatal") || strings.Contains(l, "processor_context_corrupt") || strings.Contains(l, "processor context corrupt"):
		return Fatal
	case strings.Contains(l, "uncorrected") || strings.Contains(l, "uecc"):
		return Uncorrected
	case strings.Contains(l, "deferred"):
		return Deferred
	case strings.Contains(l, "corrected") || strings.Contains(l, "cecc"):
		return Corrected
	}
	return Unknown
}

// MemEvent is one memory-controller (EDAC) event from rasdaemon.
type MemEvent struct {
	Time     time.Time `json:"time,omitzero"`
	Count    int       `json:"count"`
	Type     string    `json:"type"` // Corrected, Uncorrected, Fatal, Info
	Label    string    `json:"label,omitempty"`
	Location string    `json:"location,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Raw      string    `json:"-"`
}

// Uncorrected reports whether the event lost data.
func (e MemEvent) Uncorrected() bool {
	t := strings.ToLower(e.Type)
	return strings.HasPrefix(t, "uncorrected") || strings.HasPrefix(t, "fatal")
}

// MemCount is one row of the "Memory controller events summary".
type MemCount struct {
	Type     string `json:"type"`
	Label    string `json:"label,omitempty"`
	Location string `json:"location,omitempty"`
	Count    int    `json:"count"`
	Raw      string `json:"-"`
}

// Uncorrected reports whether the row counts lost-data events.
func (c MemCount) Uncorrected() bool {
	t := strings.ToLower(c.Type)
	return strings.HasPrefix(t, "uncorrected") || strings.HasPrefix(t, "fatal")
}

// MsgCount is a "<count> <message>" summary row (MCE, AER, disk).
type MsgCount struct {
	Msg   string `json:"msg"`
	Count int    `json:"count"`
	Raw   string `json:"-"`
}

// Report is what ras-mc-ctl printed (summary or errors).
type Report struct {
	Recognized bool       `json:"recognized"` // at least one known section header was seen
	Mem        []MemCount `json:"mem,omitempty"`
	MemEvents  []MemEvent `json:"memEvents,omitempty"`
	MCECounts  []MsgCount `json:"mceCounts,omitempty"`
	MCEs       []MCE      `json:"mces,omitempty"`
	AER        []MsgCount `json:"aer,omitempty"`
	Disk       []MsgCount `json:"disk,omitempty"`
	MemFailure []MsgCount `json:"memFailure,omitempty"`
	Omitted    int        `json:"omitted,omitempty"` // records the collector left out
}

// MemTotal returns (corrected, uncorrected) event totals.
func (r Report) MemTotal() (ce, ue int) {
	for _, m := range r.Mem {
		if m.Uncorrected() {
			ue += m.Count
		} else if strings.HasPrefix(strings.ToLower(m.Type), "corrected") {
			ce += m.Count
		}
	}
	for _, e := range r.MemEvents {
		if e.Uncorrected() {
			ue += e.Count
		} else if strings.HasPrefix(strings.ToLower(e.Type), "corrected") {
			ce += e.Count
		}
	}
	return
}

var (
	reSumMem   = regexp.MustCompile(`^(\S+) on DIMM Label\(s\): '(.*)' location: (\S+) errors: (\d+)`)
	reSumCount = regexp.MustCompile(`^(\d+) (.*?) errors(?:: (.*))?$`)
	reDisk     = regexp.MustCompile(`^(\S+) has (\d+) errors`)
	reMemFail  = regexp.MustCompile(`^(.*) errors: (\d+)$`)
	reRecord   = regexp.MustCompile(`^(\d+) (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4}|\S+) (.*)$`)
	reMemEvt   = regexp.MustCompile(`^(\d+) (\S+) error\(s\): (.*?) at (.*?) location: (\S+?),`)
	rePyEvents = regexp.MustCompile(`^(.*): (\d+) event\(s\)$`)
	reOmitted  = regexp.MustCompile(`^\.\.\. (\d+) older records omitted`)
)

const rasTime = "2006-01-02 15:04:05 -0700"

// section names as ras-mc-ctl prints them (summary and errors).
func sectionOf(line string) (string, bool) {
	l := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(l, "Memory controller events"):
		return "mem", true
	case strings.HasPrefix(l, "PCIe AER events"):
		return "aer", true
	case strings.HasPrefix(l, "MCE records summary"), strings.HasPrefix(l, "MCE events"):
		return "mce", true
	case strings.HasPrefix(l, "Disk errors"):
		return "disk", true
	case strings.HasPrefix(l, "Memory failure events"):
		return "memfail", true
	case strings.HasPrefix(l, "No ") && strings.HasSuffix(l, "errors."):
		return "", true
	case strings.HasSuffix(l, "summary:") || strings.HasSuffix(l, "events:") || strings.HasSuffix(l, "records summary:"):
		return "other", true // ARM, Extlog, devlink, CXL, SIGNAL, vendor tables
	}
	return "", false
}

// Parse reads ras-mc-ctl --summary or --errors output (both share section
// headers). It also accepts the Python ras-mc-ctl (rasdaemon >= 1.0)
// "database --summary" layout, as far as table names and counts go.
func Parse(s string) Report {
	var r Report
	sec := ""
	pyTable := ""
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if m := reOmitted.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			r.Omitted += n
			continue
		}
		if name, ok := sectionOf(raw); ok && !strings.HasPrefix(raw, "\t") && !strings.HasPrefix(raw, " ") {
			r.Recognized = true
			sec = name
			continue
		}
		// Python layout: "Hostname: x", "  mc_event:", "    k=v, ...: N event(s)".
		if strings.HasPrefix(line, "Hostname:") {
			r.Recognized = true
			continue
		}
		if strings.HasSuffix(line, ":") && !strings.Contains(line, " ") {
			pyTable = strings.TrimSuffix(line, ":")
			continue
		}
		if m := rePyEvents.FindStringSubmatch(line); m != nil && (pyTable != "" || !strings.Contains(m[1], " ")) {
			r.Recognized = true
			n, _ := strconv.Atoi(m[2])
			table, fields := pyTable, m[1]
			if !strings.Contains(fields, "=") { // "  mc_event: 3 event(s)"
				table, fields = fields, ""
			}
			parsePy(&r, table, fields, n, raw)
			continue
		}
		switch sec {
		case "mem":
			if m := reSumMem.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[4])
				r.Mem = append(r.Mem, MemCount{Type: m[1], Label: m[2], Location: m[3], Count: n, Raw: line})
			} else if e, ok := parseMemEvent(line); ok {
				r.MemEvents = append(r.MemEvents, e)
			}
		case "mce":
			if e, ok := parseRasMCE(line); ok {
				r.MCEs = append(r.MCEs, e)
			} else if m := reSumCount.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				r.MCECounts = append(r.MCECounts, MsgCount{Msg: m[2], Count: n, Raw: line})
			}
		case "aer":
			if m := reSumCount.FindStringSubmatch(line); m != nil && !strings.Contains(line, " error: ") {
				n, _ := strconv.Atoi(m[1])
				msg := m[2]
				if m[3] != "" {
					msg += ": " + m[3]
				}
				r.AER = append(r.AER, MsgCount{Msg: msg, Count: n, Raw: line})
			} else if rec := reRecord.FindStringSubmatch(line); rec != nil {
				r.AER = append(r.AER, MsgCount{Msg: rec[3], Count: 1, Raw: line})
			}
		case "disk":
			if m := reDisk.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[2])
				r.Disk = append(r.Disk, MsgCount{Msg: m[1], Count: n, Raw: line})
			} else if rec := reRecord.FindStringSubmatch(line); rec != nil {
				r.Disk = append(r.Disk, MsgCount{Msg: rec[3], Count: 1, Raw: line})
			}
		case "memfail":
			if rec := reRecord.FindStringSubmatch(line); rec != nil && strings.Contains(line, "error:") {
				r.MemFailure = append(r.MemFailure, MsgCount{Msg: rec[3], Count: 1, Raw: line})
			} else if m := reMemFail.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[2])
				r.MemFailure = append(r.MemFailure, MsgCount{Msg: m[1], Count: n, Raw: line})
			}
		}
	}
	return r
}

// parsePy maps a Python ras-mc-ctl summary row onto the report. Only
// mc_event and mce_record matter here; the rest are counted as "other".
func parsePy(r *Report, table, fields string, n int, raw string) {
	kv := map[string]string{}
	for _, f := range strings.Split(fields, ", ") {
		if k, v, ok := strings.Cut(f, "="); ok {
			kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), "'\"")
		}
	}
	switch table {
	case "mc_event":
		t := kv["err_type"]
		if t == "" {
			t = "Unknown"
		}
		r.Mem = append(r.Mem, MemCount{Type: t, Label: kv["label"], Count: n, Raw: strings.TrimSpace(raw)})
	case "mce_record":
		msg := kv["error_msg"]
		if s := kv["mcistatus_msg"]; s != "" {
			msg += " " + s
		}
		r.MCECounts = append(r.MCECounts, MsgCount{Msg: strings.TrimSpace(msg), Count: n, Raw: strings.TrimSpace(raw)})
	case "aer_event":
		r.AER = append(r.AER, MsgCount{Msg: kv["err_type"] + " " + kv["err_msg"], Count: n, Raw: strings.TrimSpace(raw)})
	case "disk_errors":
		r.Disk = append(r.Disk, MsgCount{Msg: kv["dev"], Count: n, Raw: strings.TrimSpace(raw)})
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(rasTime, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseMemEvent parses "<id> <time> <count> <type> error(s): <msg> at
// <label> location: <mc:top:mid:low>, addr ..., grain ..., syndrome ...".
func parseMemEvent(line string) (MemEvent, bool) {
	rec := reRecord.FindStringSubmatch(line)
	if rec == nil {
		return MemEvent{}, false
	}
	rest := rec[3]
	f := strings.SplitN(rest, " ", 3)
	if len(f) < 3 {
		return MemEvent{}, false
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return MemEvent{}, false
	}
	e := MemEvent{Time: parseTime(rec[2]), Count: n, Type: f[1], Raw: line}
	body := strings.TrimPrefix(f[2], "error(s): ")
	if i := strings.Index(body, " location: "); i >= 0 {
		head := body[:i]
		loc := body[i+len(" location: "):]
		if j := strings.IndexByte(loc, ','); j >= 0 {
			loc = loc[:j]
		}
		e.Location = strings.TrimSpace(loc)
		if k := strings.LastIndex(head, " at "); k >= 0 {
			e.Msg = strings.TrimSpace(head[:k])
			e.Label = strings.TrimSpace(head[k+4:])
		} else {
			e.Msg = strings.TrimSpace(head)
		}
	} else {
		e.Msg = strings.TrimSpace(body)
	}
	if e.Count <= 0 {
		e.Count = 1
	}
	return e, true
}

// parseRasMCE parses "<id> <time> error: <msg>, CPU <vendor>, bank <name>,
// mcg <...>, mci <...>, ..., cpu=0x..., socketid=0x..., bank=0x...".
func parseRasMCE(line string) (MCE, bool) {
	rec := reRecord.FindStringSubmatch(line)
	if rec == nil || !strings.HasPrefix(rec[3], "error:") {
		return MCE{}, false
	}
	m := MCE{Source: "rasdaemon", Time: parseTime(rec[2]), CPU: -1, Socket: -1, Raw: line}
	body := strings.TrimSpace(strings.TrimPrefix(rec[3], "error:"))
	parts := strings.Split(body, ", ")
	var msg, mci []string
	for i, p := range parts {
		switch {
		case strings.HasPrefix(p, "bank ") && m.Bank == "":
			m.Bank = strings.TrimPrefix(p, "bank ")
		case strings.HasPrefix(p, "mci "):
			mci = append(mci, strings.TrimPrefix(p, "mci "))
		case strings.HasPrefix(p, "cpu=0x"):
			if v, err := strconv.ParseInt(strings.TrimPrefix(p, "cpu=0x"), 16, 32); err == nil {
				m.CPU = int(v)
			}
		case strings.HasPrefix(p, "socketid=0x"):
			if v, err := strconv.ParseInt(strings.TrimPrefix(p, "socketid=0x"), 16, 32); err == nil {
				m.Socket = int(v)
			}
		case strings.HasPrefix(p, "bank=0x") && m.Bank == "":
			if v, err := strconv.ParseInt(strings.TrimPrefix(p, "bank=0x"), 16, 32); err == nil {
				m.Bank = strconv.Itoa(int(v))
			}
		case strings.HasPrefix(p, "CPU "), strings.HasPrefix(p, "mcg "), strings.Contains(p, "=0x"):
		case strings.HasPrefix(p, "memory_channel="):
			msg = append(msg, p)
		case strings.HasPrefix(p, "Large number of corrected"):
			m.Hint = p
		default:
			if i == 0 || len(mci) == 0 {
				msg = append(msg, p)
			}
		}
	}
	m.Msg = strings.TrimSpace(strings.Join(msg, ", "))
	// Classification looks at the mci status words first: rasdaemon's Intel
	// decoder writes "Corrected_error" or "Uncorrected_error" for every
	// record; AMD writes CECC/UECC and puts the severity in the message.
	cls := classify(strings.Join(mci, " "))
	if c := classify(m.Msg); c == Fatal || c == Thermal || (cls == Unknown && c != Unknown) || (c == Uncorrected && cls == Corrected) {
		cls = c
	}
	if strings.Contains(strings.Join(mci, " "), "Processor_context_corrupt") {
		cls = Fatal
	}
	m.Class = cls
	m.finish()
	if m.Msg == "" {
		m.Msg = strings.Join(mci, " ")
	}
	return m, true
}

// SummaryClass classifies an "MCE records summary" message, whose text is
// the decoded error message only.
func SummaryClass(msg string) Class { return classify(msg) }

// SummaryMemory reports whether a summary message names a memory controller.
func SummaryMemory(msg string) bool {
	l := strings.ToLower(msg)
	return strings.Contains(l, "memory controller")
}

// ---- mcelog ----

var (
	reMCHead   = regexp.MustCompile(`^CPU (\d+) (BANK (\d+)|THERMAL EVENT|.*)`)
	reMCTime   = regexp.MustCompile(`^TIME (\d+)`)
	reSocketID = regexp.MustCompile(`SOCKETID ([0-9a-fA-F]+)`)
	reSyslog   = regexp.MustCompile(`^(?:\S+\s+\d+\s+[\d:]+\s+\S+\s+mcelog\[\d+\]:\s?|\d{4}-\d\d-\d\dT\S+\s+\S+\s+mcelog\[\d+\]:\s?)`)
)

// Mcelog parses decoded mcelog records (the /var/log/mcelog file). Records
// begin with "Hardware event. This is not a software error." or "MCE <n>".
// Lines from a syslog-style log ("... mcelog[123]: ") are accepted too.
func Mcelog(s string) []MCE {
	var (
		out []MCE
		cur *MCE
		mca bool
		msg []string
		ev  []string
	)
	flush := func() {
		if cur == nil {
			return
		}
		cur.Msg = strings.TrimSpace(strings.Join(msg, " "))
		if cur.Class == Unknown {
			cur.Class = classify(cur.Msg)
		}
		cur.finish()
		cur.Raw = strings.Join(ev, " | ")
		out = append(out, *cur)
		cur, mca, msg, ev = nil, false, nil, nil
	}
	start := func() {
		flush()
		cur = &MCE{Source: "mcelog", CPU: -1, Socket: -1}
	}
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(reSyslog.ReplaceAllString(raw, ""))
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "Hardware event. This is not a software error"):
			start()
			continue
		case strings.HasPrefix(line, "MCE ") && isNum(strings.TrimPrefix(line, "MCE ")):
			if cur == nil || cur.CPU >= 0 || len(ev) > 0 {
				start()
			}
			continue
		}
		if cur == nil {
			// A record without the disclaimer line (truncated log head).
			if !reMCHead.MatchString(line) {
				continue
			}
			start()
		}
		if len(ev) < 8 {
			ev = append(ev, line)
		}
		switch {
		case reMCHead.MatchString(line) && cur.CPU < 0:
			m := reMCHead.FindStringSubmatch(line)
			cur.CPU, _ = strconv.Atoi(m[1])
			switch {
			case m[3] != "":
				cur.Bank = m[3]
			case strings.HasPrefix(m[2], "THERMAL EVENT"):
				cur.Bank = "THERMAL EVENT"
				cur.Class = Thermal
			default:
				cur.Bank = strings.TrimSpace(strings.SplitN(m[2], " TSC ", 2)[0])
			}
		case reMCTime.MatchString(line):
			if v, err := strconv.ParseInt(reMCTime.FindStringSubmatch(line)[1], 10, 64); err == nil && v > 0 {
				cur.Time = time.Unix(v, 0).UTC()
			}
		case line == "Uncorrected error":
			if cur.Class != Fatal {
				cur.Class = Uncorrected
			}
		case strings.HasPrefix(line, "Corrected error"):
			if cur.Class == Unknown {
				cur.Class = Corrected
			}
		case line == "Processor context corrupt":
			cur.Class = Fatal
		case strings.Contains(line, "heated above trip temperature"):
			cur.Class = Thermal
			msg = append(msg, line)
		case strings.HasPrefix(line, "Large number of corrected cache errors"):
			cur.Hint = "Large number of corrected cache errors"
		case strings.HasPrefix(line, "MCA: "):
			mca = true
			msg = append(msg, strings.TrimPrefix(line, "MCA: "))
		case strings.HasPrefix(line, "STATUS "):
			mca = false
		case reSocketID.MatchString(line) && strings.Contains(line, "APICID"):
			if v, err := strconv.ParseInt(reSocketID.FindStringSubmatch(line)[1], 16, 32); err == nil {
				cur.Socket = int(v)
			}
		case mca:
			msg = append(msg, line)
		}
	}
	flush()
	return out
}

func isNum(s string) bool {
	_, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil
}

// ClientDIMM is one entry of "mcelog --client" (memdb.c dump_dimm): error
// counters per socket/channel/DIMM since the daemon started.
type ClientDIMM struct {
	Socket   string   `json:"socket"`
	Channel  string   `json:"channel"`
	DIMM     string   `json:"dimm"`
	Name     string   `json:"name,omitempty"`     // DMI_NAME (when the BIOS table matched)
	Location string   `json:"location,omitempty"` // DMI_LOCATION
	CETotal  int      `json:"ceTotal"`
	CE24h    int      `json:"ce24h"`
	UCTotal  int      `json:"ucTotal"`
	UC24h    int      `json:"uc24h"`
	Raw      []string `json:"-"`
}

// Target names the DIMM as precisely as the record allows.
func (d ClientDIMM) Target() string {
	if d.Name != "" {
		return d.Name
	}
	s := "socket " + d.Socket
	if d.Channel != "any" {
		s += " channel " + d.Channel
	}
	if d.DIMM != "any" {
		s += " DIMM " + d.DIMM
	}
	return s
}

// Specific reports whether the entry is one DIMM (not an "any" aggregate).
func (d ClientDIMM) Specific() bool { return d.Channel != "any" && d.DIMM != "any" }

var (
	reClientHead  = regexp.MustCompile(`^SOCKET (\S+) CHANNEL (\S+) DIMM (\S+)`)
	reClientTotal = regexp.MustCompile(`^(\d+) total`)
	reClient24h   = regexp.MustCompile(`^(\d+) in (\S+)`)
	reDMIName     = regexp.MustCompile(`DMI_NAME "([^"]*)"`)
	reDMILoc      = regexp.MustCompile(`DMI_LOCATION "([^"]*)"`)
)

// McelogClient parses "mcelog --client" output.
func McelogClient(s string) []ClientDIMM {
	var (
		out  []ClientDIMM
		cur  *ClientDIMM
		kind string
	)
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if m := reClientHead.FindStringSubmatch(line); m != nil {
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &ClientDIMM{Socket: m[1], Channel: m[2], DIMM: m[3], Raw: []string{line}}
			kind = ""
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "DMI_NAME") || strings.HasPrefix(line, "DMI_LOCATION"):
			if m := reDMIName.FindStringSubmatch(line); m != nil {
				cur.Name = strings.TrimSpace(m[1])
			}
			if m := reDMILoc.FindStringSubmatch(line); m != nil {
				cur.Location = strings.TrimSpace(m[1])
			}
		case strings.HasPrefix(line, "corrected memory errors"):
			kind = "ce"
		case strings.HasPrefix(line, "uncorrected memory errors"):
			kind = "uc"
		case reClientTotal.MatchString(line):
			n, _ := strconv.Atoi(reClientTotal.FindStringSubmatch(line)[1])
			if kind == "ce" {
				cur.CETotal = n
			} else if kind == "uc" {
				cur.UCTotal = n
			}
			cur.Raw = append(cur.Raw, kind+": "+line)
		case reClient24h.MatchString(line):
			n, _ := strconv.Atoi(reClient24h.FindStringSubmatch(line)[1])
			if kind == "ce" {
				cur.CE24h = n
			} else if kind == "uc" {
				cur.UC24h = n
			}
			cur.Raw = append(cur.Raw, kind+": "+line)
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}
