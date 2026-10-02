package redfish

import (
	"sort"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// EventGroup is one kind of BMC log event (same MessageId and message),
// with how often and when it happened.
type EventGroup struct {
	Log       string         `json:"log"`
	MessageID string         `json:"messageId,omitempty"`
	Message   string         `json:"message"`
	Raw       string         `json:"rawSeverity"` // Critical / Warning
	Count     int            `json:"count"`
	First     *time.Time     `json:"first,omitempty"`
	Last      *time.Time     `json:"last,omitempty"`
	Repaired  bool           `json:"repaired,omitempty"`
	Cleared   bool           `json:"cleared,omitempty"`     // a later SEL "Deassert" entry ended it
	Unknown   bool           `json:"unknownTime,omitempty"` // BMC clock unset
	Component string         `json:"component"`
	Severity  model.Severity `json:"severity"`
}

// recentDays: a Critical BMC event newer than this is treated as a current
// problem (Crit); older ones are history (Info). One week covers a fault
// that happened since the last weekly check without re-alarming on faults
// that were long fixed (the BMC log is never cleared on repair).
const recentDays = 7

type rawEntry struct {
	id, msgID, msg, sev, sensor string
	t                           time.Time
	hasTime                     bool
	repaired                    bool
	deassert                    bool // SEL EntryCode "Deassert": the condition ended
	nonHW                       bool // audit, security, configuration: not a hardware event
	count                       int
}

// events reads the entries of every log service and groups the Critical
// and Warning ones.
func (w *walker) events(now time.Time, windowDays int) []EventGroup {
	lgA := w.area("logs")
	cutoff := now.AddDate(0, 0, -windowDays)
	recent := now.AddDate(0, 0, -recentDays)
	groups := map[string]*EventGroup{}
	var order []string
	seenLog := map[string]bool{}
	// The same event often sits in two logs (Dell: SEL and Lifecycle log)
	// with the same time: count it once.
	seenEvent := map[string]bool{}
	// Latest "Deassert" per event kind: a sensor event (Supermicro, OpenBMC,
	// Dell SEL) that was deasserted later has recovered.
	cleared := map[string]time.Time{}
	for _, ls := range w.logs {
		key := normKey(ls.entries)
		if key == "" || seenLog[key] {
			continue
		}
		seenLog[key] = true
		seenEntry := map[string]bool{}
		for _, e := range w.entries(lgA, key) {
			if e.id != "" {
				if seenEntry[e.id] {
					continue
				}
				seenEntry[e.id] = true
			}
			gk := e.msgID + "|" + e.msg
			if e.deassert {
				if e.hasTime && e.t.After(cleared[gk]) {
					cleared[gk] = e.t
				}
				continue
			}
			if e.nonHW || (e.sev != "critical" && e.sev != "warning") {
				continue
			}
			if e.hasTime && e.t.Before(cutoff) {
				continue
			}
			if e.hasTime {
				ek := gk + "|" + e.t.UTC().Format(time.RFC3339)
				if seenEvent[ek] {
					continue
				}
				seenEvent[ek] = true
			}
			g := groups[gk]
			if g != nil && !strings.Contains(g.Log, ls.name) {
				g.Log += ", " + ls.name
			}
			if g == nil {
				g = &EventGroup{Log: ls.name, MessageID: e.msgID, Message: e.msg, Raw: titleCase(e.sev), Repaired: true, Component: eventComponent(e.sensor + " " + e.msg + " " + e.msgID)}
				groups[gk] = g
				order = append(order, gk)
			}
			if e.sev == "critical" {
				g.Raw = "Critical"
			}
			g.Count += e.count
			g.Repaired = g.Repaired && e.repaired
			if !e.hasTime {
				g.Unknown = true
				continue
			}
			t := e.t
			if g.First == nil || t.Before(*g.First) {
				g.First = &t
			}
			if g.Last == nil || t.After(*g.Last) {
				tt := t
				g.Last = &tt
			}
		}
	}
	var out []EventGroup
	for _, k := range order {
		g := groups[k]
		crit := g.Raw == "Critical"
		if c, ok := cleared[k]; ok && g.Last != nil && !c.Before(*g.Last) {
			g.Cleared = true
		}
		switch {
		case g.Repaired, g.Cleared:
			// HPE IML entries marked repaired by a technician.
			g.Severity = model.Info
		case g.Last != nil && !g.Last.Before(recent):
			g.Severity = model.Warn
			if crit {
				g.Severity = model.Crit
			}
		case g.Last == nil && crit:
			// The BMC clock was unset, so the event may be recent: worth a
			// look, but not certain enough for Crit.
			g.Severity = model.Warn
		default:
			g.Severity = model.Info
		}
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return lastOf(out[i]).After(lastOf(out[j]))
	})
	return out
}

func lastOf(g EventGroup) time.Time {
	if g.Last == nil {
		return time.Time{}
	}
	return *g.Last
}

// entries returns the entries of one log: every collected page (the
// collection itself, $skip / $skiptoken pages, nextLink pages) and
// entries read one by one.
func (w *walker) entries(a *area, key string) []rawEntry {
	var out []rawEntry
	pages := []string{key}
	pages = append(pages, w.s.withPrefix(key+"?")...)
	seenPage := map[string]bool{}
	for i := 0; i < len(pages) && i < 200; i++ {
		p := pages[i]
		if seenPage[p] {
			continue
		}
		seenPage[p] = true
		coll := w.s.read(a, p)
		if coll == nil {
			continue
		}
		if n := normKey(nextLink(coll)); n != "" && !seenPage[n] {
			if _, oc, _ := w.s.get(n); oc != outMissing {
				pages = append(pages, n)
			}
		}
		// iLO 4 lists only links in Members and the entries in Items.
		ms, _ := coll["Items"].([]any)
		if len(ms) == 0 {
			ms, _ = coll["Members"].([]any)
		}
		for _, m := range ms {
			mo, _ := m.(map[string]any)
			if mo == nil {
				continue
			}
			if len(mo) <= 2 {
				if full, oc, _ := w.s.get(str(mo, "@odata.id")); oc == outOK {
					mo = full
				}
			}
			out = append(out, entryOf(mo))
		}
	}
	return out
}

func entryOf(m map[string]any) rawEntry {
	hp := hpOem(m)
	e := rawEntry{
		id:       first(str(m, "@odata.id"), str(m, "Id")),
		msgID:    str(m, "MessageId"),
		msg:      oneLine(first(str(m, "Message"), messageFromID(str(m, "MessageId")), str(m, "Name"))),
		sensor:   str(m, "SensorType") + " " + str(m, "OemSensorType") + " " + str(hp, "ClassDescription"),
		count:    1,
		deassert: strings.EqualFold(str(m, "EntryCode"), "Deassert"),
		nonHW:    nonHardware(m),
	}
	e.sev = strings.ToLower(first(str(m, "Severity"), str(m, "MessageSeverity")))
	switch strings.ToLower(str(hp, "Severity")) {
	case "caution":
		if e.sev != "critical" {
			e.sev = "warning"
		}
	case "critical":
		e.sev = "critical"
	case "repaired":
		e.repaired = true
	}
	if b := boolp(hp, "Repaired"); b != nil && *b {
		e.repaired = true
	}
	// HPE IML/IEL entries have no MessageId; class and code identify the event.
	if e.msgID == "" {
		if cl, cd := str(hp, "Class"), str(hp, "Code"); cl != "" && cd != "" {
			e.msgID = "HPE-" + cl + "-" + cd
		}
	}
	if n := num(hp, "Count"); n != nil && *n > 1 && *n < 1e6 {
		e.count = int(*n)
	}
	// HPE keeps the first time in Created and the latest in Oem.Hpe.Updated
	// (iLO 4: Oem.Hp.Updated, the only time on some POST entries).
	for _, v := range []string{str(hp, "Updated"), str(m, "Created"), str(m, "EventTimestamp")} {
		if t, ok := parseTime(v); ok {
			e.t, e.hasTime = t, true
			break
		}
	}
	return e
}

// parseTime reads Redfish timestamps and rejects the placeholder dates of
// a BMC whose clock is unset ("0000-00-00T00:00:00Z", 1970).
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(l, s); err == nil {
			if t.Year() < 2000 {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// messageFromID turns a registry MessageId into readable words when the
// entry has no Message (HPE iLO 5 "Event" log: "iLOEvents.3.7.ServerResetDetected"
// → "Server Reset Detected").
func messageFromID(id string) string {
	i := strings.LastIndexByte(id, '.')
	if i < 0 {
		return "" // not a registry id (Dell SEL "7e012790", Supermicro "0xA401FF")
	}
	id = id[i+1:]
	if id == "" {
		return ""
	}
	var b strings.Builder
	rs := []rune(id)
	for i, r := range rs {
		if i > 0 && r >= 'A' && r <= 'Z' && rs[i-1] >= 'a' && rs[i-1] <= 'z' {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// nonHardware recognises log entries about logins, accounts, security
// settings, configuration jobs and firmware updates, which BMCs log at
// Warning/Critical too (failed logins, "security state at risk", a failed
// configuration job) but which say nothing about the hardware:
//   - Dell Lifecycle log: Oem.Dell.Category Audit, Configuration, Updates,
//     Work Notes (hardware events are "System Health" and "Storage");
//   - HPE iLO 5/6: Oem.Hpe.Categories made only of Security, Administration,
//     Maintenance (and Configuration), never Hardware/Power/...;
//   - Supermicro maintenance log: Oem.Supermicro.Category Account, and
//     root-of-trust / "First AC Power on" entries of its health log;
//   - any entry whose OriginOfCondition is the account, session, security,
//     certificate or update service.
func nonHardware(m map[string]any) bool {
	switch strings.ToLower(str(m, "Oem", "Dell", "Category")) {
	case "audit", "configuration", "updates", "work notes":
		return true
	}
	if strings.EqualFold(str(m, "Oem", "Supermicro", "Category"), "account") {
		return true
	}
	// Supermicro X13/H13 health log: firmware root-of-trust state changes
	// ("[ROT-0017] Security State of BMC JTAG Lockout changed to Unlock")
	// and "[PWR-0020] First AC Power on", both logged as Warning.
	switch strings.ToLower(str(m, "OemSensorType")) {
	case "pfr (rot)", "ac power on":
		return true
	}
	if cats, ok := dig(hpOem(m), "Categories").([]any); ok && len(cats) > 0 {
		admin, other := false, false
		for _, c := range cats {
			s, _ := c.(string)
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "security", "administration", "maintenance":
				admin = true
			case "configuration":
			default:
				other = true
			}
		}
		if admin && !other {
			return true
		}
	}
	origin := strings.ToLower(link(m, "Links", "OriginOfCondition"))
	for _, s := range []string{"/accountservice", "/sessionservice", "/securityservice", "/certificateservice", "/updateservice"} {
		if strings.Contains(origin, s) {
			return true
		}
	}
	return false
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// eventComponent guesses the component from the sensor type, message and
// MessageId (Dell ids carry the subsystem: PSU0003, FAN0001, TMP0120,
// MEM0001, PDR1016, CPU0000...).
func eventComponent(text string) string {
	t := strings.ToLower(text)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(t, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("power supply", "power_supply", "powersupply", "psu", "power input", "ac lost", "input lost"):
		return model.CompPower
	case has("fan"):
		return model.CompFan
	case has("temperature", "thermal", "tmp0", "overheat"):
		return model.CompThermal
	case has("virtual disk", "logical drive", "raid", "array controller", "storage controller", "vdr", "volume", "rebuild", "degraded"):
		return model.CompRAID
	case has("drive", "disk", "pdr", "hdd", "ssd", "nvme", "storage enclosure"):
		return model.CompDisk
	case has("memory", "dimm", "ecc", "mem0"):
		return model.CompMemory
	case has("processor", "cpu", "ierr", "machine check", "mce"):
		return model.CompCPU
	case has("voltage", "vrm", "volt"):
		return model.CompPower
	}
	return model.CompLogs
}
