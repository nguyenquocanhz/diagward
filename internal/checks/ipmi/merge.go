package ipmi

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// The SDR is the current state of every sensor, the SEL its history. When
// both show the same fault on the same sensor (PSU 2 "Failure detected" in
// the SDR and in the SEL), the report keeps one finding: the current-state
// one, at its severity, with the SEL events folded in as history. A SEL
// fault whose sensor the SDR shows healthy again stays a separate, lower
// history finding (currentState).
//
// Matching is conservative: the same PSU number, or the same sensor name
// in a compatible class (ipmitool prints the SEL sensor name from the same
// SDR record, so a real pair has identical names). Only for the parts a
// chassis has one sensor of — the PSU redundancy sensor, the intrusion
// switch, a single drive sensor — may names differ, and only when the SEL
// name carries no instance number and the SDR has exactly one candidate.
// Memory events naming a DIMM are never folded: the SEL names the module,
// the SDR sensor does not.

// instanceRe finds an instance designator in a sensor name: a digit
// ("PS2 Status", "Drive 0", "FAN3") or a trailing single letter ("Drive B").
var instanceRe = regexp.MustCompile(`[0-9]|(?:^|[\s_-])[A-Za-z]$`)

func hasInstance(name string) bool { return instanceRe.MatchString(strings.TrimSpace(name)) }

// sameName compares sensor names ignoring case and repeated spaces.
func sameName(a, b string) bool {
	return a != "" && strings.EqualFold(strings.Join(strings.Fields(a), " "), strings.Join(strings.Fields(b), " "))
}

// classGroup merges the classes one physical part can show up under: a PSU
// redundancy sensor is "Power Supply" in the SEL and a power unit (entity
// 19 or a "PS Redundancy" name) in the SDR.
func classGroup(cl string) string {
	switch cl {
	case clPSU, clPowerUnit:
		return clPowerUnit
	}
	return cl
}

func isRedundancySensor(s *Sensor) bool {
	if strings.Contains(strings.ToLower(s.Name), "redundan") {
		return true
	}
	for _, st := range s.States {
		if strings.Contains(strings.ToLower(st), "redundan") {
			return true
		}
	}
	return false
}

// matchSensors returns the SDR sensors that are the sensor of a SEL group,
// or nil when that cannot be told for sure. byPSU: matched by PSU number
// (all the sensors of that supply).
func (c *checker) matchSensors(g *selGroup) []*Sensor {
	ms, _ := c.matchSensorsBy(g)
	return ms
}

func (c *checker) matchSensorsBy(g *selGroup) (ms []*Sensor, byPSU bool) {
	if len(c.sensors) == 0 {
		return nil, false
	}
	_, sname, _ := splitSELSensor(g.Sensor)
	if sname == "" {
		sname = g.Sensor
	}
	if strings.HasPrefix(sname, "#") {
		return nil, false // "Memory #0x02": no SDR record named it
	}
	// A power supply: by number, whatever the vendor calls its sensors.
	if strings.HasPrefix(g.v.key, "psu_") || g.Class == clPSU {
		if n := psuNumber(sname); n > 0 {
			var out []*Sensor
			for _, s := range c.sensors {
				byEntity := s.entityID == 10 && s.instance > 0
				if (byEntity && s.instance == n) || (!byEntity && s.Class == clPSU && psuNumber(s.Name) == n) {
					out = append(out, s)
				}
			}
			return out, true
		}
	}
	grp := classGroup(g.Class)
	var out []*Sensor
	for _, s := range c.sensors {
		if sameName(s.Name, sname) && classGroup(s.Class) == grp {
			out = append(out, s)
		}
	}
	if len(out) > 0 || hasInstance(sname) {
		return out, false
	}
	// One-per-chassis parts with a differently named SEL sensor.
	var cands []*Sensor
	for _, s := range c.sensors {
		if classGroup(s.Class) != grp {
			continue
		}
		switch {
		case g.v.key == "redundancy_lost" && grp == clPowerUnit && isRedundancySensor(s),
			g.v.key == "intrusion" && grp == clIntrusion,
			strings.HasPrefix(g.v.key, "drive_") && grp == clDisk:
			cands = append(cands, s)
		}
	}
	if len(cands) == 1 {
		return cands, false
	}
	return nil, false
}

// selDir is the threshold direction a SEL threshold event names.
func selDir(event string) string {
	n := normEvent(event)
	switch {
	case strings.Contains(n, "going low"):
		return "low"
	case strings.Contains(n, "going high"):
		return "high"
	}
	return ""
}

// sameFault reports whether SDR finding f (raised by sensor s) is the fault
// the SEL group logged.
func sameFault(g *selGroup, s *Sensor, f *model.Finding) bool {
	key := strings.TrimPrefix(f.ID, domain+".")
	if key == g.v.key {
		return true
	}
	if strings.HasPrefix(g.v.key, "sensor_") && (key == "sensor_critical" || key == "sensor_warning") {
		d := selDir(g.Event)
		return d == "" || d == thresholdDir(s.Status)
	}
	return false
}

// sdrFindingFor returns the index of the current-state SDR finding for the
// fault a SEL group logged, if exactly one matches.
func (c *checker) sdrFindingFor(g *selGroup) (int, bool) {
	if !g.v.ok || g.v.key == "" || (strings.HasPrefix(g.v.key, "memory_") && len(g.dimms) > 0) {
		return 0, false
	}
	ms, byPSU := c.matchSensorsBy(g)
	if len(ms) > 1 && !byPSU {
		// Several sensors share the name (Dell's two "Temp"): the SEL does
		// not say which one logged the event.
		return 0, false
	}
	idx := -1
	for _, s := range ms {
		i, ok := c.sdrIdx[s]
		if !ok || i >= len(c.res.Findings) || !sameFault(g, s, &c.res.Findings[i]) {
			continue
		}
		if idx >= 0 && idx != i {
			return 0, false // two different findings: ambiguous
		}
		idx = i
	}
	return idx, idx >= 0
}

// foldSEL adds a SEL group to the SDR finding at index i as history.
func (c *checker) foldSEL(i int, g *selGroup) {
	f := &c.res.Findings[i]
	times := model.Tf("%d times", "%d lần", g.Count)
	if g.Count == 1 {
		times = model.T("once", "1 lần")
	}
	when := model.Text{}
	switch {
	case g.First.IsZero():
	case g.Count == 1 || g.First.Equal(g.Last):
		when = model.Tf(", on %s", ", vào %s", fmtTime(g.Last))
	default:
		when = model.T(fmt.Sprintf(", first %s, last %s", fmtTime(g.First), fmtTime(g.Last)),
			fmt.Sprintf(", lần đầu %s, gần nhất %s", fmtTime(g.First), fmtTime(g.Last)))
	}
	f.Detail.EN += fmt.Sprintf(" Logged in the BMC event log (SEL) %s (%q on sensor %q)%s.", times.EN, g.Event, g.Sensor, when.EN)
	f.Detail.VI += fmt.Sprintf(" Nhật ký sự kiện BMC (SEL) đã ghi lỗi này %s (%q trên cảm biến %q)%s.", times.VI, g.Event, g.Sensor, when.VI)
	if g.Recovered() {
		f.Detail.EN += " The SEL shows it cleared (deasserted) afterwards, but the live sensor reports it again now."
		f.Detail.VI += " Theo SEL, lỗi từng hết (deasserted) nhưng cảm biến hiện tại lại đang báo lỗi."
	}
	room := 10 - len(f.Evidence)
	if room <= 0 {
		return
	}
	lines := g.lines
	if len(lines) > room {
		lines = lines[len(lines)-room:] // keep the newest
	}
	f.Evidence = append(f.Evidence, units.Evidence(lines, room)...)
}

// slotRe finds a drive bay or slot number in ipmitool's OEM event details
// ("Drive Fault (Bay 3)", "Drive Present (Slot 05)").
var slotRe = regexp.MustCompile(`(?i)\b(?:bay|slot|disk|drive|hdd)\s*#?\s*[0-9]{1,3}\b`)

// driveTarget names the drive of a SEL drive event as precisely as the log
// allows: the sensor name when it carries the slot ("Drive 3"), else the
// whole sensor column ("Drive Slot HDD Status"), plus the bay or slot from
// the event details when ipmitool decoded one.
func driveTarget(sensor, sname, event string) string {
	t := sname
	if !hasInstance(sname) {
		t = sensor
	}
	if i := strings.Index(event, "("); i >= 0 {
		if m := slotRe.FindString(event[i:]); m != "" && !strings.Contains(strings.ToLower(t), strings.ToLower(m)) {
			t += " (" + m + ")"
		}
	}
	return t
}
