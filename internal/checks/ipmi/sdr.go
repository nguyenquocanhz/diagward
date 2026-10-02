package ipmi

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/model"
)

// Sensor is one SDR record from `ipmitool sdr elist`:
//
//	Fan1A RPM        | 30h | ok  |  7.1 | 3600 RPM
//	PS1 Status       | C8h | ok  | 10.1 | Presence detected, Failure detected
type Sensor struct {
	Name     string         `json:"name"`
	Number   string         `json:"number,omitempty"` // "30h"
	Status   string         `json:"status"`           // ok, ns, lnc, unc, lcr, ucr, lnr, unr (nc/cr/nr without -e)
	Entity   string         `json:"entity,omitempty"` // "10.1"
	Reading  string         `json:"reading"`
	Value    *float64       `json:"value,omitempty"`
	Unit     string         `json:"unit,omitempty"`
	States   []string       `json:"states,omitempty"`
	Class    string         `json:"class"`
	Severity model.Severity `json:"severity"`

	entityID, instance int
	key                string // finding key for discrete problems
	comp               string
	line               string
}

// Readable reports whether the BMC returned a value (ns = "no reading",
// "Disabled": absent component or sensor not scanned).
func (s *Sensor) Readable() bool { return s.Status != "ns" }

var sdrNumRe = regexp.MustCompile(`^[0-9A-Fa-f]{2}h$`)
var analogRe = regexp.MustCompile(`^(-?[0-9]+(?:\.[0-9]+)?)\s+([A-Za-z][A-Za-z %/]*?)\s*(?:,\s*(.*))?$`)

// parseSDR parses `ipmitool sdr elist`. Lines that are not five
// pipe-separated columns (e.g. "Unable to send command: Invalid argument",
// which ipmitool interleaves on some BMCs) are skipped.
func parseSDR(out string) []*Sensor {
	var list []*Sensor
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		f := strings.SplitN(line, "|", 5)
		if len(f) != 5 {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if f[0] == "" || !sdrNumRe.MatchString(f[1]) {
			continue
		}
		s := &Sensor{Name: f[0], Number: f[1], Status: strings.ToLower(f[2]), Entity: f[3], Reading: f[4], line: strings.TrimRight(line, " ")}
		if a, b, ok := strings.Cut(f[3], "."); ok {
			s.entityID, _ = strconv.Atoi(a)
			s.instance, _ = strconv.Atoi(b)
		}
		s.parseReading()
		s.Class = classify(s.Name, s.entityID, s.Unit, s.States)
		s.judge()
		list = append(list, s)
	}
	return list
}

func (s *Sensor) parseReading() {
	r := s.Reading
	switch strings.ToLower(r) {
	case "", "no reading", "disabled", "not readable", "na":
		return
	}
	if m := analogRe.FindStringSubmatch(r); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			s.Value = &v
			s.Unit = m[2]
			s.States = splitStates(m[3])
			return
		}
	}
	if strings.HasPrefix(r, "0x") { // raw discrete value (sdr list without -e)
		return
	}
	s.States = splitStates(r)
}

// splitStates splits the comma-separated asserted states. One ipmitool
// state text itself contains a comma ("AC out-of-range, but present").
func splitStates(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ", ")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(out) > 0 && strings.HasPrefix(strings.ToLower(p), "but present") {
			out[len(out)-1] += ", " + p
			continue
		}
		out = append(out, p)
	}
	return out
}

// judge sets the severity. Threshold status per ipmitool
// ipmi_sdr_get_thresh_status: nc/lnc/unc = non-critical (Warn), cr/lcr/ucr
// = critical, nr/lnr/unr = non-recoverable (both Crit: the BMC itself says
// the sensor is past its critical threshold). Discrete sensors always show
// "ok" in that column (ipmitool issue #176), so their asserted states are
// judged with the rule table.
func (s *Sensor) judge() {
	s.comp = classComponent(s.Class)
	switch s.Status {
	case "nc", "lnc", "unc":
		s.Severity = model.Warn
	case "cr", "lcr", "ucr", "nr", "lnr", "unr":
		s.Severity = model.Crit
	}
	if !s.Readable() {
		return
	}
	best := model.OK
	for _, st := range s.States {
		v := judge(st, s.Class, s.Name)
		if !v.ok || v.sev <= best {
			continue
		}
		best, s.key, s.comp = v.sev, v.key, v.comp
	}
	s.Severity = model.Worst(s.Severity, best)
}

// thresholdDir says whether a threshold status is a low or high excursion.
func thresholdDir(status string) string {
	switch status {
	case "lnc", "lcr", "lnr":
		return "low"
	case "unc", "ucr", "unr":
		return "high"
	}
	return ""
}

// PSU is one power supply, from SDR records and FRU data.
type PSU struct {
	Number     int            `json:"number"`
	Present    *bool          `json:"present,omitempty"`
	Failed     bool           `json:"failed,omitempty"`
	InputLost  bool           `json:"inputLost,omitempty"`
	Predictive bool           `json:"predictive,omitempty"`
	States     []string       `json:"states,omitempty"`
	Watts      *float64       `json:"watts,omitempty"`
	Volts      *float64       `json:"volts,omitempty"`
	Amps       *float64       `json:"amps,omitempty"`
	Vendor     string         `json:"vendor,omitempty"`
	Model      string         `json:"model,omitempty"`
	PartNumber string         `json:"partNumber,omitempty"`
	Serial     string         `json:"serial,omitempty"`
	Severity   model.Severity `json:"severity"`
	sensors    []*Sensor
}

// Label is "PSU 1".
func (p *PSU) Label() string { return "PSU " + strconv.Itoa(p.Number) }

func (p *PSU) part() *model.Part {
	return &model.Part{Kind: "psu", Vendor: p.Vendor, Model: strings.TrimSpace(strings.TrimSpace(p.Model + " " + p.PartNumber)), Serial: p.Serial, Location: p.Label()}
}

// buildPSUs groups power-supply sensors by PSU number: the entity instance
// for entity 10 (power supply), else the digits in the name.
func buildPSUs(sensors []*Sensor) []*PSU {
	idx := map[int]*PSU{}
	var order []int
	for _, s := range sensors {
		n := 0
		switch {
		case s.entityID == 10 && s.instance > 0:
			n = s.instance
		case s.Class == clPSU:
			n = psuNumber(s.Name)
		}
		if n <= 0 || n > 16 {
			continue
		}
		p := idx[n]
		if p == nil {
			p = &PSU{Number: n}
			idx[n] = p
			order = append(order, n)
		}
		p.sensors = append(p.sensors, s)
		if !s.Readable() {
			continue
		}
		if s.Value != nil {
			switch strings.ToLower(s.Unit) {
			case "watts":
				p.Watts = s.Value
			case "volts":
				p.Volts = s.Value
			case "amps":
				p.Amps = s.Value
			}
		}
		for _, st := range s.States {
			n := normEvent(st)
			switch {
			case n == "presence detected" || n == "present" || n == "device present":
				p.Present = boolp(true)
			case n == "absent" || n == "device absent":
				p.Present = boolp(false)
			case strings.Contains(n, "failure detected"):
				p.Failed = true
			case strings.Contains(n, "ac lost") || strings.Contains(n, "out-of-range"):
				p.InputLost = true
			case strings.Contains(n, "predictive failure") && !strings.Contains(n, "deasserted"):
				p.Predictive = true
			}
			if v := judge(st, s.Class, s.Name); (v.ok && v.sev > 0) || strings.Contains(n, "presen") || n == "absent" {
				if !contains(p.States, st) {
					p.States = append(p.States, st)
				}
			}
		}
		if s.Class != clTemp {
			p.Severity = model.Worst(p.Severity, s.Severity)
		}
	}
	// keep only real PSUs: ones with a status/presence sensor or readings
	var out []*PSU
	for _, n := range sortedInts(order) {
		p := idx[n]
		if p.Present != nil || p.Failed || p.InputLost || len(p.States) > 0 || p.Watts != nil || p.Amps != nil || p.Volts != nil {
			if p.Present != nil && !*p.Present {
				p.Severity = model.Worst(p.Severity, model.Info)
			}
			out = append(out, p)
		}
	}
	return out
}

func boolp(b bool) *bool { return &b }

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func sortedInts(a []int) []int {
	b := append([]int(nil), a...)
	for i := 1; i < len(b); i++ {
		for j := i; j > 0 && b[j] < b[j-1]; j-- {
			b[j], b[j-1] = b[j-1], b[j]
		}
	}
	return b
}
