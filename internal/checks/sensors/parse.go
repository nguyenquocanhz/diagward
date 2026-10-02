package sensors

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
)

// Sensor kinds, named after the hwmon file prefixes.
const (
	kTemp      = "temp"
	kFan       = "fan"
	kIn        = "in"
	kPower     = "power"
	kCurr      = "curr"
	kIntrusion = "intrusion"
)

// Where a reading came from.
const (
	srcLM      = "lm-sensors"
	srcHwmon   = "hwmon"
	srcThermal = "thermal-zone"
	srcACPI    = "acpi-wmi"
	srcLHM     = "LibreHardwareMonitor"
	srcOHM     = "OpenHardwareMonitor"
	srcSMBIOS  = "smbios"
)

// reading is one sensor channel (temp1, fan2, in0...) of one chip, in
// display units: °C, RPM, V, W, A.
type reading struct {
	Source string
	Chip   string // "coretemp-isa-0000", "hwmon3 (nct6779)", "thermal_zone0"
	Driver string // hwmon name: coretemp, k10temp, nvme, nct6775...
	Model  string // device model, when sysfs has one (nvme, drivetemp)
	Kind   string
	Index  string // "temp1"
	Label  string // "Package id 0", "CPU Fan", "temp1"

	Input     *float64
	Min       *float64
	Max       *float64 // temperatures: the "high" threshold
	Crit      *float64
	Emergency *float64
	Alarm     *bool
	MinAlarm  *bool
	MaxAlarm  *bool
	CritAlarm *bool
	Fault     *bool
	// Thermal zones and Windows: trip points that are not plain max/crit.
	Passive *float64
	Status  string // Windows SMBIOS status text
}

func (r *reading) key() string { return r.Chip + "\x00" + r.Kind + r.Index }

func (r *reading) name() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Kind + r.Index
}

func fptr(v float64) *float64 { return &v }
func bptr(v bool) *bool       { return &v }
func isTrue(b *bool) bool     { return b != nil && *b }

// subRe splits a subfeature name such as temp1_crit_alarm.
var subRe = regexp.MustCompile(`^(temp|fan|in|power|curr|intrusion)([0-9]+)_([a-z_]+)$`)

// apply stores one subfeature value (already in display units).
func (r *reading) apply(suffix string, v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	switch suffix {
	case "input":
		r.Input = fptr(v)
	case "average":
		if r.Input == nil {
			r.Input = fptr(v)
		}
	case "min":
		r.Min = fptr(v)
	case "max":
		r.Max = fptr(v)
	case "crit":
		r.Crit = fptr(v)
	case "emergency":
		r.Emergency = fptr(v)
	case "alarm":
		r.Alarm = bptr(v != 0)
	case "min_alarm":
		r.MinAlarm = bptr(v != 0)
	case "max_alarm":
		r.MaxAlarm = bptr(v != 0)
	case "crit_alarm":
		r.CritAlarm = bptr(v != 0)
	case "fault":
		r.Fault = bptr(v != 0)
	}
}

// collector keeps readings in first-seen order.
type collector struct {
	idx  map[string]*reading
	list []*reading
}

func newCollector() *collector { return &collector{idx: map[string]*reading{}} }

func (c *collector) get(src, chip, driver, kind, index string) *reading {
	k := chip + "\x00" + kind + index
	if r, ok := c.idx[k]; ok {
		return r
	}
	r := &reading{Source: src, Chip: chip, Driver: driver, Kind: kind, Index: index}
	c.idx[k] = r
	c.list = append(c.list, r)
	return r
}

// chipDriver returns the driver part of an lm-sensors chip name
// ("coretemp-isa-0000" -> "coretemp"). Kernel hwmon names cannot contain
// '-', so the first dash ends the name.
func chipDriver(chip string) string {
	if i := strings.IndexByte(chip, '-'); i > 0 {
		return chip[:i]
	}
	return chip
}

// trailingComma fixes the invalid JSON some lm-sensors versions print when
// every feature of a chip is ignored (lm-sensors issue #513:
// `"Adapter": "PCI adapter",` followed by `}`).
var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// parseLMJSON parses `sensors -j` (lm-sensors >= 3.5). It also accepts the
// structured `-J` form of newer releases ({"input": {"value": 42}}).
func parseLMJSON(s string) ([]*reading, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return nil, false
	}
	s = trailingComma.ReplaceAllString(s, "$1")
	var chips map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &chips); err != nil {
		return nil, false
	}
	names := make([]string, 0, len(chips))
	for n := range chips {
		names = append(names, n)
	}
	sort.Strings(names)
	c := newCollector()
	for _, chip := range names {
		var feats map[string]json.RawMessage
		if json.Unmarshal(chips[chip], &feats) != nil {
			continue
		}
		drv := chipDriver(chip)
		labels := make([]string, 0, len(feats))
		for l := range feats {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		for _, label := range labels {
			if label == "Adapter" {
				continue
			}
			var subs map[string]json.RawMessage
			if json.Unmarshal(feats[label], &subs) != nil {
				continue
			}
			for sub, raw := range subs {
				if m := subRe.FindStringSubmatch(sub); m != nil {
					var v float64
					if json.Unmarshal(raw, &v) != nil {
						continue
					}
					r := c.get(srcLM, chip, drv, m[1], m[2])
					r.Label = label
					r.apply(m[3], v) // lm-sensors prints display units already
					continue
				}
				// -J form: {"input": {"quantity": "temperature", "unit": "°C", "value": 42}}
				var obj struct {
					Quantity string   `json:"quantity"`
					Value    *float64 `json:"value"`
				}
				if json.Unmarshal(raw, &obj) != nil || obj.Value == nil {
					continue
				}
				kind := quantityKind(obj.Quantity)
				if kind == "" {
					continue
				}
				r := c.get(srcLM, chip, drv, kind, "#"+label)
				r.Label = label
				r.apply(sub, *obj.Value)
			}
		}
	}
	return c.list, true
}

func quantityKind(q string) string {
	switch strings.ToLower(q) {
	case "temperature":
		return kTemp
	case "fan", "fan speed":
		return kFan
	case "voltage":
		return kIn
	case "power":
		return kPower
	case "current":
		return kCurr
	}
	return ""
}

// lmSubLine matches a `sensors -u` subfeature line: "  temp1_input: 42.000".
var lmSubLine = regexp.MustCompile(`^\s+(temp|fan|in|power|curr|intrusion)([0-9]+)_([a-z_]+):\s*(\S+)\s*$`)

// parseLMRaw parses `sensors -u` (with or without -A). Chips are separated
// by blank lines; the first line of a block is the chip name, then an
// optional "Adapter:" line, then features ("Core 0:") each followed by
// indented subfeatures.
func parseLMRaw(s string) []*reading {
	c := newCollector()
	chip, label := "", ""
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			chip, label = "", ""
			continue
		}
		if chip == "" {
			chip = t
			continue
		}
		if label == "" && strings.HasPrefix(t, "Adapter:") {
			continue
		}
		if m := lmSubLine.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseFloat(m[4], 64)
			if err != nil {
				continue
			}
			r := c.get(srcLM, chip, chipDriver(chip), m[1], m[2])
			if label != "" {
				r.Label = label
			}
			r.apply(m[3], v)
			continue
		}
		if strings.HasSuffix(t, ":") {
			label = strings.TrimSpace(strings.TrimSuffix(t, ":"))
		}
	}
	return c.list
}

var hwmonPath = regexp.MustCompile(`^/sys/class/hwmon/(hwmon[0-9]+)/(.+)$`)

// parseHwmon parses the dw_sysfs dump of /sys/class/hwmon. sysfs units:
// millidegree C, millivolt, milliampere, microwatt, RPM
// (Documentation/hwmon/sysfs-interface.rst).
func parseHwmon(sec *collect.Section) []*reading {
	type file struct{ dev, name, val string }
	var files []file
	names := map[string]string{}
	models := map[string]string{}
	for _, l := range sec.Lines() {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		m := hwmonPath.FindStringSubmatch(strings.TrimSpace(k))
		if m == nil {
			continue
		}
		v = strings.TrimSpace(v)
		switch m[2] {
		case "name":
			names[m[1]] = v
		case "device/model":
			models[m[1]] = v
		default:
			files = append(files, file{m[1], m[2], v})
		}
	}
	c := newCollector()
	for _, f := range files {
		m := subRe.FindStringSubmatch(f.name)
		if m == nil {
			continue
		}
		drv := names[f.dev]
		chip := f.dev
		if drv != "" {
			chip = f.dev + " (" + drv + ")"
		}
		r := c.get(srcHwmon, chip, drv, m[1], m[2])
		r.Model = models[f.dev]
		if m[3] == "label" {
			r.Label = f.val
			continue
		}
		v, err := strconv.ParseFloat(f.val, 64)
		if err != nil {
			continue
		}
		if !strings.HasSuffix(m[3], "alarm") && m[3] != "fault" {
			v = scaleSysfs(m[1], v)
		}
		r.apply(m[3], v)
	}
	return c.list
}

func scaleSysfs(kind string, v float64) float64 {
	switch kind {
	case kTemp, kIn, kCurr:
		return v / 1000
	case kPower:
		return v / 1e6
	}
	return v
}

var thermalPath = regexp.MustCompile(`^/sys/class/thermal/(thermal_zone[0-9]+)/(type|temp|trip_point_([0-9]+)_(temp|type))$`)

// parseThermal parses /sys/class/thermal/thermal_zone* (millidegree C;
// trip point types: critical, hot, passive, active —
// Documentation/driver-api/thermal/sysfs-api.rst).
func parseThermal(sec *collect.Section) []*reading {
	type zone struct {
		typ      string
		temp     *float64
		tripTemp map[string]float64
		tripType map[string]string
	}
	zones := map[string]*zone{}
	var order []string
	for _, l := range sec.Lines() {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		m := thermalPath.FindStringSubmatch(strings.TrimSpace(k))
		if m == nil {
			continue
		}
		z := zones[m[1]]
		if z == nil {
			z = &zone{tripTemp: map[string]float64{}, tripType: map[string]string{}}
			zones[m[1]] = z
			order = append(order, m[1])
		}
		v = strings.TrimSpace(v)
		switch {
		case m[2] == "type":
			z.typ = v
		case m[2] == "temp":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				z.temp = fptr(f / 1000)
			}
		case m[4] == "temp":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				z.tripTemp[m[3]] = f / 1000
			}
		case m[4] == "type":
			z.tripType[m[3]] = v
		}
	}
	var out []*reading
	for _, name := range order {
		z := zones[name]
		r := &reading{Source: srcThermal, Chip: name, Driver: z.typ, Kind: kTemp, Index: "", Label: z.typ, Input: z.temp}
		for id, typ := range z.tripType {
			t, ok := z.tripTemp[id]
			if !ok {
				continue
			}
			switch typ {
			case "critical":
				if r.Crit == nil || t < *r.Crit {
					r.Crit = fptr(t)
				}
			case "hot":
				if r.Max == nil || t < *r.Max {
					r.Max = fptr(t)
				}
			case "passive":
				if r.Passive == nil || t < *r.Passive {
					r.Passive = fptr(t)
				}
			}
		}
		out = append(out, r)
	}
	return out
}
