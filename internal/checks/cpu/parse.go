package cpu

import (
	"encoding/json"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/dmi"
)

// lscpuFields flattens lscpu output (JSON from -J, with or without the
// "children" nesting of util-linux >= 2.38, or plain text) into
// "Model name" -> "Intel(R) Xeon(R) ...". The first occurrence wins.
func lscpuFields(jsonOut, textOut string) map[string]string {
	m := map[string]string{}
	add := func(k, v string) {
		k = strings.TrimSuffix(strings.TrimSpace(k), ":")
		v = strings.TrimSpace(v)
		if k == "" {
			return
		}
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	if strings.TrimSpace(jsonOut) != "" {
		type entry struct {
			Field    string  `json:"field"`
			Data     *string `json:"data"`
			Children []entry `json:"children"`
		}
		var doc struct {
			Lscpu []entry `json:"lscpu"`
		}
		if json.Unmarshal([]byte(jsonOut), &doc) == nil {
			var walk func([]entry)
			walk = func(es []entry) {
				for _, e := range es {
					if e.Data != nil {
						add(e.Field, *e.Data)
					}
					walk(e.Children)
				}
			}
			walk(doc.Lscpu)
		}
	}
	for _, l := range strings.Split(textOut, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			add(k, v)
		}
	}
	return m
}

// cpuinfoSummary reads the collector's "<count>\t<key>=<value>" summary of
// /proc/cpuinfo.
type cpuinfoSummary struct {
	Processors int
	Hypervisor bool
	Values     map[string]map[string]int // key -> value -> count
}

func parseCpuinfo(s string) cpuinfoSummary {
	c := cpuinfoSummary{Values: map[string]map[string]int{}}
	for _, l := range strings.Split(s, "\n") {
		n, rest, ok := strings.Cut(strings.TrimSpace(l), "\t")
		if !ok {
			continue
		}
		cnt, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			continue
		}
		switch rest {
		case "processors":
			c.Processors = cnt
			continue
		case "hypervisor":
			c.Hypervisor = cnt > 0
			continue
		}
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		if c.Values[k] == nil {
			c.Values[k] = map[string]int{}
		}
		c.Values[k][v] += cnt
	}
	return c
}

// sorted returns the distinct values of key, most common first.
func (c cpuinfoSummary) sorted(key string) []string {
	m := c.Values[key]
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// cpuList counts the CPUs in a kernel CPU list such as "0-3,8,10-11".
// It returns -1 for garbage.
func cpuList(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		a, b, rng := strings.Cut(strings.TrimSpace(part), "-")
		x, err := strconv.Atoi(a)
		if err != nil || x < 0 {
			return -1
		}
		if !rng {
			n++
			continue
		}
		y, err := strconv.Atoi(b)
		if err != nil || y < x || y-x > 1<<20 {
			return -1
		}
		n += y - x + 1
	}
	return n
}

// cpuIDs expands a kernel CPU list ("0-3,8") into sorted CPU numbers. ok
// is false for garbage or lists too large to expand (more than 65536 CPUs).
func cpuIDs(s string) (ids []int, ok bool) {
	n := cpuList(s)
	if n < 0 || n > 1<<16 {
		return nil, false
	}
	seen := map[int]bool{}
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, rng := strings.Cut(part, "-")
		x, _ := strconv.Atoi(a)
		y := x
		if rng {
			y, _ = strconv.Atoi(b)
		}
		for i := x; i <= y; i++ {
			if !seen[i] {
				seen[i] = true
				ids = append(ids, i)
			}
		}
	}
	sort.Ints(ids)
	return ids, true
}

// formatCPUs writes sorted CPU numbers back as a kernel CPU list.
func formatCPUs(ids []int) string {
	var parts []string
	for i := 0; i < len(ids); {
		j := i
		for j+1 < len(ids) && ids[j+1] == ids[j]+1 {
			j++
		}
		if j == i {
			parts = append(parts, strconv.Itoa(ids[i]))
		} else {
			parts = append(parts, strconv.Itoa(ids[i])+"-"+strconv.Itoa(ids[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// sysfsBase maps the base names of a dw_sysfs dump ("online", "offline",
// "control" for smt/control) to their values.
func sysfsBase(sec *collect.Section) map[string]string {
	m := map[string]string{}
	for k, v := range sec.KV() {
		b := path.Base(k)
		if strings.HasSuffix(k, "/smt/control") {
			b = "smt_control"
		} else if strings.HasSuffix(k, "/smt/active") {
			b = "smt_active"
		}
		m[b] = v
	}
	return m
}

// Processor is one CPU socket.
type Processor struct {
	Socket       string `json:"socket"`
	Status       string `json:"status"` // dmidecode Status or a Windows CpuStatus text
	Populated    bool   `json:"populated"`
	Enabled      bool   `json:"enabled"`
	DisabledBIOS bool   `json:"disabledByBios,omitempty"` // disabled after a POST error
	DisabledUser bool   `json:"disabledByUser,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Cores        int    `json:"cores,omitempty"`
	CoresEnabled int    `json:"coresEnabled,omitempty"`
	Threads      int    `json:"threads,omitempty"`
	CurrentMHz   int    `json:"currentMHz,omitempty"`
	MaxMHz       int    `json:"maxMHz,omitempty"`
	Serial       string `json:"serial,omitempty"`
	PartNumber   string `json:"partNumber,omitempty"`
}

// dmiProcessors reads dmidecode type 4 records.
func dmiProcessors(s string) []Processor {
	var out []Processor
	for _, r := range dmi.OfType(dmi.Parse(s), 4) {
		st := r.Get("Status")
		low := strings.ToLower(st)
		p := Processor{
			Socket:       firstNonEmpty(dmi.Clean(r.Get("Socket Designation")), r.Handle),
			Status:       st,
			Populated:    strings.HasPrefix(low, "populated"),
			Enabled:      strings.Contains(low, "enabled"),
			DisabledBIOS: strings.Contains(low, "disabled by bios"),
			DisabledUser: strings.Contains(low, "disabled by user"),
			Manufacturer: dmi.Clean(r.Get("Manufacturer")),
			Model:        strings.Join(strings.Fields(dmi.Clean(r.Get("Version"))), " "),
			Cores:        atoi(r.Get("Core Count")),
			CoresEnabled: atoi(r.Get("Core Enabled")),
			Threads:      atoi(r.Get("Thread Count")),
			CurrentMHz:   dmi.Speed(r.Get("Current Speed")),
			MaxMHz:       dmi.Speed(r.Get("Max Speed")),
			Serial:       dmi.Clean(r.Get("Serial Number")),
			PartNumber:   dmi.Clean(r.Get("Part Number")),
		}
		// Some boards list processor records without a status line; treat
		// them as populated when they name a CPU.
		if st == "" && p.Model != "" {
			p.Populated, p.Enabled = true, true
		}
		out = append(out, p)
	}
	return out
}

// throttle counters from /sys/devices/system/cpu/cpuN/thermal_throttle.
type cpuThrottle struct {
	CPU           int
	Package       int
	CoreCount     uint64
	CoreTimeMS    uint64
	HasCoreTime   bool
	PkgCount      uint64
	PkgTimeMS     uint64
	HasPkgTime    bool
	HasCoreCount  bool
	HasPkgCounter bool
}

func parseThrottle(sec *collect.Section) map[int]*cpuThrottle {
	out := map[int]*cpuThrottle{}
	get := func(cpu int) *cpuThrottle {
		t := out[cpu]
		if t == nil {
			t = &cpuThrottle{CPU: cpu, Package: -1}
			out[cpu] = t
		}
		return t
	}
	for k, v := range sec.KV() {
		i := strings.Index(k, "/cpu/cpu")
		if i < 0 {
			continue
		}
		rest := k[i+len("/cpu/cpu"):]
		num, file, ok := strings.Cut(rest, "/")
		if !ok {
			continue
		}
		cpu, err := strconv.Atoi(num)
		if err != nil {
			continue
		}
		val, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch file {
		case "topology/physical_package_id":
			get(cpu).Package = int(val)
		case "thermal_throttle/core_throttle_count":
			t := get(cpu)
			t.CoreCount, t.HasCoreCount = val, true
		case "thermal_throttle/core_throttle_total_time_ms":
			t := get(cpu)
			t.CoreTimeMS, t.HasCoreTime = val, true
		case "thermal_throttle/package_throttle_count":
			t := get(cpu)
			t.PkgCount, t.HasPkgCounter = val, true
		case "thermal_throttle/package_throttle_total_time_ms":
			t := get(cpu)
			t.PkgTimeMS, t.HasPkgTime = val, true
		}
	}
	return out
}

func atoi(s string) int {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
