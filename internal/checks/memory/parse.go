package memory

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/dmi"
	"github.com/nguyenquocanhz/diagward/internal/units"
)

// DIMM is one memory slot (populated or empty).
type DIMM struct {
	Locator      string `json:"locator"`
	Bank         string `json:"bank,omitempty"`
	Populated    bool   `json:"populated"`
	SizeBytes    uint64 `json:"sizeBytes,omitempty"`
	Type         string `json:"type,omitempty"`       // DDR4, DDR5
	TypeDetail   string `json:"typeDetail,omitempty"` // Registered (Buffered), LRDIMM...
	FormFactor   string `json:"formFactor,omitempty"`
	SpeedMT      int    `json:"speedMTs,omitempty"`      // rated
	ConfiguredMT int    `json:"configuredMTs,omitempty"` // running at
	Manufacturer string `json:"manufacturer,omitempty"`
	PartNumber   string `json:"partNumber,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Rank         int    `json:"rank,omitempty"`
	TotalWidth   int    `json:"totalWidth,omitempty"`
	DataWidth    int    `json:"dataWidth,omitempty"`
	// Technology is the SMBIOS 3.2 "Memory Technology" (DRAM, NVDIMM-N,
	// "Intel persistent memory"); empty on older tables.
	Technology string `json:"technology,omitempty"`
	// PMem marks persistent memory (Optane PMem, NVDIMM): its capacity is
	// not RAM the OS counts in MemTotal unless it runs in Memory Mode.
	PMem bool `json:"pmem,omitempty"`
	// VolatileBytes is the part of the module the OS can use as RAM
	// ("Volatile Size" on SMBIOS 3.2+, else the size of a DRAM module).
	VolatileBytes uint64 `json:"volatileBytes,omitempty"`
	// EDAC counters joined to this slot; -1 when unknown.
	CE        int64  `json:"ce"`
	UE        int64  `json:"ue"`
	EDACLabel string `json:"edacLabel,omitempty"`
}

// Name is how findings refer to the slot: "A1", "PROC 1 DIMM 3",
// "P1-DIMMA1 (P0_Node0_Channel0_Dimm0)".
func (d DIMM) Name() string {
	if d.Bank != "" && !strings.Contains(d.Locator, d.Bank) && len(d.Locator) <= 4 {
		return d.Locator + " (" + d.Bank + ")"
	}
	return d.Locator
}

// ECCWidth reports whether the module carries ECC bits (72/80-bit total
// width for 64 data bits), and whether the widths were known at all.
func (d DIMM) ECCWidth() (ecc, known bool) {
	if d.TotalWidth <= 0 || d.DataWidth <= 0 {
		return false, false
	}
	return d.TotalWidth > d.DataWidth, true
}

// Array is a physical memory array (SMBIOS type 16).
type Array struct {
	ECC         string `json:"ecc"` // "Multi-bit ECC", "Single-bit ECC", "None", ...
	MaxCapacity string `json:"maxCapacity,omitempty"`
	Devices     int    `json:"devices,omitempty"`
}

func dmiMemory(s string) ([]Array, []DIMM) {
	recs := dmi.Parse(s)
	var arrays []Array
	other := map[string]bool{} // handles of arrays that are not system RAM
	for _, r := range dmi.OfType(recs, 16) {
		if u := strings.ToLower(r.Get("Use")); u != "" && u != "system memory" {
			other[r.Handle] = true
			continue // flash, video or cache memory arrays
		}
		arrays = append(arrays, Array{
			ECC:         r.Get("Error Correction Type"),
			MaxCapacity: dmi.Clean(r.Get("Maximum Capacity")),
			Devices:     atoi(r.Get("Number Of Devices")),
		})
	}
	var dimms []DIMM
	for _, r := range dmi.OfType(recs, 17) {
		if other[r.Get("Array Handle")] {
			continue // a device of a flash/video array, not a DIMM
		}
		size, ok := dmi.Size(r.Get("Size"))
		d := DIMM{
			Locator:      firstNonEmpty(dmi.Clean(r.Get("Locator")), r.Handle),
			Bank:         dmi.Clean(r.Get("Bank Locator")),
			Populated:    ok,
			SizeBytes:    size,
			Type:         dmi.Clean(r.Get("Type")),
			TypeDetail:   dmi.Clean(r.Get("Type Detail")),
			FormFactor:   dmi.Clean(r.Get("Form Factor")),
			SpeedMT:      dmi.Speed(r.Get("Speed")),
			ConfiguredMT: dmi.Speed(firstNonEmpty(r.Get("Configured Memory Speed"), r.Get("Configured Clock Speed"))),
			Manufacturer: dmi.Vendor(r.Get("Manufacturer")),
			PartNumber:   dmi.Clean(r.Get("Part Number")),
			Serial:       dmi.Clean(r.Get("Serial Number")),
			Rank:         atoi(r.Get("Rank")),
			TotalWidth:   atoi(r.Get("Total Width")),
			DataWidth:    atoi(r.Get("Data Width")),
			CE:           -1,
			UE:           -1,
		}
		if !d.Populated {
			d.Type, d.TypeDetail, d.SpeedMT, d.ConfiguredMT, d.Manufacturer, d.PartNumber, d.Serial = "", "", 0, 0, "", "", ""
		} else {
			d.Technology = dmi.Clean(r.Get("Memory Technology"))
			lt := strings.ToLower(d.Technology)
			d.PMem = strings.Contains(lt, "persistent memory") || strings.Contains(lt, "nvdimm") ||
				strings.Contains(strings.ToLower(d.TypeDetail), "non-volatile")
			if v, present := r.Fields["Volatile Size"]; present {
				d.VolatileBytes, _ = dmi.Size(v) // "None" = 0
			} else if !d.PMem {
				d.VolatileBytes = size
			}
			if d.PMem && d.Type == "" { // Optane reports Type <OUT OF SPEC>
				d.Type = "PMem"
				if strings.Contains(lt, "intel") {
					d.Type = "Optane PMem"
				}
			}
		}
		dimms = append(dimms, d)
	}
	return arrays, dimms
}

// ---- EDAC ----

// EDACMC is one memory controller in /sys/devices/system/edac/mc.
type EDACMC struct {
	Name     string     `json:"name"`             // mc0
	Ctl      string     `json:"ctl,omitempty"`    // mc_name: "Skylake Socket#0 IMC#0", "ghes_edac"
	SizeMB   int64      `json:"sizeMB,omitempty"` // size_mb
	Seconds  int64      `json:"secondsSinceReset,omitempty"`
	CE       int64      `json:"ce"`
	UE       int64      `json:"ue"`
	CENoInfo int64      `json:"ceNoInfo"`
	UENoInfo int64      `json:"ueNoInfo"`
	DIMMs    []EDACDimm `json:"dimms,omitempty"`
}

// EDACDimm is one DIMM (dimmN/rankN) or csrow channel the driver counts.
type EDACDimm struct {
	MC       string   `json:"mc"`
	Node     string   `json:"node"` // dimm3, rank0, csrow1/ch0
	Label    string   `json:"label,omitempty"`
	Location string   `json:"location,omitempty"`
	SizeMB   int64    `json:"sizeMB,omitempty"`
	MemType  string   `json:"memType,omitempty"`
	Mode     string   `json:"edacMode,omitempty"`
	CE       int64    `json:"ce"`
	UE       int64    `json:"ue"`
	Raw      []string `json:"-"`
}

// Name is the label the driver gives, or its sysfs position.
func (d EDACDimm) Name() string {
	l := strings.TrimSpace(d.Label)
	if l != "" {
		return l
	}
	if d.Location != "" {
		return d.MC + " " + strings.TrimSpace(d.Location)
	}
	return d.MC + "/" + d.Node
}

var reMC = regexp.MustCompile(`/edac/mc/(mc\d+)/(.*)$`)

func parseEDAC(sec *collect.Section) []EDACMC {
	type key struct{ mc, node string }
	mcs := map[string]*EDACMC{}
	dimms := map[key]*EDACDimm{}
	csrowUE := map[key]int64{} // csrow-level UE (old drivers count UE per csrow)
	getMC := func(n string) *EDACMC {
		m := mcs[n]
		if m == nil {
			m = &EDACMC{Name: n, CE: -1, UE: -1, CENoInfo: -1, UENoInfo: -1}
			mcs[n] = m
		}
		return m
	}
	getD := func(mc, node string) *EDACDimm {
		k := key{mc, node}
		d := dimms[k]
		if d == nil {
			d = &EDACDimm{MC: mc, Node: node, CE: -1, UE: -1}
			dimms[k] = d
		}
		return d
	}
	num := func(v string) int64 {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n < 0 {
			return -1
		}
		return n
	}
	for _, l := range sec.Lines() {
		p, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		m := reMC.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		mc, rest := m[1], m[2]
		mm := getMC(mc)
		dir, file := path.Split(rest)
		dir = strings.TrimSuffix(dir, "/")
		if dir == "" {
			switch file {
			case "mc_name":
				mm.Ctl = strings.TrimSpace(v)
			case "size_mb":
				mm.SizeMB = num(v)
			case "seconds_since_reset":
				mm.Seconds = num(v)
			case "ce_count":
				mm.CE = num(v)
			case "ue_count":
				mm.UE = num(v)
			case "ce_noinfo_count":
				mm.CENoInfo = num(v)
			case "ue_noinfo_count":
				mm.UENoInfo = num(v)
			}
			continue
		}
		switch {
		case strings.HasPrefix(dir, "dimm") || strings.HasPrefix(dir, "rank"):
			d := getD(mc, dir)
			switch file {
			case "dimm_label":
				d.Label = strings.TrimSpace(v)
			case "dimm_location":
				d.Location = strings.TrimSpace(v)
			case "size":
				d.SizeMB = num(v)
			case "dimm_mem_type":
				d.MemType = strings.TrimSpace(v)
			case "dimm_edac_mode":
				d.Mode = strings.TrimSpace(v)
			case "dimm_ce_count":
				d.CE = num(v)
				d.Raw = append(d.Raw, l)
			case "dimm_ue_count":
				d.UE = num(v)
				d.Raw = append(d.Raw, l)
			}
		case strings.HasPrefix(dir, "csrow"):
			k := key{mc, dir}
			switch {
			case file == "ue_count":
				csrowUE[k] = num(v)
			case strings.HasPrefix(file, "ch") && strings.HasSuffix(file, "_ce_count"):
				ch := strings.TrimSuffix(file, "_ce_count")
				d := getD(mc, dir+"/"+ch)
				d.CE = num(v)
				d.Raw = append(d.Raw, l)
			case strings.HasPrefix(file, "ch") && strings.HasSuffix(file, "_ue_count"):
				ch := strings.TrimSuffix(file, "_ue_count")
				d := getD(mc, dir+"/"+ch)
				d.UE = num(v)
				d.Raw = append(d.Raw, l)
			case strings.HasPrefix(file, "ch") && strings.HasSuffix(file, "_dimm_label"):
				ch := strings.TrimSuffix(file, "_dimm_label")
				getD(mc, dir+"/"+ch).Label = strings.TrimSpace(v)
			case file == "size_mb":
				for _, d := range dimms {
					if d.MC == mc && strings.HasPrefix(d.Node, dir+"/") && d.SizeMB == 0 {
						d.SizeMB = num(v)
					}
				}
			case file == "mem_type":
				for _, d := range dimms {
					if d.MC == mc && strings.HasPrefix(d.Node, dir+"/") {
						d.MemType = strings.TrimSpace(v)
					}
				}
			}
		}
	}
	// Prefer dimmN/rankN nodes; fall back to csrow channels for old drivers.
	hasModern := map[string]bool{}
	for k := range dimms {
		if !strings.HasPrefix(k.node, "csrow") {
			hasModern[k.mc] = true
		}
	}
	// Old drivers count UE per csrow, not per channel: attach csrow UE to
	// the csrow's first channel when the channels have no UE of their own.
	for k, ue := range csrowUE {
		if hasModern[k.mc] || ue <= 0 {
			continue
		}
		has := false
		for dk, d := range dimms {
			if dk.mc == k.mc && strings.HasPrefix(dk.node, k.node+"/") && d.UE > 0 {
				has = true
			}
		}
		if !has {
			d := getD(k.mc, k.node+"/ch0")
			d.UE = ue
			d.Raw = append(d.Raw, "/sys/devices/system/edac/mc/"+k.mc+"/"+k.node+"/ue_count="+strconv.FormatInt(ue, 10))
		}
	}
	var out []EDACMC
	names := make([]string, 0, len(mcs))
	for n := range mcs {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return natLess(names[i], names[j]) })
	for _, n := range names {
		m := mcs[n]
		var ds []EDACDimm
		for k, d := range dimms {
			if k.mc != n || (hasModern[n] && strings.HasPrefix(k.node, "csrow")) {
				continue
			}
			ds = append(ds, *d)
		}
		sort.Slice(ds, func(i, j int) bool { return natLess(ds[i].Node, ds[j].Node) })
		m.DIMMs = ds
		out = append(out, *m)
	}
	return out
}

// natLess orders "dimm2" before "dimm10".
func natLess(a, b string) bool {
	ai, bi := trailingNum(a), trailingNum(b)
	pa, pb := strings.TrimRight(a, "0123456789"), strings.TrimRight(b, "0123456789")
	if pa == pb && ai >= 0 && bi >= 0 {
		return ai < bi
	}
	return a < b
}

func trailingNum(s string) int {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return -1
	}
	n, _ := strconv.Atoi(s[i:])
	return n
}

// ---- /proc/meminfo, PSI, vmstat ----

type meminfo map[string]uint64 // bytes (or a count for HugePages_*)

func parseMeminfo(s string) meminfo {
	m := meminfo{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && strings.EqualFold(f[1], "kB") {
			n *= 1024
		}
		m[strings.TrimSpace(k)] = n
	}
	return m
}

// PSI is one line of /proc/pressure/memory.
type PSI struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
	Ok     bool    `json:"-"`
}

func parsePSI(s string) (some, full PSI) {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		var p PSI
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil || x < 0 || x > 100 {
				continue
			}
			switch k {
			case "avg10":
				p.Avg10, p.Ok = x, true
			case "avg60":
				p.Avg60 = x
			case "avg300":
				p.Avg300 = x
			}
		}
		switch f[0] {
		case "some":
			some = p
		case "full":
			full = p
		}
	}
	return
}

func parseVmstat(s string) map[string]uint64 {
	m := map[string]uint64{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		if n, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			m[f[0]] = n
		}
	}
	return m
}

// ---- memtester ----

// memtesterTests are the test names memtester 4.x prints, in order
// (memtester.c tests[] plus "Stuck Address").
var memtesterTests = []string{
	"Stuck Address", "Random Value", "Compare XOR", "Compare SUB", "Compare MUL", "Compare DIV",
	"Compare OR", "Compare AND", "Sequential Increment", "Solid Bits", "Block Sequential",
	"Checkerboard", "Bit Spread", "Bit Flip", "Walking Ones", "Walking Zeroes", "8-bit Writes", "16-bit Writes",
}

var reMemtestLabel = func() *regexp.Regexp {
	var alts []string
	for _, t := range memtesterTests {
		alts = append(alts, regexp.QuoteMeta(t))
	}
	return regexp.MustCompile(`(` + strings.Join(alts, "|") + `)\s*:`)
}()

// Memtest is the parsed memtester run.
type Memtest struct {
	Size      string   `json:"size,omitempty"`
	TestedMB  int      `json:"testedMB,omitempty"`
	Locked    bool     `json:"locked"`
	RC        int      `json:"rc"`
	Done      bool     `json:"done"`
	Passed    []string `json:"passed,omitempty"`
	Failed    []string `json:"failed,omitempty"`
	Failures  []string `json:"failures,omitempty"` // FAILURE: lines (capped)
	TimeoutS  int      `json:"timeoutSeconds,omitempty"`
	Unlocked  bool     `json:"unlocked,omitempty"`
	MemAvailK int64    `json:"memAvailableKB,omitempty"`
}

var (
	reGot   = regexp.MustCompile(`got\s+(\d+)MB`)
	reHdrKV = regexp.MustCompile(`(\w+)=(\S+)`)
)

// parseMemtest reads the collector's memtester section. Stdout has the
// progress backspaces removed; FAILURE lines (memtester writes them to
// stderr) are in errOut. A test whose label is not followed by "ok"
// failed: memtester prints nothing else for a failed test on stdout.
func parseMemtest(out, errOut string, rc int) Memtest {
	m := Memtest{RC: rc}
	stdout := strings.ReplaceAll(out, "\b", "")
	for _, l := range strings.Split(stdout, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "diagward: size="):
			for _, kv := range reHdrKV.FindAllStringSubmatch(t, -1) {
				switch kv[1] {
				case "size":
					m.Size = kv[2]
				case "timeout":
					m.TimeoutS = atoi(kv[2])
				case "memavailable_kb":
					n, _ := strconv.ParseInt(kv[2], 10, 64)
					m.MemAvailK = n
				}
			}
			continue
		case strings.HasPrefix(t, "diagward: rc="):
			if n, err := strconv.Atoi(strings.TrimPrefix(t, "diagward: rc=")); err == nil {
				m.RC = n
			}
			continue
		case t == "Done.":
			m.Done = true
		}
		if g := reGot.FindAllStringSubmatch(t, -1); len(g) > 0 {
			m.TestedMB = atoi(g[len(g)-1][1])
		}
		if strings.Contains(t, "...locked.") {
			m.Locked = true
		}
		if strings.Contains(t, "insufficient permission") || strings.Contains(t, "Trying again, unlocked") {
			m.Unlocked = true
		}
		if strings.Contains(t, "FAILURE:") {
			m.Failures = append(m.Failures, t[strings.Index(t, "FAILURE:"):])
		}
		idx := reMemtestLabel.FindAllStringSubmatchIndex(l, -1)
		for i, ix := range idx {
			name := l[ix[2]:ix[3]]
			end := len(l)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			rest := strings.TrimSpace(l[ix[1]:end])
			if strings.HasSuffix(rest, "ok") {
				m.Passed = append(m.Passed, name)
			} else {
				m.Failed = append(m.Failed, name)
			}
		}
	}
	for _, l := range strings.Split(errOut, "\n") {
		t := strings.TrimSpace(l)
		if strings.Contains(t, "FAILURE:") && len(m.Failures) < 50 {
			m.Failures = append(m.Failures, t[strings.Index(t, "FAILURE:"):])
		}
		if strings.Contains(t, "Continuing with unlocked memory") {
			m.Unlocked = true
		}
	}
	// The last label of an interrupted run has no "ok" only because the
	// run stopped: that is not a failure.
	if !m.Done && len(m.Failed) > 0 && len(m.Failures) == 0 && (m.Killed() || m.RC&6 == 0) {
		m.Failed = m.Failed[:len(m.Failed)-1]
	}
	return m
}

// Killed reports whether memtester was stopped (timeout or signal) rather
// than exiting with its own status bits (0x01 could not start, 0x02 stuck
// address failure, 0x04 other test failure: memtester.c EXIT_FAIL_*).
func (m Memtest) Killed() bool { return m.RC == 124 || m.RC == 137 || m.RC > 128 || m.RC < 0 }

// ---- helpers ----

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

func iec(b uint64) string {
	if b == 0 {
		return ""
	}
	return units.IEC(b)
}
