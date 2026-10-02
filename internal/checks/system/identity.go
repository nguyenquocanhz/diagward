package system

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/dmi"
	"github.com/nguyenquocanhz/diagward/model"
)

// Identity is what the machine says it is (SMBIOS / CIM).
type Identity struct {
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`
	Serial        string `json:"serial,omitempty"`
	SKU           string `json:"sku,omitempty"`
	Family        string `json:"family,omitempty"`
	BIOSVendor    string `json:"biosVendor,omitempty"`
	BIOSVersion   string `json:"biosVersion,omitempty"`
	BIOSDate      string `json:"biosDate,omitempty"` // YYYY-MM-DD
	BoardVendor   string `json:"boardVendor,omitempty"`
	BoardModel    string `json:"boardModel,omitempty"`
	BoardSerial   string `json:"boardSerial,omitempty"`
	ChassisType   string `json:"chassisType,omitempty"`
	ChassisSerial string `json:"chassisSerial,omitempty"`
	AssetTag      string `json:"assetTag,omitempty"`
	CPU           string `json:"cpu,omitempty"`
	CPUModel      string `json:"cpuModel,omitempty"`
	Sockets       int    `json:"sockets,omitempty"`
	Cores         int    `json:"cores,omitempty"`
	Threads       int    `json:"threads,omitempty"`
	MemBytes      uint64 `json:"memBytes,omitempty"`
	// Source says where the hardware identity came from: "dmidecode",
	// "sysfs", "hostnamectl", "cim" or "".
	Source string `json:"source,omitempty"`

	biosTime time.Time
}

// linuxIdentity merges dmidecode (best, needs root), /sys/class/dmi/id
// (no serial without root) and hostnamectl (newer systemd).
func linuxIdentity(b *collect.Bundle) Identity {
	var id Identity
	if s := b.Get("system.dmidecode"); s.Ran() {
		recs := parseDMIDecode(s.Text())
		sys, bios, board, ch := firstDMI(recs, 1), firstDMI(recs, 0), firstDMI(recs, 2), firstDMI(recs, 3)
		if sys != nil || bios != nil {
			id.Source = "dmidecode"
		}
		id.Vendor = sys.get("manufacturer")
		id.Model = cleanModel(sys.get("product name"))
		id.Serial = sys.get("serial number")
		id.SKU = sys.get("sku number")
		id.Family = sys.get("family")
		id.BIOSVendor = bios.get("vendor")
		id.BIOSVersion = cleanVersion(bios.get("version"))
		if t, ok := parseBIOSDate(bios.get("release date")); ok {
			id.biosTime = t
		}
		id.BoardVendor = board.get("manufacturer")
		id.BoardModel = cleanModel(board.get("product name"))
		id.BoardSerial = board.get("serial number")
		id.ChassisType = ch.get("type")
		id.ChassisSerial = ch.get("serial number")
		id.AssetTag = ch.get("asset tag")
	}
	if s := b.Get("system.dmi"); s.Ran() {
		kv := map[string]string{}
		for k, v := range s.KV() {
			kv[k[strings.LastIndexByte(k, '/')+1:]] = v
		}
		if len(kv) > 0 && id.Source == "" {
			id.Source = "sysfs"
		}
		fill(&id.Vendor, clean(kv["sys_vendor"]))
		fill(&id.Model, cleanModel(kv["product_name"]))
		fill(&id.Serial, clean(kv["product_serial"]))
		fill(&id.SKU, clean(kv["product_sku"]))
		fill(&id.Family, clean(kv["product_family"]))
		fill(&id.BIOSVendor, clean(kv["bios_vendor"]))
		fill(&id.BIOSVersion, cleanVersion(kv["bios_version"]))
		if id.biosTime.IsZero() {
			if t, ok := parseBIOSDate(kv["bios_date"]); ok {
				id.biosTime = t
			}
		}
		fill(&id.BoardVendor, clean(kv["board_vendor"]))
		fill(&id.BoardModel, cleanModel(kv["board_name"]))
		fill(&id.BoardSerial, clean(kv["board_serial"]))
		fill(&id.ChassisSerial, clean(kv["chassis_serial"]))
		fill(&id.AssetTag, clean(kv["chassis_asset_tag"]))
		if id.ChassisType == "" {
			if n, err := strconv.Atoi(kv["chassis_type"]); err == nil {
				id.ChassisType = chassisName(n)
			}
		}
	}
	if s := b.Get("system.hostnamectl"); s.OK() {
		h := colonKV(s.Text())
		if id.Source == "" && (clean(h["hardware vendor"]) != "" || clean(h["hardware model"]) != "") {
			id.Source = "hostnamectl"
		}
		fill(&id.Vendor, clean(h["hardware vendor"]))
		fill(&id.Model, cleanModel(h["hardware model"]))
		fill(&id.Serial, clean(h["hardware serial"]))
		fill(&id.BIOSVersion, cleanVersion(h["firmware version"]))
		if id.biosTime.IsZero() {
			if t, ok := parseBIOSDate(h["firmware date"]); ok {
				id.biosTime = t
			}
		}
	}
	if id.Serial == "" {
		id.Serial = id.ChassisSerial // Supermicro often fills only the chassis serial
	}
	if !id.biosTime.IsZero() {
		id.BIOSDate = id.biosTime.Format("2006-01-02")
	}
	c := parseCPUInfo(b.Get("system.cpuinfo").Text())
	id.CPUModel, id.Sockets, id.Cores, id.Threads = c.model, c.sockets, c.cores, c.threads
	if id.Threads == 0 {
		id.Threads = atoi(strings.TrimSpace(b.Get("system.nproc").Text()))
	}
	if id.CPUModel == "" {
		dmiCPU(b.Get("cpu.dmidecode").Text(), &id)
	}
	id.CPU = cpuSummary(id.CPUModel, id.Sockets, id.Cores, id.Threads)
	if kb := meminfoKB(b.Get("system.meminfo").Text(), "MemTotal"); kb > 0 {
		id.MemBytes = kb * 1024
	}
	return id
}

func fill(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// colonKV parses "Key: value" lines (hostnamectl, timedatectl, ethtool -i)
// into a map with lower-case keys.
func colonKV(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := m[k]; !dup && k != "" {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

type cpuInfo struct {
	model                   string
	sockets, cores, threads int
}

// parseCPUInfo summarises /proc/cpuinfo (the filtered lines the collector
// keeps): model, sockets (distinct physical id), cores (sum of "cpu cores"
// per socket) and threads (processor entries).
func parseCPUInfo(s string) cpuInfo {
	var c cpuInfo
	socketCores := map[string]int{}
	var models []string
	seen := map[string]bool{}
	curPhys := ""
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			if _, err := strconv.Atoi(v); err == nil {
				c.threads++
				curPhys = ""
			} else if c.model == "" && v != "" {
				c.model = v // old ARM kernels: "Processor : ARMv7 ..."
			}
		case "model name", "cpu model":
			if v != "" && !seen[v] {
				seen[v] = true
				models = append(models, v)
			}
		case "physical id":
			curPhys = v
			if _, ok := socketCores[v]; !ok {
				socketCores[v] = 0
			}
		case "cpu cores":
			if n, err := strconv.Atoi(v); err == nil && curPhys != "" {
				socketCores[curPhys] = n
			}
		case "Hardware":
			if c.model == "" && len(models) == 0 && v != "" {
				c.model = v
			}
		}
	}
	if len(models) > 0 {
		c.model = strings.Join(models, " + ")
	}
	c.model = cleanCPUName(c.model)
	c.sockets = len(socketCores)
	for _, n := range socketCores {
		c.cores += n
	}
	return c
}

var cpuNoise = regexp.MustCompile(`\((R|r|TM|tm)\)|\s+CPU\b|\s+@\s+[0-9.]+\s*[GM]Hz|\s+Processor$|\s+processor$`)

// cleanCPUName turns "Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz" into
// "Intel Xeon Silver 4214".
func cleanCPUName(s string) string {
	s = cpuNoise.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}

// cpuSummary formats "2 × Intel Xeon Silver 4214 (24 cores, 48 threads)" (the
// English line kept in Identity.CPU; model.CPUSummary has both languages).
func cpuSummary(name string, sockets, cores, threads int) string {
	return model.CPUSummary(name, sockets, cores, threads).EN
}

func meminfoKB(s, key string) uint64 {
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			return 0
		}
		n, _ := strconv.ParseUint(f[0], 10, 64)
		return n
	}
	return 0
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// windowsIdentity reads the CIM sections written by 10-system.ps1.
func windowsIdentity(b *collect.Bundle) Identity {
	var id Identity
	var cs []struct {
		Manufacturer, Model, SystemFamily, SystemSKUNumber string
		TotalPhysicalMemory                                uint64
	}
	if collect.DecodeJSON(b.Get("system.win_computer").Text(), &cs) == nil && len(cs) > 0 {
		id.Source = "cim"
		id.Vendor, id.Model = clean(cs[0].Manufacturer), cleanModel(cs[0].Model)
		id.Family, id.SKU = clean(cs[0].SystemFamily), clean(cs[0].SystemSKUNumber)
		id.MemBytes = cs[0].TotalPhysicalMemory
	}
	var bios []struct {
		Manufacturer, SerialNumber, SMBIOSBIOSVersion, ReleaseDate string
	}
	if collect.DecodeJSON(b.Get("system.win_bios").Text(), &bios) == nil && len(bios) > 0 {
		id.Serial = clean(bios[0].SerialNumber)
		id.BIOSVendor = clean(bios[0].Manufacturer)
		id.BIOSVersion = cleanVersion(bios[0].SMBIOSBIOSVersion)
		if t, ok := collect.WinTime(bios[0].ReleaseDate); ok && t.Year() >= 1980 {
			id.biosTime = t
		}
	}
	var bb []struct{ Manufacturer, Product, SerialNumber string }
	if collect.DecodeJSON(b.Get("system.win_baseboard").Text(), &bb) == nil && len(bb) > 0 {
		id.BoardVendor, id.BoardModel, id.BoardSerial = clean(bb[0].Manufacturer), cleanModel(bb[0].Product), clean(bb[0].SerialNumber)
	}
	var enc []struct {
		SerialNumber, SMBIOSAssetTag string
		ChassisTypes                 []int
	}
	if collect.DecodeJSON(b.Get("system.win_enclosure").Text(), &enc) == nil && len(enc) > 0 {
		id.ChassisSerial, id.AssetTag = clean(enc[0].SerialNumber), clean(enc[0].SMBIOSAssetTag)
		if len(enc[0].ChassisTypes) > 0 {
			id.ChassisType = chassisName(enc[0].ChassisTypes[0])
		}
	}
	if id.Serial == "" {
		id.Serial = id.ChassisSerial
	}
	if !id.biosTime.IsZero() {
		id.BIOSDate = id.biosTime.Format("2006-01-02")
	}
	var cpus []struct {
		Name                                     string
		NumberOfCores, NumberOfLogicalProcessors int
	}
	if collect.DecodeJSON(b.Get("system.win_cpu").Text(), &cpus) == nil && len(cpus) > 0 {
		var models []string
		seen := map[string]bool{}
		for _, c := range cpus {
			n := cleanCPUName(c.Name)
			if n != "" && !seen[n] {
				seen[n] = true
				models = append(models, n)
			}
			id.Cores += c.NumberOfCores
			id.Threads += c.NumberOfLogicalProcessors
		}
		id.Sockets = len(cpus)
		id.CPUModel = strings.Join(models, " + ")
		id.CPU = cpuSummary(id.CPUModel, id.Sockets, id.Cores, id.Threads)
	}
	return id
}

// biosString formats "2.12.2 (2021-07-09)".
func (id Identity) biosString() string {
	switch {
	case id.BIOSVersion != "" && id.BIOSDate != "":
		return id.BIOSVersion + " (" + id.BIOSDate + ")"
	case id.BIOSVersion != "":
		return id.BIOSVersion
	}
	return id.BIOSDate
}

func (id Identity) boardString() string {
	return strings.TrimSpace(id.BoardVendor + " " + id.BoardModel)
}

// bmcHost returns what a BMC bundle offers about the host. The bmc package
// is not finished yet, so this accepts a meta.bmc section as key=value lines
// or as a Redfish ComputerSystem JSON object, and otherwise only the address.
func bmcHost(b *collect.Bundle, env model.Env) model.HostInfo {
	h := model.HostInfo{Hostname: b.Host}
	s := b.Get("meta.bmc")
	if s == nil {
		return h
	}
	txt := strings.TrimSpace(s.Text())
	if strings.HasPrefix(txt, "{") || strings.HasPrefix(txt, "[") {
		var v []struct {
			HostName, Manufacturer, Model, SerialNumber, BiosVersion string
			MemorySummary                                            struct {
				TotalSystemMemoryGiB float64
			}
		}
		if collect.DecodeJSON(txt, &v) == nil && len(v) > 0 {
			fill(&h.Vendor, clean(v[0].Manufacturer))
			fill(&h.Model, clean(v[0].Model))
			fill(&h.Serial, clean(v[0].SerialNumber))
			fill(&h.BIOS, clean(v[0].BiosVersion))
			if n := clean(v[0].HostName); n != "" {
				h.Hostname = n
			}
			if g := v[0].MemorySummary.TotalSystemMemoryGiB; g > 0 {
				h.MemBytes = uint64(g * (1 << 30))
			}
		}
		return h
	}
	kv := s.KV()
	fill(&h.Vendor, clean(kv["vendor"]))
	fill(&h.Model, clean(kv["model"]))
	fill(&h.Serial, clean(kv["serial"]))
	fill(&h.BIOS, clean(kv["bios"]))
	fill(&h.BMC, clean(kv["firmware"]))
	if n := clean(kv["hostname"]); n != "" {
		h.Hostname = n
	}
	return h
}

// dmiCPU fills the CPU model, sockets and cores from the cpu domain's
// dmidecode type 4 records (populated and enabled sockets) when
// /proc/cpuinfo gave no model, so the report header still names the CPU.
func dmiCPU(s string, id *Identity) {
	var models []string
	seen := map[string]bool{}
	sockets, cores, threads := 0, 0, 0
	for _, r := range dmi.OfType(dmi.Parse(s), 4) {
		st := strings.ToLower(r.Get("Status"))
		if !strings.HasPrefix(st, "populated") || !strings.Contains(st, "enabled") {
			continue
		}
		m := cleanCPUName(dmi.Clean(r.Get("Version")))
		if m == "" {
			continue
		}
		if !seen[m] {
			seen[m] = true
			models = append(models, m)
		}
		sockets++
		n := atoi(r.Get("Core Enabled"))
		if n <= 0 {
			n = atoi(r.Get("Core Count"))
		}
		cores += max(n, 0)
		threads += max(atoi(r.Get("Thread Count")), 0)
	}
	if len(models) == 0 {
		return
	}
	id.CPUModel, id.Sockets, id.Cores = strings.Join(models, " + "), sockets, cores
	if id.Threads == 0 {
		id.Threads = threads
	}
}
