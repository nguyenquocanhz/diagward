package network

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ethtoolInfo is the part of `ethtool IF` output the checks use.
type ethtoolInfo struct {
	Supported    []string
	Advertised   []string
	Partner      []string
	SpeedMbps    int    // 0 = unknown
	Duplex       string // "full", "half" or ""
	AutoNeg      string // "on", "off" or ""
	Port         string
	LinkDetected *bool
	PartnerAuto  string
}

var ethtoolModeKeys = map[string]string{
	"supported link modes":               "s",
	"advertised link modes":              "a",
	"link partner advertised link modes": "p",
}

// parseEthtool parses `ethtool IF`. Link mode lists continue on the
// following, deeper-indented lines without a key.
func parseEthtool(s string) ethtoolInfo {
	var e ethtoolInfo
	cur := ""
	addModes := func(v string) {
		for _, tok := range strings.Fields(v) {
			if modeSpeed(tok) == 0 {
				continue
			}
			switch cur {
			case "s":
				e.Supported = append(e.Supported, tok)
			case "a":
				e.Advertised = append(e.Advertised, tok)
			case "p":
				e.Partner = append(e.Partner, tok)
			}
		}
	}
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		key := strings.ToLower(strings.TrimSpace(k))
		if !ok {
			// continuation line ("100baseT/Half 100baseT/Full", "drv probe link")
			addModes(line)
			continue
		}
		v = strings.TrimSpace(v)
		if m, isMode := ethtoolModeKeys[key]; isMode {
			cur = m
			addModes(v)
			continue
		}
		cur = ""
		switch key {
		case "speed":
			e.SpeedMbps = parseSpeed(v)
		case "duplex":
			switch strings.ToLower(strings.Fields(v + " ")[0]) {
			case "full":
				e.Duplex = "full"
			case "half":
				e.Duplex = "half"
			}
		case "auto-negotiation":
			e.AutoNeg = strings.ToLower(v)
		case "link partner advertised auto-negotiation":
			e.PartnerAuto = strings.ToLower(v)
		case "port":
			e.Port = v
		case "link detected":
			switch strings.ToLower(v) {
			case "yes":
				t := true
				e.LinkDetected = &t
			case "no":
				f := false
				e.LinkDetected = &f
			}
		}
	}
	return e
}

// modeSpeed returns the speed in Mb/s of an ethtool link mode such as
// "10000baseSR/Full" or "25000baseCR/Full", or 0.
func modeSpeed(mode string) int {
	i := strings.Index(mode, "base")
	if i <= 0 {
		return 0
	}
	n, err := strconv.Atoi(mode[:i])
	if err != nil || n <= 0 || n > 1_600_000 {
		return 0
	}
	return n
}

func maxModeSpeed(modes []string) int {
	m := 0
	for _, x := range modes {
		if s := modeSpeed(x); s > m {
			m = s
		}
	}
	return m
}

// parseSpeed parses "1000Mb/s", "25000Mb/s", "Unknown!" (-> 0).
func parseSpeed(v string) int {
	v = strings.TrimSpace(v)
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	n, err := strconv.Atoi(v[:i])
	if err != nil || n <= 0 || n > 1_600_000 {
		return 0
	}
	return n
}

// Bond is one Linux bonding interface from /proc/net/bonding/<name>.
type Bond struct {
	Name             string      `json:"name"`
	Mode             string      `json:"mode,omitempty"`
	MII              string      `json:"mii,omitempty"`
	ActiveSlave      string      `json:"activeSlave,omitempty"`
	ActiveAggregator string      `json:"activeAggregator,omitempty"`
	PartnerMAC       string      `json:"partnerMac,omitempty"`
	Slaves           []BondSlave `json:"slaves,omitempty"`
	CarriesIP        bool        `json:"carriesIp,omitempty"`
	Windows          bool        `json:"windows,omitempty"` // LBFO or SET team
}

// BondSlave is one member port.
type BondSlave struct {
	Name         string  `json:"name"`
	MII          string  `json:"mii,omitempty"`
	Speed        string  `json:"speed,omitempty"`
	Duplex       string  `json:"duplex,omitempty"`
	LinkFailures *uint64 `json:"linkFailures,omitempty"`
	AggregatorID string  `json:"aggregatorId,omitempty"`
	PermMAC      string  `json:"permMac,omitempty"`
	Reason       string  `json:"reason,omitempty"` // Windows FailureReason
}

func (b *Bond) is8023ad() bool { return strings.Contains(strings.ToLower(b.Mode), "802.3ad") }

// parseBonding parses /proc/net/bonding/<bond> (format: drivers/net/bonding/
// bond_procfs.c; samples in Documentation/networking/bonding.rst).
func parseBonding(name, s string) Bond {
	b := Bond{Name: name}
	var cur *BondSlave
	inAgg, inDetails := false, false
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			if line == "802.3ad info" {
				inAgg = false
			}
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case k == "Slave Interface":
			b.Slaves = append(b.Slaves, BondSlave{Name: v})
			cur = &b.Slaves[len(b.Slaves)-1]
			inAgg, inDetails = false, false
			continue
		case k == "Active Aggregator Info":
			inAgg = true
			continue
		case strings.HasPrefix(k, "details "):
			inDetails = true
			continue
		}
		if cur == nil {
			switch k {
			case "Bonding Mode":
				b.Mode = v
			case "MII Status":
				b.MII = strings.ToLower(v)
			case "Currently Active Slave":
				b.ActiveSlave = v
			case "Aggregator ID":
				if inAgg {
					b.ActiveAggregator = v
				}
			case "Partner Mac Address":
				if inAgg {
					b.PartnerMAC = strings.ToLower(v)
				}
			}
			continue
		}
		if inDetails {
			continue // LACP PDU details of the current slave
		}
		switch k {
		case "MII Status":
			cur.MII = strings.ToLower(v)
		case "Speed":
			cur.Speed = v
		case "Duplex":
			cur.Duplex = strings.ToLower(v)
		case "Link Failure Count":
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				cur.LinkFailures = &n
			}
		case "Aggregator ID":
			cur.AggregatorID = v
		case "Permanent HW addr":
			cur.PermMAC = strings.ToLower(v)
		}
	}
	return b
}

// topo is one line of network.topology.
type topo struct {
	Name, Kind, Master, Driver string
	Lower                      []string
}

func parseTopology(s string) map[string]topo {
	m := map[string]topo{}
	for _, l := range strings.Split(s, "\n") {
		var t topo
		for _, f := range strings.Fields(l) {
			k, v, _ := strings.Cut(f, "=")
			switch k {
			case "if":
				t.Name = v
			case "kind":
				t.Kind = v
			case "master":
				t.Master = v
			case "driver":
				t.Driver = v
			case "lower":
				if v != "" {
					t.Lower = strings.Split(v, ",")
				}
			}
		}
		if t.Name != "" {
			m[t.Name] = t
		}
	}
	return m
}

// parseSysfs groups network.sysfs lines by interface:
// "/sys/class/net/eth0/statistics/rx_crc_errors=0" -> ["eth0"]["rx_crc_errors"].
func parseSysfs(s string) map[string]map[string]string {
	m := map[string]map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(k), "/sys/class/net/")
		if !ok {
			continue
		}
		name, attr, ok := strings.Cut(rest, "/")
		if !ok || name == "" {
			continue
		}
		attr = strings.TrimPrefix(attr, "statistics/")
		if m[name] == nil {
			m[name] = map[string]string{}
		}
		m[name][attr] = strings.TrimSpace(v)
	}
	return m
}

// ipInfo is what `ip addr` says about one interface.
type ipInfo struct {
	AdminUp *bool
	Addrs   []string // global-scope addresses (CIDR)
}

// parseIP parses `ip -j addr` (iproute2 >= 4.13) or `ip -o addr`.
func parseIP(s string) map[string]*ipInfo {
	m := map[string]*ipInfo{}
	get := func(n string) *ipInfo {
		if m[n] == nil {
			m[n] = &ipInfo{}
		}
		return m[n]
	}
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "[") {
		var arr []struct {
			Ifname   string   `json:"ifname"`
			Flags    []string `json:"flags"`
			AddrInfo []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal([]byte(t), &arr); err == nil {
			for _, a := range arr {
				if a.Ifname == "" {
					continue
				}
				in := get(a.Ifname)
				if a.Flags != nil {
					up := false
					for _, f := range a.Flags {
						if f == "UP" {
							up = true
						}
					}
					in.AdminUp = &up
				}
				for _, ai := range a.AddrInfo {
					if usableIP(ai.Local) && (ai.Scope == "" || ai.Scope == "global" || ai.Scope == "site") {
						in.Addrs = append(in.Addrs, ai.Local+"/"+strconv.Itoa(ai.Prefixlen))
					}
				}
			}
			return m
		}
	}
	// "2: eth0    inet 172.29.218.192/20 brd 172.29.223.255 scope global eth0\ ..."
	for _, l := range strings.Split(t, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(name, '@'); i > 0 {
			name = name[:i]
		}
		if f[2] != "inet" && f[2] != "inet6" {
			continue
		}
		addr := f[3]
		host, _, _ := strings.Cut(addr, "/")
		scope := ""
		for i := 4; i+1 < len(f); i++ {
			if f[i] == "scope" {
				scope = f[i+1]
				break
			}
		}
		if usableIP(host) && (scope == "" || scope == "global" || scope == "site") {
			get(name).Addrs = append(get(name).Addrs, addr)
		}
	}
	return m
}

// usableIP reports whether an address means "this port carries traffic":
// not loopback, not link-local (fe80::/10, 169.254.0.0/16 APIPA).
func usableIP(s string) bool {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
