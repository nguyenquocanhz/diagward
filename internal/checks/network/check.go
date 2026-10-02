// Package network is the "network" domain: physical NIC link state,
// negotiated speed and duplex, physical-layer error counters, link flapping,
// and bond/team redundancy, on Linux and Windows.
package network

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "network"

// NIC is one physical network port.
type NIC struct {
	Name           string            `json:"name"`
	Kind           string            `json:"kind,omitempty"` // phys, wireless
	Description    string            `json:"description,omitempty"`
	Master         string            `json:"master,omitempty"` // bond / bridge / team
	BondSlave      bool              `json:"bondSlave,omitempty"`
	Driver         string            `json:"driver,omitempty"`
	DriverVersion  string            `json:"driverVersion,omitempty"`
	Firmware       string            `json:"firmware,omitempty"`
	BusInfo        string            `json:"busInfo,omitempty"`
	MAC            string            `json:"mac,omitempty"`
	OperState      string            `json:"operState,omitempty"`
	Carrier        *bool             `json:"carrier,omitempty"`
	AdminUp        *bool             `json:"adminUp,omitempty"`
	Disabled       bool              `json:"disabled,omitempty"` // Windows: adapter disabled
	SpeedMbps      int               `json:"speedMbps,omitempty"`
	Duplex         string            `json:"duplex,omitempty"`
	MTU            int               `json:"mtu,omitempty"`
	AutoNeg        string            `json:"autoNeg,omitempty"`
	ForcedSpeed    bool              `json:"forcedSpeed,omitempty"`
	SupportedMax   int               `json:"supportedMaxMbps,omitempty"`
	AdvertisedMax  int               `json:"advertisedMaxMbps,omitempty"`
	PartnerMax     int               `json:"partnerMaxMbps,omitempty"`
	CarrierChanges *uint64           `json:"carrierChanges,omitempty"`
	IPs            []string          `json:"ips,omitempty"`
	CarriesIP      bool              `json:"carriesIp,omitempty"` // in use: an IP on it or above it, or a bridge with guests
	UsedBy         string            `json:"usedBy,omitempty"`
	Stats          map[string]uint64 `json:"stats,omitempty"`
}

// Facts is the typed data of the network domain.
type Facts struct {
	NICs  []NIC  `json:"nics"`
	Bonds []Bond `json:"bonds,omitempty"`
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	switch b.OS {
	case collect.OSLinux:
		if len(b.Prefix("network.")) == 0 {
			return res
		}
		nics, bonds := linuxNICs(b)
		linuxCoverage(b, env, nics, &res)
		if env.Container {
			return res
		}
		analyze(nics, bonds, env, uptimeOf(b), &res)
	case collect.OSWindows:
		if b.Get("network.win_adapter") == nil {
			return res
		}
		nics, bonds, ok := windowsNICs(b)
		windowsCoverage(b, env, ok, &res)
		if !ok {
			return res
		}
		analyze(nics, bonds, env, uptimeOf(b), &res)
	}
	return res
}

func linuxCoverage(b *collect.Bundle, env model.Env, nics []NIC, res *model.Result) {
	c := model.Coverage{ID: "network.links", Component: model.CompNetwork,
		Name: model.T("Network ports (link, speed, errors, bonding)", "Cổng mạng (link, tốc độ, lỗi, bonding)")}
	eth := b.Get("network.ethtool")
	switch {
	case env.Container:
		c.State, c.Reason = model.CovSkipped, hint.Virtual(env)
	case len(nics) == 0:
		c.State = model.CovPartial
		c.Reason = model.T("No physical network port was found.", "Không tìm thấy cổng mạng vật lý nào.")
	case eth != nil && eth.Missing != "":
		c.State = model.CovPartial
		c.Reason = model.T("ethtool is not installed: supported speeds, driver and firmware were not checked.", "Chưa cài ethtool: chưa kiểm tra được tốc độ hỗ trợ, driver và firmware.")
		c.Fix = hint.Install(env, "ethtool")
	default:
		c.State = model.CovRan
	}
	res.Coverage = append(res.Coverage, c)
}

func uptimeOf(b *collect.Bundle) float64 {
	parse := func(s string) float64 {
		f := strings.Fields(s)
		if len(f) == 0 {
			return 0
		}
		x, err := strconv.ParseFloat(f[0], 64)
		if err != nil || x < 0 {
			return 0
		}
		return x
	}
	switch b.OS {
	case collect.OSLinux:
		if u := parse(b.Get("system.uptime").Text()); u > 0 {
			return u
		}
		return parse(b.Get("meta.ident").KV()["uptime"])
	case collect.OSWindows:
		var ps []struct{ SystemUpTime float64 }
		if collect.DecodeJSON(b.Get("system.win_perf").Text(), &ps) == nil && len(ps) > 0 {
			return ps[len(ps)-1].SystemUpTime
		}
	}
	return 0
}

// linuxNICs assembles the physical ports from sysfs, topology, ethtool and
// `ip addr`, and the bonds from /proc/net/bonding.
func linuxNICs(b *collect.Bundle) ([]NIC, []Bond) {
	tp := parseTopology(b.Get("network.topology").Text())
	sys := parseSysfs(b.Get("network.sysfs").Text())
	ips := parseIP(b.Get("network.ip").Text())

	names := map[string]bool{}
	for n := range sys {
		names[n] = true
	}
	for n, t := range tp {
		if t.Kind == "phys" || t.Kind == "wireless" {
			names[n] = true
		}
	}
	var bonds []Bond
	bondOf := map[string]string{}
	for _, s := range b.Prefix("network.bonding:") {
		name := strings.TrimPrefix(s.Name, "network.bonding:")
		if !s.Ran() {
			continue
		}
		bd := parseBonding(name, s.Text())
		for _, sl := range bd.Slaves {
			bondOf[sl.Name] = name
		}
		bonds = append(bonds, bd)
	}

	var nics []NIC
	for _, name := range sortedKeys(names) {
		n := NIC{Name: name, Kind: "phys"}
		if t, ok := tp[name]; ok {
			n.Kind, n.Master, n.Driver = t.Kind, t.Master, t.Driver
		}
		if bd, ok := bondOf[name]; ok {
			n.BondSlave = true
			if n.Master == "" {
				n.Master = bd
			}
		}
		if a := sys[name]; a != nil {
			n.OperState = a["operstate"]
			switch a["carrier"] {
			case "1":
				t := true
				n.Carrier = &t
			case "0":
				f := false
				n.Carrier = &f
			}
			if sp, err := strconv.Atoi(a["speed"]); err == nil && sp > 0 && sp < 1_600_000 {
				n.SpeedMbps = sp
			}
			if d := strings.ToLower(a["duplex"]); d == "full" || d == "half" {
				n.Duplex = d
			}
			n.MTU, _ = strconv.Atoi(a["mtu"])
			n.MAC = a["address"]
			if v, err := strconv.ParseUint(a["carrier_changes"], 10, 64); err == nil {
				n.CarrierChanges = &v
			}
			n.Stats = map[string]uint64{}
			for k, v := range a {
				if strings.HasPrefix(k, "rx_") || strings.HasPrefix(k, "tx_") || k == "collisions" || k == "multicast" {
					if x, err := strconv.ParseUint(v, 10, 64); err == nil {
						n.Stats[k] = x
					}
				}
			}
		}
		if s := b.Get("network.ethtool:" + name); s.Ran() {
			e := parseEthtool(s.Text())
			n.SupportedMax, n.AdvertisedMax, n.PartnerMax = maxModeSpeed(e.Supported), maxModeSpeed(e.Advertised), maxModeSpeed(e.Partner)
			n.AutoNeg = e.AutoNeg
			if e.LinkDetected != nil && n.Carrier == nil {
				n.Carrier = e.LinkDetected
			}
			if n.SpeedMbps == 0 {
				n.SpeedMbps = e.SpeedMbps
			}
			if n.Duplex == "" {
				n.Duplex = e.Duplex
			}
		}
		if s := b.Get("network.ethtool_i:" + name); s.Ran() {
			kv := colonKV(s.Text())
			if d := kv["driver"]; d != "" {
				n.Driver = d
			}
			n.DriverVersion = kv["version"]
			if fw := kv["firmware-version"]; fw != "" && !strings.EqualFold(fw, "n/a") {
				n.Firmware = fw
			}
			n.BusInfo = kv["bus-info"]
		}
		if in := ips[name]; in != nil {
			n.AdminUp = in.AdminUp
			n.IPs = in.Addrs
		}
		nics = append(nics, n)
	}

	// Which ports carry an IP: directly, or through a bridge/VLAN/bond above.
	uppers := map[string][]string{}
	for n, t := range tp {
		if t.Master != "" {
			uppers[n] = append(uppers[n], t.Master)
		}
		for _, l := range t.Lower {
			uppers[l] = append(uppers[l], n)
		}
	}
	for bd, sl := range invert(bondOf) {
		for _, s := range sl {
			uppers[s] = appendUnique(uppers[s], bd)
		}
	}
	// Bridges with VM/container ports (Proxmox vmbrN with tap/veth/fwpr
	// members) are in use even when the host has no IP on them.
	guests := map[string]int{}
	for _, t := range tp {
		if t.Master != "" && t.Kind == "virtual" && tp[t.Master].Kind == "bridge" {
			guests[t.Master]++
		}
	}
	carries := func(start string) (bool, string) {
		seen := map[string]bool{}
		q := []string{start}
		for len(q) > 0 {
			x := q[0]
			q = q[1:]
			if seen[x] {
				continue
			}
			seen[x] = true
			if in := ips[x]; in != nil && len(in.Addrs) > 0 {
				return true, ""
			}
			if guests[x] > 0 {
				return true, fmt.Sprintf("bridge %s (%d VM/container ports)", x, guests[x])
			}
			q = append(q, uppers[x]...)
		}
		return false, ""
	}
	for i := range nics {
		nics[i].CarriesIP, nics[i].UsedBy = carries(nics[i].Name)
	}
	for i := range bonds {
		bonds[i].CarriesIP, _ = carries(bonds[i].Name)
	}
	return nics, bonds
}

func invert(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		out[v] = append(out[v], k)
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// colonKV parses "key: value" lines with lower-case keys.
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

// Thresholds.
const (
	// IEEE 802.3 specifies a bit error ratio of at most 1e-12 for 1G/10G
	// links, i.e. about one bad 1500-byte frame in 1e8. More than one CRC or
	// alignment (frame) error per million packets is two orders of magnitude
	// above that: a damaged cable, a dirty/failing SFP or a bad switch port.
	// At least 10 errors are required so a single replug does not count.
	physErrRate = 1e-6
	physErrMin  = 10
	// A boot adds 1-4 carrier transitions (driver init, negotiation; WSL's
	// eth0 shows 3 after boot) and each switch reboot or cable move adds 2.
	// 20+ transitions averaging 6+ per day of uptime (3 link losses a day)
	// is a link that keeps dropping: cable, SFP, NIC or switch port.
	flapMin       = 20
	flapPerDay    = 6.0
	bondFailMin   = 10 // bonding "Link Failure Count" counts only link losses
	bondFailToDay = 3.0
	// Dropped packets are often benign on Linux (unknown protocols, VLANs
	// not configured, multicast nobody joined), so drops are Info only, and
	// only above 0.1 % of traffic.
	dropRate = 1e-3
	dropMin  = 1000
)

// linkUp reports whether the port has carrier; unknown counts as not down.
func (n *NIC) linkDown() bool {
	if n.Disabled {
		return false
	}
	if n.Carrier != nil {
		return !*n.Carrier
	}
	return n.OperState == "down" || n.OperState == "lowerlayerdown"
}

func (n *NIC) linkUp() bool {
	if n.Carrier != nil {
		return *n.Carrier
	}
	return n.OperState == "up"
}

func (n *NIC) part() *model.Part {
	loc := n.Name
	var extra []string
	if n.MAC != "" {
		extra = append(extra, "MAC "+n.MAC)
	}
	if n.BusInfo != "" {
		extra = append(extra, "PCI "+n.BusInfo)
	}
	if len(extra) > 0 {
		loc += " (" + strings.Join(extra, ", ") + ")"
	}
	mdl := n.Description
	if mdl == "" {
		mdl = n.Driver
	}
	return &model.Part{Kind: "nic", Model: mdl, Location: loc, Firmware: n.Firmware}
}

func (n *NIC) stat(k string) uint64 { return n.Stats[k] }

func speedText(mbps int) string {
	switch {
	case mbps <= 0:
		return "?"
	case mbps >= 1000 && mbps%1000 == 0:
		return fmt.Sprintf("%d Gb/s", mbps/1000)
	case mbps >= 1000:
		return fmt.Sprintf("%.1f Gb/s", float64(mbps)/1000)
	}
	return fmt.Sprintf("%d Mb/s", mbps)
}

func analyze(nics []NIC, bonds []Bond, env model.Env, uptime float64, res *model.Result) {
	res.Facts = &Facts{NICs: nics, Bonds: bonds}
	byName := map[string]*NIC{}
	for i := range nics {
		byName[nics[i].Name] = &nics[i]
	}
	vm := env.Virtual != "" && !env.Container
	problems := 0
	rowStatus := map[string]model.Severity{}
	mark := func(name string, s model.Severity) {
		if s > rowStatus[name] {
			rowStatus[name] = s
		}
		if s >= model.Warn {
			problems++
		}
	}

	for i := range bonds {
		bondFindings(&bonds[i], byName, vm, res, mark)
	}
	siblingsUp := map[string]int{}
	for i := range nics {
		if nics[i].Master != "" && nics[i].linkUp() && nics[i].Kind != "wireless" {
			siblingsUp[nics[i].Master]++
		}
	}

	for i := range nics {
		n := &nics[i]
		if n.Kind == "wireless" {
			continue
		}
		// Link down while the port carries an IP (and is not protected by a bond).
		if n.linkDown() && n.CarriesIP && !n.BondSlave {
			sev := model.Crit
			act := model.Tf("Check the cable and the switch port of %s (link LEDs on both ends), try another cable or port, reseat or replace the SFP/DAC. If the switch side is up, check the NIC in the BMC/iDRAC/iLO and the kernel log (journalctl -k | grep %s).",
				"Kiểm tra dây mạng và cổng switch của %s (đèn link ở cả hai đầu), thử dây hoặc cổng khác, cắm lại hoặc thay module SFP/DAC. Nếu phía switch vẫn up, kiểm tra card mạng trong BMC/iDRAC/iLO và log kernel (journalctl -k | grep %s).", n.Name, n.Name)
			if vm {
				sev = model.Warn
				act = model.Tf("Check that the virtual NIC %s is connected in the hypervisor (VM settings, port group/bridge), and that the host's physical uplink is up.",
					"Kiểm tra card mạng ảo %s đã được kết nối trong hypervisor (cấu hình VM, port group/bridge) và đường uplink vật lý của máy host vẫn hoạt động.", n.Name)
			}
			detail := model.Tf("%s is configured (%s) but reports no carrier: traffic through this port is down.",
				"%s đã được cấu hình (%s) nhưng không có tín hiệu link: mọi kết nối qua cổng này đang bị gián đoạn.", n.Name, ipSummary(n, nics))
			// Another physical port of the same master (team, OVS, bridge
			// with two uplinks) still has link: redundancy lost, not an outage.
			if n.Master != "" && siblingsUp[n.Master] > 0 {
				sev = model.Warn
				detail = model.Tf("%s (member of %s) reports no carrier. Traffic continues over the other port(s) of %s, but redundancy is lost.",
					"%s (thuộc %s) không có tín hiệu link. Kết nối vẫn chạy qua cổng khác của %s nhưng đã mất dự phòng.", n.Name, n.Master, n.Master)
			}
			if n.AdminUp != nil && !*n.AdminUp {
				sev = model.Warn
				act = model.Tf("The port is administratively down. If it should be in use, bring it up (ip link set %s up, or nmcli/ifup) and check the network configuration.",
					"Cổng đang bị tắt bằng cấu hình. Nếu cổng cần dùng, bật lại (ip link set %s up, hoặc nmcli/ifup) và kiểm tra cấu hình mạng.", n.Name)
			}
			res.Findings = append(res.Findings, model.Finding{
				ID: "network.link_down", Component: model.CompNetwork, Severity: sev, Target: n.Name,
				Title:    model.Tf("Network port %s is in use but has no link", "Cổng mạng %s đang được sử dụng nhưng mất link", n.Name),
				Detail:   detail,
				Action:   act,
				Evidence: nicEvidence(n),
				Part:     n.part(),
			})
			mark(n.Name, sev)
		}
		if !n.linkUp() {
			continue
		}
		if !vm {
			speedFindings(n, res, mark)
			if n.Duplex == "half" {
				res.Findings = append(res.Findings, model.Finding{
					ID: "network.half_duplex", Component: model.CompNetwork, Severity: model.Warn, Target: n.Name,
					Title: model.Tf("%s runs at half duplex (%s)", "%s đang chạy half duplex (%s)", n.Name, speedText(n.SpeedMbps)),
					Detail: model.T("Switched networks always run full duplex. Half duplex means auto-negotiation failed or one side was forced (duplex mismatch), which causes collisions, late collisions and very slow transfers.",
						"Mạng dùng switch luôn chạy full duplex. Half duplex nghĩa là tự thương lượng bị lỗi hoặc một đầu bị ép cấu hình (lệch duplex), gây va chạm gói và truyền rất chậm."),
					Action: model.Tf("Set both the NIC and the switch port to auto-negotiation (ethtool -s %s autoneg on), then replace the cable if it stays at half duplex.",
						"Đặt cả card mạng và cổng switch về tự thương lượng (ethtool -s %s autoneg on); nếu vẫn half duplex thì thay dây mạng.", n.Name),
					Evidence: nicEvidence(n),
					Part:     n.part(),
				})
				mark(n.Name, model.Warn)
			}
		}
		errorFindings(n, res, mark)
		flapFindings(n, bonds, uptime, res, mark)
		dropFindings(n, res, mark)
	}

	nicTable(nics, bonds, rowStatus, res)
	if problems == 0 && len(nics) > 0 {
		up := 0
		for i := range nics {
			if nics[i].linkUp() {
				up++
			}
		}
		extra, extraVI := "", ""
		if len(bonds) > 0 {
			extra = fmt.Sprintf(", %d bond(s) redundant", len(bonds))
			extraVI = fmt.Sprintf(", %d bond/team đủ dự phòng", len(bonds))
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.links_ok", Component: model.CompNetwork, Severity: model.OK,
			Title: model.Tf("%d network port(s) checked, %d with link: no errors found%s", "Đã kiểm tra %d cổng mạng, %d cổng có link: không phát hiện lỗi%s", len(nics), up, extra),
		})
		if extraVI != "" {
			f := &res.Findings[len(res.Findings)-1]
			f.Title.VI = fmt.Sprintf("Đã kiểm tra %d cổng mạng, %d cổng có link: không phát hiện lỗi%s", len(nics), up, extraVI)
		}
	}
}

func ipSummary(n *NIC, nics []NIC) string {
	if len(n.IPs) > 0 {
		return strings.Join(n.IPs, ", ")
	}
	if n.UsedBy != "" {
		return n.UsedBy
	}
	if n.Master != "" {
		return "via " + n.Master
	}
	return "IP on an upper interface"
}

func nicEvidence(n *NIC) []string {
	var ev []string
	l := fmt.Sprintf("%s: operstate=%s", n.Name, n.OperState)
	if n.Carrier != nil {
		l += fmt.Sprintf(" carrier=%t", *n.Carrier)
	}
	if n.SpeedMbps > 0 {
		l += " speed=" + speedText(n.SpeedMbps)
	}
	if n.Duplex != "" {
		l += " duplex=" + n.Duplex
	}
	ev = append(ev, l)
	if n.SupportedMax > 0 || n.PartnerMax > 0 {
		ev = append(ev, fmt.Sprintf("supported up to %s, advertised up to %s, link partner up to %s, auto-negotiation %s",
			speedText(n.SupportedMax), speedText(n.AdvertisedMax), speedText(n.PartnerMax), orQ(n.AutoNeg)))
	}
	if n.Driver != "" || n.Firmware != "" || n.Description != "" {
		ev = append(ev, strings.TrimSpace(fmt.Sprintf("%s driver=%s %s firmware=%s bus=%s", n.Description, n.Driver, n.DriverVersion, n.Firmware, n.BusInfo)))
	}
	if len(n.IPs) > 0 {
		ev = append(ev, "addresses: "+strings.Join(n.IPs, ", "))
	}
	if n.Master != "" {
		ev = append(ev, "member of "+n.Master)
	}
	return ev
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// speedFindings compares the negotiated speed with what the port and the
// link partner support.
func speedFindings(n *NIC, res *model.Result, mark func(string, model.Severity)) {
	sp := n.SpeedMbps
	if sp <= 0 || n.SupportedMax <= 0 {
		return
	}
	common := n.SupportedMax
	if n.PartnerMax > 0 && n.PartnerMax < common {
		common = n.PartnerMax
	}
	switch {
	case n.PartnerMax > 0 && common > sp:
		// Both ends offer more than what was negotiated: the link fell back
		// ("downshift"), which on copper means a broken pair in the cable.
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.speed_low", Component: model.CompNetwork, Severity: model.Warn, Target: n.Name,
			Title: model.Tf("%s linked at %s although both ends support %s", "%s chỉ chạy %s dù cả hai đầu hỗ trợ %s", n.Name, speedText(sp), speedText(common)),
			Detail: model.T("The NIC and the switch both advertise a faster mode, but the link came up slower. This is the classic sign of a damaged cable (a broken wire pair makes gigabit fall back to 100 Mb/s), a bad patch panel or a failing port/SFP.",
				"Card mạng và switch đều hỗ trợ tốc độ cao hơn nhưng link chỉ lên tốc độ thấp. Đây là dấu hiệu điển hình của dây mạng hỏng (đứt một cặp dây khiến gigabit tụt xuống 100 Mb/s), patch panel lỗi hoặc cổng/module SFP sắp hỏng."),
			Action: model.Tf("Replace the cable of %s (Cat5e/Cat6 for 1 Gb/s, Cat6a for 10GBASE-T), try another switch port, then reseat or replace the SFP. Check again with: ethtool %s.",
				"Thay dây mạng của %s (Cat5e/Cat6 cho 1 Gb/s, Cat6a cho 10GBASE-T), thử cổng switch khác, sau đó cắm lại hoặc thay module SFP. Kiểm tra lại bằng: ethtool %s.", n.Name, n.Name),
			Evidence: nicEvidence(n), Part: n.part(),
		})
		mark(n.Name, model.Warn)
	case sp <= 100 && n.SupportedMax >= 1000:
		// Servers are never meant to run at 10/100 Mb/s on gigabit ports.
		why := model.T("The port supports gigabit or faster but negotiated 100 Mb/s or less: a damaged cable, a 100 Mb/s switch port or a forced speed setting.",
			"Cổng hỗ trợ gigabit trở lên nhưng chỉ chạy 100 Mb/s hoặc thấp hơn: dây mạng hỏng, cổng switch chỉ 100 Mb/s hoặc bị ép tốc độ.")
		if n.PartnerMax > 0 && n.PartnerMax <= sp {
			why = model.Tf("The link partner (switch port) only offers up to %s, so the switch port, its configuration or an old switch is the limit.",
				"Thiết bị đầu bên kia (cổng switch) chỉ hỗ trợ tối đa %s, nên giới hạn nằm ở cổng switch, cấu hình của nó hoặc switch đời cũ.", speedText(n.PartnerMax))
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.speed_low", Component: model.CompNetwork, Severity: model.Warn, Target: n.Name,
			Title:  model.Tf("%s runs at only %s on a %s port", "%s chỉ chạy %s trên cổng hỗ trợ %s", n.Name, speedText(sp), speedText(n.SupportedMax)),
			Detail: why,
			Action: model.Tf("Check the switch port speed setting (auto), move %s to a gigabit port, replace the cable, and make sure the NIC is set to auto-negotiation (ethtool -s %s autoneg on).",
				"Kiểm tra cấu hình tốc độ cổng switch (để auto), chuyển %s sang cổng gigabit, thay dây mạng và đảm bảo card mạng để tự thương lượng (ethtool -s %s autoneg on).", n.Name, n.Name),
			Evidence: nicEvidence(n), Part: n.part(),
		})
		mark(n.Name, model.Warn)
	case n.SupportedMax > sp && (n.AdvertisedMax == 0 || n.AdvertisedMax > sp || n.ForcedSpeed):
		note := model.T("This is normal if the switch port or the module is slower (for example a 10 GbE NIC on a 1 GbE switch).",
			"Điều này bình thường nếu cổng switch hoặc module chậm hơn (ví dụ card 10 GbE cắm switch 1 GbE).")
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.speed_below_max", Component: model.CompNetwork, Severity: model.Info, Target: n.Name,
			Title:    model.Tf("%s runs at %s; the port supports up to %s", "%s đang chạy %s; cổng hỗ trợ tối đa %s", n.Name, speedText(sp), speedText(n.SupportedMax)),
			Detail:   note,
			Action:   model.T("If the switch and module support the higher speed, check the cable/module type and the switch port configuration.", "Nếu switch và module hỗ trợ tốc độ cao hơn, kiểm tra loại dây/module và cấu hình cổng switch."),
			Evidence: nicEvidence(n), Part: n.part(),
		})
		mark(n.Name, model.Info)
	}
}

func errorFindings(n *NIC, res *model.Result, mark func(string, model.Severity)) {
	rxPk := n.stat("rx_packets")
	rxErr := n.stat("rx_crc_errors") + n.stat("rx_frame_errors")
	txPk := n.stat("tx_packets")
	txErr := n.stat("tx_carrier_errors")
	winRx := n.stat("win_rx_errors") // Windows: ReceivedPacketErrors
	winTx := n.stat("win_tx_errors")
	check := func(errs, pk uint64) bool {
		if errs < physErrMin {
			return false
		}
		return pk == 0 || float64(errs)/float64(pk) >= physErrRate
	}
	var ev []string
	bad := false
	if check(rxErr, rxPk) {
		bad = true
		ev = append(ev, fmt.Sprintf("rx_crc_errors=%d rx_frame_errors=%d rx_packets=%d (%.2g per packet)", n.stat("rx_crc_errors"), n.stat("rx_frame_errors"), rxPk, ratio(rxErr, rxPk)))
	}
	if check(txErr, txPk) {
		bad = true
		ev = append(ev, fmt.Sprintf("tx_carrier_errors=%d tx_packets=%d (%.2g per packet)", txErr, txPk, ratio(txErr, txPk)))
	}
	if check(winRx, rxPk) {
		bad = true
		ev = append(ev, fmt.Sprintf("ReceivedPacketErrors=%d received packets=%d (%.2g per packet)", winRx, rxPk, ratio(winRx, rxPk)))
	}
	if check(winTx, txPk) {
		bad = true
		ev = append(ev, fmt.Sprintf("OutboundPacketErrors=%d sent packets=%d (%.2g per packet)", winTx, txPk, ratio(winTx, txPk)))
	}
	if !bad {
		return
	}
	total := rxErr + txErr + winRx + winTx
	res.Findings = append(res.Findings, model.Finding{
		ID: "network.rx_errors", Component: model.CompNetwork, Severity: model.Warn, Target: n.Name,
		Title: model.Tf("%s has %s physical-layer errors (bad frames)", "%s có %s lỗi đường truyền (khung hỏng)", n.Name, units.Thousands(total)),
		Detail: model.T("CRC/alignment errors mean frames arrived damaged. The rate is far above what a healthy Ethernet link produces (IEEE 802.3 allows about one bad frame in 100 million), which points at the cable, the SFP/transceiver or the switch port. Damaged frames are retransmitted, so applications see slowness and timeouts.",
			"Lỗi CRC/alignment nghĩa là gói tin đến nơi đã bị hỏng. Tỉ lệ này cao hơn nhiều so với link Ethernet bình thường (chuẩn IEEE 802.3 chỉ cho phép khoảng 1 khung lỗi trên 100 triệu), cho thấy lỗi ở dây mạng, module SFP hoặc cổng switch. Gói hỏng phải gửi lại nên ứng dụng bị chậm và timeout."),
		Action: model.Tf("Replace the cable of %s, clean or replace the SFP/fibre patch, try another switch port, and check the error counters on the switch side too. Watch whether the counters still grow: ip -s link show %s.",
			"Thay dây mạng của %s, vệ sinh hoặc thay module SFP/dây quang, thử cổng switch khác và xem bộ đếm lỗi ở phía switch. Theo dõi bộ đếm có còn tăng không: ip -s link show %s.", n.Name, n.Name),
		Evidence: units.Evidence(append(ev, nicEvidence(n)...), 10),
		Part:     n.part(),
	})
	mark(n.Name, model.Warn)
}

func ratio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func flapFindings(n *NIC, bonds []Bond, uptime float64, res *model.Result, mark func(string, model.Severity)) {
	days := uptime / 86400
	var count uint64
	var what string
	threshold, perDay := uint64(flapMin), flapPerDay
	if n.CarrierChanges != nil {
		count, what = *n.CarrierChanges, "carrier_changes"
	} else {
		for _, b := range bonds {
			for _, s := range b.Slaves {
				if s.Name == n.Name && s.LinkFailures != nil {
					count, what = *s.LinkFailures, "bonding Link Failure Count"
					threshold, perDay = bondFailMin, bondFailToDay
				}
			}
		}
	}
	if what == "" || count < threshold {
		return
	}
	if days > 0 && float64(count)/days < perDay {
		return
	}
	rate := ""
	rateVI := ""
	if days > 0 {
		rate = fmt.Sprintf(" (%.0f per day over %.1f days of uptime)", float64(count)/days, days)
		rateVI = fmt.Sprintf(" (%.0f lần/ngày trong %.1f ngày chạy)", float64(count)/days, days)
	}
	res.Findings = append(res.Findings, model.Finding{
		ID: "network.link_flapping", Component: model.CompNetwork, Severity: model.Warn, Target: n.Name,
		Title: model.Tf("Link on %s keeps going down and up (%s changes)", "Link của %s liên tục rớt rồi lên lại (%s lần)", n.Name, units.Thousands(count)),
		Detail: model.Text{
			EN: fmt.Sprintf("%s = %d%s. Each drop interrupts traffic for seconds and can trigger bond failovers and spanning-tree recalculation.", what, count, rate),
			VI: fmt.Sprintf("%s = %d%s. Mỗi lần rớt link làm gián đoạn kết nối vài giây và có thể gây chuyển đổi bond, tính toán lại spanning-tree.", what, count, rateVI),
		},
		Action: model.Tf("Check the cable and connectors of %s, reseat or replace the SFP/DAC, look at the switch port log (err-disable, flaps), and check the kernel log for the link down/up times: journalctl -k | grep '%s.*Link'.",
			"Kiểm tra dây và đầu cắm của %s, cắm lại hoặc thay module SFP/DAC, xem log cổng switch (err-disable, flap) và xem thời điểm rớt/lên link trong log kernel: journalctl -k | grep '%s.*Link'.", n.Name, n.Name),
		Evidence: nicEvidence(n),
		Part:     n.part(),
	})
	mark(n.Name, model.Warn)
}

func dropFindings(n *NIC, res *model.Result, mark func(string, model.Severity)) {
	drops := n.stat("rx_dropped") + n.stat("tx_dropped") + n.stat("rx_missed_errors") + n.stat("rx_fifo_errors") + n.stat("win_rx_discards") + n.stat("win_tx_discards")
	pk := n.stat("rx_packets") + n.stat("tx_packets")
	if drops < dropMin || pk == 0 || float64(drops)/float64(pk) < dropRate {
		return
	}
	res.Findings = append(res.Findings, model.Finding{
		ID: "network.drops", Component: model.CompNetwork, Severity: model.Info, Target: n.Name,
		Title: model.Tf("%s dropped %s packets (%.2f%% of traffic)", "%s đã bỏ %s gói tin (%.2f%% lưu lượng)", n.Name, units.Thousands(drops), float64(drops)*100/float64(pk)),
		Detail: model.T("Dropped packets are often harmless (unknown protocols, VLANs not configured on this host), but missed/FIFO drops mean the NIC's receive ring overflowed because the host did not keep up.",
			"Gói bị bỏ thường vô hại (giao thức lạ, VLAN không cấu hình trên máy này), nhưng lỗi missed/FIFO nghĩa là bộ đệm nhận của card mạng bị tràn do máy xử lý không kịp."),
		Action: model.Tf("If users see packet loss, check ethtool -S %s for the drop reason and consider a larger ring buffer (ethtool -g/-G).",
			"Nếu người dùng bị mất gói, xem ethtool -S %s để biết nguyên nhân và cân nhắc tăng ring buffer (ethtool -g/-G).", n.Name),
		Evidence: []string{fmt.Sprintf("rx_dropped=%d tx_dropped=%d rx_missed_errors=%d rx_fifo_errors=%d discards=%d packets=%d",
			n.stat("rx_dropped"), n.stat("tx_dropped"), n.stat("rx_missed_errors"), n.stat("rx_fifo_errors"), n.stat("win_rx_discards")+n.stat("win_tx_discards"), pk)},
	})
	mark(n.Name, model.Info)
}

// bondFindings checks redundancy of a bond (Linux) or team (Windows).
func bondFindings(bd *Bond, byName map[string]*NIC, vm bool, res *model.Result, mark func(string, model.Severity)) {
	var up, down []BondSlave
	for _, s := range bd.Slaves {
		if s.MII == "up" {
			up = append(up, s)
		} else {
			down = append(down, s)
		}
	}
	ev := bondEvidence(bd)
	kind := "Bond"
	if bd.Windows {
		kind = "Team"
	}
	switch {
	case bd.MII == "down" || (len(bd.Slaves) > 0 && len(up) == 0):
		sev := model.Crit
		if !bd.CarriesIP && !bd.Windows {
			sev = model.Warn // configured but not carrying an address
		}
		if vm && sev == model.Crit {
			sev = model.Warn
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.bond_down", Component: model.CompNetwork, Severity: sev, Target: bd.Name,
			Title: model.Tf("%s %s is down: no member port has link", "%s %s đã mất kết nối: không cổng thành viên nào có link", kind, bd.Name),
			Detail: model.Tf("All member ports of %s (%s) are down, so everything that uses it is offline.",
				"Tất cả cổng thành viên của %s (%s) đều mất link nên mọi dịch vụ dùng nó đang mất mạng.", bd.Name, slaveNames(bd.Slaves)),
			Action: model.T("Check the cables and switch ports of every member (link LEDs), the switch itself (powered, uplinks, port-channel/LACP configuration), and the NIC status in the BMC.",
				"Kiểm tra dây và cổng switch của từng cổng thành viên (đèn link), bản thân switch (nguồn, uplink, cấu hình port-channel/LACP) và trạng thái card mạng trong BMC."),
			Evidence: ev,
		})
		for _, s := range bd.Slaves {
			mark(s.Name, sev)
		}
		return
	case len(down) > 0:
		names := slaveNames(down)
		var part *model.Part
		if n := byName[down[0].Name]; n != nil {
			part = n.part()
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.bond_degraded", Component: model.CompNetwork, Severity: model.Warn, Target: bd.Name,
			Title: model.Tf("%s %s lost redundancy: port %s is down", "%s %s mất dự phòng: cổng %s bị rớt link", kind, bd.Name, names),
			Detail: model.Tf("%s still works on %s, but if that port or its cable fails too, the server goes offline.%s",
				"%s vẫn chạy trên %s, nhưng nếu cổng hoặc dây đó hỏng nốt thì máy chủ sẽ mất mạng.%s", bd.Name, slaveNames(up), reasonText(down)),
			Action: model.Tf("Check the cable and switch port of %s (link LED), reseat or replace the SFP/cable, and check the port on the switch (shutdown, err-disabled, wrong VLAN/port-channel).",
				"Kiểm tra dây và cổng switch của %s (đèn link), cắm lại hoặc thay SFP/dây, và kiểm tra cổng trên switch (bị shutdown, err-disabled, sai VLAN/port-channel).", names),
			Evidence: ev,
			Part:     part,
		})
		for _, s := range down {
			mark(s.Name, model.Warn)
		}
		return
	}
	// 802.3ad: every up member must be in the active aggregator, otherwise
	// LACP did not form with the switch and only part of the links carry
	// traffic (no redundancy for the rest).
	if bd.is8023ad() && bd.ActiveAggregator != "" {
		var out []BondSlave
		for _, s := range up {
			if s.AggregatorID != "" && s.AggregatorID != bd.ActiveAggregator {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			noPartner := bd.PartnerMAC == "" || strings.Trim(strings.ReplaceAll(bd.PartnerMAC, ":", ""), "0") == ""
			why := model.T("", "")
			if noPartner {
				why = model.T(" The switch did not answer LACP (partner MAC 00:00:00:00:00:00): the switch ports are probably not configured as an LACP port-channel.",
					" Switch không phản hồi LACP (partner MAC 00:00:00:00:00:00): nhiều khả năng các cổng switch chưa được cấu hình port-channel LACP.")
			}
			res.Findings = append(res.Findings, model.Finding{
				ID: "network.bond_lacp", Component: model.CompNetwork, Severity: model.Warn, Target: bd.Name,
				Title: model.Tf("Bond %s: LACP did not include port %s", "Bond %s: LACP chưa gộp được cổng %s", bd.Name, slaveNames(out)),
				Detail: model.Text{
					EN: fmt.Sprintf("Active aggregator is %s, but %s sits in another aggregator, so it carries no traffic and gives no redundancy.%s", bd.ActiveAggregator, slaveNames(out), why.EN),
					VI: fmt.Sprintf("Aggregator đang hoạt động là %s nhưng %s nằm ở aggregator khác nên không truyền dữ liệu và không có dự phòng.%s", bd.ActiveAggregator, slaveNames(out), why.VI),
				},
				Action: model.T("Configure the switch ports of all members in one LACP port-channel (mode active) with the same speed and VLANs; check cabling goes to the right switch ports.",
					"Cấu hình các cổng switch của tất cả thành viên vào cùng một port-channel LACP (mode active), cùng tốc độ và VLAN; kiểm tra dây cắm đúng cổng switch."),
				Evidence: ev,
			})
			for _, s := range out {
				mark(s.Name, model.Warn)
			}
			return
		}
	}
	if len(bd.Slaves) >= 2 {
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.bond_ok", Component: model.CompNetwork, Severity: model.OK, Target: bd.Name,
			Title: model.Tf("%s %s is redundant: all %d ports up (%s)", "%s %s đủ dự phòng: cả %d cổng đều up (%s)", kind, bd.Name, len(bd.Slaves), modeShort(bd.Mode)),
		})
	} else if len(bd.Slaves) == 1 {
		res.Findings = append(res.Findings, model.Finding{
			ID: "network.bond_single", Component: model.CompNetwork, Severity: model.Info, Target: bd.Name,
			Title:    model.Tf("%s %s has only one member port (no redundancy)", "%s %s chỉ có một cổng thành viên (không có dự phòng)", kind, bd.Name),
			Action:   model.T("Add a second port, cabled to a second switch, if this link must survive a cable or switch failure.", "Thêm cổng thứ hai, cắm sang switch thứ hai, nếu đường mạng này cần chịu được lỗi dây hoặc switch."),
			Evidence: ev,
		})
	}
}

func modeShort(m string) string {
	if m == "" {
		return "?"
	}
	return m
}

func reasonText(ss []BondSlave) string {
	var r []string
	for _, s := range ss {
		if s.Reason != "" {
			r = append(r, s.Name+": "+s.Reason)
		}
	}
	if len(r) == 0 {
		return ""
	}
	return " (" + strings.Join(r, "; ") + ")"
}

func slaveNames(ss []BondSlave) string {
	var n []string
	for _, s := range ss {
		n = append(n, s.Name)
	}
	if len(n) == 0 {
		return "-"
	}
	return strings.Join(n, ", ")
}

func bondEvidence(bd *Bond) []string {
	ev := []string{fmt.Sprintf("%s: mode=%s status=%s active=%s", bd.Name, bd.Mode, orQ(bd.MII), orQ(bd.ActiveSlave))}
	if bd.ActiveAggregator != "" {
		ev = append(ev, fmt.Sprintf("active aggregator %s, partner MAC %s", bd.ActiveAggregator, orQ(bd.PartnerMAC)))
	}
	for _, s := range bd.Slaves {
		l := fmt.Sprintf("  %s: status=%s speed=%s duplex=%s", s.Name, orQ(s.MII), orQ(s.Speed), orQ(s.Duplex))
		if s.LinkFailures != nil {
			l += fmt.Sprintf(" link_failures=%d", *s.LinkFailures)
		}
		if s.AggregatorID != "" {
			l += " aggregator=" + s.AggregatorID
		}
		if s.Reason != "" {
			l += " reason=" + s.Reason
		}
		ev = append(ev, l)
	}
	return units.Evidence(ev, 10)
}

func nicTable(nics []NIC, bonds []Bond, status map[string]model.Severity, res *model.Result) {
	if len(nics) == 0 {
		return
	}
	t := model.Table{
		ID:    "network.nics",
		Title: model.T("Network ports", "Cổng mạng"),
		Columns: []model.Text{
			model.T("Port", "Cổng"), model.T("Driver / firmware", "Driver / firmware"), model.T("Link", "Link"),
			model.T("Speed / duplex", "Tốc độ / duplex"), model.T("Member of", "Thuộc"), model.T("IP", "IP"),
			model.T("CRC/frame errors", "Lỗi CRC/frame"), model.T("Link changes", "Số lần đổi link"),
		},
		Note: model.T("Ports without link and without an IP are treated as unused.", "Cổng không có link và không cấu hình IP được coi là không sử dụng."),
	}
	for i := range nics {
		n := &nics[i]
		link := "?"
		switch {
		case n.Disabled:
			link = "disabled"
		case n.linkUp():
			link = "up"
		case n.linkDown():
			link = "down"
			if !n.CarriesIP && !n.BondSlave {
				link = "down (unused)"
			}
		}
		sd := ""
		if n.linkUp() && n.SpeedMbps > 0 {
			sd = speedText(n.SpeedMbps)
			if n.Duplex != "" {
				sd += " " + n.Duplex
			}
		}
		drv := strings.TrimSpace(strings.Join(nonEmpty(firstNonEmpty(n.Description, n.Driver), n.DriverVersion, n.Firmware), " / "))
		errs := n.stat("rx_crc_errors") + n.stat("rx_frame_errors") + n.stat("win_rx_errors")
		flaps := ""
		if n.CarrierChanges != nil {
			flaps = fmt.Sprint(*n.CarrierChanges)
		}
		ip := strings.Join(n.IPs, ", ")
		if ip == "" && n.CarriesIP {
			ip = "(via " + firstNonEmpty(n.Master, "upper interface") + ")"
		}
		t.Rows = append(t.Rows, model.Row{Status: status[n.Name], Cells: []string{
			n.Name, drv, link, sd, n.Master, ip, fmt.Sprint(errs), flaps,
		}})
	}
	res.Tables = append(res.Tables, t)
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
