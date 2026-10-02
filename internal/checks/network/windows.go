package network

import (
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

type winAdapter struct {
	Name                 string
	InterfaceDescription string
	InterfaceIndex       int
	Status               string
	MediaConnectionState string
	LinkSpeed            string
	ReceiveLinkSpeed     *float64
	TransmitLinkSpeed    *float64
	FullDuplex           *bool
	MacAddress           string
	DriverProvider       string
	DriverVersionString  string
	DriverDate           string
	NdisPhysicalMedium   *int
	PnPDeviceID          string
}

type winStats struct {
	Name                                                                       string
	ReceivedUnicastPackets, ReceivedMulticastPackets, ReceivedBroadcastPackets uint64
	SentUnicastPackets, SentMulticastPackets, SentBroadcastPackets             uint64
	ReceivedPacketErrors, OutboundPacketErrors                                 uint64
	ReceivedDiscardedPackets, OutboundDiscardedPackets                         uint64
}

// NdisPhysicalMedium values (ntddndis.h): 0 unspecified, 9 native 802.11,
// 10 Bluetooth, 11 InfiniBand, 14 802.3 (Ethernet). Only wired media get the
// speed/duplex checks.
func wiredMedium(m *int) bool {
	if m == nil {
		return true
	}
	switch *m {
	case 0, 11, 14:
		return true
	}
	return false
}

// speedDuplexMax maps the NDIS *SpeedDuplex keyword values to Mb/s
// (learn.microsoft.com "Enumeration keywords"): 1-2 = 10M, 3-4 = 100M,
// 5-6 = 1G, 7 = 10G, 8 = 20G, 9 = 40G, 10 = 100G; values of 1000 and above
// are the speed in Mb/s directly.
func speedDuplexMbps(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	switch {
	case n == 1 || n == 2:
		return 10
	case n == 3 || n == 4:
		return 100
	case n == 5 || n == 6:
		return 1000
	case n == 7:
		return 10000
	case n == 8:
		return 20000
	case n == 9:
		return 40000
	case n == 10:
		return 100000
	case n >= 1000 && n <= 1_600_000:
		return n
	}
	return 0
}

func windowsNICs(b *collect.Bundle) ([]NIC, []Bond, bool) {
	var ads []winAdapter
	if err := collect.DecodeJSON(b.Get("network.win_adapter").Text(), &ads); err != nil || !b.Get("network.win_adapter").Ran() {
		return nil, nil, false
	}
	var st []winStats
	_ = collect.DecodeJSON(b.Get("network.win_adapter_stats").Text(), &st)
	stats := map[string]winStats{}
	for _, s := range st {
		stats[s.Name] = s
	}
	var sd []struct {
		Name                string
		RegistryValue       string
		ValidRegistryValues []string
	}
	_ = collect.DecodeJSON(b.Get("network.win_speedduplex").Text(), &sd)
	sdMax, sdForced := map[string]int{}, map[string]bool{}
	for _, x := range sd {
		m := 0
		for _, v := range x.ValidRegistryValues {
			if s := speedDuplexMbps(v); s > m {
				m = s
			}
		}
		sdMax[x.Name] = m
		if rv := strings.TrimSpace(x.RegistryValue); rv != "" && rv != "0" {
			sdForced[x.Name] = true
		}
	}
	var ips []struct {
		InterfaceIndex int
		InterfaceAlias string
		IPAddress      string
		PrefixLength   int
	}
	_ = collect.DecodeJSON(b.Get("network.win_ip").Text(), &ips)
	ipByIdx := map[int][]string{}
	ipByAlias := map[string][]string{}
	for _, ip := range ips {
		if !usableIP(ip.IPAddress) {
			continue
		}
		a := ip.IPAddress + "/" + strconv.Itoa(ip.PrefixLength)
		ipByIdx[ip.InterfaceIndex] = append(ipByIdx[ip.InterfaceIndex], a)
		ipByAlias[ip.InterfaceAlias] = append(ipByAlias[ip.InterfaceAlias], a)
	}

	// Teams: LBFO members and Hyper-V external switches (SET or single NIC).
	var teams []struct {
		Name, Status string
		Members      []string
	}
	_ = collect.DecodeJSON(b.Get("network.win_lbfo_team").Text(), &teams)
	var members []struct {
		Name, Team, OperationalStatus, FailureReason, AdministrativeMode string
	}
	_ = collect.DecodeJSON(b.Get("network.win_lbfo_member").Text(), &members)
	var switches []struct {
		Name, SwitchType                string
		EmbeddedTeamingEnabled          bool
		NetAdapterInterfaceDescriptions []string
	}
	_ = collect.DecodeJSON(b.Get("network.win_vmswitch").Text(), &switches)

	var nics []NIC
	byName, byDesc := map[string]int{}, map[string]int{}
	for _, a := range ads {
		n := NIC{
			Name: a.Name, Kind: "phys", Description: a.InterfaceDescription,
			Driver: strings.TrimSpace(a.DriverProvider), DriverVersion: a.DriverVersionString,
			MAC: strings.ToLower(strings.ReplaceAll(a.MacAddress, "-", ":")),
		}
		if !wiredMedium(a.NdisPhysicalMedium) {
			n.Kind = "wireless"
		}
		n.OperState = strings.ToLower(a.Status)
		switch strings.ToLower(a.Status) {
		case "disabled", "not present":
			n.Disabled = true
		}
		switch strings.ToLower(a.MediaConnectionState) {
		case "connected", "1":
			t := true
			n.Carrier = &t
		case "disconnected", "2":
			f := false
			n.Carrier = &f
		}
		if a.ReceiveLinkSpeed != nil && *a.ReceiveLinkSpeed > 0 {
			n.SpeedMbps = int(*a.ReceiveLinkSpeed / 1e6)
		}
		if a.FullDuplex != nil && n.Kind == "phys" {
			if *a.FullDuplex {
				n.Duplex = "full"
			} else {
				n.Duplex = "half"
			}
		}
		n.SupportedMax = sdMax[a.Name]
		n.ForcedSpeed = sdForced[a.Name]
		if n.ForcedSpeed {
			n.AutoNeg = "off"
		} else if _, ok := sdMax[a.Name]; ok {
			n.AutoNeg = "on"
		}
		n.IPs = ipByIdx[a.InterfaceIndex]
		if len(n.IPs) == 0 {
			n.IPs = ipByAlias[a.Name]
		}
		n.CarriesIP = len(n.IPs) > 0
		if s, ok := stats[a.Name]; ok {
			n.Stats = map[string]uint64{
				"rx_packets":      s.ReceivedUnicastPackets + s.ReceivedMulticastPackets + s.ReceivedBroadcastPackets,
				"tx_packets":      s.SentUnicastPackets + s.SentMulticastPackets + s.SentBroadcastPackets,
				"win_rx_errors":   s.ReceivedPacketErrors,
				"win_tx_errors":   s.OutboundPacketErrors,
				"win_rx_discards": s.ReceivedDiscardedPackets,
				"win_tx_discards": s.OutboundDiscardedPackets,
			}
		}
		byName[a.Name] = len(nics)
		byDesc[a.InterfaceDescription] = len(nics)
		nics = append(nics, n)
	}

	var bonds []Bond
	for _, t := range teams {
		bd := Bond{Name: t.Name, Windows: true, Mode: "LBFO", CarriesIP: len(ipByAlias[t.Name]) > 0}
		switch strings.ToLower(t.Status) {
		case "down":
			bd.MII = "down"
		case "up", "degraded":
			bd.MII = "up"
		}
		for _, m := range members {
			if m.Team != t.Name {
				continue
			}
			sl := BondSlave{Name: m.Name, MII: "up"}
			fr := strings.ToLower(m.FailureReason)
			if strings.EqualFold(m.OperationalStatus, "Failed") || (fr != "" && fr != "nofailure" && fr != "administrativedecision") {
				sl.MII = "down"
				sl.Reason = m.FailureReason
			}
			bd.Slaves = append(bd.Slaves, sl)
			if i, ok := byName[m.Name]; ok {
				nics[i].BondSlave, nics[i].Master = true, t.Name
				nics[i].CarriesIP = nics[i].CarriesIP || bd.CarriesIP
			}
		}
		bonds = append(bonds, bd)
	}
	for _, sw := range switches {
		if !strings.EqualFold(sw.SwitchType, "External") || len(sw.NetAdapterInterfaceDescriptions) == 0 {
			continue
		}
		var idx []int
		for _, d := range sw.NetAdapterInterfaceDescriptions {
			if i, ok := byDesc[d]; ok {
				idx = append(idx, i)
			}
		}
		if len(idx) == 1 && !sw.EmbeddedTeamingEnabled {
			n := &nics[idx[0]]
			n.Master, n.CarriesIP = "vSwitch "+sw.Name, true
			continue
		}
		if len(idx) == 0 {
			continue
		}
		bd := Bond{Name: sw.Name, Windows: true, Mode: "Switch Embedded Teaming", CarriesIP: true, MII: "up"}
		allDown := true
		for _, i := range idx {
			n := &nics[i]
			n.BondSlave, n.Master, n.CarriesIP = true, "vSwitch "+sw.Name, true
			sl := BondSlave{Name: n.Name, MII: "up"}
			if n.linkDown() {
				sl.MII = "down"
			} else {
				allDown = false
			}
			bd.Slaves = append(bd.Slaves, sl)
		}
		if allDown {
			bd.MII = "down"
		}
		bonds = append(bonds, bd)
	}
	return nics, bonds, true
}

func windowsCoverage(b *collect.Bundle, env model.Env, ok bool, res *model.Result) {
	c := model.Coverage{ID: "network.links", Component: model.CompNetwork,
		Name: model.T("Network ports (link, speed, errors, teaming)", "Cổng mạng (link, tốc độ, lỗi, teaming)")}
	s := b.Get("network.win_adapter")
	sw := b.Get("network.win_vmswitch")
	switch {
	case s.Missing != "":
		c.State, c.Reason = model.CovSkipped, model.T("The NetAdapter PowerShell module is not available (Windows Server 2012 or later is needed).", "Không có module PowerShell NetAdapter (cần Windows Server 2012 trở lên).")
	case !ok:
		c.State = model.CovFailed
		c.Reason = model.Tf("Get-NetAdapter failed: %s", "Get-NetAdapter bị lỗi: %s", strings.TrimSpace(firstNonEmpty(s.Err, "unreadable output")))
	case sw != nil && sw.Skipped == "not-admin":
		c.State, c.Reason, c.Fix = model.CovPartial, model.T("Hyper-V virtual switches (SET teams) need Administrator rights to read.", "Cần quyền Administrator để đọc switch ảo Hyper-V (SET team)."), hint.RunAsRoot(env)
	default:
		c.State = model.CovRan
	}
	res.Coverage = append(res.Coverage, c)
}
