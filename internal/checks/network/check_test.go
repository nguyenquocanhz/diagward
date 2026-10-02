package network

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// sysfs renders network.sysfs lines the way dw_sysfs prints them.
func sysfs(name string, kv map[string]string) string {
	base := map[string]string{
		"operstate": "up", "carrier": "1", "speed": "1000", "duplex": "full", "mtu": "1500",
		"address": "3c:ec:ef:00:00:01", "carrier_changes": "2", "carrier_down_count": "1",
		"statistics/rx_packets": "123456789", "statistics/tx_packets": "98765432",
		"statistics/rx_crc_errors": "0", "statistics/rx_frame_errors": "0", "statistics/rx_errors": "0",
		"statistics/rx_dropped": "0", "statistics/tx_dropped": "0", "statistics/rx_missed_errors": "0",
		"statistics/tx_carrier_errors": "0",
	}
	for k, v := range kv {
		base[k] = v
	}
	var keys []string
	for k := range base {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "/sys/class/net/%s/%s=%s\n", name, k, base[k])
	}
	return b.String()
}

func ipJSON(addrs map[string]string) string {
	var parts []string
	names := make([]string, 0, len(addrs))
	for n := range addrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ai := ""
		if addrs[n] != "" {
			ip, pfx, _ := strings.Cut(addrs[n], "/")
			ai = fmt.Sprintf(`{"family":"inet","local":"%s","prefixlen":%s,"scope":"global","label":"%s"}`, ip, pfx, n)
		}
		parts = append(parts, fmt.Sprintf(`{"ifname":"%s","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","addr_info":[%s]}`, n, ai))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func server(uptime string, secs ...*collect.Section) *collect.Bundle {
	all := []*collect.Section{
		testkit.S("meta.ident", "hostname=srv01\nuid=0\nkernel=5.14.0-427.el9.x86_64\nuptime="+uptime),
		testkit.S("system.uptime", uptime+" 100.0"),
	}
	return testkit.Bundle(collect.OSLinux, append(all, secs...)...)
}

func check(t *testing.T, b *collect.Bundle, env model.Env) model.Result {
	t.Helper()
	res := Check(b, env)
	testkit.Validate(t, res)
	return res
}

func TestBondSlaveDown(t *testing.T) {
	b := server("864000",
		testkit.S("network.topology", "if=eno1 kind=phys master=bond0 lower= driver=igb\nif=eno2 kind=phys master=bond0 lower= driver=igb\nif=eno3 kind=phys master= lower= driver=igb\nif=bond0 kind=bond master= lower= driver="),
		testkit.S("network.sysfs", sysfs("eno1", nil)+sysfs("eno2", map[string]string{"operstate": "down", "carrier": "0", "speed": "", "duplex": "", "carrier_changes": "5"})+
			sysfs("eno3", map[string]string{"operstate": "down", "carrier": "0", "speed": ""})),
		testkit.S("network.bonding:bond0", testkit.Read(t, "bonding_ab_slave_down.txt")),
		testkit.S("network.ethtool_i:eno2", testkit.Read(t, "ethtool_i_e1000e.txt")),
		testkit.S("network.ip", ipJSON(map[string]string{"bond0": "10.10.0.5/24", "eno1": "", "eno2": "", "eno3": ""})),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "network.bond_degraded", "bond0")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Title.EN, "eno2") || f.Part == nil || f.Part.Kind != "nic" {
		t.Fatalf("findings %v", testkit.IDs(res))
	}
	if !strings.Contains(f.Part.Location, "0000:00:1f.6") || f.Part.Firmware != "0.5-4" {
		t.Errorf("part %+v", f.Part)
	}
	if testkit.Find(res, "network.link_down") != nil {
		t.Errorf("bond slave reported as link_down: %v", testkit.IDs(res))
	}
	fa := res.Facts.(*Facts)
	if len(fa.Bonds) != 1 || !fa.Bonds[0].CarriesIP {
		t.Errorf("bond facts %+v", fa.Bonds)
	}
	for _, n := range fa.NICs {
		if n.Name == "eno1" && !n.CarriesIP {
			t.Error("eno1 should carry the bond's IP")
		}
		if n.Name == "eno3" && n.CarriesIP {
			t.Error("eno3 is unused")
		}
	}
	if len(res.Tables) != 1 || len(res.Tables[0].Rows) != 3 {
		t.Errorf("table %+v", res.Tables)
	}
}

func TestBondFixtures(t *testing.T) {
	cases := []struct {
		file, id string
		sev      model.Severity
		ip       bool
	}{
		{"bonding_ab_all_down.txt", "network.bond_down", model.Crit, true},
		{"bonding_ab_all_down.txt", "network.bond_down", model.Warn, false},
		{"bonding_8023ad_no_partner.txt", "network.bond_lacp", model.Warn, true},
		{"bonding_8023ad_slave_down_insights.txt", "network.bond_degraded", model.Warn, true},
		{"bonding_rr_ok_insights.txt", "network.bond_ok", model.OK, true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			ip := map[string]string{"bond0": ""}
			if c.ip {
				ip["bond0"] = "192.0.2.10/24"
			}
			b := server("86400", testkit.S("network.bonding:bond0", testkit.Read(t, c.file)), testkit.S("network.ip", ipJSON(ip)),
				testkit.S("network.topology", "if=bond0 kind=bond master= lower= driver="))
			res := check(t, b, testkit.Env(collect.OSLinux))
			f := testkit.Find(res, c.id, "bond0")
			if f == nil || f.Severity != c.sev {
				t.Errorf("findings %v", testkit.IDs(res))
			}
		})
	}
	bd := parseBonding("bond0", testkit.Read(t, "bonding_8023ad_slave_down_insights.txt"))
	if bd.ActiveAggregator != "1" || bd.PartnerMAC != "00:00:00:00:00:00" || len(bd.Slaves) != 2 || bd.Slaves[1].AggregatorID != "2" || bd.Slaves[1].MII != "down" {
		t.Errorf("parse %+v", bd)
	}
}

func TestBondFlappingWithoutCarrierChanges(t *testing.T) {
	// Old kernels have no carrier_changes; the bond's Link Failure Count is used.
	sys := sysfs("em3", nil) + sysfs("p2p3", nil)
	sys = strings.ReplaceAll(sys, "/sys/class/net/em3/carrier_changes=2\n", "")
	sys = strings.ReplaceAll(sys, "/sys/class/net/p2p3/carrier_changes=2\n", "")
	b := server("2592000",
		testkit.S("network.bonding:bond0", testkit.Read(t, "bonding_ab_flapping_insights.txt")),
		testkit.S("network.sysfs", sys),
		testkit.S("network.topology", "if=em3 kind=phys master=bond0 lower= driver=tg3\nif=p2p3 kind=phys master=bond0 lower= driver=tg3\nif=bond0 kind=bond master= lower= driver="),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.link_flapping", "em3"); f == nil || !strings.Contains(f.Detail.EN, "Link Failure Count") {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	if testkit.Find(res, "network.link_flapping", "p2p3") == nil {
		t.Errorf("p2p3 not flagged: %v", testkit.IDs(res))
	}
}

func TestLinkDownWithIP(t *testing.T) {
	b := server("86400",
		testkit.S("network.topology", "if=eth0 kind=phys master= lower= driver=ice\nif=eth1 kind=phys master= lower= driver=ice"),
		testkit.S("network.sysfs", sysfs("eth0", map[string]string{"speed": "25000"})+sysfs("eth1", map[string]string{"operstate": "down", "carrier": "0", "speed": "25000"})),
		testkit.S("network.ethtool:eth0", testkit.Read(t, "ethtool_ice_25g_dac.txt")),
		testkit.S("network.ethtool:eth1", testkit.Read(t, "ethtool_ice_25g_nolink.txt")),
		testkit.S("network.ethtool_i:eth1", testkit.Read(t, "ethtool_i_ice.txt")),
		testkit.S("network.ip", ipJSON(map[string]string{"eth0": "203.0.113.7/24", "eth1": "10.0.0.7/24"})),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "network.link_down", "eth1")
	if f == nil || f.Severity != model.Crit || f.Part == nil || f.Part.Firmware != "4.20 0x8001b91f 1.3346.0" {
		t.Fatalf("findings %v", testkit.IDs(res))
	}
	// stale "Speed: 25000Mb/s" on a link that is down must not produce speed findings
	for _, x := range res.Findings {
		if strings.HasPrefix(x.ID, "network.speed") {
			t.Errorf("speed finding on %s: %s", x.Target, x.ID)
		}
	}
	// The same port without an IP is an unused port: no finding.
	b.Get("network.ip").Out = ipJSON(map[string]string{"eth0": "203.0.113.7/24", "eth1": ""})
	res = check(t, b, testkit.Env(collect.OSLinux))
	if testkit.Find(res, "network.link_down") != nil {
		t.Errorf("unused port flagged: %v", testkit.IDs(res))
	}
	if testkit.Find(res, "network.links_ok") == nil {
		t.Errorf("no ok finding: %v", testkit.IDs(res))
	}
	// On a VM the same situation is Warn (hypervisor configuration).
	b.Get("network.ip").Out = ipJSON(map[string]string{"eth0": "203.0.113.7/24", "eth1": "10.0.0.7/24"})
	env := testkit.Env(collect.OSLinux)
	env.Virtual = "kvm"
	res = check(t, b, env)
	if f := testkit.Find(res, "network.link_down", "eth1"); f == nil || f.Severity != model.Warn {
		t.Errorf("vm: %v", testkit.IDs(res))
	}
}

func TestLinkDownThroughBridge(t *testing.T) {
	// Proxmox: IP on vmbr0, physical port enp3s0 under it.
	b := server("86400",
		testkit.S("network.topology", "if=enp3s0 kind=phys master=vmbr0 lower= driver=r8169\nif=vmbr0 kind=bridge master= lower= driver=\nif=vmbr0.20 kind=vlan master= lower=vmbr0 driver="),
		testkit.S("network.sysfs", sysfs("enp3s0", map[string]string{"operstate": "down", "carrier": "0", "speed": "-1", "duplex": "unknown"})),
		testkit.S("network.ip", ipJSON(map[string]string{"vmbr0.20": "192.168.20.2/24", "vmbr0": "", "enp3s0": ""})),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.link_down", "enp3s0"); f == nil || f.Severity != model.Crit {
		t.Errorf("findings %v", testkit.IDs(res))
	}
}

func TestLinkDownGuestBridge(t *testing.T) {
	// Proxmox: vmbr1 has no host IP but carries VM traffic (tap ports).
	topo := "if=enp4s0 kind=phys master=vmbr1 lower= driver=igb\nif=vmbr1 kind=bridge master= lower= driver=\n" +
		"if=tap100i0 kind=virtual master=vmbr1 lower= driver=\nif=tap101i0 kind=virtual master=vmbr1 lower= driver=\n" +
		"if=enp5s0 kind=phys master=vmbr2 lower= driver=igb\nif=vmbr2 kind=bridge master= lower= driver="
	b := server("86400",
		testkit.S("network.topology", topo),
		testkit.S("network.sysfs", sysfs("enp4s0", map[string]string{"operstate": "down", "carrier": "0"})+sysfs("enp5s0", map[string]string{"operstate": "down", "carrier": "0"})),
		testkit.S("network.ip", ipJSON(map[string]string{"vmbr1": "", "vmbr2": ""})),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "network.link_down", "enp4s0")
	if f == nil || f.Severity != model.Crit || !strings.Contains(f.Detail.EN, "2 VM/container ports") {
		t.Errorf("findings %v %+v", testkit.IDs(res), f)
	}
	if testkit.Find(res, "network.link_down", "enp5s0") != nil {
		t.Error("empty bridge port flagged")
	}
}

func TestTeamdMemberDown(t *testing.T) {
	// teamd (NetworkManager team): no /proc/net/bonding, the master is a
	// plain virtual device. One port down while the other is up is
	// redundancy lost (Warn), not an outage.
	b := server("86400",
		testkit.S("network.topology", "if=ens1f0 kind=phys master=team0 lower= driver=i40e\nif=ens1f1 kind=phys master=team0 lower= driver=i40e\nif=team0 kind=virtual master= lower= driver="),
		testkit.S("network.sysfs", sysfs("ens1f0", nil)+sysfs("ens1f1", map[string]string{"operstate": "down", "carrier": "0"})),
		testkit.S("network.ip", ipJSON(map[string]string{"team0": "198.51.100.4/24", "ens1f0": "", "ens1f1": ""})),
	)
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.link_down", "ens1f1"); f == nil || f.Severity != model.Warn || !strings.Contains(f.Detail.EN, "redundancy") {
		t.Errorf("findings %v %+v", testkit.IDs(res), f)
	}
}

func TestSpeed(t *testing.T) {
	partner100 := testkit.Read(t, "ethtool_100m_partner_100m.txt")
	// Synthesised from the same capture: the switch also offers 1000baseT/Full,
	// yet the link came up at 100 Mb/s (cable downshift).
	downshift := strings.Replace(partner100, "Link partner advertised link modes:  10baseT/Full \n\t                                     100baseT/Half 100baseT/Full ",
		"Link partner advertised link modes:  10baseT/Full \n\t                                     100baseT/Half 100baseT/Full \n\t                                     1000baseT/Full ", 1)
	if downshift == partner100 {
		t.Fatal("downshift fixture not built")
	}
	cases := []struct {
		name, ethtool, id string
		sev               model.Severity
		inTitle           string
	}{
		{"partner 100M", partner100, "network.speed_low", model.Warn, "100 Mb/s"},
		{"downshift", downshift, "network.speed_low", model.Warn, "both ends support 1 Gb/s"},
		{"1G on 10G capable but advertising 1G", testkit.Read(t, "ethtool_e1000e_1g_on_10g_capable.txt"), "", model.OK, ""},
		{"25G DAC", testkit.Read(t, "ethtool_ice_25g_dac.txt"), "", model.OK, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := parseEthtool(c.ethtool)
			sp := e.SpeedMbps
			b := server("86400",
				testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=e1000e"),
				testkit.S("network.sysfs", sysfs("eno1", map[string]string{"speed": fmt.Sprint(sp)})),
				testkit.S("network.ethtool:eno1", c.ethtool),
				testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})),
			)
			res := check(t, b, testkit.Env(collect.OSLinux))
			if c.id == "" {
				for _, f := range res.Findings {
					if f.Severity >= model.Warn {
						t.Errorf("unexpected %s", f.ID)
					}
				}
				return
			}
			f := testkit.Find(res, c.id, "eno1")
			if f == nil || f.Severity != c.sev || !strings.Contains(f.Title.EN, c.inTitle) {
				t.Errorf("findings %v (%+v)", testkit.IDs(res), f)
			}
			// a VM's virtual NIC speed means nothing
			env := testkit.Env(collect.OSLinux)
			env.Virtual = "vmware"
			if testkit.Find(check(t, b, env), c.id) != nil {
				t.Error("speed finding on a VM")
			}
		})
	}
	// 10G SFP+ port with a 1G module: Info only.
	sfp := "Settings for eth2:\n\tSupported ports: [ FIBRE ]\n\tSupported link modes:   1000baseX/Full\n\t                        10000baseSR/Full\n\tAdvertised link modes:  1000baseX/Full\n\t                        10000baseSR/Full\n\tSpeed: 1000Mb/s\n\tDuplex: Full\n\tAuto-negotiation: on\n\tPort: FIBRE\n\tLink detected: yes\n"
	b := server("86400", testkit.S("network.topology", "if=eth2 kind=phys master= lower= driver=ixgbe"),
		testkit.S("network.sysfs", sysfs("eth2", nil)), testkit.S("network.ethtool:eth2", sfp),
		testkit.S("network.ip", ipJSON(map[string]string{"eth2": "192.0.2.6/24"})))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.speed_below_max", "eth2"); f == nil || f.Severity != model.Info {
		t.Errorf("sfp: %v", testkit.IDs(res))
	}
}

func TestHalfDuplex(t *testing.T) {
	b := server("86400", testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=tg3"),
		testkit.S("network.sysfs", sysfs("eno1", map[string]string{"speed": "100", "duplex": "half"})),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.half_duplex", "eno1"); f == nil || f.Severity != model.Warn {
		t.Errorf("findings %v", testkit.IDs(res))
	}
}

func TestErrorsAndFlaps(t *testing.T) {
	cases := []struct {
		name, uptime string
		kv           map[string]string
		id           string
	}{
		{"crc rate high", "864000", map[string]string{"statistics/rx_crc_errors": "1200", "statistics/rx_packets": "50000000"}, "network.rx_errors"},
		{"old crc burst", "864000", map[string]string{"statistics/rx_crc_errors": "40", "statistics/rx_packets": "9000000000"}, ""},
		{"few errors", "864000", map[string]string{"statistics/rx_crc_errors": "3", "statistics/rx_packets": "1000"}, ""},
		{"tx carrier errors", "864000", map[string]string{"statistics/tx_carrier_errors": "500", "statistics/tx_packets": "1000000"}, "network.rx_errors"},
		{"flapping", "864000", map[string]string{"carrier_changes": "240"}, "network.link_flapping"},
		{"planned events over a long uptime", "34560000", map[string]string{"carrier_changes": "30"}, ""},
		{"drops", "864000", map[string]string{"statistics/rx_dropped": "5000000", "statistics/rx_packets": "100000000", "statistics/tx_packets": "100000000"}, "network.drops"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := server(c.uptime, testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb"),
				testkit.S("network.sysfs", sysfs("eno1", c.kv)),
				testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
			res := check(t, b, testkit.Env(collect.OSLinux))
			if c.id == "" {
				for _, f := range res.Findings {
					if f.Severity > model.OK {
						t.Errorf("unexpected %s", f.ID)
					}
				}
				return
			}
			if testkit.Find(res, c.id, "eno1") == nil {
				t.Errorf("findings %v", testkit.IDs(res))
			}
		})
	}
}

func TestWSLReal(t *testing.T) {
	b, err := collect.Read(strings.NewReader(testkit.Read(t, "wsl.json")))
	if err != nil {
		t.Fatal(err)
	}
	env := collect.EnvOf(b)
	res := check(t, b, env)
	c := testkit.Cov(res, "network.links")
	if c == nil || c.State != model.CovSkipped {
		t.Errorf("coverage %+v", c)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings in a container: %v", testkit.IDs(res))
	}
	// The same data analysed as a plain VM (hv_netvsc NIC with carrier and IP).
	env.Container, env.Virtual = false, "microsoft"
	res = check(t, b, env)
	if testkit.Find(res, "network.links_ok") == nil {
		t.Errorf("vm: %v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovRan {
		t.Errorf("vm coverage %+v", c)
	}
}

func TestEthtoolMissing(t *testing.T) {
	b := server("86400", testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb"),
		testkit.S("network.sysfs", sysfs("eno1", nil)), testkit.Missing("network.ethtool", "ethtool"),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
	res := check(t, b, testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "network.links")
	if c == nil || c.State != model.CovPartial || !strings.Contains(c.Fix.EN, "ethtool") {
		t.Errorf("coverage %+v", c)
	}
}

func TestParsers(t *testing.T) {
	j := parseIP(testkit.Read(t, "ip_j_addr_wsl.json"))
	o := parseIP(testkit.Read(t, "ip_o_addr_wsl.txt"))
	for _, m := range []map[string]*ipInfo{j, o} {
		if m["eth0"] == nil || len(m["eth0"].Addrs) != 1 || m["eth0"].Addrs[0] != "172.29.218.192/20" {
			t.Errorf("eth0 %+v", m["eth0"])
		}
		if m["lo"] != nil && len(m["lo"].Addrs) != 0 {
			t.Errorf("loopback counted: %+v", m["lo"])
		}
	}
	e := parseEthtool(testkit.Read(t, "ethtool_hv_netvsc.txt"))
	if e.SpeedMbps != 10000 || e.SupportedMax() != 0 || e.LinkDetected == nil || !*e.LinkDetected {
		t.Errorf("hv_netvsc %+v", e)
	}
	e = parseEthtool(testkit.Read(t, "ethtool_ice_25g_dac.txt"))
	if maxModeSpeed(e.Supported) != 25000 || maxModeSpeed(e.Advertised) != 25000 || e.Port != "Direct Attach Copper" {
		t.Errorf("ice %+v", e)
	}
	e = parseEthtool(testkit.Read(t, "ethtool_e1000e_1g_on_10g_capable.txt"))
	if maxModeSpeed(e.Supported) != 10000 || maxModeSpeed(e.Advertised) != 1000 || e.SpeedMbps != 1000 {
		t.Errorf("e1000e %+v", e)
	}
	kv := colonKV(testkit.Read(t, "ethtool_i_hv_netvsc.txt"))
	if kv["driver"] != "hv_netvsc" || kv["firmware-version"] != "N/A" {
		t.Errorf("ethtool -i %v", kv)
	}
	for _, v := range []string{"10", "2", "4", "6", "7", "25000", "x", "-1"} {
		_ = speedDuplexMbps(v)
	}
	if speedDuplexMbps("6") != 1000 || speedDuplexMbps("25000") != 25000 || speedDuplexMbps("4") != 100 {
		t.Error("speedduplex mapping")
	}
}

func (e ethtoolInfo) SupportedMax() int { return maxModeSpeed(e.Supported) }

func TestWindowsReal(t *testing.T) {
	b, err := collect.Read(strings.NewReader(testkit.Read(t, "win10.json")))
	if err != nil {
		t.Fatal(err)
	}
	env := collect.EnvOf(b)
	res := check(t, b, env)
	if testkit.Find(res, "network.links_ok") == nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	for _, f := range res.Findings {
		if f.Severity > model.OK {
			t.Errorf("unexpected %s on %s (Wi-Fi half duplex or APIPA on a disconnected port?)", f.ID, f.Target)
		}
	}
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovPartial {
		t.Errorf("coverage %+v (vmswitch skipped not-admin)", c)
	}
}

func TestWindowsSynthetic(t *testing.T) {
	ad := `[` +
		`{"Name":"NIC1","InterfaceDescription":"Intel(R) Ethernet Controller X710 for 10GbE SFP+","InterfaceIndex":5,"Status":"Up","MediaConnectionState":"Connected","LinkSpeed":"10 Gbps","ReceiveLinkSpeed":10000000000,"FullDuplex":true,"MacAddress":"3C-FD-FE-00-00-01","DriverProvider":"Intel","DriverVersionString":"1.12.101.0","NdisPhysicalMedium":14},` +
		`{"Name":"NIC2","InterfaceDescription":"Intel(R) Ethernet Controller X710 for 10GbE SFP+ #2","InterfaceIndex":6,"Status":"Disconnected","MediaConnectionState":"Disconnected","LinkSpeed":"0 bps","ReceiveLinkSpeed":null,"FullDuplex":null,"MacAddress":"3C-FD-FE-00-00-02","DriverProvider":"Intel","DriverVersionString":"1.12.101.0","NdisPhysicalMedium":14},` +
		`{"Name":"Embedded LOM 1 Port 1","InterfaceDescription":"HPE Ethernet 1Gb 4-port 331i Adapter","InterfaceIndex":7,"Status":"Up","MediaConnectionState":"Connected","LinkSpeed":"100 Mbps","ReceiveLinkSpeed":100000000,"FullDuplex":true,"MacAddress":"98-F2-B3-00-00-01","DriverProvider":"Broadcom","DriverVersionString":"214.0.0.0","NdisPhysicalMedium":14},` +
		`{"Name":"Embedded LOM 1 Port 2","InterfaceDescription":"HPE Ethernet 1Gb 4-port 331i Adapter #2","InterfaceIndex":8,"Status":"Disconnected","MediaConnectionState":"Disconnected","LinkSpeed":"0 bps","FullDuplex":null,"MacAddress":"98-F2-B3-00-00-02","NdisPhysicalMedium":14},` +
		`{"Name":"Embedded LOM 1 Port 3","InterfaceDescription":"HPE Ethernet 1Gb 4-port 331i Adapter #3","InterfaceIndex":9,"Status":"Disabled","MediaConnectionState":"Unknown","LinkSpeed":"0 bps","MacAddress":"98-F2-B3-00-00-03","NdisPhysicalMedium":14}` +
		`]`
	st := `[{"Name":"Embedded LOM 1 Port 1","ReceivedUnicastPackets":2000000,"ReceivedMulticastPackets":0,"ReceivedBroadcastPackets":0,"SentUnicastPackets":1000000,"ReceivedPacketErrors":4500,"OutboundPacketErrors":0,"ReceivedDiscardedPackets":0,"OutboundDiscardedPackets":0}]`
	sd := `[{"Name":"Embedded LOM 1 Port 1","RegistryValue":"0","ValidRegistryValues":["0","1","2","3","4","6"],"DisplayValue":"Auto Negotiation"}]`
	ip := `[{"InterfaceIndex":7,"InterfaceAlias":"Embedded LOM 1 Port 1","IPAddress":"10.1.1.20","PrefixLength":24},{"InterfaceIndex":8,"InterfaceAlias":"Embedded LOM 1 Port 2","IPAddress":"10.2.2.20","PrefixLength":24},{"InterfaceIndex":20,"InterfaceAlias":"Team1","IPAddress":"10.0.0.20","PrefixLength":24}]`
	team := `[{"Name":"Team1","Status":"Degraded","TeamingMode":"SwitchIndependent","Members":["NIC1","NIC2"]}]`
	mem := `[{"Name":"NIC1","Team":"Team1","OperationalStatus":"Active","FailureReason":"NoFailure"},{"Name":"NIC2","Team":"Team1","OperationalStatus":"Failed","FailureReason":"PhysicalMediaDisconnected"}]`
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("meta.ident", `[{"hostname":"SRV-FS01","admin":true,"now":"2026-10-01T09:00:20Z"}]`),
		testkit.S("network.win_adapter", ad), testkit.S("network.win_adapter_stats", st), testkit.S("network.win_speedduplex", sd),
		testkit.S("network.win_ip", ip), testkit.S("network.win_lbfo_team", team), testkit.S("network.win_lbfo_member", mem),
	)
	res := check(t, b, testkit.Env(collect.OSWindows))
	want := map[string]string{
		"network.bond_degraded": "Team1",
		"network.link_down":     "Embedded LOM 1 Port 2",
		"network.speed_low":     "Embedded LOM 1 Port 1",
		"network.rx_errors":     "Embedded LOM 1 Port 1",
	}
	for id, target := range want {
		if testkit.Find(res, id, target) == nil {
			t.Errorf("%s@%s missing: %v", id, target, testkit.IDs(res))
		}
	}
	if f := testkit.Find(res, "network.bond_degraded", "Team1"); f != nil && !strings.Contains(f.Detail.EN, "PhysicalMediaDisconnected") {
		t.Errorf("failure reason missing: %s", f.Detail.EN)
	}
	if testkit.Find(res, "network.link_down", "NIC2") != nil {
		t.Error("team member reported as link_down")
	}
	// Team down
	b.Get("network.win_lbfo_team").Out = strings.Replace(team, "Degraded", "Down", 1)
	b.Get("network.win_lbfo_member").Out = strings.Replace(mem, `"Active","FailureReason":"NoFailure"`, `"Failed","FailureReason":"PhysicalMediaDisconnected"`, 1)
	res = check(t, b, testkit.Env(collect.OSWindows))
	if f := testkit.Find(res, "network.bond_down", "Team1"); f == nil || f.Severity != model.Crit {
		t.Errorf("team down: %v", testkit.IDs(res))
	}
	// SET switch with one adapter down
	b = testkit.Bundle(collect.OSWindows,
		testkit.S("network.win_adapter", ad),
		testkit.S("network.win_vmswitch", `[{"Name":"vSwitch-SET","SwitchType":"External","EmbeddedTeamingEnabled":true,"NetAdapterInterfaceDescriptions":["Intel(R) Ethernet Controller X710 for 10GbE SFP+","Intel(R) Ethernet Controller X710 for 10GbE SFP+ #2"]}]`))
	res = check(t, b, testkit.Env(collect.OSWindows))
	if f := testkit.Find(res, "network.bond_degraded", "vSwitch-SET"); f == nil || !strings.Contains(f.Title.EN, "NIC2") {
		t.Errorf("SET: %v", testkit.IDs(res))
	}
}

func TestGarbage(t *testing.T) {
	if res := Check(testkit.Bundle(collect.OSLinux, testkit.S("meta.ident", "uid=0")), testkit.Env(collect.OSLinux)); len(res.Coverage) != 0 {
		t.Errorf("coverage without sections: %v", res.Coverage)
	}
	files := []string{"bonding_8023ad_no_partner.txt", "bonding_8023ad_slave_down_insights.txt", "ethtool_ice_25g_dac.txt", "ethtool_100m_partner_100m.txt", "ip_j_addr_wsl.json", "ip_o_addr_wsl.txt", "win10.json"}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 400; i++ {
		src := testkit.Read(t, files[rng.Intn(len(files))])
		cut := src[:rng.Intn(len(src)+1)]
		junk := make([]byte, rng.Intn(300))
		for j := range junk {
			junk[j] = byte(rng.Intn(256))
		}
		pick := func() string {
			if rng.Intn(2) == 0 {
				return cut
			}
			return string(junk)
		}
		b := server(pick(),
			testkit.S("network.topology", pick()+"\nif=eth0 kind=phys master=bond0\nif=bond0 kind=bond master=eth0"),
			testkit.S("network.sysfs", pick()+"\n"+sysfs("eth0", map[string]string{"carrier_changes": pick(), "speed": pick()})),
			testkit.S("network.ethtool:eth0", pick()), testkit.S("network.ethtool_i:eth0", pick()),
			testkit.S("network.bonding:bond0", pick()), testkit.S("network.ip", pick()))
		check(t, b, testkit.Env(collect.OSLinux))
		wb := testkit.Bundle(collect.OSWindows,
			testkit.S("network.win_adapter", pick()), testkit.S("network.win_adapter_stats", pick()),
			testkit.S("network.win_ip", pick()), testkit.S("network.win_lbfo_team", pick()), testkit.S("network.win_lbfo_member", pick()),
			testkit.S("network.win_speedduplex", pick()), testkit.S("network.win_vmswitch", pick()))
		check(t, wb, testkit.Env(collect.OSWindows))
	}
}
