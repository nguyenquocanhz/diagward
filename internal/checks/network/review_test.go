package network

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

var linuxOnly = []string{"journalctl", "ethtool", "ip -s link", "ip link set", "nmcli"}

// Windows findings must give Windows commands, not ethtool/journalctl.
func TestWindowsActionsUseWindowsTools(t *testing.T) {
	ad := `[` +
		`{"Name":"Embedded LOM 1 Port 1","InterfaceDescription":"HPE Ethernet 1Gb 4-port 331i Adapter","InterfaceIndex":7,"Status":"Up","MediaConnectionState":"Connected","LinkSpeed":"100 Mbps","ReceiveLinkSpeed":100000000,"FullDuplex":false,"MacAddress":"98-F2-B3-00-00-01","NdisPhysicalMedium":14},` +
		`{"Name":"Embedded LOM 1 Port 2","InterfaceDescription":"HPE Ethernet 1Gb 4-port 331i Adapter #2","InterfaceIndex":8,"Status":"Disconnected","MediaConnectionState":"Disconnected","LinkSpeed":"0 bps","MacAddress":"98-F2-B3-00-00-02","NdisPhysicalMedium":14}` +
		`]`
	st := `[{"Name":"Embedded LOM 1 Port 1","ReceivedUnicastPackets":2000000,"SentUnicastPackets":1000000,"ReceivedPacketErrors":4500,"ReceivedDiscardedPackets":90000}]`
	sd := `[{"Name":"Embedded LOM 1 Port 1","RegistryValue":"3","ValidRegistryValues":["0","1","2","3","4","6"],"DisplayValue":"100 Mbps Half Duplex"}]`
	ip := `[{"InterfaceIndex":7,"InterfaceAlias":"Embedded LOM 1 Port 1","IPAddress":"10.1.1.20","PrefixLength":24},{"InterfaceIndex":8,"InterfaceAlias":"Embedded LOM 1 Port 2","IPAddress":"10.2.2.20","PrefixLength":24}]`
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("network.win_adapter", ad), testkit.S("network.win_adapter_stats", st), testkit.S("network.win_speedduplex", sd),
		testkit.S("network.win_ip", ip))
	res := check(t, b, testkit.Env(collect.OSWindows))
	for _, id := range []string{"network.link_down", "network.half_duplex", "network.speed_low", "network.rx_errors", "network.drops"} {
		if testkit.Find(res, id) == nil {
			t.Errorf("%s missing: %v", id, testkit.IDs(res))
		}
	}
	for _, f := range res.Findings {
		for _, s := range []string{f.Action.EN, f.Action.VI} {
			for _, bad := range linuxOnly {
				if strings.Contains(s, bad) {
					t.Errorf("%s on Windows suggests %q: %s", f.ID, bad, s)
				}
			}
		}
	}
	if f := testkit.Find(res, "network.half_duplex"); f != nil && !strings.Contains(f.Action.EN, "-Name 'Embedded LOM 1 Port 1' -RegistryKeyword '*SpeedDuplex'") {
		t.Errorf("half duplex: %s", f.Action.EN)
	}
}

// Without elevation Get-VMSwitch is skipped; the vms_pp binding still marks
// the external-switch uplink (which has no IP of its own) as in use.
func TestWindowsVMSwitchUplinkNotAdmin(t *testing.T) {
	ad := `[` +
		`{"Name":"SLOT 3 Port 1","InterfaceDescription":"Broadcom NetXtreme E-Series Dual-port 25Gb SFP28 Ethernet OCP 3.0 Adapter","InterfaceIndex":4,"Status":"Disconnected","MediaConnectionState":"Disconnected","LinkSpeed":"0 bps","MacAddress":"00-0A-F7-00-00-01","NdisPhysicalMedium":14},` +
		`{"Name":"NIC-MGMT","InterfaceDescription":"Intel(R) I350 Gigabit Network Connection","InterfaceIndex":5,"Status":"Up","MediaConnectionState":"Connected","LinkSpeed":"1 Gbps","ReceiveLinkSpeed":1000000000,"FullDuplex":true,"MacAddress":"00-0A-F7-00-00-02","NdisPhysicalMedium":14}` +
		`]`
	ip := `[{"InterfaceIndex":5,"InterfaceAlias":"NIC-MGMT","IPAddress":"10.0.0.5","PrefixLength":24},{"InterfaceIndex":30,"InterfaceAlias":"vEthernet (vSwitch-VM)","IPAddress":"10.10.0.5","PrefixLength":24}]`
	b := testkit.Bundle(collect.OSWindows,
		testkit.S("network.win_adapter", ad), testkit.S("network.win_ip", ip),
		testkit.Skipped("network.win_vmswitch", "not-admin"),
		testkit.S("network.win_vmswitch_bound", `[{"Name":"SLOT 3 Port 1","InterfaceDescription":"Broadcom NetXtreme E-Series Dual-port 25Gb SFP28 Ethernet OCP 3.0 Adapter"}]`))
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res := check(t, b, env)
	f := testkit.Find(res, "network.link_down", "SLOT 3 Port 1")
	if f == nil || f.Severity != model.Crit || !strings.Contains(f.Detail.EN, "Hyper-V") {
		t.Errorf("uplink down: %v %+v", testkit.IDs(res), f)
	}
	// Two uplinks (perhaps a SET team), one still up: redundancy lost, Warn.
	ad2 := strings.Replace(ad, `"Name":"NIC-MGMT"`, `"Name":"SLOT 3 Port 2"`, 1)
	b = testkit.Bundle(collect.OSWindows,
		testkit.S("network.win_adapter", ad2), testkit.Skipped("network.win_vmswitch", "not-admin"),
		testkit.S("network.win_vmswitch_bound", `[{"Name":"SLOT 3 Port 1"},{"Name":"SLOT 3 Port 2"}]`))
	res = check(t, b, env)
	if f := testkit.Find(res, "network.link_down", "SLOT 3 Port 1"); f == nil || f.Severity != model.Warn {
		t.Errorf("two uplinks: %v", testkit.IDs(res))
	}
}

func TestEthtoolMissingCmd(t *testing.T) {
	b := server("86400", testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb"),
		testkit.S("network.sysfs", sysfs("eno1", nil)), testkit.Missing("network.ethtool", "ethtool"),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
	env := testkit.Env(collect.OSLinux)
	env.Distro, env.Like, env.PM, env.Root = "ubuntu", "debian", "apt", false
	c := testkit.Cov(check(t, b, env), "network.links")
	if c == nil || c.Cmd != "sudo apt-get install -y --no-install-recommends ethtool" || strings.Contains(c.Fix.EN, "apt-get") {
		t.Errorf("coverage %+v", c)
	}
}

// Open vSwitch uplinks (OpenStack/oVirt hosts) have master "ovs-system"
// and no IP; the IP is on an OVS internal port such as br-ex.
func TestOVSUplinkDown(t *testing.T) {
	topo := "if=ens1f0 kind=phys master=ovs-system lower= driver=i40e\nif=ovs-system kind=virtual master= lower= driver=\n" +
		"if=br-ex kind=virtual master=ovs-system lower= driver=\nif=eno1 kind=phys master= lower= driver=igb"
	b := server("86400",
		testkit.S("network.topology", topo),
		testkit.S("network.sysfs", sysfs("ens1f0", map[string]string{"operstate": "down", "carrier": "0"})+sysfs("eno1", nil)),
		testkit.S("network.ip", ipJSON(map[string]string{"br-ex": "172.24.4.10/24", "eno1": "10.0.0.10/24", "ens1f0": ""})))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.link_down", "ens1f0"); f == nil || f.Severity != model.Crit {
		t.Errorf("OVS uplink down: %v", testkit.IDs(res))
	}
}

// Hyper-V installed but no external switch: nothing is left unread.
func TestWindowsNoExternalSwitchCoverage(t *testing.T) {
	b, err := collect.Read(strings.NewReader(testkit.Read(t, "win10.json")))
	if err != nil {
		t.Fatal(err)
	}
	b.Add(testkit.S("network.win_vmswitch_bound", "[]"))
	res := check(t, b, collect.EnvOf(b))
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovRan {
		t.Errorf("%+v", c)
	}
}

// NetworkManager (RHEL 8+) removes the address of a port that lost its
// link, so a configured data port with a cut cable has no IP: the boot
// profile must still make it count as used. Lines are what the collector's
// grep prints from keyfiles (nm-settings-keyfile(5)) and ifcfg files.
func TestConfiguredPortWithoutIP(t *testing.T) {
	cfg := "/etc/NetworkManager/system-connections/eno2.nmconnection:type=ethernet\n" +
		"/etc/NetworkManager/system-connections/eno2.nmconnection:interface-name=eno2\n" +
		"/etc/NetworkManager/system-connections/eno3.nmconnection:type=ethernet\n" +
		"/etc/NetworkManager/system-connections/eno3.nmconnection:autoconnect=false\n" +
		"/etc/NetworkManager/system-connections/eno3.nmconnection:interface-name=eno3\n" +
		"/etc/sysconfig/network-scripts/ifcfg-eno4:TYPE=Ethernet\n" +
		"/etc/sysconfig/network-scripts/ifcfg-eno4:DEVICE=\"eno4\"\n" +
		"/etc/sysconfig/network-scripts/ifcfg-eno4:ONBOOT=no\n"
	down := map[string]string{"operstate": "down", "carrier": "0", "speed": "-1", "duplex": "unknown"}
	b := server("86400",
		testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb\nif=eno2 kind=phys master= lower= driver=igb\nif=eno3 kind=phys master= lower= driver=igb\nif=eno4 kind=phys master= lower= driver=igb"),
		testkit.S("network.sysfs", sysfs("eno1", nil)+sysfs("eno2", down)+sysfs("eno3", down)+sysfs("eno4", down)),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "10.0.0.5/24", "eno2": "", "eno3": "", "eno4": ""})),
		testkit.S("network.config", cfg))
	res := check(t, b, testkit.Env(collect.OSLinux))
	f := testkit.Find(res, "network.link_down", "eno2")
	if f == nil || f.Severity != model.Warn || !strings.Contains(f.Detail.EN, "eno2.nmconnection") {
		t.Errorf("configured port: %v %+v", testkit.IDs(res), f)
	}
	for _, n := range []string{"eno3", "eno4", "eno1"} {
		if testkit.Find(res, "network.link_down", n) != nil {
			t.Errorf("%s flagged", n)
		}
	}
	c := parseNetConfig(cfg + "garbage\n:x=y\n/etc/sysconfig/network/ifcfg-eth0:STARTMODE='auto'\n/etc/sysconfig/network/ifcfg-eth1:BOOTPROTO=dhcp\n")
	if !c["eno2"].Auto || c["eno3"].Auto || c["eno4"].Auto || !c["eth0"].Auto || c["eth1"].Auto {
		t.Errorf("%+v", c)
	}
}
