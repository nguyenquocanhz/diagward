package network

import (
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

func nicRow(res model.Result, name string) []string {
	for _, tb := range res.Tables {
		if tb.ID != "network.nics" {
			continue
		}
		for _, r := range tb.Rows {
			if len(r.Cells) > 0 && r.Cells[0] == name {
				return r.Cells
			}
		}
	}
	return nil
}

// An older or partial bundle has /proc/net/bonding but neither the sysfs
// topology nor the counters: the bond members are physical ports and must
// be counted, not reported as "No physical network port was found".
func TestBondSlavesWithoutSysfs(t *testing.T) {
	b := server("864000",
		testkit.S("network.bonding:bond0", testkit.Read(t, "bonding_rr_ok_insights.txt")),
		testkit.S("network.ip", ipJSON(map[string]string{"bond0": "192.0.2.10/24"})))
	res := check(t, b, testkit.Env(collect.OSLinux))
	c := testkit.Cov(res, "network.links")
	if c == nil || strings.Contains(c.Reason.EN, "No physical network port") {
		t.Fatalf("coverage %+v", c)
	}
	// Only the bond data is there: the counters were not checked.
	if c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "not collected") || c.Reason.VI == "" {
		t.Errorf("coverage %+v", c)
	}
	facts := res.Facts.(*Facts)
	if len(facts.NICs) != 2 {
		t.Fatalf("nics %+v", facts.NICs)
	}
	for _, n := range facts.NICs {
		if !n.BondSlave || n.Master != "bond0" || !n.linkUp() || n.SpeedMbps != 1000 || n.Duplex != "full" || n.MAC == "" {
			t.Errorf("nic from bonding %+v", n)
		}
	}
	if testkit.Find(res, "network.bond_ok", "bond0") == nil || testkit.Find(res, "network.links_ok") == nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	row := nicRow(res, "eno1")
	if row == nil || row[2] != "up" || row[3] != "1 Gb/s full" || row[4] != "bond0" {
		t.Errorf("row %q", row)
	}
	// No counters were collected: the CRC/frame cell must not claim "0".
	if row != nil && row[6] != "" {
		t.Errorf("CRC/frame cell %q without counters, want empty", row[6])
	}

	// A bond member that is down (real active-backup capture).
	b = server("864000",
		testkit.S("network.bonding:bond0", testkit.Read(t, "bonding_ab_slave_down.txt")),
		testkit.S("network.ip", ipJSON(map[string]string{"bond0": "10.10.0.5/24"})))
	res = check(t, b, testkit.Env(collect.OSLinux))
	if f := testkit.Find(res, "network.bond_degraded", "bond0"); f == nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
	if testkit.Find(res, "network.link_down") != nil {
		t.Errorf("bond member reported as a plain link down: %v", testkit.IDs(res))
	}
	if row := nicRow(res, "eno2"); row == nil || row[2] != "down" {
		t.Errorf("eno2 row %q", row)
	}
}

// The topology is authoritative: a bond member it lists as a virtual
// device is not turned into a physical port.
func TestBondSlaveVirtualInTopology(t *testing.T) {
	b := server("864000",
		testkit.S("network.topology", "if=eno1 kind=virtual master=bond0 lower= driver=\nif=eno2 kind=virtual master=bond0 lower= driver=\nif=bond0 kind=bond master= lower= driver="),
		testkit.S("network.bonding:bond0", testkit.Read(t, "bonding_ab_slave_down.txt")))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if n := len(res.Facts.(*Facts).NICs); n != 0 {
		t.Errorf("%d nics from virtual bond members", n)
	}
}

// Counters collected and zero: the cell says 0.
func TestCRCCellWithCounters(t *testing.T) {
	b := server("86400", testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb"),
		testkit.S("network.sysfs", sysfs("eno1", nil)),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
	res := check(t, b, testkit.Env(collect.OSLinux))
	if row := nicRow(res, "eno1"); row == nil || row[6] != "0" {
		t.Errorf("row %q", row)
	}
	// Sysfs without the statistics files: unknown, not 0.
	var keep []string
	for _, l := range strings.Split(sysfs("eno1", nil), "\n") {
		if !strings.Contains(l, "/statistics/") {
			keep = append(keep, l)
		}
	}
	b = server("86400", testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb"),
		testkit.S("network.sysfs", strings.Join(keep, "\n")),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
	res = check(t, b, testkit.Env(collect.OSLinux))
	if row := nicRow(res, "eno1"); row == nil || row[6] != "" {
		t.Errorf("row without statistics %q", row)
	}
}

// Absent interface data is not "no physical port found".
func TestLinksCoverageAbsentVsFailed(t *testing.T) {
	env := testkit.Env(collect.OSLinux)
	// Only `ip addr` in the bundle (older or interrupted collector run).
	b := server("86400", testkit.S("network.ip", ipJSON(map[string]string{"eth0": "192.0.2.5/24"})))
	res := check(t, b, env)
	c := testkit.Cov(res, "network.links")
	if c == nil || c.State != model.CovSkipped || !strings.Contains(c.Reason.EN, "not collected") {
		t.Errorf("absent coverage %+v", c)
	}
	// The topology step ran and failed without output: failed, with stderr.
	b = server("86400", testkit.RC("network.topology", 1, "", "readlink: Input/output error"))
	res = check(t, b, env)
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovFailed || !strings.Contains(c.Reason.EN, "Input/output error") {
		t.Errorf("failed coverage %+v", c)
	}
	// The topology ran and lists only virtual interfaces: really no port.
	b = server("86400", testkit.S("network.topology", "if=docker0 kind=bridge master= lower= driver="))
	res = check(t, b, env)
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "No physical network port") {
		t.Errorf("no-port coverage %+v", c)
	}
	// Topology lists a port but the counters are absent: partial.
	b = server("86400", testkit.S("network.topology", "if=eno1 kind=phys master= lower= driver=igb"),
		testkit.S("network.ip", ipJSON(map[string]string{"eno1": "192.0.2.5/24"})))
	res = check(t, b, env)
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovPartial || !strings.Contains(c.Reason.EN, "not collected") {
		t.Errorf("no-sysfs coverage %+v", c)
	}
}

// Windows: Get-NetAdapter deliberately skipped is not "Get-NetAdapter failed".
func TestWindowsAdapterSkipped(t *testing.T) {
	b := testkit.Bundle(collect.OSWindows, testkit.Skipped("network.win_adapter", "not-admin"))
	env := testkit.Env(collect.OSWindows)
	env.Root = false
	res := check(t, b, env)
	if c := testkit.Cov(res, "network.links"); c == nil || c.State != model.CovSkipped {
		t.Errorf("coverage %+v", c)
	}
}
