# Fixture sources (network domain)

| File | Origin | Licence / notes |
|---|---|---|
| `bonding_ab_slave_down.txt` | Real `/proc/net/bonding/bond0` from the WSL2 kernel 6.18 bonding driver: active-backup bond of two veth ports, the peer of the second set down twice (Link Failure Count 2) | Interface names renamed `dw9a/dw9b` -> `eno1/eno2`. |
| `bonding_ab_all_down.txt` | Same setup, both peers down (bond MII down, no active slave) | Renamed as above. |
| `bonding_8023ad_no_partner.txt` | Same kernel, mode 802.3ad with no LACP partner: each port in its own aggregator, partner MAC 00:00:00:00:00:00 | Renamed to `ens1f0/ens1f1`. |
| `bonding_8023ad_slave_down_insights.txt` | RedHatInsights/insights-core `insights/tests/parsers/test_bond.py` (`BOND_MODE_4`) | Apache-2.0. Real 802.3ad bond with one slave down. |
| `bonding_ab_flapping_insights.txt` | same file (`BONDINFO_MODE_7`): Link Failure Count 92028/71524 | Apache-2.0. |
| `bonding_rr_ok_insights.txt` | same file (`BONDINFO_1`) | Apache-2.0. |
| `ethtool_e1000e_1g_on_10g_capable.txt`, `ethtool_i_e1000e.txt` | prometheus/node_exporter `collector/fixtures/ethtool/eth0/{settings,driver}` | Apache-2.0. |
| `ethtool_ice_25g_dac.txt`, `ethtool_ice_25g_nolink.txt`, `ethtool_i_ice.txt` | inode64/server-hw-report `reports/OVH-Advance-3/rescue/{eth0,eth1,eth0_info}.txt` (real OVH server, Intel E810 `ice`, 25G DAC; eth1 has no link but still prints `Speed: 25000Mb/s`) | GPL-3.0 repository; raw tool output. |
| `ethtool_100m_partner_100m.txt` | google/testrun `testing/unit/conn/ethtool/ethtool_results_compliant.txt` (gigabit NIC at 100 Mb/s, partner offers only 10/100) | Apache-2.0. `TestSpeed` derives a "downshift" variant in memory by adding `1000baseT/Full` to the partner modes. |
| `ethtool_hv_netvsc.txt`, `ethtool_i_hv_netvsc.txt` | Real `ethtool eth0` / `ethtool -i eth0` from WSL2 (hv_netvsc, "Not reported" link modes), captured by the collector with the container skip disabled | — |
| `ip_j_addr_wsl.json`, `ip_o_addr_wsl.txt` | Real `ip -j addr` / `ip -o addr` from WSL2 (iproute2) | MAC/link-local address replaced. |
| `wsl.json` | Real collector run in WSL2 (`meta.*`, `network.*`, `system.uptime`) | Hostname/MAC replaced. |
| `win10.json` | Real collector run on Windows 10 (not elevated): Get-NetAdapter -Physical (Wi-Fi + disconnected Killer E2600 with an APIPA address), statistics, *SpeedDuplex, Get-NetIPAddress, empty LBFO, vmswitch skipped | Hostname and MACs replaced. |

`network.sysfs` and `network.topology` content in `check_test.go` is synthesised in the
exact format the collector prints (`dw_sysfs` "path=value" lines; topology "if= kind= master=
lower= driver=") with counter names from the kernel ABI
(Documentation/ABI/testing/sysfs-class-net-statistics, sysfs-class-net). The WSL bundle shows
the real format. Windows LBFO/SET JSON in the tests follows the property names of
Get-NetLbfoTeam/Get-NetLbfoTeamMember/Get-VMSwitch as written by `50-network.ps1` (enums as
strings); these cmdlets returned no teams on the dev machine, so their populated shape is
unverified against real output.

## Added in the sysnet review

`network.win_vmswitch_bound` (adapters with the Hyper-V Extensible Virtual Switch protocol
`vms_pp` enabled, from `Get-NetAdapterBinding`) was verified unelevated on the dev machine,
which has Hyper-V but no external switch (all bindings `Enabled: False`, so the section is
`[]`). The bound-uplink JSON in `review_test.go` is synthesised in the shape the collector
writes (`Name`, `InterfaceDescription`). The Open vSwitch topology in `review_test.go` follows
how the kernel exposes OVS ports (`master` link to the `ovs-system` datapath device).

`network.config` lines in `TestConfiguredPortWithoutIP` are in the exact `grep -H` format the
collector prints (verified in WSL with GNU grep and BusyBox grep against a keyfile written per
nm-settings-keyfile(5) and an ifcfg file per the RHEL ifcfg documentation); no NetworkManager
host was available to capture real profiles.
