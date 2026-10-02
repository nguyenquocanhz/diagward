# Fixture sources (system domain)

| File | Origin | Licence / notes |
|---|---|---|
| `dmidecode_dell_r740.txt` | linuxhw/DMI `Server/Dell/PowerEdge/PowerEdge R740/102E11A0DB9A` (https://github.com/linuxhw/DMI), dmidecode 3.4 on real hardware | CC-BY-4.0. Filtered to the DMI types `dmidecode -t system -t bios -t baseboard -t chassis` prints (0, 1, 2, 3, 10, 12, 13, 15, 23, 32, 41). Serials anonymised by linuxhw as `--`; `TestDellServiceTag` substitutes a tag in memory. |
| `dmidecode_supermicro_sys6029p.txt` | linuxhw/DMI `Server/Supermicro/SYS-6029/SYS-6029P-TR/14E74CFA6CF5` | CC-BY-4.0, filtered as above. |
| `dmidecode_lenovo_sn550.txt` | linuxhw/DMI `Server/Lenovo/ThinkSystem/ThinkSystem SN550 -[7X16CTO1WW]-/8F8D27788C8D` | CC-BY-4.0, filtered as above. Shows Lenovo's `-[MTM]-` naming and `-[IVE182H-4.10]-` BIOS version. |
| `dmidecode_hpe_bl460c_gen10.txt` | linuxhw/DMI `Server/HPE/ProLiant/ProLiant BL460c Gen10/0D501A0F9103` | CC-BY-4.0, filtered as above. |
| `dmidecode_hp_dl380p_gen8.txt` | RedHatInsights/insights-core `insights/tests/parsers/test_dmidecode.py` (`DMIDECODE`) | Apache-2.0. Real HP DL380p Gen8 output (the insights authors lower-cased the chassis record to test case handling). |
| `dmidecode_vmware.txt`, `dmidecode_rhev_kvm.txt`, `dmidecode_aws_xen.txt` | same file (`DMIDECODE_V`, `DMIDECODE_KVM`, `DMIDECODE_AWS`) | Apache-2.0. |
| `dmidecode_nodmi.txt` | Real output of dmidecode 3.6 in WSL2 (no SMBIOS), captured by `dwdev` on the dev machine | — |
| `cpuinfo_epyc4464p.txt` | inode64/server-hw-report `reports/OVH-Advance-3/rescue/cpuinfo.txt` (real OVH server), filtered through the collector's `grep -E` | GPL-3.0 repository; raw tool output. |
| `cpuinfo_2x_e5-2670.txt` | insights-core `test_cpuinfo.py` (`CPUINFO_NOIR`, dual Xeon E5-2670), filtered through the collector's `grep -E` | Apache-2.0. |
| `hostnamectl_dell_fedora40.txt` | linuxwacom/wacom-hid-descriptors `Dell Latitude 9440 2-in-1/sysinfo.Kxg2nsyTYF/host.txt` (systemd 255 `hostnamectl` with Hardware/Firmware lines) | ODbL-1.0. |
| `timedatectl_unsynced_openshift.txt` | openshift/openshift-docs `modules/ipi-install-troubleshooting-ntp-out-of-sync.adoc` example output | Apache-2.0. |
| `timedatectl_centos7_unsynced.txt` | northbright/Notes `Linux/CentOS/time/set-timezone-on-centos.md` (CentOS 7, systemd 219 "NTP synchronized" format) | Weekday names translated from the author's zh_CN locale to C locale (the collector sets LC_ALL=C). |
| `timedatectl_synced_wsl.txt` | Real `timedatectl status` from WSL Ubuntu 26.04 (systemd), captured by the collector | — |
| `chronyc_tracking_unsynced.txt` | Synthesised from the chronyc(1) man page `tracking` example (https://chrony-project.org/doc/4.5/chronyc.html) with the values chronyd reports before its first sync | Format only. |
| `wsl.json` | Real collector run (`dwdev -os linux -save`) in WSL2 Ubuntu 26.04, kernel 6.18, root; only `meta.*` and `system.*` sections kept | Hostname/MAC replaced. |
| `win10.json` | Real collector run (`dwdev -os windows -save`) on the Windows 10 dev machine, not elevated; `meta.*` and `system.*` | Hostname, user and board serial replaced. |

Synthetic bundles inside `check_test.go` (load, PSI, /proc/stat, taint values, Windows perf
samples) follow the formats documented in proc(5), Documentation/accounting/psi.rst and
Documentation/admin-guide/tainted-kernels.rst, and the Win32_PerfFormattedData_* JSON shape
captured in `win10.json`.

The Supermicro placeholder record in `review_test.go` (`TestPlaceholderSerials`) is synthesised
in dmidecode's format with the default strings AMI Aptio firmware leaves in SMBIOS ("To be
filled by O.E.M", "Default string", "0123456789"), as seen in many linuxhw/DMI dumps.
