# Fixture sources (redfish domain and bmc collector)

The mockup trees under `mockups/` use the DMTF DSP2043 layout: one
`index.json` per resource at `<path below /redfish/v1>/index.json`. A file
named `index@<query>.json` is the page served for `<path>?<query>` (Windows
file names cannot contain `?`). The `bmc` package tests serve these trees
from an `httptest` TLS server; the `redfish` tests turn them into bundles
directly (`mockup_test.go`).

| Path | Origin | Licence |
|---|---|---|
| `mockups/localstorage/` | DMTF Redfish-Publications, `mockups/public-localstorage/` (commit 4f81814e399213c9055863ddaff42791c6b3706a), https://github.com/DMTF/Redfish-Publications/tree/main/mockups/public-localstorage — a subset (Systems, Processors, Memory, Storage/Volumes, Drives, EthernetInterfaces, LogServices, Chassis/Thermal/Power, Managers); AccountService, certificates, sessions and other services removed. Unmodified JSON. | BSD-3-Clause (DMTF) |
| `mockups/rackmount1/` | DMTF Redfish-Mockup-Server, `public-rackmount1/` (commit 23d21f9a3610f6b6fbb71ffc941296b159a524d2), https://github.com/DMTF/Redfish-Mockup-Server/tree/main/public-rackmount1 — same kind of subset, keeping both the classic Thermal/Power and the newer ThermalSubsystem/Fans, ThermalMetrics, Sensors, PowerSubsystem/PowerSupplies(+Metrics) and EnvironmentMetrics resources. Unmodified JSON. | BSD-3-Clause (DMTF) |
| `mockups/dell/Systems/index.json`, `Systems/System.Embedded.1/index.json`, `Chassis/System.Embedded.1/index.json`, `.../Thermal/index.json`, `.../Power/index.json` | influxdata/telegraf `plugins/inputs/redfish/testdata/dell/` (`dell_available_systems.json`, `dell_systems.json`, `dell_chassis.json`, `dell_thermal.json`, `dell_power.json`; commit 4617e281b0458df847ef5ab57dedf682df843a68) — captures from a Dell PowerEdge R640 / iDRAC 9. Unmodified. | MIT (InfluxData) |
| `mockups/dell/index.json`, `Chassis/index.json`, `Managers/**` | Synthesised from the iDRAC9 Redfish API Guide (https://developer.dell.com/apis/2978, ServiceRoot / Manager / LogService / LogEntry schemas) and Dell message IDs PSU0003 ("The power input for power supply N is lost"), RDU0012 ("Power supply redundancy is lost", https://www.manualowl.com/m/Dell/PowerEdge-R940/Manual/592988?page=1856), USR0030, MEM0701, FAN0002, PDR1016, TMP0120, SEL0001. Lclog is newest-first with a `Members@odata.nextLink` of `?$skip=3`, as iDRAC pages it. Dates chosen around 2026-10-01 to exercise the 7-day / 30-day windows. | written for this project |
| `mockups/hpe/index.json` | telegraf `plugins/inputs/redfish/testdata/base.json` (HPE iLO service root). Unmodified. | MIT (InfluxData) |
| `mockups/hpe/Systems/index.json`, `Systems/1/index.json`, `Chassis/1/index.json`, `Chassis/1/Thermal/index.json`, `Chassis/1/Power/index.json` | telegraf `testdata/hp/` (`hp_available_systems.json`, `hp_systems.json`, `hp_chassis.json`, `hp_thermal.json`, `hp_power.json`) — HPE ProLiant DL360 Gen10 / iLO 5 captures. Unmodified. | MIT (InfluxData) |
| `mockups/hpe/Chassis/index.json`, `Managers/**`, `Systems/1/LogServices/**`, `Systems/1/Memory/**`, `Systems/1/SmartStorage/**` | Synthesised from the HPE iLO 5 Redfish API reference (https://hewlettpackard.github.io/ilo-rest-api-docs/ilo5/ and `_ilo5_logging.md` in HewlettPackard/ilo-rest-api-docs): the IML entry "IML Cleared (iLO user: admin)" with `Created: 0000-00-00T00:00:00Z` is copied from that document; other IML entries follow its HpeLogEntry layout (Oem.Hpe Class/Code/Count/Severity/Repaired/Updated). SmartStorage ArrayController / DiskDrive / LogicalDrive fields follow HpeSmartStorage* schemas (Location "1I:1:2", CapacityMiB, SSDEnduranceUtilizationPercentage, Raid "1"). One SSD is Critical and the RAID 1 Warning on purpose. | written for this project |
| `fru_dell_r640.txt`, `mc_info_dell.txt`, `lan_print_sample1.txt` | Copied from `internal/checks/ipmi/testdata/` (owned by the ipmi domain; see its SOURCES.md for their origin). Used to test `HostInfo` on IPMI-only BMC bundles and the ipmitool runner. | see ipmi domain |

Failure variants (PSU critical / no input, fan failed, drive
FailurePredicted, SSD wear, degraded / rebuilding RAID, DIMM critical,
recent critical SEL entries, BMC health, unexplained health rollup,
voltage out of range, powered-off server) are made in the tests by
editing single fields of these mockups (`mockup.set`), never by inventing
whole documents.

The collector was also run (cross-compiled `bmc` test binary, `TestLive`)
in WSL against the real DMTF Redfish Mockup Server
(`python3 redfishMockupServer.py -S -D public-rackmount1`): session login
(POST) and logout (DELETE), 32 requests, analysis as expected.

## Real BMC captures (`captures/`)

Each file is one JSON object `{"/redfish/v1/...": resource}` (bodies
unmodified), because several Dell paths contain `:` and cannot be file names
on Windows. `captures_test.go` (redfish) and `capture_test.go` (bmc) load
them; the bmc tests serve them from the fake BMC.

| File | Origin | Licence |
|---|---|---|
| `captures/dell.json` | cholcombe973/libredfish `tests/mockups/dell/` (commit c23eb274ae4f8bd25be96ebaf071619afcc9502b), https://github.com/cholcombe973/libredfish/tree/master/tests/mockups/dell — captured with the DMTF Redfish Mockup Creator from a Dell PowerEdge R750, iDRAC9 6.00.30.00 (2024-08-08). Subset: service root, Systems/Chassis/Managers and the resources the analysis reads (Processors, Memory, EthernetInterfaces, Storage/Drives/Volumes/Controllers, Thermal, Power, LogServices with their entries). | MIT |
| `captures/hpe.json` | same repository, `tests/mockups/hpe/` — HPE ProLiant DL385 Gen10 Plus v2, iLO 5 2.72 (2024-08-15), with one failed NVMe SSD (Box 2:Bay 5) and the Smart Array tree in both Storage and Oem SmartStorage. Same subset. | MIT |
| `captures/lenovo.json` | same repository, `tests/mockups/lenovo/` — Lenovo ThinkSystem SR670 V2, XClarity Controller 2.83 (2024-08-02). Same subset. | MIT |
| `captures/supermicro.json` | same repository, `tests/mockups/supermicro/` — Supermicro SYS-821GE-TNHR (X13DEG-OAD), BMC 11.01.01 (2023-11-30): two log services both named "Log1" (maintenance and health), PSU input-lost SEL entries with their Deassert. Same subset. | MIT |
| `captures/ilo4.json`, `captures/ilo4-degraded.json` | Plume-Labs/frame `internal/redfish/testdata/ilo4-real/` (commit 747c72a2689804bde8ad99325553a4eea5e153cd), https://github.com/Plume-Labs/frame/tree/main/internal/redfish/testdata/ilo4-real — HPE ProLiant ML350 Gen9, iLO 4 2.77, captured 2026-09-10/11 (see its PROVENANCE.md). `ilo4.json` = the `_running` state; `ilo4-degraded.json` = the `_degraded` state (server off, failed Smart Storage Battery) with the SmartStorage tree and `_poweroff` power. The IML collection page 1 (`..._iml_entries.json`, whose @odata.id is `Entries/?page=1`) is stored at `.../IML/Entries`, pages 2 and 6 at `?page=2` / `?page=6` (pages 3-5 were not captured). Files are keyed by their own @odata.id without the trailing slash. | MIT |

`captures/hpe.json` and the iLO 4 files contain `"Password": "password"`
inside `Oem.Hp(e).LoginHint`: a literal template published by iLO, not a
credential.
