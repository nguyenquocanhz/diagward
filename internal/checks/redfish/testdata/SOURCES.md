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
