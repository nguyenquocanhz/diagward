# Fixture sources (ipmi)

Real outputs pasted in public issues are tool output, used here as test data;
the issue is the reference.

| File | Origin | Licence |
|---|---|---|
| `sdr_dell_r510_idrac6.txt` | Real `ipmitool sdr elist all`, Dell PowerEdge R510 / iDRAC6 (one PSU bay empty): https://github.com/tigerblue77/Dell_iDRAC_fan_controller_Docker/issues/378 | issue content |
| `sdr_hpe_dl360g10_ilo5.txt` | Real `ipmitool sdr elist`, HPE ProLiant DL360 Gen10 / iLO 5 (entity instances ≥ 10, "Transition to OK", fully redundant PSUs): https://github.com/prometheus-community/ipmi_exporter/issues/54 | issue content |
| `sdr_supermicro_x10srh.txt` | Real `ipmitool sdr elist`, Supermicro X10SRH-CF (unconnected fan headers = ns/No Reading): https://github.com/memtest86plus/memtest86plus/issues/379 | issue content |
| `sdr_telegraf_v2.txt` | `v2Data` from influxdata/telegraf `plugins/inputs/ipmi_sensor/ipmi_sensor_test.go` (interleaved "Unable to send command" lines, analog + discrete reading) | MIT |
| `sdr_dell_faults.txt` | Synthesized in the `sdr elist` format (ipmitool `lib/ipmi_sdr.c`: lnc/unc/lcr/ucr/lnr/unr status codes); PSU state texts as in Dell KB 000004068 "VxRail: Determine if a PSU Replacement is Required" (`PSU1 Status \| E0h \| ok \| 10.1 \| Presence detected, Failure detected`) | synthesized |
| `sel_recent_faults.txt` | Real SEL lines with dates moved into September 2026 (the test clock is 2026-10-01): Dell KB 000004068 (Redundancy Lost, PSU AC lost), https://github.com/vectordotdev/vector/issues/1624 (chassis intrusion, drive fault), https://github.com/ipmitool/test/issues/84 and https://github.com/nerc-project/operations/issues/1016 (pipes inside parentheses, IERR, uncorrectable ECC, 12-hour clock), https://github.com/ipmitool/ipmitool/issues/385 (1.8.19 format: 2-digit year and time zone), https://datastorageguy.com/2022/06/09/ipmitool-sel-elist-error-timestamp-clock-sync-asserted/ (Power Unit AC lost, boot events). Pre-Init, kernel-panic and OEM-record lines synthesized from ipmitool `lib/ipmi_sel.c` (`ipmi_sel_print_std_entry`) | mixed, see links |
| `sel_intel_sr2500_2008.txt`, `sel_list_supermicro_x8.txt`, `sel_info_ok.txt` | Thomas-Krenn wiki "Reading out system event log" (Intel SR2500 `sel elist`, Supermicro X8DT3 `sel list` without a direction column, `sel info`): https://www.thomas-krenn.com/en/wiki/Reading_out_system_event_log | wiki content |
| `sel_supermicro_2017.txt` | https://github.com/vectordotdev/vector/issues/1624 | issue content |
| `sel_nerc_2025.txt` | https://github.com/nerc-project/operations/issues/1016 | issue content |
| `sel_info_full.txt` | Synthesized from ipmitool `lib/ipmi_sel.c` `ipmi_sel_get_info` output format (100 % used, overflow) | synthesized |
| `chassis_supermicro_ok.txt` | Real `ipmitool chassis status` (Supermicro): https://github.com/rxseger/homebridge-ipmi/issues/2 | issue content |
| `chassis_faults.txt` | Synthesized from ipmitool `lib/ipmi_chassis.c` `ipmi_chassis_status` (main power fault, cooling fault, intrusion, `Last Power Event : ac-failed `, button lines) | synthesized |
| `mc_info_openbmc.txt` | Real `ipmitool mc info` (OpenBMC, unknown manufacturer): https://github.com/openbmc/phosphor-net-ipmid/issues/3 | issue content |
| `mc_info_dell.txt` | Same format with Dell values (IANA 674 "DELL Inc") | synthesized |
| `fru_dell_r640.txt`, `fru_hpe_dl360g8.txt` | Real `ipmitool fru print` from glpi-project/glpi-agent `resources/generic/ipmitool/fru/` (Dell R640 with PS1/PS2 FRUs and serials, absent backplane; HPE DL360p Gen8) | GPL-2.0 |
| `lan_print_sample1.txt`, `lan_print_huawei_rh1288v3.txt` | Real `ipmitool lan print` from glpi-agent `resources/generic/ipmitool_lan_print/` | GPL-2.0 |
| `dcmi_power.txt` | `ipmitool dcmi power reading` from telegraf `ipmi_sensor_test.go` | MIT |
