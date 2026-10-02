# memory test fixtures: origin

Real output is used wherever it exists publicly. "Synthesized" files follow the
exact format of the tool or kernel interface named below; their values are made
up. Some tests also read rasdaemon/mcelog fixtures from `../../cpu/testdata`
(see that SOURCES.md).

| File | Origin |
|---|---|
| `dmidecode_memory_dell_r740.txt` | Real. linuxhw/DMI `Server/Dell/PowerEdge/PowerEdge R740/102E11A0DB9A` (dmidecode 3.4), types 5/6/16/17 extracted. Serials are anonymised ("--") in the source; tests fill them in. https://github.com/linuxhw/DMI (CC BY 4.0) |
| `dmidecode_memory_hpe_dl380g10.txt` | Real. linuxhw/DMI `Server/HPE/ProLiant/ProLiant DL380 Gen10/0895878555EA`. CC BY 4.0 |
| `dmidecode_memory_supermicro_6029p.txt` | Real. linuxhw/DMI `Server/Supermicro/SYS-6029/SYS-6029P-TR/14E74CFA6CF5` (rated 3200, configured 2934 MT/s). CC BY 4.0 |
| `dmidecode_memory_qemu.txt` | Real. linuxhw/DMI `Desktop/QEMU/Standard/Standard PC/418878F10378`. CC BY 4.0 |
| `dmidecode_memory_optiplex7070.txt` | Real. linuxhw/DMI `Desktop/Dell/OptiPlex/OptiPlex 7070/03FC6EEAE3C5` (non-ECC, 64-bit total width, JEDEC "80AD000080AD"). CC BY 4.0 |
| `dmidecode_memory_hp_dl360g8.txt` | Real. fusioninventory-agent `resources/generic/dmidecode/hp-dl360-gen8` (dmidecode 3.0: "8192 MB", "Configured Clock Speed"). GPL-2.0 |
| `dmidecode_memory_vmware.txt` | Real. fusioninventory-agent `resources/generic/dmidecode/rhel-6.2-vmware-2vcpus` (63 empty "RAM slot #N"). GPL-2.0 |
| `edac_node_exporter.txt` | Real fixture data. prometheus/node_exporter `collector/fixtures/sys.ttar`, `sys/devices/system/edac` entries converted to our `path=value` dump (legacy csrow layout, UE and no-info counters). Apache-2.0 |
| `edac_skx_healthy.txt`, `edac_skx_ce250.txt`, `edac_skx_ue.txt` | Synthesized `memory.edac` dumps. Attribute names from `drivers/edac/edac_mc_sysfs.c` (dimmN/dimm_label, dimm_location, size, dimm_mem_type, dimm_edac_mode, dimm_ce_count, dimm_ue_count; mcN/mc_name, size_mb, seconds_since_reset, ce/ue(_noinfo)_count); labels in the skx_edac format "CPU_SrcID#%u_MC#%u_Chan#%u_DIMM#%u". |
| `edac_ghes_dell_r740.txt` | Synthesized ghes_edac dump whose labels are the SMBIOS locators of the R740 fixture (ghes_edac takes labels from DMI). |
| `meminfo_wsl.txt` | Real. `/proc/meminfo` from WSL (kernel 6.x). |
| `meminfo_r740.txt`, `meminfo_r740_one_dimm_missing.txt`, `meminfo_pressure.txt` | Synthesized `/proc/meminfo` (field names per `Documentation/filesystems/proc.rst`). |
| `psi_memory_high.txt` | Synthesized `/proc/pressure/memory` (format per `Documentation/accounting/psi.rst`). |
| `memtest_ok_ubuntu.txt` | Real collector output: memtester 4.7.1, 16M, root, WSL (backspace progress already stripped by the snippet). |
| `memtest_unlocked_nonroot.txt`, `memtest_unlocked_nonroot.err` | Real: memtester 4.7.1 as user nobody with `ulimit -l 0`, run through the snippet's pipeline (stdout/stderr split). |
| `memtest_failure.txt`, `memtest_failure.err` | Synthesized from memtester 4.x `memtester.c`/`tests.c`: a failed test prints no "ok" (so the next label follows on the same line) and FAILURE lines go to stderr; exit code 0x04 = EXIT_FAIL_OTHERTEST. |
| `memtest_timeout.txt` | Synthesized: the real output layout cut off by `timeout` (rc 124). |
| `win_physical_laptop.json`, `win_array_laptop.json`, `win_os_laptop.json`, `win_pagefile_laptop.json` | Real collector output from the dev machine (Windows 10 laptop, non-ECC SO-DIMMs); DIMM serial numbers replaced. |
| `win_physical_server_r740.json`, `win_array_server_r740.json`, `win_os_server_r740*.json` | Synthesized in the shape of the real Win32_PhysicalMemory / Win32_PhysicalMemoryArray / Win32_OperatingSystem output, with the R740 DIMM data (72-bit total width, MemoryErrorCorrection 6). |
| `win_os_pressure.json`, `win_pagefile_pressure.json` | Synthesized, same shape. |
| `win_memdiag_*.json` | Synthesized Get-WinEvent output for provider Microsoft-Windows-MemoryDiagnostics-Results. Event IDs and messages from the provider manifest on the dev machine (`Get-WinEvent -ListProvider`): 1101/1201 no errors, 1102/1202 hardware errors, 1103 cancelled, 1104 could not complete. |
