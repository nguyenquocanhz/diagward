# cpu test fixtures: origin

Real output is used wherever it exists publicly. "Synthesized" files follow the
exact print format of the tool's source code (named below); their values are
made up. Collector-shaped files (`*_summary_*`, `*sysfs*`, `throttle_*`) use the
section format our snippets produce (`collect/linux/20-cpu.sh`).

| File | Origin |
|---|---|
| `dmidecode_processor_dell_r740.txt` | Real. linuxhw/DMI, `Server/Dell/PowerEdge/PowerEdge R740/102E11A0DB9A` (dmidecode 3.4), type 4 records extracted. https://github.com/linuxhw/DMI (CC BY 4.0) |
| `dmidecode_processor_hpe_dl380g10.txt` | Real. linuxhw/DMI, `Server/HPE/ProLiant/ProLiant DL380 Gen10/0895878555EA`, type 4. CC BY 4.0 |
| `dmidecode_processor_qemu.txt` | Real. linuxhw/DMI, `Desktop/QEMU/Standard/Standard PC/418878F10378`, type 4. CC BY 4.0 |
| `dmidecode_processor_hp_dl360g8.txt` | Real. fusioninventory-agent `resources/generic/dmidecode/hp-dl360-gen8` (dmidecode 3.0; CPU 2 reports "Populated, Idle"). https://github.com/fusioninventory/fusioninventory-agent (GPL-2.0) |
| `dmidecode_processor_vmware.txt` | Real. fusioninventory-agent `resources/generic/dmidecode/rhel-6.2-vmware-2vcpus` (62 sockets "Populated, Disabled By BIOS"). GPL-2.0 |
| `dmidecode_processor_r740_cpu2_disabled.txt` | Derived from `dmidecode_processor_dell_r740.txt`: CPU2 status changed to "Populated, Disabled By BIOS" (SMBIOS type 4 CPU Status value 3). |
| `lscpu_json_wsl.json` | Real. `lscpu -J` (util-linux 2.41) on the dev machine's WSL Ubuntu, captured by the collector. |
| `lscpu_text_centos7_offline.txt` | Synthesized in the util-linux 2.23 (CentOS 7) text layout, with an "Off-line CPU(s) list" line. |
| `cpuinfo_summary_wsl.txt` | Real collector output (`cpu.cpuinfo` summary) from WSL. |
| `cpuinfo_summary_xeon_2s.txt` | Synthesized in the collector's summary format for a 2-socket Xeon E5-2630 v4. |
| `sysfs_cpu_one_offline.txt` | Synthesized `cpu.sysfs` dump (kernel files `/sys/devices/system/cpu/{online,offline,present,possible,smt/*}`). |
| `throttle_sysfs_hot.txt`, `throttle_sysfs_zero.txt`, `throttle_sysfs_counts_only.txt` | Synthesized `cpu.throttle` dumps. File names from the kernel's `arch/x86/kernel/cpu/mce/therm_throt.c` (`core/package_throttle_count`, `*_max_time_ms`, `*_total_time_ms` since 5.18). |
| `ras_summary_empty_ubuntu_0.8.4.txt`, `ras_errors_empty_ubuntu_0.8.4.txt`, `ras_status_not_loaded.txt` | Real. `ras-mc-ctl --summary/--errors/--status`, rasdaemon 0.8.4-1ubuntu0.1, captured in WSL (includes the non-hardware SIGNAL section). |
| `ras_summary_issue33_ce.txt`, `ras_summary_issue33_ce.err` | Real. rasdaemon issue #33 (rasdaemon 0.6.6, 1,987,314 corrected errors on 'CPU1_E0'; stderr shows the missing devlink table crash). https://github.com/mchehab/rasdaemon/issues/33 |
| `ras_summary_issue121_amd.txt`, `ras_errors_issue121_amd.txt` | Real. rasdaemon issue #121 (AMD Ryzen 7800X3D, rasdaemon 0.8.0, corrected UMC error). https://github.com/mchehab/rasdaemon/issues/121 |
| `ras_errors_intel_memory.txt` | Synthesized from `util/ras-mc-ctl.in` (sub errors, rasdaemon v0.8.0) using the Skylake mc_event/mce_record values printed in rasdaemon issue #33. |
| `ras_errors_cpu_uncorrected.txt` | Synthesized from `util/ras-mc-ctl.in` and `mce-intel.c` mcistatus strings (`Corrected_error`, `Uncorrected_error ... SRAR`); the SRAR record reuses the status of mcelog issue #74. |
| `mcelog_log_arch_uncorrected.txt` | Real. Arch Linux forums, "mcelog Hardware Error events" (2016). https://bbs.archlinux.org/viewtopic.php?id=214758 |
| `mcelog_syslog_rhel8_srar.txt` | Real. andikleen/mcelog issue #74 (RHEL 8, injected SRAR error, syslog-prefixed). https://github.com/andikleen/mcelog/issues/74 |
| `mcelog_log_corrected_thermal.txt` | Synthesized from mcelog `mcelog.c` dump_mce(), `p4.c` decode_mci()/decode_tracking()/decode_thermal(). |
| `mcelog_client_issue16.txt` | Real. andikleen/mcelog issue #16 (`mcelog --client`). https://github.com/andikleen/mcelog/issues/16 |
| `win_processor_laptop.json` | Real. `cpu.win_processor` from the dev machine (Windows 10, not elevated). |
| `win_processor_2s_disabled.json` | Synthesized in the same shape: second socket with CpuStatus 3 ("CPU Disabled By BIOS (POST Error)", Microsoft Win32_Processor docs). |
