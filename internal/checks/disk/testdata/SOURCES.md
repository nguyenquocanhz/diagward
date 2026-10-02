# Disk fixtures: origins

Real tool output wherever possible. Serial numbers in third-party files were
already masked or redacted by their authors ("XXXX", "REDACTED"); they are kept
as published.

## smartctl JSON (`smartctl -x -j` / `-a -j`, smartmontools 7.x)

| File | Origin | Licence |
|---|---|---|
| `ata_hdd_wd_healthy.json` | AnalogJ/scrutiny `webapp/backend/pkg/models/testdata/smart-ata.json` — https://github.com/AnalogJ/scrutiny | MIT |
| `ata_hdd_hitachi_failed.json` | scrutiny `smart-fail2.json` (Hitachi HDS721050DLE630 behind a USB JMicron bridge: SMART FAILED, 5 FAILING_NOW, 197 = 8, 56 ATA errors, failed extended self-test) | MIT |
| `ata_megaraid_realloc387.json` | scrutiny `smart-megaraid1.json` (`sat+megaraid,1`, 387 reallocated sectors) | MIT |
| `ata_ssd_samsung860_devstats.json` | scrutiny `smart-ata-full.json` (Samsung 860 EVO, ATA device statistics, SCT temperature limits) | MIT |
| `ata_ssd_samsung840_crc.json` | scrutiny `smart-ata-failed-scrutiny.json` (Samsung 840, 108 CRC errors) | MIT |
| `nvme_samsung970_media_errors.json` | scrutiny `smart-nvme-failed.json` (7 media errors, 62 error-log entries) | MIT |
| `scsi_seagate_healthy.json` | scrutiny `smart-scsi2.json` (Seagate ST1200MM0088 SAS) | MIT |
| `scsi_intel_raid_volume.json` | scrutiny `smart-raid.json` (Intel RST "Raid 1 Volume", no SMART) | MIT |
| `smart_open_failed_windows.json` | scrutiny `smart-fail.json` (Windows, `Open failed, Error=5`) | MIT |
| `ata_megaraid14_seagate_healthy.json` | influxdata/telegraf `plugins/inputs/smartctl/testcases_device/megaraid/response.json` — https://github.com/influxdata/telegraf | MIT |
| `nvme_sabrent_healthy.json` | telegraf `testcases_device/nvme/response.json` (4871 benign error-log entries) | MIT |
| `scsi_extended_selftests.json` | telegraf `testcases_device/scsi_extended/response.json` (SCSI self-test log, smartctl 7.4) | MIT |
| `scan_megaraid_json.json` | telegraf `testcases_scan/megaraid/response.json` (`smartctl --scan --json`) | MIT |
| `nvme_samsung_critical_warning.json` | prometheus-community/smartctl_exporter `testdata/nvme-null-SAMSUNG_MZWLL3T2HAJQ-00005-nvme0.json` (critical_warning 0x10, volatile memory backup failed) — https://github.com/prometheus-community/smartctl_exporter | Apache-2.0 |
| `scsi_seagate_defects_uncorrected.json` | smartctl_exporter `testdata/SEAGATE_ST373453LC_26.json` (260 grown defects, uncorrected read 1 / write 535) | Apache-2.0 |
| `ata_hdd_seagate_realloc304.json` | smartctl_exporter `testdata/ST3500418AS_12.json` (304 reallocated sectors) | Apache-2.0 |
| `ata_hdd_hgst_crc_errlog.json` | smartctl_exporter `testdata/HGST_HUS724020ALE640_28.json` (12 CRC errors, ICRC entries in the error log) | Apache-2.0 |
| `ata_hdd_seagate_old_errlog.json` | smartctl_exporter `testdata/ST3200820AS_16.json` (98 errors, newest at 7042 h of 100161 h) | Apache-2.0 |
| `ata_ssd_intel_s3500_wear85.json` | smartctl_exporter `testdata/sat-Intel_730_and_DC_S35x0_3610_3700_Series_SSDs-INTEL_SSDSC2BB016T4-sdf.json` (233 Media_Wearout_Indicator = 15) | Apache-2.0 |
| `scsi_msft_virtual_disk.json` | Captured on the dev machine: smartctl 7.5 in WSL2 (Ubuntu 26.04), `smartctl -x -j -n standby -d scsi /dev/sda` on a Hyper-V "Msft Virtual Disk" (exit 2) | own capture |
| `json_standby.json` | Synthesised from smartmontools 7.3 source: `ataprint.cpp` prints `jinf("Device is in %s mode, exit(%d)")` (severity "information") and sets `power_mode` | synthesised |

## smartctl text (`smartctl -a` / `-x`, for smartctl < 7.0 and saved outputs)

| File | Origin | Licence |
|---|---|---|
| `text64_sat_hdd.txt` | truenas/py-SMART `tests/dataset/singletests/sat_hdd_0_issue70/_-d_sat_--all__dev_sg2` (smartctl 6.4) — https://github.com/truenas/py-SMART | LGPL-2.1 (test data) |
| `text66_ata_ssd.txt` | py-SMART `singletests/sata_ssd_0_issue_49/_-d_ata_--all__dev_sda` (smartctl 6.6) | LGPL-2.1 |
| `text71_ata_hdd_selftest_running.txt` | py-SMART `singletests/sata_hdd_0_issue42/_-d_ata_--all__dev_sdau` (smartctl 7.1, extended self-test in progress) | LGPL-2.1 |
| `text71_sas_hgst.txt` | py-SMART `singletests/sas_hdd_0_issue_51/_-d_scsi_--all__dev_sdc` (HGST SAS; whitespace collapsed and comma decimals in the source) | LGPL-2.1 |
| `text71_megaraid_vd_intel.txt` | py-SMART `singletests/megaraid_vd_0/_-d_scsi_--all__dev_sda` (Intel RS3DC080 and AVAGO MR9361-16i logical volumes, no SMART) | LGPL-2.1 |
| `text72_nvme_toshiba.txt` | py-SMART `singletests/nvme_0/_-d_nvme_--all__dev_nvme0` (smartctl 7.2, de_DE number format, 28 % used) | LGPL-2.1 |
| `scan_megaraid_nvme.txt` | py-SMART `listingtests/linux_multiple_devices/_--scan-open` | LGPL-2.1 |
| `text540_ata_pending_selftest.txt` | `smartctl -a` output (smartctl 5.40, Samsung HD502HI with 81 pending sectors) from the Thomas-Krenn wiki article "Analyzing a Faulty Hard Disk using Smartctl" — https://www.thomas-krenn.com/en/wiki/Analyzing_a_Faulty_Hard_Disk_using_Smartctl (HTML stripped; tabs in "General SMART Values" became spaces) | tool output quoted for interoperability testing |
| `text75_msft_virtual_disk.txt` | Own capture, smartctl 7.5 in WSL2: `smartctl -x -n standby -d scsi /dev/sda` | own capture |
| `text62_ata_failed.txt` | Synthesised in the exact smartctl 6.2 layout (CentOS 7) from ataprint.cpp format strings (`FAILED!`, `Drive failure expected in less than 24 hours. SAVE ALL DATA.`, `FAILING_NOW`, `In_the_past`, self-test and error-log lines); attribute set modelled on telegraf's `seagateSATAInfoData75` sample | synthesised |
| `text_standby.txt` | Synthesised from the same `Device is in STANDBY mode, exit(2)` message | synthesised |
| `scan_megaraid_vd.txt` | Synthesised `smartctl --scan-open` text: lines in the format of the real samples above, plus a commented "open failed" line as printed by smartctl.cpp | synthesised |
| `scan_wsl.txt` | Own capture, `smartctl --scan-open` in WSL2 | own capture |

## lsblk

| File | Origin |
|---|---|
| `lsblk_wsl_msft.json` | Own capture, util-linux 2.41.3 (WSL2): `lsblk -J -b -o NAME,KNAME,PATH,TYPE,SIZE,ROTA,TRAN,MODEL,SERIAL,VENDOR,REV,STATE,HCTL,WWN,MOUNTPOINT,FSTYPE,PKNAME` |
| `lsblk_wsl_msft_P.txt` | Own capture, the collector's `lsblk -P -b` fallback (forced by hiding -J), same machine |
| `lsblk_old_strings.json` | Synthesised: util-linux < 2.33 writes every JSON value as a string ("rota": "1", "size": "4000787030016"); see the util-linux v2.33 release notes ("The old versions uses strings everywhere") — https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.33/v2.33-ReleaseNotes. Layout of a typical CentOS 8 mdadm server. |

## smartd, dd

| File / test data | Origin |
|---|---|
| `smartd_ubuntu_inactive.txt` | Own capture of the collector's `disk.smartd` section in WSL2 (Ubuntu 26.04, smartmontools installed, service inactive) |
| dd lines in `TestBench` | GNU coreutils 9.x line captured in WSL2; coreutils 8.22 (CentOS 7) form without the MiB part and the BusyBox form ("copied, 0.512 seconds, 125.0MB/s") synthesised from coreutils/busybox `dd.c` print formats |

## Windows (PowerShell JSON written by `collect/windows/30-disk.ps1`)

| File | Origin |
|---|---|
| `win_physical.json`, `win_diskdrive.json` | Shape captured from `Get-PhysicalDisk` / `Win32_DiskDrive` on the Windows 10 dev machine (the KINGSTON NVMe entry is real); the Intel SATA SSD and failing Seagate SAS entries are synthesised with the same property names |
| `win_physical_numeric.json` | Synthesised with raw numeric enums (MediaType 3, BusType 11/15, HealthStatus 1, OperationalStatus [2, 53286]) as CIM returns them without the Storage module's type data; value maps from `Storage.types.ps1xml` on Windows 10 and https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-physicaldisk |
| `win_reliability.json` | Synthesised from the documented MSFT_StorageReliabilityCounter properties — https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-storagereliabilitycounter (needs Administrator; could not be captured on the non-elevated dev machine) |
| `win_predict.json` | Synthesised from the root\wmi MSStorageDriver_FailurePredictStatus properties (InstanceName = PNP device ID + "_0", Active, PredictFailure, Reason) |
