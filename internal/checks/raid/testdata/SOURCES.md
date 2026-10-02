# Fixture sources (raid domain)

"Real" = output captured from the actual tool. "Derived" = a real fixture
with specific values changed to produce a failure case (the change is
listed). "Synthesised" = written by hand from the tool's documented format
(the documentation is linked); these are the least trustworthy and are
marked as such in the test names where it matters.

## Linux software RAID (md)

| File | Origin |
|---|---|
| `mdstat_procfs.txt` | Real. prometheus/procfs `testdata/fixtures.ttar`, path `fixtures/proc/mdstat` (Apache-2.0). https://github.com/prometheus/procfs/blob/master/testdata/fixtures.ttar — contains healthy, inactive, recovery, resync, check, failed (F), spares, DELAYED/PENDING, IMSM container, raid0/linear, read-only and reshape arrays. |
| `md_sysfs_procfs.txt` | Real values, converted. Same procfs `fixtures.ttar`, `fixtures/sys/block/md*/md/*` files rewritten as `dw_sysfs` "path=value" lines (Apache-2.0). Not consistent with `mdstat_procfs.txt` (separate fixtures upstream). |
| `wsl_mdstat_*.txt`, `wsl_mdadm_detail_*.txt`, `wsl_md_sysfs_*.txt` | Real. Captured on 2026-10-02 in WSL2 (Ubuntu 26.04, kernel 6.18.40.1-microsoft-standard-WSL2, mdadm from Ubuntu) with loop-device arrays: a RAID1 (`md90`) resyncing, clean, with a member failed (`--fail`) and removed; a RAID5 with a hot spare (`md91`) initial recovery, clean, failed member + spare rebuilding, and a running `check`. Script: create arrays on 128 MiB loop files, throttle `speed_limit_max` to catch progress lines, capture `/proc/mdstat`, `mdadm --detail`, `mdadm --detail --scan` and the md sysfs files, then tear everything down. |

## ZFS

| File | Origin |
|---|---|
| `zpool_status_healthy.txt`, `zpool_status_offline.txt`, `zpool_status_unavail.txt` | Real. Henry Leach, "Simulating ZFS Failures" (2024-09), https://henryleach.com/2024/09/simulating-zfs-failures/ (file-backed mirror: healthy after resilver, device OFFLINE, device UNAVAIL "corrupted data"). |
| `zpool_status_faulted_2q.txt` | Real (documentation sample). OpenZFS message ZFS-8000-2Q, https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-2Q/ (older "scrub:" field, `mirror` without index). |
| `zpool_status_data_errors.txt` | Real (documentation sample). OpenZFS message ZFS-8000-8A, https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-8A/ ("errors: 1 data errors"). |
| `zpool_status_resilver.txt` | Real. openzfs/zfs issue #10580, https://github.com/openzfs/zfs/issues/10580 (Proxmox rpool resilvering, `replacing-1`, DEGRADED "too many errors", permanent errors). |
| `zpool_status_scrub_recent.txt` | Synthesised from the format of the samples above and zpool-status(8) (`-P` by-id paths, completed scrub line). |
| `zpool_list_*.txt` | Synthesised from zpool-list(8) `-H -o name,size,alloc,free,health,frag,cap` (tab separated); the FAULTED row mirrors netdata `zfspool/testdata/zpool-list.txt`. |

## Btrfs

| File | Origin |
|---|---|
| `wsl_btrfs_show_ok.txt`, `wsl_btrfs_show_missing.txt`, `wsl_btrfs_show_degraded_mounted.txt`, `wsl_btrfs_stats_ok.txt`, `wsl_btrfs_stats_degraded.txt` | Real. Captured 2026-10-02 in WSL2, btrfs-progs v6.17.1: RAID1 data+metadata on two loop devices; then one device detached, `btrfs filesystem show` (unmounted: "*** Some devices missing") and mounted `-o degraded` ("devid 2 size 0 used 0 path  MISSING", stats for `[devid:2]`). |
| `btrfs_stats_errors.txt`, `btrfs_show_sdb_sdc.txt` | Synthesised from the real format above with non-zero counters (btrfs-device(8)). |

## LVM

| File | Origin |
|---|---|
| `wsl_lvs_json_*.txt`, `wsl_lvs_text_*.txt` | Real. Captured 2026-10-02 in WSL2 (lvm2 from Ubuntu, dm-raid): `lvcreate --type raid1 -m1` on two loop PVs, during the initial sync, in sync, during `lvchange --syncaction check`, and after one PV was detached and the VG activated with `--activationmode partial`. The WSL-only "File descriptor 7 leaked" stderr line was removed. The text files used `--separator '|'` with the JSON field list (the collector's old-LVM fallback uses fewer fields; the tests rebuild that form from these rows). |

## Hardware RAID

| File | Origin |
|---|---|
| `storcli_ctrl_praid_ep420i.json`, `storcli_pd_praid_ep420i.json` | Real. prometheus-community/node-exporter-textfile-collector-scripts `mock/fixtures/storcli_-cALL_show_all.json` and `storcli_-cALL-eALL-sALL_show_all.json` (Apache-2.0). Fujitsu PRAID EP420i, RAID6, CacheVault. |
| `storcli_ctrl_m5015.json`, `storcli_pd_m5015.json`, `storcli_ctrl_hba9500.json` | Real. netdata `src/go/plugin/go.d/collector/storcli/testdata/` (GPL-3.0; captured tool output): ServeRAID M5015 with iBBU08, and an HBA 9500-8i (mpt3sas, no virtual drives). |
| `storcli_ctrl_degraded.json` | Derived from `storcli_ctrl_praid_ep420i.json`: VD/topology state Optl→Dgrd, PD 252:5 Onln→UBad, Controller Status → "Needs Attention". |
| `storcli_ctrl_rebuild.json` | Derived from the same: Optl→Dgrd, PD 252:5 Onln→Rbld, CacheVault state → "Dgd (Needs Attention)" (the BBU state string reported in node-exporter-textfile-collector-scripts issue #27). |
| `storcli_pd_errors.json` | Derived from `storcli_pd_praid_ep420i.json`: s0 Media Error Count 0→12; s1 Predictive Failure Count 0→1 and S.M.A.R.T alert No→Yes. |
| `storcli_rebuild.json`, `storcli_cv_failed.json`, `storcli_vd_praid.json` | Synthesised from the StorCLI JSON conventions seen in the real files and the StorCLI reference manual (https://docs.broadcom.com/doc/12352476): `show rebuild` progress rows, CacheVault property/value tables with "Replacement required", `/call/vall show all` "PDs for VD n". Unverified against a live controller. |
| `ssacli-P212_P410i.txt`, `ssacli-P400ar.txt`, `ssacli-P400i-unassigned.txt`, `ssacli-P408i-a.txt` | Real. netdata `src/go/plugin/go.d/collector/hpssa/testdata/` (GPL-3.0; `ssacli ctrl all show config detail` output, serials redacted upstream; note the genuinely garbled line "SATA NCQ En      physicaldriveabled" kept as is). |
| `ssacli-P440ar-failed.txt` | Derived from `ssacli-P400ar.txt`: battery → "Failed (Replace Batteries/Capacitors)", logical drive 1 → "Interim Recovery Mode", physicaldrive 1I:1:2 → Failed, 2I:1:6 → "Predictive Failure" (status names from the HPE Smart Array SR Gen10 user guide). |
| `ssacli-status-failed.txt`, `ssacli-config-recovering.txt` | Synthesised from the documented `ctrl all show status` / `ctrl all show config` layouts (HPE ssacli reference; "Recovering, 26% complete" logical drive summary). |
| `arcconf-getconfig-*.txt` (ld/pd current/old/with-enclosure) | Real. netdata `src/go/plugin/go.d/collector/adaptecraid/testdata/` (GPL-3.0). |
| `arcconf-getconfig-al-synth.txt` | Synthesised controller section (field names as parsed by thomas-krenn/check_adaptec_raid: "Controller Status", "Defunct disk drive count", "Logical devices/Failed/Degraded", ZMM status) followed by the real netdata LD and PD sections. |
| `arcconf-getconfig-al-degraded.txt` | Derived from the previous file: LD Degraded with "Group 0, Segment 1 : Missing", Device #1 Failed, Device #2 S.M.A.R.T. warnings 3, ZMM failed, defunct count 1. |
| `megacli-ldpdinfo.txt`, `megacli-bbu-recent.txt`, `megacli-bbu-old.txt` | Real. netdata `src/go/plugin/go.d/collector/megacli/testdata/` (GPL-3.0; `MegaCli -LDPDInfo -aAll` and `-AdpBbuCmd -aAll`). |
| `megacli-ldpdinfo-degraded.txt`, `megacli-bbu-degraded.txt` | Derived: VD State → Degraded, slot 2 → Failed, slot 1 media errors 5, slot 3 predictive 2 + S.M.A.R.T alert Yes; battery state "Degraded(Need Attention)" and "Battery Replacement required: Yes". |

## Detection and Windows

| File | Origin |
|---|---|
| `pci_perc_hba.txt`, `pci_smartarray.txt` | Synthesised in the collector's `raid.pci` format; IDs and names from the PCI ID database (https://pci-ids.ucw.cz/: 1000:005d MegaRAID SAS-3 3108 / Dell 1f47 PERC H730P Mini; 1000:0097 SAS3008 / Dell HBA330 Mini; 103c:3239 Smart Array Gen9 / P440ar; 15ad:07c0 PVSCSI). |
| `byid_sdb_sdc.txt` | Synthesised `raid.byid` lines following udev's persistent-storage naming (ata-MODEL_SERIAL, scsi-SATA_, nvme-eui, wwn-). |
| `win_controllers_local.json`, `win_pools_local.json` | Real. Captured with the collector's PowerShell on the Windows 10 dev machine (not elevated; Intel RST controller, primordial pool only). |
| `win_controllers_perc.json`, `win_pools_*.json`, `win_vdisks_*.json`, `win_pdisks_degraded.json`, `win_jobs_repair.json` | Synthesised in the collector's JSON shape; enum names/values from the Windows Storage Management API docs (MSFT_VirtualDisk, MSFT_PhysicalDisk: https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-virtualdisk). Unverified against a real degraded Storage Spaces pool. |
