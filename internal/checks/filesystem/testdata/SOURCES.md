# Fixture sources (filesystem domain)

| File | Origin | Licence / notes |
|---|---|---|
| `wsl_loopfs.json` | Real collector run (`dwdev -os linux -save`) in WSL2 Ubuntu 26.04, kernel 6.18, as root, with three 64 MB loop-mounted ext4 filesystems: `/mnt/dwfull` filled to 100 % with dd; `/mnt/dwerr` with superblock error fields set by `debugfs -w -R "ssv error_count 3"` (+ first/last error time/func, `state 3`) before mounting; `/mnt/dwro` mounted `errors=remount-ro` after `debugfs clri` of a referenced inode, then `ls` triggered a real `EXT4-fs error ... deleted inode referenced` and the kernel's remount (shown as `emergency_ro` in /proc/mounts since Linux 6.6). Contains real `df -P -T -B1`, `df -P -T -i`, /proc/mounts, /etc/fstab, /sys/fs/ext4 and `tune2fs -l` output. | Only `meta.*`, `filesystem.*`, `system.uptime` kept; hostname replaced. |
| `df_busybox_wsl.txt`, `df_i_busybox_wsl.txt`, `proc_mounts_busybox_wsl.txt` | Real `busybox df -P -k`, `busybox df -P -i` and /proc/mounts captured together in the same WSL2 session (BusyBox prints `18446744073708552615` / `4199266%` for the 9p mounts) | — |
| `df_alP_insights.txt` | RedHatInsights/insights-core `insights/tests/parsers/test_df.py` (`DF_ALP`, with `/bin/df:` error lines) | Apache-2.0. |
| `df_li_insights.txt` | same file (`DF_LI`, non-POSIX wrapped device line and mount points with spaces) | Apache-2.0. |
| `proc_mounts_rhel6.txt` | insights-core `insights/tests/parsers/test_mount.py` (`PROC_MOUNT`, RHEL 6) | Apache-2.0. |
| `proc_mounts_rhel6_var_ro.txt` | Derived from `proc_mounts_rhel6.txt`: `/var` changed from `rw` to `ro`, which is how kernels before 6.6 show an ext4 `errors=remount-ro` remount | Modified. |
| `fstab_rhel7_hadoop.txt` | insights-core `insights/tests/parsers/test_fstab.py` (`FS_TAB_DATA`) | Apache-2.0. |
| `win10.json` | Real collector run on Windows 10 (not elevated): Get-Volume (C: 90 % used, a letter-less recovery partition), dirty bit skipped | Hostname replaced. |

The Windows "unhealthy / dirty" bundle in `check_test.go` is synthesised from the MSFT_Volume
property names and enum values (HealthStatus 0/1/2, OperationalStatus 0xD00D-0xD00F) in
Microsoft's Storage Management API documentation, in both string and numeric form, because
the dev machine has no damaged volume and is not elevated.
