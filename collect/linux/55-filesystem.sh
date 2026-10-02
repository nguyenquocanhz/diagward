# ---- filesystem: space, inodes, mounts (read-only after errors), fstab,
# ext4 error counters. Owner: system domain. Prefix: _fs_
#
# df runs under the timeout and only on local filesystems (-l): a stale NFS
# mount would otherwise hang it, and remote space belongs to another server.
# Pseudo filesystems are excluded. BusyBox df has no -T/-x/-l/-B: fall back
# to plain POSIX output and let the analysis filter by /proc/mounts.
_fs_x="-x tmpfs -x rootfs -x devtmpfs -x squashfs -x overlay -x proc -x sysfs -x devpts -x cgroup -x cgroup2 -x debugfs -x tracefs -x securityfs -x pstore -x efivarfs -x autofs -x mqueue -x hugetlbfs -x configfs -x fusectl -x binfmt_misc -x bpf -x nsfs -x ramfs -x rpc_pipefs -x iso9660 -x udf -x fuse.lxcfs -x fuse.snapfuse -x fuse.gvfsd-fuse -x 9p"
if df --version >/dev/null 2>&1; then
	dw_sh filesystem.df "df -P -T -B1 -l $_fs_x"
	dw_sh filesystem.df_inodes "df -P -T -i -l $_fs_x"
else
	dw_sh filesystem.df 'df -P -k'
	dw_sh filesystem.df_inodes 'df -P -i'
fi

dw_file filesystem.mounts /proc/mounts
dw_file filesystem.fstab /etc/fstab

# ext4 keeps an error counter in the superblock until fsck repairs the
# filesystem; the kernel exposes it per device. dm-N names map to
# /dev/mapper/<name>.
dw_sysfs filesystem.ext4 '/sys/fs/ext4/*/errors_count' '/sys/fs/ext4/*/first_error_time' \
	'/sys/fs/ext4/*/last_error_time' '/sys/fs/ext4/*/first_error_func' '/sys/fs/ext4/*/last_error_func' \
	'/sys/block/dm-*/dm/name'

# tune2fs -l (superblock: "Filesystem state", "FS Error count") for mounted
# ext2/3/4 block devices. Needs root to read the device.
_fs_devs=$(awk '$3 ~ /^ext[234]$/ && $1 ~ /^\/dev\// { print $1 }' /proc/mounts 2>/dev/null | sort -u)
if [ -n "$_fs_devs" ]; then
	if [ "$DW_ROOT" != 1 ]; then
		dw_skip filesystem.tune2fs not-root
	elif ! dw_has tune2fs; then
		dw_missing filesystem.tune2fs tune2fs
	else
		for _fs_d in $_fs_devs; do
			[ -b "$_fs_d" ] || continue
			dw_run "filesystem.tune2fs:$_fs_d" tune2fs -l "$_fs_d"
		done
	fi
fi
