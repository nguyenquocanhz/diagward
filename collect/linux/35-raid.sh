# RAID domain: Linux software RAID (md), ZFS, Btrfs, LVM RAID and hardware
# RAID controllers (Broadcom/LSI storcli, Dell perccli, storcli2/perccli2 for
# MegaRAID 9600+/PERC 12, HPE ssacli, Microchip arcconf, legacy MegaCli).
# Read-only. Variables use the _rd_ prefix.
#
# Vendor CLIs write log files into the current directory (storcli.log,
# UcliEvt.log, MegaSAS.log), so they run from $DW_T, which is removed on exit.

# Common install locations that are not on PATH by default.
# The storcli/perccli RPMs install into /opt/MegaRAID/<tool>/ without a link
# on PATH.
for _rd_d in /opt/MegaRAID/MegaCli /opt/MegaRAID/storcli /opt/MegaRAID/perccli \
	/opt/MegaRAID/storcli2 /opt/MegaRAID/perccli2 \
	/usr/Arcconf /opt/hp/hpssacli/bld /opt/smartstorageadmin/ssacli/bin; do
	[ -d "$_rd_d" ] && PATH="$PATH:$_rd_d"
done
export PATH

# _rd_inT CMD ARGS... - run a vendor CLI from the temporary directory, under
# the timeout.
_rd_inT() {
	cd "$DW_T" 2>/dev/null || return 125
	$DW_TO "$@"
}

# ---- disk identities (model/serial from udev by-id names) ----
_rd_byid() {
	for _rd_f in /dev/disk/by-id/*; do
		[ -L "$_rd_f" ] || continue
		printf '%s %s\n' "${_rd_f##*/}" "$(readlink "$_rd_f" 2>/dev/null)"
	done
	return 0
}

# ---- Linux software RAID (md) ----
_rd_md=""
if [ -r /proc/mdstat ]; then
	dw_file raid.mdstat /proc/mdstat
	_rd_md=$(sed -n 's/^\(md[^ ]*\) : .*/\1/p' /proc/mdstat 2>/dev/null)
fi
if [ -n "$_rd_md" ]; then
	dw_sysfs raid.md_sysfs '/sys/block/md*/md/array_state' '/sys/block/md*/md/level' \
		'/sys/block/md*/md/raid_disks' '/sys/block/md*/md/degraded' \
		'/sys/block/md*/md/sync_action' '/sys/block/md*/md/sync_completed' \
		'/sys/block/md*/md/mismatch_cnt' '/sys/block/md*/md/dev-*/state' \
		'/sys/block/md*/md/dev-*/errors'
	if ! dw_has mdadm; then
		dw_missing raid.mdadm_scan mdadm
	elif [ "$DW_ROOT" != 1 ]; then
		dw_skip raid.mdadm_scan not-root
	else
		dw_run raid.mdadm_scan mdadm --detail --scan
		for _rd_m in $_rd_md; do
			dw_run "raid.mdadm:/dev/$_rd_m" mdadm --detail "/dev/$_rd_m"
		done
	fi
fi

# ---- ZFS (only when the kernel module is loaded) ----
_rd_zfs=0
if [ -d /sys/module/zfs ] || [ -c /dev/zfs ]; then
	_rd_zfs=1
	if dw_has zpool; then
		dw_run raid.zpool_status zpool status -P
		dw_run raid.zpool_list zpool list -H -o name,size,alloc,free,health,frag,cap
	else
		dw_missing raid.zpool_status zpool
	fi
fi

if [ -n "$_rd_md" ] || [ "$_rd_zfs" = 1 ]; then
	[ -d /dev/disk/by-id ] && dw_fn raid.byid _rd_byid
fi

# ---- Btrfs (mounted filesystems, one stats section per filesystem) ----
_rd_bt=$(awk '$3 == "btrfs" && !s[$1]++ { print $2 }' /proc/mounts 2>/dev/null)
if [ -n "$_rd_bt" ]; then
	if ! dw_has btrfs; then
		dw_missing raid.btrfs_show btrfs
	elif [ "$DW_ROOT" != 1 ]; then
		dw_skip raid.btrfs_show not-root
	else
		dw_run raid.btrfs_show btrfs filesystem show
		set -f # mount points are data, not glob patterns
		for _rd_p in $_rd_bt; do
			# /proc/mounts escapes blanks as \040 and tabs as \011; the
			# escaped form keeps the section name free of spaces.
			_rd_real=$(printf '%s\n' "$_rd_p" | sed -e 's/\\040/ /g' -e 's/\\011/	/g')
			dw_run "raid.btrfs_stats:$_rd_p" btrfs device stats "$_rd_real"
		done
		set +f
	fi
fi

# ---- LVM RAID / mirror (only when such a logical volume is active) ----
_rd_lv=0
for _rd_f in /sys/block/dm-*/dm/name; do
	[ -r "$_rd_f" ] || continue
	case $(cat "$_rd_f" 2>/dev/null) in
	*_rimage_* | *_mimage_*) _rd_lv=1; break ;;
	esac
done
_rd_lvs() {
	LVM_SUPPRESS_FD_WARNINGS=1
	export LVM_SUPPRESS_FD_WARNINGS
	if $DW_TO lvs -a --reportformat json -o lv_name,vg_name,segtype,lv_size,lv_health_status,sync_percent,raid_mismatch_count,raid_sync_action,lv_attr,devices 2>"$DW_T/rd_lvs.err"; then
		cat "$DW_T/rd_lvs.err" >&2
		return 0
	fi
	# Old LVM (before 2.02.158) has no JSON report and fewer fields.
	echo "#fields=lv_name,vg_name,segtype,lv_size,copy_percent,lv_attr,devices"
	$DW_TO lvs -a --noheadings --separator '|' -o lv_name,vg_name,segtype,lv_size,copy_percent,lv_attr,devices
}
if [ "$_rd_lv" = 1 ]; then
	if ! dw_has lvs; then
		dw_missing raid.lvs lvs
	elif [ "$DW_ROOT" != 1 ]; then
		dw_skip raid.lvs not-root
	else
		dw_fn raid.lvs _rd_lvs
	fi
fi

# ---- hardware RAID controllers ----
# PCI storage controllers (class 0100 SCSI, 0104 RAID, 0107 SAS) from sysfs,
# with lspci names when available. One "key=value" block per device.
_rd_pci() {
	for _rd_d in /sys/bus/pci/devices/*; do
		[ -r "$_rd_d/class" ] || continue
		_rd_c=$(cat "$_rd_d/class" 2>/dev/null)
		case $_rd_c in
		0x0100* | 0x0104* | 0x0107*) ;;
		*) continue ;;
		esac
		_rd_s=${_rd_d##*/}
		echo "slot=$_rd_s"
		echo "class=$_rd_c"
		for _rd_k in vendor device subsystem_vendor subsystem_device; do
			[ -r "$_rd_d/$_rd_k" ] && echo "$_rd_k=$(cat "$_rd_d/$_rd_k" 2>/dev/null)"
		done
		if [ -L "$_rd_d/driver" ]; then
			_rd_drv=$(readlink "$_rd_d/driver" 2>/dev/null)
			echo "driver=${_rd_drv##*/}"
		fi
		if dw_has lspci; then
			$DW_TO lspci -vmm -nn -s "$_rd_s" 2>/dev/null |
				sed -n 's/^\([A-Za-z]*\):[[:space:]]*\(.*\)$/lspci_\1=\2/p'
		fi
		echo
	done
	return 0
}

_rd_sc=""
for _rd_c in storcli64 storcli; do dw_has "$_rd_c" && { _rd_sc=$_rd_c; break; }; done
_rd_pc=""
for _rd_c in perccli64 perccli; do dw_has "$_rd_c" && { _rd_pc=$_rd_c; break; }; done
# StorCLI2/PERCCLI2 manage the MPI3 controllers (mpi3mr driver: MegaRAID
# 9600/9700, PERC H965i/H765i/H365i/H975i), which storcli/perccli do not see.
_rd_s2=""
dw_has storcli2 && _rd_s2=storcli2
_rd_p2=""
dw_has perccli2 && _rd_p2=perccli2
_rd_hp=""
for _rd_c in ssacli hpssacli hpacucli; do dw_has "$_rd_c" && { _rd_hp=$_rd_c; break; }; done
_rd_mc=""
for _rd_c in MegaCli64 MegaCli megacli; do dw_has "$_rd_c" && { _rd_mc=$_rd_c; break; }; done

# _rd_arclist - arcconf LIST, also kept in $DW_T/rd_arc.txt.
_rd_arclist() {
	_rd_inT arcconf LIST >"$DW_T/rd_arc.txt"
	_rd_rc=$?
	cat "$DW_T/rd_arc.txt"
	return $_rd_rc
}

# _rd_megaraid PREFIX CLI - the storcli/perccli command set (identical JSON).
_rd_megaraid() {
	dw_fn "raid.$1_ctrl" _rd_inT "$2" /call show all J
	dw_fn "raid.$1_vd" _rd_inT "$2" /call/vall show all J
	dw_fn "raid.$1_pd" _rd_inT "$2" /call/eall/sall show all J
	dw_fn "raid.$1_rebuild" _rd_inT "$2" /call/eall/sall show rebuild J
	dw_fn "raid.$1_bbu" _rd_inT "$2" /call/bbu show all J
	dw_fn "raid.$1_cv" _rd_inT "$2" /call/cv show all J
}

# _rd_mr2ctrl CLI - "/call show all J", also kept in $DW_T/rd_mr2.json.
_rd_mr2ctrl() {
	_rd_inT "$1" /call show all J >"$DW_T/rd_mr2.json"
	_rd_rc=$?
	cat "$DW_T/rd_mr2.json"
	return $_rd_rc
}

# _rd_megaraid2 PREFIX CLI - the storcli2/perccli2 command set (identical
# JSON; commands from the StorCLI2 User Guide and Dell's sos perccli2
# plugin). Nothing more runs when the CLI sees no controller.
_rd_megaraid2() {
	dw_fn "raid.$1_ctrl" _rd_mr2ctrl "$2"
	grep -q -e '"Number of Controllers"[[:space:]]*:[[:space:]]*0[^0-9]' -e '"Number of Controllers"[[:space:]]*:[[:space:]]*0$' "$DW_T/rd_mr2.json" 2>/dev/null && return 0
	dw_fn "raid.$1_vd" _rd_inT "$2" /call/vall show all J
	dw_fn "raid.$1_pd" _rd_inT "$2" /call/eall/sall show all J
	dw_fn "raid.$1_rebuild" _rd_inT "$2" /call/eall/sall show rebuild J
	dw_fn "raid.$1_ep" _rd_inT "$2" /call/ep show all J
}

if [ -n "$DW_CONTAINER" ]; then
	dw_skip raid.hw container
else
	[ -d /sys/bus/pci/devices ] && dw_fn raid.pci _rd_pci
	if [ -n "$_rd_sc$_rd_pc$_rd_s2$_rd_p2$_rd_hp$_rd_mc" ] || dw_has arcconf; then
		if [ "$DW_ROOT" != 1 ]; then
			dw_skip raid.hw not-root
		else
			[ -n "$_rd_sc" ] && _rd_megaraid storcli "$_rd_sc"
			[ -n "$_rd_pc" ] && _rd_megaraid perccli "$_rd_pc"
			[ -n "$_rd_s2" ] && _rd_megaraid2 storcli2 "$_rd_s2"
			[ -n "$_rd_p2" ] && _rd_megaraid2 perccli2 "$_rd_p2"
			if [ -n "$_rd_hp" ]; then
				dw_fn raid.ssacli_config _rd_inT "$_rd_hp" ctrl all show config detail
				dw_fn raid.ssacli_status _rd_inT "$_rd_hp" ctrl all show status
			fi
			if dw_has arcconf; then
				# One LIST run: captured, and read back for the controller count.
				dw_fn raid.arcconf_list _rd_arclist
				_rd_n=$(sed -n 's/^Controllers found: *\([0-9][0-9]*\).*/\1/p' "$DW_T/rd_arc.txt" 2>/dev/null | head -n 1)
				_rd_i=1
				while [ -n "$_rd_n" ] && [ "$_rd_i" -le "$_rd_n" ] && [ "$_rd_i" -le 16 ]; do
					dw_fn "raid.arcconf:$_rd_i" _rd_inT arcconf GETCONFIG "$_rd_i" AL
					_rd_i=$((_rd_i + 1))
				done
			fi
			# MegaCli is the predecessor of storcli; skip it when storcli or
			# perccli already covered the same controllers.
			if [ -n "$_rd_mc" ] && [ -z "$_rd_sc$_rd_pc" ]; then
				dw_fn raid.megacli_ld _rd_inT "$_rd_mc" -LDInfo -Lall -aALL -NoLog
				dw_fn raid.megacli_pd _rd_inT "$_rd_mc" -PDList -aALL -NoLog
				dw_fn raid.megacli_bbu _rd_inT "$_rd_mc" -AdpBbuCmd -aALL -NoLog
			fi
		fi
	fi
fi
