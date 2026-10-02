# ---- disk: block device inventory (lsblk), S.M.A.R.T. (smartctl), smartd
# status and the opt-in sequential speed test (dd). Owner: disk domain.
# Prefix: _dk_
#
# Sections:
#   disk.lsblk           lsblk -J -b (util-linux >= 2.27) or lsblk -P -b (older)
#   disk.sysblock        /sys/block fallback when lsblk is missing or failed
#   disk.smart_version   smartctl --version
#   disk.smart_scan      smartctl --scan-open (text: "DEV -d TYPE # comment")
#   disk.smart:<dev>[,<type>]  smartctl -x [-j] -n standby -d TYPE DEV (one per device;
#                        ",<type>" only when the type carries a controller
#                        address, e.g. disk.smart:/dev/bus/0,megaraid,3)
#                        (HPE Smart Array drives found by probing -d cciss,N
#                        appear as disk.smart:/dev/sdX,cciss,N)
#   disk.smartd          smartd service / process state and its config lines
#   disk.bench           dd write/read test, only when DW_BENCH_DIR is set
#
# Everything only reads, except disk.bench, which writes one file in the
# directory the user chose and always deletes it.

_dk_cols_full="NAME,KNAME,PATH,TYPE,SIZE,ROTA,TRAN,MODEL,SERIAL,VENDOR,REV,STATE,HCTL,WWN,MOUNTPOINT,FSTYPE,PKNAME"
# PATH needs util-linux 2.33; the rest exists in 2.23 (CentOS 7).
_dk_cols_mid="NAME,KNAME,TYPE,SIZE,ROTA,TRAN,MODEL,SERIAL,VENDOR,REV,STATE,HCTL,WWN,MOUNTPOINT,FSTYPE,PKNAME"
_dk_cols_min="NAME,KNAME,TYPE,SIZE,ROTA,MODEL,MOUNTPOINT,FSTYPE"

# lsblk fails as a whole on an unknown column, so fall back to fewer
# columns, then to -P (key="value") for util-linux < 2.27 (no -J).
_dk_lsblk() {
	for _dk_c in "$_dk_cols_full" "$_dk_cols_mid"; do
		$DW_TO lsblk -J -b -o "$_dk_c" 2>/dev/null
		_dk_rc=$?
		[ "$_dk_rc" = 0 ] && return 0
		[ "$_dk_rc" = 124 ] || [ "$_dk_rc" = 137 ] && return "$_dk_rc"
	done
	for _dk_c in "$_dk_cols_mid" "$_dk_cols_min"; do
		$DW_TO lsblk -P -b -o "$_dk_c" 2>/dev/null && return 0
	done
	$DW_TO lsblk -P -b
}

_dk_sysblock() {
	dw_sysfs disk.sysblock '/sys/block/*/size' '/sys/block/*/queue/rotational' \
		'/sys/block/*/device/vendor' '/sys/block/*/device/model' '/sys/block/*/device/rev' \
		'/sys/block/*/device/serial' '/sys/block/*/device/firmware_rev' '/sys/block/*/device/state' \
		'/sys/block/*/device/wwid'
}

if dw_has lsblk; then
	dw_fn disk.lsblk _dk_lsblk || _dk_sysblock
else
	dw_missing disk.lsblk lsblk
	_dk_sysblock
fi

# ---- S.M.A.R.T. ----

# _dk_smart DEV TYPE — print smartctl -x for one device (JSON when smartctl
# >= 7.0). -n standby: do not spin up a sleeping disk; smartctl then prints
# "Device is in STANDBY mode" and exits 2. If -x is rejected (exit bit 0:
# command line did not parse), retry with -a. Returns smartctl's exit status.
_dk_smart() {
	_dk_sd=$1
	_dk_st=$2
	for _dk_opt in -x -a; do
		if [ -n "$_dk_st" ]; then
			$DW_TO smartctl $_dk_opt $_dk_j -n standby -d "$_dk_st" "$_dk_sd" >"$DW_T/dk_s" 2>"$DW_T/dk_se"
		else
			$DW_TO smartctl $_dk_opt $_dk_j -n standby "$_dk_sd" >"$DW_T/dk_s" 2>"$DW_T/dk_se"
		fi
		_dk_rc=$?
		if [ "$_dk_rc" -lt 124 ] && [ $((_dk_rc & 1)) -ne 0 ] && [ "$_dk_opt" = -x ]; then
			continue
		fi
		break
	done
	cat "$DW_T/dk_s"
	cat "$DW_T/dk_se" >&2
	rm -f "$DW_T/dk_s" "$DW_T/dk_se"
	return "$_dk_rc"
}

_dk_scan_out() {
	cat "$DW_T/dk_scan"
	cat "$DW_T/dk_scan_e" >&2
	return "$_dk_scanrc"
}

if [ -n "$DW_CONTAINER" ]; then
	dw_skip disk.smart_scan container
elif ! dw_has smartctl; then
	dw_missing disk.smart_scan smartctl
else
	dw_run disk.smart_version smartctl --version
	if [ "$DW_ROOT" != 1 ]; then
		dw_skip disk.smart_scan not-root
	else
		# "smartctl 7.4 2023-08-01 r5530 ..."; SVN builds say "smartctl pre-7.5 ...".
		_dk_maj=$(smartctl --version 2>/dev/null | sed -n '1s/^smartctl \(pre-\)\{0,1\}\([0-9][0-9]*\)\..*/\2/p')
		_dk_j=""
		[ -n "$_dk_maj" ] && [ "$_dk_maj" -ge 7 ] 2>/dev/null && _dk_j="-j"
		$DW_TO smartctl --scan-open >"$DW_T/dk_scan" 2>"$DW_T/dk_scan_e" </dev/null
		_dk_scanrc=$?
		dw_fn disk.smart_scan _dk_scan_out
		# One section per device. Lines starting with "#" are devices that
		# could not be opened; the analysis reads them from disk.smart_scan.
		_dk_n=0
		while read -r _dk_dev _dk_d _dk_type _dk_rest; do
			case $_dk_dev in '' | '#'*) continue ;; esac
			[ "$_dk_d" = "-d" ] || _dk_type=""
			_dk_n=$((_dk_n + 1))
			if [ "$_dk_n" -gt 256 ]; then
				# Bound the run time on huge JBODs; record the cut so the
				# report does not imply every disk was read.
				printf 'limit=256\ntotal=%s\n' "$(grep -c '^/dev' "$DW_T/dk_scan")" >"$DW_T/dk_cap"
				break
			fi
			_dk_name=$_dk_dev
			case $_dk_type in *,*) _dk_name="$_dk_dev,$_dk_type" ;; esac
			dw_fn "disk.smart:$_dk_name" _dk_smart "$_dk_dev" "$_dk_type"
		done <"$DW_T/dk_scan"
		if [ -s "$DW_T/dk_cap" ]; then dw_file disk.smart_capped "$DW_T/dk_cap"; fi
		# HPE Smart Array (hpsa) in RAID mode: --scan-open lists only the
		# logical volume; the physical drives answer to -d cciss,N on any
		# logical volume of the same controller. Probe N = 0..15 once per
		# controller (SCSI host) with a cheap -i; absent drives fail fast
		# with exit bit 1 (device open failed).
		if ! grep -q -e 'cciss,' -e 'megaraid,' "$DW_T/dk_scan" 2>/dev/null; then
			_dk_hosts=" "
			for _dk_b in /sys/block/sd*; do
				[ -r "$_dk_b/device/model" ] || continue
				_dk_v=$(cat "$_dk_b/device/vendor" 2>/dev/null)
				_dk_m=$(cat "$_dk_b/device/model" 2>/dev/null)
				case "$_dk_v" in HP*) ;; *) continue ;; esac # HP and HPE
				case "$_dk_m" in *LOGICAL*VOLUME*) ;; *) continue ;; esac
				_dk_h=$(readlink -f "$_dk_b/device" 2>/dev/null)
				_dk_h=${_dk_h##*/}
				_dk_h=${_dk_h%%:*}
				case "$_dk_hosts" in *" $_dk_h "*) continue ;; esac
				_dk_hosts="$_dk_hosts$_dk_h "
				_dk_dev="/dev/${_dk_b##*/}"
				_dk_i=0
				while [ "$_dk_i" -le 15 ]; do
					$DW_TO smartctl -i -d "cciss,$_dk_i" "$_dk_dev" >/dev/null 2>&1 </dev/null
					_dk_rc=$?
					if [ "$_dk_rc" -lt 124 ] && [ $((_dk_rc & 3)) -eq 0 ]; then
						dw_fn "disk.smart:$_dk_dev,cciss,$_dk_i" _dk_smart "$_dk_dev" "cciss,$_dk_i"
					fi
					_dk_i=$((_dk_i + 1))
				done
			done
		fi
		rm -f "$DW_T/dk_scan" "$DW_T/dk_scan_e"
	fi
fi

# ---- smartd (continuous monitoring) ----

_dk_smartd() {
	dw_has smartd && echo "installed=1"
	if dw_has systemctl && [ -d /run/systemd/system ]; then
		# Ubuntu/Debian name the unit smartmontools.service (smartd.service is
		# an alias); RHEL family names it smartd.service.
		for _dk_u in smartd smartmontools; do
			echo "active_$_dk_u=$($DW_TO systemctl is-active "$_dk_u.service" 2>/dev/null)"
			echo "enabled_$_dk_u=$($DW_TO systemctl is-enabled "$_dk_u.service" 2>/dev/null)"
		done
	fi
	if grep -qx smartd /proc/[0-9]*/comm 2>/dev/null; then
		echo "process=1"
	else
		echo "process=0"
	fi
	for _dk_f in /etc/smartd.conf /etc/smartmontools/smartd.conf; do
		[ -r "$_dk_f" ] || continue
		echo "conffile=$_dk_f"
		grep -v '^[[:space:]]*#' "$_dk_f" 2>/dev/null | grep -v '^[[:space:]]*$' | head -n 20 | sed 's/^/conf=/'
	done
	return 0
}

if [ -n "$DW_CONTAINER" ]; then
	dw_skip disk.smartd container
else
	dw_fn disk.smartd _dk_smartd
fi

# ---- opt-in sequential speed test (the classic dd test) ----

# Writes DW_BENCH_MB MiB with O_DIRECT + fdatasync, reads it back with
# O_DIRECT, deletes the file. Prints key=value lines; dd's own summary line
# is kept verbatim (write_line=, read_line=) and parsed in Go.
_dk_bench() {
	_dk_bd=$DW_BENCH_DIR
	_dk_mb=$DW_BENCH_MB
	case $_dk_mb in '' | *[!0-9]*) _dk_mb=256 ;; esac
	[ "$_dk_mb" -lt 16 ] && _dk_mb=16
	echo "dir=$_dk_bd"
	echo "mb=$_dk_mb"
	if [ ! -d "$_dk_bd" ]; then
		echo "error=not-a-directory"
		return 2
	fi
	if [ ! -w "$_dk_bd" ]; then
		echo "error=not-writable"
		return 2
	fi
	if ! dw_has dd; then
		echo "error=no-dd"
		return 2
	fi
	_dk_fs=$(stat -f -c %T "$_dk_bd" 2>/dev/null)
	echo "fs=$_dk_fs"
	_dk_df=$($DW_TO df -Pk "$_dk_bd" 2>/dev/null | awk 'NR==2 {print $1" "$4}')
	echo "source=${_dk_df% *}"
	_dk_free=${_dk_df##* }
	case $_dk_free in '' | *[!0-9]*) _dk_free=0 ;; esac
	echo "free_kb=$_dk_free"
	if [ "$_dk_free" -lt $((_dk_mb * 1024 * 3)) ]; then
		echo "error=no-space"
		return 3
	fi
	# Allow at least 10 MB/s before the timeout kills dd.
	_dk_secs=$((DW_TIMEOUT + _dk_mb / 10))
	_dk_to=""
	[ -n "$DW_TO" ] && _dk_to=$(echo "$DW_TO" | sed "s/[0-9][0-9]*\$/$_dk_secs/")
	# The cleanup traps only ever delete a file this function created
	# ($_dk_made is set after the exclusive create succeeded), so a
	# pre-existing file of the same name is never touched, on any path.
	_dk_made=""
	trap 'if [ -n "$_dk_made" ]; then rm -f "$_dk_made"; fi' EXIT
	trap 'if [ -n "$_dk_made" ]; then rm -f "$_dk_made"; fi; exit 130' HUP INT TERM
	# Create the test file exclusively: mktemp (O_EXCL, unique name), or
	# set -C (noclobber) when mktemp is missing.
	_dk_bf=""
	if dw_has mktemp; then
		_dk_bf=$(mktemp "$_dk_bd/.diagward-bench.XXXXXX" 2>/dev/null) || _dk_bf=""
	fi
	if [ -z "$_dk_bf" ]; then
		_dk_bf="$_dk_bd/.diagward-bench.$$"
		if ! (set -C; : >"$_dk_bf") 2>/dev/null; then
			echo "error=cannot-create"
			return 2
		fi
	fi
	_dk_made=$_dk_bf
	echo "write_direct=1"
	$_dk_to dd if=/dev/zero of="$_dk_bf" bs=1048576 count="$_dk_mb" oflag=direct conv=fdatasync 2>"$DW_T/dk_w"
	_dk_wrc=$?
	if [ "$_dk_wrc" != 0 ]; then
		if [ "$_dk_wrc" = 124 ] || [ "$_dk_wrc" = 137 ]; then
			echo "error=write-timeout"
			rm -f "$_dk_bf"
			return 124
		fi
		# Filesystems without O_DIRECT (tmpfs, ZFS < 2.3) reject oflag=direct.
		echo "write_direct=0"
		if ! $_dk_to dd if=/dev/zero of="$_dk_bf" bs=1048576 count="$_dk_mb" conv=fdatasync 2>"$DW_T/dk_w"; then
			echo "error=write-failed"
			echo "write_err=$(tail -n 1 "$DW_T/dk_w")"
			rm -f "$_dk_bf"
			return 4
		fi
	fi
	echo "write_line=$(tail -n 1 "$DW_T/dk_w")"
	echo "read_direct=1"
	if ! $_dk_to dd if="$_dk_bf" of=/dev/null bs=1048576 iflag=direct 2>"$DW_T/dk_r"; then
		echo "read_direct=0"
		$_dk_to dd if="$_dk_bf" of=/dev/null bs=1048576 2>"$DW_T/dk_r" || echo "error=read-failed"
	fi
	echo "read_line=$(tail -n 1 "$DW_T/dk_r")"
	rm -f "$_dk_bf" "$DW_T/dk_w" "$DW_T/dk_r"
	echo "cleaned=1"
	return 0
}

if [ -z "$DW_BENCH_DIR" ]; then
	dw_skip disk.bench disabled
else
	dw_fn disk.bench _dk_bench
fi
