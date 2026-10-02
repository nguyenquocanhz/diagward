# 60-logs.sh — logs domain: kernel log / journal lines that reveal failing
# hardware, unexpected reboots, kernel crash dumps. POSIX sh only.
#
# Every log section starts with "# key=value ..." header lines that tell the
# Go parser how to read the lines after them (journal short-iso, dmesg,
# syslog file with year-less timestamps, local UTC offset). A trailing
# "# rc=N" line carries the journalctl exit status (124 = timed out).
# Kernel messages are read with the _TRANSPORT=kernel match, not -k: -k
# implies -b (current boot only, journalctl(1)) and we want every boot in the
# window.

# Kernel messages worth keeping at ANY priority (some hardware errors are
# logged at info/notice level). Kept broad on purpose: the Go pattern table
# decides what each line means. Basic ERE only (busybox grep compatible).
_lg_re='I/O error|medium error|Medium Error|Unrecovered read|Sense Key|FAILED Result|rejecting I/O|offlined|timing out command|protection error|target error|nexus error|transport error|ata[0-9.]+: (exception|failed command|error:|status:|hard resetting|soft resetting|COMRESET|SATA link down|disabled|SError|ATA-[0-9])|nvme[0-9]+: |nvme[0-9]+n[0-9]+: |mpt[23]sas|megaraid|megasas|hpsa|smartpqi|aacraid|EXT[234]-fs (error|warning)|EXT[234]-fs \(.*(read-only|error)|XFS \(|BTRFS|EDAC|mce:|Machine [Cc]heck|Hardware Error|Memory failure|MCE 0x|temperature above threshold|ritical temperature|AER:|PCIe Bus Error|soft lockup|hard LOCKUP|detected stall|blocked for more than|kernel BUG at|BUG: unable to handle|general protection fault|Oops:|Kernel panic|NMI (received|watchdog)|NMI: |Dazed and confused|Out of memory|oom-kill|[Ll]ink is [Dd]own|Link down|link status definitely down|running without any active interface|NETDEV WATCHDOG|Unit Hang|[Tt][Xx] timeout|ACPI (BIOS )?(Error|Warning|Exception)|Firmware Bug|md/raid|Disk failure'

# Hardware daemons whose journal/syslog lines matter. rasdaemon is left out:
# it can log every traced event (very noisy) and the memory domain reads its
# database with ras-mc-ctl.
_lg_tags='smartd mdadm mdmonitor mcelog ipmievd'
_lg_tagre=' (smartd|mdadm|mdmonitor|mcelog|ipmievd)(\[[0-9]+\])?: '

_lg_tz=$(date +%z 2>/dev/null)
_lg_now=$(date +%s 2>/dev/null)
case "$_lg_now" in '' | *[!0-9]*) _lg_now=0 ;; esac
_lg_since=""
if [ "$_lg_now" -gt 0 ]; then
	_lg_since=$(date -d "@$((_lg_now - DW_SINCE_DAYS * 86400))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
fi
[ -n "$_lg_since" ] || _lg_since="-${DW_SINCE_DAYS}d"
_lg_max=$((DW_MAXLINES + 1))

# Is there a usable journal with kernel messages? (Every boot has some.)
_lg_jr=0
if dw_has journalctl; then
	if [ -n "$($DW_TO journalctl -k -b -n 1 -q --no-pager 2>/dev/null)" ]; then _lg_jr=1; fi
fi
# Persistent journal: /var/log/journal exists (Storage=auto) — otherwise the
# journal only holds the current boot.
_lg_persist=0
[ -d /var/log/journal ] && _lg_persist=1

# _lg_logfiles BASE... — rotated, uncompressed syslog files modified within
# the window, for the first BASE that has any.
_lg_logfiles() {
	for _lg_b in "$@"; do
		_lg_l=$(find /var/log -maxdepth 1 -type f \( -name "$_lg_b" -o -name "$_lg_b.[0-9]" -o -name "$_lg_b-[0-9]*" \) ! -name '*.gz' ! -name '*.xz' ! -name '*.bz2' ! -name '*.zst' -mtime "-$((DW_SINCE_DAYS + 1))" 2>/dev/null)
		if [ -n "$_lg_l" ]; then
			echo "$_lg_l"
			return 0
		fi
	done
	return 0
}

# _lg_mtime FILE — modification time in epoch seconds (for year inference).
_lg_mtime() {
	stat -c %Y "$1" 2>/dev/null || date -r "$1" +%s 2>/dev/null || echo 0
}

# _lg_grepfiles PATTERN-KIND FILES — kernel (k) or daemon (d) lines.
_lg_grepfiles() {
	_lg_kind=$1
	shift
	for _lg_f in "$@"; do
		[ -r "$_lg_f" ] || { echo "cannot read $_lg_f" >&2; continue; }
		echo "# source=syslog file=$_lg_f mtime=$(_lg_mtime "$_lg_f") tz=$_lg_tz"
		if [ "$_lg_kind" = k ]; then
			$DW_TO grep -h ' kernel: ' "$_lg_f" | grep -E "$_lg_re" | tail -n "$DW_MAXLINES"
		else
			$DW_TO grep -h -E "$_lg_tagre" "$_lg_f" | grep -v -E 'Temperature_Cel(sius)? changed' | tail -n "$DW_MAXLINES"
		fi
	done
}

_lg_uptime() { cut -d. -f1 /proc/uptime 2>/dev/null || echo 0; }

# _lg_dmesg all|warn — kernel ring buffer (current boot only).
_lg_dmesg() {
	if [ "$1" = warn ] && $DW_TO dmesg -T --level=emerg,alert,crit,err,warn >"$DW_T/lg" 2>/dev/null; then
		echo "# source=dmesg-T tz=$_lg_tz"
		tail -n "$DW_MAXLINES" "$DW_T/lg"
	elif [ "$1" = all ] && $DW_TO dmesg -T >"$DW_T/lg" 2>/dev/null; then
		echo "# source=dmesg-T tz=$_lg_tz"
		grep -E "$_lg_re" "$DW_T/lg" | tail -n "$DW_MAXLINES"
	elif $DW_TO dmesg >"$DW_T/lg" 2>"$DW_T/lge"; then
		echo "# source=dmesg boot=$((_lg_now - $(_lg_uptime))) tz=$_lg_tz"
		if [ "$1" = all ]; then
			grep -E "$_lg_re" "$DW_T/lg" | tail -n "$DW_MAXLINES"
		else
			tail -n "$DW_MAXLINES" "$DW_T/lg"
		fi
	else
		cat "$DW_T/lge" >&2
		rm -f "$DW_T/lg" "$DW_T/lge"
		return 1
	fi
	rm -f "$DW_T/lg" "$DW_T/lge"
	return 0
}

_lg_kernel() {
	if [ "$_lg_jr" = 1 ]; then
		echo "# source=journal persistent=$_lg_persist tz=$_lg_tz"
		{
			$DW_TO journalctl _TRANSPORT=kernel --since "$_lg_since" -p warning -o short-iso --no-pager -q
			echo "# rc=$?"
		} | tail -n "$_lg_max"
		return 0
	fi
	if dw_has dmesg; then
		_lg_dmesg warn
		return $?
	fi
	echo "no journal and no dmesg" >&2
	return 127
}

_lg_match() {
	_lg_ok=1
	if [ "$_lg_jr" = 1 ]; then
		echo "# source=journal persistent=$_lg_persist tz=$_lg_tz"
		{
			$DW_TO journalctl _TRANSPORT=kernel --since "$_lg_since" -o short-iso --no-pager -q
			echo "# rc=$?"
		} | grep -E -e "$_lg_re" -e '^# rc=' | tail -n "$_lg_max"
		_lg_ok=0
	elif dw_has dmesg; then
		_lg_dmesg all && _lg_ok=0
	fi
	# Previous boots from syslog files when the journal cannot provide them.
	if [ "$_lg_jr" != 1 ] || [ "$_lg_persist" != 1 ]; then
		# shellcheck disable=SC2046
		set -- $(_lg_logfiles kern.log messages syslog)
		if [ $# -gt 0 ]; then
			_lg_grepfiles k "$@"
			_lg_ok=0
		fi
	fi
	return "$_lg_ok"
}

_lg_units() {
	_lg_ok=1
	if [ "$_lg_jr" = 1 ]; then
		set --
		for _lg_t in $_lg_tags; do set -- "$@" -t "$_lg_t"; done
		echo "# source=journal persistent=$_lg_persist tz=$_lg_tz"
		{
			$DW_TO journalctl --since "$_lg_since" -o short-iso --no-pager -q "$@"
			echo "# rc=$?"
		} | grep -v -E 'Temperature_Cel(sius)? changed' | tail -n "$_lg_max"
		_lg_ok=0
	fi
	if [ "$_lg_jr" != 1 ] || [ "$_lg_persist" != 1 ]; then
		# shellcheck disable=SC2046
		set -- $(_lg_logfiles messages syslog)
		if [ $# -gt 0 ]; then
			_lg_grepfiles d "$@"
			_lg_ok=0
		fi
	fi
	return "$_lg_ok"
}

# logs.boots: the boot list plus the last lines of each recent previous boot
# (clean shutdowns end with systemd-shutdown / "Journal stopped").
_lg_boots() {
	echo "# persistent=$_lg_persist tz=$_lg_tz"
	echo "#list"
	$DW_TO journalctl --list-boots --no-pager >"$DW_T/lgb"
	_lg_rc=$?
	cat "$DW_T/lgb"
	if dw_has awk; then
		for _lg_i in $(awk '$1 ~ /^-[0-9]+$/ && $1 >= -10 { print $1 }' "$DW_T/lgb"); do
			echo "#boot $_lg_i"
			$DW_TO journalctl -b "$_lg_i" -n 20 -o short-iso --no-pager -q
		done
	fi
	rm -f "$DW_T/lgb"
	return "$_lg_rc"
}

# logs.last: wtmp boot/shutdown records ("crash" = no clean shutdown).
_lg_last() {
	for _lg_v in "-x -F reboot shutdown" "-x reboot shutdown" "reboot"; do
		# shellcheck disable=SC2086
		if $DW_TO last $_lg_v >"$DW_T/lgl" 2>"$DW_T/lgle" && [ -s "$DW_T/lgl" ]; then
			echo "# args=$_lg_v tz=$_lg_tz now=$_lg_now"
			head -n "$DW_MAXLINES" "$DW_T/lgl"
			rm -f "$DW_T/lgl" "$DW_T/lgle"
			return 0
		fi
	done
	cat "$DW_T/lgle" >&2
	rm -f "$DW_T/lgl" "$DW_T/lgle"
	return 1
}

_lg_wtmpdb() {
	if $DW_TO wtmpdb last -x -F >"$DW_T/lgl" 2>"$DW_T/lgle" && [ -s "$DW_T/lgl" ]; then
		echo "# args=wtmpdb -x -F tz=$_lg_tz now=$_lg_now"
		head -n "$DW_MAXLINES" "$DW_T/lgl"
		rm -f "$DW_T/lgl" "$DW_T/lgle"
		return 0
	fi
	cat "$DW_T/lgle" >&2
	rm -f "$DW_T/lgl" "$DW_T/lgle"
	return 1
}

# logs.kdump: kernel crash dumps (RHEL kdump: /var/crash/<ip>-<date>/vmcore,
# Debian/Ubuntu/Proxmox kdump-tools: /var/crash/<stamp>/dump.<stamp>).
#   f <mtime> <size> <path>        one line per dump file
#   p <path><TAB><line>            panic reason lines from recent dmesg files
_lg_kdump() {
	echo "# now=$_lg_now root=$DW_ROOT"
	for _lg_d in /var/crash /var/lib/kdump; do
		[ -d "$_lg_d" ] || continue
		echo "d $_lg_d"
		find "$_lg_d" -maxdepth 3 -type f \( -name 'vmcore*' -o -name 'dump.[0-9]*' -o -name 'dmesg.[0-9]*' \) 2>/dev/null | head -n 200 |
			while IFS= read -r _lg_f; do
				printf 'f %s %s %s\n' "$(stat -c %Y "$_lg_f" 2>/dev/null || echo 0)" "$(stat -c %s "$_lg_f" 2>/dev/null || echo 0)" "$_lg_f"
			done
		find "$_lg_d" -maxdepth 3 -type f \( -name 'vmcore-dmesg*' -o -name 'dmesg.[0-9]*' \) -mtime "-$((DW_SINCE_DAYS + 1))" 2>/dev/null | head -n 10 |
			while IFS= read -r _lg_f; do
				grep -E 'Kernel panic|BUG: |Oops|Machine [Cc]heck|Hardware Error|RIP: |soft lockup|hard LOCKUP' "$_lg_f" 2>/dev/null | head -n 6 |
					while IFS= read -r _lg_l; do printf 'p %s\t%s\n' "$_lg_f" "$_lg_l"; done
			done
	done
	return 0
}

if [ -n "$DW_CONTAINER" ]; then
	for _lg_s in kernel kernel_match units boots last kdump; do dw_skip "logs.$_lg_s" container; done
else
	dw_fn logs.kernel _lg_kernel
	dw_fn logs.kernel_match _lg_match
	dw_fn logs.units _lg_units
	if [ "$_lg_jr" = 1 ]; then
		dw_fn logs.boots _lg_boots
	elif dw_has journalctl; then
		dw_skip logs.boots not-applicable
	else
		dw_missing logs.boots journalctl
	fi
	if dw_has last; then
		dw_fn logs.last _lg_last
	elif dw_has wtmpdb; then
		dw_fn logs.last _lg_wtmpdb
	else
		dw_missing logs.last last
	fi
	dw_fn logs.kdump _lg_kdump
fi
