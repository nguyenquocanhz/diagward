# Memory: DIMM inventory (dmidecode), usage (/proc/meminfo, PSI, swap),
# ECC error counters (EDAC sysfs) and the opt-in memtester run.
# Owner: cpu/memory domain. Variables use the _mm_ prefix.

if [ -n "$DW_CONTAINER" ]; then
	dw_skip memory.dmidecode container
elif [ "$DW_ROOT" != 1 ]; then
	if dw_has dmidecode; then dw_skip memory.dmidecode not-root; else dw_missing memory.dmidecode dmidecode; fi
else
	dw_run memory.dmidecode dmidecode -t memory
fi

dw_file memory.meminfo /proc/meminfo
dw_file memory.swaps /proc/swaps
# PSI needs kernel >= 4.20 (not on CentOS 7) and may be disabled (psi=0).
dw_file memory.psi /proc/pressure/memory
dw_sh memory.vmstat 'grep -E "^(pswpin|pswpout|pgmajfault|oom_kill) " /proc/vmstat; exit 0'

# EDAC: the kernel's ECC error counters, per memory controller and DIMM.
# Modern drivers expose dimmN/ (or rankN/); old ones only csrowN/.
if [ -n "$DW_CONTAINER" ]; then
	dw_skip memory.edac container
	dw_skip memory.edac_modules container
else
	_mm_e=/sys/devices/system/edac/mc
	dw_sysfs memory.edac \
		"$_mm_e/mc*/mc_name" "$_mm_e/mc*/size_mb" "$_mm_e/mc*/seconds_since_reset" \
		"$_mm_e/mc*/ce_count" "$_mm_e/mc*/ue_count" "$_mm_e/mc*/ce_noinfo_count" "$_mm_e/mc*/ue_noinfo_count" \
		"$_mm_e/mc*/dimm*/dimm_label" "$_mm_e/mc*/dimm*/dimm_location" "$_mm_e/mc*/dimm*/size" \
		"$_mm_e/mc*/dimm*/dimm_mem_type" "$_mm_e/mc*/dimm*/dimm_edac_mode" \
		"$_mm_e/mc*/dimm*/dimm_ce_count" "$_mm_e/mc*/dimm*/dimm_ue_count" \
		"$_mm_e/mc*/rank*/dimm_label" "$_mm_e/mc*/rank*/dimm_location" "$_mm_e/mc*/rank*/size" \
		"$_mm_e/mc*/rank*/dimm_mem_type" "$_mm_e/mc*/rank*/dimm_edac_mode" \
		"$_mm_e/mc*/rank*/dimm_ce_count" "$_mm_e/mc*/rank*/dimm_ue_count" \
		"$_mm_e/mc*/csrow*/ce_count" "$_mm_e/mc*/csrow*/ue_count" "$_mm_e/mc*/csrow*/size_mb" \
		"$_mm_e/mc*/csrow*/mem_type" "$_mm_e/mc*/csrow*/edac_mode" \
		"$_mm_e/mc*/csrow*/ch*_ce_count" "$_mm_e/mc*/csrow*/ch*_dimm_label"
	# Which EDAC drivers are loaded (modules or built-in with parameters).
	dw_sh memory.edac_modules 'for m in /sys/module/*edac*; do [ -e "$m" ] && echo "${m##*/}"; done; exit 0'
	if dw_has edac-util; then
		dw_run memory.edac_util edac-util -v
	fi
fi

# memtester, only when asked for (DW_MEMTEST=size, e.g. 2G). It locks and
# hammers that much RAM for minutes per GB, so refuse when the server does
# not have twice that much available.
_mm_memtest() {
	_mm_bs=$(printf '\010')
	echo "diagward: size=$DW_MEMTEST mb=$_mm_mb timeout=$_mm_secs memavailable_kb=$_mm_av memlock=$_mm_ml root=$DW_ROOT"
	{
		{
			$_mm_tc memtester "$DW_MEMTEST" 1 2>&1 1>&3 3>&-
			echo "$?" >"$DW_T/mt.rc"
		} | awk 'NR <= 50 { print; next } END { if (NR > 50) print "diagward: " NR - 50 " more lines" }' >&2
	} 3>&1 | sed "s/$_mm_bs.*$_mm_bs//" |
		awk '/reducing\.\.\.$/ { r++; if (r > 3) next } { print } END { if (r > 3) print "diagward: mlock retried " r " times" }'
	_mm_rc=$(cat "$DW_T/mt.rc" 2>/dev/null)
	rm -f "$DW_T/mt.rc"
	echo "diagward: rc=${_mm_rc:-unknown}"
	return "${_mm_rc:-1}"
}

if [ -z "$DW_MEMTEST" ]; then
	dw_skip memory.memtest disabled
elif [ -n "$DW_CONTAINER" ]; then
	dw_skip memory.memtest container
elif ! dw_has memtester; then
	dw_missing memory.memtest memtester
else
	# Size in MB (memtester's default unit). Strip leading zeros: "08" is
	# an invalid octal number in shell arithmetic.
	_mm_n=$(echo "${DW_MEMTEST%[KMG]}" | sed 's/^0*//')
	case "$_mm_n" in
	'' | *[!0-9]*) _mm_n=0 ;;
	esac
	case "$DW_MEMTEST" in
	*G) _mm_mb=$((_mm_n * 1024)) ;;
	*K) _mm_mb=$((_mm_n / 1024)) ;;
	*) _mm_mb=$_mm_n ;;
	esac
	_mm_av=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo 2>/dev/null)
	# ulimit -l is not POSIX but dash, bash and busybox ash all have it.
	# shellcheck disable=SC3045
	_mm_ml=$(ulimit -l 2>/dev/null)
	# memtester needs about 10 minutes per GB on a slow core (measured
	# ~4.3 min/GB on a 2-core VM); never less than 15 minutes.
	_mm_secs=$((_mm_mb * 600 / 1024 + 120))
	[ "$_mm_secs" -lt 900 ] && _mm_secs=900
	[ "$_mm_secs" -lt "${DW_TIMEOUT:-30}" ] && _mm_secs=$DW_TIMEOUT
	case "$DW_TO" in
	"timeout -k"*) _mm_tc="timeout -k 10 $_mm_secs" ;;
	timeout*) _mm_tc="timeout $_mm_secs" ;;
	*) _mm_tc="" ;;
	esac
	if [ -z "$_mm_av" ] || [ "$_mm_av" -lt $((_mm_mb * 2048)) ]; then
		dw_skip memory.memtest low-memory
	elif [ "$DW_ROOT" != 1 ] && [ "$_mm_ml" != unlimited ] && [ "${_mm_ml:-0}" -lt $((_mm_mb * 1024)) ]; then
		# Without root, memtester cannot lock more than "ulimit -l" and
		# would shrink the test one page at a time.
		dw_skip memory.memtest not-root
	else
		dw_fn memory.memtest _mm_memtest
	fi
fi
