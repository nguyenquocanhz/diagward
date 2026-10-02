# Common helpers for the Linux collector. POSIX sh: must run under dash,
# bash, busybox ash and the sh of old distributions (CentOS 7). No bashisms,
# no `local`, no arrays. Helper globals start with _ ; domain snippets should
# use their own prefix (e.g. _dk_ in the disk snippet) for variables.
#
# Variables set by Go before this file: DW_B (boundary), DW_VERSION,
# DW_SINCE_DAYS, DW_BENCH_DIR, DW_BENCH_MB, DW_MEMTEST, DW_MAXLINES,
# DW_TIMEOUT.

LC_ALL=C
LANG=C
export LC_ALL LANG
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/opt/MegaRAID/storcli:/opt/MegaRAID/perccli:/opt/lsi/storcli:/opt/smartmontools/sbin"
export PATH
umask 077

DW_MAXBYTES=4194304
DW_T=$(mktemp -d 2>/dev/null)
if [ -z "$DW_T" ] || [ ! -d "$DW_T" ]; then
	DW_T="/tmp/diagward.$$"
	mkdir -m 700 "$DW_T" 2>/dev/null || { echo "diagward: cannot create a temporary directory" >&2; exit 3; }
fi
trap 'rm -rf "$DW_T"' EXIT
trap 'rm -rf "$DW_T"; exit 130' INT TERM HUP

# dw_has CMD — is CMD available?
dw_has() { command -v "$1" >/dev/null 2>&1; }

# $DW_TO prefixes commands that might hang (dying disks, wedged BMCs, stale
# mounts). Empty when no usable `timeout` exists.
DW_TO=""
if dw_has timeout; then
	if timeout -k 1 1 true >/dev/null 2>&1; then
		DW_TO="timeout -k 5 $DW_TIMEOUT"
	elif timeout 1 true >/dev/null 2>&1; then
		DW_TO="timeout $DW_TIMEOUT"
	fi
fi

DW_ROOT=0
[ "$(id -u 2>/dev/null)" = "0" ] && DW_ROOT=1

_dw_now() { date +%s 2>/dev/null || echo 0; }

# dw_emit NAME RC START [FLAGS] — print $DW_T/o and $DW_T/e as one section.
dw_emit() {
	_dw_fl=${4:-}
	_dw_ms=$(( ($(_dw_now) - $3) * 1000 ))
	[ "$_dw_ms" -lt 0 ] && _dw_ms=0
	if [ -f "$DW_T/o" ] && [ "$(wc -c <"$DW_T/o" 2>/dev/null || echo 0)" -gt "$DW_MAXBYTES" ]; then
		_dw_fl="${_dw_fl:+$_dw_fl }truncated"
	fi
	printf '==DW:%s:BEGIN %s\n' "$DW_B" "$1"
	[ -f "$DW_T/o" ] && head -c "$DW_MAXBYTES" "$DW_T/o" 2>/dev/null
	printf '\n==DW:%s:ERR\n' "$DW_B"
	[ -f "$DW_T/e" ] && head -c 65536 "$DW_T/e" 2>/dev/null
	printf '\n==DW:%s:END rc=%s ms=%s%s\n' "$DW_B" "$2" "$_dw_ms" "${_dw_fl:+ $_dw_fl}"
	: >"$DW_T/o"
	: >"$DW_T/e"
}

_dw_rcflags() {
	if [ -n "$DW_TO" ] && { [ "$1" = 124 ] || [ "$1" = 137 ]; }; then echo timeout; fi
}

# dw_run NAME CMD [ARGS...] — run one command under the timeout. Records
# missing=CMD when it is not installed.
dw_run() {
	_dw_n=$1
	shift
	if ! dw_has "$1"; then
		dw_missing "$_dw_n" "$1"
		return 127
	fi
	_dw_st=$(_dw_now)
	$DW_TO "$@" >"$DW_T/o" 2>"$DW_T/e" </dev/null
	_dw_rc=$?
	dw_emit "$_dw_n" "$_dw_rc" "$_dw_st" "$(_dw_rcflags "$_dw_rc")"
	return "$_dw_rc"
}

# dw_sh NAME 'SCRIPT' — run a self-contained sh snippet (pipelines, loops)
# under the timeout. The snippet runs in a new sh: helper functions are not
# available inside it, but DW_* variables are (they are exported here).
dw_sh() {
	_dw_n=$1
	_dw_st=$(_dw_now)
	export DW_SINCE_DAYS DW_MAXLINES DW_TIMEOUT DW_ROOT DW_T
	$DW_TO sh -c "$2" >"$DW_T/o" 2>"$DW_T/e" </dev/null
	_dw_rc=$?
	dw_emit "$_dw_n" "$_dw_rc" "$_dw_st" "$(_dw_rcflags "$_dw_rc")"
	return "$_dw_rc"
}

# dw_fn NAME FUNCTION [ARGS...] — run a shell function in a subshell and
# capture it. No overall timeout: the function must prefix risky commands
# with $DW_TO itself.
dw_fn() {
	_dw_n=$1
	shift
	_dw_st=$(_dw_now)
	( "$@" ) >"$DW_T/o" 2>"$DW_T/e" </dev/null
	_dw_rc=$?
	dw_emit "$_dw_n" "$_dw_rc" "$_dw_st"
	return "$_dw_rc"
}

# dw_file NAME PATH — capture a (small) file.
dw_file() {
	if [ -r "$2" ]; then
		_dw_st=$(_dw_now)
		cat "$2" >"$DW_T/o" 2>"$DW_T/e"
		dw_emit "$1" "$?" "$_dw_st"
	else
		dw_missing "$1" "$2"
	fi
}

# dw_sysfs NAME GLOB... — dump small sysfs/procfs files as "path=value"
# lines (first line of each readable regular file).
dw_sysfs() {
	_dw_n=$1
	shift
	_dw_st=$(_dw_now)
	for _dw_g in "$@"; do
		for _dw_f in $_dw_g; do
			[ -f "$_dw_f" ] && [ -r "$_dw_f" ] || continue
			_dw_v=$(head -n 1 "$_dw_f" 2>/dev/null)
			printf '%s=%s\n' "$_dw_f" "$_dw_v"
		done
	done >"$DW_T/o" 2>"$DW_T/e"
	dw_emit "$_dw_n" 0 "$_dw_st"
}

# dw_missing NAME WHAT — record that a tool/file is not present.
dw_missing() {
	: >"$DW_T/o"
	: >"$DW_T/e"
	dw_emit "$1" 127 "$(_dw_now)" "missing=$2"
}

# dw_skip NAME REASON — record that a check was deliberately not run.
# Reasons: not-root, virtual, container, disabled, not-applicable.
dw_skip() {
	: >"$DW_T/o"
	: >"$DW_T/e"
	dw_emit "$1" 0 "$(_dw_now)" "skipped=$2"
}

# ---- meta sections (owned by the framework, read by collect.EnvOf) ----

_dw_ident() {
	echo "hostname=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)"
	echo "fqdn=$(hostname -f 2>/dev/null)"
	echo "uid=$(id -u 2>/dev/null)"
	echo "user=$(id -un 2>/dev/null)"
	echo "kernel=$(uname -r 2>/dev/null)"
	echo "arch=$(uname -m 2>/dev/null)"
	echo "now=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
	echo "uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
	echo "collector=$DW_VERSION"
	echo "shell=$(readlink /proc/$$/exe 2>/dev/null)"
}

_dw_virt() {
	if dw_has systemd-detect-virt; then
		echo "vm=$(systemd-detect-virt --vm 2>/dev/null)"
		echo "container=$(systemd-detect-virt --container 2>/dev/null)"
	fi
	for _dw_k in sys_vendor product_name product_version board_vendor bios_vendor chassis_type; do
		[ -r "/sys/class/dmi/id/$_dw_k" ] && echo "$_dw_k=$(cat "/sys/class/dmi/id/$_dw_k" 2>/dev/null)"
	done
	grep -qi -e microsoft -e wsl /proc/version 2>/dev/null && echo "wsl=1"
	grep -q '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null && echo "hypervisor_flag=1"
	[ -f /.dockerenv ] && echo "dockerenv=1"
	[ -f /run/.containerenv ] && echo "containerenv=1"
	[ -d /proc/vz ] && [ ! -d /proc/bc ] && echo "openvz=1"
	_dw_c=$(tr '\0' '\n' </proc/1/environ 2>/dev/null | sed -n 's/^container=//p' | head -n 1)
	[ -n "$_dw_c" ] && echo "pid1_container=$_dw_c"
	return 0
}

_dw_pm() {
	for _dw_p in dnf yum apt-get zypper apk pacman sudo timeout systemctl journalctl; do
		dw_has "$_dw_p" && echo "$_dw_p=1"
	done
	return 0
}

dw_fn meta.ident _dw_ident
if [ -r /etc/os-release ]; then dw_file meta.osrelease /etc/os-release; else dw_file meta.osrelease /usr/lib/os-release; fi
dw_fn meta.virt _dw_virt
dw_fn meta.pm _dw_pm

# Snippets may read these.
DW_VM=$(dw_has systemd-detect-virt && systemd-detect-virt --vm 2>/dev/null)
[ "$DW_VM" = "none" ] && DW_VM=""
DW_CONTAINER=$(dw_has systemd-detect-virt && systemd-detect-virt --container 2>/dev/null)
[ "$DW_CONTAINER" = "none" ] && DW_CONTAINER=""
if [ -z "$DW_CONTAINER" ]; then
	if [ -f /.dockerenv ]; then DW_CONTAINER=docker
	elif [ -f /run/.containerenv ]; then DW_CONTAINER=podman
	elif [ -d /proc/vz ] && [ ! -d /proc/bc ]; then DW_CONTAINER=openvz
	elif grep -qi -e microsoft -e wsl /proc/version 2>/dev/null; then DW_CONTAINER=wsl
	fi
fi
