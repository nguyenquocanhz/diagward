# CPU: inventory (lscpu, /proc/cpuinfo, dmidecode type 4), online/offline
# CPUs, thermal throttle counters, machine-check history (rasdaemon, mcelog).
# Owner: cpu/memory domain. Variables use the _cp_ prefix.

# lscpu: JSON on util-linux >= 2.31 (RHEL 8+, Ubuntu 18.04+); plain text on
# older systems (CentOS 7 ships 2.23 without -J).
if dw_has lscpu; then
	if lscpu -J >/dev/null 2>&1; then
		dw_run cpu.lscpu_json lscpu -J
	else
		dw_run cpu.lscpu lscpu
	fi
else
	dw_missing cpu.lscpu lscpu
fi

# /proc/cpuinfo can be hundreds of KB on big servers: keep a summary
# ("<count><TAB>key=value" for the fields that identify the CPUs).
_cp_cpuinfo() {
	awk -F: '
{
	k = $1; sub(/[ \t]+$/, "", k)
	v = substr($0, index($0, ":") + 1); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
	if (k == "processor") { n++; next }
	if (k ~ /^(model name|vendor_id|physical id|microcode|cpu family|model|stepping|cpu cores|siblings|CPU implementer|CPU part|Hardware)$/) c[k "=" v]++
	if (k == "flags" && v ~ /(^| )hypervisor( |$)/) h++
}
END {
	printf "%d\tprocessors\n", n
	if (h) printf "%d\thypervisor\n", h
	for (x in c) printf "%d\t%s\n", c[x], x
}' /proc/cpuinfo
}
if [ -r /proc/cpuinfo ]; then
	dw_fn cpu.cpuinfo _cp_cpuinfo
else
	dw_missing cpu.cpuinfo /proc/cpuinfo
fi

dw_sysfs cpu.sysfs /sys/devices/system/cpu/online /sys/devices/system/cpu/offline \
	/sys/devices/system/cpu/present /sys/devices/system/cpu/possible \
	/sys/devices/system/cpu/smt/control /sys/devices/system/cpu/smt/active

# dmidecode type 4: socket status ("Populated, Disabled By BIOS" = the BIOS
# turned a CPU off after a POST error).
if [ -n "$DW_CONTAINER" ]; then
	dw_skip cpu.dmidecode container
elif [ "$DW_ROOT" != 1 ]; then
	if dw_has dmidecode; then dw_skip cpu.dmidecode not-root; else dw_missing cpu.dmidecode dmidecode; fi
else
	dw_run cpu.dmidecode dmidecode -t processor
fi

# Thermal throttle counters (Intel, x86 therm_throt driver). Package
# counters repeat on every CPU of a package, so keep the package id too.
if [ -n "$DW_CONTAINER" ]; then
	dw_skip cpu.throttle container
else
	dw_sysfs cpu.throttle '/sys/devices/system/cpu/cpu[0-9]*/thermal_throttle/*' \
		'/sys/devices/system/cpu/cpu[0-9]*/topology/physical_package_id'
fi

# Machine-check history. rasdaemon replaced mcelog on RHEL/Alma/Rocky 8+
# and recent Debian/Ubuntu; mcelog only decodes Intel CPUs.
_cp_svc() {
	for _cp_s in rasdaemon mcelog; do
		_cp_a=""
		_cp_e=""
		if dw_has systemctl; then
			_cp_a=$(systemctl is-active "$_cp_s.service" 2>/dev/null)
			_cp_e=$(systemctl is-enabled "$_cp_s.service" 2>/dev/null)
		fi
		_cp_p=0
		if dw_has pgrep; then
			pgrep -x "$_cp_s" >/dev/null 2>&1 && _cp_p=1
		else
			for _cp_d in /proc/[0-9]*; do
				[ "$(cat "$_cp_d/comm" 2>/dev/null)" = "$_cp_s" ] && { _cp_p=1; break; }
			done
		fi
		_cp_i=0
		dw_has "$_cp_s" && _cp_i=1
		[ "$_cp_s" = rasdaemon ] && dw_has ras-mc-ctl && _cp_i=1
		echo "$_cp_s.installed=$_cp_i"
		echo "$_cp_s.active=${_cp_a:-unknown}"
		echo "$_cp_s.enabled=${_cp_e:-unknown}"
		echo "$_cp_s.running=$_cp_p"
	done
	return 0
}

# ras-mc-ctl --errors lists every record ever stored. Keep the newest 400
# records of each section and drop the SIGNAL section (process signals that
# rasdaemon 0.8.4+ records: not hardware, and very noisy).
_cp_raserr() {
	$DW_TO ras-mc-ctl $_cp_rasdb --errors >"$DW_T/ras" 2>"$DW_T/rase"
	_cp_rc=$?
	head -c 65536 "$DW_T/rase" >&2
	awk -v max=400 '
function flush(   i, s) {
	if (!skip) {
		s = (n > max) ? n - max : 0
		if (s > 0) print "... " s " older records omitted by diagward"
		for (i = s + 1; i <= n; i++) print buf[i % (max + 1)]
	}
	n = 0
}
/^[A-Za-z][A-Za-z0-9 ]*(events|errors):?$/ || /^No .*errors\.$/ || /^Disk errors$/ {
	flush(); skip = ($0 ~ /^SIGNAL/); if (!skip) print; next
}
/^$/ { flush(); if (!skip) print; skip = 0; next }
{ n++; buf[n % (max + 1)] = $0 }
END { flush() }' "$DW_T/ras"
	rm -f "$DW_T/ras" "$DW_T/rase"
	return "$_cp_rc"
}

if [ -n "$DW_CONTAINER" ]; then
	for _cp_n in cpu.services cpu.ras_status cpu.ras_summary cpu.ras_errors cpu.mcelog_log cpu.mcelog_client; do
		dw_skip "$_cp_n" container
	done
else
	dw_fn cpu.services _cp_svc

	if dw_has ras-mc-ctl; then
		# rasdaemon >= 1.0 rewrote ras-mc-ctl in Python: the database
		# queries moved to a "database" sub-command.
		_cp_rasdb=""
		head -n 1 "$(command -v ras-mc-ctl)" 2>/dev/null | grep -q python && _cp_rasdb=database
		if [ -z "$_cp_rasdb" ]; then
			dw_run cpu.ras_status ras-mc-ctl --status
		else
			dw_skip cpu.ras_status not-applicable
		fi
		if [ "$DW_ROOT" = 1 ]; then
			dw_run cpu.ras_summary ras-mc-ctl $_cp_rasdb --summary
			dw_fn cpu.ras_errors _cp_raserr
		else
			dw_skip cpu.ras_summary not-root
			dw_skip cpu.ras_errors not-root
		fi
	else
		dw_missing cpu.ras_status ras-mc-ctl
		dw_missing cpu.ras_summary ras-mc-ctl
		dw_missing cpu.ras_errors ras-mc-ctl
	fi

	if [ -f /var/log/mcelog ]; then
		if [ -r /var/log/mcelog ]; then
			dw_sh cpu.mcelog_log 'tail -n "$DW_MAXLINES" /var/log/mcelog'
		else
			dw_skip cpu.mcelog_log not-root
		fi
	else
		dw_missing cpu.mcelog_log /var/log/mcelog
	fi

	if dw_has mcelog; then
		_cp_run=0
		if dw_has pgrep; then pgrep -x mcelog >/dev/null 2>&1 && _cp_run=1; fi
		if [ "$_cp_run" = 1 ]; then
			if [ "$DW_ROOT" = 1 ]; then
				dw_run cpu.mcelog_client mcelog --client
			else
				dw_skip cpu.mcelog_client not-root
			fi
		else
			dw_skip cpu.mcelog_client not-applicable
		fi
	else
		dw_missing cpu.mcelog_client mcelog
	fi
fi
