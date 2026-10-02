# ---- system: identity (DMI/SMBIOS), CPU summary, load, pressure, clock,
# kernel taint, pending reboot. Owner: system domain. Prefix: _sy_
# Everything here only reads; nothing is changed.

# SMBIOS via dmidecode needs root (it reads /sys/firmware/dmi/tables or
# /dev/mem). Without root, the world-readable /sys/class/dmi/id fields below
# still give vendor/model/BIOS (but not the serial number).
if [ -n "$DW_CONTAINER" ]; then
	dw_skip system.dmidecode container
elif [ "$DW_ROOT" != 1 ]; then
	dw_skip system.dmidecode not-root
else
	dw_run system.dmidecode dmidecode -t system -t bios -t baseboard -t chassis
fi
if [ -d /sys/class/dmi/id ]; then
	dw_sysfs system.dmi '/sys/class/dmi/id/*'
else
	dw_missing system.dmi /sys/class/dmi/id
fi

# hostnamectl and timedatectl talk to systemd-hostnamed / systemd-timedated
# over D-Bus, which starts those services when they are not running. The
# collector must not start services, so they are used only when already up.
_sy_active() { dw_has systemctl && $DW_TO systemctl is-active --quiet "$1" 2>/dev/null; }

if dw_has hostnamectl && [ -z "$DW_CONTAINER" ] && _sy_active systemd-hostnamed; then
	dw_run system.hostnamectl hostnamectl status
fi

dw_file system.uptime /proc/uptime
dw_file system.loadavg /proc/loadavg
if dw_has nproc; then
	dw_run system.nproc nproc
else
	dw_sh system.nproc 'grep -c "^processor" /proc/cpuinfo'
fi
# A light CPU summary (the cpu domain does the deep checks).
dw_sh system.cpuinfo 'grep -E "^(processor|vendor_id|model name|physical id|core id|cpu cores|siblings|Hardware|CPU implementer|CPU part|cpu model|Processor)[[:space:]]*:" /proc/cpuinfo'
dw_sh system.meminfo 'grep -E "^(MemTotal|MemAvailable|SwapTotal|SwapFree):" /proc/meminfo'

# Pressure stall information (kernel >= 4.20; RHEL 8 needs psi=1 on the
# kernel command line, so it is often absent there).
_sy_psi() {
	_sy_rc=1
	for _sy_r in cpu io memory; do
		[ -r "/proc/pressure/$_sy_r" ] || continue
		sed "s/^/$_sy_r /" "/proc/pressure/$_sy_r" && _sy_rc=0
	done
	return $_sy_rc
}
if [ -d /proc/pressure ]; then
	dw_fn system.pressure _sy_psi
else
	dw_missing system.pressure /proc/pressure
fi

# Two /proc/stat samples one second apart: iowait and steal percentages.
dw_sh system.stat 'grep -E "^(cpu |btime|procs_running|procs_blocked)" /proc/stat; sleep 1; grep "^cpu " /proc/stat'

dw_file system.tainted /proc/sys/kernel/tainted

_sy_timesync() {
	if [ -e /run/systemd/timesync/synchronized ]; then echo "synchronized=yes"; else echo "synchronized=no"; fi
	echo "timesyncd_active=$( (_sy_active systemd-timesyncd && echo yes) || echo no)"
}
if dw_has timedatectl && [ -z "$DW_CONTAINER" ] && _sy_active systemd-timedated; then
	dw_run system.timedatectl timedatectl status
elif dw_has chronyc && [ -z "$DW_CONTAINER" ]; then
	dw_run system.chrony chronyc -n tracking
elif [ -z "$DW_CONTAINER" ] && [ -d /run/systemd/timesync ]; then
	# systemd-timesyncd (systemd >= 239) touches this file once synchronised.
	dw_fn system.timesync _sy_timesync
fi

_sy_reboot() {
	for _sy_f in /var/run/reboot-required /run/reboot-required; do
		if [ -f "$_sy_f" ]; then
			echo "reboot_required=$_sy_f"
			break
		fi
	done
	if [ -r /var/run/reboot-required.pkgs ]; then
		sed -n 's/^/pkg=/p' /var/run/reboot-required.pkgs | head -n 20
	fi
	return 0
}
if [ -z "$DW_CONTAINER" ]; then
	dw_fn system.reboot _sy_reboot
	# RHEL family: needs-restarting -r exits 1 when a reboot is needed.
	if dw_has needs-restarting; then
		dw_run system.needs_restarting needs-restarting -r
	fi
fi
