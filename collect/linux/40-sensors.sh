# Sensors: temperatures, fans, voltages and power as the OS sees them.
#  * lm-sensors (`sensors -j`, lm-sensors >= 3.5; `sensors -u` when -j is not
#    supported) gives labels and the scaling from sensors.conf;
#  * a raw, dependency-free dump of /sys/class/hwmon is always taken, so the
#    check works on servers without lm-sensors installed;
#  * ACPI thermal zones with their trip points.
# Units in sysfs: millidegree Celsius, millivolt, milliampere, microwatt, RPM.
# Read-only; nothing is loaded or changed (sensors-detect is NOT run).
#
# The sysfs dumps run under the timeout: reading drivetemp asks the drive
# itself (an ATA command that can hang on a dying disk), nvme asks the
# controller, and acpi_power_meter / ACPI thermal zones evaluate firmware
# methods that may wait on the BMC or EC. Drive chips are read last, so a
# hung drive costs only the drive temperatures.
# The alarm globs spell out the digits because POSIX globs have no
# alternation: "temp*_alarm" would also match temp1_crit_alarm and
# "in*_alarm" would match intrusion0_alarm.

if [ -n "$DW_CONTAINER" ]; then
	dw_skip sensors.lmsensors_json container
	dw_skip sensors.hwmon container
	dw_skip sensors.thermal container
else
	if dw_has sensors; then
		# `sensors -j` exits 1 with a usage message on lm-sensors < 3.5
		# (CentOS 7 ships 3.4.0): fall back to the raw text format then,
		# but not after a timeout (-u would hang the same way).
		dw_run sensors.lmsensors_json sensors -j
		_sn_rc=$?
		if [ "$_sn_rc" != 0 ] && [ "$_sn_rc" != 124 ] && [ "$_sn_rc" != 137 ]; then
			dw_run sensors.lmsensors sensors -u
		fi
	else
		dw_missing sensors.lmsensors_json sensors
	fi
	dw_sh sensors.hwmon '
		_d() {
			for f in "$1"/name "$1"/device/model \
				"$1"/temp*_input "$1"/temp*_label "$1"/temp*_max "$1"/temp*_crit \
				"$1"/temp*_emergency "$1"/temp*_max_alarm "$1"/temp*_crit_alarm "$1"/temp*_fault \
				"$1"/temp[0-9]_alarm "$1"/temp[0-9][0-9]_alarm "$1"/temp[0-9][0-9][0-9]_alarm \
				"$1"/fan*_input "$1"/fan*_label "$1"/fan*_min "$1"/fan*_alarm \
				"$1"/in*_input "$1"/in*_label "$1"/in*_min "$1"/in*_max \
				"$1"/in[0-9]_alarm "$1"/in[0-9][0-9]_alarm \
				"$1"/power*_input "$1"/power*_average "$1"/power*_label \
				"$1"/intrusion*_alarm; do
				[ -f "$f" ] && [ -r "$f" ] || continue
				printf "%s=%s\n" "$f" "$(head -n 1 "$f" 2>/dev/null)"
			done
		}
		for pass in other drive; do
			for h in /sys/class/hwmon/hwmon*; do
				[ -d "$h" ] || continue
				n=$(head -n 1 "$h/name" 2>/dev/null)
				case "$n" in
				drivetemp | nvme) [ "$pass" = drive ] && _d "$h" ;;
				*) [ "$pass" = other ] && _d "$h" ;;
				esac
			done
		done
		exit 0'
	dw_sh sensors.thermal '
		for z in /sys/class/thermal/thermal_zone*; do
			[ -d "$z" ] || continue
			for f in "$z"/type "$z"/temp "$z"/trip_point_*_temp "$z"/trip_point_*_type; do
				[ -f "$f" ] && [ -r "$f" ] || continue
				printf "%s=%s\n" "$f" "$(head -n 1 "$f" 2>/dev/null)"
			done
		done
		exit 0'
fi
