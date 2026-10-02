# Sensors: temperatures, fans, voltages and power as the OS sees them.
#  * lm-sensors (`sensors -j`, lm-sensors >= 3.5; `sensors -u` when -j is not
#    supported) gives labels and the scaling from sensors.conf;
#  * a raw, dependency-free dump of /sys/class/hwmon is always taken, so the
#    check works on servers without lm-sensors installed;
#  * ACPI thermal zones with their trip points.
# Units in sysfs: millidegree Celsius, millivolt, milliampere, microwatt, RPM.
# Read-only; nothing is loaded or changed (sensors-detect is NOT run).
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
		# (CentOS 7 ships 3.4.0): fall back to the raw text format then.
		if ! dw_run sensors.lmsensors_json sensors -j; then
			dw_run sensors.lmsensors sensors -u
		fi
	else
		dw_missing sensors.lmsensors_json sensors
	fi
	_sn_h=/sys/class/hwmon/hwmon*
	dw_sysfs sensors.hwmon \
		"$_sn_h/name" "$_sn_h/device/model" \
		"$_sn_h/temp*_input" "$_sn_h/temp*_label" "$_sn_h/temp*_max" "$_sn_h/temp*_crit" \
		"$_sn_h/temp*_emergency" "$_sn_h/temp*_max_alarm" "$_sn_h/temp*_crit_alarm" "$_sn_h/temp*_fault" \
		"$_sn_h/temp[0-9]_alarm" "$_sn_h/temp[0-9][0-9]_alarm" "$_sn_h/temp[0-9][0-9][0-9]_alarm" \
		"$_sn_h/fan*_input" "$_sn_h/fan*_label" "$_sn_h/fan*_min" "$_sn_h/fan*_alarm" \
		"$_sn_h/in*_input" "$_sn_h/in*_label" "$_sn_h/in*_min" "$_sn_h/in*_max" \
		"$_sn_h/in[0-9]_alarm" "$_sn_h/in[0-9][0-9]_alarm" \
		"$_sn_h/power*_input" "$_sn_h/power*_average" "$_sn_h/power*_label" \
		"$_sn_h/intrusion*_alarm"
	_sn_t=/sys/class/thermal/thermal_zone*
	dw_sysfs sensors.thermal "$_sn_t/type" "$_sn_t/temp" "$_sn_t/trip_point_*_temp" "$_sn_t/trip_point_*_type"
fi
