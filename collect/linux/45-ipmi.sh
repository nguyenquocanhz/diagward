# IPMI (in-band): read the server's BMC (iDRAC, iLO, XCC, Supermicro...)
# through the kernel IPMI driver with ipmitool. Read-only commands only; the
# SEL is never cleared here.
#
# The section names below are shared with the out-of-band BMC collector, so
# keep them exactly: ipmi.sdr ipmi.sel_info ipmi.sel_time ipmi.sel ipmi.chassis ipmi.mc
# ipmi.fru ipmi.lan ipmi.power. ipmi.devices is Linux only.

_ip_secs="ipmi.mc ipmi.chassis ipmi.sel_info ipmi.sel_time ipmi.sdr ipmi.sel ipmi.fru ipmi.lan ipmi.power"

_ip_node=""
for _ip_d in /dev/ipmi0 /dev/ipmi/0 /dev/ipmidev/0; do
	if [ -c "$_ip_d" ]; then
		_ip_node=$_ip_d
		break
	fi
done

# ipmi.devices: is there a BMC at all, and is the driver loaded?
#  smbios38=1    SMBIOS type 38 "IPMI Device Information" exists (no root needed)
#  dmi_*         what dmidecode -t 38 says about it (root)
#  module_X      1 = loaded module, builtin = compiled into the kernel
_ip_devices() {
	echo "node=$_ip_node"
	for _ip_d in /dev/ipmi0 /dev/ipmi/0 /dev/ipmidev/0; do
		[ -e "$_ip_d" ] && echo "exists=$_ip_d"
	done
	for _ip_m in ipmi_msghandler ipmi_devintf ipmi_si ipmi_ssif acpi_ipmi; do
		if grep -q "^$_ip_m " /proc/modules 2>/dev/null; then
			echo "module_$_ip_m=1"
		elif [ -d "/sys/module/$_ip_m" ]; then
			echo "module_$_ip_m=builtin"
		fi
	done
	for _ip_d in /sys/class/ipmi/*; do
		[ -e "$_ip_d" ] && echo "class=${_ip_d##*/}"
	done
	[ -d /sys/firmware/dmi/entries/38-0 ] && echo "smbios38=1"
	if [ "$DW_ROOT" = 1 ] && dw_has dmidecode; then
		$DW_TO dmidecode -t 38 2>/dev/null | sed -n \
			-e 's/^[[:space:]]*Interface Type:[[:space:]]*/dmi_interface=/p' \
			-e 's/^[[:space:]]*Specification Version:[[:space:]]*/dmi_spec=/p' \
			-e 's/^[[:space:]]*Base Address:[[:space:]]*/dmi_base=/p' \
			-e 's/^[[:space:]]*I2C Slave Address:[[:space:]]*/dmi_i2c=/p'
	fi
	if dw_has ipmitool; then
		echo "ipmitool=$(command -v ipmitool)"
		echo "ipmitool_version=$(ipmitool -V 2>&1 | head -n 1)"
	fi
	return 0
}

if [ -n "$DW_CONTAINER" ]; then
	dw_skip ipmi.devices container
	for _ip_s in $_ip_secs; do dw_skip "$_ip_s" container; done
else
	dw_fn ipmi.devices _ip_devices
	if ! dw_has ipmitool; then
		for _ip_s in $_ip_secs; do dw_missing "$_ip_s" ipmitool; done
	elif [ "$DW_ROOT" != 1 ]; then
		for _ip_s in $_ip_secs; do dw_skip "$_ip_s" not-root; done
	elif [ -z "$_ip_node" ]; then
		# No /dev/ipmi0: no BMC, or the ipmi_si/ipmi_devintf drivers are not
		# loaded. ipmi.devices tells the analysis which.
		for _ip_s in $_ip_secs; do dw_skip "$_ip_s" not-applicable; done
	else
		dw_run ipmi.mc ipmitool mc info
		_ip_rc=$?
		if [ "$_ip_rc" = 124 ] || [ "$_ip_rc" = 137 ]; then
			# A wedged BMC makes every command wait for the full timeout;
			# do not spend minutes on it.
			for _ip_s in $_ip_secs; do
				[ "$_ip_s" = ipmi.mc ] || dw_skip "$_ip_s" bmc-timeout
			done
		else
			dw_run ipmi.chassis ipmitool chassis status
			dw_run ipmi.sel_info ipmitool sel info
			# The BMC clock: SEL time stamps come from it, so the analysis
			# can tell a wrong clock from old events.
			dw_run ipmi.sel_time ipmitool sel time get
			# SDR, SEL and FRU walk many records one by one: on a busy BMC
			# they can take minutes, so give them four times the timeout.
			_ip_to=$DW_TO
			_IP_SELTO=""
			if [ -n "$DW_TO" ]; then
				_ip_lt=$((DW_TIMEOUT * 4))
				# ipmitool inside the SEL snippet stops 10 s before the
				# snippet is killed, so the entries read so far are kept.
				_ip_in=$((_ip_lt - 10))
				[ "$_ip_in" -lt 5 ] && _ip_in=$_ip_lt
				case "$DW_TO" in
				*-k*) DW_TO="timeout -k 5 $_ip_lt"; _IP_SELTO="timeout -k 5 $_ip_in" ;;
				*) DW_TO="timeout $_ip_lt"; _IP_SELTO="timeout $_ip_in" ;;
				esac
			fi
			export _IP_SELTO
			dw_run ipmi.sdr ipmitool sdr elist
			# Keep the newest $DW_MAXLINES entries (the SEL lists oldest first).
			dw_sh ipmi.sel '
				$_IP_SELTO ipmitool sel elist >"$DW_T/ipmi_sel"
				rc=$?
				n=$(wc -l <"$DW_T/ipmi_sel")
				if [ "$n" -gt "$DW_MAXLINES" ]; then
					echo "diagward: kept the newest $DW_MAXLINES of $n SEL entries" >&2
				fi
				tail -n "$DW_MAXLINES" "$DW_T/ipmi_sel"
				rm -f "$DW_T/ipmi_sel"
				exit $rc'
			dw_run ipmi.fru ipmitool fru print
			DW_TO=$_ip_to
			# The SNMP community string is a credential: never ship it.
			dw_sh ipmi.lan '
				ipmitool lan print >"$DW_T/ipmi_lan"
				rc=$?
				sed "s/^\(SNMP Community String *:\).*/\1 <redacted>/" "$DW_T/ipmi_lan"
				rm -f "$DW_T/ipmi_lan"
				exit $rc'
			dw_run ipmi.power ipmitool dcmi power reading
		fi
	fi
fi
