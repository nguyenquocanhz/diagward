# ---- network: physical NICs, link state, error counters, bonds, addresses.
# Owner: system domain. Prefix: _nw_
# A NIC is "physical" when /sys/class/net/<if>/device exists (PCI, VMBus,
# virtio...). Bonds, bridges and VLANs are listed in the topology so the
# analysis knows which ports carry an IP address.

_nw_phys=""
for _nw_d in /sys/class/net/*; do
	[ -e "$_nw_d/device" ] || continue
	_nw_phys="$_nw_phys ${_nw_d##*/}"
done

# One line per interface: name, kind, master (bond/bridge) and lower devices.
_nw_topo() {
	for _nw_d in /sys/class/net/*; do
		[ -d "$_nw_d" ] || continue
		_nw_i=${_nw_d##*/}
		[ "$_nw_i" = lo ] && continue
		_nw_k=virtual
		if [ -d "$_nw_d/wireless" ] || [ -L "$_nw_d/phy80211" ]; then
			_nw_k=wireless
		elif [ -e "$_nw_d/device" ]; then
			_nw_k=phys
		elif [ -d "$_nw_d/bonding" ]; then
			_nw_k=bond
		elif [ -d "$_nw_d/bridge" ]; then
			_nw_k=bridge
		elif [ -f "/proc/net/vlan/$_nw_i" ]; then
			_nw_k=vlan
		fi
		_nw_m=""
		if [ -L "$_nw_d/master" ]; then
			_nw_m=$(readlink "$_nw_d/master" 2>/dev/null)
			_nw_m=${_nw_m##*/}
		fi
		_nw_lo=""
		for _nw_l in "$_nw_d"/lower_*; do
			[ -L "$_nw_l" ] || continue
			_nw_lo="$_nw_lo${_nw_lo:+,}${_nw_l##*/lower_}"
		done
		_nw_drv=""
		if [ -L "$_nw_d/device/driver" ]; then
			_nw_drv=$(readlink "$_nw_d/device/driver" 2>/dev/null)
			_nw_drv=${_nw_drv##*/}
		fi
		echo "if=$_nw_i kind=$_nw_k master=$_nw_m lower=$_nw_lo driver=$_nw_drv"
	done
	return 0
}
dw_fn network.topology _nw_topo

_nw_stats() {
	set --
	for _nw_i in $_nw_phys; do
		_nw_p=/sys/class/net/$_nw_i
		set -- "$@" "$_nw_p/operstate" "$_nw_p/carrier" "$_nw_p/speed" "$_nw_p/duplex" \
			"$_nw_p/mtu" "$_nw_p/address" "$_nw_p/carrier_changes" "$_nw_p/carrier_down_count" \
			"$_nw_p/statistics/*"
	done
	dw_sysfs network.sysfs "$@"
}
if [ -n "$_nw_phys" ]; then
	_nw_stats
fi

if [ -n "$_nw_phys" ]; then
	if [ -n "$DW_CONTAINER" ]; then
		dw_skip network.ethtool container
	elif dw_has ethtool; then
		for _nw_i in $_nw_phys; do
			dw_run "network.ethtool:$_nw_i" ethtool "$_nw_i"
			dw_run "network.ethtool_i:$_nw_i" ethtool -i "$_nw_i"
		done
	else
		dw_missing network.ethtool ethtool
	fi
fi

for _nw_f in /proc/net/bonding/*; do
	[ -f "$_nw_f" ] || continue
	dw_file "network.bonding:${_nw_f##*/}" "$_nw_f"
done

# iproute2 older than 4.13 (CentOS 7) has no -j: fall back to one-line text.
if dw_has ip; then
	dw_sh network.ip 'ip -j addr 2>/dev/null || ip -o addr'
else
	dw_missing network.ip ip
fi
