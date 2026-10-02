# Final marker: lets the caller tell a complete run from one that was cut off.
_dw_done() { echo "now=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; }
dw_fn meta.done _dw_done
