package redfish

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// HostInfo identifies a server read through its BMC: from the Redfish
// System / Manager resources, or for IPMI-only bundles from the ipmi.fru,
// ipmi.mc and ipmi.lan sections. It never panics on odd input.
func HostInfo(b *collect.Bundle) (h model.HostInfo) {
	defer func() {
		if recover() != nil {
			h = model.HostInfo{}
			if b != nil {
				h.Hostname = b.Host
			}
		}
	}()
	if b == nil {
		return h
	}
	h.Hostname = b.Host
	meta := b.Get("meta.bmc").KV()
	addr := first(meta["address"], b.Host)

	s := newStore(b)
	if root, _, _ := s.get("/redfish/v1"); root != nil {
		w := &walker{s: s, f: &Facts{}, areas: map[string]*area{}}
		sysColl, _, _ := s.get(link(root, "Systems"))
		for _, sys := range s.members(nil, sysColl) {
			w.systemIdentity(sys, &h)
			break
		}
		chColl, _, _ := s.get(link(root, "Chassis"))
		for _, ch := range s.members(nil, chColl) {
			if h.Serial == "" {
				h.Serial = str(ch, "SerialNumber")
			}
			if h.Board == "" {
				h.Board = first(str(ch, "Model"), str(ch, "PartNumber"))
			}
			break
		}
		mColl, _, _ := s.get(link(root, "Managers"))
		for _, m := range s.members(nil, mColl) {
			mdl, fw := first(str(m, "Model"), str(m, "Name")), str(m, "FirmwareVersion")
			if mdl != "" && strings.HasPrefix(fw, mdl) {
				mdl = "" // iLO: "iLO 5" + "iLO 5 v2.72"
			}
			bmc := strings.TrimSpace(mdl + " " + fw)
			h.BMC = joinNonEmpty(bmc, addr)
			break
		}
		if h.BMC == "" {
			h.BMC = addr
		}
		h.OS = "Redfish " + first(str(root, "RedfishVersion"), "?") + " (out-of-band)"
		return h
	}

	// IPMI-only bundle.
	fru := colonKV(b.Get("ipmi.fru").Text(), true)
	mc := colonKV(b.Get("ipmi.mc").Text(), false)
	lan := colonKV(b.Get("ipmi.lan").Text(), false)
	h.Vendor = first(fru["Product Manufacturer"], fru["Board Mfg"], meta["manufacturer"])
	h.Model = first(fru["Product Name"], fru["Board Product"], meta["model"])
	h.Serial = first(fru["Product Serial"], fru["Chassis Serial"], fru["Board Serial"], meta["serial"])
	h.Board = fru["Board Product"]
	ip := lan["IP Address"]
	if ip == "0.0.0.0" {
		ip = ""
	}
	if fw := first(mc["Firmware Revision"], meta["firmware"]); fw != "" {
		h.BMC = joinNonEmpty(strings.TrimSpace(first(mc["Manufacturer Name"], meta["vendor"])+" BMC "+fw), first(ip, addr))
	} else if ip != "" || addr != "" {
		h.BMC = first(ip, addr)
	}
	if h.Vendor != "" || h.Model != "" || h.BMC != "" {
		h.OS = "IPMI (out-of-band)"
	}
	return h
}

func (w *walker) systemIdentity(sys map[string]any, h *model.HostInfo) {
	if n := str(sys, "HostName"); n != "" {
		h.Hostname = n
	}
	h.Vendor = str(sys, "Manufacturer")
	h.Model = str(sys, "Model")
	h.Serial = str(sys, "SerialNumber")
	// Dell's service tag (what Dell support asks for) is the SKU.
	if sku := str(sys, "SKU"); sku != "" && strings.Contains(strings.ToLower(h.Vendor), "dell") {
		h.Serial = sku
	}
	h.BIOS = str(sys, "BiosVersion")
	if n := num(sys, "ProcessorSummary", "Count"); n != nil && *n > 0 && *n < 1024 {
		cpu := str(sys, "ProcessorSummary", "Model")
		if cpu != "" {
			h.CPU = fmt.Sprintf("%d × %s", int(*n), cpu)
		} else {
			h.CPU = fmt.Sprintf("%d CPU", int(*n))
		}
	}
	if g := num(sys, "MemorySummary", "TotalSystemMemoryGiB"); g != nil && *g > 0 && *g < 1<<24 {
		h.MemBytes = uint64(*g * (1 << 30))
	}
}

func joinNonEmpty(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " (" + b + ")"
}

// colonKV parses ipmitool "Key : value" lines; with firstBlock only the
// first paragraph (FRU device 0, the system board) is read.
func colonKV(s string, firstBlock bool) map[string]string {
	m := map[string]string{}
	seen := false
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			if firstBlock && seen {
				break
			}
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		seen = true
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, dup := m[k]; !dup && k != "" {
			m[k] = v
		}
	}
	return m
}
