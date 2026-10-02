package redfish

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu/dmi"
	"github.com/nguyenquocanhz/diagward/model"
)

// clean drops the placeholder values BMCs copy from unprogrammed SMBIOS/FRU
// fields ("To be filled by O.E.M.", "Default string", Supermicro's
// "0123456789").
func clean(v string) string {
	v = dmi.Clean(v)
	switch strings.ToLower(v) {
	case "0123456789", "123456789", "system serial number", "system product name", "system manufacturer", "chassis serial number":
		return ""
	}
	return v
}

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
		var chRef string
		for _, sys := range s.members(nil, sysColl) {
			w.systemIdentity(sys, &h)
			if l := links(sys, "Links", "Chassis"); len(l) > 0 {
				chRef = normKey(l[0])
			}
			break
		}
		// The server's own chassis: the one the system links to, else the
		// first rack/tower/blade chassis (not a backplane, GPU tray or
		// enclosure, which Dell and Supermicro also list).
		chColl, _, _ := s.get(link(root, "Chassis"))
		var main map[string]any
		for _, ch := range s.members(nil, chColl) {
			if chRef != "" && normKey(str(ch, "@odata.id")) == chRef {
				main = ch
				break
			}
			switch strings.ToLower(str(ch, "ChassisType")) {
			case "rackmount", "standalone", "blade", "sled", "tower", "desktop", "minitower", "mainframe", "multisystemchassis":
				if main == nil {
					main = ch
				}
			}
		}
		if main != nil {
			if h.Serial == "" {
				h.Serial = clean(str(main, "SerialNumber"))
			}
			if h.Vendor == "" {
				h.Vendor = clean(str(main, "Manufacturer"))
			}
			if h.Board == "" {
				h.Board = clean(first(str(main, "Model"), str(main, "PartNumber")))
			}
		}
		if h.Vendor == "" {
			h.Vendor = str(root, "Vendor") // service root: "Dell", "HPE", "Lenovo"
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
	h.Vendor = first(clean(fru["Product Manufacturer"]), clean(fru["Board Mfg"]), clean(meta["manufacturer"]))
	h.Model = first(clean(fru["Product Name"]), clean(fru["Board Product"]), clean(meta["model"]))
	h.Serial = first(clean(fru["Product Serial"]), clean(fru["Chassis Serial"]), clean(fru["Board Serial"]), clean(meta["serial"]))
	h.Board = clean(fru["Board Product"])
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
	h.Vendor = clean(str(sys, "Manufacturer"))
	h.Model = clean(str(sys, "Model"))
	h.Serial = clean(str(sys, "SerialNumber"))
	// Dell's service tag (what Dell support asks for) is the SKU.
	if sku := clean(str(sys, "SKU")); sku != "" && strings.Contains(strings.ToLower(h.Vendor), "dell") {
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
