package raid

import (
	"regexp"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
)

// DetectedHW is a RAID controller found on the PCI bus (Linux sysfs/lspci)
// or by Windows (Win32_SCSIController), with the CLI that manages it.
type DetectedHW struct {
	Slot   string `json:"slot,omitempty"`
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
	Vendor string `json:"vendor,omitempty"`
	Tool   string `json:"tool"`
}

var perccliSoftRe = regexp.MustCompile(`(?i)PERC S\d`)

// classifyController returns the CLI for a storage controller, or "" when
// it is not a hardware RAID controller Diagward knows (AHCI, HBAs in IT
// mode, virtual controllers, software RAID such as Intel RST or PERC S1x0).
func classifyController(vendor, subvendor, class, driver, name string) string {
	v := strings.ToLower(strings.TrimPrefix(strings.ToLower(vendor), "0x"))
	sv := strings.ToLower(strings.TrimPrefix(strings.ToLower(subvendor), "0x"))
	drv := strings.ToLower(driver)
	n := strings.ToLower(name)
	isRAIDClass := strings.HasPrefix(strings.ToLower(class), "0x0104")
	if perccliSoftRe.MatchString(name) {
		return "" // PERC S110/S130/S140/S150 are software RAID
	}
	switch {
	case strings.HasPrefix(drv, "mpt2sas"), strings.HasPrefix(drv, "mpt3sas"), strings.HasPrefix(drv, "mptsas"), strings.HasPrefix(drv, "lsi_sas"), strings.HasPrefix(drv, "sas2xp"), strings.HasPrefix(drv, "sas3xp"):
		return "" // Fusion-MPT HBAs (IT/IR mode), not MegaRAID
	case strings.Contains(drv, "megaraid") || strings.HasPrefix(drv, "megasas") || strings.HasPrefix(drv, "percsas") ||
		strings.Contains(n, "megaraid") || strings.Contains(n, "perc h") || strings.Contains(n, "perc "),
		v == "1000" && isRAIDClass:
		if sv == "1028" || strings.Contains(n, "perc") || strings.Contains(n, "dell") {
			return "perccli"
		}
		return "storcli"
	case drv == "hpsa" || drv == "cciss" || strings.HasPrefix(drv, "hpcisss") || strings.Contains(n, "smart array"):
		return "ssacli"
	case drv == "smartpqi" || strings.Contains(n, "smartpqi"):
		if sv == "103c" || sv == "1590" || strings.Contains(n, "hpe") || strings.Contains(n, "hp ") {
			return "ssacli"
		}
		return "arcconf"
	case drv == "aacraid" || strings.HasPrefix(drv, "arcsas") || strings.Contains(n, "adaptec") || strings.Contains(n, "smartraid") ||
		(v == "9005" && isRAIDClass):
		return "arcconf"
	}
	return ""
}

func (c *checker) detectControllers() []DetectedHW {
	var out []DetectedHW
	seen := map[string]bool{}
	if s := c.b.Get("raid.pci"); s.Ran() {
		for _, blk := range strings.Split(strings.ReplaceAll(s.Out, "\r", ""), "\n\n") {
			kv := map[string]string{}
			for _, l := range strings.Split(blk, "\n") {
				if k, v, ok := strings.Cut(l, "="); ok {
					kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			if kv["slot"] == "" {
				continue
			}
			name := strings.TrimSpace(stripPCIIDs(kv["lspci_Vendor"]) + " " + stripPCIIDs(kv["lspci_Device"]))
			if sd := stripPCIIDs(kv["lspci_SDevice"]); sd != "" {
				name += " / " + stripPCIIDs(kv["lspci_SVendor"]) + " " + sd
			}
			if name == "" {
				name = "PCI " + kv["vendor"] + ":" + kv["device"]
			}
			tool := classifyController(kv["vendor"], kv["subsystem_vendor"], kv["class"], kv["driver"], name)
			if tool == "" || seen[kv["slot"]] {
				continue
			}
			seen[kv["slot"]] = true
			out = append(out, DetectedHW{Slot: kv["slot"], Name: collapse(name), Driver: kv["driver"], Vendor: kv["vendor"], Tool: tool})
		}
	}
	if s := c.b.Get("raid.win_controllers"); s.Ran() {
		var rows []struct {
			Name         string `json:"Name"`
			Manufacturer string `json:"Manufacturer"`
			DriverName   string `json:"DriverName"`
			PNPDeviceID  string `json:"PNPDeviceID"`
		}
		if collect.DecodeJSON(s.Out, &rows) == nil {
			for _, r := range rows {
				ven, sub := pnpIDs(r.PNPDeviceID)
				tool := classifyController(ven, sub, "", r.DriverName, r.Name)
				if tool == "" || seen[r.PNPDeviceID] {
					continue
				}
				seen[r.PNPDeviceID] = true
				out = append(out, DetectedHW{Slot: r.PNPDeviceID, Name: collapse(r.Name), Driver: r.DriverName, Vendor: ven, Tool: tool})
			}
		}
	}
	return out
}

var pciIDSuffix = regexp.MustCompile(`\s*\[[0-9a-fA-F]{4}\]\s*$`)

func stripPCIIDs(s string) string { return strings.TrimSpace(pciIDSuffix.ReplaceAllString(s, "")) }

// pnpIDs extracts the PCI vendor and subsystem vendor from a Windows PnP
// device ID ("PCI\VEN_1000&DEV_005D&SUBSYS_1F471028&REV_02\...").
func pnpIDs(id string) (vendor, subvendor string) {
	up := strings.ToUpper(id)
	if i := strings.Index(up, "VEN_"); i >= 0 && len(up) >= i+8 {
		vendor = up[i+4 : i+8]
	}
	if i := strings.Index(up, "SUBSYS_"); i >= 0 && len(up) >= i+15 {
		subvendor = up[i+11 : i+15]
	}
	return strings.ToLower(vendor), strings.ToLower(subvendor)
}
