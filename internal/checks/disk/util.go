package disk

import (
	"fmt"
	"sort"
	"strings"
)

// clean trims whitespace (lsblk pads VENDOR to 8 characters, SCSI INQUIRY
// strings are space padded) and drops placeholder values.
func clean(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	switch strings.ToLower(s) {
	case "null", "n/a", "none", "unknown", "-":
		return ""
	}
	return s
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func firstInt(ps ...*int) *int {
	for _, p := range ps {
		if p != nil {
			return p
		}
	}
	return nil
}

func derefU(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func sortStrings(s []string) { sort.Strings(s) }

// normSerial makes serial numbers comparable across sources: lsblk, smartctl
// and Windows print the same serial with different padding, case and
// separators (Windows appends "." to NVMe EUI-64 based serials).
func normSerial(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimRight(s, ".")
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '_' || r == '-' || r == '.' {
			return -1
		}
		return r
	}, s)
}

// nvmeController maps a namespace block device to its controller node, the
// name smartctl uses: /dev/nvme0n1 -> /dev/nvme0.
func nvmeController(path string) string {
	if !strings.HasPrefix(path, "/dev/nvme") {
		return path
	}
	rest := strings.TrimPrefix(path, "/dev/nvme")
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return path
	}
	return "/dev/nvme" + rest[:i]
}

// sizeText formats a capacity the way disk vendors label it.
func sizeText(b uint64) string {
	if b == 0 {
		return ""
	}
	return siBytes(b)
}

func siBytes(b uint64) string {
	v := float64(b)
	units := []string{"B", "kB", "MB", "GB", "TB", "PB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	switch {
	case i == 0 || v >= 100:
		return fmt.Sprintf("%.0f %s", v, units[i])
	case v >= 10:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + " " + units[i]
	default:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".") + " " + units[i]
	}
}

// vendorFromModel guesses the manufacturer from an ATA/NVMe model string,
// which has no separate vendor field (ATA IDENTIFY only carries the model).
func vendorFromModel(model string) string {
	m := strings.ToUpper(strings.TrimSpace(model))
	pfx := []struct{ p, v string }{
		{"WDC ", "Western Digital"}, {"WD ", "Western Digital"}, {"WESTERN DIGITAL", "Western Digital"},
		{"WUH7", "Western Digital"}, {"WUS7", "Western Digital"},
		{"HGST", "HGST (Western Digital)"}, {"HITACHI", "Hitachi"}, {"HUS7", "HGST (Western Digital)"}, {"HUH7", "HGST (Western Digital)"},
		{"SEAGATE", "Seagate"}, {"TOSHIBA", "Toshiba"}, {"KIOXIA", "Kioxia"},
		{"SAMSUNG", "Samsung"}, {"MZ7", "Samsung"}, {"MZQ", "Samsung"}, {"MZP", "Samsung"}, {"MZW", "Samsung"}, {"MZV", "Samsung"},
		{"INTEL", "Intel"}, {"SOLIDIGM", "Solidigm"}, {"MICRON", "Micron"}, {"MTFD", "Micron"}, {"CRUCIAL", "Crucial"},
		{"KINGSTON", "Kingston"}, {"SANDISK", "SanDisk"}, {"SK HYNIX", "SK hynix"}, {"HYNIX", "SK hynix"},
		{"HFS", "SK hynix"}, {"HFM", "SK hynix"}, {"SABRENT", "Sabrent"}, {"CORSAIR", "Corsair"}, {"FORCE MP", "Corsair"},
		{"ADATA", "ADATA"}, {"TRANSCEND", "Transcend"}, {"TS", "Transcend"}, {"LITEON", "Lite-On"}, {"LITE-ON", "Lite-On"},
		{"DELL", "Dell"}, {"HPE", "HPE"}, {"HP ", "HP"}, {"LENOVO", "Lenovo"}, {"APPLE", "Apple"},
		{"FUJITSU", "Fujitsu"}, {"MAXTOR", "Maxtor"}, {"PHISON", "Phison"}, {"VMWARE", "VMware"}, {"QEMU", "QEMU"},
	}
	for _, x := range pfx {
		if strings.HasPrefix(m, x.p) {
			return x.v
		}
	}
	// Seagate models: ST + digits (ST4000NM0035, ST3500418AS).
	if len(m) > 3 && strings.HasPrefix(m, "ST") && m[2] >= '0' && m[2] <= '9' {
		return "Seagate"
	}
	// Crucial: CT + digits (CT500MX500SSD1).
	if len(m) > 3 && strings.HasPrefix(m, "CT") && m[2] >= '0' && m[2] <= '9' {
		return "Crucial"
	}
	return ""
}

// pciVendors maps common NVMe PCI vendor IDs (PCI-SIG registry).
var pciVendors = map[int]string{
	0x144d: "Samsung", 0x8086: "Intel", 0x1344: "Micron", 0x15b7: "SanDisk / Western Digital",
	0x1c5c: "SK hynix", 0x1e0f: "Kioxia", 0x1179: "Toshiba", 0x2646: "Kingston", 0x1987: "Phison",
	0x126f: "Silicon Motion", 0x1b4b: "Marvell", 0x1cc1: "ADATA", 0x1d79: "Transcend", 0x025e: "Solidigm",
	0x1bb1: "Seagate", 0x1c58: "HGST (Western Digital)", 0x1b96: "Western Digital", 0xc0a9: "Crucial (Micron)",
}

// virtualModel recognises disks presented by a hypervisor.
func virtualModel(vendor, model string) bool {
	s := strings.ToLower(vendor + " " + model)
	for _, k := range []string{"qemu", "vmware", "virtual disk", "virtual_disk", "vbox", "virtio", "xen", "msft",
		"red hat", "google persistentdisk", "amazon elastic block store", "nutanix", "hyper-v", "parallels"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// raidVolume recognises a logical drive presented by a hardware RAID
// controller (the physical disks are hidden behind it). Vendors in this list
// only appear as the INQUIRY vendor of logical volumes; products are the
// strings Dell PERC, Broadcom/LSI MegaRAID, HPE Smart Array, Intel RAID
// modules, Adaptec and Lenovo ServeRAID report for their volumes.
func raidVolume(vendor, product string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	switch v {
	case "lsi", "avago", "broadcom", "adaptec", "megaraid":
		return true
	}
	p := strings.ToLower(vendor + " " + product)
	for _, k := range []string{"perc ", "perc_", "logical volume", "raid", "megaraid", "serveraid", "smart array",
		"mr9", "rs3dc", "rs3mc", "rs3sc", "rs3wc", "rs3uc", "rms3", "smc3108", "smc2208", "asr8", "asr7", "asr6"} {
		if strings.Contains(p, k) {
			return true
		}
	}
	return strings.HasSuffix(p, " perc")
}

// passthroughType reports whether a smartctl -d type addresses a physical
// disk behind a RAID controller (megaraid,N, sat+megaraid,N, cciss,N,
// aacraid,H,L,ID, areca,N, 3ware,N, hpt,L/M/N).
func passthroughType(t string) bool {
	t = strings.ToLower(t)
	for _, k := range []string{"megaraid,", "cciss,", "aacraid,", "areca,", "3ware,", "hpt,", "sssraid,"} {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}

// sanVolume recognises a LUN from a SAN/iSCSI storage array (or a software
// target). Its physical disks live in the array, not in this server; smartctl
// cannot see them. Vendor strings are the SCSI INQUIRY vendors of common
// arrays (EMC/Dell, NetApp, HPE 3PAR/Nimble, Pure, IBM, Hitachi, Huawei,
// Linux LIO/IET targets, Synology/QNAP/TrueNAS iSCSI).
func sanVolume(vendor, model, tran string) bool {
	switch strings.ToLower(strings.TrimSpace(tran)) {
	case "iscsi", "fc":
		return true
	}
	v := strings.ToLower(strings.TrimSpace(vendor))
	switch v {
	case "dgc", "emc", "netapp", "3pardata", "pure", "nimble", "lio-org", "iet", "huawei", "compelnt",
		"synology", "qnap", "truenas", "freenas", "fujitsu eternus", "hpe nimble":
		return true
	}
	m := strings.ToLower(model)
	return (v == "ibm" && (strings.HasPrefix(m, "2145") || strings.HasPrefix(m, "2107") || strings.HasPrefix(m, "1814"))) ||
		(v == "hitachi" && strings.HasPrefix(m, "open-"))
}
