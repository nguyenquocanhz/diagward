package ipmi

import (
	"regexp"
	"strconv"
	"strings"
)

// BMC is what the OS can learn about its management controller.
type BMC struct {
	Address      string `json:"address,omitempty"` // IPv4 from lan print
	MAC          string `json:"mac,omitempty"`
	IPSource     string `json:"ipSource,omitempty"`
	Subnet       string `json:"subnet,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	VLAN         string `json:"vlan,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
	IPMIVersion  string `json:"ipmiVersion,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Interface    string `json:"interface,omitempty"` // SMBIOS type 38: KCS, SSIF...
	Device       string `json:"device,omitempty"`    // /dev/ipmi0
	Tool         string `json:"tool,omitempty"`      // ipmitool version
}

// IANA enterprise numbers of common server vendors, for "Unknown (0x...)"
// manufacturer names in older ipmitool builds.
var ianaVendors = map[string]string{
	"674": "Dell", "11": "HPE", "47196": "HPE", "10876": "Supermicro", "19046": "Lenovo", "2": "IBM",
	"10368": "Fujitsu", "343": "Intel", "2011": "Huawei", "37945": "Inspur", "7244": "Quanta",
	"40981": "Gigabyte", "15370": "Gigabyte", "49622": "ASRock Rack", "48512": "Inventec", "52538": "xFusion",
}

func parseMC(out string, b *BMC) bool {
	kv := colonKV(out)
	if kv["Firmware Revision"] == "" && kv["IPMI Version"] == "" {
		return false
	}
	b.Firmware = kv["Firmware Revision"]
	b.IPMIVersion = kv["IPMI Version"]
	name := kv["Manufacturer Name"]
	if name == "" || strings.HasPrefix(name, "Unknown") {
		id := strings.TrimSpace(kv["Manufacturer ID"])
		if v, ok := ianaVendors[id]; ok {
			name = v
		} else if id != "" {
			name = "manufacturer ID " + id
		}
	}
	b.Manufacturer = name
	if p := kv["Product Name"]; p != "" && !strings.HasPrefix(p, "Unknown") {
		b.Product = p
	}
	return true
}

func parseLAN(out string, b *BMC) bool {
	kv := colonKV(out)
	if kv["IP Address"] == "" && kv["MAC Address"] == "" {
		return false
	}
	b.Address = kv["IP Address"]
	b.MAC = kv["MAC Address"]
	b.IPSource = kv["IP Address Source"]
	b.Subnet = kv["Subnet Mask"]
	b.Gateway = kv["Default Gateway IP"]
	b.VLAN = kv["802.1q VLAN ID"]
	return true
}

// Chassis is `ipmitool chassis status` (IPMI 2.0 "Get Chassis Status").
type Chassis struct {
	Raw            map[string]string `json:"raw"`
	PowerOn        bool              `json:"powerOn"`
	Overload       bool              `json:"overload,omitempty"`
	Interlock      bool              `json:"interlock,omitempty"`
	MainPowerFault bool              `json:"mainPowerFault,omitempty"`
	ControlFault   bool              `json:"controlFault,omitempty"`
	Intrusion      bool              `json:"intrusion,omitempty"`
	DriveFault     bool              `json:"driveFault,omitempty"`
	CoolingFault   bool              `json:"coolingFault,omitempty"`
	LastPowerEvent string            `json:"lastPowerEvent,omitempty"`
}

func parseChassis(out string) (Chassis, bool) {
	kv := colonKV(out)
	c := Chassis{Raw: kv}
	if _, ok := kv["System Power"]; !ok {
		return c, false
	}
	is := func(k, v string) bool { return strings.EqualFold(strings.TrimSpace(kv[k]), v) }
	c.PowerOn = is("System Power", "on")
	c.Overload = is("Power Overload", "true")
	c.Interlock = is("Power Interlock", "active")
	c.MainPowerFault = is("Main Power Fault", "true")
	c.ControlFault = is("Power Control Fault", "true")
	c.Intrusion = is("Chassis Intrusion", "active")
	c.DriveFault = is("Drive Fault", "true")
	c.CoolingFault = is("Cooling/Fan Fault", "true")
	c.LastPowerEvent = strings.TrimSpace(kv["Last Power Event"])
	return c, true
}

var wattsRe = regexp.MustCompile(`(?i)Instantaneous power reading:\s*([0-9]+(?:\.[0-9]+)?)\s*Watts`)

// parsePower reads `ipmitool dcmi power reading`.
func parsePower(out string) *float64 {
	m := wattsRe.FindStringSubmatch(out)
	if m == nil {
		return nil
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil
	}
	return &v
}

// FRU is one `ipmitool fru print` device.
type FRU struct {
	Description string            `json:"description"`
	ID          int               `json:"id"`
	Fields      map[string]string `json:"fields,omitempty"`
	Absent      bool              `json:"absent,omitempty"`
}

var fruHeadRe = regexp.MustCompile(`^FRU Device Description\s*:\s*(.*?)\s*\(ID\s*([0-9]+)\)\s*$`)

func parseFRU(out string) []*FRU {
	var list []*FRU
	var cur *FRU
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if m := fruHeadRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			id, _ := strconv.Atoi(m[2])
			cur = &FRU{Description: m[1], ID: id, Fields: map[string]string{}}
			list = append(list, cur)
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Device not present") || strings.HasPrefix(t, "Unknown FRU header") {
			cur.Absent = true
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" && v != "" {
			if _, dup := cur.Fields[k]; !dup {
				cur.Fields[k] = v
			}
		}
	}
	return list
}

func (f *FRU) get(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(f.Fields[k]); v != "" {
			return v
		}
	}
	return ""
}

// psuFRUs maps PSU numbers to their FRU records: Dell "PS1 (ID 1)" with
// Board Product "PWR SPLY,750W,RDNT,DELTA", HPE "Power Supply 1",
// Supermicro "PWS-1K28P-SQ" style products.
func psuFRUs(frus []*FRU) map[int]*FRU {
	out := map[int]*FRU{}
	for _, f := range frus {
		if f.Absent {
			continue
		}
		n := psuNumber(f.Description)
		prod := strings.ToLower(f.get("Board Product", "Product Name"))
		isPSU := n > 0 || strings.Contains(prod, "pwr sply") || strings.Contains(prod, "power supply")
		if !isPSU {
			continue
		}
		if n == 0 {
			if m := regexp.MustCompile(`([0-9]+)`).FindString(f.Description); m != "" {
				n, _ = strconv.Atoi(m)
			}
		}
		if n > 0 && out[n] == nil {
			out[n] = f
		}
	}
	return out
}
