// Package dmi parses the text output of dmidecode (any version since 2.x)
// into records. The cpu domain reads type 4 (processors) and the memory
// domain types 16 (memory arrays) and 17 (memory devices).
package dmi

import (
	"strconv"
	"strings"
)

// Record is one SMBIOS structure as dmidecode prints it.
type Record struct {
	Handle string
	Type   int
	Title  string            // "Memory Device"
	Fields map[string]string // "Locator" -> "A1" (values trimmed)
	Lists  map[string][]string
}

// Get returns a field value ("" when absent).
func (r Record) Get(k string) string { return r.Fields[k] }

// Parse splits dmidecode output into records. Unknown lines are ignored,
// so truncated or garbled output yields the records that are complete
// enough to have a "Handle" line.
func Parse(s string) []Record {
	var (
		out     []Record
		cur     *Record
		lastKey string
	)
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "Handle 0x") {
			flush()
			cur = &Record{Type: -1, Fields: map[string]string{}, Lists: map[string][]string{}}
			parts := strings.Split(line, ",")
			cur.Handle = strings.TrimSpace(strings.TrimPrefix(parts[0], "Handle "))
			if len(parts) > 1 {
				t := strings.TrimSpace(parts[1])
				if strings.HasPrefix(t, "DMI type ") {
					if n, err := strconv.Atoi(strings.TrimPrefix(t, "DMI type ")); err == nil {
						cur.Type = n
					}
				}
			}
			lastKey = ""
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case strings.HasPrefix(line, "\t\t"):
			if lastKey != "" {
				cur.Lists[lastKey] = append(cur.Lists[lastKey], strings.TrimSpace(line))
			}
		case strings.HasPrefix(line, "\t"):
			k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			cur.Fields[k] = strings.TrimSpace(v)
			lastKey = k
		default:
			if cur.Title == "" {
				cur.Title = strings.TrimSpace(line)
			}
		}
	}
	flush()
	return out
}

// OfType returns the records of SMBIOS type t.
func OfType(recs []Record, t int) []Record {
	var out []Record
	for _, r := range recs {
		if r.Type == t {
			out = append(out, r)
		}
	}
	return out
}

// placeholders are values vendors put in SMBIOS strings when they have
// nothing to say. Compared case-insensitively.
var placeholders = map[string]bool{
	"": true, "not specified": true, "unknown": true, "not provided": true, "none": true,
	"--": true, "n/a": true, "na": true, "no dimm": true, "not available": true, "to be filled by o.e.m.": true,
	"default string": true, "0000000000": true, "00000000": true, "serial number": true, "part number": true,
	"manufacturer": true, "asset tag": true, "not installed": true, "empty": true, "unknown manufacturer": true,
	"ffffffff": true, "<bad index>": true, "<out of spec>": true, "undefined": true, "dimm_manufacturer": true,
}

// Clean returns v without padding, or "" when v is a placeholder.
func Clean(v string) string {
	v = strings.TrimSpace(v)
	if placeholders[strings.ToLower(v)] {
		return ""
	}
	if strings.Trim(v, "0 ") == "" || strings.Trim(strings.ToUpper(v), "F ") == "" {
		return ""
	}
	return v
}

// Size parses a dmidecode size ("16 GB", "8192 MB", "512 kB", "2 TB").
// It returns ok=false for "No Module Installed", "Unknown" and garbage.
func Size(v string) (uint64, bool) {
	f := strings.Fields(v)
	if len(f) != 2 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	switch strings.ToLower(f[1]) {
	case "bytes", "b":
		return n, true
	case "kb", "kib":
		return n << 10, true
	case "mb", "mib":
		return n << 20, true
	case "gb", "gib":
		return n << 30, true
	case "tb", "tib":
		return n << 40, true
	}
	return 0, false
}

// Speed parses "2933 MT/s" or "1333 MHz" (older dmidecode) into MT/s; 0 if
// unknown.
func Speed(v string) int {
	f := strings.Fields(v)
	if len(f) < 1 {
		return 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// NoTable reports output in which dmidecode found no SMBIOS table (VMs
// without SMBIOS, WSL, some ARM boards).
func NoTable(s string) bool {
	return strings.Contains(s, "No SMBIOS nor DMI entry point found")
}

// jedec maps JEDEC JEP106 manufacturer codes, as some BIOSes print them in
// the Manufacturer field (e.g. "00AD00B300AD" = SK Hynix), to names. Only
// the common DRAM makers; the code is kept when unknown.
var jedec = map[string]string{
	"00ad": "SK Hynix", "80ad": "SK Hynix", "ad00": "SK Hynix",
	"00ce": "Samsung", "80ce": "Samsung", "ce00": "Samsung",
	"002c": "Micron", "802c": "Micron", "2c00": "Micron",
	"0198": "Kingston", "8198": "Kingston", "9801": "Kingston",
	"04cb": "A-DATA", "84cb": "A-DATA",
	"059b": "Crucial", "859b": "Crucial", "9b05": "Crucial",
	"02fe": "Elpida", "82fe": "Elpida",
	"00c1": "Infineon", "80c1": "Infineon",
	"0551": "Qimonda", "8551": "Qimonda",
	"04f1": "Toshiba", "830b": "Nanya", "030b": "Nanya", "0b03": "Nanya",
	"8a76": "Lexar", "0a76": "Lexar",
	"0783": "Transcend", "8783": "Transcend",
	"04cd": "G.Skill", "84cd": "G.Skill",
	"029e": "Corsair", "829e": "Corsair",
	"0443": "Ramaxel", "8443": "Ramaxel",
	"0b2c": "Smart Modular", "0194": "Smart Modular", "8194": "Smart Modular",
	"0e7a": "Netlist", "8a45": "CXMT", "0a45": "CXMT",
}

// Vendor returns a readable DRAM vendor: decoded JEDEC codes, cleaned
// placeholders.
func Vendor(v string) string {
	v = Clean(v)
	if v == "" {
		return ""
	}
	h := strings.ToLower(strings.ReplaceAll(v, " ", ""))
	if isHex(h) && len(h) >= 4 {
		if n, ok := jedec[h[:4]]; ok {
			return n
		}
	}
	return v
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}
