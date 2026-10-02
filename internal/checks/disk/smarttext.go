package disk

import (
	"regexp"
	"strconv"
	"strings"
)

// Text output of smartctl (versions before 7.0 have no JSON, and smartctl
// on some systems is still 6.x: Ubuntu 18.04, Debian 9, CentOS 7 before
// 7.9). The formats parsed here come from smartmontools' ataprint.cpp,
// scsiprint.cpp and nvmeprint.cpp and from the real outputs in testdata/
// (smartctl 5.40 to 7.5, default and --format=brief attribute tables).

var (
	reVersion = regexp.MustCompile(`^smartctl (\d+\.\d+)`)
	// ATA attribute table, default format:
	//   5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
	reAttrDefault = regexp.MustCompile(`^\s*(\d{1,3})\s+(\S+)\s+0x([0-9a-fA-F]{4})\s+(\d+|---)\s+(\d+|---)\s+(\d+|---)\s+(Pre-fail|Old_age)\s+(\S+)\s+(\S+)\s+(.*)$`)
	// --format=brief:
	//   5 Reallocated_Sector_Ct   PO--CK   100   100   010    -    0
	reAttrBrief = regexp.MustCompile(`^\s*(\d{1,3})\s+(\S+)\s+([-POSRCK+]{6,7})\s+(\d+|---)\s+(\d+|---)\s+(\d+|---)\s+(-|NOW|Past)\s+(.*)$`)
	reSelfTest  = regexp.MustCompile(`^#\s*(\d+)\s+(.*?)\s+(\d+)%\s+(\d+)\s+(\S+)`)
	reSCSITest  = regexp.MustCompile(`^#\s*(\d+)\s+(.*?)\s+(-|\d+)\s+(-|\d+)\s+(\S+)\s*(\[.*\])?\s*$`)
	reNVMeTest  = regexp.MustCompile(`^\s*(\d+)\s+(Short|Extended|Vendor specific)\s+(.*?)\s{2,}(\d+)\s`)
	reErrAt     = regexp.MustCompile(`^Error (\d+)(?: \[\d+\])? (?:occurred )?at disk power-on lifetime: (\d+) hours`)
	reErrDesc   = regexp.MustCompile(`Error: (.*)$`)
	reCounter   = regexp.MustCompile(`^(read|write|verify):\s+(.*\S)\s*$`)
)

// parseSmartText parses `smartctl -x` / `-a` text output. It never fails:
// unknown lines are ignored. ok is false when nothing useful was found.
func parseSmartText(out string) (*smartData, bool) {
	d := &smartData{Format: "text", Exit: -1, RPM: -1}
	useful := false
	section := ""
	var nvme nvmeLog
	nvmeSeen := false
	lastErrDesc := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r ")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if m := reVersion.FindStringSubmatch(t); m != nil && d.Version == "" {
			d.Version = m[1]
			continue
		}
		if p := standbyFromMessage(t); p != "" {
			d.Standby = p
			useful = true
			continue
		}
		switch {
		case strings.HasPrefix(t, "ID# ATTRIBUTE_NAME"):
			section = "attrs"
			continue
		case strings.HasPrefix(t, "SMART Error Log") || strings.HasPrefix(t, "SMART Extended Comprehensive Error Log"):
			section = "errlog"
		case strings.HasPrefix(t, "SMART Self-test log") || strings.HasPrefix(t, "SMART Extended Self-test Log") ||
			strings.HasPrefix(t, "Self-test Log (NVMe") || strings.HasPrefix(t, "SMART Self-test Log"):
			section = "selftest"
		case strings.HasPrefix(t, "Error counter log"):
			section = "counters"
		case strings.HasPrefix(t, "SMART/Health Information"):
			section = "nvme"
		case strings.HasPrefix(t, "==="), strings.HasPrefix(t, "SMART Selective self-test log"),
			strings.HasPrefix(t, "SCT Status Version"), strings.HasPrefix(t, "Device Statistics"):
			section = ""
		}

		if section == "attrs" {
			if a, ok := parseAttrLine(line); ok {
				d.Attrs = append(d.Attrs, a)
				useful = true
				continue
			}
		}
		if section == "selftest" {
			if st, ok := parseSelfTestLine(line); ok {
				d.SelfTests = append(d.SelfTests, st)
				continue
			}
		}
		if section == "counters" {
			if m := reCounter.FindStringSubmatch(t); m != nil {
				f := strings.Fields(m[2])
				if n, ok := digitsUint(f[len(f)-1]); ok {
					if d.Uncorrected == nil {
						d.Uncorrected = map[string]uint64{}
					}
					d.Uncorrected[m[1]] = n
					useful = true
				}
				continue
			}
		}
		if section == "errlog" {
			if m := reErrAt.FindStringSubmatch(t); m != nil {
				h, _ := strconv.ParseUint(m[2], 10, 64)
				if d.ErrLogLastPOH == nil || h > *d.ErrLogLastPOH {
					d.ErrLogLastPOH = &h
				}
				lastErrDesc = true
				continue
			}
			if lastErrDesc {
				if m := reErrDesc.FindStringSubmatch(t); m != nil && len(d.ErrLogDescs) < 5 {
					d.ErrLogDescs = append(d.ErrLogDescs, "Error: "+m[1])
					lastErrDesc = false
				}
			}
		}

		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Model Family":
			d.Family = clean(v)
		case "Device Model", "Model Number":
			d.Model = clean(v)
			useful = true
		case "Product":
			d.Product = clean(v)
			useful = true
		case "Vendor":
			d.Vendor = clean(v)
		case "Serial Number", "Serial number":
			d.Serial = clean(v)
		case "Firmware Version":
			d.Firmware = clean(v)
		case "Revision":
			if d.Firmware == "" {
				d.Firmware = clean(v)
			}
		case "LU WWN Device Id", "Logical Unit id":
			d.WWN = clean(v)
		case "User Capacity", "Total NVM Capacity", "Namespace 1 Size/Capacity":
			if b, ok := capacityBytes(v); ok && d.Bytes == 0 {
				d.Bytes = b
			}
		case "Rotation Rate":
			if strings.Contains(v, "Solid State") {
				d.RPM = 0
			} else if n, ok := leadingUint(v); ok {
				d.RPM = int(n)
			}
		case "Transport protocol":
			d.Transport = clean(v)
			d.Protocol = "SCSI"
		case "SATA Version is":
			d.Transport = "SATA"
		case "SMART support is":
			switch {
			case strings.HasPrefix(v, "Available"):
				d.SmartAvailable = boolp(true)
			case strings.HasPrefix(v, "Unavailable"):
				d.SmartAvailable = boolp(false)
			case strings.HasPrefix(v, "Enabled"):
				d.SmartEnabled = boolp(true)
			case strings.HasPrefix(v, "Disabled"):
				d.SmartEnabled = boolp(false)
			}
		case "SMART overall-health self-assessment test result":
			switch {
			case strings.HasPrefix(v, "PASSED"):
				d.Passed = boolp(true)
			case strings.HasPrefix(v, "FAILED"):
				d.Passed = boolp(false)
			}
			useful = true
		case "SMART Health Status":
			if strings.HasPrefix(v, "OK") {
				d.Passed = boolp(true)
			} else {
				d.Passed = boolp(false)
				d.SCSIHealth = v
			}
			if d.Protocol == "" {
				d.Protocol = "SCSI"
			}
			useful = true
		case "Current Drive Temperature":
			d.TempC = intFrom(v)
		case "Drive Trip Temperature":
			d.TempTrip = intFrom(v)
		case "Current Temperature":
			if d.TempC == nil {
				d.TempC = intFrom(v)
			}
		case "Min/Max recommended Temperature":
			if _, mx, ok := strings.Cut(v, "/"); ok {
				d.TempWarn = intFrom(mx)
			}
		case "Min/Max Temperature Limit":
			if _, mx, ok := strings.Cut(v, "/"); ok {
				d.TempCrit = intFrom(mx)
			}
		case "Warning  Comp. Temp. Threshold", "Warning Comp. Temp. Threshold":
			d.TempWarn = intFrom(v)
		case "Critical Comp. Temp. Threshold":
			d.TempCrit = intFrom(v)
		case "Elements in grown defect list":
			if n, ok := digitsUint(v); ok {
				d.GrownDefects = &n
				useful = true
			}
		case "Percentage used endurance indicator":
			d.Endurance, d.EndurSrc = intFrom(v), "scsi endurance indicator"
		case "Accumulated power on time, hours":
			// "Accumulated power on time, hours:minutes 43549:33"
		case "ATA Error Count", "Device Error Count":
			if n, ok := leadingUint(v); ok {
				c := int(n)
				d.ErrLogCount = &c
			}
		}
		if strings.HasPrefix(t, "Accumulated power on time, hours:minutes") {
			f := strings.Fields(t)
			if h, _, ok := strings.Cut(f[len(f)-1], ":"); ok {
				if n, ok := digitsUint(h); ok {
					d.POH = &n
				}
			}
		}
		if section == "nvme" {
			nvmeSeen = true
			useful = true
			switch k {
			case "Critical Warning":
				if n, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 32); err == nil {
					c := int(n)
					nvme.CriticalWarning = &c
				}
			case "Temperature":
				nvme.Temperature = intFrom(v)
			case "Available Spare":
				nvme.AvailableSpare = intFrom(v)
			case "Available Spare Threshold":
				nvme.AvailableSpareThreshold = intFrom(v)
			case "Percentage Used":
				nvme.PercentageUsed = intFrom(v)
			case "Power Cycles":
				nvme.PowerCycles = uintFrom(v)
			case "Power On Hours":
				nvme.PowerOnHours = uintFrom(v)
			case "Unsafe Shutdowns":
				nvme.UnsafeShutdowns = uintFrom(v)
			case "Media and Data Integrity Errors":
				nvme.MediaErrors = uintFrom(v)
			case "Error Information Log Entries":
				nvme.NumErrLogEntries = uintFrom(v)
			case "Warning  Comp. Temperature Time", "Warning Comp. Temperature Time":
				nvme.WarningTempTime = uintFrom(v)
			case "Critical Comp. Temperature Time":
				nvme.CriticalCompTime = uintFrom(v)
			}
		}
		if strings.Contains(t, "No Errors Logged") && d.ErrLogCount == nil {
			z := 0
			d.ErrLogCount = &z
		}
	}
	if strings.Contains(out, "No Errors Logged") && d.ErrLogCount == nil {
		z := 0
		d.ErrLogCount = &z
	}
	if nvmeSeen {
		d.NVMe = &nvme
		d.Protocol = "NVMe"
		if d.TempC == nil {
			d.TempC = nvme.Temperature
		}
		if d.POH == nil {
			d.POH = nvme.PowerOnHours
		}
		if nvme.PercentageUsed != nil && d.Endurance == nil {
			d.Endurance, d.EndurSrc = nvme.PercentageUsed, "nvme percentage_used"
		}
	}
	if len(d.Attrs) > 0 {
		d.Protocol = "ATA"
		if a := d.attr(9); a != nil && d.POH == nil {
			n := a.count()
			d.POH = &n
		}
		if d.TempC == nil {
			for _, id := range []int{194, 190} {
				if a := d.attr(id); a != nil {
					if n, ok := leadingUint(a.RawStr); ok && n > 0 && n < 128 {
						c := int(n)
						d.TempC = &c
						break
					}
				}
			}
		}
	}
	if d.Model == "" && (d.Vendor != "" || d.Product != "") {
		d.Model = strings.TrimSpace(d.Vendor + " " + d.Product)
	}
	if d.Protocol == "" && (d.Vendor != "" || d.Product != "") {
		d.Protocol = "SCSI"
	}
	return d, useful
}

func parseAttrLine(line string) (ataAttr, bool) {
	if m := reAttrDefault.FindStringSubmatch(line); m != nil {
		a := ataAttr{Name: m[2], Prefail: m[7] == "Pre-fail"}
		a.ID, _ = strconv.Atoi(m[1])
		a.Value, a.Worst, a.Thresh = atoip(m[4]), atoip(m[5]), atoip(m[6])
		switch m[9] {
		case "FAILING_NOW":
			a.WhenFailed = "now"
		case "In_the_past":
			a.WhenFailed = "past"
		}
		a.RawStr = strings.TrimSpace(m[10])
		a.Raw, _ = leadingUint(a.RawStr)
		return a, true
	}
	if m := reAttrBrief.FindStringSubmatch(line); m != nil {
		a := ataAttr{Name: m[2], Prefail: strings.HasPrefix(m[3], "P")}
		a.ID, _ = strconv.Atoi(m[1])
		a.Value, a.Worst, a.Thresh = atoip(m[4]), atoip(m[5]), atoip(m[6])
		switch m[7] {
		case "NOW":
			a.WhenFailed = "now"
		case "Past":
			a.WhenFailed = "past"
		}
		a.RawStr = strings.TrimSpace(m[8])
		a.Raw, _ = leadingUint(a.RawStr)
		return a, true
	}
	return ataAttr{}, false
}

// parseSelfTestLine reads one line of an ATA, SCSI or NVMe self-test log.
func parseSelfTestLine(line string) (selfTest, bool) {
	t := strings.TrimSpace(line)
	if m := reSelfTest.FindStringSubmatch(t); m != nil { // ATA
		st := selfTest{Status: m[2], LBA: m[5]}
		st.Hours, _ = strconv.ParseUint(m[4], 10, 64)
		st.Kind, st.Status = splitTestDesc(m[2])
		st.Extended = strings.HasPrefix(strings.ToLower(st.Kind), "extended")
		st.Result = classifyTestStatus(m[2])
		if st.LBA == "-" {
			st.LBA = ""
		}
		return st, true
	}
	if m := reSCSITest.FindStringSubmatch(t); m != nil { // SCSI
		st := selfTest{}
		st.Kind, st.Status = splitTestDesc(m[2])
		st.Hours, _ = strconv.ParseUint(m[4], 10, 64)
		st.Extended = strings.Contains(strings.ToLower(st.Kind), "long") || strings.Contains(strings.ToLower(st.Kind), "extended")
		st.Result = classifyTestStatus(m[2])
		if m[5] != "-" {
			st.LBA = m[5]
		}
		return st, true
	}
	if m := reNVMeTest.FindStringSubmatch(line); m != nil { // NVMe (smartctl >= 7.4)
		st := selfTest{Kind: m[2], Status: strings.TrimSpace(m[3]), Extended: m[2] == "Extended"}
		st.Hours, _ = strconv.ParseUint(m[4], 10, 64)
		st.Result = classifyTestStatus(m[3])
		return st, true
	}
	return selfTest{}, false
}

var testKinds = []string{
	"Short offline", "Extended offline", "Conveyance offline", "Selective offline",
	"Short captive", "Extended captive", "Conveyance captive", "Selective captive",
	"Background short", "Background long", "Foreground short", "Foreground long",
	"Default", "Offline", "Abort offline test",
}

func splitTestDesc(s string) (kind, status string) {
	s = strings.TrimSpace(s)
	for _, k := range testKinds {
		if strings.HasPrefix(s, k) {
			return k, strings.TrimSpace(s[len(k):])
		}
	}
	if f := strings.SplitN(s, "  ", 2); len(f) == 2 {
		return strings.TrimSpace(f[0]), strings.TrimSpace(f[1])
	}
	return "", s
}

// classifyTestStatus maps the status strings smartctl prints for ATA
// (ataprint.cpp), SCSI (scsiprint.cpp self_test_result[]) and NVMe
// (nvmeprint.cpp) self-tests to 0 passed, 1 failed, 2 doubtful, -1 other.
func classifyTestStatus(s string) int {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "read failure"), strings.Contains(l, "electrical failure"),
		strings.Contains(l, "servo"), strings.Contains(l, "unknown failure"),
		strings.Contains(l, "handling damage"), strings.Contains(l, "segment failed"),
		strings.Contains(l, "failed segment"), strings.Contains(l, "failed in"):
		return 1
	case strings.Contains(l, "fatal or unknown"), strings.Contains(l, "unknown error"):
		return 2
	case strings.Contains(l, "without error"), strings.HasSuffix(strings.TrimSpace(l), "completed"),
		strings.Contains(l, "completed "):
		if strings.Contains(l, "aborted") {
			return -1
		}
		return 0
	}
	return -1
}

// capacityBytes reads "500,107,862,016 bytes [500 GB]" (any digit grouping:
// ",", ".", " " or none).
func capacityBytes(v string) (uint64, bool) {
	i := strings.Index(v, "bytes")
	if i < 0 {
		i = strings.Index(v, "[")
		if i < 0 {
			i = len(v)
		}
	}
	return digitsUint(v[:i])
}

// digitsUint parses a number written with any thousands separator
// ("5,809", "5.809", "12 000 138", "0") — smartctl uses the C locale here,
// but saved outputs from other locales exist. Stops at the first other
// character after digits have been seen.
func digitsUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	var n uint64
	seen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			if n > (1<<63)/10 {
				return 0, false
			}
			n = n*10 + uint64(c-'0')
			seen = true
		case (c == ',' || c == '.' || c == ' ' || c == '\'') && seen:
			// thousands separator; a trailing "." (decimal part) is unusual
			// for these counters and ignored.
		default:
			if seen {
				return n, true
			}
			if c != '+' {
				return 0, false
			}
		}
	}
	return n, seen
}

func intFrom(s string) *int {
	s = strings.TrimSpace(s)
	neg := strings.HasPrefix(s, "-")
	n, ok := leadingUint(strings.TrimPrefix(s, "-"))
	if !ok || n > 1<<30 {
		return nil
	}
	v := int(n)
	if neg {
		v = -v
	}
	return &v
}

func uintFrom(s string) *uint64 {
	n, ok := digitsUint(s)
	if !ok {
		return nil
	}
	return &n
}

func atoip(s string) *int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}

func boolp(b bool) *bool { return &b }
