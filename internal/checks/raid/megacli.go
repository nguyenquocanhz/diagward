package raid

import (
	"regexp"
	"strings"
)

// Legacy LSI MegaCli: -LDInfo -Lall -aALL, -PDList -aALL (or the combined
// -LDPDInfo) and -AdpBbuCmd -aALL. Plain "Key: Value" text.

var (
	mcAdapterRe = regexp.MustCompile(`(?i)^Adapter\s*#?\s*(\d+)`)
	mcBBUAdRe   = regexp.MustCompile(`(?i)for Adapter:?\s*(\d+)`)
	mcVDRe      = regexp.MustCompile(`^Virtual (?:Drive|Disk):\s*(\d+)`)
	mcLevelRe   = regexp.MustCompile(`Primary-(\d+),\s*Secondary-(\d+)`)
	mcDGRe      = regexp.MustCompile(`DiskGroup:\s*(\d+)`)
)

func mcLDClass(s string) string {
	l := strings.ToLower(s)
	switch {
	case l == "optimal":
		return stOK
	case strings.Contains(l, "degraded"):
		return stDegraded
	case strings.Contains(l, "offline"), strings.Contains(l, "failed"):
		return stFailed
	case strings.Contains(l, "recovery"), strings.Contains(l, "rebuild"):
		return stRebuilding
	}
	return stUnknown
}

// mcPDClass maps "Firmware state" values ("Online, Spun Up",
// "Unconfigured(good), Spun Up", "Hotspare, Spun down", "Failed",
// "Rebuild", "Copyback", "JBOD", "Unconfigured(bad)", "Offline").
func mcPDClass(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.HasPrefix(l, "online"), strings.HasPrefix(l, "jbod"):
		return stOK
	case strings.HasPrefix(l, "hotspare"):
		return stSpare
	case strings.HasPrefix(l, "unconfigured(good)"):
		return stUnconfigured
	case strings.HasPrefix(l, "unconfigured(bad)"), strings.HasPrefix(l, "failed"), strings.HasPrefix(l, "offline"):
		return stFailed
	case strings.HasPrefix(l, "rebuild"):
		return stRebuilding
	case strings.HasPrefix(l, "copyback"):
		return stBusy
	case strings.Contains(l, "missing"):
		return stMissing
	}
	return stUnknown
}

func mcLevel(s string) string {
	m := mcLevelRe.FindStringSubmatch(s)
	if m == nil {
		return s
	}
	p, sec := m[1], m[2]
	if sec == "3" && (p == "1" || p == "5" || p == "6") {
		return "RAID" + p + "0"
	}
	return "RAID" + p
}

// mcInquiry splits MegaCli's "Inquiry Data" into vendor/model/serial/firmware.
// SATA drives print "<serial> <model> <firmware>"; SAS drives print
// "<vendor> <model> <firmware+serial>" (SCSI INQUIRY layout).
func mcInquiry(inq, pdType string) (vendor, model, serial, fw string) {
	f := strings.Fields(inq)
	if len(f) < 2 {
		return "", collapse(inq), "", ""
	}
	if strings.EqualFold(pdType, "SAS") && len(f) >= 3 {
		last := f[len(f)-1]
		vendor, model = f[0], strings.Join(f[1:len(f)-1], " ")
		if len(last) > 4 {
			fw, serial = last[:4], last[4:]
		} else {
			fw = last
		}
		return
	}
	if len(f) >= 3 {
		return "", strings.Join(f[1:len(f)-1], " "), f[0], f[len(f)-1]
	}
	return "", f[1], f[0], ""
}

func parseMegaCli(ld, pd, bbu string) []*Controller {
	byID := map[string]*Controller{}
	var order []*Controller
	get := func(id string) *Controller {
		if ct := byID[id]; ct != nil {
			return ct
		}
		ct := &Controller{Tool: "megacli", ID: id}
		byID[id] = ct
		order = append(order, ct)
		return ct
	}
	for _, text := range []string{ld, pd} {
		var ct *Controller
		var vol *HWVolume
		var d *HWDrive
		encl, pdType, inq := "", "", ""
		flush := func() {
			if d != nil && inq != "" {
				v, m, s, f := mcInquiry(inq, pdType)
				d.Vendor, d.Model, d.Serial, d.Firmware = v, m, s, f
			}
			inq, pdType = "", ""
		}
		for _, l := range lines(text) {
			t := strings.TrimSpace(l)
			if m := mcAdapterRe.FindStringSubmatch(t); m != nil {
				flush()
				ct, vol, d = get(m[1]), nil, nil
				continue
			}
			if ct == nil {
				if strings.HasPrefix(t, "Virtual Drive") || strings.HasPrefix(t, "Enclosure Device ID") {
					ct = get("0")
				} else {
					continue
				}
			}
			if m := mcVDRe.FindStringSubmatch(t); m != nil {
				flush()
				vol = nil
				for _, v := range ct.Volumes {
					if v.ID == "v"+m[1] {
						vol = v
					}
				}
				if vol == nil {
					vol = &HWVolume{ID: "v" + m[1]}
					ct.Volumes = append(ct.Volumes, vol)
				}
				d = nil
				continue
			}
			k, v, ok := splitKV(t)
			if !ok {
				continue
			}
			switch {
			case k == "Enclosure Device ID":
				flush()
				encl, d = v, nil
			case k == "Slot Number":
				id := encl + ":" + v
				if encl == "N/A" || encl == "" {
					id = ":" + v
				}
				d = ct.drive(id)
				if encl != "" && encl != "N/A" {
					d.Location = "Enclosure " + encl + " Slot " + v
				} else {
					d.Location = "Slot " + v
				}
				if vol != nil {
					vol.Members = uniq(append(vol.Members, id))
				}
			case d != nil && k == "Firmware state":
				d.State = v
				ct.evidence = append(ct.evidence, "PD "+d.ID+" Firmware state: "+v)
			case d != nil && k == "Media Error Count":
				d.MediaErr = atoi(v)
			case d != nil && k == "Other Error Count":
				d.OtherErr = atoi(v)
			case d != nil && k == "Predictive Failure Count":
				d.PredFail = atoi(v)
			case d != nil && strings.HasPrefix(k, "Drive has flagged a S.M.A.R.T alert"):
				d.SmartAlert = strings.EqualFold(v, "Yes")
			case d != nil && k == "Inquiry Data":
				inq = v
			case d != nil && k == "PD Type":
				pdType = v
			case d != nil && k == "Raw Size":
				if i := strings.Index(v, "["); i > 0 {
					v = strings.TrimSpace(v[:i])
				}
				d.Size = v
			case d != nil && k == "Drive's position":
				if m := mcDGRe.FindStringSubmatch(v); m != nil {
					d.Group = m[1]
				}
			case d == nil && vol != nil && k == "State":
				vol.State = v
				ct.evidence = append(ct.evidence, "VD "+vol.ID+" State: "+v)
			case d == nil && vol != nil && k == "RAID Level":
				vol.Level = mcLevel(v)
			case d == nil && vol != nil && k == "Size":
				vol.Size = v
			case d == nil && vol != nil && k == "Name":
				vol.Name = v
			}
		}
		flush()
	}
	// BBU.
	var ct *Controller
	for _, l := range lines(bbu) {
		t := strings.TrimSpace(l)
		if m := mcBBUAdRe.FindStringSubmatch(t); m != nil && strings.Contains(strings.ToLower(t), "bbu") {
			ct = byID[m[1]]
			if ct == nil {
				ct = get(m[1])
			}
			continue
		}
		if ct == nil {
			continue
		}
		k, v, ok := splitKV(t)
		if !ok {
			continue
		}
		switch {
		case k == "Battery State":
			ct.Battery = v
			ct.evidence = append(ct.evidence, "Battery State: "+v)
		case k == "BatteryType":
			ct.BatteryModel = v
		case strings.Contains(k, "Replacement required") || strings.Contains(k, "about to fail") || k == "Battery Pack Missing":
			if strings.EqualFold(v, "Yes") {
				ct.BatteryFlags = uniq(append(ct.BatteryFlags, k))
			}
		}
	}
	var out []*Controller
	for _, ct := range order {
		for _, v := range ct.Volumes {
			v.Class = mcLDClass(v.State)
		}
		for _, d := range ct.Drives {
			d.Class = mcPDClass(d.State)
		}
		sortDrives(ct.Drives)
		if len(ct.Volumes)+len(ct.Drives) > 0 || ct.Battery != "" {
			out = append(out, ct)
		}
	}
	return out
}
