package raid

import (
	"regexp"
	"strings"
)

// Microchip/Adaptec ARCCONF "GETCONFIG <n> AL". States follow
// thomas-krenn/check_adaptec_raid (the reference Nagios plugin): a logical
// device is fine only when "Optimal"; physical devices are fine when
// Online, Ready, a hot spare, JBOD or raw pass-through.

var (
	arcLDRe  = regexp.MustCompile(`(?i)^Logical (?:Device|drive) number\s+(\d+)`)
	arcPDRe  = regexp.MustCompile(`^Device #(\d+)`)
	arcSegRe = regexp.MustCompile(`(?i)^(?:Group \d+,\s*)?Segment \d+$`)
)

func arcLDClass(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "optimal":
		return stOK
	case strings.Contains(l, "rebuild"), strings.Contains(l, "impacted"), strings.Contains(l, "building"):
		return stRebuilding
	case strings.Contains(l, "degraded"), strings.Contains(l, "suboptimal"):
		return stDegraded
	case strings.Contains(l, "fail"), strings.Contains(l, "offline"):
		return stFailed
	}
	return stUnknown
}

func arcPDClass(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "online", l == "online (jbod)", strings.HasPrefix(l, "raw"), l == "jbod":
		return stOK
	case strings.Contains(l, "hot-spare"), strings.Contains(l, "hot spare"):
		return stSpare
	case l == "ready":
		return stUnconfigured
	case strings.Contains(l, "rebuild"):
		return stRebuilding
	case l == "failed", l == "offline", strings.Contains(l, "fail"):
		return stFailed
	case l == "missing":
		return stMissing
	}
	return stUnknown
}

// parseArcconf parses one controller's GETCONFIG output; nil when it holds
// nothing usable.
func parseArcconf(s, id string) *Controller {
	ct := &Controller{Tool: "arcconf", ID: id}
	sect := ""
	var vol *HWVolume
	var d *HWDrive
	isEnclosure := false
	useful := false
	for _, l := range lines(s) {
		t := strings.TrimSpace(l)
		if strings.Trim(t, "-") == "" {
			continue
		}
		if m := arcLDRe.FindStringSubmatch(t); m != nil {
			vol = &HWVolume{ID: "LD " + m[1]}
			ct.Volumes = append(ct.Volumes, vol)
			sect, d, useful = "ld", nil, true
			continue
		}
		if m := arcPDRe.FindStringSubmatch(t); m != nil {
			d = newDrive("Device #" + m[1])
			isEnclosure = false
			ct.Drives = append(ct.Drives, d)
			sect, vol, useful = "pd", nil, true
			continue
		}
		k, v, ok := strings.Cut(t, " : ")
		if !ok {
			k, v, ok = splitKV(t)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok {
			lt := strings.ToLower(t)
			switch {
			case strings.HasPrefix(lt, "device is a") && d != nil:
				isEnclosure = strings.Contains(lt, "enclosure")
			case strings.Contains(lt, "battery information") || strings.Contains(lt, "zmm information") || strings.Contains(lt, "cache backup unit") || strings.Contains(lt, "supercap"):
				sect = "battery"
			case strings.HasPrefix(lt, "controller information") || strings.HasPrefix(lt, "controller version"):
				sect = "ctrl"
			case strings.HasPrefix(lt, "logical device segment") || strings.HasPrefix(lt, "logical drive segment"):
				if vol != nil {
					sect = "seg"
				}
			case strings.HasPrefix(lt, "physical device information"), strings.HasPrefix(lt, "logical device information"):
				sect = ""
			}
			continue
		}
		switch sect {
		case "ctrl":
			useful = true
			switch k {
			case "Controller Status":
				ct.Status = v
				ct.evidence = append(ct.evidence, t)
			case "Controller Model":
				ct.Model = v
			case "Controller Serial Number":
				ct.Serial = v
			case "Firmware":
				ct.Firmware = v
			case "Defunct disk drive count":
				if n := atoi(v); n > 0 {
					ct.Defunct = n
					ct.evidence = append(ct.evidence, t)
				}
			case "Logical devices/Failed/Degraded":
				ct.evidence = append(ct.evidence, t)
			}
		case "battery":
			if k == "Status" || k == "Overall Backup Unit Status" || k == "Supercap Status" {
				ct.Battery = v
				ct.evidence = append(ct.evidence, "Backup unit status: "+v)
			}
		case "ld", "seg":
			if vol == nil {
				continue
			}
			switch {
			case strings.EqualFold(k, "Status of Logical Device"):
				vol.State = v
				ct.evidence = append(ct.evidence, vol.ID+": "+t)
			case strings.EqualFold(k, "Logical Device name"):
				vol.Name = v
			case k == "RAID level":
				vol.Level = "RAID " + v
			case k == "Size":
				vol.Size = v
			case k == "Failed stripes":
				if !strings.EqualFold(v, "No") {
					vol.Progress = strings.TrimSpace(vol.Progress + " failed stripes: " + v)
				}
			case arcSegRe.MatchString(k) || strings.HasPrefix(k, "Segment") || strings.HasPrefix(k, "Group"):
				f := strings.Fields(v)
				if len(f) > 0 && strings.EqualFold(f[0], "Missing") {
					vol.Missing++
					ct.evidence = append(ct.evidence, vol.ID+" "+t)
				} else if len(f) > 1 {
					vol.Members = append(vol.Members, f[len(f)-1])
				}
			}
		case "pd":
			if d == nil {
				continue
			}
			switch k {
			case "State":
				d.State = v
				ct.evidence = append(ct.evidence, d.ID+" State: "+v)
			case "Reported Location":
				loc := v
				if i := strings.Index(loc, "("); i > 0 {
					loc = strings.TrimSpace(loc[:i])
				}
				d.Location = loc
			case "Vendor":
				d.Vendor = v
			case "Model":
				d.Model = v
			case "Serial number", "Serial Number":
				d.Serial = v
			case "Firmware":
				d.Firmware = v
			case "Total Size":
				d.Size = v
			case "S.M.A.R.T.":
				d.SmartAlert = !strings.EqualFold(v, "No")
			case "S.M.A.R.T. warnings":
				d.SmartWarn = atoi(v)
			case "Failed logical device segments":
				if !strings.EqualFold(v, "False") {
					d.State = firstNonEmpty(d.State, "Failed segments")
					d.Class = stFailed
				}
			}
			if isEnclosure {
				d.State = "enclosure"
			}
		}
	}
	if !useful {
		return nil
	}
	var drives []*HWDrive
	for _, x := range ct.Drives {
		if x.State == "enclosure" || x.State == "" {
			continue
		}
		if x.Class == "" {
			x.Class = arcPDClass(x.State)
		}
		drives = append(drives, x)
	}
	ct.Drives = drives
	for _, v := range ct.Volumes {
		v.Class = arcLDClass(v.State)
		if v.Class == stOK && v.Missing > 0 {
			v.Class = stDegraded
		}
		// Map member serials to drive IDs so the rebuild/degraded logic can
		// link them.
		for i, m := range v.Members {
			for _, x := range ct.Drives {
				if x.Serial != "" && x.Serial == m {
					v.Members[i] = x.ID
				}
			}
		}
	}
	return ct
}
