package raid

import (
	"regexp"
	"strings"
)

// HPE ssacli / hpssacli / hpacucli: "ctrl all show config detail" and
// "ctrl all show status". The output is an indented outline: a header line
// whose children are indented deeper, and "Key: Value" lines.

var (
	ssaCtrlRe    = regexp.MustCompile(`^(.*\S)\s+in\s+Slot\s+(\S+)(.*)$`)
	ssaArrayRe   = regexp.MustCompile(`(?i)^Array:?\s+(\S+)(?:\s+\(.*\))?$`)
	ssaLDRe      = regexp.MustCompile(`^Logical Drive:\s*(\d+)$`)
	ssaLDSumRe   = regexp.MustCompile(`^logicaldrive\s+(\d+)\s+\((.*)\)$`)
	ssaPDRe      = regexp.MustCompile(`^physicaldrive\s+(\S+)$`)
	ssaPDSumRe   = regexp.MustCompile(`^physicaldrive\s+(\S+)\s+\((.*)\)$`)
	ssaRecoverRe = regexp.MustCompile(`(?i)recovering|rebuilding`)
)

type ssaNode struct {
	indent int
	kind   string // ctrl, array, ld, pd, other
	ctrl   *Controller
	vol    *HWVolume
	drive  *HWDrive
	array  string
}

// ssaLDClass maps HPE logical drive statuses (HPE Smart Array SR Gen10
// User Guide, "Logical drive status").
func ssaLDClass(s string) string {
	l := strings.ToLower(s)
	switch {
	case l == "ok":
		return stOK
	case strings.Contains(l, "interim recovery"), strings.Contains(l, "ready for rebuild"), strings.Contains(l, "degraded"):
		return stDegraded
	case ssaRecoverRe.MatchString(l):
		return stRebuilding
	case strings.Contains(l, "failed"), strings.Contains(l, "offline"), strings.Contains(l, "disabled"):
		return stFailed
	case strings.Contains(l, "expand"), strings.Contains(l, "transform"), strings.Contains(l, "initializ"), strings.Contains(l, "erase"), strings.Contains(l, "queued"):
		return stBusy
	}
	return stUnknown
}

func ssaPDClass(status, driveType string) string {
	l := strings.ToLower(status)
	switch {
	case l == "ok" || l == "":
		dt := strings.ToLower(driveType)
		switch {
		case strings.Contains(dt, "spare"):
			return stSpare
		case strings.Contains(dt, "unassigned"):
			return stUnconfigured
		}
		return stOK
	case strings.Contains(l, "predictive"):
		return stPredictive
	case strings.Contains(l, "rebuild"):
		return stRebuilding
	case strings.Contains(l, "fail"):
		return stFailed
	case strings.Contains(l, "erase"):
		return stBusy
	case l == "spare":
		return stSpare
	}
	return stUnknown
}

func parseSsacli(config, status string) []*Controller {
	var ctrls []*Controller
	byKey := map[string]*Controller{}
	for _, text := range []string{config, status} {
		ls := lines(text)
		var stack []ssaNode
		for i, l := range ls {
			ind := indentOf(l)
			t := strings.TrimSpace(l)
			nextInd := -1
			if i+1 < len(ls) {
				nextInd = indentOf(ls[i+1])
			}
			for len(stack) > 0 && stack[len(stack)-1].indent >= ind {
				stack = stack[:len(stack)-1]
			}
			var top, ld *ssaNode
			var cur *Controller
			array := ""
			if len(stack) > 0 {
				top = &stack[len(stack)-1]
			}
			for j := len(stack) - 1; j >= 0; j-- {
				if cur == nil && stack[j].ctrl != nil {
					cur = stack[j].ctrl
				}
				if array == "" && stack[j].array != "" {
					array = stack[j].array
				}
				if ld == nil && stack[j].vol != nil {
					ld = &stack[j]
				}
			}

			if ind == 0 {
				m := ssaCtrlRe.FindStringSubmatch(t)
				if m == nil {
					continue // "Error: ...", "Note: ...", banners
				}
				key := "Slot " + m[2]
				ct := byKey[key]
				if ct == nil {
					ct = &Controller{Tool: "ssacli", ID: key, Model: strings.TrimSpace(m[1])}
					byKey[key] = ct
					ctrls = append(ctrls, ct)
				}
				stack = append(stack, ssaNode{indent: 0, kind: "ctrl", ctrl: ct})
				continue
			}
			if cur == nil {
				continue
			}
			if m := ssaArrayRe.FindStringSubmatch(t); m != nil {
				stack = append(stack, ssaNode{indent: ind, kind: "array", array: m[1]})
				continue
			}
			if lt := strings.ToLower(t); lt == "unassigned" || lt == "hba drives" || strings.HasPrefix(lt, "unassigned") {
				stack = append(stack, ssaNode{indent: ind, kind: "array", array: "-"})
				continue
			}
			if m := ssaLDRe.FindStringSubmatch(t); m != nil {
				v := ssaVolume(cur, m[1])
				v.Group = array
				stack = append(stack, ssaNode{indent: ind, kind: "ld", vol: v})
				continue
			}
			if m := ssaLDSumRe.FindStringSubmatch(t); m != nil {
				v := ssaVolume(cur, m[1])
				v.Group = firstNonEmpty(v.Group, array)
				parts := strings.Split(m[2], ", ")
				if len(parts) >= 3 {
					v.Size, v.Level = parts[0], parts[1]
					v.State = strings.Join(parts[2:], ", ")
				}
				cur.evidence = append(cur.evidence, t)
				if nextInd > ind {
					stack = append(stack, ssaNode{indent: ind, kind: "ld", vol: v})
				}
				continue
			}
			if m := ssaPDSumRe.FindStringSubmatch(t); m != nil {
				d := cur.drive(m[1])
				parts := strings.Split(m[2], ", ")
				st := parts[len(parts)-1]
				if strings.Contains(strings.ToLower(st), "spare") && len(parts) > 1 {
					d.Group = "spare"
					st = parts[len(parts)-2]
				}
				if d.State == "" {
					d.State = st
				}
				if len(parts) >= 3 {
					d.Location = firstNonEmpty(d.Location, parts[0])
					d.Media = firstNonEmpty(d.Media, parts[1])
					d.Size = firstNonEmpty(d.Size, parts[2])
				}
				if d.Group == "" && array != "" {
					d.Group = array
				}
				if ld != nil {
					ld.vol.Members = uniq(append(ld.vol.Members, m[1]))
				}
				cur.evidence = append(cur.evidence, t)
				continue
			}
			if m := ssaPDRe.FindStringSubmatch(t); m != nil {
				d := cur.drive(m[1])
				if array != "" && d.Group == "" {
					d.Group = array
				}
				stack = append(stack, ssaNode{indent: ind, kind: "pd", drive: d})
				continue
			}
			k, v, ok := splitKV(t)
			if !ok || nextInd > ind {
				// An unrecognised header (enclosure, port, expander...):
				// its keys must not land on the controller.
				stack = append(stack, ssaNode{indent: ind, kind: "other"})
				continue
			}
			switch {
			case top != nil && top.kind == "ctrl":
				switch k {
				case "Controller Status":
					cur.Status = v
					cur.evidence = append(cur.evidence, t)
				case "Cache Status":
					cur.Cache = v
					cur.evidence = append(cur.evidence, t)
				case "Battery/Capacitor Status":
					cur.Battery = v
					cur.evidence = append(cur.evidence, t)
				case "Serial Number":
					cur.Serial = v
				case "Firmware Version":
					cur.Firmware = v
				}
			case top != nil && top.kind == "ld":
				switch k {
				case "Status":
					top.vol.State = v
					cur.evidence = append(cur.evidence, "logicaldrive "+top.vol.ID+" Status: "+v)
				case "Size":
					top.vol.Size = v
				case "Fault Tolerance":
					top.vol.Level = "RAID " + v
				case "Logical Drive Label":
					top.vol.Name = v
				case "Unrecoverable Media Errors":
					if !strings.EqualFold(v, "None") {
						top.vol.Progress = strings.TrimSpace(top.vol.Progress + " unrecoverable media errors: " + v)
					}
				}
			case top != nil && top.kind == "pd":
				d := top.drive
				switch k {
				case "Status":
					d.State = v
					cur.evidence = append(cur.evidence, "physicaldrive "+d.ID+" Status: "+v)
				case "Drive Type":
					if strings.Contains(strings.ToLower(v), "spare") {
						d.Group = "spare"
					} else if strings.Contains(strings.ToLower(v), "unassigned") {
						d.Group = "unassigned"
					}
				case "Serial Number":
					d.Serial = v
				case "Model":
					f := strings.Fields(v)
					if len(f) > 1 {
						d.Vendor, d.Model = f[0], strings.Join(f[1:], " ")
					} else {
						d.Model = v
					}
				case "Firmware Revision":
					d.Firmware = v
				case "Size":
					d.Size = v
				}
			}
		}
	}
	for _, ct := range ctrls {
		for _, v := range ct.Volumes {
			v.Class = ssaLDClass(v.State)
			if v.Class == stRebuilding || v.Class == stDegraded {
				if p := pct(v.State); p >= 0 {
					v.Progress = strings.TrimSpace(fmtPct(p) + " " + v.Progress)
				}
			}
		}
		for _, d := range ct.Drives {
			dt := ""
			switch d.Group {
			case "spare":
				dt = "spare"
			case "unassigned", "-":
				dt = "unassigned"
			}
			d.Class = ssaPDClass(d.State, dt)
			if d.Location == "" {
				d.Location = "Bay " + d.ID
			}
		}
		sortDrives(ct.Drives)
	}
	return ctrls
}

func ssaVolume(ct *Controller, id string) *HWVolume {
	id = "LD " + id
	for _, v := range ct.Volumes {
		if v.ID == id {
			return v
		}
	}
	v := &HWVolume{ID: id}
	ct.Volumes = append(ct.Volumes, v)
	return v
}
