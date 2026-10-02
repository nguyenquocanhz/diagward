package raid

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Broadcom StorCLI and Dell PERCCLI print the same JSON ("J" suffix). The
// document is {"Controllers":[{"Command Status":{...},"Response Data":...}]}
// and values may be strings or numbers depending on the field and version.

type scEntry struct {
	status map[string]any
	data   any
}

func parseStorcliJSON(s string) []scEntry {
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return nil
	}
	var doc struct {
		Controllers []map[string]json.RawMessage `json:"Controllers"`
	}
	if json.NewDecoder(strings.NewReader(s[i:])).Decode(&doc) != nil {
		return nil
	}
	var out []scEntry
	for _, c := range doc.Controllers {
		var e scEntry
		if raw, ok := c["Command Status"]; ok {
			_ = json.Unmarshal(raw, &e.status)
		}
		if raw, ok := c["Response Data"]; ok {
			_ = json.Unmarshal(raw, &e.data)
		}
		out = append(out, e)
	}
	return out
}

// str renders a JSON scalar as a trimmed string.
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func num(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		return atoi(x)
	}
	return -1
}

func obj(v any, keys ...string) map[string]any {
	for _, k := range keys {
		m, _ := v.(map[string]any)
		if m == nil {
			return nil
		}
		v = m[k]
	}
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []map[string]any {
	a, _ := v.([]any)
	var out []map[string]any
	for _, x := range a {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func (e scEntry) ctrlID() string {
	if id := str(e.status["Controller"]); id != "" {
		return id
	}
	return str(obj(e.data, "Basics")["Controller"])
}

func (e scEntry) failed() (bool, string) {
	st := strings.ToLower(str(e.status["Status"]))
	if st == "" || st == "success" {
		return false, ""
	}
	return true, str(e.status["Description"])
}

// storcliVDClass: Optl=Optimal, Pdgd=Partially Degraded, Dgrd=Degraded,
// OfLn=OffLine, Rec=Recovery, Cac=CacheCade (StorCLI legend).
func storcliVDClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "optl", "optimal", "cac":
		return stOK
	case "pdgd", "dgrd", "degraded", "partially degraded":
		return stDegraded
	case "ofln", "offln", "offline", "failed":
		return stFailed
	case "rec", "rbld":
		return stRebuilding
	}
	return stUnknown
}

// storcliPDClass: Onln=Online, UGood/UBad=Unconfigured Good/Bad,
// Offln=Offline, Rbld=Rebuild, Cpybck=Copyback, GHS/DHS=Global/Dedicated
// Hot Spare, Msng=Missing, UGShld/HSPShld/CFShld=shielded (diagnostics after
// errors), UGUnsp=unsupported (StorCLI legend).
func storcliPDClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "onln", "online", "jbod":
		return stOK
	case "ghs", "dhs":
		return stSpare
	case "ugood":
		return stUnconfigured
	case "rbld":
		return stRebuilding
	case "cpybck", "sntze":
		return stBusy
	case "ubad", "offln", "failed", "f":
		return stFailed
	case "msng":
		return stMissing
	}
	return stUnknown
}

var scDrivePathRe = regexp.MustCompile(`^/c(\d+)(?:/e(\d+))?/s(\d+)$`)

// scDriveKey turns "/c0/e252/s3" into ("0", "252:3").
func scDriveKey(path string) (ctrl, key string, ok bool) {
	m := scDrivePathRe.FindStringSubmatch(strings.TrimSpace(path))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2] + ":" + m[3], true
}

func normEIDSlt(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), " ", "") }

func (c *checker) parseStorcliFamily(tool, prefix string) ([]*Controller, []string) {
	var errs []string
	byID := map[string]*Controller{}
	var order []*Controller
	get := func(id string) *Controller {
		if ct := byID[id]; ct != nil {
			return ct
		}
		ct := &Controller{Tool: tool, ID: id}
		byID[id] = ct
		order = append(order, ct)
		return ct
	}

	ctrlSec := c.b.Get(prefix + "ctrl")
	entries := parseStorcliJSON(ctrlSec.Text())
	if ctrlSec.Ran() && len(entries) == 0 && strings.TrimSpace(ctrlSec.Out+ctrlSec.Err) != "" {
		errs = append(errs, tool+": "+errText(ctrlSec))
	}
	for _, e := range entries {
		if bad, why := e.failed(); bad {
			if why != "" && !strings.Contains(strings.ToLower(why), "not found") {
				errs = append(errs, tool+" /c"+e.ctrlID()+": "+why)
			}
			continue
		}
		rd, _ := e.data.(map[string]any)
		if rd == nil {
			continue
		}
		if n := num(rd["Number of Controllers"]); n == 0 {
			continue
		}
		ct := get(e.ctrlID())
		basics := obj(rd, "Basics")
		ct.Model = firstNonEmpty(str(basics["Model"]), str(rd["Product Name"]))
		ct.Serial = firstNonEmpty(str(basics["Serial Number"]), str(rd["Serial Number"]))
		ver := obj(rd, "Version")
		ct.Firmware = firstNonEmpty(str(ver["Firmware Package Build"]), str(ver["Firmware Version"]), str(rd["FW Package Build"]), str(rd["FW Version"]))
		st := obj(rd, "Status")
		ct.Status = firstNonEmpty(str(st["Controller Status"]), str(rd["Controller Status"]))
		if n := num(st["Memory Uncorrectable Errors"]); n > 0 {
			ct.MemUncorr = n
		}
		if n := num(st["Memory Correctable Errors"]); n > 0 {
			ct.MemCorr = n
		}
		ct.evidence = append(ct.evidence, "Controller Status: "+ct.Status)
		for _, v := range arr(rd["VD LIST"]) {
			dgvd := str(v["DG/VD"])
			vol := &HWVolume{ID: "v" + afterSlash(dgvd), Group: beforeSlash(dgvd), Level: str(v["TYPE"]), Size: str(v["Size"]), State: str(v["State"]), Name: str(v["Name"])}
			vol.Class = storcliVDClass(vol.State)
			ct.Volumes = append(ct.Volumes, vol)
			ct.evidence = append(ct.evidence, "VD "+dgvd+" "+vol.Level+" "+vol.State+" "+vol.Size)
		}
		for _, p := range arr(rd["PD LIST"]) {
			c.storcliPDRow(ct, p, true)
		}
		for _, b := range arr(rd["BBU_Info"]) {
			ct.BatteryModel, ct.Battery = str(b["Model"]), str(b["State"])
		}
		for _, b := range arr(rd["Cachevault_Info"]) {
			ct.BatteryModel, ct.Battery = str(b["Model"]), str(b["State"])
		}
		if ct.Battery != "" {
			ct.evidence = append(ct.evidence, "Battery "+ct.BatteryModel+": "+ct.Battery)
		}
	}

	// Virtual drive membership (/call/vall show all J).
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "vd")) {
		rd, _ := e.data.(map[string]any)
		ct := byID[e.ctrlID()]
		if rd == nil || ct == nil {
			continue
		}
		for k, v := range rd {
			if !strings.HasPrefix(k, "PDs for VD ") {
				continue
			}
			vid := "v" + strings.TrimSpace(strings.TrimPrefix(k, "PDs for VD "))
			for _, vol := range ct.Volumes {
				if vol.ID != vid {
					continue
				}
				for _, p := range arr(v) {
					vol.Members = append(vol.Members, normEIDSlt(str(p["EID:Slt"])))
				}
			}
		}
	}

	// Drive details (/call/eall/sall show all J).
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "pd")) {
		rd, _ := e.data.(map[string]any)
		if rd == nil {
			continue
		}
		if bad, _ := e.failed(); bad && len(rd) == 0 {
			continue
		}
		for _, k := range sortedKeys(rd) {
			if !strings.HasPrefix(k, "Drive /c") {
				continue
			}
			path := strings.TrimPrefix(k, "Drive ")
			detailed := strings.HasSuffix(path, " - Detailed Information")
			path = strings.TrimSuffix(path, " - Detailed Information")
			cid, key, ok := scDriveKey(path)
			if !ok {
				continue
			}
			ct := byID[cid]
			if ct == nil {
				ct = get(cid)
			}
			if !detailed {
				for _, p := range arr(rd[k]) {
					c.storcliPDRow(ct, p, false)
				}
				continue
			}
			d := ct.drive(key)
			det := obj(rd, k)
			for dk, dv := range det {
				m, _ := dv.(map[string]any)
				switch {
				case strings.HasSuffix(dk, " State"):
					d.MediaErr = num(m["Media Error Count"])
					d.OtherErr = num(m["Other Error Count"])
					d.PredFail = num(m["Predictive Failure Count"])
					d.SmartAlert = strings.EqualFold(str(m["S.M.A.R.T alert flagged by drive"]), "Yes")
				case strings.HasSuffix(dk, " Device attributes"):
					d.Serial = collapse(str(m["SN"]))
					if mn := collapse(str(m["Model Number"])); mn != "" {
						d.Model = mn
					}
					d.Vendor = collapse(str(m["Manufacturer Id"]))
					d.Firmware = collapse(str(m["Firmware Revision"]))
				}
			}
		}
	}

	// Rebuild progress (/call/eall/sall show rebuild J).
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "rebuild")) {
		for _, r := range arr(e.data) {
			cid, key, ok := scDriveKey(str(r["Drive-ID"]))
			ct := byID[cid]
			if !ok || ct == nil || !strings.Contains(strings.ToLower(str(r["Status"])), "in progress") {
				continue
			}
			d := ct.drive(key)
			p := str(r["Progress%"])
			if p != "" && p != "-" {
				p += "%"
			}
			if eta := str(r["Estimated Time Left"]); eta != "" && eta != "-" {
				p += ", ETA " + eta
			}
			d.Rebuild = strings.TrimSpace(p)
			if d.Class == "" || d.Class == stOK {
				d.Class, d.State = stRebuilding, firstNonEmpty(d.State, "Rbld")
			}
		}
	}

	// Battery / CacheVault details (property/value tables).
	for _, sec := range []string{prefix + "bbu", prefix + "cv"} {
		for _, e := range parseStorcliJSON(c.sectionText(sec)) {
			ct := byID[e.ctrlID()]
			if ct == nil {
				continue
			}
			if bad, _ := e.failed(); bad {
				continue
			}
			walkProps(e.data, func(prop, val string) {
				lp := strings.ToLower(prop)
				switch {
				case (lp == "battery state" || lp == "state") && val != "":
					if ct.Battery == "" {
						ct.Battery = val
					}
				case lp == "type" || lp == "model":
					if ct.BatteryModel == "" {
						ct.BatteryModel = val
					}
				case strings.Contains(lp, "replacement required") || strings.Contains(lp, "about to fail") || strings.Contains(lp, "pack missing"):
					if strings.EqualFold(val, "yes") {
						ct.BatteryFlags = uniq(append(ct.BatteryFlags, prop))
					}
				}
			})
		}
	}

	for _, ct := range order {
		for _, d := range ct.Drives {
			if d.Class == "" {
				d.Class = storcliPDClass(d.State)
			}
		}
		sortDrives(ct.Drives)
	}
	return order, errs
}

// storcliPDRow records a PD LIST row. Rows from "/call show all" are
// primary; rows repeated in the per-drive output only fill in drives not
// seen yet, so the two snapshots cannot contradict each other.
func (c *checker) storcliPDRow(ct *Controller, p map[string]any, primary bool) {
	key := normEIDSlt(str(p["EID:Slt"]))
	if key == "" {
		return
	}
	d := ct.drive(key)
	if !primary && d.State != "" {
		return
	}
	d.State = str(p["State"])
	d.Class = storcliPDClass(d.State)
	if dg := str(p["DG"]); dg != "" && dg != "-" {
		d.Group = dg
	}
	d.Size = str(p["Size"])
	d.Media = strings.TrimSpace(str(p["Intf"]) + " " + str(p["Med"]))
	if d.Model == "" {
		d.Model = collapse(str(p["Model"]))
	}
	eid, slot, _ := strings.Cut(key, ":")
	if eid != "" {
		d.Location = "Enclosure " + eid + " Slot " + slot
	} else {
		d.Location = "Slot " + slot
	}
	ct.evidence = append(ct.evidence, "PD "+key+" "+d.State+" "+d.Size+" "+d.Model)
}

// walkProps visits every {"Property": p, "Value": v} pair and every plain
// "key": "scalar" pair in a decoded JSON tree.
func walkProps(v any, fn func(prop, val string)) {
	switch x := v.(type) {
	case map[string]any:
		if p, ok := x["Property"]; ok {
			fn(str(p), str(x["Value"]))
			return
		}
		for k, vv := range x {
			switch vv.(type) {
			case map[string]any, []any:
				walkProps(vv, fn)
			default:
				fn(k, str(vv))
			}
		}
	case []any:
		for _, e := range x {
			walkProps(e, fn)
		}
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func beforeSlash(s string) string { b, _, _ := strings.Cut(s, "/"); return strings.TrimSpace(b) }

func afterSlash(s string) string {
	if _, a, ok := strings.Cut(s, "/"); ok {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(s)
}
