package raid

import (
	"strings"
)

// Broadcom StorCLI2 (MegaRAID 9600/9700 "Avenger" controllers, mpi3mr
// driver) and Dell PERCCLI2 (PERC 12: H965i, H765i, H365i, H975i) keep the
// StorCLI JSON envelope {"Controllers":[{"Command Status":...,"Response
// Data":...}]} but change the payload (StorCLI2 User Interface User Guide
// UG104; real output from MegaRAID 9660-16i, see testdata/SOURCES.md):
//
//   - a drive has a configuration "State" (Conf, UConf, GHS, DHS, JBOD,
//     ...Shld, ...Sntz, ...Dgrd) and a health "Status" (Online, Good, Bad,
//     Failed, Offline, Missing, Replace, Unusable, Rebuild, Various,
//     Unknown); the health is in Status (Checkmk werk #18495 made the same
//     correction);
//   - /cx/eall/sall show all returns "Drives List" entries with "Drive
//     Information" and "Drive Detailed Information" (error counters under
//     "LU/NS Properties");
//   - /cx/vall show all returns "Virtual Drives" entries with "VD Info",
//     "PDs" and "VD Properties";
//   - the battery/supercap is the "Energy Pack" (/cx/ep show all), with a
//     Status of Optimal, Need Attention, Critical or Unavailable.
//
// Controller, VD and battery rules are the StorCLI ones (analyzeController).

// storcli2PDClass classifies a drive from its State and Status.
func storcli2PDClass(state, status string) string {
	st := strings.ToLower(strings.TrimSpace(state))
	ss := strings.ToLower(strings.TrimSpace(status))
	switch ss {
	case "failed", "bad", "offline", "offln", "unusable", "unusbl":
		return stFailed
	case "missing", "msng":
		return stMissing
	case "rebuild", "rbld":
		return stRebuilding
	case "copyback", "cpybck":
		return stBusy
	case "replace":
		// The firmware wants the drive replaced (Checkmk's storcli2 rules
		// default it to CRIT); the drive still works, like a predictive
		// failure, so it gets the predictive-failure finding (Crit).
		return stPredictive
	}
	switch {
	case strings.HasSuffix(st, "shld"):
		return stUnknown // shielded: diagnostics after errors
	case strings.HasSuffix(st, "sntz"):
		return stBusy // sanitize in progress
	case strings.HasSuffix(st, "dgrd"), strings.HasSuffix(st, "unsp"), st == "unknown":
		return stUnknown
	}
	switch ss {
	case "online", "good", "onln":
		switch st {
		case "ghs", "dhs":
			return stSpare
		case "uconf", "ugood":
			return stUnconfigured
		}
		return stOK
	}
	return stUnknown // Various, Unknown, empty or a newer value
}

func storcli2DriveState(state, status string) string {
	switch {
	case state == "" || state == "-":
		return status
	case status == "" || status == "-":
		return state
	}
	return state + ", " + status
}

// storcli2Count sums one error counter over every LU/NS of a drive (a
// multi-actuator or multi-namespace drive has one set per LU/NS), or -1
// when the counter is absent.
func storcli2Count(v any, key string) int64 {
	total, found := int64(0), false
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				if strings.EqualFold(k, key) {
					if n := num(vv); n >= 0 {
						total += n
						found = true
					}
					continue
				}
				walk(vv)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
	if !found {
		return -1
	}
	return total
}

// storcli2SmartAlert looks for a S.M.A.R.T. alert flag (StorCLI's "S.M.A.R.T
// alert flagged by drive"; not seen in StorCLI2 output so far, read in case
// a version prints it).
func storcli2SmartAlert(v any) bool {
	alert := false
	walkProps(v, func(prop, val string) {
		lp := strings.ToLower(prop)
		if (strings.Contains(lp, "s.m.a.r.t") || strings.Contains(lp, "smart alert")) && strings.EqualFold(val, "yes") {
			alert = true
		}
	})
	return alert
}

func (c *checker) parseStorcli2Family(tool, prefix string) ([]*Controller, []string) {
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
	notFound := func(why string) bool {
		l := strings.ToLower(why)
		return strings.Contains(l, "not found") || strings.Contains(l, "no controller")
	}

	ctrlSec := c.b.Get(prefix + "ctrl")
	entries := parseStorcliJSON(ctrlSec.Text())
	if ctrlSec.Ran() && len(entries) == 0 && strings.TrimSpace(ctrlSec.Out+ctrlSec.Err) != "" {
		errs = append(errs, tool+": "+errText(ctrlSec))
	}
	for _, e := range entries {
		if bad, why := e.failed(); bad {
			if why != "" && !notFound(why) {
				errs = append(errs, tool+" /c"+e.ctrlID()+": "+why)
			}
			continue
		}
		rd, _ := e.data.(map[string]any)
		if rd == nil || num(rd["Number of Controllers"]) == 0 {
			continue
		}
		ct := get(e.ctrlID())
		basics := obj(rd, "Basics")
		ct.Model = collapse(firstNonEmpty(str(basics["Product Name"]), str(basics["Model"]), str(rd["Product Name"])))
		ct.Serial = collapse(firstNonEmpty(str(basics["Serial Number"]), str(rd["Serial Number"])))
		ver := obj(rd, "Version")
		ct.Firmware = firstNonEmpty(str(ver["Package Version"]), str(ver["Firmware Version"]))
		st := obj(rd, "Status")
		ct.Status = firstNonEmpty(str(st["Controller Status"]), str(rd["Controller Status"]))
		if n := num(st["Memory Uncorrectable Errors"]); n > 0 {
			ct.MemUncorr = n
		}
		if n := num(st["Memory Correctable Errors"]); n > 0 {
			ct.MemCorr = n
		}
		if n := num(st["Failed PD Drive Count"]); n > 0 {
			ct.Defunct = n
		}
		ct.evidence = append(ct.evidence, "Controller Status: "+ct.Status)
		for _, v := range arr(rd["VD LIST"]) {
			c.storcli2VD(ct, v)
		}
		for _, p := range arr(rd["PD LIST"]) {
			c.storcli2PDRow(ct, p, true)
		}
		for _, b := range arr(rd["Energy Pack Info"]) {
			c.storcli2EnergyPack(ct, b)
		}
	}

	// Virtual drives with their member drives (/cx/vall show all J).
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "vd")) {
		rd, _ := e.data.(map[string]any)
		ct := byID[e.ctrlID()]
		if rd == nil || ct == nil {
			continue
		}
		for _, vd := range arr(rd["Virtual Drives"]) {
			vol := c.storcli2VD(ct, obj(vd, "VD Info"))
			if vol == nil {
				continue
			}
			var members []string
			for _, p := range arr(vd["PDs"]) {
				if k := normEIDSlt(str(p["EID:Slt"])); k != "" {
					members = append(members, k)
				}
				c.storcli2PDRow(ct, p, false)
			}
			if len(members) > 0 {
				vol.Members = members
			}
			// "Bad Block Exists": the controller's bad block table (LDBBM)
			// holds blocks of this VD it could not rebuild from redundancy.
			if strings.EqualFold(str(obj(vd, "VD Properties")["Bad Block Exists"]), "yes") {
				vol.Errors = "Bad Block Exists"
			}
		}
	}

	// Drive details (/cx/eall/sall show all J).
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "pd")) {
		rd, _ := e.data.(map[string]any)
		if rd == nil {
			continue
		}
		for _, dr := range arr(rd["Drives List"]) {
			info := obj(dr, "Drive Information")
			key := normEIDSlt(str(info["EID:Slt"]))
			if key == "" {
				continue
			}
			ct := get(e.ctrlID())
			c.storcli2PDRow(ct, info, false)
			d := ct.drive(key)
			det := obj(dr, "Drive Detailed Information")
			if det == nil {
				continue
			}
			if sn := collapse(str(det["Serial Number"])); sn != "" {
				d.Serial = sn
			}
			if mn := collapse(str(det["Model"])); mn != "" {
				d.Model = mn
			}
			if v := collapse(str(det["Vendor"])); v != "" {
				d.Vendor = v
			}
			if fw := collapse(str(det["Firmware Revision Level"])); fw != "" {
				d.Firmware = fw
			}
			d.MediaErr = storcli2Count(det, "Media Error Count")
			d.OtherErr = storcli2Count(det, "Other Error Count")
			d.PredFail = storcli2Count(det, "Predictive Failure Count")
			d.SmartAlert = storcli2SmartAlert(det)
		}
	}

	// Rebuild progress (/cx/eall/sall show rebuild J): rows with EID:Slt,
	// Progress%, Status and Estimated Time Left (UG104 "Show Rebuild").
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "rebuild")) {
		ct := byID[e.ctrlID()]
		if ct == nil {
			continue
		}
		eachRow(e.data, func(r map[string]any) {
			if _, ok := r["Progress%"]; !ok {
				return
			}
			key := normEIDSlt(str(r["EID:Slt"]))
			if key == "" {
				if _, k, ok := scDriveKey(str(r["Drive-ID"])); ok {
					key = k
				}
			}
			if key == "" || !rebuildInProgress(str(r["Status"])) {
				return
			}
			// Only drives the controller listed: a stale or mismatched
			// rebuild row must not invent a drive.
			if !hasDrive(ct, key) && len(ct.Drives) > 0 {
				return
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
				d.Class, d.State = stRebuilding, firstNonEmpty(d.State, "Rebuild")
			}
		})
	}

	// Energy pack details (/cx/ep show all J).
	for _, e := range parseStorcliJSON(c.sectionText(prefix + "ep")) {
		ct := byID[e.ctrlID()]
		if ct == nil {
			continue
		}
		if bad, _ := e.failed(); bad {
			continue
		}
		rd, _ := e.data.(map[string]any)
		if rd == nil {
			continue
		}
		for _, b := range arr(rd["Energy Pack Info"]) {
			c.storcli2EnergyPack(ct, b)
		}
		if name := collapse(str(obj(rd, "VPD Information")["Device Name"])); name != "" {
			ct.BatteryModel = name
		}
		if why := collapse(str(obj(rd, "Status")["Reason"])); why != "" {
			ct.evidence = append(ct.evidence, "Energy pack reason: "+why)
			if bc := batteryClass(ct.Battery); bc != stOK && bc != "" {
				ct.BatteryFlags = uniq(append(ct.BatteryFlags, why))
			}
		}
	}

	for _, ct := range order {
		for _, d := range ct.Drives {
			if d.Class == "" {
				d.Class = stUnknown
			}
		}
		sortDrives(ct.Drives)
	}
	return order, errs
}

// storcli2VD records (or finds) a virtual drive from a "VD LIST" row or a
// "VD Info" object.
func (c *checker) storcli2VD(ct *Controller, v map[string]any) *HWVolume {
	dgvd := str(v["DG/VD"])
	if dgvd == "" {
		return nil
	}
	id := "v" + afterSlash(dgvd)
	for _, vol := range ct.Volumes {
		if vol.ID == id {
			return vol
		}
	}
	vol := &HWVolume{ID: id, Group: beforeSlash(dgvd), Level: str(v["TYPE"]), Size: str(v["Size"]), State: str(v["State"]), Name: str(v["Name"])}
	vol.Class = storcliVDClass(vol.State)
	ct.Volumes = append(ct.Volumes, vol)
	ct.evidence = append(ct.evidence, "VD "+dgvd+" "+vol.Level+" "+vol.State+" "+vol.Size)
	return vol
}

// storcli2PDRow records a drive row ("PD LIST", "Drive Information" or a
// VD's "PDs"). Rows from "/cx show all" are primary; the others only fill
// in drives not seen yet.
func (c *checker) storcli2PDRow(ct *Controller, p map[string]any, primary bool) {
	key := normEIDSlt(str(p["EID:Slt"]))
	if key == "" {
		return
	}
	d := ct.drive(key)
	if !primary && d.State != "" {
		return
	}
	state, status := str(p["State"]), str(p["Status"])
	d.State = storcli2DriveState(state, status)
	d.Class = storcli2PDClass(state, status)
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

// storcli2EnergyPack reads an "Energy Pack Info" row (Type, SubType,
// Voltage, Temperature, Status).
func (c *checker) storcli2EnergyPack(ct *Controller, b map[string]any) {
	status := str(b["Status"])
	if status == "" {
		return
	}
	ct.Battery = status
	if ct.BatteryModel == "" {
		model := str(b["Type"])
		if sub := str(b["SubType"]); sub != "" && sub != "-" && !strings.EqualFold(sub, "none") {
			model = strings.TrimSpace(model + " " + sub)
		}
		ct.BatteryModel = model
	}
	ct.evidence = uniq(append(ct.evidence, "Energy pack "+ct.BatteryModel+": "+status))
}

// eachRow calls fn for every JSON object in a decoded tree.
func eachRow(v any, fn func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		fn(x)
		for _, vv := range x {
			eachRow(vv, fn)
		}
	case []any:
		for _, e := range x {
			eachRow(e, fn)
		}
	}
}

func hasDrive(ct *Controller, id string) bool {
	for _, d := range ct.Drives {
		if d.ID == id {
			return true
		}
	}
	return false
}
