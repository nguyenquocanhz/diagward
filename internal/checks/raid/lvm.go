package raid

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// LVMRaid is one LVM RAID or mirror logical volume.
type LVMRaid struct {
	VG         string   `json:"vg"`
	LV         string   `json:"lv"`
	SegType    string   `json:"segtype"`
	Health     string   `json:"health,omitempty"`
	SyncPct    float64  `json:"syncPct"` // -1 unknown
	Mismatches int64    `json:"mismatches,omitempty"`
	SyncAction string   `json:"syncAction,omitempty"`
	Attr       string   `json:"attr,omitempty"`
	Devices    string   `json:"devices,omitempty"`
	Size       string   `json:"size,omitempty"`
	PVs        []string `json:"pvs,omitempty"` // devices under the RAID images; "[unknown]" = missing
	Missing    []string `json:"missingPVs,omitempty"`
}

// parseLVS parses the raid.lvs section: JSON (lvs --reportformat json) or
// the "#fields=..." text fallback. It returns every row as a field map plus
// the log/warning messages.
func parseLVS(out, errOut string) ([]map[string]string, []string) {
	var rows []map[string]string
	var msgs []string
	if i := strings.Index(out, "#fields="); i >= 0 {
		rest := out[i+len("#fields="):]
		hdr, body, _ := strings.Cut(rest, "\n")
		fields := strings.Split(strings.TrimSpace(hdr), ",")
		for _, l := range lines(body) {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "WARNING") || !strings.Contains(t, "|") {
				msgs = append(msgs, t)
				continue
			}
			vals := strings.Split(t, "|")
			r := map[string]string{}
			for j, f := range fields {
				if j < len(vals) {
					r[f] = strings.TrimSpace(vals[j])
				}
			}
			if r["sync_percent"] == "" {
				r["sync_percent"] = r["copy_percent"]
			}
			rows = append(rows, r)
		}
	} else if j := strings.IndexByte(out, '{'); j >= 0 {
		var doc struct {
			Report []struct {
				LV []map[string]any `json:"lv"`
			} `json:"report"`
			Log []map[string]any `json:"log"`
		}
		dec := json.NewDecoder(strings.NewReader(out[j:]))
		if dec.Decode(&doc) == nil {
			for _, r := range doc.Report {
				for _, lv := range r.LV {
					m := map[string]string{}
					for k, v := range lv {
						m[k] = fmt.Sprint(v)
					}
					rows = append(rows, m)
				}
			}
			for _, l := range doc.Log {
				if s, ok := l["log_message"].(string); ok {
					msgs = append(msgs, s)
				}
			}
		}
	}
	for _, l := range lines(errOut) {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "WARNING") {
			msgs = append(msgs, t)
		}
	}
	return rows, uniq(msgs)
}

var lvMissingPVRe = regexp.MustCompile(`VG (\S+) is missing PV \S+ \(last written to ([^)]+)\)`)

var lvmName = model.T("LVM RAID / mirror volumes", "Volume LVM RAID / mirror")

func (c *checker) checkLVM() {
	sec := c.b.Get("raid.lvs")
	if sec == nil {
		return
	}
	if sec.Missing != "" {
		fix, cmd := installPkg(c.env, "lvm2")
		c.cover("raid.lvm", lvmName, model.CovSkipped, hint.Missing("lvs"), fix, cmd)
		return
	}
	if sec.Skipped != "" {
		c.cover("raid.lvm", lvmName, model.CovSkipped, hint.NeedRoot(c.env), hint.RunAsRoot(c.env))
		return
	}
	rows, msgs := parseLVS(sec.Out, sec.Err)
	if len(rows) == 0 {
		c.cover("raid.lvm", lvmName, model.CovFailed, model.Tf("lvs gave no usable output: %s", "lvs không trả về dữ liệu dùng được: %s", errText(sec)), model.Text{})
		return
	}
	missingByVG := map[string][]string{}
	for _, m := range msgs {
		if mm := lvMissingPVRe.FindStringSubmatch(m); mm != nil {
			missingByVG[mm[1]] = append(missingByVG[mm[1]], mm[2])
		}
	}
	// Physical volumes behind each RAID image ("[lv_rimage_0]" -> "/dev/sdb(1)").
	pvs := map[string][]string{}
	for _, r := range rows {
		n := strings.Trim(r["lv_name"], "[]")
		for _, sub := range []string{"_rimage_", "_mimage_"} {
			if i := strings.Index(n, sub); i > 0 {
				for _, d := range strings.Split(r["devices"], ",") {
					if j := strings.IndexByte(d, '('); j > 0 {
						d = d[:j]
					}
					pvs[r["vg_name"]+"/"+n[:i]] = append(pvs[r["vg_name"]+"/"+n[:i]], d)
				}
			}
		}
	}
	var ok []string
	for _, r := range rows {
		name := r["lv_name"]
		seg := r["segtype"]
		if strings.HasPrefix(name, "[") || !(strings.HasPrefix(seg, "raid") || seg == "mirror") {
			continue
		}
		lv := &LVMRaid{VG: r["vg_name"], LV: name, SegType: seg, Health: r["lv_health_status"], Attr: r["lv_attr"],
			Devices: r["devices"], SyncAction: r["raid_sync_action"], SyncPct: -1, Missing: uniq(missingByVG[r["vg_name"]]), Size: r["lv_size"], PVs: uniq(pvs[r["vg_name"]+"/"+name])}
		if f, err := strconv.ParseFloat(r["sync_percent"], 64); err == nil {
			lv.SyncPct = f
		}
		if n := atoi(r["raid_mismatch_count"]); n > 0 {
			lv.Mismatches = n
		}
		// lv_attr bit 9 is the volume health: (p)artial, (r)efresh needed,
		// (m)ismatches exist (lvs(8)); old LVM has no lv_health_status.
		if lv.Health == "" && len(lv.Attr) >= 9 {
			switch lv.Attr[8] {
			case 'p':
				lv.Health = "partial"
			case 'r':
				lv.Health = "refresh needed"
			case 'm':
				lv.Health = "mismatches exist"
			}
		}
		c.facts.LVM = append(c.facts.LVM, lv)
		if c.analyzeLV(lv, msgs) == model.OK {
			ok = append(ok, lv.VG+"/"+lv.LV)
		}
	}
	if len(ok) > 0 {
		c.add(model.Finding{
			ID: "raid.lvm_ok", Severity: model.OK, Target: strings.Join(ok, ", "),
			Title: model.Tf("LVM RAID volumes healthy and in sync: %s", "Volume LVM RAID hoạt động tốt, đã đồng bộ: %s", strings.Join(ok, ", ")),
		})
	}
	c.cover("raid.lvm", lvmName, model.CovRan, model.Text{}, model.Text{})
}

func (c *checker) analyzeLV(lv *LVMRaid, msgs []string) model.Severity {
	target := lv.VG + "/" + lv.LV
	sev := model.OK
	evid := []string{fmt.Sprintf("%s segtype=%s health=%q sync=%s attr=%s devices=%s", target, lv.SegType, lv.Health, fmtPct(lv.SyncPct), lv.Attr, lv.Devices)}
	evid = append(evid, msgs...)
	switch lv.Health {
	case "partial":
		sev = model.Crit
		var part *model.Part
		loc := joinOr(lv.Missing, "")
		if loc != "" {
			part = c.ids.diskPart(lv.Missing[0], "last seen as "+lv.Missing[0]+" (VG "+lv.VG+")")
		}
		c.add(model.Finding{
			ID: "raid.lvm_partial", Severity: model.Crit, Target: target,
			Title: model.Tf("LVM RAID %s is degraded: a physical volume is missing", "LVM RAID %s bị degraded: mất một physical volume", target),
			Detail: model.Tf("lvs reports health \"partial\": a PV of VG %s is missing%s. The %s volume still works on the remaining image(s) but has no redundancy.",
				"lvs báo trạng thái \"partial\": VG %s mất một PV%s. Volume %s vẫn chạy trên các bản còn lại nhưng không còn dự phòng.", lv.VG, strings.TrimSpace(" "+joinOr(lv.Missing, "")), lv.SegType),
			Action: model.Tf("Back up now. Reconnect or replace the missing disk. With a new disk: pvcreate /dev/<new>; vgextend %s /dev/<new>; lvconvert --repair %s; then vgreduce --removemissing %s once the volume is in sync.",
				"Sao lưu ngay. Cắm lại hoặc thay ổ bị mất. Với ổ mới: pvcreate /dev/<ổ mới>; vgextend %s /dev/<ổ mới>; lvconvert --repair %s; rồi vgreduce --removemissing %s khi volume đã đồng bộ xong.", lv.VG, target, lv.VG),
			Evidence: ev(evid),
			Part:     part,
		})
	case "refresh needed":
		sev = model.Crit
		c.add(model.Finding{
			ID: "raid.lvm_refresh_needed", Severity: model.Crit, Target: target,
			Title: model.Tf("LVM RAID %s lost an image (refresh needed)", "LVM RAID %s mất một bản sao (cần refresh)", target),
			Detail: model.T("The kernel marked one RAID image as failed, so the volume runs without redundancy. This can follow a transient disk or cable error.",
				"Kernel đã đánh dấu một bản RAID là lỗi nên volume đang chạy không có dự phòng. Có thể do lỗi ổ hoặc cáp thoáng qua."),
			Action: model.Tf("Check the disks (smartctl -a, dmesg). If the device is fine again: lvchange --refresh %s. If it failed: replace it and run lvconvert --repair %s.",
				"Kiểm tra các ổ (smartctl -a, dmesg). Nếu thiết bị đã ổn: lvchange --refresh %s. Nếu ổ hỏng: thay ổ rồi chạy lvconvert --repair %s.", target, target),
			Evidence: ev(evid),
		})
	}
	// RAID1/10 mismatches can be benign (see the md mismatch_cnt note);
	// parity RAID mismatches mean inconsistent stripes.
	if lv.Mismatches > 0 || lv.Health == "mismatches exist" {
		s := model.Warn
		if strings.HasPrefix(lv.SegType, "raid1") || lv.SegType == "mirror" {
			s = model.Info
		}
		sev = model.Worst(sev, s)
		title := model.Tf("LVM RAID %s: scrub found %d mismatches", "LVM RAID %s: lần scrub tìm thấy %d chỗ không khớp", target, lv.Mismatches)
		if lv.Mismatches <= 0 { // only lv_attr bit 9 = 'm' (old LVM has no count)
			title = model.Tf("LVM RAID %s: scrub found mismatches", "LVM RAID %s: lần scrub tìm thấy chỗ không khớp", target)
		}
		c.add(model.Finding{
			ID: "raid.lvm_mismatch", Severity: s, Target: target,
			Title: title,
			Detail: model.T("The images disagree in some places. Harmless on RAID1 with swap or files being rewritten; on RAID5/6 it points to an unclean shutdown or faulty hardware.",
				"Các bản sao không khớp nhau ở một số chỗ. Vô hại với RAID1 có swap hoặc file đang ghi đè; với RAID5/6 là dấu hiệu tắt máy đột ngột hoặc phần cứng lỗi."),
			Action:   model.Tf("Check disk S.M.A.R.T. and RAM, then run 'lvchange --syncaction repair %s' and check again.", "Kiểm tra S.M.A.R.T. ổ cứng và RAM, sau đó chạy 'lvchange --syncaction repair %s' rồi kiểm tra lại.", target),
			Evidence: ev(evid),
		})
	}
	if lv.SyncPct >= 0 && lv.SyncPct < 100 && lv.Health != "partial" && lv.Health != "refresh needed" {
		if lv.SyncAction == "check" || lv.SyncAction == "repair" {
			sev = model.Worst(sev, model.Info)
			c.add(model.Finding{
				ID: "raid.lvm_check", Severity: model.Info, Target: target,
				Title:  model.Tf("LVM RAID %s: scrub (%s) running, %s done", "LVM RAID %s: đang scrub (%s), xong %s", target, lv.SyncAction, fmtPct(lv.SyncPct)),
				Detail: model.T("A scrub verifies every block; the volume stays usable.", "Scrub kiểm tra toàn bộ dữ liệu; volume vẫn dùng bình thường."),
			})
		} else {
			sev = model.Worst(sev, model.Warn)
			c.add(model.Finding{
				ID: "raid.lvm_syncing", Severity: model.Warn, Target: target,
				Title: model.Tf("LVM RAID %s is synchronising: %s done", "LVM RAID %s đang đồng bộ: xong %s", target, fmtPct(lv.SyncPct)),
				Detail: model.T("Until the images are in sync the volume is not fully redundant (new volume, recovery after a failure or an unclean shutdown).",
					"Cho tới khi các bản sao đồng bộ xong, volume chưa có đủ dự phòng (volume mới, đang phục hồi sau lỗi, hoặc sau khi tắt máy đột ngột)."),
				Action:   model.Tf("Do not reboot or pull disks until 'lvs -a %s' shows 100%%.", "Không khởi động lại hay rút ổ cho tới khi 'lvs -a %s' báo 100%%.", lv.VG),
				Evidence: ev(evid),
			})
		}
	}
	state := lv.Health
	if state == "" {
		state = "OK"
	}
	prog := ""
	if lv.SyncPct >= 0 && lv.SyncPct < 100 {
		prog = "sync " + fmtPct(lv.SyncPct)
	}
	members := strings.Join(lv.PVs, " ")
	if members == "" {
		members = lv.Devices
	}
	c.arrayRow(sev, target, "lvm "+lv.SegType, lv.Size, state, members, prog)
	return sev
}
