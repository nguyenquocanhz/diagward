package raid

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// Normalised states shared by all vendor parsers.
const (
	stOK           = "ok"
	stDegraded     = "degraded"     // volume lost redundancy
	stFailed       = "failed"       // volume offline / drive failed
	stRebuilding   = "rebuilding"   // rebuild / recovery in progress
	stBusy         = "busy"         // initialising, expanding, copyback, ...: informational
	stSpare        = "spare"        // hot spare drive
	stUnconfigured = "unconfigured" // unused good drive
	stMissing      = "missing"      // drive missing from its array
	stPredictive   = "predictive"   // drive predicts its own failure
	stUnknown      = "unknown"
	stVerify       = "needs-verify" // redundancy data inconsistent, needs verify-with-fix (Adaptec "Impacted")
)

// HWVolume is a logical/virtual drive of a hardware RAID controller.
type HWVolume struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Level    string   `json:"level,omitempty"`
	Size     string   `json:"size,omitempty"`
	State    string   `json:"state"`
	Class    string   `json:"class"`
	Progress string   `json:"progress,omitempty"`
	Group    string   `json:"group,omitempty"`
	Members  []string `json:"members,omitempty"`
	Missing  int      `json:"missingMembers,omitempty"`
	// Errors is the controller's own report of unreadable data on the
	// volume (ssacli "Unrecoverable Media Errors", arcconf "Failed stripes").
	Errors string `json:"errors,omitempty"`
}

// HWDrive is a physical drive behind a hardware RAID controller.
type HWDrive struct {
	ID         string `json:"id"`
	Location   string `json:"location,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Firmware   string `json:"firmware,omitempty"`
	Size       string `json:"size,omitempty"`
	Media      string `json:"media,omitempty"`
	State      string `json:"state"`
	Class      string `json:"class"`
	Group      string `json:"group,omitempty"`
	MediaErr   int64  `json:"mediaErrors"`        // -1 unknown
	OtherErr   int64  `json:"otherErrors"`        // -1 unknown
	PredFail   int64  `json:"predictiveFailures"` // -1 unknown
	SmartWarn  int64  `json:"smartWarnings"`      // -1 unknown (arcconf)
	SmartAlert bool   `json:"smartAlert,omitempty"`
	Rebuild    string `json:"rebuild,omitempty"`
}

func newDrive(id string) *HWDrive {
	return &HWDrive{ID: id, MediaErr: -1, OtherErr: -1, PredFail: -1, SmartWarn: -1}
}

// Controller is one hardware RAID controller as seen by its vendor CLI.
type Controller struct {
	Tool         string      `json:"tool"`
	ID           string      `json:"id"`
	Model        string      `json:"model,omitempty"`
	Serial       string      `json:"serial,omitempty"`
	Firmware     string      `json:"firmware,omitempty"`
	Status       string      `json:"status,omitempty"`
	Cache        string      `json:"cache,omitempty"`
	Battery      string      `json:"battery,omitempty"`
	BatteryModel string      `json:"batteryModel,omitempty"`
	BatteryFlags []string    `json:"batteryFlags,omitempty"` // "Replacement required", ...
	MemUncorr    int64       `json:"memoryUncorrectable,omitempty"`
	MemCorr      int64       `json:"memoryCorrectable,omitempty"`
	Defunct      int64       `json:"defunctDrives,omitempty"`
	Volumes      []*HWVolume `json:"volumes,omitempty"`
	Drives       []*HWDrive  `json:"drives,omitempty"`

	evidence []string
}

func (ct *Controller) label() string {
	id := ct.ID
	if !strings.HasPrefix(strings.ToLower(id), "slot") && !strings.HasPrefix(strings.ToLower(id), "controller") {
		id = "Controller " + id
	}
	if ct.Model != "" {
		return id + " (" + ct.Model + ")"
	}
	return id
}

func (ct *Controller) drive(id string) *HWDrive {
	for _, d := range ct.Drives {
		if d.ID == id {
			return d
		}
	}
	d := newDrive(id)
	ct.Drives = append(ct.Drives, d)
	return d
}

func (c *checker) drivePart(ct *Controller, d *HWDrive) *model.Part {
	vendor := d.Vendor
	if strings.EqualFold(vendor, "ATA") {
		vendor = ""
	}
	loc := ct.label()
	if d.Location != "" {
		loc += ", " + d.Location
	} else {
		loc += ", " + d.ID
	}
	return &model.Part{Kind: "disk", Vendor: vendor, Model: d.Model, Serial: d.Serial, Firmware: d.Firmware, Size: d.Size, Location: loc}
}

// ctrlStatusSev classifies a controller status string. "Needs Attention"
// is what storcli reports for a degraded BBU or a pending learn cycle
// (prometheus-community/node-exporter-textfile-collector-scripts issue
// #27), so it is a warning; any other non-optimal status is critical, as in
// thomas-krenn/check_adaptec_raid and check_lsi_raid.
func ctrlStatusSev(s string) model.Severity {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "", l == "ok", l == "optimal":
		return model.OK
	case strings.Contains(l, "attention"):
		return model.Warn
	}
	return model.Crit
}

// batteryClass classifies a BBU / CacheVault / capacitor state.
func batteryClass(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "", l == "-", l == "na", l == "n/a", strings.Contains(l, "not installed"), strings.Contains(l, "not present"), strings.Contains(l, "absent"):
		return ""
	case strings.Contains(l, "non operational"), strings.Contains(l, "non-operational"), strings.Contains(l, "nonoperational"):
		return stFailed
	case strings.Contains(l, "optimal"), l == "ok", l == "operational":
		// Older MegaCli and some Exadata images print "Battery State:
		// Operational" for a healthy BBU (Oracle Exadata BBU maintenance
		// docs); "Non Operational" is the failed state.
		return stOK
	case strings.Contains(l, "learn"), strings.Contains(l, "charg"):
		return stBusy
	}
	return stFailed
}

func errCell(d *HWDrive) string {
	var p []string
	if d.MediaErr > 0 {
		p = append(p, fmt.Sprintf("media %d", d.MediaErr))
	}
	if d.OtherErr > 0 {
		p = append(p, fmt.Sprintf("other %d", d.OtherErr))
	}
	if d.PredFail > 0 {
		p = append(p, fmt.Sprintf("predictive %d", d.PredFail))
	}
	if d.SmartWarn > 0 {
		p = append(p, fmt.Sprintf("SMART warnings %d", d.SmartWarn))
	}
	if d.SmartAlert {
		p = append(p, "SMART alert")
	}
	if len(p) == 0 {
		if d.MediaErr == 0 || d.OtherErr == 0 || d.PredFail == 0 || d.SmartWarn == 0 {
			return "0"
		}
		return "-"
	}
	return strings.Join(p, ", ")
}

func (c *checker) analyzeController(ct *Controller) model.Severity {
	sev := model.OK
	label := ct.label()
	evid := ct.evidence

	// Controller status.
	if s := ctrlStatusSev(ct.Status); s > model.OK {
		sev = model.Worst(sev, s)
		c.add(model.Finding{
			ID: "raid.hw_ctrl_status", Severity: s, Target: label,
			Title: model.Tf("RAID controller %s reports status %q", "Card RAID %s báo trạng thái %q", label, ct.Status),
			Detail: model.T("The controller does not report itself as optimal. The cause is usually listed below (degraded virtual drive, failed disk, battery/cache problem, foreign configuration).",
				"Controller không ở trạng thái tối ưu. Nguyên nhân thường nằm ở các mục bên dưới (virtual drive degraded, ổ hỏng, pin/cache lỗi, cấu hình foreign)."),
			Action: model.Tf("Fix the issues reported for its drives and battery. If nothing else is reported, read the controller event log (%s), check the BMC (iDRAC/iLO) log and update the controller firmware.",
				"Xử lý các lỗi ổ cứng và pin được báo kèm. Nếu không có lỗi nào khác, xem nhật ký sự kiện của controller (%s), nhật ký BMC (iDRAC/iLO) và cập nhật firmware controller.", eventLogCmd(ct)),
			Evidence: ev(evid),
			Part:     &model.Part{Kind: "controller", Model: ct.Model, Serial: ct.Serial, Firmware: ct.Firmware, Location: label},
		})
	}
	if ct.MemUncorr > 0 {
		sev = model.Worst(sev, model.Warn)
		c.add(model.Finding{
			ID: "raid.hw_ctrl_memory", Severity: model.Warn, Target: label,
			Title:  model.Tf("RAID controller %s: %d uncorrectable cache memory errors", "Card RAID %s: %d lỗi bộ nhớ cache không sửa được", label, ct.MemUncorr),
			Detail: model.T("The controller's cache memory reported uncorrectable errors; cached writes may be at risk.", "Bộ nhớ cache của controller báo lỗi không sửa được; dữ liệu ghi qua cache có thể bị ảnh hưởng."),
			Action: model.T("Contact the vendor support with the controller serial; plan to replace the controller or its cache module.", "Liên hệ hãng kèm serial controller; lên kế hoạch thay controller hoặc module cache."),
			Part:   &model.Part{Kind: "controller", Model: ct.Model, Serial: ct.Serial, Location: label},
		})
	}
	// Battery / CacheVault / cache module. Without a working backup unit
	// the controller switches write-back to write-through (Broadcom
	// MegaRAID user guide, "No Write Cache if Bad BBU"), so writes get much
	// slower but data is not lost: Warn.
	bc := batteryClass(ct.Battery)
	cache := strings.ToLower(ct.Cache)
	cacheBad := cache != "" && cache != "ok" && !strings.Contains(cache, "not configured") && !strings.Contains(cache, "not present")
	batteryBad := bc == stFailed || len(ct.BatteryFlags) > 0
	if batteryBad {
		sev = model.Worst(sev, model.Warn)
		what := ct.Battery
		if len(ct.BatteryFlags) > 0 {
			what = strings.TrimSpace(what + " " + strings.Join(ct.BatteryFlags, ", "))
		}
		c.add(model.Finding{
			ID: "raid.hw_battery", Severity: model.Warn, Target: label,
			Title:  model.Tf("RAID controller %s: cache battery/capacitor problem (%s)", "Card RAID %s: pin/tụ bảo vệ cache gặp vấn đề (%s)", label, what),
			Detail: model.Text{EN: "The battery (BBU) or capacitor (CacheVault/FBWC) protects the write cache during power loss. When it fails, the controller usually turns write-back cache off (write-through), so disk writes become much slower." + cacheNote(ct.Cache, cacheBad, false), VI: "Pin (BBU) hoặc tụ (CacheVault/FBWC) bảo vệ dữ liệu trong cache khi mất điện. Khi nó lỗi, controller thường tắt write-back cache (chuyển sang write-through) nên tốc độ ghi giảm mạnh." + cacheNote(ct.Cache, cacheBad, true)},
			Action: model.Tf("Replace the battery/capacitor module%s (it is a consumable, usually covered by warranty). Until then expect slower writes; do not force write-back without a UPS.",
				"Thay module pin/tụ%s (là linh kiện hao mòn, thường được bảo hành). Trong lúc chờ, tốc độ ghi sẽ chậm; không ép bật write-back nếu không có UPS.", batteryModelText(ct.BatteryModel)),
			Evidence: ev(evid),
			Part:     &model.Part{Kind: "battery", Model: ct.BatteryModel, Location: label},
		})
	} else if bc == stBusy {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.hw_battery_learning", Severity: model.Info, Target: label,
			Title:  model.Tf("RAID controller %s: cache battery is charging / in a learn cycle (%s)", "Card RAID %s: pin cache đang sạc / đang chạy learn cycle (%s)", label, ct.Battery),
			Detail: model.T("During a learn cycle or charging, write-back cache may be temporarily disabled. This is routine.", "Trong lúc sạc hoặc learn cycle, write-back cache có thể tạm tắt. Đây là hoạt động định kỳ bình thường."),
		})
	}
	// A cache disabled because of the battery is reported once, above.
	if cacheBad && !batteryBad && bc != stBusy {
		sev = model.Worst(sev, model.Warn)
		c.add(model.Finding{
			ID: "raid.hw_cache", Severity: model.Warn, Target: label,
			Title:    model.Tf("RAID controller %s: cache status %q", "Card RAID %s: trạng thái cache %q", label, ct.Cache),
			Detail:   model.T("The write cache is disabled or faulty, which makes writes much slower (and can indicate a failing cache module or battery).", "Cache ghi đang bị tắt hoặc lỗi, khiến tốc độ ghi chậm hẳn (có thể do module cache hoặc pin hỏng)."),
			Action:   model.T("Check the cache module and battery/capacitor; replace the faulty part.", "Kiểm tra module cache và pin/tụ; thay linh kiện bị lỗi."),
			Evidence: ev(evid),
		})
	}

	groupRebuilding := map[string]bool{}
	anyRebuild := false
	for _, d := range ct.Drives {
		if d.Class == stRebuilding {
			groupRebuilding[d.Group] = true
			anyRebuild = true
		}
	}
	var failedDrives []*HWDrive
	for _, d := range ct.Drives {
		if d.Class == stFailed || d.Class == stMissing {
			failedDrives = append(failedDrives, d)
		}
	}
	volFlagged := false
	for _, v := range ct.Volumes {
		vt := label + " " + v.ID
		rebuildingHere := groupRebuilding[v.Group] && v.Group != ""
		for _, m := range v.Members {
			for _, d := range ct.Drives {
				if d.ID == m && d.Class == stRebuilding {
					rebuildingHere = true
				}
			}
		}
		if !rebuildingHere && v.Group == "" && len(v.Members) == 0 && anyRebuild {
			rebuildingHere = true // no membership info: any rebuild on this controller
		}
		vs := model.OK
		switch v.Class {
		case stDegraded:
			volFlagged = true
			if rebuildingHere || v.Progress != "" {
				vs = model.Warn
				c.add(c.hwRebuildFinding(ct, v, vt))
			} else {
				vs = model.Crit
				var part *model.Part
				if len(failedDrives) == 1 {
					part = c.drivePart(ct, failedDrives[0])
				}
				pen, pvi := partText(part)
				c.add(model.Finding{
					ID: "raid.hw_vd_degraded", Severity: model.Crit, Target: vt,
					Title: model.Tf("RAID volume %s (%s) is degraded", "Volume RAID %s (%s) bị degraded", vt, v.Level),
					Detail: model.Tf("Virtual drive %s reports %q: it still works but has lost redundancy (a RAID6 volume may have one parity left). Another disk failure can lose data.",
						"Virtual drive %s báo %q: vẫn chạy nhưng đã mất dự phòng (RAID6 có thể còn một lớp parity). Hỏng thêm ổ là có thể mất dữ liệu.", v.ID, v.State),
					Action: model.Text{
						EN: fmt.Sprintf("Back up now. Replace the failed disk%s with one of the same type and equal or larger size; the controller rebuilds automatically (or onto a hot spare). Check the new disk's state afterwards. If the disk only lost contact, reseat it.", pen),
						VI: fmt.Sprintf("Sao lưu ngay. Thay ổ hỏng%s bằng ổ cùng loại, dung lượng bằng hoặc lớn hơn; controller sẽ tự rebuild (hoặc dùng ổ hot spare). Sau đó kiểm tra trạng thái ổ mới. Nếu ổ chỉ mất kết nối, cắm lại cho chắc.", pvi),
					},
					Evidence: ev(evid),
					Part:     part,
				})
			}
		case stFailed:
			volFlagged = true
			vs = model.Crit
			c.add(model.Finding{
				ID: "raid.hw_vd_failed", Severity: model.Crit, Target: vt,
				Title: model.Tf("RAID volume %s is offline/failed (%s)", "Volume RAID %s bị offline/hỏng (%s)", vt, v.State),
				Detail: model.T("The virtual drive lost more disks than its RAID level tolerates; its data is not accessible.",
					"Virtual drive mất nhiều ổ hơn mức RAID chịu được; dữ liệu trên đó không truy cập được."),
				Action: model.T("Do not initialise or re-create the volume. Check whether disks are only disconnected (cables, backplane, foreign configuration). Restore from backup or contact the vendor / a data recovery expert.",
					"Không initialize hay tạo lại volume. Kiểm tra xem ổ chỉ mất kết nối hay không (cáp, backplane, cấu hình foreign). Khôi phục từ bản sao lưu hoặc liên hệ hãng / chuyên gia cứu dữ liệu."),
				Evidence: ev(evid),
			})
		case stRebuilding:
			volFlagged = true
			vs = model.Warn
			c.add(c.hwRebuildFinding(ct, v, vt))
		case stVerify:
			volFlagged = true
			vs = model.Warn
			id := strings.TrimPrefix(v.ID, "LD ")
			c.add(model.Finding{
				ID: "raid.hw_vd_needs_verify", Severity: model.Warn, Target: vt,
				Title: model.Tf("RAID volume %s is %q: its redundancy data needs a verify with fix", "Volume RAID %s ở trạng thái %q: dữ liệu dự phòng cần verify và sửa", vt, v.State),
				Detail: model.T("The controller does not trust the parity/mirror data of this volume (initialisation interrupted or an unclean event). The data is readable, but a disk failure now may not be recoverable.",
					"Controller không còn tin dữ liệu parity/mirror của volume này (initialize bị gián đoạn hoặc sự cố đột ngột). Dữ liệu vẫn đọc được, nhưng nếu hỏng ổ lúc này có thể không khôi phục được."),
				Action: model.Tf("Make sure the backup is current, then run a verify with fix: arcconf task start %s logicaldrive %s verify_fix (it runs in the background; the volume returns to Optimal when done).",
					"Kiểm tra bản sao lưu còn mới, rồi chạy verify kèm sửa: arcconf task start %s logicaldrive %s verify_fix (chạy nền; volume trở về Optimal khi xong).", ct.ID, id),
				Evidence: ev(evid),
			})
		case stBusy:
			vs = model.Info
			c.add(model.Finding{
				ID: "raid.hw_vd_busy", Severity: model.Info, Target: vt,
				Title:  model.Tf("RAID volume %s: %s", "Volume RAID %s: %s", vt, v.State),
				Detail: model.T("A background operation (initialisation, expansion, transformation) is running.", "Đang chạy tác vụ nền (initialize, mở rộng, chuyển đổi RAID)."),
			})
		case stUnknown:
			vs = model.Warn
			c.add(model.Finding{
				ID: "raid.hw_vd_state", Severity: model.Warn, Target: vt,
				Title:    model.Tf("RAID volume %s has an unrecognised state %q", "Volume RAID %s có trạng thái lạ %q", vt, v.State),
				Detail:   model.T("Diagward does not know this state, so it cannot say whether the volume is healthy.", "Diagward chưa biết trạng thái này nên không khẳng định được volume có ổn hay không."),
				Action:   model.T("Check the volume in the vendor tool or the controller BIOS.", "Kiểm tra volume bằng công cụ của hãng hoặc BIOS của controller."),
				Evidence: ev(evid),
			})
		}
		// Blocks the controller could not reconstruct (HPE "Unrecoverable
		// Media Errors", Adaptec "Failed stripes"): files on them are
		// damaged, but the volume as a whole still works, so Warn.
		if v.Errors != "" && v.Class != stFailed {
			vs = model.Worst(vs, model.Warn)
			c.add(model.Finding{
				ID: "raid.hw_vd_media_errors", Severity: model.Warn, Target: vt,
				Title: model.Tf("RAID volume %s has unreadable blocks (%s)", "Volume RAID %s có khối dữ liệu không đọc được (%s)", vt, v.Errors),
				Detail: model.T("The controller found stripes it could not rebuild from redundancy (usually a second disk error during a rebuild). The data in those blocks is lost; the rest of the volume is readable.",
					"Controller phát hiện các stripe không dựng lại được từ dữ liệu dự phòng (thường do ổ thứ hai lỗi đọc trong lúc rebuild). Dữ liệu trong các khối đó đã mất; phần còn lại của volume vẫn đọc được."),
				Action: model.T("Make sure the backup is current. Run a consistency check / surface scan from the vendor tool, find the affected files (filesystem check, application errors) and restore them from backup. Replace any disk that reports media errors.",
					"Kiểm tra bản sao lưu còn mới. Chạy consistency check / surface scan bằng công cụ của hãng, tìm file bị ảnh hưởng (kiểm tra filesystem, lỗi ứng dụng) và khôi phục chúng từ bản sao lưu. Thay ổ nào báo lỗi media."),
				Evidence: ev(evid),
			})
		}
		sev = model.Worst(sev, vs)
		c.arrayRow(vs, vt+nameSuffix(v.Name), strings.TrimSpace(v.Level+" ("+ct.Tool+")"), v.Size, v.State, strings.Join(v.Members, " "), joinOr(uniq([]string{v.Progress, v.Errors}), ""))
	}

	var spares, unconf []string
	for _, d := range ct.Drives {
		ds := model.OK
		part := c.drivePart(ct, d)
		pen, pvi := partText(part)
		where := d.ID
		if d.Location != "" {
			where = d.Location
		}
		switch {
		case d.Class == stFailed || d.Class == stMissing:
			ds = model.Crit
			c.add(model.Finding{
				ID: "raid.hw_pd_failed", Severity: model.Crit, Target: label + " " + where,
				Title: model.Tf("Disk %s on %s has failed (%s)", "Ổ %s trên %s đã hỏng (%s)", where, label, d.State),
				Detail: model.Tf("The controller reports the disk as %q. If it belonged to a RAID volume, that volume is degraded or rebuilding onto a spare.",
					"Controller báo ổ ở trạng thái %q. Nếu ổ thuộc một volume RAID thì volume đó đang degraded hoặc đang rebuild sang ổ dự phòng.", d.State),
				Action: model.Text{
					EN: fmt.Sprintf("Replace disk%s. Locate it with the bay LED (storcli /cX/eY/sZ start locate, or ssacli ... physicaldrive X modify led=on) before pulling, and never pull a healthy disk of a degraded volume.", pen),
					VI: fmt.Sprintf("Thay ổ%s. Bật đèn định vị khay ổ (storcli /cX/eY/sZ start locate, hoặc ssacli ... physicaldrive X modify led=on) trước khi rút, và tuyệt đối không rút nhầm ổ còn tốt của volume đang degraded.", pvi),
				},
				Evidence: ev(evid),
				Part:     part,
			})
		case d.Class == stPredictive || d.SmartAlert || d.PredFail > 0:
			// A drive that trips its own S.M.A.R.T. threshold ("predictive
			// failure") is the equivalent of smartctl -H FAILED, and Dell
			// and HPE replace such drives under warranty: Crit.
			ds = model.Crit
			c.add(model.Finding{
				ID: "raid.hw_pd_predictive", Severity: model.Crit, Target: label + " " + where,
				Title: model.Tf("Disk %s on %s predicts its own failure (S.M.A.R.T. alert)", "Ổ %s trên %s báo sắp hỏng (cảnh báo S.M.A.R.T.)", where, label),
				Detail: model.Text{
					EN: fmt.Sprintf("State %q, predictive failure count %d, S.M.A.R.T. alert: %s. The drive firmware has crossed a failure threshold; such drives often fail within days or weeks.", d.State, max(d.PredFail, 0), yesNo(d.SmartAlert, "yes", "no")),
					VI: fmt.Sprintf("Trạng thái %q, số lần predictive failure %d, cảnh báo S.M.A.R.T.: %s. Firmware của ổ đã vượt ngưỡng hỏng; ổ như vậy thường hỏng hẳn trong vài ngày tới vài tuần.", d.State, max(d.PredFail, 0), yesNo(d.SmartAlert, "có", "không")),
				},
				Action: model.Text{
					EN: fmt.Sprintf("Back up, then replace disk%s soon (open a warranty case: predictive failure qualifies). With a hot spare, the controller can copy to it first (storcli: /cX/eY/sZ set offline only after the spare is ready).", pen),
					VI: fmt.Sprintf("Sao lưu rồi sớm thay ổ%s (mở case bảo hành: predictive failure được hãng chấp nhận). Nếu có ổ hot spare, controller có thể chép sang trước.", pvi),
				},
				Evidence: ev(evid),
				Part:     part,
			})
		case d.Class == stRebuilding:
			ds = model.Warn
			if !volFlagged {
				c.add(model.Finding{
					ID: "raid.hw_pd_rebuilding", Severity: model.Warn, Target: label + " " + where,
					Title:  model.Tf("Disk %s on %s is rebuilding %s", "Ổ %s trên %s đang rebuild %s", where, label, d.Rebuild),
					Detail: model.T("The array has no redundancy until the rebuild completes.", "Mảng chưa có dự phòng cho tới khi rebuild xong."),
					Action: model.T("Do not reboot or pull disks until the rebuild completes.", "Không khởi động lại hay rút ổ cho tới khi rebuild xong."),
					Part:   part,
				})
			}
		case d.Class == stSpare:
			spares = append(spares, where)
		case d.Class == stUnconfigured:
			unconf = append(unconf, where)
		case d.Class == stUnknown:
			ds = model.Warn
			c.add(model.Finding{
				ID: "raid.hw_pd_state", Severity: model.Warn, Target: label + " " + where,
				Title:  model.Tf("Disk %s on %s is in state %q", "Ổ %s trên %s ở trạng thái %q", where, label, d.State),
				Detail: model.T("This state is not a normal online/spare state (for example shielded after errors, unsupported, or foreign).", "Đây không phải trạng thái online/spare bình thường (ví dụ bị shield sau khi lỗi, không được hỗ trợ, hoặc foreign)."),
				Action: model.T("Check the disk in the vendor tool; replace it if the controller marked it bad.", "Kiểm tra ổ bằng công cụ của hãng; thay nếu controller đánh dấu ổ lỗi."),
				Part:   part,
			})
		}
		// Media errors are sectors the drive could not read; Broadcom's
		// MegaRAID guide treats a growing count as a reason to replace.
		if ds < model.Crit && d.MediaErr > 0 {
			ds = model.Worst(ds, model.Warn)
			c.add(model.Finding{
				ID: "raid.hw_pd_media_errors", Severity: model.Warn, Target: label + " " + where,
				Title:  model.Tf("Disk %s on %s has %d media errors", "Ổ %s trên %s có %d lỗi media", where, label, d.MediaErr),
				Detail: model.T("Media errors are read failures on the disk surface that the controller had to repair from redundancy. A few old ones can be tolerated; a rising count means the disk is wearing out.", "Lỗi media là lỗi đọc trên bề mặt đĩa mà controller phải sửa từ bản dự phòng. Vài lỗi cũ có thể chấp nhận; số lỗi tăng dần nghĩa là ổ đang xuống cấp."),
				Action: model.Text{
					EN: fmt.Sprintf("Watch the counter; if it grows, replace disk%s. Keep patrol read / consistency checks enabled.", pen),
					VI: fmt.Sprintf("Theo dõi bộ đếm; nếu tăng, thay ổ%s. Giữ bật patrol read / consistency check.", pvi),
				},
				Part: part,
			})
		}
		if ds < model.Crit && d.SmartWarn > 0 {
			ds = model.Worst(ds, model.Warn)
			c.add(model.Finding{
				ID: "raid.hw_pd_smart_warnings", Severity: model.Warn, Target: label + " " + where,
				Title: model.Tf("Disk %s on %s has %d S.M.A.R.T. warnings", "Ổ %s trên %s có %d cảnh báo S.M.A.R.T.", where, label, d.SmartWarn),
				// thomas-krenn/check_adaptec_raid treats any count as a warning.
				Detail: model.T("The controller counted S.M.A.R.T. warnings for this disk: its own health monitoring sees attributes getting worse.", "Controller ghi nhận cảnh báo S.M.A.R.T. cho ổ này: cơ chế tự giám sát của ổ thấy các chỉ số đang xấu đi."),
				Action: model.Text{EN: "Check the disk's S.M.A.R.T. details and plan a replacement" + pen + ".", VI: "Kiểm tra chi tiết S.M.A.R.T. của ổ và lên kế hoạch thay" + pvi + "."},
				Part:   part,
			})
		}
		// "Other Error Count" counts transport-level events (timeouts,
		// resets, link errors) rather than bad sectors, and is often
		// raised by cable/backplane hiccups or firmware updates: Info.
		if ds < model.Warn && d.OtherErr > 0 {
			ds = model.Worst(ds, model.Info)
			c.add(model.Finding{
				ID: "raid.hw_pd_other_errors", Severity: model.Info, Target: label + " " + where,
				Title:  model.Tf("Disk %s on %s: %d other (link/command) errors", "Ổ %s trên %s: %d lỗi khác (kết nối/lệnh)", where, label, d.OtherErr),
				Detail: model.T("These are usually timeouts or link resets, not bad sectors. If the count keeps rising, check the cable/backplane slot and the drive firmware.", "Thường là lỗi timeout hoặc reset kết nối, không phải sector hỏng. Nếu số lỗi tiếp tục tăng, kiểm tra cáp/khe backplane và firmware ổ."),
				Part:   part,
			})
		}
		sev = model.Worst(sev, ds)
		state := d.State
		if d.Rebuild != "" {
			state += " " + d.Rebuild
		}
		c.drives = append(c.drives, model.Row{Status: ds, Cells: []string{label, where, collapse(strings.TrimSpace(d.Vendor + " " + d.Model)), d.Serial, d.Size, state, errCell(d)}})
	}
	if ct.Defunct > 0 && len(failedDrives) == 0 {
		sev = model.Worst(sev, model.Crit)
		c.add(model.Finding{
			ID: "raid.hw_pd_failed", Severity: model.Crit, Target: label,
			Title:    model.Tf("RAID controller %s reports %d defunct (failed) disks", "Card RAID %s báo %d ổ hỏng (defunct)", label, ct.Defunct),
			Detail:   model.T("The controller counts failed disks that are no longer listed individually.", "Controller đếm được ổ hỏng nhưng không còn liệt kê riêng từng ổ."),
			Action:   model.T("Check the disk bays for fault LEDs and the controller event log; replace the failed disks.", "Kiểm tra đèn báo lỗi trên khay ổ và nhật ký controller; thay các ổ hỏng."),
			Evidence: ev(evid),
		})
	}
	if len(spares)+len(unconf) > 0 {
		sev = model.Worst(sev, model.Info)
		var en, vi []string
		if len(spares) > 0 {
			en = append(en, fmt.Sprintf("%d hot spare(s): %s", len(spares), strings.Join(spares, ", ")))
			vi = append(vi, fmt.Sprintf("%d ổ hot spare: %s", len(spares), strings.Join(spares, ", ")))
		}
		if len(unconf) > 0 {
			en = append(en, fmt.Sprintf("%d unused disk(s): %s", len(unconf), strings.Join(unconf, ", ")))
			vi = append(vi, fmt.Sprintf("%d ổ chưa dùng: %s", len(unconf), strings.Join(unconf, ", ")))
		}
		c.add(model.Finding{
			ID: "raid.hw_spares", Severity: model.Info, Target: label,
			Title:  model.Text{EN: "RAID controller " + label + ": " + strings.Join(en, "; "), VI: "Card RAID " + label + ": " + strings.Join(vi, "; ")},
			Detail: model.Text{EN: "Hot spares take over automatically when a disk fails. Unused (unconfigured good) disks can be made spares.", VI: "Ổ hot spare sẽ tự thay khi có ổ hỏng. Ổ chưa dùng (unconfigured good) có thể đặt làm hot spare."},
		})
	}

	cacheCell := ct.Battery
	if cacheCell == "" {
		cacheCell = ct.Cache
	} else if ct.BatteryModel != "" {
		cacheCell = ct.BatteryModel + " " + cacheCell
	}
	c.ctrls = append(c.ctrls, model.Row{Status: sev, Cells: []string{ct.Tool + " " + ct.ID, ct.Model, ct.Serial, ct.Firmware, ct.Status, cacheCell}})
	return sev
}

func nameSuffix(n string) string {
	if strings.TrimSpace(n) == "" {
		return ""
	}
	return " \"" + strings.TrimSpace(n) + "\""
}

func batteryModelText(m string) string {
	if m == "" {
		return ""
	}
	return " (" + m + ")"
}

func (c *checker) hwRebuildFinding(ct *Controller, v *HWVolume, vt string) model.Finding {
	prog := v.Progress
	for _, d := range ct.Drives {
		if d.Class == stRebuilding && d.Rebuild != "" && (d.Group == v.Group || v.Group == "") {
			prog = strings.TrimSpace(prog + " " + d.ID + " " + d.Rebuild)
		}
	}
	if prog == "" {
		prog = "-"
	}
	return model.Finding{
		ID: "raid.hw_vd_rebuilding", Severity: model.Warn, Target: vt,
		Title: model.Tf("RAID volume %s is rebuilding (%s)", "Volume RAID %s đang rebuild (%s)", vt, prog),
		Detail: model.Tf("Virtual drive %s (%s, state %q) is rebuilding onto a replacement or spare disk. Until it finishes there is no redundancy and I/O is slower.",
			"Virtual drive %s (%s, trạng thái %q) đang rebuild sang ổ thay thế hoặc ổ dự phòng. Cho tới khi xong sẽ không có dự phòng và tốc độ đọc ghi chậm hơn.", v.ID, v.Level, v.State),
		Action: model.T("Do not reboot, shut down or pull any disk until the rebuild completes. Make sure the backup is current.",
			"Không khởi động lại, tắt máy hay rút ổ nào cho tới khi rebuild xong. Kiểm tra bản sao lưu còn mới."),
		Evidence: ev(ct.evidence),
	}
}

// ---- orchestration ----

var hwName = model.T("Hardware RAID controllers", "Card RAID phần cứng")

// hwFamilies are the CLI families and the sections they write.
var hwFamilies = []struct{ tool, prefix string }{
	{"storcli", "raid.storcli_"}, {"perccli", "raid.perccli_"}, {"ssacli", "raid.ssacli_"},
	{"arcconf", "raid.arcconf"}, {"megacli", "raid.megacli_"},
}

func (c *checker) checkHW() {
	detected := c.detectControllers()
	c.facts.Detected = detected
	hwSec := c.b.Get("raid.hw")

	var ctrls []*Controller
	ran := map[string]bool{}
	var failures []string
	for _, fam := range hwFamilies {
		secs := c.b.Prefix(fam.prefix)
		if len(secs) == 0 {
			continue
		}
		anyRan := false
		for _, s := range secs {
			if s.Ran() {
				anyRan = true
			}
		}
		if !anyRan {
			continue
		}
		var got []*Controller
		var errs []string
		switch fam.tool {
		case "storcli", "perccli":
			got, errs = c.parseStorcliFamily(fam.tool, fam.prefix)
		case "ssacli":
			got = parseSsacli(c.b.Get("raid.ssacli_config").Text(), c.b.Get("raid.ssacli_status").Text())
			if len(got) == 0 {
				if s := c.b.Get("raid.ssacli_config"); s.Ran() && s.RC != 0 {
					errs = append(errs, "ssacli: "+errText(s))
				}
			}
		case "arcconf":
			for _, s := range c.b.Prefix("raid.arcconf:") {
				if !s.Ran() {
					continue
				}
				ct := parseArcconf(s.Out, strings.TrimPrefix(s.Name, "raid.arcconf:"))
				if ct != nil {
					got = append(got, ct)
				} else if s.RC != 0 {
					errs = append(errs, "arcconf: "+errText(s))
				}
			}
		case "megacli":
			got = parseMegaCli(c.b.Get("raid.megacli_ld").Text(), c.b.Get("raid.megacli_pd").Text(), c.b.Get("raid.megacli_bbu").Text())
			if len(got) == 0 {
				if s := c.b.Get("raid.megacli_pd"); s.Ran() && s.RC != 0 && !strings.Contains(s.Out, "Exit Code: 0x00") {
					errs = append(errs, "MegaCli: "+errText(s))
				}
			}
		}
		if len(got) > 0 {
			ran[familyOf(fam.tool)] = true
		}
		failures = append(failures, errs...)
		for _, ct := range got {
			if dup(ctrls, ct) {
				continue
			}
			ctrls = append(ctrls, ct)
		}
	}

	var ok []string
	for _, ct := range ctrls {
		c.facts.Controllers = append(c.facts.Controllers, ct)
		if c.analyzeController(ct) <= model.Info {
			ok = append(ok, ct.label())
		}
	}
	if len(ok) > 0 {
		var nv, np int
		for _, ct := range ctrls {
			nv += len(ct.Volumes)
			np += len(ct.Drives)
		}
		c.add(model.Finding{
			ID: "raid.hw_ok", Severity: model.OK, Target: strings.Join(ok, ", "),
			Title: model.Tf("Hardware RAID healthy: %s (%d volumes, %d disks checked)", "RAID phần cứng hoạt động tốt: %s (đã kiểm tra %d volume, %d ổ)", strings.Join(ok, ", "), nv, np),
		})
	}

	// Detected controllers whose CLI did not run.
	var uncovered []DetectedHW
	for _, d := range detected {
		if !ran[familyOf(d.Tool)] {
			uncovered = append(uncovered, d)
		}
	}
	switch {
	case hwSec != nil && hwSec.Skipped == "container":
		if len(detected) > 0 || len(ctrls) > 0 {
			break
		}
		c.cover("raid.hw", hwName, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		return
	case hwSec != nil && (hwSec.Skipped == "not-root" || hwSec.Skipped == "not-admin"):
		c.cover("raid.hw", hwName, model.CovSkipped, hint.NeedRoot(c.env), hint.RunAsRoot(c.env))
		return
	}
	if len(ctrls) == 0 && len(uncovered) == 0 {
		if len(failures) > 0 {
			c.cover("raid.hw", hwName, model.CovFailed, model.Tf("The RAID CLI ran but its output could not be used: %s", "Công cụ RAID đã chạy nhưng không đọc được kết quả: %s", strings.Join(failures, "; ")), model.Text{})
		}
		return
	}
	for _, d := range uncovered {
		c.add(model.Finding{
			ID: "raid.hw_cli_missing", Severity: model.Info, Target: d.Name,
			Title: model.Tf("RAID controller %s found, but its tool (%s) is not installed", "Có card RAID %s nhưng chưa cài công cụ quản lý (%s)", d.Name, d.Tool),
			Detail: model.T("Without the vendor CLI Diagward cannot see the virtual drives, failed disks or battery of this controller; the OS only sees the logical volumes, so a degraded array can go unnoticed.",
				"Thiếu công cụ của hãng thì Diagward không xem được virtual drive, ổ hỏng hay pin của controller này; hệ điều hành chỉ thấy volume logic nên mảng bị degraded có thể không ai biết."),
			Action: hint.Install(c.env, d.Tool),
		})
	}
	if len(uncovered) > 0 {
		var names []string
		for _, d := range uncovered {
			names = append(names, d.Name+" → "+d.Tool)
		}
		state := model.CovSkipped
		if len(ctrls) > 0 {
			state = model.CovPartial
		}
		c.cover("raid.hw", hwName, state,
			model.Tf("Controller found but its CLI is not installed: %s.", "Có controller nhưng chưa cài công cụ quản lý: %s.", strings.Join(names, ", ")),
			hint.Install(c.env, uncovered[0].Tool))
		return
	}
	if len(failures) > 0 {
		c.cover("raid.hw", hwName, model.CovPartial, model.Tf("Some RAID CLI commands failed: %s", "Một số lệnh của công cụ RAID bị lỗi: %s", strings.Join(failures, "; ")), model.Text{})
		return
	}
	c.cover("raid.hw", hwName, model.CovRan, model.Text{}, model.Text{})
}

func familyOf(tool string) string {
	switch tool {
	case "storcli", "perccli", "megacli":
		return "megaraid"
	}
	return tool
}

func dup(list []*Controller, ct *Controller) bool {
	if ct.Serial == "" {
		return false
	}
	for _, x := range list {
		// Only storcli vs perccli (vs MegaCli) can see the same controller.
		if x.Tool != ct.Tool && x.Serial == ct.Serial && familyOf(x.Tool) == familyOf(ct.Tool) {
			return true
		}
	}
	return false
}

func (c *checker) sectionText(name string) string {
	s := c.b.Get(name)
	if !s.Ran() {
		return ""
	}
	return s.Out
}

// sortDrives orders drives by their ID for stable tables.
func sortDrives(ds []*HWDrive) {
	sort.SliceStable(ds, func(i, j int) bool { return lessNatural(ds[i].ID, ds[j].ID) })
}

// lessNatural compares strings with embedded numbers naturally ("252:10" > "252:9").
func lessNatural(a, b string) bool {
	for a != "" && b != "" {
		ia, ib := numPrefixLen(a), numPrefixLen(b)
		if ia > 0 && ib > 0 {
			na, _ := strconv.Atoi(a[:ia])
			nb, _ := strconv.Atoi(b[:ib])
			if na != nb {
				return na < nb
			}
			a, b = a[ia:], b[ib:]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func numPrefixLen(s string) int {
	n := 0
	for n < len(s) && n < 9 && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
}

func cacheNote(cache string, bad, vi bool) string {
	if !bad {
		return ""
	}
	if vi {
		return " Trạng thái cache hiện tại: " + cache + "."
	}
	return " Current cache status: " + cache + "."
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// eventLogCmd is the read-only command that shows a controller's event log.
func eventLogCmd(ct *Controller) string {
	id := strings.TrimPrefix(strings.TrimPrefix(ct.ID, "Slot "), "Controller ")
	switch ct.Tool {
	case "storcli", "perccli":
		return ct.Tool + " /c" + id + " show events"
	case "megacli":
		return "MegaCli -AdpEventLog -GetLatest 200 -f events.log -a" + id
	case "ssacli":
		return "ssacli ctrl slot=" + id + " show detail; ssacli ctrl slot=" + id + " diag file=/tmp/ssa-diag.zip"
	case "arcconf":
		return "arcconf GETLOGS " + id + " EVENT tabular"
	}
	return ct.Tool
}
