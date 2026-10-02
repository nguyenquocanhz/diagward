package disk

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// Thresholds. Each one is justified where it is used; the constants are
// collected here so they are easy to review.
const (
	// Reallocated sectors / grown defects at or above this count are Crit.
	// Google's study of 100,000 disks ("Failure Trends in a Large Disk Drive
	// Population", FAST 2007) found that after the first reallocation a disk
	// is 14x more likely to fail within 60 days, and Backblaze lists SMART 5
	// among the five attributes that best predict failure ("What SMART Stats
	// Tell Us About Hard Drives", 2016). Any count is therefore a Warn; 100
	// or more means the disk keeps remapping and is a replace-now case in
	// common practice. The vendor's own threshold (when_failed) still
	// triggers Crit on its own.
	reallocCrit = 100

	// SSD/NVMe endurance: NVMe "Percentage Used" (NVMe Base Spec 1.4,
	// 5.14.1.2) and ATA "Percentage Used Endurance Indicator" (ACS-3 device
	// statistics) reach 100 when the rated endurance is consumed; vendors
	// stop guaranteeing data retention there. Warn at 80 to leave time to
	// order a replacement.
	wearWarn = 80
	wearCrit = 100

	// Power-on hours above five years (5 x 8766 h): typical enterprise disk
	// warranty and design life is 5 years (e.g. Seagate Exos, WD Ultrastar
	// datasheets), and Backblaze's drive stats show failure rates climbing
	// after year 4-5. Info only.
	oldDiskHours = 43830

	// Default temperature limits when the drive reports none. HDD datasheets
	// commonly specify 5-60 °C operating (Seagate Exos X16, WD Ultrastar DC
	// HC550, Toshiba MG09); SATA SSD datasheets 0-70 °C (Samsung 870 EVO,
	// Intel D3-S4510, Micron 5300); NVMe drives report their own warning
	// threshold (WCTEMP) almost always, 80 °C is a conservative fallback.
	// Without a device-reported critical limit we never raise Crit.
	hddTempWarn  = 60
	ssdTempWarn  = 70
	nvmeTempWarn = 80

	// SCSI drives report a "drive trip temperature" (SPC-4 temperature log
	// page); warn 10 °C below it (a heuristic margin), Crit at the trip.
	scsiTripMargin = 10

	// An ATA error-log entry newer than this many power-on hours (30 days)
	// counts as recent; older entries that did not recur are history.
	errLogRecentHours = 720

	// NVMe unsafe shutdowns (power lost without a shutdown notification):
	// reported as Info when frequent; on a server with redundant power and a
	// UPS they should be rare, and each one risks data in volatile caches.
	unsafeShutdownsInfo = 100

	// Windows: MSFT_StorageReliabilityCounter documents that a maximum
	// read/write/flush latency above 10 seconds "may indicate a problem with
	// the disk or the HBA".
	winLatencyWarnMs = 10000
)

// analyze runs every rule on one disk and records its row severity.
func (c *checker) analyze(d *diskInfo) {
	if d.Virtual || d.RAIDVol {
		return
	}
	var fs []model.Finding
	if s := d.Smart; s != nil && s.Standby == "" && hasHealth(s) {
		switch {
		case s.NVMe != nil || s.Protocol == "NVMe":
			fs = append(fs, nvmeRules(d)...)
		case len(s.Attrs) > 0 || s.Protocol == "ATA":
			fs = append(fs, ataRules(d)...)
		default:
			fs = append(fs, scsiRules(d)...)
		}
		fs = append(fs, selfTestRule(d)...)
		fs = append(fs, tempRule(d)...)
		fs = append(fs, wearRule(d)...)
		fs = append(fs, oldRule(d)...)
		if s.SmartEnabled != nil && !*s.SmartEnabled {
			fs = append(fs, d.finding("smart_disabled", model.Info,
				model.Tf("S.M.A.R.T. is disabled on %s", "S.M.A.R.T. đang tắt trên %s", d.target()),
				model.T("The drive does not update its health data while S.M.A.R.T. is disabled.", "Khi tắt S.M.A.R.T., ổ không cập nhật dữ liệu sức khỏe."),
				model.Tf("Enable it: smartctl -s on %s", "Bật lại: smartctl -s on %s", d.SmartDev), nil))
		}
	}
	if d.SmartTO && d.Smart == nil {
		fs = append(fs, d.finding("smart_timeout", model.Warn,
			model.Tf("%s did not answer S.M.A.R.T. commands", "%s không phản hồi lệnh S.M.A.R.T.", d.target()),
			model.Tf("smartctl got no answer from the disk within the time limit (%s). A disk that hangs on simple commands is often failing; a bad cable, backplane or controller can do the same.",
				"smartctl không nhận được phản hồi từ ổ trong thời gian cho phép (%s). Ổ treo khi nhận lệnh đơn giản thường là ổ sắp hỏng; cáp, backplane hoặc controller lỗi cũng gây hiện tượng này.", d.SmartErr),
			model.Tf("Check the kernel log for I/O errors on this disk (dmesg | grep -i %s). Back up its data, then run smartctl -a %s by hand. Replace the disk (%s) if it keeps timing out.",
				"Xem kernel log có lỗi I/O trên ổ này không (dmesg | grep -i %s). Sao lưu dữ liệu, rồi chạy tay smartctl -a %s. Nếu vẫn treo, thay ổ (%s).",
				strings.TrimPrefix(d.SmartDev, "/dev/"), d.SmartDev, d.ident()), nil))
	}
	if d.Win != nil {
		fs = append(fs, c.windowsRules(d)...)
	}
	for _, f := range fs {
		d.sev = model.Worst(d.sev, f.Severity)
		c.add(f)
	}
}

func (d *diskInfo) finding(id string, sev model.Severity, title, detail, action model.Text, ev []string) model.Finding {
	f := model.Finding{
		ID: "disk." + id, Component: model.CompDisk, Severity: sev, Target: d.target(),
		Title: title, Detail: detail, Action: action, Part: d.part(),
	}
	if len(ev) > 0 {
		f.Evidence = units.Evidence(ev, 10)
	}
	return f
}

// replaceAction is the standard "back up, replace, mind the RAID" text.
func (d *diskInfo) replaceAction(extraEN, extraVI string) model.Text {
	en := fmt.Sprintf("Back up the data on %s now. Replace the disk (%s). If it is a RAID member, check that the array is otherwise healthy before pulling it, pull the bay that matches this serial, and wait for the rebuild to finish.", d.target(), d.ident())
	vi := fmt.Sprintf("Sao lưu dữ liệu trên %s ngay. Thay ổ (%s). Nếu ổ nằm trong RAID, kiểm tra các ổ còn lại không lỗi trước khi rút, rút đúng khay có serial này và chờ rebuild xong.", d.target(), d.ident())
	if extraEN != "" {
		en += " " + extraEN
		vi += " " + extraVI
	}
	return model.T(en, vi)
}

func attrLine(a *ataAttr) string {
	v := func(p *int) string {
		if p == nil {
			return "---"
		}
		return fmt.Sprintf("%03d", *p)
	}
	wf := a.WhenFailed
	if wf == "" {
		wf = "-"
	}
	typ := "Old_age"
	if a.Prefail {
		typ = "Pre-fail"
	}
	return fmt.Sprintf("%3d %-24s value=%s worst=%s thresh=%s %s when_failed=%s raw=%s",
		a.ID, a.Name, v(a.Value), v(a.Worst), v(a.Thresh), typ, wf, firstNonEmpty(a.RawStr, fmt.Sprint(a.Raw)))
}

func exitLine(s *smartData) string {
	if s.Exit <= 0 {
		return ""
	}
	bits := []string{
		"bit 0: command line did not parse",
		"bit 1: device open failed or device in low-power mode",
		"bit 2: a SMART or other command to the disk failed",
		"bit 3: SMART status check returned DISK FAILING",
		"bit 4: prefail attributes <= threshold",
		"bit 5: attributes were <= threshold in the past",
		"bit 6: the device error log contains errors",
		"bit 7: the self-test log contains errors",
	}
	var on []string
	for i, b := range bits {
		if s.Exit&(1<<i) != 0 {
			on = append(on, b)
		}
	}
	return fmt.Sprintf("smartctl exit status %d (%s)", s.Exit, strings.Join(on, "; "))
}

// exitBit reports a smartctl exit-status bit (man smartctl, EXIT STATUS),
// only when the status is a real bitmask (not a timeout/kill code).
func exitBit(s *smartData, bit int) bool {
	return s.Exit > 0 && s.Exit < 124 && s.Exit&(1<<bit) != 0
}

// ---- ATA ----

func ataRules(d *diskInfo) []model.Finding {
	s := d.Smart
	var fs []model.Finding
	ex := exitLine(s)

	failed := false
	// Overall health: the drive's own verdict (SMART RETURN STATUS).
	if (s.Passed != nil && !*s.Passed) || (s.Passed == nil && exitBit(s, 3)) {
		ev := []string{"SMART overall-health self-assessment test result: FAILED"}
		for i := range s.Attrs {
			if s.Attrs[i].WhenFailed == "now" {
				ev = append(ev, attrLine(&s.Attrs[i]))
			}
		}
		if ex != "" {
			ev = append(ev, ex)
		}
		failed = true
		fs = append(fs, d.finding("smart_failed", model.Crit,
			model.Tf("Disk %s is failing: S.M.A.R.T. health check FAILED", "Ổ %s sắp hỏng: kiểm tra S.M.A.R.T. báo FAILED", d.target()),
			model.T("The drive's own self-assessment says it is failing. Vendors define this as a failure expected soon (smartctl: \"Drive failure expected in less than 24 hours\"); it is also grounds for a warranty replacement.",
				"Chính ổ tự đánh giá là đang hỏng. Theo định nghĩa của hãng, ổ có thể chết bất cứ lúc nào (smartctl: \"Drive failure expected in less than 24 hours\"); đây cũng là căn cứ để bảo hành."),
			d.replaceAction("", ""), ev))
	}

	// Attributes at or below their vendor threshold.
	var nowPre, nowOld, pastPre, pastOld []string
	for i := range s.Attrs {
		a := &s.Attrs[i]
		switch {
		case a.WhenFailed == "now" && a.Prefail:
			nowPre = append(nowPre, attrLine(a))
		case a.WhenFailed == "now":
			nowOld = append(nowOld, attrLine(a))
		case a.WhenFailed == "past" && a.Prefail:
			pastPre = append(pastPre, attrLine(a))
		case a.WhenFailed == "past":
			pastOld = append(pastOld, attrLine(a))
		}
	}
	if len(nowPre) == 0 && exitBit(s, 4) {
		nowPre = append(nowPre, ex)
	}
	// Pre-fail attributes at or below threshold mean imminent failure (man
	// smartctl: "a Pre-failure Attribute ... indicates imminent drive
	// failure"); usage (Old_age) attributes mean end of life / wear.
	// The overall FAILED verdict is computed from these same attributes (ATA
	// SMART RETURN STATUS) and already lists them; do not report them twice.
	if len(nowPre) > 0 && !failed {
		fs = append(fs, d.finding("smart_attr_failing", model.Crit,
			model.Tf("Disk %s: pre-failure S.M.A.R.T. attribute below the vendor threshold", "Ổ %s: chỉ số S.M.A.R.T. loại pre-fail đã vượt ngưỡng của hãng", d.target()),
			model.T("A pre-failure attribute has dropped to or below the threshold the manufacturer set. By the S.M.A.R.T. definition this predicts that the drive will fail soon.",
				"Một chỉ số loại pre-fail đã xuống bằng hoặc dưới ngưỡng do hãng đặt. Theo định nghĩa S.M.A.R.T., đây là dấu hiệu ổ sắp hỏng."),
			d.replaceAction("", ""), nowPre))
	}
	if len(nowOld) > 0 {
		fs = append(fs, d.finding("smart_attr_failing", model.Warn,
			model.Tf("Disk %s: usage attribute below the vendor threshold", "Ổ %s: chỉ số hao mòn/tuổi thọ đã vượt ngưỡng của hãng", d.target()),
			model.T("An Old_age (usage) attribute is at or below its threshold: the drive has reached the end of its rated life for that attribute (wear, temperature or similar). It is not failing yet, but it is outside the vendor's spec.",
				"Một chỉ số loại Old_age (hao mòn) đã chạm ngưỡng: ổ đã hết tuổi thọ danh định cho chỉ số đó (độ mòn, nhiệt độ...). Chưa hỏng ngay nhưng đã ra ngoài thông số của hãng."),
			model.Tf("Plan to replace %s (%s) and make sure it is backed up.", "Lên kế hoạch thay %s (%s) và bảo đảm dữ liệu đã được sao lưu.", d.target(), d.ident()), nowOld))
	}
	if len(pastPre) > 0 {
		fs = append(fs, d.finding("smart_attr_failed_past", model.Warn,
			model.Tf("Disk %s: a pre-failure attribute crossed its threshold in the past", "Ổ %s: một chỉ số pre-fail từng vượt ngưỡng trong quá khứ", d.target()),
			model.T("The attribute is back above the threshold now, but its worst value once reached the failure threshold.",
				"Hiện chỉ số đã trở lại trên ngưỡng, nhưng giá trị tệ nhất của nó từng chạm ngưỡng hỏng."),
			model.Tf("Back up %s and watch it closely; plan a replacement (%s).", "Sao lưu %s và theo dõi sát; lên kế hoạch thay ổ (%s).", d.target(), d.ident()), pastPre))
	}
	if len(pastOld) > 0 {
		fs = append(fs, d.finding("smart_attr_failed_past", model.Info,
			model.Tf("Disk %s: a usage attribute crossed its threshold in the past", "Ổ %s: một chỉ số hao mòn từng vượt ngưỡng trong quá khứ", d.target()),
			model.T("Usually a past temperature excursion (attribute 190/194). It is history, not a current fault.",
				"Thường là ổ từng bị quá nhiệt (chỉ số 190/194). Đây là sự kiện cũ, không phải lỗi hiện tại."),
			model.T("Check the server's cooling and airflow.", "Kiểm tra tản nhiệt và luồng gió của máy chủ."), pastOld))
	}

	// 197 Current_Pending_Sector / 198 Offline_Uncorrectable: sectors the
	// drive could not read. The data in them is unreadable now; Backblaze
	// counts both among the five SMART stats that best predict failure.
	// Some SSDs reuse 197 for a transient ECC counter (Crucial/Micron
	// "Current_Pending_ECC_Cnt"), so only the sector-named attributes are Crit.
	pend, off := s.attr(197), s.attr(198)
	pn, on := pend.count(), off.count()
	if pn > 0 || on > 0 {
		sev := model.Crit
		sectorNamed := (pend != nil && pn > 0 && strings.Contains(strings.ToLower(pend.Name), "sector")) ||
			(off != nil && on > 0 && strings.Contains(strings.ToLower(off.Name), "uncorrect"))
		if !sectorNamed {
			sev = model.Warn
		}
		var ev []string
		for _, a := range []*ataAttr{pend, off} {
			if a != nil && a.count() > 0 {
				ev = append(ev, attrLine(a))
			}
		}
		n := max(pn, on)
		fs = append(fs, d.finding("unreadable_sectors", sev,
			model.Tf("Disk %s is failing: %s sectors could not be read", "Ổ %s sắp hỏng: %s sector không đọc được", d.target(), units.Thousands(n)),
			model.Tf("Current_Pending_Sector = %d (sectors waiting to be remapped because a read failed), Offline_Uncorrectable = %d (sectors the offline scan could not read). Data stored in those sectors is unreadable right now, and disks with pending sectors fail far more often (Backblaze drive stats).",
				"Current_Pending_Sector = %d (sector đọc lỗi, đang chờ thay thế), Offline_Uncorrectable = %d (sector lần quét offline không đọc được). Dữ liệu nằm trên các sector này hiện không đọc được, và ổ có sector chờ thay thế hỏng nhiều hơn hẳn (thống kê Backblaze).", pn, on),
			d.replaceAction("After the rebuild, run a RAID consistency check: the array may already have lost redundancy for those blocks.",
				"Sau khi rebuild, chạy kiểm tra tính nhất quán (consistency check) của RAID vì mảng có thể đã mất dự phòng ở các block đó."), ev))
	}

	// 5 Reallocated_Sector_Ct (retired blocks on SSDs).
	if a := s.attr(5); a != nil && a.count() > 0 {
		n := a.count()
		sev := model.Warn
		if n >= reallocCrit && d.kind() != "SSD" {
			sev = model.Crit
		}
		title := model.Tf("Disk %s has %s reallocated sectors", "Ổ %s có %s sector đã bị thay thế (reallocated)", d.target(), units.Thousands(n))
		detail := model.T("The drive found bad sectors and moved their data to spare sectors. Reallocations are permanent damage: after the first one a disk is much more likely to fail (Google 2007 study; Backblaze).",
			"Ổ đã phát hiện sector hỏng và chuyển dữ liệu sang vùng dự phòng. Đây là hư hỏng vĩnh viễn: sau lần thay thế đầu tiên, khả năng ổ hỏng tăng mạnh (nghiên cứu của Google 2007; Backblaze).")
		action := model.Tf("Back up %s. Plan a replacement (%s) and check again in a few days: a rising count means the disk is degrading.",
			"Sao lưu %s. Lên kế hoạch thay ổ (%s) và kiểm tra lại sau vài ngày: số tăng lên nghĩa là ổ đang xuống cấp.", d.target(), d.ident())
		if sev == model.Crit {
			action = d.replaceAction("", "")
		}
		fs = append(fs, d.finding("reallocated_sectors", sev, title, detail, action, []string{attrLine(a)}))
	}

	// 187 Reported_Uncorrect: errors ECC could not correct (Backblaze set).
	if a := s.attr(187); a != nil && a.count() > 0 {
		fs = append(fs, d.finding("reported_uncorrect", model.Warn,
			model.Tf("Disk %s reported %s uncorrectable errors", "Ổ %s báo %s lỗi không sửa được", d.target(), units.Thousands(a.count())),
			model.T("Attribute 187 counts reads the drive's error correction could not recover. Backblaze lists it among the five S.M.A.R.T. values that best predict failure.",
				"Chỉ số 187 đếm số lần đọc mà cơ chế sửa lỗi (ECC) của ổ không cứu được. Backblaze xếp chỉ số này vào nhóm 5 chỉ số dự báo hỏng ổ tốt nhất."),
			model.Tf("Back up %s and plan a replacement (%s). Check whether the count rises.", "Sao lưu %s và lên kế hoạch thay ổ (%s). Theo dõi xem số này có tăng không.", d.target(), d.ident()),
			[]string{attrLine(a)}))
	}

	// 188 Command_Timeout. Seagate packs three 16-bit counters into the raw
	// value (smartctl prints "a b c"); other vendors use a plain count. Any
	// non-zero part counts. Info only: timeouts are often caused by power
	// or cabling rather than the disk itself.
	if a := s.attr(188); a != nil {
		if n := commandTimeouts(a); n > 0 {
			fs = append(fs, d.finding("command_timeout", model.Info,
				model.Tf("Disk %s logged command timeouts", "Ổ %s từng bị timeout lệnh", d.target()),
				model.T("Attribute 188 counts commands the drive did not complete in time. It often points to power, cable or controller problems; together with other errors it adds to the case against the disk.",
					"Chỉ số 188 đếm số lệnh ổ không xử lý kịp. Thường do nguồn, cáp hoặc controller; nếu đi kèm các lỗi khác thì càng củng cố khả năng ổ có vấn đề."),
				model.T("Check the power and data cables/backplane of this bay.", "Kiểm tra cáp nguồn, cáp dữ liệu/backplane của khay này."),
				[]string{attrLine(a)}))
		}
	}

	// 199 UDMA_CRC_Error_Count: corrupted transfers between disk and
	// controller; the classic cause is the cable or backplane, not the disk.
	if a := s.attr(199); a != nil && a.count() > 0 {
		fs = append(fs, d.finding("crc_errors", model.Warn,
			model.Tf("Disk %s: %s data transfer (CRC) errors — check cable/backplane", "Ổ %s: %s lỗi truyền dữ liệu (CRC) — kiểm tra cáp/backplane", d.target(), units.Thousands(a.count())),
			model.T("UDMA_CRC_Error_Count counts transfers corrupted on the link between the disk and the controller. The usual cause is a bad or loose SATA cable, backplane slot or connector, not the disk itself. The counter never resets, so an old count that no longer grows is harmless.",
				"UDMA_CRC_Error_Count đếm số lần dữ liệu bị lỗi trên đường truyền giữa ổ và controller. Nguyên nhân thường là cáp SATA, khe backplane hoặc đầu cắm lỏng/hỏng, không phải do ổ. Bộ đếm không bao giờ reset, nên nếu con số cũ không tăng nữa thì không đáng lo."),
			model.T("Reseat or replace the data cable, or move the disk to another backplane slot. Run Diagward again later: if the count still rises, replace the cable/backplane; the disk can stay.",
				"Cắm lại hoặc thay cáp dữ liệu, hoặc chuyển ổ sang khe backplane khác. Chạy lại Diagward sau: nếu số vẫn tăng thì thay cáp/backplane; không cần thay ổ."),
			[]string{attrLine(a)}))
	}

	// 10 Spin_Retry_Count: the motor needed retries to spin up (HDD only).
	if a := s.attr(10); a != nil && a.count() > 0 && strings.Contains(strings.ToLower(a.Name), "spin") && d.kind() != "SSD" {
		fs = append(fs, d.finding("spin_retry", model.Warn,
			model.Tf("Disk %s needed %s spin-up retries", "Ổ %s phải thử quay lại %s lần mới khởi động được", d.target(), units.Thousands(a.count())),
			model.T("The spindle motor failed to reach speed on the first try. This points to a weakening motor or bearings, or to an unstable power supply.",
				"Động cơ không đạt tốc độ quay ở lần đầu. Dấu hiệu động cơ/ổ trục đang yếu hoặc nguồn cấp không ổn định."),
			model.Tf("Check the power supply to the disk and back up %s; plan a replacement (%s).", "Kiểm tra nguồn cấp cho ổ và sao lưu %s; lên kế hoạch thay ổ (%s).", d.target(), d.ident()),
			[]string{attrLine(a)}))
	}

	// ATA error log.
	if s.ErrLogCount != nil && *s.ErrLogCount > 0 {
		cnt := *s.ErrLogCount
		recent := true
		if s.ErrLogLastPOH != nil && s.POH != nil && *s.POH >= *s.ErrLogLastPOH && *s.POH-*s.ErrLogLastPOH > errLogRecentHours {
			recent = false
		}
		icrc := false
		for _, e := range s.ErrLogDescs {
			if strings.Contains(e, "ICRC") {
				icrc = true
			}
		}
		ev := append([]string{fmt.Sprintf("ATA error count: %d", cnt)}, s.ErrLogDescs...)
		if s.ErrLogLastPOH != nil {
			ev = append(ev, fmt.Sprintf("most recent error at %d power-on hours (now %d)", *s.ErrLogLastPOH, derefU(s.POH)))
		}
		detail := model.Tf("The drive's error log holds %d error(s). These are commands the drive itself reported as failed.",
			"Nhật ký lỗi của ổ ghi nhận %d lỗi. Đây là các lệnh chính ổ báo thất bại.", cnt)
		action := model.Tf("Look at the errors (smartctl -l error %s). If they are recent, back up the disk and watch for reallocated or pending sectors.",
			"Xem chi tiết lỗi (smartctl -l error %s). Nếu lỗi mới xảy ra, sao lưu dữ liệu và theo dõi số sector reallocated/pending.", d.SmartDev)
		if icrc {
			detail.EN += " The errors are interface CRC errors (ICRC): transfers corrupted on the cable/backplane."
			detail.VI += " Các lỗi là lỗi CRC đường truyền (ICRC): dữ liệu hỏng trên cáp/backplane."
			action = model.T("Reseat or replace the data cable/backplane slot of this disk.", "Cắm lại hoặc thay cáp dữ liệu/khe backplane của ổ này.")
		}
		sev := model.Warn
		title := model.Tf("Disk %s has %d error(s) in its error log", "Ổ %s có %d lỗi trong nhật ký lỗi", d.target(), cnt)
		if !recent {
			sev = model.Info
			title = model.Tf("Disk %s has %d old error(s) in its error log", "Ổ %s có %d lỗi cũ trong nhật ký lỗi", d.target(), cnt)
			detail.EN += fmt.Sprintf(" The most recent one is more than %d power-on hours old and has not recurred.", errLogRecentHours)
			detail.VI += fmt.Sprintf(" Lỗi gần nhất đã cách đây hơn %d giờ chạy và không lặp lại.", errLogRecentHours)
		}
		fs = append(fs, d.finding("ata_error_log", sev, title, detail, action, ev))
	}
	return fs
}

// commandTimeouts decodes attribute 188.
func commandTimeouts(a *ataAttr) uint64 {
	var tot uint64
	f := strings.Fields(a.RawStr)
	nums := 0
	for _, x := range f {
		if n, ok := leadingUint(x); ok {
			tot += n
			nums++
		} else {
			break
		}
	}
	if nums > 0 {
		if nums == 1 && a.Raw > 0xffff && tot == a.Raw {
			// a plain raw48 print of Seagate's packed counters
			return (a.Raw & 0xffff) + (a.Raw>>16)&0xffff + (a.Raw>>32)&0xffff
		}
		return tot
	}
	return a.Raw
}

// ---- NVMe ----

var nvmeWarnBits = []struct{ en, vi string }{
	{"available spare capacity has fallen below the threshold", "dung lượng dự phòng (spare) đã xuống dưới ngưỡng"},
	{"temperature is above an over-temperature threshold (or below an under-temperature threshold)", "nhiệt độ vượt ngưỡng quá nhiệt (hoặc dưới ngưỡng quá lạnh)"},
	{"NVM subsystem reliability is degraded by excessive media or internal errors", "độ tin cậy suy giảm do quá nhiều lỗi media hoặc lỗi nội bộ"},
	{"the media has been placed in read-only mode", "ổ đã chuyển sang chế độ chỉ đọc (read-only)"},
	{"the volatile memory backup device (power-loss protection) has failed", "bộ lưu điện cho bộ nhớ đệm (power-loss protection, tụ điện) đã hỏng"},
	{"the persistent memory region has become read-only or unreliable", "vùng persistent memory đã thành chỉ đọc hoặc không tin cậy"},
}

func nvmeRules(d *diskInfo) []model.Finding {
	s := d.Smart
	n := s.NVMe
	var fs []model.Finding
	if n == nil {
		n = &nvmeLog{}
	}
	cw := 0
	if n.CriticalWarning != nil {
		cw = *n.CriticalWarning
	}
	// Critical Warning (NVMe Base Spec, SMART/Health log byte 0): every bit
	// is a condition the controller itself flags as critical.
	if cw != 0 {
		var en, vi []string
		for i, b := range nvmeWarnBits {
			if cw&(1<<i) != 0 {
				en = append(en, fmt.Sprintf("bit %d: %s", i, b.en))
				vi = append(vi, fmt.Sprintf("bit %d: %s", i, b.vi))
			}
		}
		if len(en) == 0 {
			en, vi = []string{"reserved bits set"}, []string{"các bit dự phòng được bật"}
		}
		ev := []string{fmt.Sprintf("Critical Warning: 0x%02x", cw)}
		ev = append(ev, en...)
		if s.Passed != nil && !*s.Passed {
			ev = append(ev, "SMART overall-health self-assessment test result: FAILED")
		}
		extraEN, extraVI := "", ""
		if cw&(1<<3) != 0 {
			extraEN, extraVI = "The drive is read-only now: copy the data off before anything else.", "Ổ đã ở chế độ chỉ đọc: chép dữ liệu ra trước tiên."
		}
		if cw == 2 {
			extraEN, extraVI = "If only the temperature bit is set, fix the cooling first (airflow, heatsink) and check again.", "Nếu chỉ có bit nhiệt độ, xử lý tản nhiệt trước (luồng gió, heatsink) rồi kiểm tra lại."
		}
		fs = append(fs, d.finding("nvme_critical_warning", model.Crit,
			model.Tf("NVMe %s reports a critical warning (0x%02x)", "Ổ NVMe %s báo cảnh báo nghiêm trọng (0x%02x)", d.target(), cw),
			model.T("The controller raised its Critical Warning flags: "+strings.Join(en, "; ")+".", "Controller của ổ bật cờ Critical Warning: "+strings.Join(vi, "; ")+"."),
			d.replaceAction(extraEN, extraVI), ev))
		// Critical Warning sets Passed=false; do not report it twice.
	} else if s.Passed != nil && !*s.Passed {
		fs = append(fs, d.finding("smart_failed", model.Crit,
			model.Tf("Disk %s is failing: S.M.A.R.T. health check FAILED", "Ổ %s sắp hỏng: kiểm tra S.M.A.R.T. báo FAILED", d.target()),
			model.T("smartctl reports the drive's overall health as FAILED.", "smartctl báo tình trạng tổng thể của ổ là FAILED."),
			d.replaceAction("", ""), []string{"SMART overall-health self-assessment test result: FAILED", exitLine(s)}))
	}
	// Available spare below the vendor threshold (same condition as bit 0,
	// reported separately for controllers that do not set the bit).
	if n.AvailableSpare != nil && n.AvailableSpareThreshold != nil && *n.AvailableSpareThreshold > 0 &&
		*n.AvailableSpare < *n.AvailableSpareThreshold && cw&1 == 0 {
		fs = append(fs, d.finding("nvme_spare_low", model.Crit,
			model.Tf("NVMe %s has run out of spare blocks (%d%% < %d%%)", "Ổ NVMe %s đã cạn block dự phòng (%d%% < %d%%)", d.target(), *n.AvailableSpare, *n.AvailableSpareThreshold),
			model.T("The remaining spare capacity is below the threshold the vendor set; new bad blocks can no longer be replaced.",
				"Dung lượng dự phòng còn lại đã dưới ngưỡng của hãng; block hỏng mới sẽ không còn chỗ thay thế."),
			d.replaceAction("", ""),
			[]string{fmt.Sprintf("Available Spare: %d%%", *n.AvailableSpare), fmt.Sprintf("Available Spare Threshold: %d%%", *n.AvailableSpareThreshold)}))
	}
	// Media and Data Integrity Errors: unrecovered data integrity errors
	// (ECC, CRC, LBA tag mismatch). Any is a Warn: data could not be read
	// correctly at least once; the drive may still be usable.
	if n.MediaErrors != nil && *n.MediaErrors > 0 {
		ev := []string{fmt.Sprintf("Media and Data Integrity Errors: %d", *n.MediaErrors)}
		if n.NumErrLogEntries != nil {
			ev = append(ev, fmt.Sprintf("Error Information Log Entries: %d", *n.NumErrLogEntries))
		}
		fs = append(fs, d.finding("nvme_media_errors", model.Warn,
			model.Tf("NVMe %s has %s media/data integrity errors", "Ổ NVMe %s có %s lỗi media/toàn vẹn dữ liệu", d.target(), units.Thousands(*n.MediaErrors)),
			model.T("The controller detected unrecovered data integrity errors (ECC/CRC failures while reading the flash). Some data could not be read correctly at least once.",
				"Controller phát hiện lỗi toàn vẹn dữ liệu không khôi phục được (lỗi ECC/CRC khi đọc flash). Đã có lúc dữ liệu không đọc đúng được."),
			model.Tf("Back up %s. Run a file system / RAID check, and plan a replacement (%s), sooner if the count rises.",
				"Sao lưu %s. Kiểm tra file system / RAID và lên kế hoạch thay ổ (%s), sớm hơn nếu con số tăng.", d.target(), d.ident()), ev))
	}
	// Unsafe shutdowns: Info only when frequent.
	if n.UnsafeShutdowns != nil && *n.UnsafeShutdowns >= unsafeShutdownsInfo {
		fs = append(fs, d.finding("unsafe_shutdowns", model.Info,
			model.Tf("NVMe %s recorded %s unsafe shutdowns", "Ổ NVMe %s ghi nhận %s lần tắt nguồn đột ngột", d.target(), units.Thousands(*n.UnsafeShutdowns)),
			model.T("Each unsafe shutdown means power was lost (or the server was hard-reset) without the drive being told to flush its cache.",
				"Mỗi lần tắt đột ngột là một lần mất điện (hoặc reset cứng) mà ổ không kịp ghi bộ nhớ đệm."),
			model.T("Check the UPS/power supplies and avoid hard resets.", "Kiểm tra UPS/nguồn và tránh reset cứng máy."),
			[]string{fmt.Sprintf("Unsafe Shutdowns: %d", *n.UnsafeShutdowns), fmt.Sprintf("Power Cycles: %d", derefU(n.PowerCycles))}))
	}
	// Time spent above the warning/critical composite temperature.
	if (n.WarningTempTime != nil && *n.WarningTempTime > 0) || (n.CriticalCompTime != nil && *n.CriticalCompTime > 0) {
		fs = append(fs, d.finding("temperature_history", model.Info,
			model.Tf("NVMe %s has run hot in the past", "Ổ NVMe %s từng chạy quá nóng", d.target()),
			model.Tf("It spent %d minute(s) above its warning temperature and %d minute(s) above its critical temperature over its life.",
				"Trong suốt thời gian sử dụng, ổ đã chạy %d phút trên ngưỡng cảnh báo và %d phút trên ngưỡng nguy hiểm.", derefU(n.WarningTempTime), derefU(n.CriticalCompTime)),
			model.T("Check airflow over the NVMe drives (heatsinks, fan curve).", "Kiểm tra luồng gió qua các ổ NVMe (heatsink, tốc độ quạt)."),
			[]string{fmt.Sprintf("Warning Comp. Temperature Time: %d", derefU(n.WarningTempTime)), fmt.Sprintf("Critical Comp. Temperature Time: %d", derefU(n.CriticalCompTime))}))
	}
	return fs
}

// ---- SCSI / SAS ----

func scsiRules(d *diskInfo) []model.Finding {
	s := d.Smart
	var fs []model.Finding
	// SMART Health Status: informational exceptions (SPC-4). Anything other
	// than OK is a failure prediction by the drive.
	if s.Passed != nil && !*s.Passed {
		ev := []string{"SMART Health Status: " + firstNonEmpty(s.SCSIHealth, "FAILED")}
		if ex := exitLine(s); ex != "" {
			ev = append(ev, ex)
		}
		fs = append(fs, d.finding("smart_failed", model.Crit,
			model.Tf("Disk %s is failing: S.M.A.R.T. health status %s", "Ổ %s sắp hỏng: S.M.A.R.T. báo %s", d.target(), firstNonEmpty(s.SCSIHealth, "FAILED")),
			model.T("The drive raised a failure prediction (informational exception). Vendors replace drives under warranty on this.",
				"Ổ đã tự báo trước sắp hỏng (informational exception). Hãng chấp nhận bảo hành với lỗi này."),
			d.replaceAction("", ""), ev))
	}
	// Grown defect list: blocks remapped since manufacture (same meaning as
	// ATA reallocated sectors; same thresholds).
	if s.GrownDefects != nil && *s.GrownDefects > 0 {
		n := *s.GrownDefects
		sev := model.Warn
		action := model.Tf("Back up %s. Plan a replacement (%s) and check again in a few days: a rising count means the disk is degrading.",
			"Sao lưu %s. Lên kế hoạch thay ổ (%s) và kiểm tra lại sau vài ngày: số tăng lên nghĩa là ổ đang xuống cấp.", d.target(), d.ident())
		if n >= reallocCrit {
			sev = model.Crit
			action = d.replaceAction("", "")
		}
		fs = append(fs, d.finding("grown_defects", sev,
			model.Tf("Disk %s has %s grown defects", "Ổ %s có %s sector lỗi phát sinh (grown defects)", d.target(), units.Thousands(n)),
			model.T("The grown defect list counts blocks the drive has retired since it left the factory (the SAS equivalent of reallocated sectors).",
				"Grown defect list đếm số block ổ đã loại bỏ kể từ khi xuất xưởng (tương đương sector reallocated trên ổ SATA)."),
			action, []string{fmt.Sprintf("Elements in grown defect list: %d", n)}))
	}
	// Error counter log: "total uncorrected errors" are reads/writes/verifies
	// the drive could not recover — data was lost or not written.
	var unc []string
	var tot uint64
	for _, k := range []string{"read", "write", "verify"} {
		if v, ok := s.Uncorrected[k]; ok && v > 0 {
			unc = append(unc, fmt.Sprintf("%s: %d total uncorrected errors", k, v))
			tot += v
		}
	}
	if tot > 0 {
		fs = append(fs, d.finding("scsi_uncorrected", model.Crit,
			model.Tf("Disk %s has %s uncorrected read/write errors", "Ổ %s có %s lỗi đọc/ghi không sửa được", d.target(), units.Thousands(tot)),
			model.T("The drive's error counter log records operations its error recovery could not complete: data could not be read back or written.",
				"Bộ đếm lỗi của ổ ghi nhận các thao tác mà cơ chế phục hồi lỗi không hoàn thành được: dữ liệu không đọc lại hoặc không ghi được."),
			d.replaceAction("", ""), unc))
	}
	return fs
}

// ---- common rules ----

func selfTestRule(d *diskInfo) []model.Finding {
	s := d.Smart
	var bad, doubt []string
	for i, t := range s.SelfTests {
		if t.Result == 0 && t.Extended {
			break // a newer passed extended test supersedes older failures (man smartctl, bit 7)
		}
		line := fmt.Sprintf("#%d %s: %s at %d h", i+1, firstNonEmpty(t.Kind, "self-test"), t.Status, t.Hours)
		if t.LBA != "" {
			line += ", first failing LBA " + t.LBA
		}
		switch t.Result {
		case 1:
			bad = append(bad, line)
		case 2:
			doubt = append(doubt, line)
		}
	}
	if len(bad) == 0 && len(doubt) == 0 && exitBit(s, 7) {
		bad = append(bad, exitLine(s))
	}
	if len(bad) > 0 {
		return []model.Finding{d.finding("selftest_failed", model.Crit,
			model.Tf("Disk %s failed a S.M.A.R.T. self-test", "Ổ %s không qua bài tự kiểm tra S.M.A.R.T.", d.target()),
			model.T("The drive's own surface/electrical self-test failed (for example \"read failure\": a sector could not be read). No newer extended test has passed since.",
				"Bài tự kiểm tra của chính ổ đã thất bại (ví dụ \"read failure\": có sector không đọc được). Chưa có bài kiểm tra extended nào sau đó đạt."),
			d.replaceAction("", ""), bad)}
	}
	if len(doubt) > 0 {
		return []model.Finding{d.finding("selftest_failed", model.Warn,
			model.Tf("Disk %s: a S.M.A.R.T. self-test ended with an error", "Ổ %s: bài tự kiểm tra S.M.A.R.T. kết thúc với lỗi", d.target()),
			model.T("A self-test stopped with a fatal or unknown error.", "Một bài tự kiểm tra dừng do lỗi nghiêm trọng hoặc không xác định."),
			model.Tf("Run an extended test (smartctl -t long %s) and check the result with smartctl -l selftest %s.",
				"Chạy bài kiểm tra dài (smartctl -t long %s) rồi xem kết quả bằng smartctl -l selftest %s.", d.SmartDev, d.SmartDev), doubt)}
	}
	return nil
}

func tempRule(d *diskInfo) []model.Finding {
	s := d.Smart
	t := validTemp(s.TempC)
	if t == nil {
		return nil
	}
	ok := func(p *int) bool { return p != nil && *p >= 30 && *p <= 120 }
	warn, crit := 0, 0
	src := ""
	switch {
	case ok(s.TempWarn):
		warn, src = *s.TempWarn, "drive-reported limit"
	case ok(s.TempTrip):
		warn, src = *s.TempTrip-scsiTripMargin, "drive trip temperature"
	}
	if ok(s.TempCrit) {
		crit = *s.TempCrit
	} else if ok(s.TempTrip) {
		crit = *s.TempTrip
	}
	if warn == 0 {
		switch d.kind() {
		case "NVMe":
			warn = nvmeTempWarn
		case "SSD":
			warn = ssdTempWarn
		default:
			warn = hddTempWarn
		}
		src = "typical datasheet limit"
	}
	if crit > 0 && warn > crit {
		warn = crit
	}
	ev := []string{fmt.Sprintf("current %d °C, warning limit %d °C (%s)", *t, warn, src)}
	if crit > 0 {
		ev[0] += fmt.Sprintf(", critical limit %d °C", crit)
	}
	switch {
	case crit > 0 && *t >= crit:
		return []model.Finding{d.finding("temperature", model.Crit,
			model.Tf("Disk %s is overheating: %d °C (limit %d °C)", "Ổ %s quá nóng: %d °C (giới hạn %d °C)", d.target(), *t, crit),
			model.T("The temperature is at or above the drive's critical limit. The drive may throttle, go read-only or shut down, and heat this high damages it.",
				"Nhiệt độ đã chạm giới hạn nguy hiểm của ổ. Ổ có thể tự giảm tốc, chuyển sang chỉ đọc hoặc tự tắt; nhiệt độ cao như vậy làm hỏng ổ."),
			model.T("Fix the cooling now: check fans, airflow, blanking panels and the room temperature. Reduce the load if needed.",
				"Xử lý tản nhiệt ngay: kiểm tra quạt, luồng gió, tấm che khe trống và nhiệt độ phòng máy. Giảm tải nếu cần."), ev)}
	case *t >= warn:
		return []model.Finding{d.finding("temperature", model.Warn,
			model.Tf("Disk %s is running hot: %d °C (limit %d °C)", "Ổ %s đang nóng: %d °C (ngưỡng %d °C)", d.target(), *t, warn),
			model.T("The temperature is at or above the drive's maximum operating temperature. Sustained heat shortens drive life.",
				"Nhiệt độ đã chạm mức tối đa cho phép khi hoạt động. Chạy nóng lâu dài làm giảm tuổi thọ ổ."),
			model.T("Check fans, airflow and the room temperature.", "Kiểm tra quạt, luồng gió và nhiệt độ phòng máy."), ev)}
	}
	return nil
}

// wearCandidates lists vendor wear attributes whose normalised VALUE is the
// remaining life in percent (smartmontools drivedb.h names): 233
// Media_Wearout_Indicator (Intel), 231 SSD_Life_Left (Kingston/SandForce,
// Phison), 202 Percent_Lifetime_Remain (Micron/Crucial), 177
// Wear_Leveling_Count (Samsung), 169 Remaining_Lifetime_Perc (WD/SanDisk,
// Toshiba), 173 Wear_Leveling/Erase count (Micron, SanDisk) — in that order.
func wearCandidates(s *smartData) []*ataAttr {
	var out []*ataAttr
	want := []struct {
		id   int
		keys []string
	}{
		{233, []string{"wearout", "media_wear"}},
		{231, []string{"life"}},
		{202, []string{"lifetime", "life_remain", "percent_life"}},
		{177, []string{"wear_leveling", "wear_range"}},
		{169, []string{"life", "remain"}},
		{173, []string{"wear_leveling", "erase_count", "wear"}},
		{248, []string{"life"}},
	}
	for _, w := range want {
		a := s.attr(w.id)
		if a == nil || a.Value == nil || *a.Value > 100 || *a.Value < 0 {
			continue
		}
		n := strings.ToLower(a.Name)
		for _, k := range w.keys {
			if strings.Contains(n, k) {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// wearUsed returns the percentage of rated endurance used and a line that
// shows where it came from.
func wearUsed(s *smartData) (*int, string) {
	if s.Endurance != nil && *s.Endurance >= 0 && *s.Endurance <= 255 {
		return s.Endurance, fmt.Sprintf("percentage used %d%% (%s)", *s.Endurance, s.EndurSrc)
	}
	if s.RPM > 0 {
		return nil, ""
	}
	if c := wearCandidates(s); len(c) > 0 {
		u := 100 - *c[0].Value
		return &u, attrLine(c[0]) + fmt.Sprintf(" -> %d%% used", u)
	}
	return nil, ""
}

func wearRule(d *diskInfo) []model.Finding {
	u, line := wearUsed(d.Smart)
	if u == nil || *u < wearWarn {
		return nil
	}
	return []model.Finding{wearFinding(d, *u, line)}
}

func wearFinding(d *diskInfo, used int, line string) model.Finding {
	if used >= wearCrit {
		return d.finding("ssd_wear", model.Crit,
			model.Tf("SSD %s is worn out: %d%% of its rated endurance used", "SSD %s đã hết tuổi thọ: dùng %d%% độ bền danh định", d.target(), used),
			model.T("The drive has written as much data as it is rated for. Flash wears out with writes; past 100% the vendor no longer guarantees data retention and the drive may switch to read-only.",
				"Ổ đã ghi hết lượng dữ liệu danh định. Chip flash mòn dần theo số lần ghi; vượt 100% hãng không còn bảo đảm giữ dữ liệu và ổ có thể chuyển sang chỉ đọc."),
			d.replaceAction("", ""), []string{line})
	}
	return d.finding("ssd_wear", model.Warn,
		model.Tf("SSD %s is wearing out: %d%% of its rated endurance used", "SSD %s đang mòn: đã dùng %d%% độ bền danh định", d.target(), used),
		model.T("Flash wears out with writes. The drive still works, but it is approaching the end of its rated endurance.",
			"Chip flash mòn dần theo số lần ghi. Ổ vẫn chạy nhưng sắp hết độ bền danh định."),
		model.Tf("Order a replacement for %s (%s) and plan the swap. Check whether the workload writes more than expected.",
			"Đặt ổ thay thế cho %s (%s) và lên lịch thay. Kiểm tra xem tải ghi có lớn bất thường không.", d.target(), d.ident()),
		[]string{line})
}

func oldRule(d *diskInfo) []model.Finding {
	s := d.Smart
	if s.POH == nil || *s.POH < oldDiskHours {
		return nil
	}
	h := units.Hours(*s.POH)
	return []model.Finding{d.finding("old_disk", model.Info,
		model.T(fmt.Sprintf("Disk %s has been powered on for %s", d.target(), h.EN), fmt.Sprintf("Ổ %s đã chạy %s", d.target(), h.VI)),
		model.T("More than five years of power-on time: beyond the usual warranty and design life, and failure rates rise with age.",
			"Đã chạy hơn 5 năm: quá thời hạn bảo hành và tuổi thọ thiết kế thông thường; tỉ lệ hỏng tăng theo tuổi."),
		model.T("Plan a replacement in the next hardware refresh and keep backups current.", "Đưa ổ vào kế hoạch thay mới đợt nâng cấp tới và giữ bản sao lưu luôn cập nhật."),
		[]string{fmt.Sprintf("power-on hours: %d", *s.POH)})}
}
