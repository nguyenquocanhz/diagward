package ipmi

import "github.com/nguyenquocanhz/diagward/model"

// keyText holds the wording for one finding key: a title template taking
// the target, an explanation and the next steps.
type keyText struct {
	title  model.Text // %s = target
	detail model.Text
	action model.Text
}

var keyTexts = map[string]keyText{
	"psu_failed": {
		model.T("%s: power supply has failed", "%s: bộ nguồn bị hỏng"),
		model.T("The BMC reports a failure of this power supply. The server now depends on the remaining supplies; if it had no redundancy it is at risk of going down.",
			"BMC báo bộ nguồn này bị hỏng. Máy chủ đang chạy nhờ các bộ nguồn còn lại; nếu không có nguồn dự phòng thì máy có thể sập bất cứ lúc nào."),
		model.T("Check the PSU LED and reseat the supply once. If it still reports a failure, replace it: open a warranty case with the PSU serial number below.",
			"Xem đèn trên bộ nguồn và thử rút ra cắm lại một lần. Nếu vẫn báo lỗi, thay bộ nguồn: mở yêu cầu bảo hành kèm số serial bên dưới."),
	},
	"psu_ac_lost": {
		model.T("%s: power supply has no input power (AC lost)", "%s: bộ nguồn mất điện đầu vào (AC lost)"),
		model.T("The supply is installed but gets no (or out-of-range) AC input: unplugged cord, dead PDU outlet, tripped breaker or UPS problem. The server runs without power redundancy.",
			"Bộ nguồn vẫn gắn nhưng không có điện AC đầu vào (hoặc điện áp sai): dây nguồn lỏng/rút, ổ PDU hỏng, CB nhảy hoặc UPS có vấn đề. Máy chủ đang chạy không có nguồn dự phòng."),
		model.T("Check the power cord, the PDU outlet, the breaker and the UPS feeding this supply. If the feed is fine, swap cords/outlets with the healthy supply to tell a bad PSU from a bad feed; replace the PSU if the fault follows it.",
			"Kiểm tra dây nguồn, ổ cắm PDU, CB và UPS cấp cho bộ nguồn này. Nếu nguồn cấp vẫn tốt, đổi chéo dây/ổ cắm với bộ nguồn còn lại để phân biệt hỏng bộ nguồn hay hỏng nguồn cấp; nếu lỗi đi theo bộ nguồn thì thay bộ nguồn."),
	},
	"psu_predictive": {
		model.T("%s: power supply predicts a failure", "%s: bộ nguồn báo sắp hỏng"),
		model.T("The supply's own monitoring expects it to fail soon (fan, capacitors, temperature).",
			"Bộ nguồn tự giám sát và dự báo sắp hỏng (quạt, tụ, nhiệt độ)."),
		model.T("Plan a replacement soon and order the part now (serial below). Make sure the other supply is healthy.",
			"Lên kế hoạch thay sớm và đặt linh kiện ngay (serial bên dưới). Đảm bảo bộ nguồn còn lại đang tốt."),
	},
	"psu_absent": {
		model.T("%s: power supply bay is empty", "%s: khe nguồn đang trống"),
		model.T("No supply is installed in this bay, so the server has no power redundancy (normal if it was ordered with one supply).",
			"Khe này không gắn bộ nguồn nên máy chủ không có nguồn dự phòng (bình thường nếu máy được đặt mua với một bộ nguồn)."),
		model.T("If the server should have redundant power, install a matching supply.", "Nếu máy chủ cần nguồn dự phòng, hãy lắp thêm bộ nguồn cùng loại."),
	},
	"psu_inactive": {
		model.T("%s: power supply is inactive", "%s: bộ nguồn đang ở trạng thái không hoạt động"),
		model.T("The supply is in standby (for example Dell \"hot spare\" mode) or switched off.", "Bộ nguồn đang ở chế độ chờ (ví dụ chế độ \"hot spare\" của Dell) hoặc đã bị tắt."),
		model.T("Nothing to do if hot-spare mode is configured on purpose.", "Không cần làm gì nếu chế độ hot spare được cấu hình có chủ ý."),
	},
	"power_failed": {
		model.T("%s: power unit reports a failure", "%s: khối nguồn báo lỗi"),
		model.T("The BMC reports a failure of the power subsystem.", "BMC báo hệ thống cấp nguồn bị lỗi."),
		model.T("Check every power supply (see the PSU table) and the power feed; contact the vendor if no supply shows a fault.",
			"Kiểm tra từng bộ nguồn (xem bảng PSU) và nguồn điện cấp vào; liên hệ hãng nếu không bộ nguồn nào báo lỗi."),
	},
	"redundancy_lost": {
		model.T("%s: redundancy lost", "%s: mất dự phòng"),
		model.T("The server is running without a spare power supply or fan: one more failure takes it down or makes it overheat.",
			"Máy chủ đang chạy không còn bộ nguồn hoặc quạt dự phòng: chỉ cần hỏng thêm một cái là máy sẽ sập hoặc quá nhiệt."),
		model.T("Find the failed, missing or unplugged unit (PSU/fan tables and BMC log) and restore it.", "Tìm bộ nguồn/quạt bị hỏng, thiếu hoặc rút điện (xem bảng PSU/quạt và nhật ký BMC) rồi khắc phục."),
	},
	"fan_failed": {
		model.T("%s: fan has failed", "%s: quạt bị hỏng"),
		model.T("The BMC reports a fan failure. The other fans speed up to compensate, but cooling is reduced.",
			"BMC báo quạt bị hỏng. Các quạt khác sẽ tăng tốc để bù, nhưng khả năng làm mát đã giảm."),
		model.T("Replace the fan module (most server fans are hot-swap). Watch the temperatures until then.",
			"Thay module quạt (đa số quạt máy chủ thay nóng được). Theo dõi nhiệt độ cho tới khi thay."),
	},
	"fan_predictive": {
		model.T("%s: fan predicts a failure", "%s: quạt báo sắp hỏng"),
		model.T("The fan is degrading.", "Quạt đang xuống cấp."),
		model.T("Order a replacement fan and swap it at the next maintenance window.", "Đặt quạt thay thế và thay vào lần bảo trì gần nhất."),
	},
	"fan_absent": {
		model.T("%s: fan bay is empty", "%s: khe quạt đang trống"),
		model.T("No fan is installed in this bay. Normal on some configurations, a cooling problem on others.",
			"Khe này không gắn quạt. Bình thường với một số cấu hình, nhưng có thể gây thiếu làm mát với cấu hình khác."),
		model.T("Check the vendor's fan population rules for this configuration.", "Kiểm tra quy định lắp quạt của hãng cho cấu hình này."),
	},
	"drive_fault": {
		model.T("%s: drive fault reported by the BMC", "%s: BMC báo lỗi ổ cứng"),
		model.T("The backplane/RAID controller reported a drive fault to the BMC.", "Backplane/controller RAID đã báo lỗi ổ cứng cho BMC."),
		model.T("Back up now. Check the RAID state (see the RAID and disk sections), replace the drive in that bay and make sure the array rebuilds.",
			"Sao lưu dữ liệu ngay. Kiểm tra trạng thái RAID (xem phần RAID và ổ cứng), thay ổ ở khe đó và đảm bảo RAID rebuild xong."),
	},
	"drive_predictive": {
		model.T("%s: drive predicts a failure (BMC)", "%s: ổ cứng báo sắp hỏng (BMC)"),
		model.T("The drive's S.M.A.R.T. or the controller predicts a failure.", "S.M.A.R.T. của ổ hoặc controller dự báo ổ sắp hỏng."),
		model.T("Back up and plan the replacement now; check the disk section for the serial number.", "Sao lưu và lên kế hoạch thay ổ ngay; xem phần ổ cứng để lấy số serial."),
	},
	"raid_failed": {
		model.T("%s: drive is in a failed or degraded array", "%s: ổ nằm trong RAID đã hỏng hoặc đang suy giảm"),
		model.T("The controller reports the array this drive belongs to as critical (degraded) or failed.", "Controller báo RAID chứa ổ này đang ở trạng thái critical (suy giảm) hoặc đã hỏng."),
		model.T("Back up now, check the RAID section and replace the failed member.", "Sao lưu ngay, kiểm tra phần RAID và thay ổ hỏng."),
	},
	"raid_rebuild": {
		model.T("%s: RAID rebuild problem", "%s: sự cố rebuild RAID"),
		model.T("A rebuild was aborted or is running.", "Quá trình rebuild bị hủy hoặc đang chạy."),
		model.T("Check the RAID section; restart the rebuild and replace the drive if it aborts again.", "Kiểm tra phần RAID; chạy lại rebuild và thay ổ nếu vẫn bị hủy."),
	},
	"memory_ue": {
		model.T("%s: uncorrectable memory error", "%s: lỗi bộ nhớ không sửa được"),
		model.T("ECC could not correct this error: data may have been corrupted and the OS may have crashed. A DIMM, its slot or the CPU memory controller is failing.",
			"ECC không sửa được lỗi này: dữ liệu có thể đã hỏng và hệ điều hành có thể đã bị treo/sập. Thanh RAM, khe cắm hoặc bộ điều khiển bộ nhớ của CPU đang có vấn đề."),
		model.T("Replace the DIMM named in the event (see the memory section for its serial). If errors move with the slot rather than the DIMM, the mainboard or CPU is at fault: open a warranty case.",
			"Thay thanh RAM được nêu trong sự kiện (xem phần bộ nhớ để lấy serial). Nếu lỗi đi theo khe chứ không theo thanh RAM thì lỗi ở mainboard hoặc CPU: mở yêu cầu bảo hành."),
	},
	"memory_ce": {
		model.T("%s: corrected memory errors (ECC)", "%s: lỗi bộ nhớ đã được ECC sửa"),
		model.T("ECC corrected the errors, but the BMC only logs them when they repeat (or the logging limit was reached). A DIMM that keeps logging corrected errors is wearing out and often turns into uncorrectable errors.",
			"ECC đã sửa được lỗi, nhưng BMC chỉ ghi lại khi lỗi lặp lại nhiều (hoặc đã chạm giới hạn ghi log). Thanh RAM liên tục có lỗi được sửa là đang xuống cấp và thường dẫn tới lỗi không sửa được."),
		model.T("Plan to replace the DIMM named in the event (see the memory section for its serial). Reseating it is worth a try the first time.",
			"Lên kế hoạch thay thanh RAM được nêu trong sự kiện (xem phần bộ nhớ để lấy serial). Lần đầu có thể thử cắm lại thanh RAM."),
	},
	"memory_disabled": {
		model.T("%s: memory disabled by the firmware", "%s: RAM đã bị firmware vô hiệu hóa"),
		model.T("The BIOS took a DIMM out of service (usually after errors), so the server runs with less memory.",
			"BIOS đã ngắt một thanh RAM (thường do lỗi), máy chủ đang chạy với dung lượng RAM ít hơn."),
		model.T("Replace the DIMM named in the event, then re-enable it in the BIOS if needed.", "Thay thanh RAM được nêu trong sự kiện, sau đó bật lại trong BIOS nếu cần."),
	},
	"memory_overtemp": {
		model.T("%s: memory critically overheated", "%s: RAM quá nhiệt nghiêm trọng"),
		model.T("The DIMMs reached their critical temperature.", "Các thanh RAM đã chạm nhiệt độ tới hạn."),
		model.T("Check the fans, airflow baffles and blanking panels around the DIMMs.", "Kiểm tra quạt, tấm dẫn gió và tấm che khe trống quanh khu vực RAM."),
	},
	"cpu_error": {
		model.T("%s: processor error", "%s: lỗi CPU"),
		model.T("The BMC logged a fatal processor or machine-check error (IERR, uncorrectable MCE, FRB). The server usually crashes or resets when this happens.",
			"BMC ghi nhận lỗi CPU nghiêm trọng (IERR, machine check không sửa được, FRB). Khi xảy ra, máy chủ thường bị treo hoặc tự khởi động lại."),
		model.T("Read the full event in the BMC web interface, update the BIOS and BMC firmware, and contact the vendor: repeated IERR/MCE errors mean a CPU, mainboard or DIMM replacement.",
			"Xem chi tiết sự kiện trên giao diện web của BMC, cập nhật BIOS và firmware BMC, rồi liên hệ hãng: IERR/MCE lặp lại nghĩa là cần thay CPU, mainboard hoặc RAM."),
	},
	"cpu_ce": {
		model.T("%s: corrected processor errors", "%s: lỗi CPU đã được tự sửa"),
		model.T("The CPU corrected machine-check errors. Occasional ones are harmless; frequent ones point to a failing CPU, cache or memory.",
			"CPU đã tự sửa lỗi machine check. Thỉnh thoảng một lần thì vô hại; nếu thường xuyên thì CPU, cache hoặc RAM đang có vấn đề."),
		model.T("Check the CPU and memory sections; update the BIOS; contact the vendor if they keep growing.", "Xem phần CPU và bộ nhớ; cập nhật BIOS; liên hệ hãng nếu số lỗi tiếp tục tăng."),
	},
	"cpu_absent": {
		model.T("%s: processor socket is empty", "%s: socket CPU đang trống"),
		model.T("No CPU in this socket.", "Không có CPU trong socket này."),
		model.T("Normal on single-CPU configurations.", "Bình thường với cấu hình một CPU."),
	},
	"thermal_trip": {
		model.T("%s: thermal trip (overheat shutdown)", "%s: quá nhiệt khiến máy bị ngắt (thermal trip)"),
		model.T("A component got so hot that the hardware cut the power to protect itself.", "Một linh kiện nóng tới mức phần cứng phải tự ngắt điện để bảo vệ."),
		model.T("Find the cause before running loads again: fans, heatsink seating and paste, airflow, room temperature.", "Tìm nguyên nhân trước khi chạy tải trở lại: quạt, tản nhiệt và keo tản nhiệt, luồng gió, nhiệt độ phòng."),
	},
	"intrusion": {
		model.T("%s: chassis intrusion detected", "%s: phát hiện mở nắp thùng máy"),
		model.T("The chassis cover switch reports that the server was opened. On many boards the state latches until it is cleared, so it may be from an earlier service visit.",
			"Công tắc nắp thùng máy báo máy chủ đã bị mở. Trên nhiều bo mạch trạng thái này được giữ cho tới khi xóa, nên có thể là từ lần bảo trì trước."),
		model.T("Confirm with whoever had access. Close the cover properly, then clear the latch (BMC web interface; Supermicro: ipmitool raw 0x30 0x03).",
			"Xác nhận với người có quyền tiếp cận máy. Đóng nắp cẩn thận rồi xóa trạng thái (trên giao diện web BMC; Supermicro: ipmitool raw 0x30 0x03)."),
	},
	"pci_error": {
		model.T("%s: PCIe / system bus error", "%s: lỗi bus PCIe / hệ thống"),
		model.T("A card or the chipset reported a bus error (PCI SERR/PERR, bus uncorrectable/fatal). Fatal ones crash the server.",
			"Một card mở rộng hoặc chipset báo lỗi bus (PCI SERR/PERR, lỗi bus không sửa được/nghiêm trọng). Lỗi nghiêm trọng sẽ làm máy sập."),
		model.T("Find the slot/device in the BMC web log, reseat or replace that card, and update its firmware and the BIOS.",
			"Xác định khe/thiết bị trong nhật ký web của BMC, cắm lại hoặc thay card đó, cập nhật firmware của card và BIOS."),
	},
	"battery": {
		model.T("%s: battery low or failed", "%s: pin yếu hoặc đã hỏng"),
		model.T("A CMOS or RAID-cache battery is low or failed: the BIOS clock/settings or the RAID write cache are at risk.",
			"Pin CMOS hoặc pin cache RAID yếu/hỏng: đồng hồ, cấu hình BIOS hoặc cache ghi của RAID có thể bị ảnh hưởng."),
		model.T("Replace the battery at the next maintenance window.", "Thay pin vào lần bảo trì gần nhất."),
	},
	"config_error": {
		model.T("%s: configuration error", "%s: lỗi cấu hình"),
		model.T("The BMC/BIOS reports a configuration problem (mismatched power supplies, CPU or memory population).",
			"BMC/BIOS báo lỗi cấu hình (bộ nguồn không cùng loại, lắp CPU hoặc RAM sai quy định)."),
		model.T("Check that the parts match the vendor's rules (same PSU model and wattage, DIMM population order).",
			"Kiểm tra linh kiện đúng quy định của hãng (bộ nguồn cùng model và công suất, thứ tự lắp RAM)."),
	},
	"throttled": {
		model.T("%s: throttled", "%s: đang bị giảm hiệu năng (throttled)"),
		model.T("The component is slowed down because of temperature or power limits.", "Linh kiện bị giảm tốc vì nhiệt độ hoặc giới hạn công suất."),
		model.T("Check the cooling and the power supplies.", "Kiểm tra làm mát và bộ nguồn."),
	},
	"ac_lost": {
		model.T("%s: the server lost input power", "%s: máy chủ bị mất điện đầu vào"),
		model.T("All supplies lost AC at the same time: a power outage, tripped breaker, UPS fault or someone unplugged the server.",
			"Tất cả bộ nguồn mất điện AC cùng lúc: cúp điện, nhảy CB, UPS lỗi hoặc ai đó rút điện máy chủ."),
		model.T("Check the UPS and PDU logs for that time and whether the server should be on separate power feeds.",
			"Kiểm tra nhật ký UPS và PDU tại thời điểm đó và xem máy chủ có nên cắm vào hai nguồn điện riêng biệt không."),
	},
	"power_control": {
		model.T("%s: power control problem", "%s: sự cố điều khiển nguồn"),
		model.T("The system powered down unexpectedly (interlock, 240 VA protection or a soft-power failure).",
			"Hệ thống bị tắt nguồn bất thường (interlock, bảo vệ 240 VA hoặc lỗi điều khiển nguồn mềm)."),
		model.T("Check the BMC log details and the power supplies; contact the vendor if it repeats.", "Xem chi tiết nhật ký BMC và bộ nguồn; liên hệ hãng nếu lặp lại."),
	},
	"os_crash": {
		model.T("%s: operating system crash", "%s: hệ điều hành bị sập"),
		model.T("The OS stopped with a critical error (kernel panic / blue screen) and reported it to the BMC.", "Hệ điều hành dừng vì lỗi nghiêm trọng (kernel panic / màn hình xanh) và đã báo cho BMC."),
		model.T("Look at the logs section for the crash cause; check memory and CPU errors around the same time.", "Xem phần nhật ký để biết nguyên nhân; kiểm tra lỗi RAM và CPU quanh thời điểm đó."),
	},
	"watchdog": {
		model.T("%s: watchdog reset the server", "%s: watchdog đã reset máy"),
		model.T("The watchdog timer expired: the OS hung and the BMC reset or powered off the server.", "Bộ đếm watchdog hết hạn: hệ điều hành bị treo và BMC đã reset hoặc tắt máy chủ."),
		model.T("Find why the system hung (logs, memory/CPU errors, storage timeouts).", "Tìm nguyên nhân treo máy (nhật ký, lỗi RAM/CPU, ổ cứng không phản hồi)."),
	},
	"post_error": {
		model.T("%s: POST error", "%s: lỗi POST khi khởi động"),
		model.T("The BIOS reported a hardware error during power-on self test.", "BIOS báo lỗi phần cứng trong quá trình tự kiểm tra khi khởi động (POST)."),
		model.T("Read the error in the BMC/BIOS log and fix the named component.", "Xem lỗi trong nhật ký BMC/BIOS và xử lý linh kiện được nêu."),
	},
	"hw_failure": {
		model.T("%s: undetermined hardware failure", "%s: lỗi phần cứng chưa xác định"),
		model.T("The BIOS/BMC detected a hardware failure it could not attribute.", "BIOS/BMC phát hiện lỗi phần cứng nhưng không xác định được linh kiện."),
		model.T("Read the full event in the BMC web interface and contact the vendor.", "Xem chi tiết sự kiện trên giao diện web của BMC và liên hệ hãng."),
	},
	"sel_full": {
		model.T("BMC event log is full (%s)", "Nhật ký sự kiện BMC đã đầy (%s)"),
		model.T("When the SEL is full, new hardware events are dropped, so future faults go unrecorded.",
			"Khi SEL đầy, các sự kiện phần cứng mới sẽ bị bỏ, lỗi xảy ra sau này sẽ không được ghi lại."),
		model.T("Save the log first (ipmitool sel elist > sel-$(hostname)-$(date +%F).txt), then clear it: ipmitool sel clear.",
			"Lưu nhật ký trước (ipmitool sel elist > sel-$(hostname)-$(date +%F).txt), sau đó xóa: ipmitool sel clear."),
	},
	"state_asserted": {
		model.T("%s: BMC sensor is asserted", "%s: cảm biến BMC đang báo lỗi (asserted)"),
		model.T("This discrete sensor's fault state is asserted (Dell \"PG\"/\"FAIL\" sensors use this for power-good and failure signals).",
			"Cảm biến rời rạc này đang ở trạng thái lỗi (các cảm biến \"PG\"/\"FAIL\" của Dell dùng trạng thái này cho tín hiệu nguồn và lỗi)."),
		model.T("Check the sensor in the BMC web interface; contact the vendor if it stays asserted.", "Kiểm tra cảm biến trên giao diện web của BMC; liên hệ hãng nếu trạng thái không tự hết."),
	},
}

// fallbackText is used for keys without specific wording.
var fallbackText = keyText{
	model.T("%s: BMC sensor reports a problem", "%s: cảm biến BMC báo sự cố"),
	model.T("The BMC reports an abnormal state for this sensor.", "BMC báo cảm biến này ở trạng thái bất thường."),
	model.T("Check the event details in the BMC web interface (iDRAC, iLO, XCC...) and contact the vendor if it persists.",
		"Xem chi tiết trên giao diện web của BMC (iDRAC, iLO, XCC...) và liên hệ hãng nếu sự cố còn tiếp diễn."),
}

// thresholdTexts word threshold excursions per sensor class.
func thresholdText(class string, crit bool) keyText {
	switch class {
	case clTemp:
		return keyText{
			model.T("%s: temperature beyond its threshold", "%s: nhiệt độ vượt ngưỡng"),
			model.T("The BMC's own threshold for this temperature sensor is exceeded. Parts throttle, shut down or wear out faster.",
				"Nhiệt độ vượt ngưỡng do chính BMC đặt. Linh kiện sẽ giảm xung, tự tắt hoặc nhanh hỏng hơn."),
			model.T("Check the fans and airflow (blanking panels, cables, dust filters), the room/inlet temperature and the heatsinks.",
				"Kiểm tra quạt và luồng gió (tấm che khe trống, dây cáp, lưới lọc bụi), nhiệt độ phòng/khí vào và tản nhiệt."),
		}
	case clFan:
		return keyText{
			model.T("%s: fan speed beyond its threshold", "%s: tốc độ quạt vượt ngưỡng"),
			model.T("The fan runs slower (or faster) than the BMC allows: a failing or blocked fan, or a fan that is missing.",
				"Quạt quay chậm (hoặc nhanh) hơn mức BMC cho phép: quạt sắp hỏng, bị kẹt hoặc bị thiếu."),
			model.T("Check the fan module: reseat it, clean it, replace it if it stays out of range (most server fans are hot-swap). If slower non-original fans were fitted on purpose (common on Supermicro boards), lower the BMC thresholds instead, e.g. ipmitool sensor thresh FAN1 lower 100 200 300.",
				"Kiểm tra module quạt: cắm lại, vệ sinh, thay nếu vẫn ngoài ngưỡng (đa số quạt máy chủ thay nóng được). Nếu đã cố ý lắp quạt không chính hãng quay chậm hơn (hay gặp trên bo mạch Supermicro), hãy hạ ngưỡng trong BMC, ví dụ: ipmitool sensor thresh FAN1 lower 100 200 300."),
		}
	case clVoltage, clCurrent, clPower, clPSU:
		return keyText{
			model.T("%s: reading beyond its threshold", "%s: số đo vượt ngưỡng"),
			model.T("A voltage, current or power reading is outside the limits set by the BMC: a failing power supply, voltage regulator or overload.",
				"Điện áp, dòng điện hoặc công suất nằm ngoài ngưỡng của BMC: bộ nguồn sắp hỏng, mạch ổn áp có vấn đề hoặc quá tải."),
			model.T("Check the power supplies (PSU table), the input power and the load; have the PSU or mainboard checked under warranty if it persists.",
				"Kiểm tra các bộ nguồn (bảng PSU), điện đầu vào và tải; nếu còn tiếp diễn hãy bảo hành bộ nguồn hoặc mainboard."),
		}
	}
	return keyText{
		model.T("%s: BMC sensor beyond its threshold", "%s: cảm biến BMC vượt ngưỡng"),
		model.T("The reading is outside the thresholds configured in the BMC.", "Số đo nằm ngoài ngưỡng cấu hình trong BMC."),
		model.T("Check the sensor in the BMC web interface and the component it monitors.", "Kiểm tra cảm biến trên giao diện web của BMC và linh kiện mà nó giám sát."),
	}
}

func textFor(key string) keyText {
	if t, ok := keyTexts[key]; ok {
		return t
	}
	return fallbackText
}
