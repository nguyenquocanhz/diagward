package logs

import "github.com/nguyenquocanhz/diagward/model"

// ruleNames is the short name of each log rule for the event table, where
// the rule ID ("disk_medium_error") would otherwise show. The ID stays in
// EventFact.Rule and in the finding ID.
var ruleNames = map[string]model.Text{
	"bond_no_active_link":       model.T("Bond without an active port", "Bond không còn cổng hoạt động"),
	"controller_fault":          model.T("Storage controller fault", "Lỗi controller lưu trữ"),
	"controller_reset":          model.T("Storage controller reset", "Controller lưu trữ bị reset"),
	"cpu_thermal_throttle":      model.T("CPU thermal throttling", "CPU giảm xung do nhiệt"),
	"disk_ata_error":            model.T("ATA errors", "Lỗi ATA"),
	"disk_command_failed":       model.T("Disk command failed", "Lệnh tới ổ bị lỗi"),
	"disk_hardware_error":       model.T("Disk hardware error", "Lỗi phần cứng ổ"),
	"disk_io_error":             model.T("Disk I/O error", "Lỗi I/O trên ổ"),
	"disk_link_crc":             model.T("Disk link CRC errors", "Lỗi CRC đường truyền ổ"),
	"disk_medium_error":         model.T("Unreadable sectors (medium error)", "Sector không đọc được (medium error)"),
	"disk_offline":              model.T("Disk went offline", "Ổ bị offline"),
	"disk_protection_error":     model.T("Disk data protection error", "Lỗi kiểm tra toàn vẹn dữ liệu trên ổ"),
	"firmware_messages":         model.T("Firmware bug messages", "Thông báo lỗi firmware"),
	"fs_checksum_error":         model.T("Filesystem checksum errors", "Lỗi checksum hệ thống tệp"),
	"fs_error":                  model.T("Filesystem errors", "Lỗi hệ thống tệp"),
	"fs_errors_recorded":        model.T("Filesystem errors recorded", "Hệ thống tệp đã ghi nhận lỗi"),
	"fs_readonly":               model.T("Filesystem remounted read-only", "Hệ thống tệp bị chuyển sang chỉ đọc"),
	"hard_lockup":               model.T("Hard lockup", "CPU bị treo cứng (hard lockup)"),
	"hardware_panic":            model.T("Kernel panic from hardware", "Kernel panic do phần cứng"),
	"hung_task":                 model.T("Hung tasks (I/O stall)", "Tiến trình bị treo (nghẽn I/O)"),
	"ipmievd_event":             model.T("BMC event (ipmievd)", "Sự kiện BMC (ipmievd)"),
	"kernel_oops":               model.T("Kernel oops", "Kernel oops"),
	"kernel_panic":              model.T("Kernel panic", "Kernel panic"),
	"mce_corrected":             model.T("Corrected machine checks", "Machine check đã sửa"),
	"mce_uncorrected":           model.T("Uncorrected machine checks", "Machine check không sửa được"),
	"memory_corrected":          model.T("Corrected memory errors", "Lỗi RAM đã sửa"),
	"memory_page_offlined":      model.T("Memory pages taken offline", "Trang bộ nhớ bị loại bỏ"),
	"memory_uncorrected":        model.T("Uncorrected memory errors", "Lỗi RAM không sửa được"),
	"nic_link_down":             model.T("Network link down", "Cổng mạng mất link"),
	"nic_tx_timeout":            model.T("Network transmit timeout", "Card mạng bị treo khi gửi (TX timeout)"),
	"nmi_hardware":              model.T("Hardware NMI", "NMI phần cứng"),
	"nvme_controller_down":      model.T("NVMe controller down", "Controller NVMe ngừng hoạt động"),
	"nvme_timeout":              model.T("NVMe timeouts", "NVMe quá thời gian chờ"),
	"oom_cgroup":                model.T("Out of memory (cgroup)", "Hết bộ nhớ (cgroup)"),
	"oom_kill":                  model.T("Out of memory", "Hết bộ nhớ (OOM)"),
	"pcie_corrected":            model.T("Corrected PCIe errors", "Lỗi PCIe đã sửa"),
	"pcie_fatal":                model.T("Fatal PCIe errors", "Lỗi PCIe nghiêm trọng"),
	"pcie_uncorrected":          model.T("Uncorrected PCIe errors", "Lỗi PCIe không sửa được"),
	"raid_member_failed":        model.T("RAID member failed", "Ổ thành viên RAID bị hỏng"),
	"raid_spare_missing":        model.T("RAID without a spare", "RAID thiếu ổ dự phòng"),
	"smartd_device_lost":        model.T("Disk disappeared (smartd)", "Ổ bị mất (smartd)"),
	"smartd_failure":            model.T("S.M.A.R.T. failure (smartd)", "S.M.A.R.T. báo hỏng (smartd)"),
	"smartd_pending_sectors":    model.T("Pending sectors (smartd)", "Sector chờ thay (smartd)"),
	"smartd_temperature":        model.T("Disk temperature (smartd)", "Nhiệt độ ổ (smartd)"),
	"smartd_warning":            model.T("S.M.A.R.T. warning (smartd)", "Cảnh báo S.M.A.R.T. (smartd)"),
	"soft_lockup":               model.T("Soft lockup", "CPU bị treo mềm (soft lockup)"),
	"thermal_critical":          model.T("Critical temperature", "Nhiệt độ tới hạn"),
	"win_cpu_firmware_throttle": model.T("CPU throttled by firmware", "CPU bị firmware giảm xung"),
	"win_crash_dump_problem":    model.T("Crash dump problem", "Lỗi ghi crash dump"),
	"win_disk_bad_block":        model.T("Bad block on disk", "Ổ có block hỏng"),
	"win_disk_controller_error": model.T("Disk controller error", "Lỗi controller ổ cứng"),
	"win_disk_hardware_error":   model.T("Disk hardware error", "Lỗi phần cứng ổ"),
	"win_disk_io_retried":       model.T("Disk I/O retried", "I/O trên ổ phải thử lại"),
	"win_disk_not_ready":        model.T("Disk not ready", "Ổ chưa sẵn sàng"),
	"win_disk_paging_error":     model.T("Paging error on disk", "Lỗi paging trên ổ"),
	"win_disk_smart_predict":    model.T("Disk predicts failure (S.M.A.R.T.)", "Ổ báo sắp hỏng (S.M.A.R.T.)"),
	"win_low_memory":            model.T("Low memory", "Thiếu bộ nhớ"),
	"win_nic_link_down":         model.T("Network link down", "Cổng mạng mất link"),
	"win_nic_reset":             model.T("Network adapter reset", "Card mạng bị reset"),
	"win_ntfs_corruption":       model.T("NTFS corruption", "NTFS bị hỏng cấu trúc"),
	"win_ntfs_needs_chkdsk":     model.T("NTFS needs chkdsk", "NTFS cần chạy chkdsk"),
	"win_ntfs_write_error":      model.T("NTFS write error", "Lỗi ghi NTFS"),
	"win_storage_reset":         model.T("Storage reset", "Thiết bị lưu trữ bị reset"),
	"win_whea_corrected":        model.T("Corrected hardware errors (WHEA)", "Lỗi phần cứng đã sửa (WHEA)"),
	"win_whea_fatal":            model.T("Fatal hardware error (WHEA)", "Lỗi phần cứng nghiêm trọng (WHEA)"),
	"win_whea_pcie_corrected":   model.T("Corrected PCIe errors (WHEA)", "Lỗi PCIe đã sửa (WHEA)"),
}

// ruleName is the table name of a rule (its ID when it has none).
func ruleName(id string) model.Text {
	if t, ok := ruleNames[id]; ok {
		return t
	}
	return model.T(id, id)
}

// bootEndings is Vietnamese for BootFact.Ending and Source in the boot
// table.
var bootEndings = map[string]model.Text{
	"clean":               model.T("clean shutdown", "tắt máy bình thường"),
	"unclean":             model.T("unclean (crash, power loss or reset)", "tắt đột ngột (treo, mất điện hoặc reset)"),
	"panic":               model.T("kernel panic", "kernel panic"),
	"shutdown_incomplete": model.T("shutdown did not finish", "tắt máy không hoàn tất"),
	"running":             model.T("running", "đang chạy"),
	"unknown":             model.T("unknown", "không rõ"),
}

func bootEnding(s string) model.Text {
	if t, ok := bootEndings[s]; ok {
		return t
	}
	return model.T(s, s)
}

// winLevel is a Windows event level for the summary table.
func winLevel(l int) model.Text {
	switch l {
	case 1:
		return model.T("critical", "nghiêm trọng")
	case 2:
		return model.T("error", "lỗi")
	case 3:
		return model.T("warning", "cảnh báo")
	}
	return model.Text{}
}

// targetWords is Vietnamese for the generic targets some rules use when a
// log line names no device.
var targetWords = map[string]string{
	"disk":   "ổ cứng",
	"memory": "bộ nhớ",
	"system": "hệ thống",
}

// targetCell is an event target for the table.
func targetCell(s string) model.Text {
	if v, ok := targetWords[s]; ok {
		return model.T(s, v)
	}
	return model.T(s, s)
}
