package logs

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// winEvent is one event as written by collect/windows/60-logs.ps1.
type winEvent struct {
	T  string   `json:"t"`
	P  string   `json:"p"`
	ID int      `json:"id"`
	L  int      `json:"l"` // 1 critical, 2 error, 3 warning, 4 information
	M  string   `json:"m"`
	X  []string `json:"x"`

	time time.Time
}

// WinCount is one provider/ID line of the error/warning summary.
type WinCount struct {
	Provider string `json:"provider"`
	ID       int    `json:"id"`
	Level    int    `json:"level"`
	Count    int    `json:"count"`
	Last     string `json:"last,omitempty"`
}

func (e *winEvent) raw() string {
	lvl := map[int]string{1: "Critical", 2: "Error", 3: "Warning", 4: "Information"}[e.L]
	return fmt.Sprintf("%s %s %d %s: %s", e.time.UTC().Format("2006-01-02 15:04:05Z"), e.P, e.ID, lvl, e.M)
}

var (
	reHarddisk = regexp.MustCompile(`(?i)\\Device\\Harddisk(\d+)\\`)
	reRaidPort = regexp.MustCompile(`(?i)\\Device\\RaidPort(\d+)`)
	reVolume   = regexp.MustCompile(`^[A-Za-z]:$`)
	reHDVolume = regexp.MustCompile(`(?i)\\Device\\HarddiskVolume\d+`)
	reStorPort = regexp.MustCompile(`(?i)^(stor\w*|iaStor\w*|LSI_\w+|megasas\w*|percsas\w*|HpCISSs\d*|HpSAMD|SmartPqi|arcsas|ADPU320|mpt\w*|ql2\w+|elx\w+|nvme\w*|vhdmp|UASPStor|USBSTOR|amd_?sata|amdxata|mvs\w*|RSTe\w*|vsmraid|3ware|MegaSR\w*|SmartRAID\w*)$`)
	reNICIntel = regexp.MustCompile(`(?i)^(e1\w*express|e1\w*65|ixgb\w*|ixn\w*|ixs\w*|ixt\w*|i40e\w*|icea\w*|iavf\w*)$`)
	reNICBcm   = regexp.MustCompile(`(?i)^(b57nd60\w*|l2nd\w*|bxnd\w*|bxvbd\w*|bnxtnd\w*|q57nd60\w*|evbd\w*|qebdrv\w*)$`)
	reNICMlx   = regexp.MustCompile(`(?i)^(mlx4\w*|mlx5\w*|ibbus)$`)
	reUSBStor  = regexp.MustCompile(`(?i)^(UASPStor|USBSTOR)$`)
	reBugcheck = regexp.MustCompile(`(?i)0x([0-9a-f]{1,8})\b`)
)

func (e *winEvent) prop(i int) string {
	if i < len(e.X) {
		return strings.TrimSpace(e.X[i])
	}
	return ""
}

// diskTarget names the physical disk from "\Device\Harddisk1\DR1".
func (e *winEvent) diskTarget() string {
	for _, s := range append(append([]string{}, e.X...), e.M) {
		if m := reHarddisk.FindStringSubmatch(s); m != nil {
			return "PhysicalDrive" + m[1]
		}
	}
	return "disk"
}

func (e *winEvent) portTarget() string {
	for _, s := range append(append([]string{}, e.X...), e.M) {
		if m := reRaidPort.FindStringSubmatch(s); m != nil {
			return "RaidPort" + m[1] + " (" + e.P + ")"
		}
	}
	return e.P
}

func (e *winEvent) volumeTarget() string {
	for _, s := range e.X {
		s = strings.TrimSpace(s)
		if reVolume.MatchString(s) {
			return strings.ToUpper(s)
		}
	}
	for _, s := range e.X {
		if m := reHDVolume.FindString(s); m != "" {
			return m
		}
	}
	return "volume"
}

// ---- Windows specs ----

var (
	wActDisk = model.T(
		"Back up the data on {t} now. Find the disk (Get-PhysicalDisk, Get-StorageReliabilityCounter, or the RAID controller tool) and check its S.M.A.R.T./health status with smartctl or the vendor tool. Replace it if it reports errors; if it is in a RAID set or Storage Spaces pool, check the other members first.",
		"Sao lưu dữ liệu trên {t} ngay. Xác định ổ (Get-PhysicalDisk, Get-StorageReliabilityCounter hoặc công cụ của card RAID) và kiểm tra S.M.A.R.T./tình trạng bằng smartctl hoặc công cụ của hãng. Thay ổ nếu có lỗi; nếu ổ nằm trong RAID hoặc Storage Spaces, kiểm tra các ổ còn lại trước.")
	wActStor = model.T(
		"Check the disks and the controller behind {t}: cables/backplane, controller and disk firmware, driver version. Many resets/timeouts in a short time mean a disk is hanging or the controller is failing.",
		"Kiểm tra các ổ và controller phía sau {t}: cáp/backplane, firmware controller và ổ, phiên bản driver. Nhiều lần reset/timeout trong thời gian ngắn nghĩa là có ổ bị treo hoặc controller sắp hỏng.")
	wActNTFS = model.T(
		"Check the disk under {t} first, then run chkdsk {t} /scan (online) and, in a maintenance window, chkdsk {t} /f (or Repair-Volume {t} -OfflineScanAndFix). Restore damaged files from backup.",
		"Kiểm tra ổ chứa {t} trước, sau đó chạy chkdsk {t} /scan (online) và trong giờ bảo trì chạy chkdsk {t} /f (hoặc Repair-Volume {t} -OfflineScanAndFix). Khôi phục file hỏng từ bản sao lưu.")
	wActWHEA = model.T(
		"Open the event details (Event Viewer > System > WHEA-Logger) to see the component (processor, memory, PCI Express) and its location, and check the BMC/iDRAC/iLO event log at the same time. Update BIOS/firmware; replace the reported DIMM, CPU or card if errors continue.",
		"Mở chi tiết sự kiện (Event Viewer > System > WHEA-Logger) để xem thành phần (processor, memory, PCI Express) và vị trí, đồng thời xem log sự kiện BMC/iDRAC/iLO cùng thời điểm. Cập nhật BIOS/firmware; thay thanh RAM, CPU hoặc card được báo nếu lỗi còn tiếp diễn.")
	wActNIC = model.T(
		"Check the cable, transceiver and switch port of {t}; look at the switch log. Update the NIC driver/firmware and disable power saving on the adapter (Device Manager > Power Management, Energy-Efficient Ethernet). Replace the NIC if the link keeps dropping.",
		"Kiểm tra cáp, module quang và cổng switch của {t}; xem log switch. Cập nhật driver/firmware card mạng và tắt tiết kiệm điện trên card (Device Manager > Power Management, Energy-Efficient Ethernet). Thay card mạng nếu link vẫn rớt.")

	wsBadBlock = &spec{ID: "win_disk_bad_block", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t} has bad blocks (disk event 7)", "Ổ {t} có bad block (sự kiện disk 7)"),
		Detail: model.T("Windows could not read or write a block on {t}: the disk reported a media error.", "Windows không đọc/ghi được block trên {t}: ổ báo lỗi bề mặt."),
		Action: wActDisk}
	wsSmart = &spec{ID: "win_disk_smart_predict", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t}: S.M.A.R.T. predicts failure (disk event 52)", "Ổ {t}: S.M.A.R.T. dự báo sắp hỏng (sự kiện disk 52)"),
		Detail: model.T("The disk's own self-monitoring says it is likely to fail soon.", "Cơ chế tự giám sát của ổ báo ổ có khả năng hỏng trong thời gian tới."),
		Action: wActDisk}
	wsHWFail = &spec{ID: "win_disk_hardware_error", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t}: I/O failed due to a hardware error (disk event 154)", "Ổ {t}: I/O lỗi do lỗi phần cứng (sự kiện disk 154)"),
		Detail: model.T("An I/O request to {t} failed because of a hardware error.", "Một yêu cầu I/O tới {t} thất bại vì lỗi phần cứng."),
		Action: wActDisk}
	wsPaging = &spec{ID: "win_disk_paging_error", Comp: model.CompDisk, Sev: model.Warn, CritAt: 20,
		Title:  model.T("Disk {t}: errors during paging I/O (disk event 51)", "Ổ {t}: lỗi khi đọc/ghi trang bộ nhớ (sự kiện disk 51)"),
		Detail: model.T("An I/O error happened while Windows was paging to/from {t}. Usually the disk, its cable or controller; a removed USB disk also logs it.", "Có lỗi I/O khi Windows đọc/ghi trang bộ nhớ trên {t}. Thường do ổ, cáp hoặc controller; rút ổ USB đang dùng cũng sinh ra sự kiện này."),
		Action: wActDisk}
	wsCtrlErr = &spec{ID: "win_disk_controller_error", Comp: model.CompDisk, Sev: model.Warn, CritAt: 20,
		Title:  model.T("Disk {t}: controller errors (event 11)", "Ổ {t}: lỗi controller (sự kiện 11)"),
		Detail: model.T("The storage driver reported a controller error for {t}.", "Driver lưu trữ báo lỗi controller với {t}."),
		Action: wActStor}
	wsRetried = &spec{ID: "win_disk_io_retried", Comp: model.CompDisk, Sev: model.Warn, Decay: true, CritAt: 100,
		Title:  model.T("Disk {t}: I/O operations had to be retried (disk event 153)", "Ổ {t}: thao tác I/O phải thực hiện lại (sự kiện disk 153)"),
		Detail: model.T("Requests to {t} timed out and were retried. A slow or failing disk, cable, controller, or an overloaded SAN path.", "Yêu cầu tới {t} bị timeout và phải thử lại. Do ổ chậm hoặc sắp hỏng, cáp, controller, hoặc đường SAN quá tải."),
		Action: wActStor}
	wsNotReady = &spec{ID: "win_disk_not_ready", Comp: model.CompDisk, Sev: model.Warn, Decay: true,
		Title:  model.T("Disk {t} was not ready or was surprise-removed", "Ổ {t} chưa sẵn sàng hoặc bị rút bất ngờ"),
		Detail: model.T("Windows reported {t} as not ready (event 15) or surprise removed (event 157).", "Windows báo {t} chưa sẵn sàng (sự kiện 15) hoặc bị rút bất ngờ (sự kiện 157)."),
		Action: model.T("If {t} was not removed on purpose, check its slot/cable and its health; a disk that drops off and comes back is failing.", "Nếu {t} không bị rút có chủ đích, kiểm tra khe/cáp và tình trạng ổ; ổ tự rớt ra rồi nhận lại là ổ sắp hỏng.")}
	wsReset = &spec{ID: "win_storage_reset", Comp: model.CompDisk, Sev: model.Warn, Decay: true, CritAt: 20,
		Title:  model.T("Storage {t}: device resets/timeouts (event 129/9)", "Lưu trữ {t}: thiết bị bị reset/timeout (sự kiện 129/9)"),
		Detail: model.T("The storage driver had to reset a device behind {t} because it stopped responding (each reset stalls I/O for about 30 seconds). USBSTOR/UASPStor are USB disks.", "Driver lưu trữ phải reset thiết bị phía sau {t} vì không phản hồi (mỗi lần reset làm I/O treo khoảng 30 giây). USBSTOR/UASPStor là ổ USB."),
		Action: wActStor}
	wsNtfsCorrupt = &spec{ID: "win_ntfs_corruption", Comp: model.CompFilesystem, Sev: model.Warn, CritAt: 5,
		Title:  model.T("NTFS corruption detected on {t} (Ntfs event 55)", "Phát hiện hỏng cấu trúc NTFS trên {t} (sự kiện Ntfs 55)"),
		Detail: model.T("NTFS found damaged file system structures on {t}. Often follows disk errors or power loss.", "NTFS phát hiện cấu trúc filesystem bị hỏng trên {t}. Thường xảy ra sau lỗi ổ hoặc mất điện."),
		Action: wActNTFS}
	wsNtfsChkdsk = &spec{ID: "win_ntfs_needs_chkdsk", Comp: model.CompFilesystem, Sev: model.Crit,
		Title:  model.T("Volume {t} needs an offline chkdsk (Ntfs event 98)", "Phân vùng {t} cần chạy chkdsk offline (sự kiện Ntfs 98)"),
		Detail: model.T("NTFS could not repair {t} online; it must be taken offline for a full chkdsk.", "NTFS không tự sửa được {t} khi đang chạy; cần đưa offline để chạy chkdsk đầy đủ."),
		Action: wActNTFS}
	wsNtfsWarn = &spec{ID: "win_ntfs_write_error", Comp: model.CompFilesystem, Sev: model.Warn, Min: 5, Below: model.Info, Decay: true,
		Title:  model.T("NTFS could not write data or its log on volume {t} (Ntfs 50/137/140)", "NTFS không ghi được dữ liệu hoặc log trên phân vùng {t} (Ntfs 50/137/140)"),
		Detail: model.T("Delayed writes or transaction log flushes to {t} failed; data written at that time may be lost. A removed USB disk also causes it.", "Ghi trễ hoặc ghi log giao dịch xuống {t} thất bại; dữ liệu ghi lúc đó có thể bị mất. Rút ổ USB cũng gây ra lỗi này."),
		Action: wActNTFS}
	wsDump = &spec{ID: "win_crash_dump_problem", Comp: model.CompSystem, Sev: model.Info,
		Title:  model.T("Windows could not write a crash dump (volmgr 45/46/161/162)", "Windows không ghi được file crash dump (volmgr 45/46/161/162)"),
		Detail: model.T("Dump creation failed or the dump settings are invalid, so the cause of a blue screen may not be recorded.", "Không tạo được file dump hoặc cấu hình dump không hợp lệ, nên nguyên nhân màn hình xanh có thể không được ghi lại."),
		Action: model.T("Check System Properties > Startup and Recovery (dump type, page file size on C:, free space).", "Kiểm tra System Properties > Startup and Recovery (loại dump, dung lượng page file trên C:, dung lượng trống).")}
	wsThrottle = &spec{ID: "win_cpu_firmware_throttle", Comp: model.CompThermal, Sev: model.Warn, Min: 5, Below: model.Info, Decay: true,
		Title:  model.T("CPU speed was limited by the system firmware (Kernel-Processor-Power 37)", "Tốc độ CPU bị firmware giới hạn (Kernel-Processor-Power 37)"),
		Detail: model.T("Firmware reduced the processor speed, usually because of temperature or a power cap (BIOS power profile, BMC power capping, a failed PSU).", "Firmware đã giảm tốc độ CPU, thường do nhiệt độ hoặc giới hạn công suất (power profile trong BIOS, power capping của BMC, PSU hỏng)."),
		Action: model.T("Check temperatures, fans and PSUs in the BMC; check the BIOS power profile (set \"Maximum Performance\" on servers) and BMC power capping.", "Kiểm tra nhiệt độ, quạt và nguồn trong BMC; kiểm tra power profile trong BIOS (máy chủ nên đặt \"Maximum Performance\") và power capping của BMC.")}
	wsLowMem = &spec{ID: "win_low_memory", Comp: model.CompMemory, Sev: model.Warn, Decay: true,
		Title:  model.T("Windows ran low on virtual memory (Resource-Exhaustion-Detector 2004)", "Windows thiếu bộ nhớ ảo (Resource-Exhaustion-Detector 2004)"),
		Detail: model.T("RAM plus page file was nearly exhausted. This is a capacity problem, not a hardware fault; the event names the processes that used the most memory.", "RAM cộng page file gần cạn. Đây là thiếu dung lượng, không phải lỗi phần cứng; sự kiện có liệt kê tiến trình dùng nhiều bộ nhớ nhất."),
		Action: model.T("Look at the processes named in the event, limit or fix them, enlarge the page file or add RAM.", "Xem các tiến trình được nêu trong sự kiện, giới hạn hoặc sửa chúng, tăng page file hoặc nâng RAM.")}
	wsWHEAFatal = &spec{ID: "win_whea_fatal", Comp: model.CompCPU, Sev: model.Crit,
		Title:  model.T("Fatal hardware error reported by WHEA ({t})", "WHEA báo lỗi phần cứng nghiêm trọng ({t})"),
		Detail: model.T("The Windows Hardware Error Architecture logged an uncorrectable hardware error (WHEA-Logger events 1/18/20/46 at error level). These normally crash the server (stop code 0x124).", "Windows Hardware Error Architecture ghi nhận lỗi phần cứng không sửa được (WHEA-Logger 1/18/20/46 mức Error). Lỗi này thường làm máy chủ màn hình xanh (stop code 0x124)."),
		Action: wActWHEA}
	wsWHEACorr = &spec{ID: "win_whea_corrected", Comp: model.CompCPU, Sev: model.Warn, Decay: true,
		Title:  model.T("Corrected hardware errors reported by WHEA ({t})", "WHEA báo lỗi phần cứng đã được sửa ({t})"),
		Detail: model.T("WHEA logged corrected machine-check or memory errors (WHEA-Logger 19/47). No data was lost, but repeated errors point to a DIMM or CPU that is degrading.", "WHEA ghi nhận lỗi machine check hoặc lỗi RAM đã được sửa (WHEA-Logger 19/47). Không mất dữ liệu, nhưng lỗi lặp lại cho thấy thanh RAM hoặc CPU đang xuống cấp."),
		Action: wActWHEA}
	wsWHEAPCIe = &spec{ID: "win_whea_pcie_corrected", Comp: model.CompSystem, Sev: model.Warn, Min: 20, Below: model.Info, Decay: true,
		Title:  model.T("Corrected PCI Express errors reported by WHEA", "WHEA báo lỗi PCI Express đã được sửa"),
		Detail: model.T("WHEA-Logger event 17: PCIe Advanced Error Reporting saw corrected link errors. A steady stream points to a card, riser or slot with a marginal connection, or to PCIe power saving (ASPM).", "WHEA-Logger 17: PCIe AER ghi nhận lỗi đường truyền đã được sửa. Lỗi liên tục cho thấy card, riser hoặc khe cắm tiếp xúc kém, hoặc do chế độ tiết kiệm điện PCIe (ASPM)."),
		Action: wActWHEA}
	wsNICDown = &spec{ID: "win_nic_link_down", Comp: model.CompNetwork, Sev: model.Warn, Min: 4, Below: model.Info, Decay: true,
		Title:  model.T("Network link on {t} went down", "Link mạng trên {t} bị rớt"),
		Detail: model.T("The NIC driver reported the link as down. Once can be a planned change; repeated drops mean a bad cable, transceiver, switch port or NIC.", "Driver card mạng báo mất link. Một lần có thể do thay đổi có kế hoạch; rớt nhiều lần là do cáp, module quang, cổng switch hoặc card mạng lỗi."),
		Action: wActNIC}
	wsNICReset = &spec{ID: "win_nic_reset", Comp: model.CompNetwork, Sev: model.Warn, Decay: true,
		Title:  model.T("Network adapter hung and was reset (NDIS {t})", "Card mạng bị treo và phải reset (NDIS {t})"),
		Detail: model.T("NDIS reset a network adapter that stopped responding (10400) or whose driver reported a fatal error (10317).", "NDIS phải reset card mạng vì không phản hồi (10400) hoặc driver báo lỗi nghiêm trọng (10317)."),
		Action: wActNIC}
)

// classifyWin maps one event to a spec and a target (nil = not a pattern).
func classifyWin(e *winEvent) (*spec, string) {
	p := strings.ToLower(e.P)
	switch p {
	case "microsoft-windows-whea-logger":
		// Classify by level, not by the (localised) text: WHEA writes fatal
		// errors at Error/Critical level and corrected ones as Warnings.
		comp := "CPU"
		switch e.ID {
		case 46, 47:
			comp = "memory"
		case 17, 20:
			comp = "PCIe"
		}
		if e.L == 1 || e.L == 2 {
			return wsWHEAFatal, comp
		}
		if e.ID == 17 {
			return wsWHEAPCIe, "PCIe"
		}
		return wsWHEACorr, comp
	case "disk":
		switch e.ID {
		case 7:
			return wsBadBlock, e.diskTarget()
		case 52:
			return wsSmart, e.diskTarget()
		case 154:
			return wsHWFail, e.diskTarget()
		case 51:
			return wsPaging, e.diskTarget()
		case 11:
			return wsCtrlErr, e.diskTarget()
		case 153:
			return wsRetried, e.diskTarget()
		case 15, 157:
			return wsNotReady, e.diskTarget()
		}
	case "ntfs", "microsoft-windows-ntfs":
		switch e.ID {
		case 55:
			return wsNtfsCorrupt, e.volumeTarget()
		case 98:
			return wsNtfsChkdsk, e.volumeTarget()
		case 50, 137, 140:
			return wsNtfsWarn, e.volumeTarget()
		}
	case "volmgr":
		switch e.ID {
		case 45, 46, 161, 162:
			return wsDump, "dump"
		}
	case "microsoft-windows-kernel-processor-power":
		if e.ID == 37 {
			return wsThrottle, "CPU"
		}
	case "microsoft-windows-resource-exhaustion-detector":
		if e.ID == 2004 {
			return wsLowMem, "RAM"
		}
	case "microsoft-windows-ndis":
		if e.ID == 10400 || e.ID == 10317 {
			return wsNICReset, strconv.Itoa(e.ID)
		}
	}
	if reStorPort.MatchString(e.P) {
		switch e.ID {
		case 9, 129:
			return wsReset, e.portTarget()
		case 11:
			return wsCtrlErr, e.portTarget()
		}
	}
	if (reNICIntel.MatchString(e.P) && e.ID == 27) || (reNICBcm.MatchString(e.P) && e.ID == 4) || (reNICMlx.MatchString(e.P) && e.ID == 14) {
		return wsNICDown, e.P
	}
	return nil, ""
}

// Stop codes (Microsoft "Bug check code reference") with what they usually
// point at. hw=true means the code itself reports a hardware error.
var stopCodes = map[uint64]struct {
	name string
	hw   bool
	hint model.Text
}{
	0x0A:  {"IRQL_NOT_LESS_OR_EQUAL", false, model.T("usually a driver", "thường do driver")},
	0x19:  {"BAD_POOL_HEADER", false, model.T("a driver or faulty RAM", "driver hoặc RAM lỗi")},
	0x1A:  {"MEMORY_MANAGEMENT", false, model.T("faulty RAM or a driver", "RAM lỗi hoặc driver")},
	0x1E:  {"KMODE_EXCEPTION_NOT_HANDLED", false, model.T("usually a driver", "thường do driver")},
	0x24:  {"NTFS_FILE_SYSTEM", false, model.T("disk or file system corruption", "lỗi ổ hoặc hỏng filesystem")},
	0x3B:  {"SYSTEM_SERVICE_EXCEPTION", false, model.T("usually a driver", "thường do driver")},
	0x50:  {"PAGE_FAULT_IN_NONPAGED_AREA", false, model.T("a driver or faulty RAM", "driver hoặc RAM lỗi")},
	0x77:  {"KERNEL_STACK_INPAGE_ERROR", false, model.T("the disk or controller holding the page file", "ổ hoặc controller chứa page file")},
	0x7A:  {"KERNEL_DATA_INPAGE_ERROR", false, model.T("the disk or controller holding the page file", "ổ hoặc controller chứa page file")},
	0x7B:  {"INACCESSIBLE_BOOT_DEVICE", false, model.T("the boot disk/controller or its driver", "ổ boot/controller hoặc driver của nó")},
	0x7E:  {"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", false, model.T("usually a driver", "thường do driver")},
	0x7F:  {"UNEXPECTED_KERNEL_MODE_TRAP", false, model.T("often hardware (RAM, CPU) or a driver", "thường do phần cứng (RAM, CPU) hoặc driver")},
	0x80:  {"NMI_HARDWARE_FAILURE", true, model.T("a hardware failure signalled by NMI", "lỗi phần cứng báo qua NMI")},
	0x9C:  {"MACHINE_CHECK_EXCEPTION", true, model.T("a CPU/memory hardware error", "lỗi phần cứng CPU/RAM")},
	0x9F:  {"DRIVER_POWER_STATE_FAILURE", false, model.T("a driver", "driver")},
	0xBE:  {"ATTEMPTED_WRITE_TO_READONLY_MEMORY", false, model.T("usually a driver", "thường do driver")},
	0xC2:  {"BAD_POOL_CALLER", false, model.T("a driver", "driver")},
	0xD1:  {"DRIVER_IRQL_NOT_LESS_OR_EQUAL", false, model.T("a driver", "driver")},
	0xE2:  {"MANUALLY_INITIATED_CRASH", false, model.T("someone forced the crash (keyboard or a BMC NMI)", "có người chủ động gây crash (bàn phím hoặc NMI từ BMC)")},
	0xED:  {"UNMOUNTABLE_BOOT_VOLUME", false, model.T("the boot disk or file system", "ổ boot hoặc filesystem")},
	0xEF:  {"CRITICAL_PROCESS_DIED", false, model.T("a system process died (disk errors are a common cause)", "một tiến trình hệ thống bị chết (lỗi ổ là nguyên nhân hay gặp)")},
	0xF4:  {"CRITICAL_OBJECT_TERMINATION", false, model.T("often the disk/controller of the system volume", "thường do ổ/controller của phân vùng hệ thống")},
	0x101: {"CLOCK_WATCHDOG_TIMEOUT", false, model.T("a CPU core stopped responding (CPU, firmware or overclock)", "một nhân CPU ngừng phản hồi (CPU, firmware hoặc ép xung)")},
	0x109: {"CRITICAL_STRUCTURE_CORRUPTION", false, model.T("a driver or faulty RAM", "driver hoặc RAM lỗi")},
	0x116: {"VIDEO_TDR_FAILURE", false, model.T("the graphics card or its driver", "card đồ họa hoặc driver")},
	0x124: {"WHEA_UNCORRECTABLE_ERROR", true, model.T("an uncorrectable hardware error (CPU, RAM, PCIe)", "lỗi phần cứng không sửa được (CPU, RAM, PCIe)")},
	0x133: {"DPC_WATCHDOG_VIOLATION", false, model.T("a driver or storage firmware", "driver hoặc firmware lưu trữ")},
	0x139: {"KERNEL_SECURITY_CHECK_FAILURE", false, model.T("a driver or faulty RAM", "driver hoặc RAM lỗi")},
	0x154: {"UNEXPECTED_STORE_EXCEPTION", false, model.T("often the system disk", "thường do ổ hệ thống")},
}

// bugcheckOf extracts the stop code from 1001's first property
// ("0x00000124 (0x0..., ...)") or 41's BugcheckCode (decimal).
func bugcheckOf(e *winEvent) (uint64, bool) {
	s := e.prop(0)
	if e.ID == 41 {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 {
			return 0, false
		}
		return n, true
	}
	for _, src := range []string{s, e.M} {
		if m := reBugcheck.FindStringSubmatch(src); m != nil {
			if n, err := strconv.ParseUint(m[1], 16, 64); err == nil && n != 0 {
				return n, true
			}
		}
	}
	return 0, false
}

type incident struct {
	t           time.Time
	code        uint64
	bsod        bool
	powerButton bool // Kernel-Power 41 PowerButtonTimestamp set: someone held the power button
	lines       []string
}

// windowsEvents analyses logs.win_events / win_summary / win_boots.
func windowsEvents(b *collect.Bundle, env model.Env, res *model.Result, facts *Facts) {
	es := b.Get("logs.win_events")
	if es == nil {
		return
	}
	cov := model.Coverage{ID: "logs.windows", Component: model.CompLogs,
		Name: model.T("Windows System event log", "Nhật ký sự kiện System của Windows")}
	rcov := model.Coverage{ID: "logs.reboots", Component: model.CompSystem,
		Name: model.T("Unexpected reboots and blue screens", "Khởi động lại bất thường và màn hình xanh")}
	if !es.Ran() {
		cov.State, rcov.State = model.CovSkipped, model.CovSkipped
		cov.Reason = model.Tf("Not collected (%s%s).", "Không thu thập (%s%s).", es.Missing, es.Skipped)
		rcov.Reason = cov.Reason
		res.Coverage = append(res.Coverage, cov, rcov)
		return
	}
	var evs []winEvent
	if err := collect.DecodeJSON(es.Out, &evs); err != nil {
		cov.State, rcov.State = model.CovFailed, model.CovFailed
		cov.Reason = model.Tf("The event list could not be read: %v %s", "Không đọc được danh sách sự kiện: %v %s", err, firstLine(es.Err))
		rcov.Reason = cov.Reason
		res.Coverage = append(res.Coverage, cov, rcov)
		return
	}
	cov.State, rcov.State = model.CovRan, model.CovRan
	if e := strings.TrimSpace(es.Err); e != "" && len(evs) == 0 {
		cov.State, rcov.State = model.CovFailed, model.CovFailed
		cov.Reason = model.Tf("Get-WinEvent failed: %s", "Get-WinEvent bị lỗi: %s", firstLine(e))
		rcov.Reason = cov.Reason
	}
	facts.Sources = append(facts.Sources, "eventlog")

	gr := newGrouper(env.Now)
	var marks []*winEvent // 41 / 6008 / 1001
	for i := range evs {
		e := &evs[i]
		if t, ok := collect.WinTime(e.T); ok {
			e.time = t
		}
		if !inWindow(e.time, env) {
			continue
		}
		p := strings.ToLower(e.P)
		switch {
		case p == "microsoft-windows-kernel-power" && e.ID == 41,
			p == "eventlog" && e.ID == 6008,
			(p == "microsoft-windows-wer-systemerrorreporting" || p == "bugcheck") && e.ID == 1001:
			marks = append(marks, e)
			continue
		}
		sp, target := classifyWin(e)
		if sp == nil {
			continue
		}
		g := gr.add(sp, target, e.time, e.raw(), true)
		if sp == wsReset && reUSBStor.MatchString(e.P) {
			// USB disks (external backup drives) also reset when unplugged or
			// on a flaky USB port: worth a warning, not an emergency.
			g.capped, g.capSev = true, model.Warn
		}
		if g.part == nil && sp.Comp == model.CompDisk && strings.HasPrefix(target, "PhysicalDrive") {
			g.part = &model.Part{Kind: "disk", Location: target}
		}
		if sp == wsWHEAFatal || sp == wsWHEACorr {
			switch target {
			case "memory":
				g.comp = model.CompMemory
			case "PCIe":
				g.comp = model.CompSystem
			}
		}
	}
	var vmNote model.Text
	if env.Virtual != "" {
		vmNote = model.T("This is a virtual machine: hardware errors here usually come from the host or its storage — check the host too.",
			"Đây là máy ảo: lỗi phần cứng ở đây thường đến từ máy host hoặc hệ thống lưu trữ của host — hãy kiểm tra cả máy host.")
	}
	findings, efacts := buildFindings(gr.list(), env.Now, vmNote)
	res.Findings = append(res.Findings, findings...)
	facts.Events = append(facts.Events, efacts...)
	worst := model.OK
	for _, f := range findings {
		worst = model.Worst(worst, f.Severity)
	}
	if worst < model.Warn && cov.State == model.CovRan {
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.windows_clean", Component: model.CompLogs, Severity: model.OK,
			Title: model.Tf("No hardware errors in the System event log for the last %d days", "Nhật ký System %d ngày qua không có lỗi phần cứng", env.SinceDays),
			Detail: model.T("Disk, storage controller, NTFS, WHEA (CPU/memory/PCIe), processor throttling and NIC events were checked.",
				"Đã kiểm tra các sự kiện ổ cứng, controller lưu trữ, NTFS, WHEA (CPU/RAM/PCIe), giảm xung CPU và card mạng."),
		})
	}

	// Summary of every error/warning provider.
	var sum []WinCount
	if ss := b.Get("logs.win_summary"); ss.Ran() {
		var raw []struct {
			P    string `json:"p"`
			ID   int    `json:"id"`
			L    int    `json:"l"`
			N    int    `json:"n"`
			Last string `json:"last"`
		}
		if collect.DecodeJSON(ss.Out, &raw) == nil {
			for _, r := range raw {
				sum = append(sum, WinCount{Provider: r.P, ID: r.ID, Level: r.L, Count: r.N, Last: r.Last})
			}
		}
	}
	sort.SliceStable(sum, func(i, j int) bool { return sum[i].Count > sum[j].Count })
	facts.WinProviders = sum
	if len(efacts) > 0 {
		res.Tables = append(res.Tables, eventTable("logs.events",
			model.T("Hardware-related events (System log)", "Sự kiện liên quan phần cứng (log System)"), efacts,
			model.Tf("Last %d days. Classified by provider and event ID (messages are localised).",
				"%d ngày gần nhất. Phân loại theo provider và event ID (nội dung thông báo phụ thuộc ngôn ngữ Windows).", env.SinceDays)))
	}
	if len(sum) > 0 {
		t := model.Table{ID: "logs.win_summary", Title: model.T("All errors and warnings in the System log", "Toàn bộ lỗi và cảnh báo trong log System"),
			Columns: []model.Text{model.T("Provider", "Provider"), model.T("Event ID", "Event ID"), model.T("Level", "Mức"),
				model.T("Count", "Số lần"), model.T("Last seen", "Lần cuối")},
			Note: model.T("Top 15 by count. Only the hardware-related ones are analysed.", "15 dòng nhiều nhất. Chỉ các sự kiện liên quan phần cứng được phân tích.")}
		for i, s := range sum {
			if i == 15 {
				break
			}
			st := model.OK
			e := winEvent{P: s.Provider, ID: s.ID, L: s.Level}
			if sp, _ := classifyWin(&e); sp != nil {
				st = model.Info
			}
			last := s.Last
			if tt, ok := collect.WinTime(s.Last); ok {
				last = fmtTime(tt)
			}
			lvl := map[int]string{1: "critical", 2: "error", 3: "warning"}[s.Level]
			t.Rows = append(t.Rows, model.Row{Status: st, Cells: []string{s.Provider, strconv.Itoa(s.ID), lvl, strconv.Itoa(s.Count), last}})
		}
		res.Tables = append(res.Tables, t)
	}

	windowsReboots(b, env, marks, res, facts)
	res.Coverage = append(res.Coverage, cov, rcov)
}

// windowsReboots groups Kernel-Power 41, EventLog 6008 and BugCheck 1001
// (all logged at the next boot) into incidents.
func windowsReboots(b *collect.Bundle, env model.Env, marks []*winEvent, res *model.Result, facts *Facts) {
	sort.SliceStable(marks, func(i, j int) bool { return marks[i].time.Before(marks[j].time) })
	var incs []*incident
	for _, e := range marks {
		var cur *incident
		if n := len(incs); n > 0 && !e.time.IsZero() && e.time.Sub(incs[n-1].t) <= 30*time.Minute {
			cur = incs[n-1]
		} else {
			cur = &incident{t: e.time}
			incs = append(incs, cur)
		}
		cur.lines = append(cur.lines, e.raw())
		if code, ok := bugcheckOf(e); ok {
			cur.bsod, cur.code = true, code
		}
		// Microsoft: "Event ID 41 that includes a nonzero value for the
		// PowerButtonTimestamp entry" = restarted by holding the power button.
		if e.ID == 41 && e.prop(5) != "" && e.prop(5) != "0" {
			cur.powerButton = true
		}
	}
	// Planned restarts (User32 1074) for context.
	planned := 0
	var plannedLines []string
	if bs := b.Get("logs.win_boots"); bs.Ran() {
		var evs []winEvent
		if collect.DecodeJSON(bs.Out, &evs) == nil {
			for i := range evs {
				e := &evs[i]
				if t, ok := collect.WinTime(e.T); ok {
					e.time = t
				}
				if strings.EqualFold(e.P, "User32") && e.ID == 1074 && inWindow(e.time, env) {
					planned++
					if len(plannedLines) < 3 {
						plannedLines = append(plannedLines, e.raw())
					}
				}
			}
		}
	}
	byCode := map[uint64][]*incident{}
	var codes []uint64
	var unexpected []*incident
	for _, in := range incs {
		if in.bsod {
			if _, ok := byCode[in.code]; !ok {
				codes = append(codes, in.code)
			}
			byCode[in.code] = append(byCode[in.code], in)
		} else {
			unexpected = append(unexpected, in)
		}
		facts.Boots = append(facts.Boots, BootFact{End: in.t, Ending: map[bool]string{true: "bugcheck", false: "unclean"}[in.bsod], Source: "eventlog"})
	}
	facts.UncleanShutdowns = len(incs)
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	for _, code := range codes {
		list := byCode[code]
		info, known := stopCodes[code]
		name := fmt.Sprintf("0x%08X", code)
		target := name
		if known {
			target = name + " " + info.name
		}
		var ev []string
		var times []string
		for _, in := range list {
			ev = append(ev, in.lines...)
			times = append(times, fmtTime(in.t))
		}
		detail := tf("Windows crashed with stop code %s %d time(s): %s.", "Windows bị màn hình xanh với stop code %s %d lần: %s.",
			target, len(list), strings.Join(times, ", "))
		if known {
			detail = joinText(detail, model.Text{EN: "This code usually points to " + info.hint.EN + ".", VI: "Mã này thường do " + info.hint.VI + "."})
		}
		action := model.T("Analyse the dump (C:\\Windows\\MEMORY.DMP or C:\\Windows\\Minidump) with WinDbg: !analyze -v names the faulting driver. Update that driver, the BIOS and firmware. If the same stop code repeats with different drivers, test the RAM and check the BMC event log.",
			"Phân tích file dump (C:\\Windows\\MEMORY.DMP hoặc C:\\Windows\\Minidump) bằng WinDbg: !analyze -v cho biết driver gây lỗi. Cập nhật driver đó, BIOS và firmware. Nếu cùng stop code lặp lại với các driver khác nhau, kiểm tra RAM và log sự kiện BMC.")
		if known && info.hw {
			action = joinText(wActWHEA, model.T("The dump's !errrec output shows the failing component.", "Lệnh !errrec trong file dump cho biết thành phần bị lỗi."))
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.win_bugcheck", Component: model.CompSystem, Severity: model.Crit, Target: target,
			Title:    tf("Blue screen (stop code %s) %d time(s)", "Màn hình xanh (stop code %s) %d lần", target, len(list)),
			Detail:   detail,
			Action:   action,
			Evidence: units.Evidence(ev, 10),
		})
	}
	if len(unexpected) > 0 {
		var ev, times []string
		buttons := 0
		for _, in := range unexpected {
			ev = append(ev, in.lines...)
			times = append(times, fmtTime(in.t))
			if in.powerButton {
				buttons++
			}
		}
		var btn model.Text
		if buttons > 0 {
			btn = model.Tf("%d of them were hard resets with the power button (Kernel-Power 41 PowerButtonTimestamp): the server had probably hung.",
				"%d lần trong số đó là reset cứng bằng nút nguồn (Kernel-Power 41 PowerButtonTimestamp): nhiều khả năng máy đã bị treo.", buttons)
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.unexpected_reboot", Component: model.CompSystem, Severity: model.Warn,
			Title: tf("Server restarted without a clean shutdown %d time(s) in the last %d days",
				"Máy chủ khởi động lại mà không tắt máy đúng cách %d lần trong %d ngày qua", len(unexpected), env.SinceDays),
			Detail: joinText(model.Tf("Kernel-Power 41 / EventLog 6008 at: %s, without a blue-screen record.",
				"Kernel-Power 41 / EventLog 6008 lúc: %s, không có bản ghi màn hình xanh.", strings.Join(times, ", ")),
				model.T("Causes: power loss, a PSU fault, overheating, a hard hang reset by someone, or a watchdog/BMC reset.",
					"Nguyên nhân có thể: mất điện, lỗi bộ nguồn (PSU), quá nhiệt, máy treo cứng và bị reset, hoặc watchdog/BMC reset máy."), btn),
			Action: model.T("Check the BMC/iDRAC/iLO event log for power, PSU, temperature or watchdog events at those times and the UPS log. If the server hung, configure a full memory dump and an NMI crash (CrashOnNMI) so the next hang leaves a dump.",
				"Xem log sự kiện BMC/iDRAC/iLO có sự kiện nguồn, PSU, nhiệt độ hoặc watchdog vào các thời điểm đó không, và xem log UPS. Nếu máy bị treo, cấu hình full memory dump và CrashOnNMI để lần treo sau có file dump."),
			Evidence: units.Evidence(ev, 10),
		})
	}
	if len(incs) == 0 {
		d := model.Text{}
		if planned > 0 {
			d = tf("%d planned restart/shutdown(s) recorded (User32 1074).", "Có %d lần khởi động lại/tắt máy có chủ đích (User32 1074).", planned)
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "logs.reboots_clean", Component: model.CompSystem, Severity: model.OK,
			Title:    model.Tf("No unexpected reboots or blue screens in the last %d days", "Không có khởi động lại bất thường hay màn hình xanh trong %d ngày qua", env.SinceDays),
			Detail:   d,
			Evidence: plannedLines,
		})
	}
}
