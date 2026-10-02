package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// rule is one Linux log pattern. The first rule whose tag and regexp match a
// line wins, so specific patterns come before generic ones.
type rule struct {
	sp  *spec
	tag string // syslog identifier ("" = kernel)
	re  *regexp.Regexp
	// target names the affected thing from the match ("" when the rule has
	// no natural target).
	target func(m []string, l logLine, ctx *matchCtx) string
	// skip drops lines that match but are not a hardware problem (empty
	// CD-ROM drives, loop devices, discard requests...).
	skip func(m []string, l logLine) bool
	// evidence-only lines go into the group's samples without counting as
	// an event (the "failed command" lines that follow an ATA exception).
	evidence bool
}

// matchCtx carries what the whole log tells about device names.
type matchCtx struct {
	hctl      map[string]string // "0:0:2:0" -> "sdc", learnt from "sd 0:0:2:0: [sdc]"
	ata       map[string]*model.Part
	usbHosts  map[string]bool // SCSI host numbers created by usb-storage/uas
	removable map[string]bool // "sdb" announced as "Attached SCSI removable disk"
}

func grp(i int) func(m []string, l logLine, ctx *matchCtx) string {
	return func(m []string, _ logLine, _ *matchCtx) string {
		if i < len(m) {
			return m[i]
		}
		return ""
	}
}

func fixed(s string) func(m []string, l logLine, ctx *matchCtx) string {
	return func([]string, logLine, *matchCtx) string { return s }
}

// Devices that are not server disks: an empty CD/DVD tray, floppy probes on
// VMs, loop/RAM/network block devices.
var notDiskRe = regexp.MustCompile(`^(?:/dev/)?(?:sr\d+|fd\d+|loop\d+|ram\d+|zram\d+|nbd\d+|scd\d+)(?:p?\d+)?$`)

// diskOf maps a partition to its disk and adds /dev/: sda1 -> /dev/sda,
// nvme0n1p2 -> /dev/nvme0n1, mmcblk0p1 -> /dev/mmcblk0.
func diskOf(dev string) string {
	d := strings.TrimPrefix(strings.TrimSpace(dev), "/dev/")
	d = strings.TrimRight(d, ",:")
	switch {
	case strings.HasPrefix(d, "nvme") || strings.HasPrefix(d, "mmcblk"):
		if i := strings.LastIndex(d, "p"); i > 0 && i < len(d)-1 && isDigits(d[i+1:]) && strings.ContainsAny(d[:i], "0123456789") {
			d = d[:i]
		}
	case strings.HasPrefix(d, "sd") || strings.HasPrefix(d, "vd") || strings.HasPrefix(d, "xvd") || strings.HasPrefix(d, "hd"):
		d = strings.TrimRight(d, "0123456789")
	}
	if d == "" {
		return ""
	}
	return "/dev/" + d
}

func devPath(dev string) string {
	d := strings.TrimRight(strings.TrimSpace(dev), ",:")
	if d == "" || strings.HasPrefix(d, "/dev/") {
		return d
	}
	return "/dev/" + d
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func diskGrp(i int) func(m []string, l logLine, ctx *matchCtx) string {
	return func(m []string, _ logLine, _ *matchCtx) string {
		if i < len(m) {
			return diskOf(m[i])
		}
		return ""
	}
}

func devGrp(i int) func(m []string, l logLine, ctx *matchCtx) string {
	return func(m []string, _ logLine, _ *matchCtx) string {
		if i < len(m) {
			return devPath(m[i])
		}
		return ""
	}
}

var (
	reSdName = regexp.MustCompile(`\[(sd[a-z]+)\]`)
	reHCTL   = regexp.MustCompile(`\b(?:sd|scsi) (\d+:\d+:\d+:\d+):`)
)

// scsiTarget finds the disk in a SCSI line: "[sdb]", else the H:C:T:L
// address mapped through earlier lines, else the address itself.
func scsiTarget(_ []string, l logLine, ctx *matchCtx) string {
	if m := reSdName.FindStringSubmatch(l.Msg); m != nil {
		return "/dev/" + m[1]
	}
	if m := reHCTL.FindStringSubmatch(l.Msg); m != nil {
		if ctx != nil {
			if d, ok := ctx.hctl[m[1]]; ok {
				return "/dev/" + d
			}
		}
		return "scsi " + m[1]
	}
	return ""
}

// SCSI lines from CD/DVD drives (sr), tapes (st) and enclosures (ses): an
// empty or scratched disc in a VM's virtual drive reports Medium Error too.
var reSCSINotDisk = regexp.MustCompile(`^(?:sr|st|ses|osst|ch) \d+:\d+:\d+:\d+:|\[(?:sr|st|nst)\d+\]`)

func skipSCSINotDisk(_ []string, l logLine) bool { return reSCSINotDisk.MatchString(l.Msg) }

func skipNotDisk(i int) func(m []string, l logLine) bool {
	return func(m []string, _ logLine) bool { return i < len(m) && notDiskRe.MatchString(m[i]) }
}

// Discard/zeroing requests fail on devices that do not support them; that is
// not a media problem.
var reNonDataOp = regexp.MustCompile(`op 0x[0-9a-f]+:\((?:DISCARD|SECURE_ERASE|WRITE_ZEROES|WRITE_SAME|ZONE_\w+)\)`)

func skipIOErr(m []string, l logLine) bool {
	return (len(m) > 2 && notDiskRe.MatchString(m[2])) || reNonDataOp.MatchString(l.Msg)
}

// ---- texts shared by several rules ----

var (
	actDiskReplace = model.T(
		"Back up the data on {t} now. Check it with smartctl -a {t} (and the RAID controller if there is one). Replace the disk if S.M.A.R.T. shows pending/reallocated/uncorrectable sectors or the errors continue; if it is in a RAID array, make sure the array is otherwise healthy before pulling it.",
		"Sao lưu dữ liệu trên {t} ngay. Kiểm tra bằng smartctl -a {t} (và card RAID nếu có). Thay ổ nếu S.M.A.R.T. có sector pending/reallocated/uncorrectable hoặc lỗi còn tiếp diễn; nếu ổ nằm trong RAID, kiểm tra các ổ còn lại vẫn tốt trước khi rút ổ.")
	actLink = model.T(
		"Check the cable and backplane slot of {t} (reseat or swap the SATA/SAS cable, try another bay), then check smartctl -a for CRC errors. If the errors follow the disk to another slot, replace the disk.",
		"Kiểm tra cáp và khe backplane của {t} (cắm lại hoặc thay cáp SATA/SAS, thử khe khác), rồi xem smartctl -a có lỗi CRC không. Nếu đổi khe mà lỗi vẫn theo ổ thì thay ổ.")
	actFS = model.T(
		"Find the disk under {t} and check it first (smartctl, RAID state): filesystem errors usually follow disk or controller errors. Then unmount and repair: fsck -f (ext4), xfs_repair (XFS) or btrfs check/scrub — from rescue mode for the root filesystem. Restore damaged files from backup.",
		"Tìm ổ chứa {t} và kiểm tra ổ trước (smartctl, trạng thái RAID): lỗi filesystem thường đi kèm lỗi ổ hoặc controller. Sau đó umount và sửa: fsck -f (ext4), xfs_repair (XFS) hoặc btrfs check/scrub — với phân vùng root thì chạy ở chế độ rescue. Khôi phục file hỏng từ bản sao lưu.")
	actMemCE = model.T(
		"Note the DIMM ({t}) and watch the count (edac-util -v, ras-mc-ctl --errors, or the BMC log). If corrected errors keep appearing on the same DIMM, schedule its replacement: corrected errors often precede uncorrectable ones.",
		"Ghi lại thanh RAM ({t}) và theo dõi số lỗi (edac-util -v, ras-mc-ctl --errors hoặc log BMC). Nếu lỗi corrected tiếp tục xuất hiện trên cùng thanh RAM, lên kế hoạch thay: lỗi corrected thường báo trước lỗi uncorrectable.")
	actMemUE = model.T(
		"Uncorrectable memory errors can corrupt data or crash the server. Identify the DIMM ({t}) in the BMC event log or with dmidecode -t memory, replace it (or move it to another slot to confirm), then run a memory test (memtester, or the vendor's offline diagnostics).",
		"Lỗi RAM không sửa được có thể làm hỏng dữ liệu hoặc treo máy. Xác định thanh RAM ({t}) trong log sự kiện BMC hoặc bằng dmidecode -t memory, thay thanh đó (hoặc chuyển sang khe khác để xác nhận), rồi chạy kiểm tra RAM (memtester hoặc công cụ chẩn đoán offline của hãng).")
	actMCE = model.T(
		"Decode the machine checks (mcelog --client, ras-mc-ctl --errors, or the BMC event log) to see whether they come from a CPU or a memory channel. Update BIOS and CPU microcode. If they continue, open a hardware case with the vendor (CPU or DIMM replacement).",
		"Giải mã lỗi machine check (mcelog --client, ras-mc-ctl --errors hoặc log sự kiện BMC) để biết lỗi từ CPU hay kênh RAM. Cập nhật BIOS và microcode CPU. Nếu lỗi còn tiếp, mở case bảo hành với hãng (thay CPU hoặc thanh RAM).")
	actThermal = model.T(
		"Check fans, air filters and room temperature; look at the BMC temperature and fan sensors (ipmitool sdr). Make sure blanking panels are in place and nothing blocks the airflow. Replace failed fans; re-apply thermal paste if one CPU runs much hotter than the other.",
		"Kiểm tra quạt, lưới lọc bụi và nhiệt độ phòng máy; xem cảm biến nhiệt độ và quạt trên BMC (ipmitool sdr). Đảm bảo có tấm che khe trống và không có gì cản luồng gió. Thay quạt hỏng; tra lại keo tản nhiệt nếu một CPU nóng hơn hẳn CPU còn lại.")
	actPCIe = model.T(
		"Identify the device {t} with lspci -vv and look at the BMC event log at the same time. Reseat the card or riser, check the slot, and update the device firmware and BIOS. Repeated errors on one device point to that card, its slot or its riser.",
		"Xác định thiết bị {t} bằng lspci -vv và xem log sự kiện BMC cùng thời điểm. Cắm lại card hoặc riser, kiểm tra khe cắm, cập nhật firmware thiết bị và BIOS. Lỗi lặp lại trên một thiết bị cho thấy card, khe cắm hoặc riser đó có vấn đề.")
	actHang = model.T(
		"Look at what the CPU or task was doing (the call trace after the line). On a VM this is usually the host being overloaded. On bare metal, update BIOS, firmware and drivers; if it repeats with different call traces, test the RAM and check the BMC event log.",
		"Xem CPU hoặc tiến trình đang làm gì (call trace ngay sau dòng log). Trên máy ảo, nguyên nhân thường là máy host quá tải. Trên máy vật lý, cập nhật BIOS, firmware và driver; nếu lặp lại với call trace khác nhau, kiểm tra RAM và log sự kiện BMC.")
	actNIC = model.T(
		"Check the cable, the transceiver/SFP and the switch port of {t} (switch log, port errors). Run ethtool {t} and ethtool -S {t}. If the link keeps dropping with a new cable and another switch port, update the NIC firmware/driver or replace the NIC.",
		"Kiểm tra cáp, module quang/SFP và cổng switch của {t} (log switch, lỗi trên cổng). Chạy ethtool {t} và ethtool -S {t}. Nếu thay cáp và đổi cổng switch mà link vẫn rớt, cập nhật firmware/driver card mạng hoặc thay card mạng.")
	actController = model.T(
		"Check the controller with its tool (storcli /c0 show all, perccli, ssacli, sas3ircu) and its event log. Update controller firmware and driver. A controller that faults again needs to be replaced; check the cache battery/capacitor too.",
		"Kiểm tra controller bằng công cụ của hãng (storcli /c0 show all, perccli, ssacli, sas3ircu) và log sự kiện của nó. Cập nhật firmware và driver controller. Controller bị fault lặp lại cần được thay; kiểm tra cả pin/tụ cache.")
)

// ---- specs ----

var (
	spDiskIO = &spec{ID: "disk_io_error", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t}: I/O errors in the kernel log", "Ổ {t}: có lỗi I/O trong log kernel"),
		Detail: model.T("The kernel could not read or write blocks on {t}. On a physical disk this almost always means bad sectors, a failing disk or a bad cable/controller path.", "Kernel không đọc/ghi được block trên {t}. Với ổ vật lý, gần như chắc chắn là bad sector, ổ sắp hỏng, hoặc đường cáp/controller có vấn đề."),
		Action: actDiskReplace}
	spDiskMedium = &spec{ID: "disk_medium_error", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t} has unreadable sectors (medium error)", "Ổ {t} có sector không đọc được (medium error)"),
		Detail: model.T("The disk itself reported that it could not read data (medium error / unrecovered read error / UNC). This is a defect on the disk surface or flash.", "Chính ổ cứng báo không đọc được dữ liệu (medium error / unrecovered read error / UNC). Đây là lỗi trên bề mặt đĩa hoặc chip nhớ flash."),
		Action: actDiskReplace}
	spDiskHW = &spec{ID: "disk_hardware_error", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t} reported an internal hardware error", "Ổ {t} báo lỗi phần cứng bên trong"),
		Detail: model.T("The disk returned sense key \"Hardware Error\": its own electronics or mechanics failed a command.", "Ổ trả về sense key \"Hardware Error\": mạch điện hoặc cơ của ổ không thực hiện được lệnh."),
		Action: actDiskReplace}
	spDiskOffline = &spec{ID: "disk_offline", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("Disk {t} was taken offline by the kernel", "Ổ {t} bị kernel đưa về trạng thái offline"),
		Detail: model.T("After failed error recovery the kernel stopped sending I/O to {t} (or the link was disabled). Everything on it is unreachable until it comes back.", "Sau khi khôi phục lỗi thất bại, kernel ngừng gửi I/O tới {t} (hoặc link bị vô hiệu). Mọi dữ liệu trên ổ không truy cập được cho tới khi ổ hoạt động lại."),
		Action: model.T("Check whether {t} is still present (lsblk, the RAID controller). If it was not removed on purpose, back up what you can, check its cable/slot and S.M.A.R.T., and replace it. If it was in a RAID array, the array is now degraded.", "Kiểm tra {t} còn được nhận không (lsblk, card RAID). Nếu không phải do rút ổ có chủ đích, sao lưu những gì còn đọc được, kiểm tra cáp/khe cắm và S.M.A.R.T., rồi thay ổ. Nếu ổ nằm trong RAID thì RAID đang bị degraded.")}
	spDiskCmd = &spec{ID: "disk_command_failed", Comp: model.CompDisk, Sev: model.Warn, Decay: true, CritAt: 30,
		Title:  model.T("Disk {t}: commands failed or timed out", "Ổ {t}: lệnh bị lỗi hoặc quá thời gian"),
		Detail: model.T("Commands to {t} failed at the transport level (timeouts, aborts, resets). Causes: a disk that is starting to fail, a loose cable, a backplane or controller problem.", "Lệnh gửi tới {t} lỗi ở tầng truyền dẫn (timeout, abort, reset). Nguyên nhân: ổ bắt đầu hỏng, cáp lỏng, backplane hoặc controller có vấn đề."),
		Action: actLink}
	spDiskProt = &spec{ID: "disk_protection_error", Comp: model.CompDisk, Sev: model.Warn,
		Title:  model.T("Disk {t}: data integrity (T10 PI) errors", "Ổ {t}: lỗi kiểm tra toàn vẹn dữ liệu (T10 PI)"),
		Detail: model.T("End-to-end data protection checks failed on {t}: data read back did not match its checksum/reference tag. This can be the disk, the HBA, or a driver/firmware bug.", "Kiểm tra bảo vệ dữ liệu đầu-cuối trên {t} thất bại: dữ liệu đọc lại không khớp checksum/reference tag. Có thể do ổ, HBA hoặc lỗi driver/firmware."),
		Action: model.T("Check {t} with smartctl -a and the HBA firmware/driver versions against the vendor's compatibility list; update firmware. Replace the disk if the errors continue.", "Kiểm tra {t} bằng smartctl -a và đối chiếu phiên bản firmware/driver HBA với danh sách tương thích của hãng; cập nhật firmware. Thay ổ nếu lỗi còn tiếp diễn.")}
	spATA = &spec{ID: "disk_ata_error", Comp: model.CompDisk, Sev: model.Warn, Decay: true, CritAt: 30,
		Title:  model.T("SATA port {t}: command errors and link resets", "Cổng SATA {t}: lỗi lệnh và reset link"),
		Detail: model.T("libata reported exceptions on {t} and had to reset the link. Usually a cable/backplane problem or a disk that is starting to fail; NCQ/firmware bugs are a rarer cause.", "libata báo exception trên {t} và phải reset link. Thường do cáp/backplane hoặc ổ bắt đầu hỏng; ít gặp hơn là lỗi NCQ/firmware."),
		Action: actLink}
	spCRC = &spec{ID: "disk_link_crc", Comp: model.CompDisk, Sev: model.Warn, Decay: true,
		Title:  model.T("SATA port {t}: transfer CRC errors (cable)", "Cổng SATA {t}: lỗi CRC khi truyền dữ liệu (cáp)"),
		Detail: model.T("Data was corrupted on the way between the controller and the disk (ICRC/BadCRC). The data on the disk is fine; the cable, connector or backplane is not.", "Dữ liệu bị lỗi trên đường truyền giữa controller và ổ (ICRC/BadCRC). Dữ liệu trên ổ vẫn ổn; cáp, đầu cắm hoặc backplane có vấn đề."),
		Action: actLink}
	spNVMeDead = &spec{ID: "nvme_controller_down", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("NVMe {t} stopped responding (controller down)", "NVMe {t} ngừng phản hồi (controller down)"),
		Detail: model.T("The NVMe controller {t} could not be reset or dropped off the PCIe bus (CSTS=0xffffffff in the log means the device no longer answers at all). I/O to it fails until it is reset or replaced.", "Controller NVMe {t} không reset được hoặc rớt khỏi bus PCIe (CSTS=0xffffffff trong log nghĩa là thiết bị không còn phản hồi). Mọi I/O tới ổ đều lỗi cho tới khi được reset hoặc thay."),
		Action: model.T("Back up the data if {t} is reachable. Check smartctl -a /dev/{t} (critical warning, media errors), reseat the drive, update its firmware and the BIOS. Power-saving bugs can cause this (try nvme_core.default_ps_max_latency_us=0); if it happens again, replace the drive.", "Sao lưu dữ liệu nếu còn truy cập được {t}. Kiểm tra smartctl -a /dev/{t} (critical warning, media errors), cắm lại ổ, cập nhật firmware ổ và BIOS. Lỗi tiết kiệm điện có thể gây ra hiện tượng này (thử nvme_core.default_ps_max_latency_us=0); nếu tái diễn, thay ổ.")}
	spNVMeTimeout = &spec{ID: "nvme_timeout", Comp: model.CompDisk, Sev: model.Warn, Decay: true, CritAt: 30,
		Title:  model.T("NVMe {t}: I/O timeouts and controller resets", "NVMe {t}: I/O bị timeout và controller bị reset"),
		Detail: model.T("Commands to {t} did not complete in time and the kernel aborted them or reset the controller. I/O stalls for many seconds each time.", "Lệnh gửi tới {t} không hoàn thành kịp và kernel phải hủy lệnh hoặc reset controller. Mỗi lần như vậy I/O bị treo nhiều giây."),
		Action: model.T("Check smartctl -a /dev/{t} (media errors, temperature, critical warning), update the drive firmware and BIOS, reseat the drive. Persistent timeouts on one drive mean it should be replaced.", "Kiểm tra smartctl -a /dev/{t} (media errors, nhiệt độ, critical warning), cập nhật firmware ổ và BIOS, cắm lại ổ. Timeout kéo dài trên cùng một ổ thì nên thay ổ.")}
	spHBAFault = &spec{ID: "controller_fault", Comp: model.CompRAID, Sev: model.Crit,
		Title:  model.T("Storage controller {t} entered a fault state", "Controller lưu trữ {t} rơi vào trạng thái lỗi (fault)"),
		Detail: model.T("The RAID/HBA controller firmware faulted or locked up; the driver had to reset it. All disks behind it were unavailable meanwhile.", "Firmware card RAID/HBA bị fault hoặc treo; driver phải reset nó. Trong lúc đó toàn bộ ổ phía sau controller không truy cập được."),
		Action: actController}
	spHBAReset = &spec{ID: "controller_reset", Comp: model.CompRAID, Sev: model.Warn, Decay: true,
		Title:  model.T("Storage controller {t} was reset by its driver", "Controller lưu trữ {t} bị driver reset"),
		Detail: model.T("The driver reset the RAID/HBA controller after commands stopped completing.", "Driver đã reset card RAID/HBA vì lệnh không hoàn thành."),
		Action: actController}

	spFSError = &spec{ID: "fs_error", Comp: model.CompFilesystem, Sev: model.Crit,
		Title:  model.T("Filesystem on {t} reported corruption/errors", "Filesystem trên {t} báo lỗi/hỏng cấu trúc"),
		Detail: model.T("The filesystem found inconsistent metadata or failed to read its own structures. Files may be damaged and it may switch to read-only.", "Filesystem phát hiện metadata không nhất quán hoặc không đọc được cấu trúc của chính nó. File có thể bị hỏng và phân vùng có thể chuyển sang chỉ đọc."),
		Action: actFS}
	spFSReadOnly = &spec{ID: "fs_readonly", Comp: model.CompFilesystem, Sev: model.Crit,
		Title:  model.T("Filesystem on {t} was remounted read-only / shut down", "Filesystem trên {t} bị chuyển sang chỉ đọc / bị tắt"),
		Detail: model.T("After an error the kernel stopped all writes to {t} to protect the data. Applications writing there fail until it is repaired and remounted.", "Sau khi gặp lỗi, kernel đã chặn mọi thao tác ghi lên {t} để bảo vệ dữ liệu. Ứng dụng ghi vào đó sẽ lỗi cho tới khi sửa và mount lại."),
		Action: actFS}
	spFSRecorded = &spec{ID: "fs_errors_recorded", Comp: model.CompFilesystem, Sev: model.Warn,
		Title:  model.T("Filesystem on {t} has recorded errors that were never repaired", "Filesystem trên {t} có lỗi đã ghi nhận nhưng chưa được sửa"),
		Detail: model.T("ext4 keeps an error counter in the superblock and reminds about it every day until fsck runs.", "ext4 lưu bộ đếm lỗi trong superblock và nhắc lại mỗi ngày cho tới khi chạy fsck."),
		Action: model.T("Schedule a maintenance window and run fsck -f on {t} (unmounted, or from rescue mode for /). Check the disk under it with smartctl first.", "Lên lịch bảo trì và chạy fsck -f trên {t} (khi đã umount, hoặc ở chế độ rescue với /). Kiểm tra ổ chứa nó bằng smartctl trước.")}
	spFSCsum = &spec{ID: "fs_checksum_error", Comp: model.CompFilesystem, Sev: model.Warn, CritAt: 10,
		Title:  model.T("Btrfs on {t}: checksum errors", "Btrfs trên {t}: lỗi checksum"),
		Detail: model.T("Data read from {t} did not match its checksum. Btrfs repairs it from another copy when the profile has one (RAID1/10/DUP); otherwise the file is damaged. Causes: a failing disk, cable, or bad RAM.", "Dữ liệu đọc từ {t} không khớp checksum. Btrfs tự sửa từ bản sao khác nếu có (RAID1/10/DUP); nếu không thì file bị hỏng. Nguyên nhân: ổ sắp hỏng, cáp, hoặc RAM lỗi."),
		Action: model.T("Run btrfs device stats and btrfs scrub start on the filesystem, check the disks with smartctl, and test the RAM if several disks are affected.", "Chạy btrfs device stats và btrfs scrub start trên filesystem, kiểm tra các ổ bằng smartctl, và kiểm tra RAM nếu nhiều ổ cùng bị.")}
	spMDFail = &spec{ID: "raid_member_failed", Comp: model.CompRAID, Sev: model.Warn, CritRecent: true,
		Title:  model.T("Software RAID {t}: a member disk failed", "RAID mềm {t}: có ổ thành viên bị lỗi"),
		Detail: model.T("mdadm/md marked a member of {t} as failed (or the array became degraded). Redundancy is reduced until the disk is replaced and the rebuild finishes.", "mdadm/md đánh dấu một ổ thành viên của {t} là lỗi (hoặc mảng RAID bị degraded). Khả năng chịu lỗi bị giảm cho tới khi thay ổ và rebuild xong."),
		Action: model.T("Check cat /proc/mdstat and mdadm --detail {t}. If it is still degraded, back up, replace the failed disk (note its serial with smartctl -i) and add the new one (mdadm --manage {t} --add /dev/sdX).", "Kiểm tra cat /proc/mdstat và mdadm --detail {t}. Nếu vẫn degraded, sao lưu, thay ổ lỗi (ghi lại serial bằng smartctl -i) rồi thêm ổ mới (mdadm --manage {t} --add /dev/sdX).")}
	spMDSpare = &spec{ID: "raid_spare_missing", Comp: model.CompRAID, Sev: model.Info,
		Title:  model.T("Software RAID {t}: fewer spare disks than configured", "RAID mềm {t}: thiếu ổ dự phòng (spare) so với cấu hình"),
		Action: model.T("Check mdadm --detail {t} and add a spare, or update mdadm.conf if the spare was removed on purpose.", "Kiểm tra mdadm --detail {t} và thêm ổ spare, hoặc sửa mdadm.conf nếu ổ spare được gỡ có chủ đích.")}

	spMemCE = &spec{ID: "memory_corrected", Comp: model.CompMemory, Sev: model.Warn,
		Title:  model.T("Corrected memory (ECC) errors: {t}", "Lỗi RAM đã được ECC sửa: {t}"),
		Detail: model.T("ECC corrected memory errors. No data was lost, but repeated corrected errors on one DIMM predict uncorrectable errors (Schroeder et al., \"DRAM Errors in the Wild\", 2009).", "ECC đã sửa lỗi bộ nhớ. Không mất dữ liệu, nhưng lỗi corrected lặp lại trên một thanh RAM là dấu hiệu sắp có lỗi không sửa được (Schroeder và cộng sự, \"DRAM Errors in the Wild\", 2009)."),
		Action: actMemCE}
	spMemUE = &spec{ID: "memory_uncorrected", Comp: model.CompMemory, Sev: model.Crit,
		Title:  model.T("Uncorrectable memory error: {t}", "Lỗi RAM không sửa được: {t}"),
		Detail: model.T("ECC detected memory errors it could not correct. The affected data was lost or the page was taken out of service.", "ECC phát hiện lỗi bộ nhớ không thể sửa. Dữ liệu ở vùng đó bị mất hoặc trang nhớ bị loại khỏi sử dụng."),
		Action: actMemUE}
	spMemPoison = &spec{ID: "memory_page_offlined", Comp: model.CompMemory, Sev: model.Crit,
		Title:  model.T("Memory pages were taken offline after uncorrectable errors", "Trang bộ nhớ bị loại bỏ sau lỗi không sửa được"),
		Detail: model.T("The kernel's memory-failure handler isolated physical pages that hardware reported as poisoned (uncorrectable ECC error). Processes using them may have been killed.", "Cơ chế memory-failure của kernel đã cô lập các trang nhớ vật lý mà phần cứng báo lỗi (ECC không sửa được). Tiến trình dùng các trang đó có thể đã bị dừng."),
		Action: actMemUE}
	spMCECorr = &spec{ID: "mce_corrected", Comp: model.CompCPU, Sev: model.Warn, Decay: true,
		Title:  model.T("Machine check events (corrected hardware errors) logged", "Có sự kiện machine check (lỗi phần cứng đã được sửa)"),
		Detail: model.T("The CPU reported corrected machine-check errors. They come from a CPU core/cache, the memory controller (often a DIMM) or a bus.", "CPU báo lỗi machine check đã được sửa. Nguồn lỗi có thể là nhân/cache CPU, bộ điều khiển RAM (thường là một thanh RAM) hoặc bus."),
		Action: actMCE}
	spMCEUncorr = &spec{ID: "mce_uncorrected", Comp: model.CompCPU, Sev: model.Crit,
		Title:  model.T("Uncorrected machine check (CPU/memory hardware error)", "Lỗi machine check không sửa được (lỗi phần cứng CPU/RAM)"),
		Detail: model.T("A machine-check bank reported an uncorrected error (the UC bit of MCi_STATUS is set, Intel SDM vol. 3B ch. 16). Data in a cache line or memory was lost.", "Một bank machine check báo lỗi không sửa được (bit UC của MCi_STATUS bật, Intel SDM tập 3B chương 16). Dữ liệu trong cache hoặc RAM đã bị mất."),
		Action: actMCE}
	spHWPanic = &spec{ID: "hardware_panic", Comp: model.CompCPU, Sev: model.Crit,
		Title:  model.T("Kernel panicked because of a fatal hardware error", "Kernel bị panic do lỗi phần cứng nghiêm trọng"),
		Detail: model.T("The kernel stopped the machine after a fatal machine check / platform hardware error.", "Kernel đã dừng máy sau một lỗi machine check / lỗi phần cứng nền tảng nghiêm trọng."),
		Action: model.T("Read the BMC event log (ipmitool sel elist) for the failing CPU/DIMM/PCIe slot, update BIOS and microcode, and open a hardware case with the vendor.", "Đọc log sự kiện BMC (ipmitool sel elist) để biết CPU/RAM/khe PCIe bị lỗi, cập nhật BIOS và microcode, rồi mở case bảo hành với hãng.")}

	spThermCrit = &spec{ID: "thermal_critical", Comp: model.CompThermal, Sev: model.Crit,
		Title:  model.T("Critical temperature reached ({t})", "Nhiệt độ chạm ngưỡng nguy hiểm ({t})"),
		Detail: model.T("A thermal zone reached its critical trip point; the kernel shuts the machine down at that point to protect the hardware.", "Một vùng nhiệt chạm ngưỡng critical; khi đó kernel sẽ tắt máy để bảo vệ phần cứng."),
		Action: actThermal}
	spThrottle = &spec{ID: "cpu_thermal_throttle", Comp: model.CompThermal, Sev: model.Warn, Decay: true,
		Title:  model.T("CPU was throttled because it was too hot", "CPU bị giảm xung vì quá nóng"),
		Detail: model.T("The CPU passed its thermal threshold and slowed its clock (PROCHOT). Server CPUs should not do this under normal cooling.", "CPU vượt ngưỡng nhiệt và tự giảm xung nhịp (PROCHOT). CPU máy chủ không nên bị như vậy nếu tản nhiệt bình thường."),
		Action: actThermal}

	spPCIeCorr = &spec{ID: "pcie_corrected", Comp: model.CompSystem, Sev: model.Warn, Min: 20, Below: model.Info, Decay: true,
		Title:  model.T("PCIe device {t}: corrected link errors (AER)", "Thiết bị PCIe {t}: lỗi đường truyền đã được sửa (AER)"),
		Detail: model.T("PCIe Advanced Error Reporting logged corrected errors on {t}. They are recovered by the hardware (kernel Documentation/PCI/pcieaer-howto), but a steady stream points to a marginal link: card seating, riser, slot or power management (ASPM).", "PCIe AER ghi nhận lỗi đã được phần cứng sửa trên {t} (tài liệu kernel pcieaer-howto). Nhưng lỗi liên tục cho thấy đường truyền không ổn định: card cắm chưa chặt, riser, khe cắm hoặc chế độ tiết kiệm điện (ASPM)."),
		Action: actPCIe}
	spPCIeNonFatal = &spec{ID: "pcie_uncorrected", Comp: model.CompSystem, Sev: model.Warn, CritAt: 10,
		Title:  model.T("PCIe device {t}: uncorrected (non-fatal) errors", "Thiết bị PCIe {t}: lỗi không sửa được (non-fatal)"),
		Detail: model.T("A PCIe transaction to/from {t} failed; the link stayed up and the kernel tried to recover the device. Unsupported-request errors from device passthrough (vfio) are a known harmless cause.", "Một giao dịch PCIe tới/từ {t} bị lỗi; link vẫn hoạt động và kernel đã cố khôi phục thiết bị. Lỗi Unsupported Request khi passthrough thiết bị (vfio) là nguyên nhân vô hại đã biết."),
		Action: actPCIe}
	spPCIeFatal = &spec{ID: "pcie_fatal", Comp: model.CompSystem, Sev: model.Crit,
		Title:  model.T("PCIe device {t}: fatal link error", "Thiết bị PCIe {t}: lỗi đường truyền nghiêm trọng (fatal)"),
		Detail: model.T("A fatal PCIe error on {t}: the link had to be reset and the device was unusable meanwhile.", "Lỗi PCIe fatal trên {t}: link phải reset và thiết bị không dùng được trong lúc đó."),
		Action: actPCIe}

	spPanic = &spec{ID: "kernel_panic", Comp: model.CompSystem, Sev: model.Crit,
		Title:  model.T("Kernel panic recorded in the log", "Log có ghi nhận kernel panic"),
		Detail: model.T("The kernel stopped with a panic; the server crashed or rebooted.", "Kernel dừng với lỗi panic; máy chủ đã bị treo hoặc khởi động lại."),
		Action: model.T("Read the lines before the panic (and the kdump vmcore-dmesg.txt if kdump is set up). Hardware causes show up as machine checks, NMIs or I/O errors right before it; otherwise update the kernel and drivers.", "Đọc các dòng ngay trước panic (và vmcore-dmesg.txt nếu đã cấu hình kdump). Nguyên nhân phần cứng thường hiện ra dưới dạng machine check, NMI hoặc lỗi I/O ngay trước đó; nếu không, cập nhật kernel và driver.")}
	spHardLockup = &spec{ID: "hard_lockup", Comp: model.CompSystem, Sev: model.Crit,
		Title:  model.T("A CPU froze completely (hard lockup)", "Một CPU bị treo hoàn toàn (hard lockup)"),
		Detail: model.T("The NMI watchdog found a CPU that had not serviced interrupts for over 10 seconds. On bare metal this is a firmware, CPU or PCIe device hang, or a serious driver bug.", "NMI watchdog phát hiện một CPU không xử lý ngắt quá 10 giây. Trên máy vật lý, nguyên nhân là firmware, CPU hoặc thiết bị PCIe bị treo, hoặc lỗi driver nghiêm trọng."),
		Action: actHang}
	spSoftLockup = &spec{ID: "soft_lockup", Comp: model.CompSystem, Sev: model.Warn, Decay: true,
		Title:  model.T("CPU soft lockups / RCU stalls", "CPU bị soft lockup / RCU stall"),
		Detail: model.T("A CPU was stuck in the kernel for tens of seconds. Common on overloaded VM hosts; on bare metal it points to a driver, firmware or hardware problem.", "Một CPU bị kẹt trong kernel hàng chục giây. Hay gặp khi máy host ảo hóa quá tải; trên máy vật lý thường do driver, firmware hoặc phần cứng."),
		Action: actHang}
	spHungTask = &spec{ID: "hung_task", Comp: model.CompSystem, Sev: model.Warn, Decay: true,
		Title:  model.T("Tasks blocked for more than 2 minutes (hung tasks)", "Tiến trình bị treo hơn 2 phút (hung task)"),
		Detail: model.T("Processes waited more than 120 seconds, almost always for disk or network storage I/O. Look for disk, RAID or NFS/iSCSI errors at the same time.", "Tiến trình phải chờ hơn 120 giây, gần như luôn là chờ I/O ổ cứng hoặc lưu trữ qua mạng. Tìm lỗi ổ, RAID hoặc NFS/iSCSI cùng thời điểm."),
		Action: model.T("Check the disks and controllers (smartctl, RAID state) and any NFS/iSCSI storage for errors at the same time; check iowait with iostat -x 1.", "Kiểm tra ổ và controller (smartctl, trạng thái RAID) cùng lưu trữ NFS/iSCSI có lỗi cùng thời điểm không; xem iowait bằng iostat -x 1.")}
	spOops = &spec{ID: "kernel_oops", Comp: model.CompSystem, Sev: model.Warn,
		Title:  model.T("Kernel BUG/Oops recorded", "Có lỗi kernel BUG/Oops"),
		Detail: model.T("The kernel hit an internal error. Usually a driver or kernel bug; when it repeats with different call traces, faulty RAM is a classic cause.", "Kernel gặp lỗi nội bộ. Thường do lỗi driver hoặc kernel; nếu lặp lại với call trace khác nhau, RAM lỗi là nguyên nhân kinh điển."),
		Action: model.T("Update the kernel and drivers. If Oopses repeat with different call traces, run a memory test and check the BMC event log for ECC errors.", "Cập nhật kernel và driver. Nếu Oops lặp lại với call trace khác nhau, chạy kiểm tra RAM và xem log sự kiện BMC có lỗi ECC không.")}
	spNMI = &spec{ID: "nmi_hardware", Comp: model.CompSystem, Sev: model.Warn,
		Title:  model.T("Unexplained NMIs / PCI system errors", "Có NMI không rõ nguyên nhân / lỗi hệ thống PCI"),
		Detail: model.T("The platform raised non-maskable interrupts the kernel could not attribute (or reported PCI SERR/IOCHK). These come from hardware: memory/bus errors, a PCIe device, or the BMC.", "Nền tảng phát ra ngắt NMI mà kernel không xác định được nguồn (hoặc báo PCI SERR/IOCHK). Các ngắt này đến từ phần cứng: lỗi RAM/bus, thiết bị PCIe hoặc BMC."),
		Action: model.T("Check the BMC event log (ipmitool sel elist) at the same time for the failing component; update BIOS/BMC firmware.", "Xem log sự kiện BMC (ipmitool sel elist) cùng thời điểm để biết thành phần lỗi; cập nhật firmware BIOS/BMC.")}
	spOOM = &spec{ID: "oom_kill", Comp: model.CompMemory, Sev: model.Warn, Decay: true,
		Title:  model.T("Out of memory: the kernel killed processes", "Hết RAM: kernel đã buộc dừng tiến trình"),
		Detail: model.T("The OOM killer ended processes because RAM and swap ran out. This is a capacity problem, not a hardware fault.", "OOM killer đã dừng tiến trình vì hết RAM và swap. Đây là vấn đề thiếu dung lượng, không phải lỗi phần cứng."),
		Action: model.T("Find what used the memory (the OOM report lists processes; check free -h, ps aux --sort=-rss). Limit or fix that service, add swap, or add RAM.", "Tìm tiến trình chiếm RAM (báo cáo OOM có danh sách; xem free -h, ps aux --sort=-rss). Giới hạn hoặc sửa dịch vụ đó, thêm swap hoặc nâng RAM.")}
	spOOMcg = &spec{ID: "oom_cgroup", Comp: model.CompMemory, Sev: model.Info,
		Title:  model.T("A service hit its own memory limit (cgroup OOM)", "Một dịch vụ chạm giới hạn RAM của chính nó (cgroup OOM)"),
		Detail: model.T("A container or systemd unit exceeded its configured memory limit and a process in it was killed. The machine itself had memory left.", "Một container hoặc unit systemd vượt giới hạn RAM được cấu hình và một tiến trình trong đó bị dừng. Bản thân máy vẫn còn RAM."),
		Action: model.T("Raise the limit (MemoryMax=, container memory limit) or fix the service's memory use.", "Tăng giới hạn (MemoryMax=, giới hạn RAM của container) hoặc sửa mức dùng RAM của dịch vụ.")}

	spLinkDown = &spec{ID: "nic_link_down", Comp: model.CompNetwork, Sev: model.Warn, Min: 4, Below: model.Info, Decay: true,
		Title:  model.T("Network link on {t} went down", "Link mạng trên {t} bị rớt"),
		Detail: model.T("The NIC lost its link. Once can be a planned cable or switch change; repeated drops (link flapping) mean a bad cable, transceiver, switch port or NIC.", "Card mạng mất link. Một lần có thể do thay cáp hoặc switch có kế hoạch; rớt nhiều lần (link flapping) là do cáp, module quang, cổng switch hoặc card mạng lỗi."),
		Action: actNIC}
	spBondDown = &spec{ID: "bond_no_active_link", Comp: model.CompNetwork, Sev: model.Warn, CritRecent: true,
		Title:  model.T("Bond {t} lost all its links", "Bond {t} mất toàn bộ link"),
		Detail: model.T("The bonding driver had no active interface left: the server was cut off on this bond.", "Driver bonding không còn interface nào hoạt động: máy chủ bị mất kết nối trên bond này."),
		Action: model.T("Check every member of {t} (cat /proc/net/bonding/{t}), their cables and switch ports. Members that went down at the same time point to the switch or its power.", "Kiểm tra từng thành viên của {t} (cat /proc/net/bonding/{t}), cáp và cổng switch. Nếu các thành viên rớt cùng lúc thì nghi switch hoặc nguồn của switch.")}
	spNICHang = &spec{ID: "nic_tx_timeout", Comp: model.CompNetwork, Sev: model.Warn, Decay: true,
		Title:  model.T("NIC {t} stopped transmitting (TX timeout / hardware hang)", "Card mạng {t} ngừng truyền (TX timeout / treo phần cứng)"),
		Detail: model.T("The network driver detected that {t} stopped sending packets and reset it. Each reset drops traffic briefly.", "Driver mạng phát hiện {t} ngừng gửi gói và đã reset nó. Mỗi lần reset làm mất kết nối trong giây lát."),
		Action: model.T("Update the NIC firmware and driver; on Intel e1000e/igb try disabling TSO/GSO (ethtool -K {t} tso off gso off). Replace the NIC if hangs continue.", "Cập nhật firmware và driver card mạng; với Intel e1000e/igb thử tắt TSO/GSO (ethtool -K {t} tso off gso off). Thay card mạng nếu vẫn treo.")}

	spFirmware = &spec{ID: "firmware_messages", Comp: model.CompSystem, Sev: model.Info, Min: 100, Below: model.OK,
		Title:  model.T("Frequent ACPI/firmware error messages", "Nhiều thông báo lỗi ACPI/firmware"),
		Detail: model.T("The BIOS/ACPI tables produce errors the kernel keeps reporting. Usually harmless noise (and not a hardware fault), but a BIOS update often removes it and fixes power-management bugs.", "BIOS/bảng ACPI sinh ra lỗi mà kernel liên tục báo. Thường chỉ là nhiễu vô hại (không phải lỗi phần cứng), nhưng cập nhật BIOS thường hết và sửa luôn lỗi quản lý điện."),
		Action: model.T("Update the BIOS/UEFI firmware when convenient.", "Cập nhật BIOS/UEFI khi thuận tiện.")}

	spSmartPending = &spec{ID: "smartd_pending_sectors", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("smartd: disk {t} has unreadable (pending) sectors", "smartd: ổ {t} có sector không đọc được (pending)"),
		Detail: model.T("smartd saw Current_Pending_Sector or Offline_Uncorrectable above zero: sectors whose data could not be read. Backblaze's drive statistics show these attributes strongly predict failure.", "smartd thấy Current_Pending_Sector hoặc Offline_Uncorrectable lớn hơn 0: các sector không đọc được dữ liệu. Thống kê ổ cứng của Backblaze cho thấy các chỉ số này báo trước ổ sắp hỏng rất rõ."),
		Action: actDiskReplace}
	spSmartFail = &spec{ID: "smartd_failure", Comp: model.CompDisk, Sev: model.Crit,
		Title:  model.T("smartd: disk {t} failed a S.M.A.R.T. check", "smartd: ổ {t} không đạt kiểm tra S.M.A.R.T."),
		Detail: model.T("smartd reported a failed health check, a failed self-test, a failing attribute or an NVMe critical warning for {t}.", "smartd báo {t} không đạt kiểm tra sức khỏe, self-test lỗi, có chỉ số ở ngưỡng hỏng hoặc NVMe có critical warning."),
		Action: actDiskReplace}
	spSmartWarn = &spec{ID: "smartd_warning", Comp: model.CompDisk, Sev: model.Warn,
		Title:  model.T("smartd: disk {t} reports rising error counters", "smartd: ổ {t} có bộ đếm lỗi tăng lên"),
		Detail: model.T("smartd saw reallocated-sector or ATA error counters on {t} increase. The disk is wearing out or remapping bad sectors.", "smartd thấy bộ đếm sector bị thay thế (reallocated) hoặc lỗi ATA trên {t} tăng. Ổ đang xuống cấp hoặc đang thay thế sector hỏng."),
		Action: model.T("Run smartctl -a {t} and compare with earlier values; make sure backups are current and plan the replacement if counters keep rising.", "Chạy smartctl -a {t} và so với các lần trước; đảm bảo bản sao lưu còn mới và lên kế hoạch thay ổ nếu bộ đếm tiếp tục tăng.")}
	spSmartTemp = &spec{ID: "smartd_temperature", Comp: model.CompThermal, Sev: model.Warn, Decay: true,
		Title:  model.T("smartd: disk {t} reached its temperature limit", "smartd: ổ {t} chạm ngưỡng nhiệt độ"),
		Detail: model.T("The disk temperature reached the limit configured in smartd.conf.", "Nhiệt độ ổ chạm ngưỡng cấu hình trong smartd.conf."),
		Action: actThermal}
	spSmartGone = &spec{ID: "smartd_device_lost", Comp: model.CompDisk, Sev: model.Warn, Decay: true,
		Title:  model.T("smartd: disk {t} disappeared", "smartd: ổ {t} biến mất"),
		Detail: model.T("smartd could no longer open {t}: the disk was removed, dropped off the bus, or its name changed.", "smartd không mở được {t} nữa: ổ đã bị rút, rớt khỏi bus hoặc bị đổi tên."),
		Action: model.T("Check that {t} is still present (lsblk, RAID controller). If it was not removed on purpose, check its slot/cable and its S.M.A.R.T. data.", "Kiểm tra {t} còn được nhận không (lsblk, card RAID). Nếu không phải rút có chủ đích, kiểm tra khe/cáp và dữ liệu S.M.A.R.T. của ổ.")}
	spIPMIEvd = &spec{ID: "ipmievd_event", Comp: model.CompBMC, Sev: model.Warn, Decay: true,
		Title:  model.T("BMC reported a hardware event ({t})", "BMC báo sự kiện phần cứng ({t})"),
		Detail: model.T("ipmievd copied a BMC system event log entry about a failure or critical threshold to the system log.", "ipmievd đã chép một sự kiện từ log BMC về lỗi hoặc ngưỡng nguy hiểm vào log hệ thống."),
		Action: model.T("Check the full BMC event log (ipmitool sel elist) and the sensor ({t}); replace the failed part.", "Xem toàn bộ log sự kiện BMC (ipmitool sel elist) và cảm biến ({t}); thay linh kiện bị lỗi.")}
)

// mcStatusUC reports whether an MCi_STATUS value has the UC (uncorrected)
// bit set: bit 61 (Intel SDM vol. 3B, 16.3.2.2; AMD APM vol. 2, 9.3.2).
func mcStatusUC(hex string) (uc, ok bool) {
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return false, false
	}
	if v>>63 == 0 { // VAL bit clear: nothing valid in this bank
		return false, false
	}
	return v>>61&1 == 1, true
}

// edacTarget names the DIMM in an EDAC line.
var (
	reEdacOn    = regexp.MustCompile(`\bon (\S+?)(?:\s+\(|$|\s)`)
	reEdacLabel = regexp.MustCompile(`label "([^"]+)"`)
)

func edacTarget(m []string, l logLine, _ *matchCtx) string {
	if x := reEdacLabel.FindStringSubmatch(l.Msg); x != nil {
		return x[1]
	}
	if x := reEdacOn.FindStringSubmatch(l.Msg); x != nil && x[1] != "unknown" {
		return x[1]
	}
	if len(m) > 1 {
		return m[1]
	}
	return "memory"
}

var reBDF = regexp.MustCompile(`\b([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b`)

func pcieTarget(m []string, l logLine, _ *matchCtx) string {
	if len(m) > 2 && m[2] != "" {
		return m[2]
	}
	if x := reBDF.FindStringSubmatch(l.Msg); x != nil {
		return x[1]
	}
	return "PCIe"
}

func mdTarget(m []string, _ logLine, _ *matchCtx) string {
	if len(m) > 1 {
		return devPath(m[1])
	}
	return ""
}

func ipmiTarget(m []string, _ logLine, _ *matchCtx) string {
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func r(sp *spec, re string, target func([]string, logLine, *matchCtx) string) rule {
	return rule{sp: sp, re: regexp.MustCompile(re), target: target}
}

// smartdDev matches the device part of a smartd line: "Device: /dev/sda [SAT], "
// or "Device: /dev/bus/0 [megaraid_disk_03] [SAT], ".
const smartdDev = `^Device: (/dev/\S+?(?: \[\w+_disk_\d+\])?)(?: \[[^\]]+\])?,? `

// rules is the Linux pattern library, in matching order.
var rules = buildRules()

func buildRules() []rule {
	rs := []rule{
		// ---- fatal first ----
		r(spHWPanic, `Kernel panic - not syncing: .*(?:[Mm]achine [Cc]heck|[Hh]ardware [Ee]rror|MCE)`, fixed("CPU")),
		r(spPanic, `Kernel panic - not syncing`, fixed("kernel")),

		// ---- disks: block layer ----
		{sp: spDiskMedium, re: regexp.MustCompile(`\bcritical medium error,? dev ([^\s,]+)`), target: diskGrp(1), skip: skipNotDisk(1)},
		{sp: spDiskIO, re: regexp.MustCompile(`\b(I/O) error,? dev ([^\s,]+),? sector`), target: diskGrp(2), skip: skipIOErr},
		{sp: spDiskCmd, re: regexp.MustCompile(`\b(?:critical target|critical nexus|recoverable transport|timeout) error,? dev ([^\s,]+)`), target: diskGrp(1), skip: skipNotDisk(1)},
		{sp: spDiskProt, re: regexp.MustCompile(`\bprotection error,? dev ([^\s,]+)`), target: diskGrp(1), skip: skipNotDisk(1)},
		{sp: spDiskIO, re: regexp.MustCompile(`Buffer I/O error on (?:dev(?:ice)? )?([^\s,]+)`), target: diskGrp(1), skip: skipNotDisk(1)},
		// ---- disks: SCSI ----
		{sp: spDiskMedium, re: regexp.MustCompile(`Sense Key ?: ?Medium Error|Add\. Sense: Unrecovered read error|Unrecovered read error - auto reallocate failed`), target: scsiTarget, skip: skipSCSINotDisk},
		{sp: spDiskHW, re: regexp.MustCompile(`Sense Key ?: ?Hardware Error`), target: scsiTarget, skip: skipSCSINotDisk},
		{sp: spDiskOffline, re: regexp.MustCompile(`rejecting I/O to (?:offline|dead) device|Device offlined - not ready after error recovery`), target: scsiTarget, skip: skipSCSINotDisk},
		{sp: spDiskCmd, re: regexp.MustCompile(`Sense Key ?: ?Aborted Command|timing out command, waited \d+s|FAILED Result: hostbyte=DID_(?:TIME_OUT|ABORT|ERROR|RESET|BAD_TARGET|NO_CONNECT|SOFT_ERROR|TRANSPORT_\w+)`), target: scsiTarget, skip: skipSCSINotDisk},
		// ---- disks: SATA (libata) ----
		r(spDiskMedium, `^(ata\d+)(?:\.\d+)?: error: \{[^}]*\bUNC\b`, grp(1)),
		r(spCRC, `^(ata\d+)(?:\.\d+)?: error: \{[^}]*\bICRC\b|^(ata\d+): SError: \{[^}]*\bBadCRC\b`, func(m []string, _ logLine, _ *matchCtx) string {
			if m[1] != "" {
				return m[1]
			}
			return m[2]
		}),
		r(spDiskOffline, `^(ata\d+)(?:\.\d+)?: disabled$`, grp(1)),
		r(spATA, `^(ata\d+)(?:\.\d+)?: exception Emask`, grp(1)),
		r(spATA, `^(ata\d+): (?:hard resetting link|COMRESET failed|link is slow to respond)`, grp(1)),
		{sp: spATA, re: regexp.MustCompile(`^(ata\d+)(?:\.\d+)?: (?:failed command:|status: \{|SATA link down|soft resetting link|cmd [0-9a-f]{2}/)`), target: grp(1), evidence: true},
		// ---- disks: NVMe ----
		r(spNVMeDead, `^nvme (nvme\d+): (?:controller is down; will reset: CSTS=0xffffffff|Device not ready; aborting (?:reset|initialisation)|Removing after probe failure|Disabling device after reset failure)`, grp(1)),
		r(spNVMeTimeout, `^nvme (nvme\d+): (?:I/O (?:tag )?\d+ .*QID \d+ timeout|controller is down; will reset)`, grp(1)),
		{sp: spNVMeTimeout, re: regexp.MustCompile(`^nvme (nvme\d+): (?:resetting controller|Abort status:)`), target: grp(1), evidence: true},
		// Status code type 2 is "Media and Data Integrity Errors" (NVMe base
		// spec, Figure "Status Code - Media and Data Integrity Errors"), but
		// 0x86 Access Denied (locked Opal range) and 0x87 Deallocated or
		// Unwritten Logical Block (reading a trimmed block with DULBE set)
		// are not media defects.
		{sp: spDiskMedium, re: regexp.MustCompile(`^(nvme\d+n\d+): .*\(sct 0x2 / sc 0x([0-9a-f]+)\)`), target: diskGrp(1),
			skip: func(m []string, _ logLine) bool { return m[2] == "86" || m[2] == "87" }},
		// ---- storage controllers ----
		r(spHBAFault, `^(mpt[23]sas_cm\d+): fault_state\(0x[0-9a-f]+\)`, grp(1)),
		r(spHBAFault, `^megaraid_sas (\S+): (?:Found )?FW in FAULT state|^(megasas): FW in FAULT state`, func(m []string, _ logLine, _ *matchCtx) string {
			if m[1] != "" {
				return "megaraid_sas " + m[1]
			}
			return "megaraid_sas"
		}),
		r(spHBAFault, `^(hpsa|smartpqi|aacraid) (\S+): .*(?:Controller lockup detected|controller is offline|[Cc]ontroller (?:fault|failed))`, func(m []string, _ logLine, _ *matchCtx) string { return m[1] + " " + m[2] }),
		r(spHBAReset, `^(mpt[23]sas_cm\d+): sending diag reset`, grp(1)),
		r(spHBAReset, `^megaraid_sas (\S+): (?:resetting fusion adapter|Controller encountered an fatal error|OCR)`, func(m []string, _ logLine, _ *matchCtx) string { return "megaraid_sas " + m[1] }),

		// ---- filesystems ----
		{sp: spFSReadOnly, re: regexp.MustCompile(`EXT[234]-fs \(([^)]+)\): (?:error: )?[Rr]emounting filesystem read-only`), target: devGrp(1), skip: skipNotDisk(1)},
		{sp: spFSReadOnly, re: regexp.MustCompile(`XFS \(([^)]+)\): (?:.*Shutting down filesystem|Filesystem has been shut down|xfs_do_force_shutdown)`), target: devGrp(1), skip: skipNotDisk(1)},
		// Since 6.x btrfs adds the filesystem state: "BTRFS info (device dm-0: state EA): forced readonly" (fs/btrfs/messages.c).
		{sp: spFSReadOnly, re: regexp.MustCompile(`BTRFS(?: \w+)?:? \(device ([^):\s]+)(?:: state \w+)?\):? (?:.*)?forced readonly`), target: devGrp(1), skip: skipNotDisk(1)},
		{sp: spFSRecorded, re: regexp.MustCompile(`EXT[34]-fs \(([^)]+)\): error count since last fsck: (\d+)`), target: devGrp(1), skip: skipNotDisk(1)},
		{sp: spFSError, re: regexp.MustCompile(`EXT[234]-fs error \(device ([^)]+)\)|EXT[234]-fs \(([^)]+)\): I/O error while writing superblock`), target: func(m []string, _ logLine, _ *matchCtx) string {
			if m[1] != "" {
				return devPath(m[1])
			}
			return devPath(m[2])
		}, skip: func(m []string, _ logLine) bool { return notDiskRe.MatchString(m[1]) || notDiskRe.MatchString(m[2]) }},
		{sp: spFSError, re: regexp.MustCompile(`XFS \(([^)]+)\): (?:Corruption|Metadata corruption|Metadata CRC error|metadata I/O error|Log I/O Error|log I/O error|Corruption warning)`), target: devGrp(1), skip: skipNotDisk(1)},
		{sp: spFSCsum, re: regexp.MustCompile(`BTRFS warning \(device ([^):\s]+)(?:: state \w+)?\): csum failed`), target: devGrp(1), skip: skipNotDisk(1)},
		{sp: spFSError, re: regexp.MustCompile(`BTRFS(?:: error| error| critical) \(device ([^):\s]+)(?:: state \w+)?\)`), target: devGrp(1), skip: skipNotDisk(1)},
		// ---- md software RAID (kernel side) ----
		{sp: spMDFail, re: regexp.MustCompile(`md/raid\d*:(md\d+): Disk failure on (\S+?),? disabling device`), target: mdTarget, skip: skipNotDisk(2)},
		{sp: spMDFail, re: regexp.MustCompile(`md/raid\d*:(md\d+): Operation continuing on \d+ devices`), target: mdTarget, evidence: true},

		// ---- memory / CPU ----
		r(spMemUE, `EDAC (?:\S+ )?(MC\d+): (?:\d+ )?UE\b`, edacTarget),
		r(spMemCE, `EDAC (?:\S+ )?(MC\d+): (?:\d+ )?CE\b`, edacTarget),
		r(spMemPoison, `^Memory failure: (0x[0-9a-f]+): |^MCE (0x[0-9a-f]+): .*recovery`, fixed("RAM")),
		r(spThermCrit, `(?:thermal (\S+?):? |ACPI: )?[Cc]ritical temperature reached`, func(m []string, _ logLine, _ *matchCtx) string {
			if m[1] != "" {
				return m[1]
			}
			return "thermal zone"
		}),
		{sp: spThrottle, re: reThrottle, target: fixed("CPU")},
		r(spMCECorr, `Machine check events logged`, fixed("CPU")),

		// ---- PCIe AER ----
		r(spPCIeFatal, `^(?:(\S+) )?(\S+): (?:AER: )?PCIe Bus Error: severity=Uncorrect(?:ed|able) \(Fatal\)`, pcieTarget),
		r(spPCIeNonFatal, `^(?:(\S+) )?(\S+): (?:AER: )?PCIe Bus Error: severity=Uncorrect(?:ed|able) \(Non-Fatal\)`, pcieTarget),
		r(spPCIeCorr, `^(?:(\S+) )?(\S+): (?:AER: )?PCIe Bus Error: severity=Correct(?:ed|able)`, pcieTarget),

		// ---- kernel stability ----
		r(spHardLockup, `[Ww]atchdog detected hard LOCKUP on cpu`, fixed("CPU")),
		r(spSoftLockup, `BUG: soft lockup - CPU#\d+ stuck for|self-detected stall on CPU|detected stalls on CPUs`, fixed("CPU")),
		r(spHungTask, `INFO: task \S+ blocked for more than \d+ seconds`, fixed("I/O")),
		r(spOops, `kernel BUG at |BUG: unable to handle (?:kernel )?(?:NULL pointer dereference|paging request|page fault)|^(?:Oops: )?general protection fault[,:]|^Oops: [0-9a-f]{4} `, fixed("kernel")),
		r(spNMI, `NMI received for unknown reason|^Dazed and confused, but trying to continue|NMI: (?:PCI system error \(SERR\)|IOCK error)`, fixed("NMI")),
		r(spOOMcg, `Memory cgroup out of memory: Kill(?:ed)? process`, fixed("cgroup")),
		r(spOOM, `^Out of memory(?: \([^)]*\))?: Kill(?:ed)? process`, fixed("RAM")),

		// ---- network ----
		r(spBondDown, `^([\w.@-]+): now running without any active interface`, grp(1)),
		r(spLinkDown, `\(slave ([\w.@-]+)\): link status definitely down|link status definitely down for interface ([\w.@-]+)`, func(m []string, _ logLine, _ *matchCtx) string {
			if m[1] != "" {
				return m[1]
			}
			return m[2]
		}),
		{sp: spLinkDown, re: regexp.MustCompile(`([A-Za-z][\w.@-]*):? (?:NIC )?[Ll]ink (?:is )?[Dd]own\b`), target: grp(1),
			skip: func(m []string, l logLine) bool {
				return strings.HasPrefix(l.Msg, "IPv6") || m[1] == "NIC" || virtualIfRe.MatchString(m[1])
			}},
		r(spNICHang, `NETDEV WATCHDOG: ([\w.@-]+) \([^)]*\): transmit (?:queue \d+ )?timed out`, grp(1)),
		r(spNICHang, `([\w.@-]+): (?:Detected (?:Hardware|Tx) Unit Hang|[Tt][Xx] timeout)`, grp(1)),

		// ---- firmware noise ----
		r(spFirmware, `^(?:ACPI (?:BIOS )?(?:Error|Warning|Exception)|\[Firmware Bug\])`, fixed("BIOS/ACPI")),

		// ---- daemons ----
		{sp: spSmartPending, tag: "smartd", re: regexp.MustCompile(smartdDev + `\d+ (?:Currently unreadable \(pending\)|Offline uncorrectable) sectors`), target: grp(1)},
		{sp: spSmartFail, tag: "smartd", re: regexp.MustCompile(smartdDev + `(?:FAILED SMART self-check|SMART Failure|Failed SMART usage Attribute|Self-Test Log error count increased|Critical Warning \(0x[0-9a-f]+\))`), target: grp(1)},
		{sp: spSmartWarn, tag: "smartd", re: regexp.MustCompile(smartdDev + `(?:ATA error count increased|SMART Prefailure Attribute: (?:5|196) \S+ changed from)`), target: grp(1)},
		{sp: spSmartTemp, tag: "smartd", re: regexp.MustCompile(smartdDev + `Temperature \d+ Celsius reached (?:critical )?limit`), target: grp(1)},
		{sp: spSmartGone, tag: "smartd", re: regexp.MustCompile(smartdDev + `(?:open\(\) failed|removed (?:ATA|SCSI) device)`), target: grp(1)},
		// DeviceDisappeared means the array was stopped (mdadm(8), MONITOR
		// MODE), not a failure. Members on loop devices are test arrays.
		{sp: spMDFail, tag: "mdadm", re: regexp.MustCompile(`^(?:mdadm: )?(?:Fail|FailSpare|DegradedArray) event detected on md device (/dev/\S+?),?(?:\s|$)`), target: mdTarget,
			skip: func(_ []string, l logLine) bool { return strings.Contains(l.Msg, "component device /dev/loop") }},
		{sp: spMDSpare, tag: "mdadm", re: regexp.MustCompile(`^(?:mdadm: )?SparesMissing event detected on md device (/dev/\S+?),?(?:\s|$)`), target: mdTarget},
		{sp: spMemCE, tag: "mcelog", re: regexp.MustCompile(`(?:[Cc]orrected memory errors|memory error count).*exceed`), target: fixed("memory")},
		{sp: spIPMIEvd, tag: "ipmievd", re: regexp.MustCompile(`(?i)\b(power supply|fan|temperature|memory|processor|voltage|critical interrupt)\b.*\b(fail\w*|critical|non-recoverable|lost|uncorrectable|predictive)\b`), target: ipmiTarget,
			skip: func(_ []string, l logLine) bool { return strings.Contains(strings.ToLower(l.Msg), "deasserted") }},
	}
	// The same message from the same daemon can be logged under a slightly
	// different tag (mdmonitor on RHEL).
	for i := range rs {
		if rs[i].tag == "mdadm" {
			rs = append(rs, rule{sp: rs[i].sp, tag: "mdmonitor", re: rs[i].re, target: rs[i].target})
		}
	}
	return rs
}

// Lines that clear an earlier smartd warning for a device.
var reSmartdReset = regexp.MustCompile(smartdDev + `No more (?:Currently unreadable \(pending\)|Offline uncorrectable) sectors`)

// MCE bank lines: "mce: [Hardware Error]: CPU 3: Machine Check: 0 Bank 5: be00000000800400".
var reMCEBank = regexp.MustCompile(`\[Hardware Error\]: CPU (\d+): Machine Check(?: Exception)?: \S+ Bank (\d+): ([0-9a-f]{16})`)

// GHES/APEI records: "{1}[Hardware Error]: event severity: corrected", followed
// by "section_type: memory error" a few lines later.
var (
	reGHESSev     = regexp.MustCompile(`(?:\{(\d+)\})?\[Hardware Error\]: event severity: (corrected|recoverable|fatal)`)
	reGHESSection = regexp.MustCompile(`section_type: (.+?)\s*$`)
	reGHESDevice  = regexp.MustCompile(`\bdevice_id: ([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b`)
)

// ATA identify lines give the disk model on a port: "ata1.00: ATA-9: ST4000NM0035-1V4107, TN03, max UDMA/133".
var reATAIdent = regexp.MustCompile(`^(ata\d+)\.\d+: ATA-\d+: (.+?), (\S+), max`)

// Virtual network interfaces (containers, VM taps, Proxmox firewall
// bridges, tunnels): their links go up and down with the guests, which is
// not a NIC or cable problem.
var virtualIfRe = regexp.MustCompile(`^(?:veth|tap|tun|vnet|fwpr|fwln|fwbr|docker|br-|virbr|cali|flannel|cni|lxc|vxlan|wg|kube-|weave|genev|vmbr\d+v)`)

func ruleTag(tag string) string {
	if tag == "" {
		return "kernel"
	}
	return tag
}

// CPU thermal throttling (arch/x86/kernel/cpu/mce/therm_throt.c).
var reThrottle = regexp.MustCompile(`CPU\d+: (?:Core|Package) temperature (?:is )?above threshold|Temperature above threshold, cpu clock throttled`)

// near reports whether t is within d of one of ts.
func near(t time.Time, ts []time.Time, d time.Duration) bool {
	if t.IsZero() {
		return false
	}
	for _, x := range ts {
		if t.Sub(x) <= d && x.Sub(t) <= d {
			return true
		}
	}
	return false
}
