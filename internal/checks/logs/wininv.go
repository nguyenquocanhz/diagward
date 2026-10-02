package logs

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// winInv is what the disk and filesystem domains' sections say about the
// disks and volumes attached now. The logs domain only reads these sections
// to judge its own events (a disk event for a USB disk, or for a disk that
// is no longer there, is not a server disk failure).
type winInv struct {
	disks     map[int]string // disk number -> bus type ("USB", "SATA", "RAID", "NVMe", ...; "" unknown)
	haveDisks bool
	vols      map[string]string // "G:" -> drive type ("Fixed", "Removable", ...)
	haveVols  bool
}

// Storage bus type 7 is USB (MSFT_PhysicalDisk.BusType); older collectors
// may have written the number instead of the name.
func usbBus(s string) bool {
	s = strings.TrimSpace(strings.ToUpper(s))
	return s == "USB" || s == "7"
}

func jsonStr(v any) string {
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
	return fmt.Sprint(v)
}

func readWinInv(b *collect.Bundle) winInv {
	inv := winInv{disks: map[int]string{}, vols: map[string]string{}}
	if s := b.Get("disk.win_physical"); s.Ran() {
		var rows []map[string]any
		if collect.DecodeJSON(s.Out, &rows) == nil && len(rows) > 0 {
			for _, r := range rows {
				n, err := strconv.Atoi(jsonStr(r["DeviceId"]))
				if err != nil {
					continue
				}
				inv.haveDisks = true
				if bus := jsonStr(r["BusType"]); bus != "" || inv.disks[n] == "" {
					inv.disks[n] = bus
				}
			}
		}
	}
	if s := b.Get("disk.win_diskdrive"); s.Ran() {
		var rows []map[string]any
		if collect.DecodeJSON(s.Out, &rows) == nil && len(rows) > 0 {
			for _, r := range rows {
				n, err := strconv.Atoi(jsonStr(r["Index"]))
				if err != nil {
					continue
				}
				inv.haveDisks = true
				usb := strings.EqualFold(jsonStr(r["InterfaceType"]), "USB") ||
					strings.HasPrefix(strings.ToUpper(jsonStr(r["PNPDeviceID"])), "USBSTOR\\")
				switch {
				case usb:
					inv.disks[n] = "USB"
				case inv.disks[n] == "":
					inv.disks[n] = jsonStr(r["InterfaceType"])
				}
			}
		}
	}
	if s := b.Get("filesystem.win_volume"); s.Ran() {
		var rows []map[string]any
		if collect.DecodeJSON(s.Out, &rows) == nil && len(rows) > 0 {
			inv.haveVols = true
			for _, r := range rows {
				l := strings.TrimSuffix(jsonStr(r["DriveLetter"]), ":")
				if len(l) != 1 {
					continue
				}
				inv.vols[strings.ToUpper(l)+":"] = jsonStr(r["DriveType"])
			}
		}
	}
	return inv
}

// Win32_Volume/Get-Volume drive type 2 is "Removable".
func removableDrive(s string) bool {
	return strings.EqualFold(s, "Removable") || s == "2"
}

// usbWindow: a disk/NTFS event this close to a reset logged by the USB
// storage drivers (UASPStor, USBSTOR) is taken to be about that USB disk.
// Windows writes them in the same burst (reset, retried I/O, paging error,
// failed NTFS log flush) — seen in real_win_events.json.
const usbWindow = 10 * time.Minute

func nearAny(ts, ref []time.Time, d time.Duration) bool {
	for _, t := range ts {
		if t.IsZero() {
			continue
		}
		for _, r := range ref {
			if !r.IsZero() && t.Sub(r) <= d && r.Sub(t) <= d {
				return true
			}
		}
	}
	return false
}

// judgeWinDevices lowers disk and NTFS groups that are about USB disks, or
// about disks/volumes that are no longer attached, using the inventory and
// the USB storage resets.
func judgeWinDevices(groups []*group, times map[*group][]time.Time, usbTimes []time.Time, inv winInv, now time.Time) {
	// A disk or volume seen next to USB resets once is a USB device for all
	// its events: NTFS logs "needs chkdsk" (98) when the USB disk comes back,
	// often well after the resets themselves.
	usbTarget := map[string]bool{}
	for _, g := range groups {
		if nearAny(times[g], usbTimes, usbWindow) {
			usbTarget[g.target] = true
		}
	}
	for _, g := range groups {
		isDisk := strings.HasPrefix(g.target, "PhysicalDrive")
		isVol := g.spec.Comp == model.CompFilesystem && g.target != ""
		if !isDisk && !isVol {
			continue
		}
		known, usb, gone := false, false, false
		how := ""
		if isDisk {
			if n, err := strconv.Atoi(strings.TrimPrefix(g.target, "PhysicalDrive")); err == nil && inv.haveDisks {
				if bus, ok := inv.disks[n]; ok {
					known, usb = true, usbBus(bus)
					how = "inventory"
				} else {
					gone = true
				}
			}
		} else if reVolume.MatchString(g.target) && inv.haveVols {
			if dt, ok := inv.vols[strings.ToUpper(g.target)]; ok {
				known, usb = true, removableDrive(dt)
				how = "inventory"
			} else {
				gone = true
			}
		}
		if !known && usbTarget[g.target] {
			usb, how = true, "resets"
		}
		recent := !g.last.IsZero() && !now.IsZero() && now.Sub(g.last) <= decayWindow
		switch {
		case usb:
			why := model.T("Windows lists it on the USB bus.", "Windows nhận ổ này qua cổng USB.")
			if how == "resets" {
				why = model.T("The USB storage driver UASPStor/USBSTOR reset a device around the same time.", "Driver lưu trữ USB UASPStor/USBSTOR phải reset thiết bị vào khoảng cùng thời gian đó.")
			}
			g.limit(model.Warn,
				model.Text{
					EN: "This is a USB disk, usually an external backup disk: the errors come from that disk, its USB cable or port, or from unplugging it while in use, not from a server disk. " + why.EN,
					VI: "Đây là ổ USB, thường là ổ sao lưu gắn ngoài: lỗi đến từ chính ổ USB đó, cáp hoặc cổng USB, hoặc do rút ổ khi đang dùng, không phải ổ cứng của máy chủ. " + why.VI},
				model.T("It is a USB disk: copy its data elsewhere, use another USB port/cable and always eject it before unplugging. Replace the USB disk if the errors come back.",
					"Đây là ổ USB: chép dữ liệu ra nơi khác, đổi cổng/cáp USB và luôn \"Eject\" trước khi rút. Thay ổ USB nếu lỗi còn lặp lại."))
			g.part = nil // not a server part for a warranty case
		case gone && !recent:
			g.limit(model.Warn,
				model.Tf("%s is no longer attached (not in the current disk/volume list) and its last event is more than 3 days old: if it was removed or replaced on purpose, this is history.",
					"Hiện không còn thấy %s (không có trong danh sách ổ/phân vùng hiện tại) và sự kiện cuối đã hơn 3 ngày: nếu đã tháo hoặc thay có chủ đích thì đây chỉ là lịch sử.", g.target),
				model.Tf("Confirm that %s was removed on purpose; if not, find out where it went (RAID controller, cabling).",
					"Xác nhận %s đã được tháo có chủ đích; nếu không, tìm xem ổ đã đi đâu (card RAID, dây cáp).", g.target))
		case gone:
			g.note = joinText(g.note, model.Tf("%s is no longer attached: if nobody removed it, it has dropped off the bus.",
				"Hiện không còn thấy %s: nếu không ai tháo ra thì ổ đã rớt khỏi hệ thống.", g.target))
		}
	}
}

// winCapped reads logs.win_meta and says whether the collector hit one of
// its caps (50,000 errors/warnings read, or DW_MAXLINES hardware events
// kept), so the coverage does not claim the whole period was checked.
// readCapped means the read itself was capped, so reboot events older than
// the oldest one read were not seen either.
func winCapped(b *collect.Bundle) (reason model.Text, readCapped bool) {
	s := b.Get("logs.win_meta")
	if !s.Ran() {
		return model.Text{}, false
	}
	var rows []struct {
		Read      int    `json:"read"`
		ReadMax   int    `json:"readMax"`
		Wanted    int    `json:"wanted"`
		WantedMax int    `json:"wantedMax"`
		Oldest    string `json:"oldest"`
	}
	if collect.DecodeJSON(s.Out, &rows) != nil || len(rows) == 0 {
		return model.Text{}, false
	}
	m := rows[0]
	switch {
	case m.ReadMax > 0 && m.Read >= m.ReadMax:
		oldest, _ := collect.WinTime(m.Oldest)
		return model.Tf("The System log has more than %d errors/warnings in the period; only the events since %s were read.",
			"Log System có hơn %d lỗi/cảnh báo trong khoảng thời gian này; chỉ đọc được các sự kiện từ %s trở lại đây.",
			m.ReadMax, fmtTime(oldest)), true
	case m.WantedMax > 0 && m.Wanted >= m.WantedMax:
		return model.Tf("More than %d hardware-related events in the period; only the newest %d were analysed.",
			"Có hơn %d sự kiện liên quan phần cứng trong khoảng thời gian này; chỉ phân tích %d sự kiện mới nhất.",
			m.WantedMax, m.WantedMax), false
	}
	return model.Text{}, false
}
