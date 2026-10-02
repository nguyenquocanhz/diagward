package logs

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// linuxInv is what the disk domain's lsblk section says about the block
// devices attached now (read only to judge the logs domain's own events).
type linuxInv struct {
	names map[string]bool // every NAME and KNAME (sda, sda1, dm-0, nvme0n1...)
	usb   map[string]bool // devices on the USB transport (and their partitions)
	have  bool
}

var reLsblkPair = regexp.MustCompile(`([A-Z:-]+)="([^"]*)"`)

func readLinuxInv(b *collect.Bundle) linuxInv {
	inv := linuxInv{names: map[string]bool{}, usb: map[string]bool{}}
	s := b.Get("disk.lsblk")
	if !s.Ran() {
		return inv
	}
	out := strings.TrimSpace(s.Out)
	if strings.HasPrefix(out, "{") {
		var doc struct {
			Blockdevices []map[string]any `json:"blockdevices"`
		}
		if json.Unmarshal([]byte(out), &doc) == nil {
			var walk func(nodes []map[string]any, usb bool)
			walk = func(nodes []map[string]any, usb bool) {
				for _, n := range nodes {
					u := usb || strings.EqualFold(jsonStr(n["tran"]), "usb")
					for _, k := range []string{"name", "kname"} {
						if v := jsonStr(n[k]); v != "" {
							inv.names[v] = true
							inv.have = true
							if u {
								inv.usb[v] = true
							}
						}
					}
					if ch, ok := n["children"].([]any); ok {
						var kids []map[string]any
						for _, c := range ch {
							if m, ok := c.(map[string]any); ok {
								kids = append(kids, m)
							}
						}
						walk(kids, u)
					}
				}
			}
			walk(doc.Blockdevices, false)
		}
		return inv
	}
	// lsblk -P: one device per line, KEY="value"; partitions name their
	// parent in PKNAME (util-linux >= 2.23).
	parent := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		kv := map[string]string{}
		for _, m := range reLsblkPair.FindAllStringSubmatch(l, -1) {
			kv[m[1]] = m[2]
		}
		name := kv["NAME"]
		if name == "" {
			continue
		}
		inv.have = true
		for _, v := range []string{name, kv["KNAME"]} {
			if v == "" {
				continue
			}
			inv.names[v] = true
			if strings.EqualFold(kv["TRAN"], "usb") {
				inv.usb[v] = true
			}
			if kv["PKNAME"] != "" {
				parent[v] = kv["PKNAME"]
			}
		}
	}
	for c, p := range parent {
		if inv.usb[p] {
			inv.usb[c] = true
		}
	}
	return inv
}

var (
	// "scsi host6: usb-storage 2-1.4:1.0" (4.x+), "scsi6 : usb-storage
	// 2-1.4:1.0" (3.10, CentOS 7), "scsi host7: uas".
	reUSBHost = regexp.MustCompile(`\bscsi ?(?:host)?(\d+) ?: (?:usb-storage|uas)\b`)
	// "sd 6:0:0:0: [sdb] Attached SCSI removable disk".
	reRemovable = regexp.MustCompile(`\[(sd[a-z]+)\] Attached SCSI removable disk`)
	// Block devices whose presence can be checked in lsblk.
	reCheckableDev = regexp.MustCompile(`^(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|nvme\d+|mmcblk\d+)$`)
)

// usbDisk reports whether dev ("/dev/sdb", "/dev/sdb1") is a USB disk,
// from lsblk (TRAN=usb) or from the kernel log (attached through
// usb-storage/uas, or announced as a removable disk).
func usbDisk(dev string, inv linuxInv, ctx *matchCtx) bool {
	name := strings.TrimPrefix(diskOf(dev), "/dev/")
	if name == "" {
		return false
	}
	if inv.usb[name] || inv.usb[strings.TrimPrefix(dev, "/dev/")] {
		return true
	}
	if ctx == nil {
		return false
	}
	if ctx.removable[name] {
		return true
	}
	for hctl, d := range ctx.hctl {
		if d != name {
			continue
		}
		if h, _, ok := strings.Cut(hctl, ":"); ok && ctx.usbHosts[h] {
			return true
		}
	}
	return false
}

// presentNow reports whether dev is still attached (lsblk), and whether
// that could be checked at all.
func presentNow(dev string, inv linuxInv) (present, checkable bool) {
	name := strings.TrimPrefix(diskOf(dev), "/dev/")
	if !inv.have || !reCheckableDev.MatchString(name) {
		return true, false
	}
	if inv.names[name] {
		return true, true
	}
	if strings.HasPrefix(name, "nvme") && !strings.Contains(name[4:], "n") {
		// An NVMe controller (nvme1): present if any of its namespaces is.
		for n := range inv.names {
			if strings.HasPrefix(n, name+"n") {
				return true, true
			}
		}
	}
	return false, true
}

// judgeLinuxDevices lowers disk and filesystem groups about USB disks, and
// about disks that are no longer attached and have been quiet for 3 days.
func judgeLinuxDevices(groups []*group, inv linuxInv, ctx *matchCtx, now time.Time) {
	for _, g := range groups {
		c := g.component()
		if c != model.CompDisk && c != model.CompFilesystem {
			continue
		}
		dev := g.target
		if !strings.HasPrefix(dev, "/dev/") && !strings.HasPrefix(dev, "nvme") {
			continue
		}
		if strings.HasPrefix(dev, "/dev/bus/") || strings.HasPrefix(dev, "/dev/md") || strings.HasPrefix(dev, "/dev/dm-") {
			continue
		}
		recent := !g.last.IsZero() && !now.IsZero() && now.Sub(g.last) <= decayWindow
		if usbDisk(dev, inv, ctx) {
			g.limit(model.Warn,
				model.T("This is a USB disk (usb-storage/uas), usually an external backup disk or a USB stick: the errors come from that disk, its USB cable or port, or from unplugging it while in use, not from a server disk.",
					"Đây là ổ USB (usb-storage/uas), thường là ổ sao lưu gắn ngoài hoặc USB: lỗi đến từ chính ổ USB đó, cáp hoặc cổng USB, hoặc do rút ổ khi đang dùng, không phải ổ cứng của máy chủ."),
				model.T("It is a USB disk: copy its data elsewhere, try another USB port/cable and unmount it (umount) before unplugging. Replace the USB disk if the errors come back.",
					"Đây là ổ USB: chép dữ liệu ra nơi khác, đổi cổng/cáp USB và umount trước khi rút. Thay ổ USB nếu lỗi còn lặp lại."))
			g.part = nil
			continue
		}
		present, checkable := presentNow(dev, inv)
		if !checkable || present {
			continue
		}
		name := diskOf(dev)
		if strings.HasPrefix(dev, "nvme") {
			name = dev
		}
		if recent {
			g.note = joinText(g.note, model.Tf("%s is no longer in the current disk list (lsblk): if nobody removed it, it has dropped off the bus.",
				"Hiện lsblk không còn thấy %s: nếu không ai tháo ra thì ổ đã rớt khỏi hệ thống.", name))
			continue
		}
		g.limit(model.Warn,
			model.Tf("%s is no longer in the current disk list (lsblk) and its last event is more than 3 days old: if it was removed or replaced on purpose, this is history (device names can also change after a reboot).",
				"Hiện lsblk không còn thấy %s và sự kiện cuối đã hơn 3 ngày: nếu ổ đã được tháo hoặc thay có chủ đích thì đây chỉ là lịch sử (tên thiết bị cũng có thể đổi sau khi khởi động lại).", name),
			model.Tf("Confirm that %s was removed on purpose; if not, check the RAID controller and the cabling for a disk that dropped out.",
				"Xác nhận %s đã được tháo có chủ đích; nếu không, kiểm tra card RAID và dây cáp xem có ổ nào bị rớt.", name))
	}
}

// currentBootStart is when the running boot began, from the journal's boot
// list (logs.boots), or zero when unknown.
func currentBootStart(b *collect.Bundle, now time.Time) time.Time {
	s := b.Get("logs.boots")
	if !s.Ran() {
		return time.Time{}
	}
	boots, _ := parseBoots(s.Out, now)
	for _, bi := range boots {
		if bi.idx == 0 {
			return bi.first
		}
	}
	return time.Time{}
}

// noteEarlierBoot warns that sdX names of an earlier boot may now belong to
// another disk: the kernel names disks in probe order at every boot.
func noteEarlierBoot(groups []*group, boot time.Time) {
	if boot.IsZero() {
		return
	}
	for _, g := range groups {
		if g.part == nil || g.last.IsZero() || !g.last.Before(boot) || !strings.HasPrefix(g.target, "/dev/sd") {
			continue
		}
		g.note = joinText(g.note, model.Tf("All these events are from before the last boot (%s); sdX names can change at boot, so confirm the disk by its serial (smartctl -i %s) before replacing it.",
			"Các sự kiện này đều trước lần khởi động gần nhất (%s); tên sdX có thể đổi sau khi khởi động, nên xác nhận ổ theo serial (smartctl -i %s) trước khi thay.", fmtTime(boot), g.target))
	}
}
