package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// ataDisk is one disk under a libata port, from its sysfs path.
type ataDisk struct {
	dev     string // "sda"
	channel int    // SCSI channel: the port-multiplier link (0 without one)
	id      int    // SCSI id: the device number on a PATA-style port (0 on SATA)
}

var (
	// "sda", "nvme0n1": the whole-disk names the collector lists.
	reBlockName = regexp.MustCompile(`^(?:sd[a-z]+|nvme\d+n\d+)$`)
	// The libata port in a sysfs path: ".../0000:00:17.0/ata1/host0/...".
	// The port device is the parent of the SCSI host (drivers/ata/libata-transport.c,
	// ata_tport_add names it "ata%d").
	reSysATAPort = regexp.MustCompile(`/(ata\d+)/`)
	// The SCSI address of the disk: ".../target0:0:0/0:0:0:0/block/sda".
	reSysHCTL = regexp.MustCompile(`/(\d+):(\d+):(\d+):(\d+)/block/`)
	// The libata device a kernel line is about: "ata1.00: ...", "ata1: ...".
	reATALine = regexp.MustCompile(`^(ata\d+)(?:\.(\d+))?:`)
	// A target that is a libata port name.
	reATAPort = regexp.MustCompile(`^ata\d+$`)
)

// addBlockDevs reads logs.blockdevs ("sda=/sys/devices/.../ata1/host0/
// target0:0:0/0:0:0:0/block/sda") into the context: which disks sit on
// which libata port, and the SCSI address of every disk. Addresses the
// log itself named ("sd 0:0:0:0: [sda]") win: the map describes the
// current boot, the log the boot it was written in.
func addBlockDevs(ctx *matchCtx, s *collect.Section) {
	if ctx == nil || !s.Ran() {
		return
	}
	for _, line := range strings.Split(s.Out, "\n") {
		name, path, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !reBlockName.MatchString(name) || !strings.HasPrefix(path, "/sys/") {
			continue
		}
		h := reSysHCTL.FindStringSubmatch(path)
		if h != nil && strings.HasPrefix(name, "sd") {
			addr := h[1] + ":" + h[2] + ":" + h[3] + ":" + h[4]
			if ctx.hctl == nil {
				ctx.hctl = map[string]string{}
			}
			if _, known := ctx.hctl[addr]; !known {
				ctx.hctl[addr] = name
			}
		}
		p := reSysATAPort.FindStringSubmatch(path)
		if p == nil || h == nil || !strings.HasPrefix(name, "sd") {
			continue
		}
		ch, err1 := strconv.Atoi(h[2])
		id, err2 := strconv.Atoi(h[3])
		if err1 != nil || err2 != nil {
			continue
		}
		if ctx.ataDisks == nil {
			ctx.ataDisks = map[string][]ataDisk{}
		}
		ctx.ataDisks[p[1]] = append(ctx.ataDisks[p[1]], ataDisk{dev: name, channel: ch, id: id})
	}
}

// ataDisk names the disk ("/dev/sda") a libata line is about, or "" when
// the map does not know it. A port with one disk is that disk. Behind a
// port multiplier "ataN.MM" is link MM, which libata exposes as SCSI channel
// MM; on a PATA-style port with master/slave it is device MM, SCSI id MM
// (drivers/ata/libata-scsi.c, ata_scsi_scan_host). A port-wide line on a
// port with several disks cannot be pinned to one.
func (c *matchCtx) ataDisk(msg string) string {
	if c == nil {
		return ""
	}
	m := reATALine.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	ds := c.ataDisks[m[1]]
	if len(ds) == 1 {
		return "/dev/" + ds[0].dev
	}
	if len(ds) == 0 || m[2] == "" {
		return ""
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return ""
	}
	found := ""
	for _, d := range ds {
		if (d.channel == n && d.id == 0) || (d.channel == 0 && d.id == n) {
			if found != "" {
				return ""
			}
			found = "/dev/" + d.dev
		}
	}
	return found
}

// sameATAEvent is how far apart the libata and SCSI lines of one failed
// command can be. libata's error handler reports the device error, resets
// the link if needed, then completes the command with sense data, and the
// sd driver prints its lines then; the SCSI command timeout (30 s, sd.c
// SD_TIMEOUT) bounds one round of that, so a minute covers it.
const sameATAEvent = time.Minute

// mergeATA ties the groups of libata port lines ("ata1.00: error: { UNC }")
// to the disk on that port. Disk-level problems (unreadable sectors, disk
// disabled) become the disk's finding: merged into the group the sd driver
// lines made for that disk, or moved to it, so one disk gets one finding.
// Port-level problems (link resets, CRC) keep the port as target and name
// the disk. When the disk is unknown, the port stays and the action says
// how to find the disk behind it.
func mergeATA(gr *grouper) {
	for _, g := range gr.list() {
		if g.spec.Comp != model.CompDisk || !reATAPort.MatchString(g.target) {
			continue
		}
		port := g.target
		if g.ataDev == "" {
			switch g.spec {
			case spDiskMedium:
				g.action = actATAMedium
			case spDiskOffline:
				g.action = actATAOffline
			default:
				g.action = joinText(g.spec.Action, ataFindHint)
			}
			continue
		}
		dev := g.ataDev
		var part *model.Part
		if g.part != nil {
			cp := *g.part
			cp.Location = dev
			part = &cp
		} else {
			part = &model.Part{Kind: "disk", Location: dev}
		}
		if g.spec != spDiskMedium && g.spec != spDiskOffline {
			g.part = part
			g.note = joinText(g.note, model.Tf("SATA port %s is disk %s.", "Cổng SATA %s là ổ %s.", port, dev))
			continue
		}
		if h := gr.get(g.spec, dev); h != nil {
			h.absorb(g, sameATAEvent, gr.now)
			gr.remove(g)
			if h.part == nil {
				h.part = part
			} else if h.part.Model == "" && part.Model != "" {
				cp := *h.part
				cp.Model, cp.Firmware = part.Model, part.Firmware
				h.part = &cp
			}
			h.note = joinText(h.note, model.Tf("libata reported the same errors on SATA port %s, which is this disk.",
				"libata cũng báo lỗi này trên cổng SATA %s, chính là ổ này.", port))
			continue
		}
		gr.retarget(g, dev)
		g.part = part
		g.note = joinText(g.note, model.Tf("Reported by libata on SATA port %s, which is %s.",
			"libata báo lỗi trên cổng SATA %s, tức là ổ %s.", port, dev))
	}
}

var (
	ataFindHint = model.T(
		"To see which disk is on {t}: ls -l /sys/class/block/ | grep /{t}/ (the sdX name at the end of the line).",
		"Để biết ổ nào nằm trên {t}: ls -l /sys/class/block/ | grep /{t}/ (tên sdX ở cuối dòng).")
	actATAMedium = model.T(
		"Back up the data on the disk on SATA port {t} now. Find that disk: ls -l /sys/class/block/ | grep /{t}/ shows its sdX name (or compare the model in the log with lsblk -o NAME,MODEL,SERIAL). Check it with smartctl -a /dev/sdX and replace it if S.M.A.R.T. shows pending/reallocated/uncorrectable sectors or the errors continue; if it is in a RAID array, make sure the array is otherwise healthy before pulling it.",
		"Sao lưu ngay dữ liệu trên ổ cắm ở cổng SATA {t}. Tìm ổ đó: ls -l /sys/class/block/ | grep /{t}/ cho biết tên sdX của ổ (hoặc so model trong log với lsblk -o NAME,MODEL,SERIAL). Kiểm tra bằng smartctl -a /dev/sdX và thay ổ nếu S.M.A.R.T. có sector pending/reallocated/uncorrectable hoặc lỗi còn tiếp diễn; nếu ổ nằm trong RAID, kiểm tra các ổ còn lại vẫn tốt trước khi rút ổ.")
	actATAOffline = model.T(
		"Check whether the disk on SATA port {t} is still present: ls -l /sys/class/block/ | grep /{t}/ (no line = the disk is gone) and lsblk. If it was not removed on purpose, back up what you can, check its cable/slot and S.M.A.R.T. (smartctl -a /dev/sdX), and replace it. If it was in a RAID array, the array is now degraded.",
		"Kiểm tra ổ ở cổng SATA {t} còn được nhận không: ls -l /sys/class/block/ | grep /{t}/ (không có dòng nào = ổ đã mất) và lsblk. Nếu không phải do rút ổ có chủ đích, sao lưu những gì còn đọc được, kiểm tra cáp/khe cắm và S.M.A.R.T. (smartctl -a /dev/sdX), rồi thay ổ. Nếu ổ nằm trong RAID thì RAID đang bị degraded.")
)
