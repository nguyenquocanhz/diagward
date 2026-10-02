package raid

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// BtrfsDev is one device of a Btrfs filesystem.
type BtrfsDev struct {
	DevID   string           `json:"devid"`
	Path    string           `json:"path,omitempty"`
	Size    string           `json:"size,omitempty"`
	Missing bool             `json:"missing,omitempty"`
	Stats   map[string]int64 `json:"stats,omitempty"`
}

// BtrfsFS is one Btrfs filesystem.
type BtrfsFS struct {
	Label   string      `json:"label,omitempty"`
	UUID    string      `json:"uuid"`
	Total   int         `json:"totalDevices,omitempty"`
	Used    string      `json:"used,omitempty"`
	Missing bool        `json:"missing,omitempty"`
	Devices []*BtrfsDev `json:"devices,omitempty"`
	Mount   string      `json:"mount,omitempty"`

	lines []string
}

var (
	btLabelRe = regexp.MustCompile(`^Label:\s+(?:'(.*)'|(\S+))\s+uuid:\s+(\S+)`)
	btTotalRe = regexp.MustCompile(`Total devices\s+(\d+)\s+FS bytes used\s+(\S+)`)
	btDevRe   = regexp.MustCompile(`devid\s+(\d+)\s+size\s+(\S+)\s+used\s+(\S+)\s+path\s*(.*)$`)
	btStatRe  = regexp.MustCompile(`^\[(.+)\]\.(\w+)\s+(\d+)$`)
)

// parseBtrfsShow parses `btrfs filesystem show`.
func parseBtrfsShow(s string) []*BtrfsFS {
	var out []*BtrfsFS
	var cur *BtrfsFS
	for _, l := range lines(s) {
		t := strings.TrimSpace(l)
		if m := btLabelRe.FindStringSubmatch(t); m != nil {
			label := m[1]
			if label == "" && m[2] != "none" {
				label = m[2]
			}
			cur = &BtrfsFS{Label: label, UUID: m[3], lines: []string{t}}
			out = append(out, cur)
			continue
		}
		if cur == nil {
			continue
		}
		cur.lines = append(cur.lines, t)
		if m := btTotalRe.FindStringSubmatch(t); m != nil {
			cur.Total, _ = strconv.Atoi(m[1])
			cur.Used = m[2]
		} else if m := btDevRe.FindStringSubmatch(t); m != nil {
			d := &BtrfsDev{DevID: m[1], Size: m[2], Path: strings.TrimSpace(m[4])}
			lp := strings.ToLower(d.Path)
			if lp == "" || strings.Contains(lp, "missing") {
				d.Missing, cur.Missing = true, true
				d.Path = ""
			}
			cur.Devices = append(cur.Devices, d)
		} else if strings.Contains(t, "Some devices missing") {
			cur.Missing = true
		}
	}
	for _, f := range out {
		present := 0
		for _, d := range f.Devices {
			if !d.Missing {
				present++
			}
		}
		if f.Total > present {
			f.Missing = true
		}
	}
	return out
}

// parseBtrfsStats parses `btrfs device stats MNT`: device -> counter -> value.
func parseBtrfsStats(s string) (map[string]map[string]int64, []string) {
	m := map[string]map[string]int64{}
	var order []string
	for _, l := range lines(s) {
		mm := btStatRe.FindStringSubmatch(strings.TrimSpace(l))
		if mm == nil {
			continue
		}
		if m[mm[1]] == nil {
			m[mm[1]] = map[string]int64{}
			order = append(order, mm[1])
		}
		n, _ := strconv.ParseInt(mm[3], 10, 64)
		m[mm[1]][mm[2]] = n
	}
	return m, order
}

var btrfsName = model.T("Btrfs device health", "Tình trạng thiết bị Btrfs")

func (c *checker) checkBtrfs() {
	show := c.b.Get("raid.btrfs_show")
	stats := c.b.Prefix("raid.btrfs_stats:")
	if show == nil && len(stats) == 0 {
		return
	}
	if show != nil && show.Missing != "" {
		fix, cmd := installPkg(c.env, "btrfs-progs")
		c.cover("raid.btrfs", btrfsName, model.CovSkipped, hint.Missing("btrfs"), fix, cmd)
		return
	}
	if show != nil && show.Skipped != "" {
		c.cover("raid.btrfs", btrfsName, model.CovSkipped, hint.NeedRoot(c.env), hint.RunAsRoot(c.env))
		return
	}
	fss := parseBtrfsShow(show.Text())
	byPath := map[string]*BtrfsFS{}
	for _, f := range fss {
		for _, d := range f.Devices {
			if d.Path != "" {
				byPath[d.Path] = f
			}
		}
	}
	failedStats := 0
	for _, s := range stats {
		mnt := strings.TrimPrefix(s.Name, "raid.btrfs_stats:")
		if !s.OK() && strings.TrimSpace(s.Out) == "" {
			failedStats++
			continue
		}
		st, order := parseBtrfsStats(s.Out)
		var fs *BtrfsFS
		for _, dev := range order {
			if f := byPath[dev]; f != nil {
				fs = f
				break
			}
		}
		if fs == nil {
			fs = &BtrfsFS{UUID: "?", Mount: mnt}
			fss = append(fss, fs)
		}
		if fs.Mount == "" {
			fs.Mount = strings.ReplaceAll(mnt, `\040`, " ")
		}
		for _, dev := range order {
			var d *BtrfsDev
			for _, x := range fs.Devices {
				if x.Path == dev || "devid:"+x.DevID == dev {
					d = x
				}
			}
			if d == nil {
				d = &BtrfsDev{Path: dev}
				if strings.HasPrefix(dev, "devid:") {
					d.DevID, d.Path, d.Missing = strings.TrimPrefix(dev, "devid:"), "", true
				}
				fs.Devices = append(fs.Devices, d)
			}
			d.Stats = st[dev]
		}
	}

	var ok []string
	for _, f := range fss {
		c.facts.Btrfs = append(c.facts.Btrfs, f)
		name := f.Label
		if name == "" {
			name = f.UUID
		}
		if f.Mount != "" {
			name += " (" + f.Mount + ")"
		}
		sev := model.OK
		if f.Missing {
			sev = model.Crit
			c.add(model.Finding{
				ID: "raid.btrfs_missing", Severity: model.Crit, Target: name,
				Title: model.Tf("Btrfs filesystem %s is missing a device", "Hệ thống tệp Btrfs %s bị thiếu thiết bị", name),
				Detail: model.Tf("btrfs filesystem show lists %d devices but not all are present. With RAID1/10/5/6 profiles the data is still readable but no longer redundant; with single/RAID0 profiles data is lost.",
					"btrfs filesystem show có %d thiết bị nhưng không đủ. Với profile RAID1/10/5/6 dữ liệu vẫn đọc được nhưng đã mất dự phòng; với profile single/RAID0 thì dữ liệu bị mất.", f.Total),
				Action: model.T("Back up now. Check cables and 'dmesg' for the missing disk. If it is dead, add a new disk and run 'btrfs replace start <devid> /dev/<new> <mount>' (or 'btrfs device add' + 'btrfs device remove missing'). A filesystem mounted with -o degraded must be repaired before the next reboot.",
					"Sao lưu ngay. Kiểm tra cáp và 'dmesg' để tìm ổ bị mất. Nếu ổ hỏng, gắn ổ mới rồi chạy 'btrfs replace start <devid> /dev/<ổ mới> <điểm mount>' (hoặc 'btrfs device add' + 'btrfs device remove missing'). Nếu đang mount với -o degraded, cần sửa xong trước lần khởi động lại tiếp theo."),
				Evidence: ev(f.lines),
			})
		}
		for _, d := range f.Devices {
			// The counters are persistent and only reset with
			// 'btrfs device stats -z' (btrfs-device(8)), so a non-zero value
			// may be old: Warn, not Crit.
			var errs []string
			var total int64
			for _, k := range []string{"write_io_errs", "read_io_errs", "flush_io_errs", "corruption_errs", "generation_errs"} {
				if v := d.Stats[k]; v > 0 {
					errs = append(errs, fmt.Sprintf("%s=%d", k, v))
					total += v
				}
			}
			if total == 0 {
				continue
			}
			sev = model.Worst(sev, model.Warn)
			dev := d.Path
			if dev == "" {
				dev = "devid " + d.DevID
			}
			part := c.ids.diskPart(dev, dev+" (btrfs "+name+")")
			pen, pvi := partText(part)
			c.add(model.Finding{
				ID: "raid.btrfs_dev_errors", Severity: model.Warn, Target: dev,
				Title: model.Tf("Btrfs device %s has recorded errors: %s", "Thiết bị Btrfs %s đã ghi nhận lỗi: %s", dev, strings.Join(errs, ", ")),
				Detail: model.T("write/read/flush errors are I/O failures reported by the disk or its link; corruption errors are checksum mismatches; generation errors are stale metadata. The counters are lifetime totals.",
					"Lỗi write/read/flush là lỗi I/O do ổ hoặc đường kết nối báo về; corruption là sai checksum; generation là metadata cũ. Các bộ đếm này cộng dồn từ trước tới nay."),
				Action: model.Text{
					EN: fmt.Sprintf("Check the disk%s with 'smartctl -a' and its cable, run 'btrfs scrub start %s', then reset the counters with 'btrfs device stats -z %s' so new errors stand out. Replace the disk if errors keep growing.", pen, f.Mount, f.Mount),
					VI: fmt.Sprintf("Kiểm tra ổ%s bằng 'smartctl -a' và cáp, chạy 'btrfs scrub start %s', rồi đặt lại bộ đếm bằng 'btrfs device stats -z %s' để thấy lỗi mới. Thay ổ nếu lỗi tiếp tục tăng.", pvi, f.Mount, f.Mount),
				},
				Evidence: []string{fmt.Sprintf("[%s] %s", dev, strings.Join(errs, " "))},
				Part:     part,
			})
		}
		var members []string
		for _, d := range f.Devices {
			if d.Missing {
				members = append(members, "devid "+d.DevID+"(MISSING)")
			} else {
				members = append(members, d.Path)
			}
		}
		state := "OK"
		if f.Missing {
			state = "missing device"
		}
		used := ""
		if f.Used != "" {
			used = f.Used + " used"
		}
		c.arrayRow(sev, name, "btrfs", used, state, strings.Join(members, " "), "")
		if sev == model.OK {
			ok = append(ok, name)
		}
	}
	if len(ok) > 0 {
		c.add(model.Finding{
			ID: "raid.btrfs_ok", Severity: model.OK, Target: strings.Join(ok, ", "),
			Title: model.Tf("Btrfs: all devices present, no errors recorded: %s", "Btrfs: đủ thiết bị, không ghi nhận lỗi: %s", strings.Join(ok, ", ")),
		})
	}
	switch {
	case show != nil && !show.OK() && len(fss) == 0:
		c.cover("raid.btrfs", btrfsName, model.CovFailed, model.Tf("btrfs filesystem show failed: %s", "btrfs filesystem show lỗi: %s", errText(show)), model.Text{})
	case failedStats > 0:
		c.cover("raid.btrfs", btrfsName, model.CovPartial, model.T("btrfs device stats failed for some filesystems.", "btrfs device stats lỗi trên một số hệ thống tệp."), model.Text{})
	default:
		c.cover("raid.btrfs", btrfsName, model.CovRan, model.Text{}, model.Text{})
	}
}
