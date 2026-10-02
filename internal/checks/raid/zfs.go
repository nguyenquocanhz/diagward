package raid

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// ZVdev is one row of the zpool status config table.
type ZVdev struct {
	Name    string `json:"name"`
	State   string `json:"state,omitempty"`
	Read    string `json:"read,omitempty"`
	Write   string `json:"write,omitempty"`
	Cksum   string `json:"cksum,omitempty"`
	Note    string `json:"note,omitempty"`
	Depth   int    `json:"depth"`
	Leaf    bool   `json:"leaf,omitempty"`
	Section string `json:"section,omitempty"` // "", logs, cache, spares, special, dedup
	Parent  string `json:"parent,omitempty"`
}

// ZPool is one ZFS pool.
type ZPool struct {
	Name       string  `json:"name"`
	State      string  `json:"state"`
	Status     string  `json:"status,omitempty"`
	Action     string  `json:"action,omitempty"`
	Scan       string  `json:"scan,omitempty"`
	Errors     string  `json:"errors,omitempty"`
	DataErrors int64   `json:"dataErrors,omitempty"` // -1: permanent errors listed, count unknown
	Vdevs      []ZVdev `json:"vdevs,omitempty"`
	Size       string  `json:"size,omitempty"`
	Alloc      string  `json:"alloc,omitempty"`
	Free       string  `json:"free,omitempty"`
	Frag       string  `json:"frag,omitempty"`
	Cap        string  `json:"cap,omitempty"`

	lines []string
}

var zKeyRe = regexp.MustCompile(`^\s*(pool|id|state|status|action|see|scan|scrub|config|errors|remove|checkpoint|resilver|expand|errata):\s?(.*)$`)

// parseZpoolStatus parses `zpool status [-P]`.
func parseZpoolStatus(s string) []*ZPool {
	var pools []*ZPool
	var cur *ZPool
	lastKey := ""
	inConfig := false
	baseIndent := -1
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		l := strings.TrimRight(raw, " \t")
		if m := zKeyRe.FindStringSubmatch(l); m != nil && !(inConfig && m[1] != "errors") {
			key, val := m[1], strings.TrimSpace(m[2])
			if key == "pool" {
				cur = &ZPool{Name: val}
				pools = append(pools, cur)
				inConfig, baseIndent, lastKey = false, -1, "pool"
				cur.lines = append(cur.lines, strings.TrimSpace(l))
				continue
			}
			if cur == nil {
				continue
			}
			cur.lines = append(cur.lines, strings.TrimSpace(l))
			lastKey = key
			switch key {
			case "state":
				cur.State = val
			case "status":
				cur.Status = val
			case "action":
				cur.Action = val
			case "scan", "scrub", "resilver":
				cur.Scan = val
				lastKey = "scan"
			case "config":
				inConfig = true
			case "errors":
				inConfig = false
				cur.Errors = val
				cur.DataErrors = zDataErrors(val)
			}
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(l)
		if t == "" {
			if !inConfig {
				lastKey = ""
			}
			continue
		}
		if inConfig {
			f := strings.Fields(t)
			if len(f) >= 1 && f[0] == "NAME" {
				baseIndent = indentOf(l)
				continue
			}
			if baseIndent < 0 {
				baseIndent = indentOf(l)
			}
			depth := (indentOf(l) - baseIndent) / 2
			if depth < 0 {
				depth = 0
			}
			v := ZVdev{Name: f[0], Depth: depth}
			if len(f) >= 2 {
				v.State = f[1]
			}
			if len(f) >= 5 {
				v.Read, v.Write, v.Cksum = f[2], f[3], f[4]
				v.Note = strings.Join(f[5:], " ")
			} else if len(f) > 2 {
				v.Note = strings.Join(f[2:], " ")
			}
			cur.Vdevs = append(cur.Vdevs, v)
			cur.lines = append(cur.lines, t)
			continue
		}
		// Continuation of a multi-line field.
		switch lastKey {
		case "status":
			cur.Status += " " + t
		case "action":
			cur.Action += " " + t
		case "scan":
			cur.Scan += "\n" + t
			cur.lines = append(cur.lines, t)
		case "errors":
			cur.lines = append(cur.lines, t)
		}
	}
	for _, p := range pools {
		markLeaves(p)
	}
	return pools
}

var zSections = map[string]bool{"logs": true, "cache": true, "spares": true, "special": true, "dedup": true}

func markLeaves(p *ZPool) {
	section := ""
	var stack []string
	for i := range p.Vdevs {
		v := &p.Vdevs[i]
		if v.Depth == 0 {
			stack = stack[:0]
			if zSections[v.Name] && v.State == "" {
				section = v.Name
			} else if v.Name == p.Name {
				section = ""
			}
		}
		v.Section = section
		for len(stack) > v.Depth {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			v.Parent = stack[len(stack)-1]
		}
		for len(stack) < v.Depth {
			stack = append(stack, "")
		}
		stack = append(stack, v.Name)
		next := -1
		if i+1 < len(p.Vdevs) {
			next = p.Vdevs[i+1].Depth
		}
		isGroup := v.Depth == 0 || (zSections[v.Name] && v.State == "")
		v.Leaf = !isGroup && next <= v.Depth
	}
}

var zDataErrRe = regexp.MustCompile(`^(\d+) data errors`)

func zDataErrors(s string) int64 {
	if strings.HasPrefix(s, "No known data errors") {
		return 0
	}
	if m := zDataErrRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	if strings.Contains(s, "Permanent errors") {
		return -1
	}
	return 0
}

// zCount parses a zpool error counter ("0", "248", "1.2K").
func zCount(s string) float64 {
	if s == "" {
		return 0
	}
	mult := 1.0
	switch s[len(s)-1] {
	case 'K':
		mult, s = 1e3, s[:len(s)-1]
	case 'M':
		mult, s = 1e6, s[:len(s)-1]
	case 'G':
		mult, s = 1e9, s[:len(s)-1]
	case 'T':
		mult, s = 1e12, s[:len(s)-1]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f * mult
}

func (v ZVdev) errors() float64 { return zCount(v.Read) + zCount(v.Write) + zCount(v.Cksum) }

var (
	zGroupSuffix = regexp.MustCompile(`-\d+$`)
	zResilverRe  = regexp.MustCompile(`^resilver(?: \([^)]*\))? in progress`)
)

// wasPath returns the old device path ZFS prints for a vdev it can no
// longer open ("5332611342296232703  UNAVAIL ... was /dev/disk/by-id/...").
func (v ZVdev) wasPath() string {
	if p, ok := strings.CutPrefix(v.Note, "was "); ok {
		return strings.TrimSpace(p)
	}
	return ""
}

// label names a vdev for findings, with its old path when it has one.
func (v ZVdev) label() string {
	if w := v.wasPath(); w != "" {
		return v.Name + " (was " + w + ")"
	}
	return v.Name
}

var (
	zScanDoneRe = regexp.MustCompile(`(scrub repaired|resilvered) (\S+) in .* with (\d+) errors on (.+)$`)
	zToGoRe     = regexp.MustCompile(`,\s*([^,]+?)\s+to go`)
)

// zScanTime parses the zpool scan date ("Sun Sep 13 00:24:02 2026"),
// written in the server's local time.
func zScanTime(s string) (time.Time, bool) {
	t, err := time.Parse("Mon Jan 2 15:04:05 2006", collapse(s))
	return t, err == nil
}

func parseZpoolList(s string) map[string][]string {
	m := map[string][]string{}
	for _, l := range lines(s) {
		f := strings.Split(l, "\t")
		if len(f) < 5 {
			f = strings.Fields(l)
		}
		if len(f) >= 5 && f[0] != "NAME" {
			m[f[0]] = f
		}
	}
	return m
}

var zfsName = model.T("ZFS pools", "ZFS pool")

func (c *checker) checkZFS() {
	st := c.b.Get("raid.zpool_status")
	if st == nil {
		return
	}
	if st.Missing != "" {
		fix, cmd := hint.InstallFix(c.env, "zpool")
		c.cover("raid.zfs", zfsName, model.CovSkipped, hint.Missing("zpool"), fix, cmd)
		return
	}
	if st.Skipped != "" {
		return
	}
	pools := parseZpoolStatus(st.Out)
	list := parseZpoolList(c.b.Get("raid.zpool_list").Text())
	seen := map[string]bool{}
	for _, p := range pools {
		seen[p.Name] = true
		if f := list[p.Name]; f != nil {
			p.Size, p.Alloc, p.Free = f[1], f[2], f[3]
			if len(f) > 5 {
				p.Frag = f[5]
			}
			if len(f) > 6 {
				p.Cap = f[6]
			}
		}
	}
	for _, name := range sortedKeys(list) {
		if seen[name] {
			continue
		}
		f := list[name]
		p := &ZPool{Name: name, State: f[4], Size: f[1], Alloc: f[2], Free: f[3], lines: []string{strings.Join(f, " ")}}
		pools = append(pools, p)
	}
	if len(pools) == 0 {
		low := strings.ToLower(st.Out + st.Err)
		if st.RC != 0 && !strings.Contains(low, "no pools available") && !strings.Contains(low, "modules are not loaded") {
			if strings.Contains(low, "permission denied") {
				c.cover("raid.zfs", zfsName, model.CovSkipped, hint.NeedRoot(c.env), hint.RunAsRoot(c.env))
			} else {
				c.cover("raid.zfs", zfsName, model.CovFailed,
					model.Tf("zpool status failed: %s", "zpool status lỗi: %s", errText(st)), model.Text{})
			}
		}
		return
	}
	var ok []string
	for _, p := range pools {
		c.facts.ZFS = append(c.facts.ZFS, p)
		if c.analyzeZPool(p) <= model.Info {
			ok = append(ok, p.Name)
		}
	}
	if len(ok) > 0 {
		c.add(model.Finding{
			ID: "raid.zfs_ok", Severity: model.OK, Target: strings.Join(ok, ", "),
			Title: model.Tf("ZFS pools healthy (ONLINE, no errors): %s", "ZFS pool hoạt động tốt (ONLINE, không lỗi): %s", strings.Join(ok, ", ")),
		})
	}
	state := model.CovRan
	if st.Timeout {
		state = model.CovPartial
	}
	reason := model.Text{}
	if state == model.CovPartial {
		reason = model.T("zpool status timed out; the output may be incomplete (a suspended pool can hang it).", "zpool status bị quá thời gian; dữ liệu có thể thiếu (pool bị suspended có thể làm treo lệnh).")
	}
	c.cover("raid.zfs", zfsName, state, reason, model.Text{})
}

func (c *checker) zPart(p *ZPool, v ZVdev) *model.Part {
	if w := v.wasPath(); w != "" {
		return c.ids.diskPart(w, fmt.Sprintf("%s (pool %s)", w, p.Name))
	}
	return c.ids.diskPart(v.Name, fmt.Sprintf("%s (pool %s)", v.Name, p.Name))
}

func (c *checker) analyzeZPool(p *ZPool) model.Severity {
	sev := model.OK
	evid := p.lines
	scan := strings.ToLower(p.Scan)
	// dRAID sequential rebuilds print "resilver (draid1:4d:11c:1s-0) in
	// progress" (OpenZFS dRAID howto).
	first, _, _ := strings.Cut(scan, "\n")
	resilvering := zResilverRe.MatchString(first)
	scrubbing := strings.Contains(first, "scrub in progress")
	progress := ""
	if resilvering || scrubbing {
		progress = strings.SplitN(p.Scan, " ", 2)[0]
		if pc := pct(p.Scan); pc >= 0 {
			progress += " " + fmtPct(pc)
		}
		if m := zToGoRe.FindStringSubmatch(p.Scan); m != nil {
			progress += ", ETA " + m[1]
		}
	}

	var bad []string
	for _, v := range p.Vdevs {
		if v.Leaf && v.State != "ONLINE" && v.State != "AVAIL" && v.State != "INUSE" && v.State != "" {
			bad = append(bad, v.Name+" "+v.State)
		}
	}

	switch p.State {
	case "ONLINE", "":
	case "DEGRADED":
		if resilvering {
			sev = model.Worst(sev, model.Warn)
			c.add(model.Finding{
				ID: "raid.zfs_resilver", Severity: model.Warn, Target: p.Name,
				Title: model.Tf("ZFS pool %s is resilvering (rebuilding): %s", "ZFS pool %s đang resilver (rebuild): %s", p.Name, progress),
				Detail: model.Tf("The pool is DEGRADED while ZFS copies data onto the new or returning device. Until it finishes, redundancy is reduced. Devices not OK: %s.",
					"Pool đang DEGRADED trong lúc ZFS chép dữ liệu sang ổ mới hoặc ổ vừa kết nối lại. Cho tới khi xong, mức dự phòng bị giảm. Ổ chưa ổn: %s.", joinOr(bad, "-")),
				Action: model.Tf("Do not reboot, export the pool or pull disks until the resilver ends (watch: zpool status %s). Make sure the backup is current.",
					"Không khởi động lại, export pool hay rút ổ cho tới khi resilver xong (theo dõi: zpool status %s). Kiểm tra bản sao lưu còn mới.", p.Name),
				Evidence: ev(evid),
			})
		} else {
			sev = model.Crit
			c.add(model.Finding{
				ID: "raid.zfs_pool_degraded", Severity: model.Crit, Target: p.Name,
				Title: model.Tf("ZFS pool %s is DEGRADED: %s", "ZFS pool %s bị DEGRADED: %s", p.Name, joinOr(bad, "a device is not online")),
				Detail: model.Tf("The pool still works but has lost redundancy; one more failure can lose data. ZFS says: %s",
					"Pool vẫn chạy nhưng đã mất dự phòng; hỏng thêm một ổ là có thể mất dữ liệu. ZFS báo: %s", joinOr([]string{p.Status}, "-")),
				Action: model.Tf("Back up now. Find the failed device (zpool status -P %s), check its cable and S.M.A.R.T.; if it is dead, replace it with 'zpool replace %s <old-device> <new-device>' (use /dev/disk/by-id paths) and wait for the resilver. If it was only offline/unplugged, reconnect it and run 'zpool online %s <device>'.",
					"Sao lưu ngay. Xác định ổ lỗi (zpool status -P %s), kiểm tra cáp và S.M.A.R.T.; nếu ổ hỏng, thay bằng 'zpool replace %s <ổ cũ> <ổ mới>' (dùng đường dẫn /dev/disk/by-id) rồi chờ resilver xong. Nếu ổ chỉ bị offline/rút ra, cắm lại và chạy 'zpool online %s <ổ>'.", p.Name, p.Name, p.Name),
				Evidence: ev(evid),
			})
		}
	default: // FAULTED, UNAVAIL, SUSPENDED, ...
		sev = model.Crit
		c.add(model.Finding{
			ID: "raid.zfs_pool_faulted", Severity: model.Crit, Target: p.Name,
			Title: model.Tf("ZFS pool %s is %s: data is not accessible", "ZFS pool %s ở trạng thái %s: không truy cập được dữ liệu", p.Name, p.State),
			Detail: model.Tf("A pool in state %s has lost too many devices or hit I/O errors it cannot recover from. ZFS says: %s",
				"Pool ở trạng thái %s đã mất quá nhiều ổ hoặc gặp lỗi I/O không tự khắc phục được. ZFS báo: %s", p.State, joinOr([]string{p.Status}, "-")),
			Action: model.Tf("Check that all disks of pool %s are connected (cables, backplane, controller), then 'zpool clear %s'. If devices are really dead, restore from backup. Do not run 'zpool import -F' or destroy anything without a backup.",
				"Kiểm tra tất cả ổ của pool %s còn kết nối (cáp, backplane, controller) rồi chạy 'zpool clear %s'. Nếu ổ thật sự hỏng, khôi phục từ bản sao lưu. Không chạy 'zpool import -F' hay xóa gì khi chưa có bản sao lưu.", p.Name, p.Name),
			Evidence: ev(evid),
		})
	}

	poolErrs := 0.0
	leafErrs := false
	for _, v := range p.Vdevs {
		if v.Depth == 0 && v.Name == p.Name {
			poolErrs = v.errors()
			continue
		}
		if !v.Leaf {
			continue
		}
		replacing := strings.HasPrefix(v.Parent, "replacing-")
		inAux := v.Section == "logs" || v.Section == "cache" || v.Section == "spares"
		part := c.zPart(p, v)
		pen, pvi := partText(part)
		switch v.State {
		case "FAULTED", "UNAVAIL", "REMOVED", "DEGRADED":
			s := model.Crit
			idSuffix := "device_failed"
			if replacing || inAux {
				// Being replaced already, or a cache/log/spare device whose
				// loss does not endanger pool data.
				s = model.Warn
			}
			sev = model.Worst(sev, s)
			leafErrs = true
			c.add(model.Finding{
				ID: "raid.zfs_" + idSuffix, Severity: s, Target: p.Name + "/" + v.Name,
				Title: model.Tf("ZFS device %s in pool %s is %s", "Ổ %s trong ZFS pool %s ở trạng thái %s", v.label(), p.Name, v.State),
				Detail: model.Tf("State %s %s (read/write/checksum errors: %s/%s/%s). FAULTED/DEGRADED: ZFS stopped trusting it because of errors; UNAVAIL/REMOVED: it cannot be opened or was unplugged.",
					"Trạng thái %s %s (lỗi đọc/ghi/checksum: %s/%s/%s). FAULTED/DEGRADED: ZFS ngừng tin ổ này vì quá nhiều lỗi; UNAVAIL/REMOVED: không mở được ổ hoặc ổ đã bị rút.", v.State, v.Note, v.Read, v.Write, v.Cksum),
				Action: model.Text{
					EN: fmt.Sprintf("Check the disk%s: cable/backplane, 'smartctl -a'. If it is failing, replace it: zpool replace %s %s <new-device>; then wait for the resilver.", pen, p.Name, v.Name),
					VI: fmt.Sprintf("Kiểm tra ổ%s: cáp/backplane, 'smartctl -a'. Nếu ổ hỏng, thay ổ: zpool replace %s %s <ổ mới>; sau đó chờ resilver xong.", pvi, p.Name, v.Name),
				},
				Evidence: ev(evid),
				Part:     part,
			})
		case "OFFLINE":
			sev = model.Worst(sev, model.Warn)
			leafErrs = true
			c.add(model.Finding{
				ID: "raid.zfs_device_offline", Severity: model.Warn, Target: p.Name + "/" + v.Name,
				Title:  model.Tf("ZFS device %s in pool %s is OFFLINE", "Ổ %s trong ZFS pool %s đang OFFLINE", v.label(), p.Name),
				Detail: model.T("The device was taken offline (usually by an administrator).", "Ổ đã bị đưa về offline (thường do quản trị viên)."),
				Action: model.Tf("If the maintenance is over: zpool online %s %s; otherwise replace it.", "Nếu đã bảo trì xong: zpool online %s %s; nếu không thì thay ổ.", p.Name, v.Name),
				Part:   part,
			})
		default:
			if v.errors() > 0 && v.State == "ONLINE" {
				sev = model.Worst(sev, model.Warn)
				leafErrs = true
				c.add(model.Finding{
					ID: "raid.zfs_device_errors", Severity: model.Warn, Target: p.Name + "/" + v.Name,
					Title: model.Tf("ZFS device %s in pool %s has errors (read %s, write %s, checksum %s)", "Ổ %s trong ZFS pool %s có lỗi (đọc %s, ghi %s, checksum %s)", v.Name, p.Name, v.Read, v.Write, v.Cksum),
					Detail: model.T("ZFS repaired the affected blocks from redundancy, but the device returned errors or bad data. Checksum errors often come from cables, the controller or RAM as well as the disk itself.",
						"ZFS đã tự sửa các khối bị ảnh hưởng từ bản dự phòng, nhưng ổ đã trả lỗi hoặc dữ liệu sai. Lỗi checksum có thể do cáp, controller, RAM chứ không riêng gì ổ."),
					Action: model.Text{
						EN: fmt.Sprintf("Check the disk%s with 'smartctl -a' and its cable. Then 'zpool clear %s' and run 'zpool scrub %s'; if errors return, replace the disk.", pen, p.Name, p.Name),
						VI: fmt.Sprintf("Kiểm tra ổ%s bằng 'smartctl -a' và cáp. Sau đó 'zpool clear %s' rồi chạy 'zpool scrub %s'; nếu lỗi quay lại, thay ổ.", pvi, p.Name, p.Name),
					},
					Evidence: ev(evid),
					Part:     part,
				})
			}
		}
	}
	if poolErrs > 0 && !leafErrs {
		sev = model.Worst(sev, model.Warn)
		c.add(model.Finding{
			ID: "raid.zfs_device_errors", Severity: model.Warn, Target: p.Name,
			Title:    model.Tf("ZFS pool %s has I/O or checksum errors", "ZFS pool %s có lỗi I/O hoặc checksum", p.Name),
			Detail:   model.T("Errors are counted at pool level and not attributed to one device.", "Lỗi được đếm ở cấp pool, không gắn với một ổ cụ thể."),
			Action:   model.Tf("Run 'zpool status -v %s', check disks and cables, then 'zpool clear %s' and 'zpool scrub %s'.", "Chạy 'zpool status -v %s', kiểm tra ổ và cáp, rồi 'zpool clear %s' và 'zpool scrub %s'.", p.Name, p.Name, p.Name),
			Evidence: ev(evid),
		})
	}

	if p.DataErrors != 0 {
		sev = model.Crit
		n := "some"
		nv := "một số"
		if p.DataErrors > 0 {
			n = strconv.FormatInt(p.DataErrors, 10)
			nv = n
		}
		c.add(model.Finding{
			ID: "raid.zfs_data_errors", Severity: model.Crit, Target: p.Name,
			Title: model.Text{EN: fmt.Sprintf("ZFS pool %s has %s permanent data errors (corrupted files)", p.Name, n), VI: fmt.Sprintf("ZFS pool %s có %s lỗi dữ liệu vĩnh viễn (file bị hỏng)", p.Name, nv)},
			Detail: model.T("ZFS found blocks it could not repair from any copy. The affected files are damaged.",
				"ZFS phát hiện các khối không sửa được từ bất kỳ bản sao nào. Các file liên quan đã bị hỏng."),
			Action: model.Tf("List the damaged files with 'zpool status -v %s' and restore them from backup. Then fix the cause (failing disk, cable, RAM), run 'zpool scrub %s' and 'zpool clear %s'.",
				"Xem danh sách file hỏng bằng 'zpool status -v %s' và khôi phục chúng từ bản sao lưu. Sau đó xử lý nguyên nhân (ổ hỏng, cáp, RAM), chạy 'zpool scrub %s' và 'zpool clear %s'.", p.Name, p.Name, p.Name),
			Evidence: ev(evid),
		})
	}

	if resilvering && p.State != "DEGRADED" {
		sev = model.Worst(sev, model.Warn)
		c.add(model.Finding{
			ID: "raid.zfs_resilver", Severity: model.Warn, Target: p.Name,
			Title:    model.Tf("ZFS pool %s is resilvering: %s", "ZFS pool %s đang resilver: %s", p.Name, progress),
			Detail:   model.T("ZFS is copying data onto a new or returning device.", "ZFS đang chép dữ liệu sang ổ mới hoặc ổ vừa kết nối lại."),
			Action:   model.Tf("Do not reboot or pull disks until it finishes (zpool status %s).", "Không khởi động lại hay rút ổ cho tới khi xong (zpool status %s).", p.Name),
			Evidence: ev(evid),
		})
	}
	if scrubbing {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.zfs_scrub_running", Severity: model.Info, Target: p.Name,
			Title:  model.Tf("ZFS pool %s: scrub running (%s)", "ZFS pool %s: đang scrub (%s)", p.Name, progress),
			Detail: model.T("A scrub reads and verifies every block. The pool is slower meanwhile; it is safe to keep working.", "Scrub đọc và kiểm tra toàn bộ dữ liệu. Pool chậm hơn trong lúc chạy; vẫn dùng bình thường được."),
		})
	}
	if m := zScanDoneRe.FindStringSubmatch(strings.SplitN(p.Scan, "\n", 2)[0]); m != nil {
		if n := atoi(m[3]); n > 0 {
			sev = model.Worst(sev, model.Warn)
			c.add(model.Finding{
				ID: "raid.zfs_scrub_errors", Severity: model.Warn, Target: p.Name,
				Title:    model.Tf("ZFS pool %s: last %s finished with %d errors", "ZFS pool %s: lần %s gần nhất kết thúc với %d lỗi", p.Name, strings.Fields(m[1])[0], n),
				Detail:   model.T("Errors during a scrub/resilver mean some blocks could not be read or verified.", "Lỗi trong lúc scrub/resilver nghĩa là có khối không đọc hoặc không kiểm tra được."),
				Action:   model.Tf("Run 'zpool status -v %s', check the devices with errors, then scrub again.", "Chạy 'zpool status -v %s', kiểm tra các ổ có lỗi rồi scrub lại.", p.Name),
				Evidence: ev(evid),
			})
		}
		// OpenZFS and the distributions schedule a scrub monthly
		// (zfsutils-linux cron: 2nd Sunday; systemd zfs-scrub-monthly
		// timer). 35 days leaves a few days of slack.
		if strings.HasPrefix(m[1], "scrub") {
			if t, ok := zScanTime(m[4]); ok && !c.env.Now.IsZero() && c.env.Now.Sub(t) > 35*24*time.Hour {
				age := units.Duration(c.env.Now.Sub(t))
				sev = model.Worst(sev, model.Info)
				c.add(model.Finding{
					ID: "raid.zfs_scrub_old", Severity: model.Info, Target: p.Name,
					Title:  model.Tf("ZFS pool %s: last scrub was %s ago", "ZFS pool %s: lần scrub gần nhất cách đây %s", p.Name, age.EN),
					Detail: model.T("Regular scrubs (monthly) find silent corruption and failing disks while redundancy can still repair them.", "Scrub định kỳ (hằng tháng) giúp phát hiện dữ liệu hỏng âm thầm và ổ sắp hỏng khi vẫn còn dự phòng để sửa."),
					Action: model.Tf("Run 'zpool scrub %s' and schedule it monthly (systemd: systemctl enable --now zfs-scrub-monthly@%s.timer).", "Chạy 'zpool scrub %s' và đặt lịch hằng tháng (systemd: systemctl enable --now zfs-scrub-monthly@%s.timer).", p.Name, p.Name),
				})
			}
		}
	} else if strings.Contains(scan, "none requested") && sev <= model.Info {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.zfs_scrub_old", Severity: model.Info, Target: p.Name,
			Title:  model.Tf("ZFS pool %s has never been scrubbed", "ZFS pool %s chưa từng được scrub", p.Name),
			Detail: model.T("Regular scrubs (monthly) find silent corruption and failing disks early.", "Scrub định kỳ (hằng tháng) giúp phát hiện sớm dữ liệu hỏng âm thầm và ổ sắp hỏng."),
			Action: model.Tf("Run 'zpool scrub %s' and schedule it monthly.", "Chạy 'zpool scrub %s' và đặt lịch hằng tháng.", p.Name),
		})
	}

	state := p.State
	if p.Cap != "" {
		state += ", " + p.Cap + " used"
	}
	var members []string
	for _, v := range p.Vdevs {
		if v.Leaf {
			s := v.Name[strings.LastIndexByte(v.Name, '/')+1:]
			if v.State != "ONLINE" {
				s += "(" + v.State + ")"
			}
			members = append(members, s)
		}
	}
	typ := "zfs"
	for _, v := range p.Vdevs {
		if v.Depth == 1 && v.Section == "" && !v.Leaf {
			typ = "zfs " + zGroupSuffix.ReplaceAllString(v.Name, "")
			break
		}
	}
	c.arrayRow(sev, p.Name, typ, p.Size, state, strings.Join(members, " "), progress)
	return sev
}
