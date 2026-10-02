package raid

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// MDMember is one member device of an md array.
type MDMember struct {
	Name   string `json:"name"`            // sdb1
	Slot   int    `json:"slot"`            // the [n] in /proc/mdstat
	Flags  string `json:"flags,omitempty"` // F (faulty), S (spare), W (write-mostly), R (replacement)
	State  string `json:"state,omitempty"` // mdadm --detail / sysfs state
	Errors int64  `json:"errors,omitempty"`
}

// MDArray is one Linux software RAID array.
type MDArray struct {
	Name      string     `json:"name"`
	Active    bool       `json:"active"`
	Broken    bool       `json:"broken,omitempty"`   // "broken" instead of "active" in mdstat (MD_BROKEN, kernel >= 5.x)
	ReadOnly  string     `json:"readOnly,omitempty"` // "read-only", "auto-read-only"
	Level     string     `json:"level,omitempty"`
	Container bool       `json:"container,omitempty"` // IMSM/DDF metadata container (normally inactive)
	Members   []MDMember `json:"members,omitempty"`
	Blocks    uint64     `json:"blocks,omitempty"` // 1 KiB blocks
	Super     string     `json:"super,omitempty"`
	Want      int        `json:"raidDisks,omitempty"`
	Have      int        `json:"activeDisks,omitempty"`
	Status    string     `json:"status,omitempty"` // UU_ map
	SyncOp    string     `json:"syncOp,omitempty"` // recovery, resync, reshape, check, repair
	SyncPct   float64    `json:"syncPct,omitempty"`
	Finish    string     `json:"finish,omitempty"`
	Speed     string     `json:"speed,omitempty"`
	Pending   string     `json:"pending,omitempty"` // resync=DELAYED / PENDING

	// mdadm --detail
	State         string   `json:"state,omitempty"`
	FailedDevices int      `json:"failedDevices,omitempty"`
	Removed       int      `json:"removedSlots,omitempty"`
	ArraySize     string   `json:"arraySize,omitempty"`
	UUID          string   `json:"uuid,omitempty"`
	DetailPaths   []string `json:"-"`

	// sysfs
	ArrayState string `json:"arrayState,omitempty"`
	SyncAction string `json:"syncAction,omitempty"`
	SyncDone   string `json:"syncCompleted,omitempty"` // sync_completed: "n / m", "none" or "delayed"
	Degraded   int    `json:"degraded,omitempty"`
	Mismatch   int64  `json:"mismatchCnt,omitempty"`

	lines  []string // mdstat lines (evidence)
	detail []string // mdadm --detail lines (evidence)
}

var (
	mdHeadRe   = regexp.MustCompile(`^(md[^\s:]*)\s*:\s*(.*)$`)
	mdMemberRe = regexp.MustCompile(`^([^\[\s]+)\[(\d+)\]((?:\([A-Za-z]+\))*)$`)
	mdCountRe  = regexp.MustCompile(`\[(\d+)/(\d+)\]\s*\[([U_]+)\]`)
	mdSyncRe   = regexp.MustCompile(`(recovery|resync|reshape|check|repair)\s*=\s*([0-9.]+)%`)
	mdPendRe   = regexp.MustCompile(`(recovery|resync|reshape|check|repair)\s*=\s*(DELAYED|PENDING)`)
	mdFinishRe = regexp.MustCompile(`finish=(\S+)`)
	mdSpeedRe  = regexp.MustCompile(`speed=(\S+)`)
	mdSuperRe  = regexp.MustCompile(`super (\S+)`)
)

// parseMdstat parses /proc/mdstat.
func parseMdstat(s string) []*MDArray {
	var out []*MDArray
	var cur *MDArray
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		l := strings.TrimRight(raw, " \t")
		if strings.TrimSpace(l) == "" {
			cur = nil
			continue
		}
		if m := mdHeadRe.FindStringSubmatch(l); m != nil && indentOf(l) == 0 {
			cur = &MDArray{Name: m[1], Mismatch: -1, lines: []string{l}}
			out = append(out, cur)
			for _, t := range strings.Fields(m[2]) {
				switch {
				case t == "active":
					cur.Active = true
				case t == "broken":
					// md_seq_show prints "broken" in place of "active" when
					// MD_BROKEN is set: the array is still assembled, but a
					// raid0/linear member is gone or a raid1/10 runs on its
					// last device (drivers/md/md.c).
					cur.Active, cur.Broken = true, true
				case t == "inactive":
					cur.Active = false
				case t == "(read-only)":
					cur.ReadOnly = "read-only"
				case t == "(auto-read-only)":
					cur.ReadOnly = "auto-read-only"
				case strings.HasPrefix(t, "("):
				default:
					if mm := mdMemberRe.FindStringSubmatch(t); mm != nil {
						slot, _ := strconv.Atoi(mm[2])
						flags := strings.NewReplacer("(", "", ")", "").Replace(mm[3])
						cur.Members = append(cur.Members, MDMember{Name: mm[1], Slot: slot, Flags: flags})
					} else if cur.Level == "" && len(cur.Members) == 0 {
						cur.Level = t
					}
				}
			}
			continue
		}
		if cur == nil || indentOf(l) == 0 {
			cur = nil
			continue
		}
		cur.lines = append(cur.lines, l)
		t := strings.TrimSpace(l)
		if strings.Contains(t, " blocks") && cur.Blocks == 0 {
			if n := atoi(t); n > 0 {
				cur.Blocks = uint64(n)
			}
			if m := mdSuperRe.FindStringSubmatch(t); m != nil {
				cur.Super = m[1]
			}
		}
		if m := mdCountRe.FindStringSubmatch(t); m != nil {
			cur.Want, _ = strconv.Atoi(m[1])
			cur.Have, _ = strconv.Atoi(m[2])
			cur.Status = m[3]
		}
		if m := mdSyncRe.FindStringSubmatch(t); m != nil {
			cur.SyncOp = m[1]
			cur.SyncPct, _ = strconv.ParseFloat(m[2], 64)
			if f := mdFinishRe.FindStringSubmatch(t); f != nil {
				cur.Finish = f[1]
			}
			if f := mdSpeedRe.FindStringSubmatch(t); f != nil {
				cur.Speed = f[1]
			}
		} else if m := mdPendRe.FindStringSubmatch(t); m != nil {
			cur.Pending = m[1] + "=" + m[2]
		}
	}
	for _, a := range out {
		// IMSM/DDF metadata containers are always "inactive" and list
		// only spares; that is normal (mdadm(8), "CONTAINERS").
		if !a.Active && a.Level == "" && (strings.HasPrefix(a.Super, "external:imsm") || strings.HasPrefix(a.Super, "external:ddf")) {
			a.Container = true
		}
	}
	return out
}

// mdDetail is the parsed output of mdadm --detail.
type mdDetail struct {
	kv   map[string]string
	rows [][2]string // state, path
	all  []string
}

func parseMdadmDetail(s string) mdDetail {
	d := mdDetail{kv: map[string]string{}}
	inRows := false
	for _, l := range lines(s) {
		t := strings.TrimSpace(l)
		d.all = append(d.all, t)
		if strings.HasPrefix(t, "Number") && strings.Contains(t, "Major") {
			inRows = true
			continue
		}
		if inRows {
			f := strings.Fields(t)
			if len(f) < 5 {
				continue
			}
			rest := f[4:]
			path := ""
			if last := rest[len(rest)-1]; strings.HasPrefix(last, "/dev/") {
				path = last
				rest = rest[:len(rest)-1]
			}
			d.rows = append(d.rows, [2]string{strings.Join(rest, " "), path})
			continue
		}
		if k, v, ok := splitKV(t); ok && !strings.HasPrefix(t, "/dev/") {
			d.kv[strings.ToLower(k)] = v
		}
	}
	return d
}

// parseMdSysfs reads "path=value" lines from dw_sysfs.
func parseMdSysfs(s *collect.Section) (attrs map[string]map[string]string, devs map[string]map[string]map[string]string) {
	attrs = map[string]map[string]string{}
	devs = map[string]map[string]map[string]string{}
	for _, l := range s.Lines() {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		p := strings.Split(strings.TrimPrefix(k, "/sys/block/"), "/")
		if len(p) < 3 || p[1] != "md" {
			continue
		}
		md := p[0]
		if len(p) == 3 {
			if attrs[md] == nil {
				attrs[md] = map[string]string{}
			}
			attrs[md][p[2]] = strings.TrimSpace(v)
		} else if len(p) == 4 && strings.HasPrefix(p[2], "dev-") {
			dev := strings.TrimPrefix(p[2], "dev-")
			if devs[md] == nil {
				devs[md] = map[string]map[string]string{}
			}
			if devs[md][dev] == nil {
				devs[md][dev] = map[string]string{}
			}
			devs[md][dev][p[3]] = strings.TrimSpace(v)
		}
	}
	return attrs, devs
}

var mdNames = model.T("Linux software RAID (mdadm)", "RAID mềm Linux (mdadm)")

func (c *checker) checkMD() {
	sec := c.b.Get("raid.mdstat")
	if sec == nil || !sec.Ran() {
		return
	}
	arrays := parseMdstat(sec.Out)
	if len(arrays) == 0 {
		return // md module loaded but no arrays: nothing to report
	}
	attrs, devs := parseMdSysfs(c.b.Get("raid.md_sysfs"))
	detailOK := 0
	for _, a := range arrays {
		if at := attrs[a.Name]; at != nil {
			a.ArrayState = at["array_state"]
			a.SyncAction = at["sync_action"]
			a.SyncDone = at["sync_completed"]
			if n := atoi(at["degraded"]); n > 0 {
				a.Degraded = int(n)
			}
			if n := atoi(at["mismatch_cnt"]); n >= 0 {
				a.Mismatch = n
			}
			if at["level"] == "container" {
				a.Container = true
			}
			if a.Level == "" && at["level"] != "" && at["level"] != "container" {
				a.Level = at["level"]
			}
		}
		for i := range a.Members {
			if d := devs[a.Name][a.Members[i].Name]; d != nil {
				a.Members[i].State = d["state"]
				if n := atoi(d["errors"]); n > 0 {
					a.Members[i].Errors = n
				}
			}
		}
		if ds := c.b.Get("raid.mdadm:/dev/" + a.Name); ds.Ran() && strings.TrimSpace(ds.Out) != "" {
			detailOK++
			d := parseMdadmDetail(ds.Out)
			a.detail = d.all
			a.State = d.kv["state"]
			if n := atoi(d.kv["failed devices"]); n > 0 {
				a.FailedDevices = int(n)
			}
			a.ArraySize = d.kv["array size"]
			a.UUID = d.kv["uuid"]
			for _, r := range d.rows {
				if r[0] == "removed" {
					a.Removed++
				}
				if r[1] != "" {
					a.DetailPaths = append(a.DetailPaths, r[1])
					name := strings.TrimPrefix(r[1], "/dev/")
					for i := range a.Members {
						if a.Members[i].Name == name && r[0] != "" {
							a.Members[i].State = r[0]
						}
					}
				}
			}
			if a.SyncOp == "" {
				for _, k := range []string{"rebuild status", "resync status", "reshape status", "check status"} {
					if v, ok := d.kv[k]; ok {
						a.SyncOp = map[string]string{"rebuild status": "recovery", "resync status": "resync", "reshape status": "reshape", "check status": "check"}[k]
						a.SyncPct = pct(v)
					}
				}
			}
		}
		c.facts.MD = append(c.facts.MD, a)
		c.analyzeMD(a)
	}
	if len(c.okMD) > 0 {
		c.add(model.Finding{
			ID: "raid.md_ok", Severity: model.OK, Target: strings.Join(c.okMD, ", "),
			Title: model.Tf("Software RAID healthy: %s", "RAID mềm hoạt động tốt: %s", strings.Join(c.okMD, ", ")),
		})
	}

	// Coverage.
	scan := c.b.Get("raid.mdadm_scan")
	switch {
	case scan != nil && scan.Missing != "":
		fix, cmd := hint.InstallFix(c.env, "mdadm")
		c.cover("raid.md", mdNames, model.CovPartial,
			model.T("/proc/mdstat was read, but mdadm is not installed, so member details (which disk failed) are limited.",
				"Đã đọc /proc/mdstat nhưng chưa cài mdadm nên thông tin chi tiết từng ổ thành viên bị hạn chế."),
			fix, cmd)
	case scan != nil && scan.Skipped != "":
		c.cover("raid.md", mdNames, model.CovPartial,
			model.T("/proc/mdstat was read; mdadm --detail needs root.", "Đã đọc /proc/mdstat; mdadm --detail cần quyền root."),
			hint.RunAsRoot(c.env))
	case scan != nil && detailOK == 0:
		c.cover("raid.md", mdNames, model.CovPartial,
			model.Tf("mdadm --detail gave no output: %s", "mdadm --detail không trả về dữ liệu: %s", errText(scan)), model.Text{})
	default:
		c.cover("raid.md", mdNames, model.CovRan, model.Text{}, model.Text{})
	}
}

// mdFailedMembers returns members that are marked faulty.
func mdFailedMembers(a *MDArray) []MDMember {
	var out []MDMember
	for _, m := range a.Members {
		if strings.Contains(m.Flags, "F") || strings.Contains(m.State, "faulty") {
			out = append(out, m)
		}
	}
	return out
}

func mdSpares(a *MDArray) []string {
	var out []string
	for _, m := range a.Members {
		if strings.Contains(m.Flags, "S") && !strings.Contains(m.Flags, "F") {
			out = append(out, m.Name)
		}
	}
	return out
}

func mdRedundant(level string) bool {
	switch level {
	case "raid1", "raid4", "raid5", "raid6", "raid10", "multipath":
		return true
	}
	return false
}

// mdTolerance is how many members the level can lose and keep running.
func mdTolerance(a *MDArray) int {
	switch a.Level {
	case "raid1":
		return a.Want - 1
	case "raid4", "raid5":
		return 1
	case "raid6":
		return 2
	case "raid10":
		// It survives several failures if they hit different mirror
		// pairs, so the member count alone cannot prove a failure; rely on
		// mdadm's "FAILED" state instead.
		return a.Want
	}
	return 0
}

func (a *MDArray) size() string {
	if a.Blocks > 0 {
		return units.IEC(a.Blocks * 1024)
	}
	return ""
}

func (a *MDArray) memberList() string {
	var ms []string
	for _, m := range a.Members {
		s := m.Name
		if m.Flags != "" {
			s += "(" + m.Flags + ")"
		}
		ms = append(ms, s)
	}
	return strings.Join(ms, " ")
}

// mdETA formats "finish=17.0min" as a duration.
func mdETA(finish string) model.Text {
	m := strings.TrimSuffix(finish, "min")
	f, err := strconv.ParseFloat(m, 64)
	if err != nil || f < 0 {
		return model.T(finish, finish)
	}
	return units.Duration(time.Duration(f * float64(time.Minute)))
}

func (c *checker) mdMemberPart(a *MDArray, member string) *model.Part {
	return c.ids.diskPart(member, fmt.Sprintf("/dev/%s (member %s of %s)", diskOf(member), member, a.Name))
}

func (c *checker) analyzeMD(a *MDArray) {
	evid := append(append([]string{}, a.lines...), mdDetailEvidence(a)...)
	failed := mdFailedMembers(a)
	failedNames := []string{}
	for _, m := range failed {
		failedNames = append(failedNames, m.Name)
	}
	state := "active"
	if !a.Active {
		state = "inactive"
	}
	if a.Status != "" {
		state += " [" + a.Status + "]"
	}
	if a.ReadOnly != "" {
		state += " (" + a.ReadOnly + ")"
	}
	progress := ""
	if a.SyncOp != "" {
		progress = a.SyncOp + " " + fmtPct(a.SyncPct)
		if a.Finish != "" {
			progress += ", ETA " + mdETA(a.Finish).EN
		}
	} else if a.Pending != "" {
		progress = a.Pending
	}
	typ := a.Level
	if a.Container {
		typ = "container (" + a.Super + ")"
	}
	members := a.memberList()

	missing := 0
	if a.Want > a.Have {
		missing = a.Want - a.Have
	}
	if a.Degraded > missing {
		missing = a.Degraded
	}
	if a.Removed > missing {
		missing = a.Removed
	}
	degraded := missing > 0 || strings.Contains(a.Status, "_") || strings.Contains(strings.ToLower(a.State), "degraded") ||
		(a.Broken && mdRedundant(a.Level))
	// sysfs sync_action says "recover"/"reshape" as soon as a spare is
	// being rebuilt into a degraded array, also while the rebuild waits for
	// another array on the same disks (mdstat "resync=DELAYED", mdadm
	// "resyncing (DELAYED)", sync_completed "delayed"). Right after a member
	// fails without a spare, sync_action briefly reads "recover" too, but
	// sync_completed stays "none" (real WSL capture): that is no rebuild.
	syncRunning := a.SyncDone != "" && a.SyncDone != "none"
	rebuilding := a.SyncOp == "recovery" || a.SyncOp == "reshape" || strings.Contains(strings.ToLower(a.State), "recovering") || strings.Contains(strings.ToLower(a.State), "reshaping") ||
		((a.SyncAction == "recover" || a.SyncAction == "reshape") && syncRunning)
	queued := a.SyncOp == "" && (a.Pending != "" || a.SyncDone == "delayed")
	for _, m := range a.Members {
		if strings.Contains(m.State, "rebuilding") {
			rebuilding = true
		}
	}
	// array_state "broken" (and the mdstat word "broken") on raid0/linear:
	// a member is gone and the data is not readable.
	failedArray := strings.Contains(a.State, "FAILED") || a.ArrayState == "broken" || (a.Broken && !mdRedundant(a.Level)) ||
		(a.Active && mdRedundant(a.Level) && missing > mdTolerance(a) && a.Want > 0)

	sev := model.OK
	switch {
	case a.Container:
		// normal
	case !a.Active:
		sev = model.Crit
		c.add(model.Finding{
			ID: "raid.md_inactive", Severity: model.Crit, Target: a.Name,
			Title: model.Tf("RAID %s is inactive (not running)", "RAID %s đang inactive (không chạy)", a.Name),
			Detail: model.Tf("The kernel knows array %s but has not started it (members: %s). Its data is not accessible. This usually means members are missing or failed at boot.",
				"Kernel nhận diện mảng %s nhưng chưa khởi động được nó (thành viên: %s). Dữ liệu trên mảng hiện không truy cập được. Thường do thiếu ổ hoặc ổ lỗi lúc khởi động.", a.Name, joinOr([]string{members}, "-")),
			Action: model.Tf("Do not write to the member disks. Check which disks are present (lsblk, dmesg), then inspect them with 'mdadm --examine /dev/sdX1'. If enough members are healthy, start it with 'mdadm --run /dev/%s'. Do not use --force or re-create the array without a backup and an expert.",
				"Không ghi gì lên các ổ thành viên. Kiểm tra ổ nào còn nhận (lsblk, dmesg), xem từng ổ bằng 'mdadm --examine /dev/sdX1'. Nếu đủ thành viên còn tốt, chạy lại bằng 'mdadm --run /dev/%s'. Không dùng --force hay tạo lại mảng khi chưa có bản sao lưu và người có kinh nghiệm.", a.Name),
			Evidence: ev(evid),
		})
	case failedArray:
		sev = model.Crit
		c.add(model.Finding{
			ID: "raid.md_failed", Severity: model.Crit, Target: a.Name,
			Title: mdFailedTitle(a, missing),
			Detail: model.Tf("Array %s (%s) lost more members than its level can tolerate. Data on it is very likely unreadable. Failed: %s.",
				"Mảng %s (%s) mất nhiều thành viên hơn mức chịu lỗi. Dữ liệu trên mảng gần như chắc chắn không đọc được. Ổ lỗi: %s.", a.Name, a.Level, joinOr(failedNames, "-")),
			Action: model.T("Stop writing to the server. Restore from backup, or contact a data recovery expert before touching the disks; do not re-create or force-assemble the array.",
				"Ngừng ghi lên máy. Khôi phục từ bản sao lưu, hoặc liên hệ chuyên gia cứu dữ liệu trước khi đụng vào các ổ; không tạo lại hay ép (--force) lắp lại mảng."),
			Evidence: ev(evid),
			Part:     c.firstPart(a, failed),
		})
	case degraded && rebuilding:
		sev = model.Warn
		eta := model.Text{}
		if a.Finish != "" {
			e := mdETA(a.Finish)
			eta = model.Text{EN: ", about " + e.EN + " left", VI: ", còn khoảng " + e.VI}
		}
		title := model.Text{
			EN: fmt.Sprintf("RAID %s is rebuilding: %s done%s", a.Name, fmtPct(a.SyncPct), eta.EN),
			VI: fmt.Sprintf("RAID %s đang rebuild: xong %s%s", a.Name, fmtPct(a.SyncPct), eta.VI),
		}
		if queued {
			title = model.Tf("RAID %s is degraded; its rebuild is queued (waiting for another array on the same disks)",
				"RAID %s đang thiếu ổ; rebuild đang chờ tới lượt (đợi mảng khác dùng chung ổ đồng bộ xong)", a.Name)
		}
		op := a.SyncOp
		if op == "" {
			op = "recovery"
		}
		c.add(model.Finding{
			ID: "raid.md_rebuilding", Severity: model.Warn, Target: a.Name,
			Title: title,
			Detail: model.Tf("Array %s (%s) is degraded and is copying data onto a replacement/spare (%s, speed %s). Until it finishes the array has no redundancy: another disk failure can lose data.",
				"Mảng %s (%s) đang thiếu thành viên và đang chép dữ liệu sang ổ thay thế/ổ dự phòng (%s, tốc độ %s). Cho tới khi xong, mảng không còn dự phòng: hỏng thêm một ổ là có thể mất dữ liệu.", a.Name, a.Level, op, joinOr([]string{a.Speed}, "-")),
			Action: model.Tf("Do not reboot, shut down or pull any disk until the rebuild finishes (watch: cat /proc/mdstat). Make sure the backup is current. When it is done, check that 'mdadm --detail /dev/%s' shows State: clean.",
				"Không khởi động lại, tắt máy hay rút ổ nào cho tới khi rebuild xong (theo dõi: cat /proc/mdstat). Kiểm tra bản sao lưu còn mới. Khi xong, kiểm tra 'mdadm --detail /dev/%s' báo State: clean.", a.Name),
			Evidence: ev(evid),
		})
	case degraded:
		sev = model.Crit
		which := joinOr(failedNames, "")
		en, vi := "", ""
		if which != "" {
			en, vi = "; failed member: "+which, "; ổ lỗi: "+which
		}
		part := c.firstPart(a, failed)
		pen, pvi := partText(part)
		// A spare is already attached but an (auto-)read-only array never
		// starts recovery until it is switched to read-write (md.rst).
		startEN, startVI := "", ""
		if sp := mdSpares(a); len(sp) > 0 && a.ReadOnly != "" {
			startEN = fmt.Sprintf("Spare %s is attached but the array is %s, so the rebuild has not started: run 'mdadm --readwrite /dev/%s' and watch /proc/mdstat. ", strings.Join(sp, ", "), a.ReadOnly, a.Name)
			startVI = fmt.Sprintf("Đã có ổ dự phòng %s nhưng mảng đang %s nên chưa rebuild: chạy 'mdadm --readwrite /dev/%s' rồi theo dõi /proc/mdstat. ", strings.Join(sp, ", "), a.ReadOnly, a.Name)
		}
		c.add(model.Finding{
			ID: "raid.md_degraded", Severity: model.Crit, Target: a.Name,
			Title: model.Text{
				EN: fmt.Sprintf("RAID %s is degraded: %d member(s) missing%s", a.Name, missing, en),
				VI: fmt.Sprintf("RAID %s bị degraded: thiếu %d ổ thành viên%s", a.Name, missing, vi),
			},
			Detail: model.Tf("Array %s (%s) runs with %d of %d members [%s]. It still works, but has lost redundancy: one more disk failure can lose data.",
				"Mảng %s (%s) đang chạy với %d/%d thành viên [%s]. Mảng vẫn hoạt động nhưng đã mất dự phòng: hỏng thêm một ổ là có thể mất dữ liệu.", a.Name, a.Level, a.Have, a.Want, a.Status),
			Action: model.Text{
				EN: startEN + fmt.Sprintf("Back up now. Replace the failed disk%s: 1) mdadm --manage /dev/%s --fail /dev/sdX1 (if not already failed); 2) mdadm --manage /dev/%s --remove /dev/sdX1; 3) swap the disk and check the new one with 'smartctl -H -a'; 4) copy the partition table from a healthy member (sfdisk -d /dev/sdOK | sfdisk /dev/sdNEW, or sgdisk for GPT); 5) mdadm --manage /dev/%s --add /dev/sdNEW1 and watch /proc/mdstat until the rebuild ends. If the disk is not failed but missing, check its cable/backplane first.", pen, a.Name, a.Name, a.Name),
				VI: startVI + fmt.Sprintf("Sao lưu ngay. Thay ổ lỗi%s: 1) mdadm --manage /dev/%s --fail /dev/sdX1 (nếu ổ chưa bị đánh dấu lỗi); 2) mdadm --manage /dev/%s --remove /dev/sdX1; 3) thay ổ mới và kiểm tra bằng 'smartctl -H -a'; 4) chép bảng phân vùng từ ổ còn tốt (sfdisk -d /dev/sdOK | sfdisk /dev/sdNEW, hoặc sgdisk với GPT); 5) mdadm --manage /dev/%s --add /dev/sdNEW1 rồi theo dõi /proc/mdstat tới khi rebuild xong. Nếu ổ không hỏng mà chỉ mất kết nối, kiểm tra cáp/backplane trước.", pvi, a.Name, a.Name, a.Name),
			},
			Evidence: ev(evid),
			Part:     part,
		})
	}

	// A failed member that is still attached although the array is not
	// reported degraded (a hot spare took over) or is rebuilding: the dead
	// disk still has to be replaced.
	if a.Active && !failedArray && !(degraded && !rebuilding) && len(failed) > 0 {
		for _, m := range failed {
			part := c.mdMemberPart(a, m.Name)
			pen, pvi := partText(part)
			sev = model.Worst(sev, model.Crit)
			c.add(model.Finding{
				ID: "raid.md_member_failed", Severity: model.Crit, Target: a.Name + "/" + m.Name,
				Title: model.Tf("Disk %s in RAID %s has failed", "Ổ %s trong RAID %s đã hỏng", m.Name, a.Name),
				Detail: model.Tf("md marked %s as faulty (F). The array kept running on the remaining members or a hot spare, but the failed disk must be replaced to restore full redundancy and a spare.",
					"md đã đánh dấu %s là lỗi (F). Mảng vẫn chạy nhờ các ổ còn lại hoặc ổ dự phòng, nhưng phải thay ổ hỏng để khôi phục đủ dự phòng.", m.Name),
				Action: model.Text{
					EN: fmt.Sprintf("Replace disk %s%s: mdadm --manage /dev/%s --remove /dev/%s, swap the disk, check the new one with 'smartctl -H -a', partition it like the others and add it back with 'mdadm --manage /dev/%s --add /dev/<new>'. If a rebuild is running, wait for it to finish first.", m.Name, pen, a.Name, m.Name, a.Name),
					VI: fmt.Sprintf("Thay ổ %s%s: mdadm --manage /dev/%s --remove /dev/%s, thay ổ mới, kiểm tra bằng 'smartctl -H -a', phân vùng giống các ổ còn lại rồi thêm lại bằng 'mdadm --manage /dev/%s --add /dev/<ổ mới>'. Nếu đang rebuild, chờ rebuild xong rồi mới làm.", m.Name, pvi, a.Name, m.Name, a.Name),
				},
				Evidence: ev(evid),
				Part:     part,
			})
		}
	}

	if a.Active && !degraded && (a.SyncOp == "resync" || a.SyncOp == "reshape" || a.SyncOp == "recovery") {
		sev = model.Worst(sev, model.Warn)
		eta := model.Text{}
		if a.Finish != "" {
			e := mdETA(a.Finish)
			eta = model.Text{EN: ", about " + e.EN + " left", VI: ", còn khoảng " + e.VI}
		}
		c.add(model.Finding{
			ID: "raid.md_resync", Severity: model.Warn, Target: a.Name,
			Title: model.Text{
				EN: fmt.Sprintf("RAID %s is synchronising (%s): %s done%s", a.Name, a.SyncOp, fmtPct(a.SyncPct), eta.EN),
				VI: fmt.Sprintf("RAID %s đang đồng bộ (%s): xong %s%s", a.Name, a.SyncOp, fmtPct(a.SyncPct), eta.VI),
			},
			Detail: model.T("A resync runs after an unclean shutdown or on a new array; a reshape changes the layout or size. Until it ends, part of the array is not yet redundant and I/O is slower.",
				"Resync chạy sau khi tắt máy đột ngột hoặc khi mới tạo mảng; reshape là đang đổi cấu trúc/dung lượng. Cho tới khi xong, một phần mảng chưa có dự phòng và tốc độ đọc ghi chậm hơn."),
			Action: model.T("Do not reboot or pull disks until it finishes (watch: cat /proc/mdstat). If it follows an unexpected power loss, check the UPS/power and the system logs.",
				"Không khởi động lại hay rút ổ cho tới khi xong (theo dõi: cat /proc/mdstat). Nếu do mất điện đột ngột, kiểm tra UPS/nguồn điện và nhật ký hệ thống."),
			Evidence: ev(a.lines),
		})
	}
	if a.Active && (a.SyncOp == "check" || a.SyncOp == "repair") {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.md_check", Severity: model.Info, Target: a.Name,
			Title: model.Tf("RAID %s: consistency check (%s) running, %s done", "RAID %s: đang kiểm tra định kỳ (%s), xong %s", a.Name, a.SyncOp, fmtPct(a.SyncPct)),
			Detail: model.T("A scheduled scrub reads every block to find unreadable sectors early (most distributions run it monthly). The server is slower while it runs; it is safe to keep working.",
				"Kiểm tra định kỳ (scrub) đọc toàn bộ mảng để phát hiện sớm sector hỏng (đa số bản Linux chạy hằng tháng). Máy chậm hơn trong lúc chạy; vẫn dùng bình thường được."),
			Action: model.T("Nothing to do. To pause it during busy hours: echo idle > /sys/block/<md>/md/sync_action.",
				"Không cần làm gì. Muốn tạm dừng giờ cao điểm: echo idle > /sys/block/<md>/md/sync_action."),
			Evidence: ev(a.lines),
		})
	}
	if a.Active && a.SyncOp == "" && a.Pending != "" && !(degraded && rebuilding) {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.md_sync_pending", Severity: model.Info, Target: a.Name,
			Title: model.Tf("RAID %s: %s", "RAID %s: %s", a.Name, a.Pending),
			Detail: model.T("The synchronisation is queued (DELAYED: waits for another array on the same disks; PENDING: the array is auto-read-only and starts syncing on the first write).",
				"Việc đồng bộ đang xếp hàng (DELAYED: chờ mảng khác dùng chung ổ; PENDING: mảng đang auto-read-only, sẽ đồng bộ khi có lần ghi đầu tiên)."),
			Evidence: ev(a.lines),
		})
	}
	if a.ReadOnly == "read-only" {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.md_readonly", Severity: model.Info, Target: a.Name,
			Title:  model.Tf("RAID %s is read-only", "RAID %s đang ở chế độ chỉ đọc", a.Name),
			Detail: model.T("The array was started read-only (by an administrator or during recovery). Writes fail until it is switched back with 'mdadm --readwrite'.", "Mảng được bật ở chế độ chỉ đọc (do quản trị viên hoặc lúc khôi phục). Ghi sẽ lỗi cho tới khi chuyển lại bằng 'mdadm --readwrite'."),
			Action: model.Tf("If this is not intended: mdadm --readwrite /dev/%s", "Nếu không chủ ý: mdadm --readwrite /dev/%s", a.Name),
		})
	}

	// mismatch_cnt is only meaningful once a check/repair has finished.
	// Kernel docs (Documentation/admin-guide/md.rst, "mismatch_cnt"): on
	// RAID1/RAID10 non-zero counts are expected when pages change while
	// being written (swap, O_DIRECT), so they are informational; on parity
	// RAID they mean real inconsistent stripes.
	if a.Active && a.SyncOp == "" && a.Mismatch > 0 {
		s := model.Warn
		if a.Level == "raid1" || a.Level == "raid10" {
			s = model.Info
		}
		sev = model.Worst(sev, s)
		c.add(model.Finding{
			ID: "raid.md_mismatch", Severity: s, Target: a.Name,
			Title: model.Tf("RAID %s: last check found %d mismatched sectors", "RAID %s: lần kiểm tra gần nhất thấy %d sector không khớp", a.Name, a.Mismatch),
			Detail: model.Tf("mismatch_cnt=%d on a %s array. On RAID1/10 this is common and harmless when swap or files being rewritten live on the array. On RAID5/6 it means some parity blocks disagree with the data (after a crash without a write-intent bitmap, or a faulty disk/RAM).",
				"mismatch_cnt=%d trên mảng %s. Với RAID1/10 điều này hay gặp và vô hại nếu có swap hoặc file đang ghi đè nằm trên mảng. Với RAID5/6 nghĩa là một số khối parity không khớp dữ liệu (do sập máy khi không có bitmap, hoặc ổ/RAM lỗi).", a.Mismatch, a.Level),
			Action: model.Tf("Check the member disks' S.M.A.R.T. and the RAM (ECC errors). On parity RAID, run 'echo repair > /sys/block/%s/md/sync_action' and then a new check; if the count comes back, investigate the hardware.",
				"Kiểm tra S.M.A.R.T. các ổ thành viên và RAM (lỗi ECC). Với RAID parity, chạy 'echo repair > /sys/block/%s/md/sync_action' rồi kiểm tra lại; nếu vẫn còn sai lệch, cần kiểm tra phần cứng.", a.Name),
			Evidence: []string{fmt.Sprintf("/sys/block/%s/md/mismatch_cnt=%d", a.Name, a.Mismatch)},
		})
	}

	for _, m := range a.Members {
		// dev-*/state "write_error": the device has seen a write error
		// (md.rst); "errors": read errors md corrected by rewriting.
		if strings.Contains(m.State, "write_error") || strings.Contains(m.State, "want_replacement") {
			part := c.mdMemberPart(a, m.Name)
			sev = model.Worst(sev, model.Warn)
			c.add(model.Finding{
				ID: "raid.md_member_errors", Severity: model.Warn, Target: a.Name + "/" + m.Name,
				Title: mdMemberErrTitle(m, a),
				Detail: model.Tf("md sysfs state of %s is %q. The disk is still in the array, but it is unreliable.",
					"Trạng thái md sysfs của %s là %q. Ổ vẫn nằm trong mảng nhưng không còn đáng tin cậy.", m.Name, m.State),
				Action: model.Tf("Check 'smartctl -a /dev/%s' and the kernel log; plan to replace the disk.", "Kiểm tra 'smartctl -a /dev/%s' và nhật ký kernel; lên kế hoạch thay ổ.", diskOf(m.Name)),
				Part:   part,
			})
		} else if m.Errors > 0 && !strings.Contains(m.Flags, "F") {
			sev = model.Worst(sev, model.Info)
			c.add(model.Finding{
				ID: "raid.md_member_read_errors", Severity: model.Info, Target: a.Name + "/" + m.Name,
				Title: model.Tf("Disk %s in RAID %s: %d read errors corrected by md", "Ổ %s trong RAID %s: md đã tự sửa %d lỗi đọc", m.Name, a.Name, m.Errors),
				Detail: model.T("md read bad data from this member and rewrote it from the other copies. A few are harmless; a growing number points to a failing disk.",
					"md đọc lỗi trên ổ này và đã ghi lại từ bản sao khác. Vài lỗi thì không sao; số lỗi tăng dần là dấu hiệu ổ sắp hỏng."),
				Action: model.Tf("Check 'smartctl -a /dev/%s' (pending/reallocated sectors).", "Kiểm tra 'smartctl -a /dev/%s' (pending/reallocated sector).", diskOf(m.Name)),
				Part:   c.mdMemberPart(a, m.Name),
			})
		}
	}

	if sp := mdSpares(a); len(sp) > 0 && a.Active && !a.Container {
		sev = model.Worst(sev, model.Info)
		c.add(model.Finding{
			ID: "raid.md_spare", Severity: model.Info, Target: a.Name,
			Title:  model.Tf("RAID %s has %d hot spare(s): %s", "RAID %s có %d ổ dự phòng (hot spare): %s", a.Name, len(sp), strings.Join(sp, ", ")),
			Detail: model.T("A hot spare takes over automatically when a member fails.", "Ổ hot spare sẽ tự động thay thế khi một ổ thành viên hỏng."),
		})
	}

	c.arrayRow(sev, a.Name, typ, a.size(), state, members, progress)
	if sev <= model.Info && a.Active && !a.Container {
		s := a.Name + " " + a.Level
		if a.Status != "" {
			s += " [" + a.Status + "]"
		}
		c.okMD = append(c.okMD, s)
	}
}

// mdFailedTitle: raid0/linear have no "[n/m]" counts in mdstat.
func mdFailedTitle(a *MDArray, missing int) model.Text {
	if a.Want > 0 && missing > 0 {
		return model.Tf("RAID %s has failed: %d of %d members missing", "RAID %s đã hỏng: thiếu %d/%d thành viên", a.Name, missing, a.Want)
	}
	return model.Tf("RAID %s has failed: a member is missing or failed", "RAID %s đã hỏng: có ổ thành viên bị mất hoặc lỗi", a.Name)
}

func (c *checker) firstPart(a *MDArray, failed []MDMember) *model.Part {
	if len(failed) == 0 {
		return nil
	}
	return c.mdMemberPart(a, failed[0].Name)
}

func mdDetailEvidence(a *MDArray) []string {
	var out []string
	for _, l := range a.detail {
		lo := strings.ToLower(l)
		if strings.HasPrefix(lo, "state :") || strings.HasPrefix(lo, "failed devices") || strings.HasPrefix(lo, "rebuild status") ||
			strings.Contains(lo, "faulty") || strings.Contains(lo, "removed") || strings.Contains(lo, "rebuilding") {
			out = append(out, l)
		}
	}
	return out
}

// mdMemberErrTitle: "write_error" comes from the disk; "want_replacement"
// is set by 'mdadm --replace' or by md when the bad-block list fills up.
func mdMemberErrTitle(m MDMember, a *MDArray) model.Text {
	if strings.Contains(m.State, "write_error") {
		return model.Tf("Disk %s in RAID %s reported write errors", "Ổ %s trong RAID %s đã gặp lỗi ghi", m.Name, a.Name)
	}
	return model.Tf("Disk %s in RAID %s is marked for replacement (want_replacement)", "Ổ %s trong RAID %s đang được đánh dấu cần thay (want_replacement)", m.Name, a.Name)
}
