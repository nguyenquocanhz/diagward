// Package filesystem is the "filesystem" domain: free space and inodes,
// filesystems the kernel remounted read-only after errors, ext4 error
// counters, fstab entries that failed to mount (often a missing disk), and
// Windows volume health / dirty bit.
package filesystem

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "filesystem"

// FS is one filesystem as reported.
type FS struct {
	Mount       string   `json:"mount"`
	Device      string   `json:"device,omitempty"`
	Type        string   `json:"type,omitempty"`
	SizeBytes   uint64   `json:"sizeBytes,omitempty"`
	UsedBytes   uint64   `json:"usedBytes,omitempty"`
	AvailBytes  uint64   `json:"availBytes,omitempty"`
	UsePct      float64  `json:"usePct"`
	InodePct    *float64 `json:"inodePct,omitempty"`
	InodesFree  uint64   `json:"inodesFree,omitempty"`
	ReadOnly    bool     `json:"readOnly,omitempty"`
	ErrorsCount uint64   `json:"errorsCount,omitempty"`
	State       string   `json:"state,omitempty"` // ext superblock state / Windows health
	Dirty       bool     `json:"dirty,omitempty"`
}

// Facts is the typed data of the filesystem domain.
type Facts struct {
	Filesystems []FS `json:"filesystems"`
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	switch b.OS {
	case collect.OSLinux:
		if len(b.Prefix("filesystem.")) == 0 {
			return res
		}
		checkLinux(b, env, &res)
	case collect.OSWindows:
		if b.Get("filesystem.win_volume") == nil {
			return res
		}
		checkWindows(b, env, &res)
	}
	return res
}

// Filesystem types that live on a local disk. Space and read-only checks
// only apply to these (plus unknown types on a /dev device).
var diskTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "vfat": true, "msdos": true, "exfat": true,
	"ntfs": true, "ntfs3": true, "fuseblk": true, "bcachefs": true, "ocfs2": true, "gfs2": true,
	"hfsplus": true, "nilfs2": true,
}

// Types that remount read-only on errors (errors=remount-ro, btrfs/xfs
// forced read-only). vfat and others are often read-only on purpose.
var roOnErrorTypes = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "f2fs": true, "jfs": true, "reiserfs": true, "bcachefs": true}

var pseudoTypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "rootfs": true, "squashfs": true, "overlay": true, "proc": true,
	"sysfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "pstore": true, "efivarfs": true, "autofs": true, "mqueue": true, "hugetlbfs": true,
	"configfs": true, "fusectl": true, "binfmt_misc": true, "bpf": true, "nsfs": true, "ramfs": true,
	"rpc_pipefs": true, "iso9660": true, "udf": true, "9p": true, "swap": true, "none": true,
}

var networkTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "glusterfs": true, "ceph": true,
	"fuse.sshfs": true, "fuse.glusterfs": true, "fuse.cephfs": true, "davfs": true, "fuse.s3fs": true, "lustre": true,
}

// Mount points whose filesystem must be writable for the server to work.
var criticalMounts = map[string]bool{
	"/": true, "/var": true, "/home": true, "/tmp": true, "/srv": true, "/opt": true,
	"/var/log": true, "/var/lib": true, "/data": true, "/var/lib/mysql": true,
	"/var/lib/pgsql": true, "/var/lib/postgresql": true, "/var/lib/docker": true, "/var/lib/vz": true,
	"/var/www": true,
}

// Space thresholds. ext2/3/4 reserve 5 % of blocks for root by default
// (mke2fs -m 5), so at ~95 % df usage ordinary services already get "No
// space left on device". Databases, mail queues and journald fail or
// corrupt data when a write fails, so 90 % is the point to act and 97 %
// means writes are about to fail. When more than 1 TiB is still free the
// level drops one step: the percentage alone overstates the urgency on very
// large volumes. Windows Explorer marks a drive red at 90 % too.
const (
	usageWarn       = 90.0
	usageCrit       = 97.0
	largeFreeBytes  = 1 << 40
	largeFreeInodes = 10_000_000
)

func normPoint(p string) string {
	if p == "" {
		return p
	}
	p = path.Clean(p)
	return p
}

func usageSeverity(pct float64, plentyFree bool) model.Severity {
	s := model.OK
	switch {
	case pct >= usageCrit:
		s = model.Crit
	case pct >= usageWarn:
		s = model.Warn
	}
	if plentyFree && s > model.OK {
		s--
	}
	return s
}

// pctOf mirrors df's Use%: used / (used + available), rounded up, which
// counts the root-reserved blocks as unavailable.
func pctOf(used, avail uint64) float64 {
	if used+avail == 0 {
		return 0
	}
	return math.Ceil(float64(used) * 100 / float64(used+avail))
}

func checkLinux(b *collect.Bundle, env model.Env, res *model.Result) {
	mounts := parseMounts(b.Get("filesystem.mounts").Text())
	typeAt := map[string]string{}
	devAt := map[string]string{}
	for _, m := range mounts {
		typeAt[normPoint(m.Point)] = m.Type // later mounts hide earlier ones
		devAt[normPoint(m.Point)] = m.Device
	}
	dfSec := b.Get("filesystem.df")
	rows, unit := parseDF(dfSec.Text())
	inoRows, _ := parseDF(b.Get("filesystem.df_inodes").Text())
	inodes := map[string]dfRow{}
	for _, r := range inoRows {
		inodes[normPoint(r.Point)] = r
	}

	var fss []FS
	seenDev := map[string]bool{}
	for _, r := range rows {
		p := normPoint(r.Point)
		t := r.Type
		if t == "" {
			t = typeAt[p]
		}
		if pseudoTypes[t] || networkTypes[t] || strings.HasPrefix(t, "fuse.") && !diskTypes[t] {
			continue
		}
		if t == "" && !strings.HasPrefix(r.Device, "/dev/") {
			continue
		}
		if !diskTypes[t] && t != "" && !strings.HasPrefix(r.Device, "/dev/") {
			continue
		}
		if r.Total == 0 {
			continue
		}
		key := r.Device + "|" + fmt.Sprint(r.Total)
		if seenDev[key] {
			continue // bind mount or second view of the same filesystem
		}
		seenDev[key] = true
		fs := FS{Mount: p, Device: r.Device, Type: t, SizeBytes: r.Total * unit, UsedBytes: r.Used * unit, AvailBytes: r.Avail * unit}
		fs.UsePct = pctOf(r.Used, r.Avail)
		if ir, ok := inodes[p]; ok && ir.Total > 0 {
			v := pctOf(ir.Used, ir.Avail)
			fs.InodePct, fs.InodesFree = &v, ir.Avail
		}
		fss = append(fss, fs)
	}

	spaceCoverage(b, dfSec, rows, res)
	status := map[string]model.Severity{}
	spaceFindings(fss, status, res, env)

	// Health: read-only remounts, ext4 errors, superblock state, fstab.
	healthCov := model.Coverage{ID: "filesystem.health", Component: model.CompFilesystem,
		Name: model.T("Filesystem health (read-only remounts, ext4 errors, fstab)", "Tình trạng hệ thống tệp (bị chuyển read-only, lỗi ext4, fstab)")}
	if len(mounts) == 0 {
		healthCov.State = model.CovFailed
		healthCov.Reason = model.T("/proc/mounts could not be read.", "Không đọc được /proc/mounts.")
		res.Coverage = append(res.Coverage, healthCov)
		finishTable(fss, status, res)
		return
	}
	healthCov.State = model.CovRan
	if t := b.Get("filesystem.tune2fs"); t != nil {
		switch {
		case t.Skipped == "not-root":
			healthCov.State, healthCov.Reason, healthCov.Fix = model.CovPartial,
				model.T("Reading the ext superblock state (tune2fs -l) needs root.", "Cần quyền root để đọc trạng thái superblock ext (tune2fs -l)."), hint.RunAsRoot(env)
		case t.Missing != "":
			healthCov.State, healthCov.Reason, healthCov.Fix = model.CovPartial, hint.Missing("tune2fs"),
				model.T("Install e2fsprogs and run Diagward again.", "Cài gói e2fsprogs rồi chạy lại Diagward.")
		}
	}
	res.Coverage = append(res.Coverage, healthCov)

	problems := 0
	problems += readOnlyFindings(mounts, parseFstab(b.Get("filesystem.fstab").Text()), env, &fss, status, res)
	problems += ext4Findings(b, mounts, env, &fss, status, res)
	if !env.Container {
		problems += fstabFindings(b, mounts, res)
	}
	if problems == 0 {
		n := 0
		for _, m := range mounts {
			if roOnErrorTypes[m.Type] {
				n++
			}
		}
		if n > 0 {
			res.Findings = append(res.Findings, model.Finding{
				ID: "filesystem.health_ok", Component: model.CompFilesystem, Severity: model.OK,
				Title: model.Tf("Filesystems are mounted normally; no filesystem errors recorded (%d mounts checked)", "Các phân vùng được mount bình thường; không ghi nhận lỗi hệ thống tệp (đã kiểm tra %d điểm mount)", n),
			})
		}
	}
	finishTable(fss, status, res)
}

func spaceCoverage(b *collect.Bundle, df *collect.Section, rows []dfRow, res *model.Result) {
	c := model.Coverage{ID: "filesystem.space", Component: model.CompFilesystem,
		Name: model.T("Free space and inodes", "Dung lượng trống và inode")}
	switch {
	case df == nil:
		c.State, c.Reason = model.CovSkipped, model.T("df was not run.", "df chưa được chạy.")
	case df.Timeout:
		c.State = model.CovFailed
		c.Reason = model.T("df timed out — usually a hung network mount (NFS/CIFS) or a disk that stopped answering.", "df bị quá thời gian — thường do mount mạng (NFS/CIFS) bị treo hoặc ổ đĩa không phản hồi.")
	case len(rows) == 0:
		c.State = model.CovFailed
		c.Reason = model.T("df output could not be read.", "Không đọc được kết quả df.")
		if e := strings.TrimSpace(df.Err); e != "" {
			c.Reason = model.Tf("df output could not be read: %s", "Không đọc được kết quả df: %s", firstLine(e))
		}
	case b.Get("filesystem.df_inodes") == nil || len(b.Get("filesystem.df_inodes").Lines()) == 0:
		c.State, c.Reason = model.CovPartial, model.T("Inode usage was not available.", "Không có dữ liệu sử dụng inode.")
	default:
		c.State = model.CovRan
	}
	res.Coverage = append(res.Coverage, c)
}

func spaceFindings(fss []FS, status map[string]model.Severity, res *model.Result, env model.Env) {
	worst := ""
	worstPct := -1.0
	bad := 0
	for _, fs := range fss {
		if fs.UsePct > worstPct {
			worst, worstPct = fs.Mount, fs.UsePct
		}
		sev := usageSeverity(fs.UsePct, fs.AvailBytes >= largeFreeBytes)
		ev := []string{fmt.Sprintf("%s on %s (%s): size %s, used %s, available %s, %.0f%% used",
			fs.Device, fs.Mount, fs.Type, units.SI(fs.SizeBytes), units.SI(fs.UsedBytes), units.SI(fs.AvailBytes), fs.UsePct)}
		if sev > model.OK {
			if sev >= model.Warn {
				bad++
			}
			status[fs.Mount] = max(status[fs.Mount], sev)
			res.Findings = append(res.Findings, model.Finding{
				ID: "filesystem.space_low", Component: model.CompFilesystem, Severity: sev, Target: fs.Mount,
				Title: model.Tf("Filesystem %s is %.0f%% full (%s free)", "Phân vùng %s đã đầy %.0f%% (còn trống %s)", fs.Mount, fs.UsePct, units.SI(fs.AvailBytes)),
				Detail: spaceDetail(env, model.T("When a filesystem fills up, writes fail: databases stop or corrupt tables, logs are lost, services crash and updates break. ext4 keeps 5% for root, so normal services fail before df shows 100%.",
					"Khi phân vùng đầy, mọi thao tác ghi sẽ lỗi: database dừng hoặc hỏng bảng, mất log, dịch vụ bị treo và cập nhật hệ thống thất bại. ext4 giữ lại 5% cho root nên dịch vụ thường đã lỗi trước khi df báo 100%.")),
				Action: spaceAction(env, fs.Mount, model.Tf("Free space on %s: find big directories (du -xh --max-depth=2 %s | sort -h | tail), clean old logs (journalctl --vacuum-size=500M, logrotate), old backups and package caches (dnf clean all / apt-get clean). Check for deleted files still held open (lsof +L1). Extend the volume if it keeps growing.",
					"Giải phóng dung lượng trên %s: tìm thư mục lớn (du -xh --max-depth=2 %s | sort -h | tail), dọn log cũ (journalctl --vacuum-size=500M, logrotate), bản backup cũ và cache gói (dnf clean all / apt-get clean). Kiểm tra file đã xoá nhưng vẫn bị giữ (lsof +L1). Mở rộng dung lượng nếu tiếp tục tăng.", fs.Mount, fs.Mount)),
				Evidence: ev,
			})
		}
		if fs.InodePct != nil {
			isev := usageSeverity(*fs.InodePct, fs.InodesFree >= largeFreeInodes)
			if isev > model.OK {
				if isev >= model.Warn {
					bad++
				}
				status[fs.Mount] = max(status[fs.Mount], isev)
				res.Findings = append(res.Findings, model.Finding{
					ID: "filesystem.inodes_low", Component: model.CompFilesystem, Severity: isev, Target: fs.Mount,
					Title: model.Tf("Filesystem %s has used %.0f%% of its inodes", "Phân vùng %s đã dùng %.0f%% số inode", fs.Mount, *fs.InodePct),
					Detail: model.T("Each file needs an inode. When they run out, no new file can be created even if df shows free space (\"No space left on device\").",
						"Mỗi file cần một inode. Khi hết inode sẽ không tạo được file mới dù df vẫn báo còn dung lượng (\"No space left on device\")."),
					Action: model.Tf("Find directories with huge numbers of small files (du --inodes -x %s | sort -n | tail, or find %s -xdev -type d -size +1M): session files, mail queues, cache. Delete what is not needed.",
						"Tìm thư mục chứa rất nhiều file nhỏ (du --inodes -x %s | sort -n | tail, hoặc find %s -xdev -type d -size +1M): file session, hàng đợi mail, cache. Xoá những gì không cần.", fs.Mount, fs.Mount),
					Evidence: []string{fmt.Sprintf("%s: inodes %.0f%% used, %s free", fs.Mount, *fs.InodePct, units.Thousands(fs.InodesFree))},
				})
			}
		}
	}
	if bad == 0 && len(fss) > 0 {
		res.Findings = append(res.Findings, model.Finding{
			ID: "filesystem.space_ok", Component: model.CompFilesystem, Severity: model.OK,
			Title: model.Tf("%d filesystem(s) have enough free space (fullest: %s at %.0f%%)", "%d phân vùng còn đủ dung lượng trống (đầy nhất: %s ở mức %.0f%%)", len(fss), worst, worstPct),
		})
	}
}

// readOnlyFindings reports filesystems the kernel switched to read-only.
// Since Linux 6.6 ext4 no longer sets the read-only mount flag after an
// error; /proc/mounts shows "emergency_ro" (or "shutdown") instead, so both
// forms are checked.
func readOnlyFindings(mounts []mount, fstab []fstabEntry, env model.Env, fss *[]FS, status map[string]model.Severity, res *model.Result) int {
	rwDev := map[string]bool{}
	for _, m := range mounts {
		if !m.has("ro") && !m.has("emergency_ro") && !m.has("shutdown") {
			rwDev[m.Device] = true
		}
	}
	fstabAt := map[string]fstabEntry{}
	for _, e := range fstab {
		fstabAt[normPoint(e.Point)] = e
	}
	done := map[string]bool{}
	n := 0
	for _, m := range mounts {
		if !roOnErrorTypes[m.Type] || done[m.Device] {
			continue
		}
		p := normPoint(m.Point)
		emergency := m.has("emergency_ro") || m.has("shutdown")
		ro := m.has("ro")
		if !emergency && !ro {
			continue
		}
		sev := model.Info
		why := ""
		switch {
		case emergency:
			sev, why = model.Crit, "emergency_ro"
		case rwDev[m.Device]:
			continue // a read-only bind/second view of a filesystem that is still writable
		case fstabAt[p].Point != "" && fstabAt[p].has("ro"):
			continue // read-only on purpose
		case env.Container:
			sev = model.Info
		case fstabAt[p].Point != "":
			sev, why = model.Crit, "fstab"
		case criticalMounts[p]:
			sev, why = model.Crit, "critical"
		}
		done[m.Device] = true
		for i := range *fss {
			if (*fss)[i].Mount == p || (*fss)[i].Device == m.Device {
				(*fss)[i].ReadOnly = true
			}
		}
		status[p] = max(status[p], sev)
		ev := []string{fmt.Sprintf("%s %s %s %s", m.Device, m.Point, m.Type, strings.Join(m.Opts, ","))}
		if e, ok := fstabAt[p]; ok {
			ev = append(ev, "fstab: "+e.Line)
		}
		if sev == model.Crit {
			n++
			detail := model.Tf("%s (%s) is mounted read-only although it should be writable. The kernel does this when it detects filesystem corruption or the disk returns I/O errors, to protect the data. Every write to it now fails.",
				"%s (%s) đang bị mount chỉ-đọc (read-only) dù lẽ ra phải ghi được. Kernel tự chuyển sang read-only khi phát hiện hệ thống tệp bị hỏng hoặc ổ đĩa trả về lỗi đọc/ghi, để bảo vệ dữ liệu. Mọi thao tác ghi vào đây đều thất bại.", p, m.Device)
			if why == "emergency_ro" {
				detail.EN += " /proc/mounts shows emergency_ro: ext4 aborted after an error."
				detail.VI += " /proc/mounts có cờ emergency_ro: ext4 đã dừng ghi sau khi gặp lỗi."
			}
			res.Findings = append(res.Findings, model.Finding{
				ID: "filesystem.readonly", Component: model.CompFilesystem, Severity: model.Crit, Target: p,
				Title:  model.Tf("Filesystem %s was remounted read-only after errors", "Phân vùng %s đã bị chuyển sang chỉ-đọc (read-only) do lỗi", p),
				Detail: detail,
				Action: model.Tf("Back up the data that is still readable now. Check the Disks and RAID sections and the kernel log (journalctl -k | grep -i -e 'I/O error' -e EXT4-fs -e XFS) to see whether the disk is failing. Then boot into rescue mode and run fsck on %s (xfs_repair for XFS); replace the disk first if it is failing. Do not just remount it read-write.",
					"Sao lưu ngay dữ liệu còn đọc được. Xem mục Ổ cứng, RAID và log kernel (journalctl -k | grep -i -e 'I/O error' -e EXT4-fs -e XFS) để biết ổ có đang hỏng không. Sau đó khởi động vào chế độ rescue và chạy fsck cho %s (xfs_repair nếu là XFS); nếu ổ đang hỏng thì thay ổ trước. Không chỉ đơn giản remount lại read-write.", m.Device),
				Evidence: ev,
			})
		} else {
			res.Findings = append(res.Findings, model.Finding{
				ID: "filesystem.mounted_ro", Component: model.CompFilesystem, Severity: model.Info, Target: p,
				Title:    model.Tf("%s is mounted read-only", "%s đang được mount chỉ-đọc (read-only)", p),
				Detail:   model.T("It is not in /etc/fstab and not a system path, so this may be intentional (backup or recovery mount).", "Điểm mount này không có trong /etc/fstab và không phải thư mục hệ thống, nên có thể là cố ý (mount để sao lưu hoặc cứu dữ liệu)."),
				Action:   model.T("If it should be writable, check the kernel log for filesystem errors before remounting.", "Nếu cần ghi được, hãy kiểm tra log kernel xem có lỗi hệ thống tệp không trước khi remount."),
				Evidence: ev,
			})
		}
	}
	return n
}

// ext4Findings reports the superblock error counters (s_error_count, kept
// until fsck repairs the filesystem) and "clean with errors" states.
func ext4Findings(b *collect.Bundle, mounts []mount, env model.Env, fss *[]FS, status map[string]model.Severity, res *model.Result) int {
	errs, dm := parseExt4(b.Get("filesystem.ext4").Text())
	nameToDM := map[string]string{}
	for k, v := range dm {
		nameToDM[v] = k
	}
	// sysfs name of a mounted device: sda1, dm-0, md0, nvme0n1p2, loop0
	sysName := func(dev string) string {
		if n, ok := strings.CutPrefix(dev, "/dev/mapper/"); ok {
			if d, ok := nameToDM[n]; ok {
				return d
			}
			return n
		}
		return path.Base(dev)
	}
	type fsErr struct {
		m     mount
		e     *ext4Err
		t2    *tune2fs
		ev    []string
		count uint64
	}
	byDev := map[string]*fsErr{}
	var order []string
	for _, m := range mounts {
		if !strings.HasPrefix(m.Type, "ext") || !strings.HasPrefix(m.Device, "/dev/") {
			continue
		}
		if _, ok := byDev[m.Device]; ok {
			continue
		}
		fe := &fsErr{m: m}
		if e := errs[sysName(m.Device)]; e != nil {
			fe.e = e
			fe.count = e.Count
		}
		if s := b.Get("filesystem.tune2fs:" + m.Device); s.Ran() {
			t := parseTune2fs(s.Text())
			fe.t2 = &t
			if fe.count == 0 {
				fe.count = t.ErrorCount
			}
		}
		byDev[m.Device] = fe
		order = append(order, m.Device)
	}
	n := 0
	for _, dev := range order {
		fe := byDev[dev]
		withErrors := fe.t2 != nil && strings.Contains(strings.ToLower(fe.t2.State), "error")
		if fe.count == 0 && !withErrors {
			continue
		}
		p := normPoint(fe.m.Point)
		var ev []string
		recent := false
		var last time.Time
		if fe.e != nil {
			ev = append(ev, fmt.Sprintf("/sys/fs/ext4/%s/errors_count=%d", fe.e.Dev, fe.e.Count))
			if fe.e.First > 0 {
				ev = append(ev, fmt.Sprintf("first error %s in %s", time.Unix(fe.e.First, 0).UTC().Format(time.RFC3339), orDash(fe.e.FirstFn)))
			}
			if fe.e.Last > 0 {
				last = time.Unix(fe.e.Last, 0).UTC()
				ev = append(ev, fmt.Sprintf("last error %s in %s", last.Format(time.RFC3339), orDash(fe.e.LastF)))
				// An error inside the log window means the filesystem is being
				// damaged now, not an old event awaiting fsck.
				days := env.SinceDays
				if days <= 0 {
					days = 7
				}
				if !env.Now.IsZero() && env.Now.Sub(last) <= time.Duration(days)*24*time.Hour && !last.After(env.Now.Add(24*time.Hour)) {
					recent = true
				}
			}
		}
		if fe.t2 != nil {
			ev = append(ev, fe.t2.Lines...)
		}
		sev := model.Warn
		if recent {
			sev = model.Crit
		}
		for i := range *fss {
			if (*fss)[i].Device == dev {
				(*fss)[i].ErrorsCount = fe.count
				if fe.t2 != nil {
					(*fss)[i].State = fe.t2.State
				}
			}
		}
		status[p] = max(status[p], sev)
		n++
		when := model.T("", "")
		if !last.IsZero() {
			when = model.Tf(" The last error was on %s.", " Lỗi gần nhất vào %s.", last.Format("2006-01-02 15:04 UTC"))
		}
		// Already reported as remounted read-only: add the error record to
		// that finding instead of a second Crit for the same filesystem.
		merged := false
		for i := range res.Findings {
			f := &res.Findings[i]
			if f.ID == "filesystem.readonly" && f.Target == p {
				f.Detail.EN += fmt.Sprintf(" The superblock has recorded %d error(s).%s", fe.count, when.EN)
				f.Detail.VI += fmt.Sprintf(" Superblock đã ghi nhận %d lỗi.%s", fe.count, when.VI)
				f.Evidence = units.Evidence(append(f.Evidence, ev...), 10)
				merged = true
			}
		}
		if merged {
			continue
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "filesystem.ext4_errors", Component: model.CompFilesystem, Severity: sev, Target: p,
			Title: model.Tf("Filesystem %s (%s) has recorded %d error(s)", "Phân vùng %s (%s) đã ghi nhận %d lỗi", p, dev, fe.count),
			Detail: model.Text{
				EN: fmt.Sprintf("The ext4 superblock records errors the kernel found (corrupted metadata, failed reads). They stay recorded until fsck repairs the filesystem, so the filesystem has known damage.%s", when.EN),
				VI: fmt.Sprintf("Superblock ext4 lưu lại các lỗi kernel phát hiện (metadata bị hỏng, đọc thất bại). Lỗi được giữ cho tới khi fsck sửa xong, nghĩa là hệ thống tệp đang có chỗ hỏng.%s", when.VI),
			},
			Action: model.Tf("Back up important data. Check the Disks section and the kernel log (journalctl -k | grep -i 'EXT4-fs error') for the cause. Schedule downtime and run fsck -f %s from rescue mode (or unmounted); replace the disk first if S.M.A.R.T. shows problems.",
				"Sao lưu dữ liệu quan trọng. Xem mục Ổ cứng và log kernel (journalctl -k | grep -i 'EXT4-fs error') để tìm nguyên nhân. Lên lịch dừng máy và chạy fsck -f %s trong chế độ rescue (hoặc khi đã umount); nếu S.M.A.R.T. báo lỗi thì thay ổ trước.", dev),
			Evidence: units.Evidence(ev, 10),
		})
	}
	return n
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// fstabFindings reports fstab entries that should be mounted but are not —
// often a disk that disappeared or a filesystem that failed to mount at boot.
func fstabFindings(b *collect.Bundle, mounts []mount, res *model.Result) int {
	fs := b.Get("filesystem.fstab")
	if !fs.Ran() {
		return 0
	}
	mounted := map[string]bool{}
	for _, m := range mounts {
		mounted[normPoint(m.Point)] = true
	}
	n := 0
	for _, e := range parseFstab(fs.Text()) {
		p := normPoint(e.Point)
		if !strings.HasPrefix(p, "/") || e.Type == "swap" || pseudoTypes[e.Type] && e.Type != "none" || e.Type == "none" && !e.has("bind") {
			continue
		}
		if e.has("noauto") || e.has("nofail") || e.has("x-systemd.automount") || e.has("_netdev") && !networkTypes[e.Type] {
			continue
		}
		if mounted[p] {
			continue
		}
		network := networkTypes[e.Type] || strings.HasPrefix(e.Type, "fuse.") || strings.Contains(e.Spec, ":/") || strings.HasPrefix(e.Spec, "//")
		sev := model.Warn
		if network {
			sev = model.Info
		}
		if sev >= model.Warn {
			n++
		}
		act := model.Tf("Check that the device %s still exists (lsblk -f, blkid) — a missing disk shows up here first — then check the Disks/RAID sections and try mount %s to see the error.",
			"Kiểm tra thiết bị %s còn tồn tại không (lsblk -f, blkid) — ổ đĩa bị mất thường lộ ra ở đây đầu tiên — rồi xem mục Ổ cứng/RAID và thử mount %s để xem lỗi.", e.Spec, p)
		if network {
			act = model.Tf("Check the network share server and connectivity, then try mount %s to see the error.", "Kiểm tra máy chủ chia sẻ và kết nối mạng, rồi thử mount %s để xem lỗi.", p)
		}
		res.Findings = append(res.Findings, model.Finding{
			ID: "filesystem.fstab_unmounted", Component: model.CompFilesystem, Severity: sev, Target: p,
			Title: model.Tf("%s is in /etc/fstab but not mounted", "%s có trong /etc/fstab nhưng không được mount", p),
			Detail: model.T("The filesystem should be mounted at boot but is not. Data written to that path now goes to the parent filesystem instead, and applications expecting it may fail.",
				"Phân vùng này lẽ ra được mount khi khởi động nhưng hiện không có. Dữ liệu ghi vào đường dẫn đó sẽ rơi vào phân vùng cha, và ứng dụng cần nó có thể bị lỗi."),
			Action:   act,
			Evidence: []string{"fstab: " + e.Line},
		})
	}
	return n
}

func finishTable(fss []FS, status map[string]model.Severity, res *model.Result) {
	res.Facts = &Facts{Filesystems: fss}
	if len(fss) == 0 {
		return
	}
	sort.SliceStable(fss, func(i, j int) bool { return fss[i].Mount < fss[j].Mount })
	t := model.Table{
		ID:    "filesystem.usage",
		Title: model.T("Filesystems", "Phân vùng"),
		Columns: []model.Text{
			model.T("Mount", "Điểm mount"), model.T("Device", "Thiết bị"), model.T("Type", "Loại"),
			model.T("Size", "Dung lượng"), model.T("Free", "Còn trống"), model.T("Used", "Đã dùng"),
			model.T("Inodes used", "Inode đã dùng"), model.T("Mode", "Chế độ"),
		},
	}
	for _, fs := range fss {
		ino := ""
		if fs.InodePct != nil {
			ino = fmt.Sprintf("%.0f%%", *fs.InodePct)
		}
		mode := "rw"
		if fs.ReadOnly {
			mode = "ro"
		}
		if fs.ErrorsCount > 0 {
			mode += fmt.Sprintf(", %d errors", fs.ErrorsCount)
		}
		if fs.Dirty {
			mode += ", dirty"
		}
		if fs.State != "" && !strings.EqualFold(fs.State, "clean") && !strings.EqualFold(fs.State, "healthy") {
			mode += ", " + fs.State
		}
		t.Rows = append(t.Rows, model.Row{Status: status[fs.Mount], Cells: []string{
			fs.Mount, fs.Device, fs.Type, units.SI(fs.SizeBytes), units.SI(fs.AvailBytes), fmt.Sprintf("%.0f%%", fs.UsePct), ino, mode,
		}})
	}
	res.Tables = append(res.Tables, t)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return strings.TrimSpace(s)
}

// spaceDetail and spaceAction pick the Windows wording on Windows.
func spaceDetail(env model.Env, linux model.Text) model.Text {
	if env.OS != collect.OSWindows {
		return linux
	}
	return model.T("When a volume fills up, writes fail: databases (SQL Server, Exchange) stop, Windows Update and the page file fail, shadow copies (VSS) are deleted and services crash.",
		"Khi volume đầy, mọi thao tác ghi sẽ lỗi: database (SQL Server, Exchange) dừng, Windows Update và page file bị lỗi, bản shadow copy (VSS) bị xoá và dịch vụ bị treo.")
}

func spaceAction(env model.Env, mnt string, linux model.Text) model.Text {
	if env.OS != collect.OSWindows {
		return linux
	}
	return model.Tf("Free space on %s: find big folders (TreeSize or WizTree on %s), run Disk Cleanup (cleanmgr) and Dism /Online /Cleanup-Image /StartComponentCleanup, remove old backups, logs (IIS, SQL) and user temp files. Extend the volume if it keeps growing.",
		"Giải phóng dung lượng trên %s: tìm thư mục lớn (TreeSize hoặc WizTree trên %s), chạy Disk Cleanup (cleanmgr) và Dism /Online /Cleanup-Image /StartComponentCleanup, xoá backup cũ, log (IIS, SQL) và file tạm. Mở rộng volume nếu dung lượng tiếp tục tăng.", mnt, mnt)
}
