package filesystem

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// ZPoolSpace is the capacity of one ZFS pool from `zpool list`.
type ZPoolSpace struct {
	Name      string  `json:"name"`
	Size      string  `json:"size,omitempty"` // as zpool prints it ("7.25T")
	Alloc     string  `json:"alloc,omitempty"`
	Free      string  `json:"free,omitempty"`
	FreeBytes uint64  `json:"freeBytes,omitempty"`
	SizeBytes uint64  `json:"sizeBytes,omitempty"`
	CapPct    float64 `json:"capPct"`
	Health    string  `json:"health,omitempty"`
}

// ZFS space thresholds, on the pool's CAP (allocated / size). df cannot
// judge ZFS: every dataset reports used = its own "referenced" and size =
// referenced + pool free, so a pool can be 96 % full while "/" shows 52 %
// and the other datasets 1 % (real Proxmox case, forum.proxmox.com thread
// 139255). OpenZFS keeps a "slop" reserve of 1/32 of the pool
// (spa_slop_shift = 5, capped at 128 GiB since 2.1): ordinary writes fail
// once allocation reaches ~96.9 %, so 95 % is "act today". Above ~85 % the
// allocator switches to best-fit and writes slow down markedly (OpenZFS
// metaslab_df_free_pct / Oracle's "keep pools below 80 %" guidance), so
// that is the point to plan.
const (
	zfsWarn = 85.0
	zfsCrit = 95.0
)

// parseZpoolList parses `zpool list -H -o name,size,alloc,free,health,frag,cap`
// (tab separated, human-readable sizes, cap like "96%"). The raid domain's
// collector writes it as raid.zpool_list.
func parseZpoolList(s string) []ZPoolSpace {
	var out []ZPoolSpace
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 7 || f[0] == "NAME" {
			continue
		}
		c, err := strconv.ParseFloat(strings.TrimSuffix(f[6], "%"), 64)
		if err != nil || c < 0 || c > 100 {
			continue
		}
		out = append(out, ZPoolSpace{Name: f[0], Size: f[1], Alloc: f[2], Free: f[3], Health: f[4], CapPct: c,
			SizeBytes: humanBytes(f[1]), FreeBytes: humanBytes(f[3])})
	}
	return out
}

// humanBytes parses ZFS's binary human sizes ("239G", "7.25T", "512",
// "1.5K"); 0 when unknown ("-").
func humanBytes(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	mult := 1.0
	switch strings.ToUpper(s[len(s)-1:]) {
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	case "P":
		mult = 1 << 50
	case "E":
		mult = 1 << 60
	}
	if mult > 1 || strings.ToUpper(s[len(s)-1:]) == "B" {
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0
	}
	return uint64(v * mult)
}

// zfsPools marks ZFS datasets whose fullness is judged at pool level and
// returns the pools from raid.zpool_list. A dataset that is fuller than its
// pool by df's measure is limited by a quota and keeps its own check.
func zfsPools(b *collect.Bundle, fss []FS) []ZPoolSpace {
	pools := parseZpoolList(b.Get("raid.zpool_list").Text())
	byName := map[string]ZPoolSpace{}
	for _, p := range pools {
		byName[p.Name] = p
	}
	for i := range fss {
		fs := &fss[i]
		if fs.Type != "zfs" {
			continue
		}
		fs.Pool, _, _ = strings.Cut(fs.Device, "/")
		p, ok := byName[fs.Pool]
		if !ok {
			continue
		}
		fs.poolKnown = true
		quota := fs.UsePct >= usageWarn && p.CapPct < zfsWarn
		fs.byPool = !quota
	}
	return pools
}

func zpoolSeverity(p ZPoolSpace) model.Severity {
	s := model.OK
	switch {
	case p.CapPct >= zfsCrit:
		s = model.Crit
	case p.CapPct >= zfsWarn:
		s = model.Warn
	}
	if s > model.OK && p.FreeBytes >= largeFreeBytes {
		s--
	}
	return s
}

func zpoolFinding(p ZPoolSpace, sev model.Severity) model.Finding {
	return model.Finding{
		ID: "filesystem.space_low", Component: model.CompFilesystem, Severity: sev, Target: p.Name,
		Title: model.Tf("ZFS pool %s is %.0f%% full (%s free of %s)", "ZFS pool %s đã đầy %.0f%% (còn trống %s trên %s)", p.Name, p.CapPct, p.Free, p.Size),
		Detail: model.T("df cannot show this: each ZFS dataset reports only its own data, so the datasets can look almost empty while the pool is full. ZFS keeps about 3% of the pool in reserve; when allocation reaches it, every dataset and zvol on the pool stops accepting writes (VMs on zvols pause or crash), and above about 85% writes already slow down.",
			"df không thể hiện được điều này: mỗi dataset ZFS chỉ báo phần dữ liệu của riêng nó nên các dataset có thể trông gần trống trong khi pool đã đầy. ZFS giữ lại khoảng 3% dung lượng pool; khi dùng tới phần đó, mọi dataset và zvol trên pool đều không ghi được nữa (VM chạy trên zvol bị treo hoặc dừng), và từ khoảng 85% tốc độ ghi đã giảm rõ."),
		Action: model.Tf("Free space in pool %s: list snapshots by size and delete old ones (zfs list -t snapshot -o name,used -s used), remove unused VM disks and datasets, and check zvol reservations (zfs get -r refreservation %s). Check usage with zpool list and zfs list -o space. If it keeps growing, add a vdev or move data to another pool; keep ZFS pools below 80%%.",
			"Giải phóng dung lượng trong pool %s: liệt kê snapshot theo dung lượng và xoá bản cũ (zfs list -t snapshot -o name,used -s used), xoá ổ đĩa VM và dataset không dùng, kiểm tra dung lượng đặt trước của zvol (zfs get -r refreservation %s). Theo dõi bằng zpool list và zfs list -o space. Nếu vẫn tăng, thêm vdev hoặc chuyển dữ liệu sang pool khác; nên giữ pool ZFS dưới 80%%.", p.Name, p.Name),
		Evidence: []string{fmt.Sprintf("zpool list: %s size %s alloc %s free %s cap %.0f%% health %s", p.Name, p.Size, p.Alloc, p.Free, p.CapPct, p.Health)},
	}
}
