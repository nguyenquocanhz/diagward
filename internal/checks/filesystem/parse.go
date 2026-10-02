package filesystem

import (
	"strconv"
	"strings"
)

// mount is one line of /proc/mounts.
type mount struct {
	Device, Point, Type string
	Opts                []string
}

func (m mount) has(opt string) bool {
	for _, o := range m.Opts {
		if o == opt {
			return true
		}
	}
	return false
}

// unescapeMount decodes the octal escapes the kernel and fstab use for
// spaces, tabs, newlines and backslashes (\040 \011 \012 \134).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseMounts(s string) []mount {
	var out []mount
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		out = append(out, mount{
			Device: unescapeMount(f[0]),
			Point:  unescapeMount(f[1]),
			Type:   f[2],
			Opts:   strings.Split(f[3], ","),
		})
	}
	return out
}

// fstabEntry is one active line of /etc/fstab.
type fstabEntry struct {
	Spec, Point, Type string
	Opts              []string
	Line              string
}

func (e fstabEntry) has(opt string) bool {
	for _, o := range e.Opts {
		if o == opt || strings.HasPrefix(o, opt+"=") {
			return true
		}
	}
	return false
}

func parseFstab(s string) []fstabEntry {
	var out []fstabEntry
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 3 {
			continue
		}
		e := fstabEntry{Spec: unescapeMount(f[0]), Point: unescapeMount(f[1]), Type: f[2], Line: t}
		if len(f) >= 4 {
			e.Opts = strings.Split(f[3], ",")
		} else {
			e.Opts = []string{"defaults"}
		}
		out = append(out, e)
	}
	return out
}

// dfRow is one filesystem from df.
type dfRow struct {
	Device, Type, Point string
	Total, Used, Avail  uint64 // bytes (blocks) or inode counts
	Line                string
}

// parseDF parses POSIX `df -P` output, with or without the -T type column
// and with any block size header ("1-blocks", "1024-blocks", "Inodes").
// The mount point is everything after the capacity column, so mount
// points with spaces survive. Rows whose numbers do not parse (BusyBox
// prints garbage such as 18446744073708552615 for some 9p mounts) are kept
// only if used <= total.
func parseDF(s string) (rows []dfRow, unit uint64) {
	unit = 1
	typed := false
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		if f[0] == "Filesystem" {
			typed = f[1] == "Type"
			col := f[1]
			if typed && len(f) > 2 {
				col = f[2]
			}
			if b, ok := strings.CutSuffix(col, "-blocks"); ok {
				if n, err := strconv.ParseUint(b, 10, 64); err == nil && n > 0 {
					unit = n
				} else if b == "1K" {
					unit = 1024
				}
			}
			continue
		}
		// locate the capacity column ("12%" or "-")
		ci := -1
		start := 4
		if typed {
			start = 5
		}
		if len(f) <= start {
			continue
		}
		if strings.HasSuffix(f[start], "%") || f[start] == "-" {
			ci = start
		}
		if ci < 0 {
			continue
		}
		r := dfRow{Device: f[0], Line: l}
		nums := f[1:ci]
		if typed {
			r.Type = f[1]
			nums = f[2:ci]
		}
		if len(nums) != 3 {
			continue
		}
		var errs [3]error
		r.Total, errs[0] = strconv.ParseUint(nums[0], 10, 64)
		r.Used, errs[1] = strconv.ParseUint(nums[1], 10, 64)
		r.Avail, errs[2] = strconv.ParseUint(nums[2], 10, 64)
		if errs[0] != nil || errs[1] != nil || errs[2] != nil || r.Used > r.Total {
			continue
		}
		// mount point = rest of the line after the capacity token
		idx := indexField(l, ci)
		if idx < 0 {
			continue
		}
		r.Point = strings.TrimSpace(l[idx+len(f[ci]):])
		if r.Point == "" {
			continue
		}
		rows = append(rows, r)
	}
	return rows, unit
}

// indexField returns the byte offset of the n-th whitespace-separated field.
func indexField(l string, n int) int {
	inField := false
	k := -1
	for i := 0; i < len(l); i++ {
		sp := l[i] == ' ' || l[i] == '\t'
		if !sp && !inField {
			k++
			if k == n {
				return i
			}
		}
		inField = !sp
	}
	return -1
}

// ext4Err is the per-device error state from /sys/fs/ext4/<dev>/.
type ext4Err struct {
	Dev            string
	Count          uint64
	First, Last    int64 // unix seconds, 0 = never
	FirstFn, LastF string
}

// parseExt4 parses filesystem.ext4 (dw_sysfs dump) into per-device error
// state and the dm-N -> name map.
func parseExt4(s string) (map[string]*ext4Err, map[string]string) {
	errs := map[string]*ext4Err{}
	dm := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if rest, ok := strings.CutPrefix(k, "/sys/block/"); ok {
			if dev, tail, ok := strings.Cut(rest, "/"); ok && tail == "dm/name" && v != "" {
				dm[dev] = v
			}
			continue
		}
		rest, ok := strings.CutPrefix(k, "/sys/fs/ext4/")
		if !ok {
			continue
		}
		dev, attr, ok := strings.Cut(rest, "/")
		if !ok || dev == "" {
			continue
		}
		e := errs[dev]
		if e == nil {
			e = &ext4Err{Dev: dev}
			errs[dev] = e
		}
		switch attr {
		case "errors_count":
			e.Count, _ = strconv.ParseUint(v, 10, 64)
		case "first_error_time":
			e.First, _ = strconv.ParseInt(v, 10, 64)
		case "last_error_time":
			e.Last, _ = strconv.ParseInt(v, 10, 64)
		case "first_error_func":
			e.FirstFn = v
		case "last_error_func":
			e.LastF = v
		}
	}
	return errs, dm
}

// tune2fs holds the superblock lines we use from `tune2fs -l`.
type tune2fs struct {
	State      string
	ErrorCount uint64
	Lines      []string
}

func parseTune2fs(s string) tune2fs {
	var t tune2fs
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Filesystem state":
			t.State = v
			t.Lines = append(t.Lines, strings.TrimSpace(l))
		case "FS Error count":
			t.ErrorCount, _ = strconv.ParseUint(v, 10, 64)
			t.Lines = append(t.Lines, strings.TrimSpace(l))
		case "First error time", "Last error time", "Last error function", "First error function", "Errors behavior":
			t.Lines = append(t.Lines, strings.TrimSpace(l))
		}
	}
	return t
}
