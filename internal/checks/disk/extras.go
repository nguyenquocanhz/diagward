package disk

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// ---- smartd ----

// SmartdFact is the state of the smartd monitoring daemon.
type SmartdFact struct {
	Installed bool     `json:"installed"`
	Running   bool     `json:"running"`
	Enabled   bool     `json:"enabled"`
	Config    []string `json:"config,omitempty"` // active lines of smartd.conf
}

var covSmartd = model.T("Continuous S.M.A.R.T. monitoring (smartd)", "Giám sát S.M.A.R.T. liên tục (smartd)")

func (c *checker) smartd() {
	s := c.b.Get("disk.smartd")
	if s == nil {
		return
	}
	if !s.Ran() {
		if s.Skipped == "container" || c.env.Container {
			c.cover("smartd", covSmartd, model.CovSkipped, hint.Virtual(c.env), model.Text{})
		} else {
			c.cover("smartd", covSmartd, model.CovSkipped, model.Tf("Skipped (%s).", "Bỏ qua (%s).", firstNonEmpty(s.Skipped, s.Missing)), model.Text{})
		}
		return
	}
	f := &SmartdFact{}
	for _, l := range s.Lines() {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "installed":
			f.Installed = v == "1"
		case k == "process":
			f.Running = f.Running || v == "1"
		case strings.HasPrefix(k, "active_"):
			f.Running = f.Running || v == "active"
		case strings.HasPrefix(k, "enabled_"):
			f.Enabled = f.Enabled || v == "enabled"
		case k == "conf" && len(f.Config) < 20:
			f.Config = append(f.Config, v)
		}
	}
	if f.Running {
		f.Installed = true
	}
	c.facts.Smartd = f
	c.cover("smartd", covSmartd, model.CovRan, model.Text{}, model.Text{})
	if f.Running || !c.env.Bare() {
		return
	}
	unit := "smartd"
	if hint.Family(c.env) == "debian" {
		// Debian/Ubuntu ship smartmontools.service; smartd.service is only
		// an alias there and systemctl refuses to enable an alias.
		unit = "smartmontools"
	}
	sudo := ""
	if !c.env.Root {
		sudo = "sudo "
	}
	act := model.Tf("Enable continuous monitoring: %ssystemctl enable --now %s (smartd e-mails or logs a warning as soon as a disk starts failing).",
		"Bật giám sát liên tục: %ssystemctl enable --now %s (smartd sẽ gửi mail hoặc ghi log ngay khi ổ có dấu hiệu hỏng).", sudo, unit)
	if !f.Installed {
		inst := hint.InstallCommand(c.env, hint.Package(c.env, "smartctl"))
		if inst != "" {
			act = model.Tf("Install smartmontools and enable continuous monitoring: %s && %ssystemctl enable --now %s",
				"Cài smartmontools và bật giám sát liên tục: %s && %ssystemctl enable --now %s", inst, sudo, unit)
		}
	}
	ev := []string{}
	for _, l := range s.Lines() {
		if strings.HasPrefix(l, "active_") || strings.HasPrefix(l, "enabled_") || strings.HasPrefix(l, "process=") || strings.HasPrefix(l, "installed=") {
			ev = append(ev, l)
		}
	}
	c.add(model.Finding{
		ID: "disk.smartd_not_running", Component: model.CompDisk, Severity: model.Info, Target: "smartd",
		Title:  model.T("Continuous disk monitoring (smartd) is not running", "Dịch vụ giám sát ổ cứng liên tục (smartd) chưa chạy"),
		Detail: model.T("Without smartd, a failing disk is only noticed when someone runs a check like this one.", "Không có smartd thì ổ sắp hỏng chỉ được phát hiện khi có người chạy kiểm tra như lần này."),
		Action: act, Evidence: ev,
	})
}

// ---- disk speed test ----

// BenchFact is the result of the opt-in dd test.
type BenchFact struct {
	Dir         string  `json:"dir"`
	FS          string  `json:"fs,omitempty"`
	Source      string  `json:"source,omitempty"`
	MB          int     `json:"mb,omitempty"`
	WriteMBps   float64 `json:"writeMBps,omitempty"`
	ReadMBps    float64 `json:"readMBps,omitempty"`
	WriteDirect bool    `json:"writeDirect"`
	ReadDirect  bool    `json:"readDirect"`
	Error       string  `json:"error,omitempty"`
}

var covBench = model.T("Disk speed test (dd)", "Kiểm tra tốc độ ổ (dd)")

// reDD matches dd's summary line: GNU coreutils
// "268435456 bytes (268 MB, 256 MiB) copied, 1.53 s, 175 MB/s" (older:
// "268435456 bytes (268 MB) copied, 1.53 s, 175 MB/s") and BusyBox
// "268435456 bytes (256.0MB) copied, 1.53 seconds, 167.3MB/s". The rate is
// recomputed from bytes and seconds so the unit suffix does not matter.
var reDD = regexp.MustCompile(`^(\d+) bytes.*copied, ([0-9]+(?:\.[0-9]+)?) s`)

func ddRate(line string) (float64, bool) {
	m := reDD.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return 0, false
	}
	b, err1 := strconv.ParseFloat(m[1], 64)
	s, err2 := strconv.ParseFloat(m[2], 64)
	if err1 != nil || err2 != nil || s <= 0 || b <= 0 {
		return 0, false
	}
	return b / s / 1e6, true
}

// benchSlowMBps: a sequential 1 MiB-block direct write or read below this is
// clearly abnormal for any server disk: 5400 rpm HDDs sustain roughly
// 100-200 MB/s on outer tracks, SATA SSDs 400-550 MB/s and NVMe over
// 1000 MB/s (vendor datasheets). Below 30 MB/s points to a failing disk
// (retries), a degraded or rebuilding RAID, a disabled write cache or a
// USB 2.0 link.
const benchSlowMBps = 30

func (c *checker) bench() {
	s := c.b.Get("disk.bench")
	if s == nil {
		return
	}
	if !s.Ran() {
		if s.Skipped == "disabled" {
			c.cover("bench", covBench, model.CovSkipped,
				model.T("Opt-in test, not requested: it writes a test file to disk.", "Bài kiểm tra tùy chọn, không được yêu cầu: nó ghi một file thử lên ổ."),
				model.T("To run it, give Diagward a benchmark directory on the disk to test (the BenchDir option, e.g. --bench-dir /var/tmp); it needs 3x the test size free and deletes its file afterwards.",
					"Muốn chạy, chỉ định thư mục kiểm tra nằm trên ổ cần đo (tùy chọn BenchDir, ví dụ --bench-dir /var/tmp); cần trống gấp 3 lần dung lượng thử và file thử sẽ tự xóa sau khi đo."))
		} else {
			c.cover("bench", covBench, model.CovSkipped, model.Tf("Skipped (%s).", "Bỏ qua (%s).", firstNonEmpty(s.Skipped, s.Missing)), model.Text{})
		}
		return
	}
	kv := s.KV()
	bf := &BenchFact{Dir: kv["dir"], FS: kv["fs"], Source: kv["source"], Error: kv["error"],
		WriteDirect: kv["write_direct"] == "1", ReadDirect: kv["read_direct"] == "1"}
	bf.MB, _ = strconv.Atoi(kv["mb"])
	c.facts.Bench = bf
	w, wok := ddRate(kv["write_line"])
	r, rok := ddRate(kv["read_line"])
	if wok {
		bf.WriteMBps = round1(w)
	}
	if rok {
		bf.ReadMBps = round1(r)
	}
	switch bf.Error {
	case "":
	case "no-space":
		c.cover("bench", covBench, model.CovSkipped,
			model.Tf("Not enough free space in %s (%s kB free, the test needs 3x %d MiB).", "Không đủ chỗ trống trong %s (còn %s kB, cần gấp 3 lần %d MiB).", bf.Dir, kv["free_kb"], bf.MB),
			model.T("Choose a directory with more free space.", "Chọn thư mục còn nhiều chỗ trống hơn."))
		return
	case "write-timeout":
		c.cover("bench", covBench, model.CovRan, model.Text{}, model.Text{})
		c.add(model.Finding{ID: "disk.bench_slow", Component: model.CompDisk, Severity: model.Warn, Target: bf.Dir,
			Title:  model.Tf("Disk speed test in %s did not finish in time", "Kiểm tra tốc độ trong %s không xong kịp", bf.Dir),
			Detail: model.Tf("Writing %d MiB took longer than the time limit, i.e. well under 10 MB/s.", "Ghi %d MiB mất lâu hơn thời gian cho phép, tức là chậm hơn nhiều so với 10 MB/s.", bf.MB),
			Action: benchSlowAction(bf), Evidence: benchEvidence(kv)})
		return
	default:
		c.cover("bench", covBench, model.CovFailed,
			model.Tf("The speed test could not run in %s: %s. %s", "Không chạy được kiểm tra tốc độ trong %s: %s. %s", bf.Dir, bf.Error, firstLine(firstNonEmpty(kv["write_err"], s.Err))),
			model.T("Use an existing, writable directory on a local disk.", "Dùng một thư mục có sẵn, ghi được, nằm trên ổ cục bộ."))
		return
	}
	if !wok {
		c.cover("bench", covBench, model.CovFailed,
			model.Tf("dd output could not be read: %s", "Không đọc được kết quả dd: %s", firstLine(firstNonEmpty(kv["write_line"], s.Err))), model.Text{})
		return
	}
	c.cover("bench", covBench, model.CovRan, model.Text{}, model.Text{})
	ev := benchEvidence(kv)
	readTxt := "n/a"
	if rok {
		readTxt = fmt.Sprintf("%.0f MB/s", r)
		if !bf.ReadDirect {
			readTxt += " (cached, not a disk read)"
		}
	}
	fsl := strings.ToLower(bf.FS)
	var note model.Text
	notDisk := false
	switch {
	case strings.Contains(fsl, "tmpfs") || strings.Contains(fsl, "ramfs"):
		notDisk = true
		note = model.T(" The directory is in RAM (tmpfs), so this does not measure a disk.", " Thư mục nằm trên RAM (tmpfs) nên kết quả không phản ánh ổ cứng.")
	case strings.Contains(fsl, "nfs") || strings.Contains(fsl, "cifs") || strings.Contains(fsl, "smb") || strings.Contains(fsl, "fuse") || strings.Contains(fsl, "9p") || strings.Contains(fsl, "ceph") || strings.Contains(fsl, "gluster"):
		notDisk = true
		note = model.T(" The directory is on a network or FUSE filesystem, so this measures the network/remote storage, not a local disk.", " Thư mục nằm trên file system mạng hoặc FUSE nên kết quả là tốc độ mạng/lưu trữ từ xa, không phải ổ cục bộ.")
	case strings.Contains(fsl, "zfs") || strings.Contains(fsl, "btrfs"):
		note = model.T(" ZFS/Btrfs may compress the test data (zeros) and cache reads, so fast results can be inflated.", " ZFS/Btrfs có thể nén dữ liệu thử (toàn số 0) và cache khi đọc, nên kết quả nhanh có thể bị phóng đại.")
	}
	slow := !notDisk && (w < benchSlowMBps || (rok && bf.ReadDirect && r < benchSlowMBps))
	if slow {
		c.add(model.Finding{ID: "disk.bench_slow", Component: model.CompDisk, Severity: model.Warn, Target: bf.Dir,
			Title: model.Tf("Disk is very slow in %s: write %.0f MB/s, read %s", "Ổ rất chậm trong %s: ghi %.0f MB/s, đọc %s", bf.Dir, w, readTxt),
			Detail: model.T(fmt.Sprintf("Sequential throughput below %d MB/s is abnormal for a server disk (HDD ~100-250 MB/s, SATA SSD ~400-550 MB/s, NVMe >1000 MB/s).%s", benchSlowMBps, note.EN),
				fmt.Sprintf("Tốc độ tuần tự dưới %d MB/s là bất thường với ổ máy chủ (HDD ~100-250 MB/s, SSD SATA ~400-550 MB/s, NVMe >1000 MB/s).%s", benchSlowMBps, note.VI)),
			Action: benchSlowAction(bf), Evidence: ev})
		return
	}
	c.add(model.Finding{ID: "disk.bench", Component: model.CompDisk, Severity: model.OK, Target: bf.Dir,
		Title: model.Tf("Disk speed in %s: write %.0f MB/s, read %s", "Tốc độ ổ trong %s: ghi %.0f MB/s, đọc %s", bf.Dir, w, readTxt),
		Detail: model.T(fmt.Sprintf("Sequential %d MiB test with dd (direct I/O). For reference: HDD ~100-250 MB/s, SATA SSD ~400-550 MB/s, NVMe >1000 MB/s.%s", bf.MB, note.EN),
			fmt.Sprintf("Đo tuần tự %d MiB bằng dd (direct I/O). Tham khảo: HDD ~100-250 MB/s, SSD SATA ~400-550 MB/s, NVMe >1000 MB/s.%s", bf.MB, note.VI)),
		Evidence: ev})
}

func benchSlowAction(bf *BenchFact) model.Text {
	return model.Tf("Check the disk behind %s (%s): its S.M.A.R.T. findings above, whether a RAID array is degraded or rebuilding, the controller write-cache/battery state, and the kernel log for I/O errors. Run the test again when the server is idle.",
		"Kiểm tra ổ chứa %s (%s): các cảnh báo S.M.A.R.T. ở trên, RAID có đang degraded/rebuild không, trạng thái cache ghi/pin của controller, và kernel log có lỗi I/O không. Chạy lại bài đo khi máy chủ rảnh.",
		bf.Dir, firstNonEmpty(bf.Source, "?"))
}

func benchEvidence(kv map[string]string) []string {
	var ev []string
	for _, k := range []string{"dir", "fs", "source", "mb", "write_direct", "write_line", "read_direct", "read_line", "error"} {
		if v, ok := kv[k]; ok && v != "" {
			ev = append(ev, k+"="+v)
		}
	}
	return ev
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}
