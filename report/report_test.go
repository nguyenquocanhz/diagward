package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

var update = flag.Bool("update", false, "write testdata/sample.* previews")

const evil = `<script>alert("x")</script>" onmouseover="alert(1)" '><img src=x onerror=alert(2)>`

// richReport builds a report that exercises every renderer path: all
// severities, every component, parts, tables, all coverage states, notes,
// long Vietnamese text, CJK, emoji, control characters and HTML in
// untrusted strings.
func richReport() *model.Report {
	loc := time.FixedZone("ICT", 7*3600)
	disk := model.Result{
		Domain: "disk",
		Findings: []model.Finding{
			{
				ID: "disk.smart_pending", Component: model.CompDisk, Severity: model.Crit, Target: "/dev/sda",
				Title:  model.T("Disk /dev/sda is failing: 24 sectors could not be read", "Ổ /dev/sda sắp hỏng: 24 sector không đọc được"),
				Detail: model.T("S.M.A.R.T. attribute 197 Current_Pending_Sector = 24 and 198 Offline_Uncorrectable = 24. Sectors that cannot be read mean data on them may already be lost, and the count usually grows quickly.", "Thuộc tính S.M.A.R.T. 197 Current_Pending_Sector = 24 và 198 Offline_Uncorrectable = 24. Sector không đọc được nghĩa là dữ liệu trên đó có thể đã mất, và số lượng thường tăng nhanh."),
				Action: model.T("Back up the data now. Replace disk /dev/sda (serial ZC1234AB). If it is in a RAID, check the array has rebuilt before pulling the disk.", "Sao lưu dữ liệu ngay. Thay ổ /dev/sda (serial ZC1234AB). Nếu ổ nằm trong RAID, kiểm tra RAID đã rebuild xong trước khi rút ổ."),
				Evidence: []string{
					"197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       24",
					"198 Offline_Uncorrectable   0x0010   100   100   000    Old_age   Offline      -       24",
					evil,
					"line with \x1b[31mANSI\x1b[0m escape and a\ttab and bell\a",
				},
				Part: &model.Part{Kind: "disk", Vendor: "Seagate", Model: "ST4000NM0035-1V4107", Serial: "ZC1234AB", Location: "/dev/sda (bay 3)", Firmware: "TN03", Size: "4.0 TB"},
			},
			{
				ID: "disk.smart_selftest_failed", Component: model.CompDisk, Severity: model.Crit, Target: "/dev/sda",
				Title:  model.T("Disk /dev/sda failed its last self-test", "Ổ /dev/sda không qua bài tự kiểm tra gần nhất"),
				Action: model.T("Replace the disk.", "Thay ổ."),
				Part:   &model.Part{Kind: "disk", Vendor: "Seagate", Model: "ST4000NM0035-1V4107", Serial: "ZC1234AB", Location: "/dev/sda (bay 3)"},
			},
			{
				ID: "disk.crc_errors", Component: model.CompDisk, Severity: model.Warn, Target: evil,
				Title:  model.T("Cable errors on "+evil, "Lỗi cáp trên "+evil),
				Detail: model.T("UDMA_CRC_Error_Count = 31", "UDMA_CRC_Error_Count = 31"),
				Action: model.T("Reseat or replace the SATA/SAS cable and backplane slot.", "Cắm lại hoặc thay cáp SATA/SAS và khe backplane."),
			},
			{
				ID: "disk.smart_ok", Component: model.CompDisk, Severity: model.OK,
				Title: model.T("3 disks passed S.M.A.R.T.", "3 ổ cứng đạt kiểm tra S.M.A.R.T."),
			},
		},
		Tables: []model.Table{{
			ID: "disk.inventory", Title: model.T("Disks", "Ổ cứng"),
			Columns: []model.Text{model.T("Device", "Thiết bị"), model.T("Model", "Model"), model.T("Serial", "Serial"), model.T("Size", "Dung lượng"), model.T("Temp", "Nhiệt độ"), model.T("Power-on", "Thời gian chạy"), model.T("Health", "Sức khỏe")},
			Rows: []model.Row{
				{Status: model.Crit, Cells: []string{"/dev/sda", "ST4000NM0035-1V4107", "ZC1234AB", "4.0 TB", "41 °C", "5 năm 2 tháng (45,600 giờ)", "FAILING: 24 pending sectors, đang hỏng dần"}},
				{Status: model.Warn, Cells: []string{"/dev/sdb", "WDC WD40EFRX-68N32N0", "WD-WCC7K1234567", "4.0 TB", "38 °C", "2 năm", evil}},
				{Status: model.OK, Cells: []string{"/dev/nvme0n1", "SAMSUNG MZQL2960HCJR-00A07", "S64FNE0R123456", "960 GB", "35 °C", "1 năm", "OK"}},
			},
			Note: model.T("Values from smartctl -a.", "Số liệu từ smartctl -a."),
		}},
		Coverage: []model.Coverage{
			{ID: "disk.smart", Component: model.CompDisk, Name: model.T("S.M.A.R.T. health", "Sức khỏe S.M.A.R.T."), State: model.CovRan},
			{ID: "disk.nvme_log", Component: model.CompDisk, Name: model.T("NVMe error log", "Nhật ký lỗi NVMe"), State: model.CovSkipped,
				Reason: model.T("nvme is not installed.", "Chưa cài nvme."), Fix: model.T("Install it: dnf install -y nvme-cli", "Cài đặt: dnf install -y nvme-cli")},
			{ID: "disk.bench", Component: model.CompDisk, Name: model.T("Disk speed test", "Đo tốc độ ổ cứng"), State: model.CovSkipped,
				Reason: model.T("Disabled by default; it writes a test file.", "Mặc định tắt vì phải ghi tệp thử."), Fix: model.T("Run: diagward check --bench --bench-dir /var/tmp --bench-mb 1024 --some-very-long-option-name-to-force-wrapping=value", "Chạy: diagward check --bench --bench-dir /var/tmp --bench-mb 1024 --some-very-long-option-name-to-force-wrapping=value")},
		},
	}
	raid := model.Result{
		Domain: "raid",
		Findings: []model.Finding{{
			ID: "raid.md_degraded", Component: model.CompRAID, Severity: model.Crit, Target: "md0",
			Title:    model.T("RAID md0 is degraded [_U]: one member is missing", "RAID md0 bị suy giảm [_U]: thiếu một ổ thành viên"),
			Detail:   model.T("/proc/mdstat shows [2/1] [_U].\nThe array has no redundancy left.", "/proc/mdstat cho thấy [2/1] [_U].\nRAID không còn dự phòng."),
			Action:   model.T("Back up now, then replace the failed member and re-add it: mdadm --manage /dev/md0 --add /dev/sdX1", "Sao lưu ngay, sau đó thay ổ hỏng và thêm lại: mdadm --manage /dev/md0 --add /dev/sdX1"),
			Evidence: []string{"md0 : active raid1 sdb1[1]", "      976630464 blocks super 1.2 [2/1] [_U]"},
		}},
		Coverage: []model.Coverage{
			{ID: "raid.mdstat", Component: model.CompRAID, Name: model.T("Linux software RAID", "RAID mềm Linux"), State: model.CovRan},
			{ID: "raid.megaraid", Component: model.CompRAID, Name: model.T("MegaRAID controller", "Card RAID MegaRAID"), State: model.CovPartial,
				Reason: model.T("Controller found but storcli could not read the battery.", "Có card RAID nhưng storcli không đọc được pin.")},
		},
	}
	mem := model.Result{
		Domain: "memory",
		Findings: []model.Finding{{
			ID: "memory.ce_rising", Component: model.CompMemory, Severity: model.Warn, Target: "DIMM_A1",
			Title:  model.T("Corrected ECC errors on DIMM_A1 (152 in 7 days)", "Thanh RAM DIMM_A1 có lỗi ECC đã sửa (152 lỗi trong 7 ngày)"),
			Detail: model.T("EDAC reports corrected errors on one module. They are fixed by ECC but often precede uncorrectable errors.", "EDAC báo lỗi đã sửa trên một thanh RAM. ECC đã sửa được nhưng đây thường là dấu hiệu trước khi xảy ra lỗi không sửa được."),
			Action: model.T("Plan to replace DIMM_A1 at the next maintenance window. Run memtester or the vendor diagnostics to confirm.", "Lên kế hoạch thay thanh RAM DIMM_A1 trong lần bảo trì tới. Chạy memtester hoặc công cụ chẩn đoán của hãng để xác nhận."),
			Part:   &model.Part{Kind: "dimm", Vendor: "Samsung", Model: "M393A4K40CB2-CVF", Serial: "4C1A2B3D", Location: "CPU1 DIMM_A1", Size: "32 GiB"},
		}},
		Coverage: []model.Coverage{
			{ID: "memory.edac", Component: model.CompMemory, Name: model.T("ECC error counters", "Bộ đếm lỗi ECC"), State: model.CovRan},
			{ID: "memory.dmi", Component: model.CompMemory, Name: model.T("DIMM inventory", "Danh sách thanh RAM"), State: model.CovSkipped, Reason: model.T("Needs root.", "Cần quyền root."), Fix: model.T("Run it as root: sudo diagward", "Chạy với quyền root: sudo diagward")},
		},
	}
	ipmi := model.Result{
		Domain: "ipmi",
		Findings: []model.Finding{
			{ID: "ipmi.psu_failed", Component: model.CompPower, Severity: model.Crit, Target: "PSU2",
				Title:  model.T("Power supply PSU2 has failed (AC input lost)", "Bộ nguồn PSU2 bị hỏng (mất điện đầu vào)"),
				Action: model.T("Check the power cord and PDU of PSU2; if power is present, replace PSU2.", "Kiểm tra dây nguồn và PDU cấp cho PSU2; nếu vẫn có điện thì thay PSU2."),
				Part:   &model.Part{Kind: "psu", Vendor: "Dell", Model: "0PJMDN 750W", Location: "PSU2"}},
			{ID: "ipmi.fan_ok", Component: model.CompFan, Severity: model.OK, Title: model.T("6 fans spinning normally", "6 quạt quay bình thường")},
			{ID: "ipmi.temp_ok", Component: model.CompThermal, Severity: model.OK, Title: model.T("All temperatures below warning thresholds", "Mọi nhiệt độ đều dưới ngưỡng cảnh báo")},
			{ID: "ipmi.sel_info", Component: model.CompBMC, Severity: model.Info, Title: model.T("SEL is 71% full", "SEL đã đầy 71%"),
				Detail: model.T("Old events may be dropped soon.", "Sự kiện cũ có thể sớm bị ghi đè.")},
		},
		Coverage: []model.Coverage{
			{ID: "ipmi.sdr", Component: model.CompBMC, Name: model.T("IPMI sensors", "Cảm biến IPMI"), State: model.CovRan},
			{ID: "ipmi.fru", Component: model.CompBMC, Name: model.T("FRU inventory", "Thông tin FRU"), State: model.CovFailed,
				Reason: model.T("ipmitool fru timed out: "+evil, "ipmitool fru bị quá thời gian: "+evil)},
		},
	}
	sensors := model.Result{
		Domain: "sensors",
		Coverage: []model.Coverage{
			lmSensorsCov(),
			{ID: "sensors.dmi", Component: model.CompThermal, Name: model.T("hwmon", "hwmon"), State: model.CovSkipped, Reason: model.T("Needs root.", "Cần quyền root."), Fix: model.T("Run it as root: sudo diagward", "Chạy với quyền root: sudo diagward")},
		},
	}
	logs := model.Result{
		Domain: "logs",
		Findings: []model.Finding{{
			ID: "logs.reboots", Component: model.CompLogs, Severity: model.Warn, Target: "kernel",
			Title:  model.T("3 unexpected reboots in 7 days", "3 lần khởi động lại bất thường trong 7 ngày"),
			Detail: model.T("ログ: 予期しない再起動 — 服务器意外重启 🔥 (unicode test)", "ログ: 予期しない再起動 — 服务器意外重启 🔥 (kiểm thử unicode)"),
			Action: model.T("Check the BMC event log around each reboot time for power or thermal events.", "Xem nhật ký sự kiện BMC quanh các thời điểm khởi động lại để tìm sự cố nguồn hoặc nhiệt độ."),
		}},
		Coverage: []model.Coverage{{ID: "logs.journal", Component: model.CompLogs, Name: model.T("Kernel log", "Nhật ký kernel"), State: model.CovRan}},
	}
	results := []model.Result{disk, raid, mem, ipmi, sensors, logs}
	rep := &model.Report{
		Tool: "diagward", Version: "0.1.0-test",
		Host: model.HostInfo{
			Hostname: "srv-db01.khachhang.vn", OS: "AlmaLinux 9.4 (Seafoam Ocelot)", Kernel: "5.14.0-427.13.1.el9_4.x86_64", Arch: "x86_64",
			Vendor: "Dell Inc.", Model: "PowerEdge R740", Serial: "7XK9Q73", BIOS: "2.12.2 (2021-07-09)", Board: "0YWR7D",
			CPU: "2 × Intel Xeon Silver 4214 (24 cores, 48 threads)", MemBytes: 192 << 30, Uptime: 12*86400 + 3*3600 + 120,
			BMC: "iDRAC9 4.40.00.00",
		},
		Env:       model.Env{OS: "linux", Root: false, Distro: "almalinux", DistroVer: "9.4", PM: "dnf", SinceDays: 7},
		Collected: time.Date(2026, 10, 1, 16, 0, 20, 0, loc),
		Seconds:   23.4,
		Results:   results,
		Notes: []model.Text{
			model.T("Diagward ran without root, so some checks were skipped. Run it again with sudo for a complete report.", "Diagward chạy không có quyền root nên một số mục đã bị bỏ qua. Hãy chạy lại bằng sudo để có báo cáo đầy đủ."),
		},
	}
	for _, res := range results {
		rep.Findings = append(rep.Findings, res.Findings...)
		rep.Coverage = append(rep.Coverage, res.Coverage...)
	}
	sortFindings(rep)
	rep.Summary = summarize(rep)
	for _, f := range rep.Findings {
		rep.Verdict = model.Worst(rep.Verdict, f.Severity)
	}
	return rep
}

// sortFindings and summarize mirror diag.Analyze (not imported: diag pulls
// in every check package).
func sortFindings(rep *model.Report) {
	order := map[string]int{}
	for i, c := range model.Components {
		order[c] = i
	}
	fs := rep.Findings
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0; j-- {
			a, b := fs[j-1], fs[j]
			less := b.Severity > a.Severity || (b.Severity == a.Severity && order[b.Component] < order[a.Component])
			if !less {
				break
			}
			fs[j-1], fs[j] = fs[j], fs[j-1]
		}
	}
}

func summarize(rep *model.Report) []model.ComponentSummary {
	var out []model.ComponentSummary
	idx := map[string]int{}
	for i, c := range model.Components {
		out = append(out, model.ComponentSummary{Component: c, Name: model.ComponentName(c)})
		idx[c] = i
	}
	for _, c := range rep.Coverage {
		if i, ok := idx[c.Component]; ok && (c.State == model.CovRan || c.State == model.CovPartial) {
			out[i].Checked = true
			out[i].Partial = out[i].Partial || c.State == model.CovPartial
		}
	}
	for _, c := range rep.Coverage {
		if i, ok := idx[c.Component]; ok && out[i].Checked && (c.State == model.CovFailed || (c.State == model.CovSkipped && c.ID != "disk.bench" && c.ID != "memory.memtest")) {
			out[i].Partial = true
		}
	}
	for _, f := range rep.Findings {
		i, ok := idx[f.Component]
		if !ok {
			continue
		}
		s := &out[i]
		s.Checked = true
		s.Severity = model.Worst(s.Severity, f.Severity)
		switch f.Severity {
		case model.Crit:
			s.Crit++
		case model.Warn:
			s.Warn++
		case model.Info:
			s.Info++
		}
	}
	return out
}

// lmSensorsCov is a coverage entry in the current contract: Fix explains,
// Cmd is the command to copy (hint.InstallFix).
func lmSensorsCov() model.Coverage {
	fix, cmd := hint.InstallFix(model.Env{OS: "linux", Distro: "almalinux", PM: "dnf"}, "sensors")
	return model.Coverage{ID: "sensors.lm", Component: model.CompThermal, Name: model.T("lm-sensors", "lm-sensors"), State: model.CovSkipped,
		Reason: hint.Missing("sensors"), Fix: fix, Cmd: cmd}
}

func okReport() *model.Report {
	r := &model.Report{
		Tool: "diagward", Version: "0.1.0-test",
		Host:      model.HostInfo{Hostname: "pve-node2", OS: "Proxmox VE 8.2", Vendor: "Supermicro", Model: "SYS-1029P-WTR", Serial: "S123456X"},
		Env:       model.Env{OS: "linux", Root: true, Distro: "debian", PM: "apt"},
		Collected: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
		Findings: []model.Finding{
			{ID: "disk.smart_ok", Component: model.CompDisk, Title: model.T("2 disks passed S.M.A.R.T.", "2 ổ cứng đạt kiểm tra S.M.A.R.T.")},
			{ID: "system.old_bios", Component: model.CompSystem, Severity: model.Info, Title: model.T("BIOS is 4 years old", "BIOS đã 4 năm chưa cập nhật")},
		},
		Coverage: []model.Coverage{{ID: "disk.smart", Component: model.CompDisk, Name: model.T("S.M.A.R.T.", "S.M.A.R.T."), State: model.CovRan}},
	}
	r.Summary = summarize(r)
	r.Verdict = model.Info
	return r
}

func TestRichReportIsValid(t *testing.T) {
	for _, res := range richReport().Results {
		testkit.Validate(t, res)
	}
}

func render(t *testing.T, kind string, r *model.Report, o Options) string {
	t.Helper()
	var b bytes.Buffer
	var err error
	switch kind {
	case "text":
		err = Text(&b, r, o)
	case "html":
		err = HTML(&b, r, o)
	case "md":
		err = Markdown(&b, r, o)
	case "json":
		err = JSON(&b, r)
	}
	if err != nil {
		t.Fatalf("%s: %v", kind, err)
	}
	if !utf8.Valid(b.Bytes()) {
		t.Errorf("%s: output is not valid UTF-8", kind)
	}
	return b.String()
}

var allKinds = []string{"text", "html", "md", "json"}

func TestEmptyAndNil(t *testing.T) {
	reports := map[string]*model.Report{
		"nil":   nil,
		"empty": {},
		"odd": {
			Verdict:  model.Severity(9),
			Summary:  []model.ComponentSummary{{Component: "weird", Checked: true, Severity: model.Severity(-3)}},
			Findings: []model.Finding{{Severity: model.Severity(7)}, {Severity: model.Warn, Part: &model.Part{}}, {Severity: model.Crit, Part: &model.Part{}}},
			Coverage: []model.Coverage{{State: "bogus"}, {}},
			Results:  []model.Result{{Tables: []model.Table{{}, {Columns: []model.Text{{}}, Rows: []model.Row{{}, {Cells: []string{"a", "b", "c"}}}}}}},
			Notes:    []model.Text{{}},
			Seconds:  -1, Host: model.HostInfo{Uptime: 1e300},
		},
	}
	for name, r := range reports {
		for _, k := range allKinds {
			for _, o := range []Options{{}, {Lang: "vi", Color: true, Verbose: true}, {ASCII: true, Width: 1, Verbose: true}} {
				out := render(t, k, r, o)
				if out == "" {
					t.Errorf("%s/%s: empty output", name, k)
				}
			}
		}
	}
	out := render(t, "text", &model.Report{}, Options{Lang: "vi"})
	if !strings.Contains(out, "CHƯA ĐỦ DỮ LIỆU") {
		t.Errorf("empty report should say there is not enough data:\n%s", out)
	}
}

// garbage turns strings into hostile input: truncated UTF-8, controls,
// very long tokens.
func TestGarbageStrings(t *testing.T) {
	r := richReport()
	junk := []string{"\xff\xfe\xfd", strings.Repeat("A", 5000), "\x00\x01\x1b]0;pwned\a", "tiếng\u0301 việt\u0300 decomposed", "\u202eevil-bidi", strings.Repeat("服", 300)}
	for i := range r.Findings {
		f := &r.Findings[i]
		j := junk[i%len(junk)]
		f.Target = j
		f.Title.VI += j
		f.Detail.EN += j
		f.Evidence = append(f.Evidence, j)
	}
	r.Host.Hostname = junk[0] + junk[2]
	for _, k := range allKinds {
		for _, w := range []int{24, 40, 80} {
			out := render(t, k, r, Options{Width: w, Verbose: true, Lang: "vi"})
			if k == "text" || k == "md" {
				if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0) || strings.ContainsRune(out, '\a') {
					t.Errorf("%s: control characters leaked", k)
				}
				if strings.ContainsRune(out, '\u202e') {
					t.Errorf("%s: bidi override leaked", k)
				}
			}
			if k == "text" {
				checkWidth(t, out, w)
			}
		}
	}
}

func checkWidth(t *testing.T, out string, w int) {
	t.Helper()
	for i, l := range strings.Split(out, "\n") {
		l = ansiRE.ReplaceAllString(l, "")
		if n := strWidth(l); n > w {
			t.Errorf("line %d is %d cells wide (max %d): %q", i+1, n, w, l)
		}
	}
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestTextWidth(t *testing.T) {
	r := richReport()
	for _, w := range []int{24, 32, 40, 60, 80, 100, 132} {
		for _, lang := range []string{"vi", "en"} {
			for _, o := range []Options{
				{Lang: lang, Width: w},
				{Lang: lang, Width: w, Verbose: true, Color: true},
				{Lang: lang, Width: w, Verbose: true, ASCII: true},
			} {
				checkWidth(t, render(t, "text", r, o), w)
			}
		}
	}
	// Width 0 means 100.
	checkWidth(t, render(t, "text", r, Options{Verbose: true}), 100)
	// Widths below the minimum are raised to it, never ignored.
	checkWidth(t, render(t, "text", r, Options{Width: 5, Verbose: true}), minWidth)
}

func TestTextASCII(t *testing.T) {
	r := richReport()
	out := render(t, "text", r, Options{Lang: "en", ASCII: true, Verbose: true, Width: 80})
	for _, bad := range []string{"✓", "✗", "⚠", "–", "╭", "─", "│", "→", "•", "◐", "…"} {
		if strings.Contains(out, bad) {
			t.Errorf("ASCII output contains %q", bad)
		}
	}
	// Only report content (hostnames, Vietnamese words, CJK from the
	// machine) may be non-ASCII; the renderer's own glyphs must not be.
	for _, want := range []string{"[CRIT]", "[WARN]", "[OK]", "[--]", "+---", "| "} {
		if !strings.Contains(out, want) {
			t.Errorf("ASCII output lacks %q", want)
		}
	}
	// An English ASCII report of an all-ASCII machine is pure ASCII.
	plain := &model.Report{
		Host:     model.HostInfo{Hostname: "srv"},
		Env:      model.Env{OS: "linux", Root: true},
		Findings: []model.Finding{{ID: "disk.x", Component: model.CompDisk, Severity: model.Warn, Title: model.T("Disk warm", "Ổ nóng"), Action: model.T("Check fans", "Kiểm tra quạt")}},
		Coverage: []model.Coverage{{ID: "disk.smart", Component: model.CompDisk, Name: model.T("SMART", "SMART"), State: model.CovSkipped, Reason: model.T("smartctl is not installed.", "Chưa cài smartctl."), Fix: model.T("Install it: apt-get install -y smartmontools", "Cài đặt: apt-get install -y smartmontools")}},
	}
	plain.Summary = summarize(plain)
	plain.Verdict = model.Warn
	out = render(t, "text", plain, Options{Lang: "en", ASCII: true, Verbose: true})
	for i, r := range out {
		if r > 0x7e || (r < 0x20 && r != '\n') {
			t.Fatalf("non-ASCII rune %q at %d in ASCII output:\n%s", r, i, out)
		}
	}
}

func TestTextColor(t *testing.T) {
	r := richReport()
	if out := render(t, "text", r, Options{Verbose: true}); strings.ContainsRune(out, 0x1b) {
		t.Error("escape codes without Color")
	}
	out := render(t, "text", r, Options{Color: true})
	if !strings.Contains(out, "\x1b[1;31m") || !strings.Contains(out, "\x1b[0m") {
		t.Error("Color output lacks ANSI codes")
	}
}

func TestTextContent(t *testing.T) {
	r := richReport()
	vi := render(t, "text", r, Options{Lang: "vi", Width: 100})
	for _, want := range []string{
		"CẦN XỬ LÝ NGAY", "srv-db01.khachhang.vn", "PowerEdge R740", "7XK9Q73",
		"Ổ /dev/sda sắp hỏng", "Sao lưu dữ liệu ngay", "LINH KIỆN CẦN THAY", "ZC1234AB", "4C1A2B3D",
		"CHƯA KIỂM TRA ĐẦY ĐỦ", "dnf install -y nvme-cli", "ĐÃ KIỂM TRA, ỔN", "6 quạt quay bình thường",
		"GHI CHÚ", "--html report.html", "--lang en",
	} {
		if !strings.Contains(vi, want) {
			t.Errorf("vi text lacks %q", want)
		}
	}
	// The fix command is on a line of its own, verbatim (copy-paste).
	if !regexp.MustCompile(`(?m)^\s+dnf install -y nvme-cli$`).MatchString(vi) {
		t.Errorf("fix command not on its own line:\n%s", vi)
	}
	// "Needs root" checks are grouped.
	if strings.Count(vi, "Chạy với quyền root") != 1 {
		t.Errorf("identical fixes should be grouped once")
	}
	// The same disk appears once in the parts list, with both reasons.
	if strings.Count(vi, "Serial: ZC1234AB") != 1 {
		t.Errorf("duplicate part rows:\n%s", vi)
	}
	en := render(t, "text", r, Options{Lang: "en", Width: 100})
	for _, want := range []string{"ACTION NEEDED NOW", "Disk /dev/sda is failing", "PARTS TO REPLACE", "NOT FULLY CHECKED", "--lang vi"} {
		if !strings.Contains(en, want) {
			t.Errorf("en text lacks %q", want)
		}
	}
	if strings.Contains(en, "Sao lưu") {
		t.Error("en text contains Vietnamese action")
	}
	// Evidence only when verbose.
	if strings.Contains(vi, "Current_Pending_Sector  0x0012") {
		t.Error("evidence shown without Verbose")
	}
	v := render(t, "text", r, Options{Lang: "en", Verbose: true, Width: 160})
	for _, want := range []string{"Current_Pending_Sector  0x0012", "INVENTORY AND MEASUREMENTS", "WD-WCC7K1234567", "CHECKED (", "CPU", "192 GiB"} {
		if !strings.Contains(v, want) {
			t.Errorf("verbose text lacks %q", want)
		}
	}
	ok := render(t, "text", okReport(), Options{Lang: "vi"})
	if !strings.Contains(ok, "KHÔNG PHÁT HIỆN LỖI PHẦN CỨNG") {
		t.Errorf("ok report verdict:\n%s", ok)
	}
	if w := render(t, "text", okReport(), Options{Lang: "en"}); !strings.Contains(w, "NO HARDWARE PROBLEMS FOUND") {
		t.Errorf("ok report verdict (en):\n%s", w)
	}
}

func TestWrapVietnamese(t *testing.T) {
	s := "Sao lưu dữ liệu ngay. Thay ổ /dev/sda (serial ZA1234). Nếu ổ nằm trong RAID, kiểm tra RAID đã rebuild xong trước khi rút ổ."
	for _, w := range []int{10, 20, 33} {
		lines := wrap(s, w)
		for _, l := range lines {
			if strWidth(l) > w {
				t.Errorf("w=%d: %q is %d wide", w, l, strWidth(l))
			}
		}
		if strings.Join(lines, " ") != s {
			t.Errorf("w=%d: wrap lost words: %q", w, lines)
		}
	}
	if strWidth("Ổ cứng sắp hỏng") != 15 {
		t.Errorf("precomposed Vietnamese must be single width, got %d", strWidth("Ổ cứng sắp hỏng"))
	}
	if strWidth("O\u0302\u0309") != 1 {
		t.Error("combining marks must be zero width")
	}
	if strWidth("服务器") != 6 {
		t.Error("CJK must be double width")
	}
	for _, l := range wrap(strings.Repeat("服", 15), 7) {
		if strWidth(l) > 7 {
			t.Errorf("CJK hard break too wide: %q", l)
		}
	}
}

func TestSplitFix(t *testing.T) {
	cases := []struct{ in, prose, cmd string }{
		{"Install it: dnf install -y smartmontools", "Install it:", "dnf install -y smartmontools"},
		{"Cài đặt: sudo apt-get install -y lm-sensors", "Cài đặt:", "sudo apt-get install -y lm-sensors"},
		{"Bật kho EPEL rồi cài: dnf install -y epel-release && dnf install -y memtester", "Bật kho EPEL rồi cài:", "dnf install -y epel-release && dnf install -y memtester"},
		{"Run it as root: sudo diagward", "Run it as root:", "sudo diagward"},
		{"Install smartmontools for Windows (https://www.smartmontools.org/wiki/Download) and run Diagward again.", "Install smartmontools for Windows (https://www.smartmontools.org/wiki/Download) and run Diagward again.", ""},
		{"Note: sudo is needed.", "Note: sudo is needed.", ""},
		{"Run: Get-PhysicalDisk | Get-StorageReliabilityCounter", "Run:", "Get-PhysicalDisk | Get-StorageReliabilityCounter"},
		{"", "", ""},
	}
	for _, c := range cases {
		p, cmd := splitFix(c.in)
		if p != c.prose || cmd != c.cmd {
			t.Errorf("splitFix(%q) = %q, %q; want %q, %q", c.in, p, cmd, c.prose, c.cmd)
		}
	}
	lines := cmdLines("dnf install -y epel-release && dnf install -y memtester edac-utils rasdaemon", 30, " \\")
	for _, l := range lines {
		if strWidth(l) > 30 {
			t.Errorf("cmd line too wide: %q", l)
		}
	}
	if len(lines) < 2 || !strings.HasSuffix(lines[0], " \\") {
		t.Errorf("long command should be split with continuations: %q", lines)
	}
}

func TestParts(t *testing.T) {
	parts := Parts(richReport())
	if len(parts) != 3 {
		t.Fatalf("want 3 parts (disk merged, dimm, psu), got %d: %+v", len(parts), parts)
	}
	if parts[0].Serial != "ZC1234AB" || len(parts[0].IDs) != 2 || !strings.Contains(parts[0].Why.VI, "; ") {
		t.Errorf("disk part not merged: %+v", parts[0])
	}
	// crit first: disk, psu, then the warn dimm
	if parts[1].Kind.EN != "Power supply (PSU)" || parts[2].Kind.EN != "Memory module (DIMM)" {
		t.Errorf("order: %v, %v", parts[1].Kind, parts[2].Kind)
	}
	rma := RMAText(richReport(), "vi")
	for _, want := range []string{"7XK9Q73", "ZC1234AB", "Thanh RAM", "CPU1 DIMM_A1", "Bộ nguồn (PSU)"} {
		if !strings.Contains(rma, want) {
			t.Errorf("RMA text lacks %q:\n%s", want, rma)
		}
	}
	if RMAText(okReport(), "en") != "" || Parts(nil) != nil {
		t.Error("no parts expected")
	}
}

func TestHTMLEscaping(t *testing.T) {
	out := render(t, "html", richReport(), Options{Lang: "vi", Verbose: true})
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img") || strings.Contains(out, `" onmouseover="`) {
		t.Fatal("untrusted string was not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Error("escaped evidence not found")
	}
	if strings.Count(out, "<script>") != 2 { // theme bootstrap + app script, both ours
		t.Errorf("want exactly 2 inline scripts, got %d", strings.Count(out, "<script>"))
	}
	// No control characters (invalid in HTML).
	if strings.ContainsAny(out, "\x1b\x00\a") {
		t.Error("control characters in HTML")
	}
}

var urlRE = regexp.MustCompile(`(?i)(?:src|href|action|poster|data)\s*=\s*["']?\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//|@import`)

func TestHTMLSelfContained(t *testing.T) {
	out := render(t, "html", richReport(), Options{Lang: "en"})
	for _, m := range urlRE.FindAllStringIndex(out, -1) {
		ctx := out[m[0]:min(len(out), m[1]+60)]
		if !strings.Contains(ctx, RepoURL) {
			t.Errorf("external reference: %q", ctx)
		}
	}
	for _, bad := range []string{"<link", "<iframe", "<img", "fonts.googleapis", "@font-face"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	if !strings.Contains(out, `href="`+RepoURL+`"`) {
		t.Error("repo link missing")
	}
}

func TestHTMLBalanced(t *testing.T) {
	for _, r := range []*model.Report{richReport(), okReport(), {}} {
		for _, lang := range []string{"vi", "en"} {
			out := render(t, "html", r, Options{Lang: lang})
			if err := balanced(out); err != nil {
				t.Errorf("lang=%s: %v", lang, err)
			}
		}
	}
}

// balanced checks that elements are properly nested (void elements aside),
// a cheap stand-in for an HTML validator.
func balanced(s string) error {
	void := map[string]bool{"meta": true, "br": true, "hr": true, "img": true, "input": true, "link": true, "wbr": true, "!doctype": true}
	tagRE := regexp.MustCompile(`<(/?)([a-zA-Z!][a-zA-Z0-9]*)[^>]*>`)
	// Skip script and style bodies.
	s = regexp.MustCompile(`(?s)<script>.*?</script>`).ReplaceAllString(s, "<script></script>")
	s = regexp.MustCompile(`(?s)<style>.*?</style>`).ReplaceAllString(s, "<style></style>")
	var stack []string
	for _, m := range tagRE.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[2])
		if void[name] {
			continue
		}
		if m[1] == "" {
			stack = append(stack, name)
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1] != name {
			return fmt.Errorf("unexpected </%s>, open: %v", name, stack)
		}
		stack = stack[:len(stack)-1]
	}
	if len(stack) != 0 {
		return fmt.Errorf("unclosed: %v", stack)
	}
	return nil
}

func TestHTMLBothLanguages(t *testing.T) {
	r := richReport()
	for _, lang := range []string{"vi", "en"} {
		out := render(t, "html", r, Options{Lang: lang})
		for _, want := range []string{
			`data-lang="` + lang + `"`,
			`<span lang="vi">CẦN XỬ LÝ NGAY</span><span lang="en">ACTION NEEDED NOW</span>`,
			"Sao lưu dữ liệu ngay", "Back up the data now",
			`id="rma-vi"`, `id="rma-en"`, "dnf install -y nvme-cli", "data-copy-cmd", "data-copy-rma",
			"prefers-color-scheme:dark", "@media print", "#FAF9F5", "#C96442",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("lang=%s: html lacks %q", lang, want)
			}
		}
	}
}

func TestHTMLSize(t *testing.T) {
	r := richReport()
	base := r.Findings
	for i := 0; i < 4; i++ {
		r.Findings = append(r.Findings, base...)
	}
	tb := r.Results[0].Tables[0]
	for len(tb.Rows) < 40 {
		tb.Rows = append(tb.Rows, tb.Rows[:3]...)
	}
	for i := 0; i < 10; i++ {
		r.Results = append(r.Results, model.Result{Domain: "x", Tables: []model.Table{tb}})
	}
	out := render(t, "html", r, Options{Lang: "vi"})
	t.Logf("large report: %d findings, %d bytes", len(r.Findings), len(out))
	// ~200 KB target; this fixture is extreme (440 table rows, a third of
	// them full of escaped HTML), so allow some headroom.
	if len(out) > 240_000 {
		t.Errorf("HTML for a large report is %d bytes", len(out))
	}
	small := render(t, "html", richReport(), Options{})
	if len(small) > 80_000 {
		t.Errorf("HTML for a normal report is %d bytes", len(small))
	}
}

func TestMarkdown(t *testing.T) {
	r := richReport()
	out := render(t, "md", r, Options{Lang: "vi", Verbose: true})
	// No HTML outside code spans: every "<" in text is escaped.
	noCode := regexp.MustCompile("(`+)[^`]*?(`+)").ReplaceAllString(out, "")
	if regexp.MustCompile(`(^|[^\\])<[a-zA-Z/!]`).MatchString(noCode) {
		t.Errorf("Markdown contains raw HTML:\n%s", noCode)
	}
	if strings.Contains(out, "|---") || strings.Contains(out, "<br") {
		t.Error("Markdown should have no tables or HTML")
	}
	for _, want := range []string{"**Diagward · srv-db01.khachhang.vn**", "### 🔴 CẦN XỬ LÝ NGAY", "Sao lưu dữ liệu ngay", "`ZC1234AB`", "`dnf install -y nvme-cli`", "Linh kiện cần thay", "Chưa kiểm tra đầy đủ", RepoURL} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	en := render(t, "md", r, Options{Lang: "en"})
	if !strings.Contains(en, "ACTION NEEDED NOW") || strings.Contains(en, "Sao lưu") {
		t.Error("en markdown language")
	}
	if got := mdCode("a`b"); got != "`` a`b ``" {
		t.Errorf("mdCode backtick: %q", got)
	}
	for in, want := range map[string]string{
		"*bold* <x> [l](u)":             `\*bold\* \<x> \[l\](u)`,
		"Current_Pending_Sector _it_":   `Current_Pending_Sector \_it\_`,
		"temp > 80 °C, [_U] ~~strike~~": `temp > 80 °C, \[\_U] \~\~strike\~\~`,
	} {
		if got := mdEsc(in); got != want {
			t.Errorf("mdEsc(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJSONStable(t *testing.T) {
	r := richReport()
	a, b := render(t, "json", r, Options{}), render(t, "json", r, Options{})
	if a != b {
		t.Error("JSON not stable")
	}
	var back model.Report
	if err := json.Unmarshal([]byte(a), &back); err != nil {
		t.Fatal(err)
	}
	if back.Verdict != model.Crit || len(back.Findings) != len(r.Findings) {
		t.Error("JSON round trip lost data")
	}
	if !strings.HasPrefix(a, "{\n  \"tool\": \"diagward\",\n  \"version\"") {
		t.Errorf("JSON field order: %.60q", a)
	}
}

func TestTemplateParses(t *testing.T) {
	if _, err := template.New("x").Funcs(template.FuncMap{"L": label}).Parse(htmlSource); err != nil {
		t.Fatal(err)
	}
}

// TestWriteSamples writes previews of each format to testdata/ when run
// with -update (go generate ./report).
func TestWriteSamples(t *testing.T) {
	if !*update {
		t.Skip("run with -update to write testdata/sample.*")
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, fn func(io.Writer) error) {
		var b bytes.Buffer
		if err := fn(&b); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", name), b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := richReport()
	write("sample.html", func(w io.Writer) error { return HTML(w, r, Options{Lang: "vi"}) })
	write("sample-ok.html", func(w io.Writer) error { return HTML(w, okReport(), Options{Lang: "en"}) })
	write("sample-vi.txt", func(w io.Writer) error { return Text(w, r, Options{Lang: "vi", Width: 100}) })
	write("sample-en.txt", func(w io.Writer) error { return Text(w, r, Options{Lang: "en", Width: 100}) })
	write("sample-verbose-en.txt", func(w io.Writer) error { return Text(w, r, Options{Lang: "en", Width: 100, Verbose: true}) })
	write("sample-ascii-80.txt", func(w io.Writer) error { return Text(w, r, Options{Lang: "en", Width: 80, ASCII: true}) })
	write("sample-vi.md", func(w io.Writer) error { return Markdown(w, r, Options{Lang: "vi"}) })
	write("sample.json", func(w io.Writer) error { return JSON(w, r) })
}

// TestRenderReportFile renders a real report (for example the output of
// "go run ./internal/devtools/dwdev -os linux -analyze") in every format
// and checks the same invariants as the synthetic one. Set
// DIAGWARD_REPORT_JSON to its path; outputs go next to it.
func TestRenderReportFile(t *testing.T) {
	path := os.Getenv("DIAGWARD_REPORT_JSON")
	if path == "" {
		t.Skip("set DIAGWARD_REPORT_JSON to a report JSON file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	for _, w := range []int{60, 100} {
		checkWidth(t, render(t, "text", &r, Options{Lang: "vi", Width: w, Verbose: true}), w)
	}
	outs := map[string]string{
		".vi.txt": render(t, "text", &r, Options{Lang: "vi", Width: 100}),
		".en.txt": render(t, "text", &r, Options{Lang: "en", Width: 100, Verbose: true}),
		".html":   render(t, "html", &r, Options{Lang: "vi"}),
		".vi.md":  render(t, "md", &r, Options{Lang: "vi"}),
	}
	if err := balanced(outs[".html"]); err != nil {
		t.Error(err)
	}
	for ext, s := range outs {
		if err := os.WriteFile(base+ext, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMarkdownDetails(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Windows\MEMORY.DMP`: `C:\Windows\MEMORY.DMP`,
		`a\*b`:                  `a\\\*b`,
		`end\`:                  `end\`,
	} {
		if got := mdEsc(in); got != want {
			t.Errorf("mdEsc(%q) = %q, want %q", in, got, want)
		}
	}
	r := richReport()
	for i := 0; i < 3; i++ {
		r.Findings = append(r.Findings, r.Findings...)
	}
	out := render(t, "md", r, Options{Lang: "en"})
	if !strings.Contains(out, "\n10. ") || !strings.Contains(out, "\n    - **What to do:**") {
		t.Errorf("items >= 10 need 4-space sub-bullets")
	}
}

// TestRandomReports renders many reports built from random, often hostile,
// strings and odd shapes: nothing may panic and Text must respect the width.
func TestRandomReports(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	pieces := []string{"", " ", "\n", "\t", "ổ cứng", "服务器", "🔥", "\x1b[2J", "\xff", "<b>", "`", "**", "_", "\\", "a-very-long-token-without-spaces-0123456789abcdef0123456789", ": ", "sudo ", "dnf install -y x", "́", "|", "]("}
	str := func() string {
		var b strings.Builder
		for n := rng.IntN(8); n > 0; n-- {
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		return b.String()
	}
	txt := func() model.Text { return model.Text{EN: str(), VI: str()} }
	comps := append([]string{"", "bogus"}, model.Components...)
	states := []string{model.CovRan, model.CovPartial, model.CovSkipped, model.CovFailed, "", "weird"}
	for i := 0; i < 300; i++ {
		r := &model.Report{Version: str(), Host: model.HostInfo{Hostname: str(), Vendor: str(), Model: str(), Serial: str(), OS: str(), Uptime: rng.Float64() * 1e8}, Seconds: rng.Float64() * 400}
		r.Env.OS = []string{"linux", "windows", "bmc", ""}[rng.IntN(4)]
		r.Env.Virtual = []string{"", "kvm"}[rng.IntN(2)]
		for n := rng.IntN(12); n > 0; n-- {
			f := model.Finding{ID: str(), Component: comps[rng.IntN(len(comps))], Severity: model.Severity(rng.IntN(6) - 1), Target: str(), Title: txt(), Detail: txt(), Action: txt()}
			for k := rng.IntN(4); k > 0; k-- {
				f.Evidence = append(f.Evidence, str())
			}
			if rng.IntN(3) == 0 {
				f.Part = &model.Part{Kind: str(), Vendor: str(), Model: str(), Serial: str(), Location: str()}
			}
			r.Findings = append(r.Findings, f)
		}
		for n := rng.IntN(8); n > 0; n-- {
			r.Coverage = append(r.Coverage, model.Coverage{ID: str(), Component: comps[rng.IntN(len(comps))], Name: txt(), State: states[rng.IntN(len(states))], Reason: txt(), Fix: txt()})
		}
		var tb model.Table
		tb.Title = txt()
		for n := rng.IntN(6); n > 0; n-- {
			tb.Columns = append(tb.Columns, txt())
		}
		for n := rng.IntN(6); n > 0; n-- {
			row := model.Row{Status: model.Severity(rng.IntN(4))}
			for k := rng.IntN(8); k > 0; k-- {
				row.Cells = append(row.Cells, str())
			}
			tb.Rows = append(tb.Rows, row)
		}
		r.Results = []model.Result{{Tables: []model.Table{tb}}}
		r.Notes = []model.Text{txt()}
		r.Summary = summarize(r)
		w := 24 + rng.IntN(120)
		o := Options{Lang: []string{"vi", "en"}[rng.IntN(2)], Width: w, ASCII: rng.IntN(2) == 0, Color: rng.IntN(2) == 0, Verbose: rng.IntN(2) == 0}
		checkWidth(t, render(t, "text", r, o), w)
		render(t, "md", r, o)
		if err := balanced(render(t, "html", r, o)); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
		render(t, "json", r, o)
	}
}

// partialReport: CPU fully checked, memory and thermal only partly (one
// check ran, another needed root), disk partly checked with a warning.
func partialReport() *model.Report {
	env := model.Env{OS: "linux", Distro: "ubuntu", PM: "apt"}
	fix, cmd := hint.InstallFix(env, "smartctl")
	r := &model.Report{
		Host: model.HostInfo{Hostname: "srv-partial"},
		Env:  env,
		Findings: []model.Finding{
			{ID: "disk.crc", Component: model.CompDisk, Severity: model.Warn, Title: model.T("Cable errors on /dev/sdb", "Lỗi cáp trên /dev/sdb")},
			{ID: "memory.info", Component: model.CompMemory, Severity: model.Info, Title: model.T("Mixed DIMMs", "RAM không đồng bộ")},
		},
		Coverage: []model.Coverage{
			{ID: "cpu.mce", Component: model.CompCPU, Name: model.T("Machine checks", "Machine check"), State: model.CovRan},
			{ID: "memory.edac", Component: model.CompMemory, Name: model.T("ECC counters", "Bộ đếm ECC"), State: model.CovRan},
			{ID: "memory.dmi", Component: model.CompMemory, Name: model.T("DIMM inventory", "Danh sách thanh RAM"), State: model.CovSkipped, Reason: hint.NeedRoot(env), Fix: hint.RunAsRoot(env)},
			{ID: "sensors.temperature", Component: model.CompThermal, Name: model.T("Temperatures", "Nhiệt độ"), State: model.CovPartial, Reason: model.T("No ACPI zones.", "Không có vùng nhiệt ACPI.")},
			{ID: "disk.lsblk", Component: model.CompDisk, Name: model.T("Disk list", "Danh sách ổ"), State: model.CovRan},
			{ID: "disk.smart", Component: model.CompDisk, Name: model.T("S.M.A.R.T.", "S.M.A.R.T."), State: model.CovSkipped, Reason: hint.Missing("smartctl"), Fix: fix, Cmd: cmd},
			{ID: "disk.bench", Component: model.CompDisk, Name: model.T("Disk speed test", "Đo tốc độ ổ"), State: model.CovSkipped, Reason: model.T("Not requested.", "Không yêu cầu."),
				Fix: model.T("Run a write/read test in a directory on the disk.", "Chạy bài đo ghi/đọc trong một thư mục trên ổ."), Cmd: "sudo diagward check --bench /var/tmp --bench-size 1G"},
		},
	}
	r.Summary = summarize(r)
	r.Verdict = model.Warn
	return r
}

func TestPartialComponents(t *testing.T) {
	r := partialReport()
	byComp := map[string]model.ComponentSummary{}
	for _, s := range r.Summary {
		byComp[s.Component] = s
	}
	if !byComp[model.CompMemory].Partial || !byComp[model.CompThermal].Partial || byComp[model.CompCPU].Partial || !byComp[model.CompDisk].Partial {
		t.Fatalf("fixture summary: %+v", r.Summary)
	}
	vi := render(t, "text", r, Options{Lang: "vi", Width: 100})
	for _, want := range []string{"◐ Bộ nhớ (RAM)", "◐ Nhiệt độ", "✓ CPU", "⚠ Ổ cứng (1)", "◐ kiểm tra một phần", "(3 nhóm chỉ một phần)"} {
		if !strings.Contains(vi, want) {
			t.Errorf("vi text lacks %q:\n%s", want, vi)
		}
	}
	if a := render(t, "text", r, Options{Lang: "en", ASCII: true}); !strings.Contains(a, "[PART] Memory (RAM)") || !strings.Contains(a, "(3 only partly)") {
		t.Errorf("ascii text lacks partial mark:\n%s", a)
	}
	// A report without partial components has no partial legend.
	if ok := render(t, "text", okReport(), Options{Lang: "en"}); strings.Contains(ok, "partly checked") {
		t.Errorf("legend shows partial without partial components:\n%s", ok)
	}
	h := render(t, "html", r, Options{Lang: "vi"})
	for _, want := range []string{
		`<li class="tile c-part"><a href="#coverage"><span class="badge" aria-hidden="true">◐</span>`,
		`<span class="tpart">&#9680; <span lang="vi">kiểm tra một phần</span>`, // the warn disk tile is partial too
		`<li class="tile c-ok"><div><span class="badge" aria-hidden="true">✓</span><span class="tname">CPU</span>`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	if n := strings.Count(h, `class="tile c-part"`); n != 2 {
		t.Errorf("want 2 partial tiles (memory, thermal), got %d", n)
	}
}

func TestCoverageCmd(t *testing.T) {
	r := partialReport()
	vi := render(t, "text", r, Options{Lang: "vi", Width: 100})
	// Fix stays prose; Cmd is on its own line, verbatim.
	for _, re := range []string{
		`(?m)^\s+Cài smartmontools rồi chạy lại Diagward\.$`,
		`(?m)^\s+sudo apt-get install -y --no-install-recommends smartmontools$`,
		`(?m)^\s+sudo diagward check --bench /var/tmp --bench-size 1G$`,
	} {
		if !regexp.MustCompile(re).MatchString(vi) {
			t.Errorf("text lacks %s:\n%s", re, vi)
		}
	}
	// Narrow terminals split a long Cmd with continuations.
	narrow := render(t, "text", r, Options{Lang: "en", Width: 40})
	if !regexp.MustCompile(`(?m) \\$`).MatchString(narrow) {
		t.Errorf("long Cmd not split with continuations:\n%s", narrow)
	}
	md := render(t, "md", r, Options{Lang: "en"})
	if !strings.Contains(md, "  - Install smartmontools, then run Diagward again. `sudo apt-get install -y --no-install-recommends smartmontools`") {
		t.Errorf("markdown Cmd:\n%s", md)
	}
	h := render(t, "html", r, Options{Lang: "en"})
	for _, want := range []string{
		`<span class="fprose">Install smartmontools, then run Diagward again.</span><div class="cmd"><code>sudo apt-get install -y --no-install-recommends smartmontools</code>`,
		`<code>sudo diagward check --bench /var/tmp --bench-size 1G</code>`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	// A Fix with an embedded command and no Cmd is still split (older bundles).
	old := render(t, "html", richReport(), Options{Lang: "en"})
	if !strings.Contains(old, `<span class="fprose">Install it:</span><div class="cmd"><code>dnf install -y nvme-cli</code>`) {
		t.Error("splitFix fallback lost")
	}
	// A Cmd with HTML in it is escaped.
	r.Coverage[len(r.Coverage)-1].Cmd = evil
	h = render(t, "html", r, Options{Lang: "en"})
	if strings.Contains(h, "<script>alert") || strings.Contains(h, "<img") {
		t.Error("Cmd not escaped")
	}
	if strings.ContainsRune(render(t, "text", r, Options{}), 0x1b) {
		t.Error("escape in text")
	}
}

func TestNoHints(t *testing.T) {
	r := richReport()
	with := render(t, "text", r, Options{Lang: "en"})
	without := render(t, "text", r, Options{Lang: "en", NoHints: true})
	for _, h := range []string{"--html report.html", "--lang vi", "add -v"} {
		if !strings.Contains(with, h) {
			t.Errorf("hints missing by default: %q", h)
		}
		if strings.Contains(without, h) {
			t.Errorf("NoHints still shows %q", h)
		}
	}
	if !strings.Contains(without, RepoURL) {
		t.Error("NoHints must keep the version/repo line")
	}
}

// A healthy VM or container must not get the green "no hardware problems"
// banner: its hardware belongs to the host and was not checked.
func TestGuestHeadline(t *testing.T) {
	r := okReport()
	r.Env.Virtual = "kvm"
	if h := Headline(r); h.EN != "NO PROBLEMS FOUND IN THIS VIRTUAL MACHINE" || h.VI != "KHÔNG PHÁT HIỆN LỖI TRONG MÁY ẢO NÀY" {
		t.Errorf("vm headline: %+v", h)
	}
	if s := headlineSeverity(r); s != model.Info {
		t.Errorf("vm banner severity %v, want info", s)
	}
	out := render(t, "text", r, Options{Lang: "en", ASCII: true})
	if !strings.Contains(out, "[INFO]  NO PROBLEMS FOUND IN THIS VIRTUAL MACHINE") {
		t.Errorf("vm banner:\n%s", out)
	}
	if h := render(t, "html", r, Options{Lang: "en"}); !strings.Contains(h, `<div class="verdict c-info" role="status">`) {
		t.Error("vm html banner should be info")
	}
	r.Env.Container, r.Env.Virtual = true, "wsl"
	if h := Headline(r); h.EN != "NO PROBLEMS FOUND IN THIS CONTAINER" {
		t.Errorf("container headline: %+v", h)
	}
	// Problems found inside a VM are still reported as such.
	r.Verdict = model.Warn
	if h := Headline(r); h.EN != "NEEDS ATTENTION" {
		t.Errorf("vm with warnings: %+v", h)
	}
	// A BMC bundle is out-of-band hardware data, never "virtual".
	b := okReport()
	b.Env = model.Env{OS: "bmc"}
	if h := Headline(b); h.EN != "NO HARDWARE PROBLEMS FOUND" {
		t.Errorf("bmc headline: %+v", h)
	}
}

// TestHTMLNarrow guards the rules that keep the page inside a 360 px phone
// screen: long unbroken tokens (stop codes, serials, paths) in flex/grid
// items must be allowed to break, tiles go to two columns, and tables keep
// their natural width inside their own scroll box.
func TestHTMLNarrow(t *testing.T) {
	out := render(t, "html", richReport(), Options{Lang: "vi"})
	for _, want := range []string{
		`<meta name="viewport" content="width=device-width, initial-scale=1">`,
		".todo-t{font-weight:600;color:var(--text);text-decoration:none;overflow-wrap:anywhere}",
		".tile>a,.tile>div{display:grid;grid-template-columns:auto minmax(0,1fr)",
		".tiles{grid-template-columns:repeat(2,minmax(0,1fr))",
		".tablewrap{overflow-x:auto",
		"table.data{width:max-content;min-width:100%}",
		".brand .sub{flex-basis:100%",
		".cmd code{flex:1;min-width:0;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html lacks %q", want)
		}
	}
}
