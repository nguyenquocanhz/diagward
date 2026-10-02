package raid

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// raidWords is Vietnamese for the states the RAID tools print, as they
// appear in the tables: mdstat/sysfs, ZFS, LVM, Btrfs, MegaCLI/StorCLI
// (including StorCLI's abbreviations), ssacli, arcconf and Storage Spaces.
// RAID terms (rebuild, hot spare, resilver, scrub, stripe, copyback, JBOD)
// stay in English, as Vietnamese admins say them.
var raidWords = map[string]string{
	// md, LVM, Btrfs
	"active":         "đang chạy",
	"inactive":       "không chạy",
	"auto-read-only": "tự chuyển chỉ đọc",
	"missing device": "thiếu thiết bị",
	"partial":        "thiếu một phần",
	"refresh needed": "cần refresh",
	"mismatches":     "lệch dữ liệu",
	"check":          "kiểm tra",
	"repair":         "sửa",
	"recovery":       "phục hồi",
	"recover":        "phục hồi",
	"resync":         "đồng bộ lại",
	"reshape":        "đổi cấu trúc (reshape)",
	"sync":           "đồng bộ",
	"resync=delayed": "chờ đồng bộ lại (delayed)",
	"resync=pending": "chờ đồng bộ lại (pending)",
	"eta":            "còn",
	// ZFS
	"faulted":   "lỗi (faulted)",
	"unavail":   "không truy cập được",
	"removed":   "đã rút",
	"suspended": "tạm dừng (suspended)",
	"used":      "đã dùng",
	// hardware controllers: volumes
	"optl":                       "bình thường",
	"dgrd":                       "suy giảm",
	"pdgd":                       "suy giảm một phần",
	"partially degraded":         "suy giảm một phần",
	"ofln":                       "ngừng hoạt động",
	"impacted":                   "bị ảnh hưởng",
	"interim recovery mode":      "chế độ phục hồi tạm (Interim Recovery)",
	"ready for rebuild":          "sẵn sàng rebuild",
	"recovering":                 "đang phục hồi",
	"complete":                   "hoàn tất",
	"expanding":                  "đang mở rộng",
	"initializing":               "đang khởi tạo",
	"failed stripes":             "stripe hỏng",
	"unrecoverable media errors": "lỗi media không phục hồi",
	"detected":                   "có",
	// hardware controllers: drives
	"onln":                "hoạt động",
	"offln":               "ngừng hoạt động",
	"spun up":             "đang quay",
	"spun down":           "đã dừng quay",
	"unconfigured(good)":  "chưa cấu hình (tốt)",
	"unconfigured(bad)":   "chưa cấu hình (lỗi)",
	"unconfigured good":   "chưa cấu hình (tốt)",
	"unconfigured bad":    "chưa cấu hình (lỗi)",
	"ugood":               "chưa cấu hình (tốt)",
	"ubad":                "chưa cấu hình (lỗi)",
	"ugunsp":              "không được hỗ trợ",
	"ugshld":              "bị shield",
	"shielded":            "bị shield",
	"hotspare":            "hot spare",
	"hot spare":           "hot spare",
	"hot-spare":           "hot spare",
	"global hot-spare":    "hot spare toàn cục",
	"global hot spare":    "hot spare toàn cục",
	"dedicated hot-spare": "hot spare riêng",
	"dedicated hot spare": "hot spare riêng",
	"ghs":                 "hot spare toàn cục",
	"dhs":                 "hot spare riêng",
	"rbld":                "đang rebuild",
	"cpybck":              "đang copyback",
	"copyback":            "đang copyback",
	"msng":                "bị thiếu",
	"conf":                "đã cấu hình", // StorCLI2 drive state
	"uconf":               "chưa cấu hình",
	"unusable":            "không dùng được",
	"replace":             "cần thay",
	"various":             "nhiều trạng thái",
	"frgn":                "foreign",
	"ready":               "sẵn sàng",
	"raw (pass through)":  "raw (pass-through)",
	"failed segments":     "segment hỏng",
	"unassigned":          "chưa gán",
	"hours":               "giờ",
	"hour":                "giờ",
	"minutes":             "phút",
	"minute":              "phút",
	"seconds":             "giây",
	"days":                "ngày",
	"day":                 "ngày",
	// controllers, cache and battery
	"needs attention":              "cần chú ý",
	"need attention":               "cần chú ý",
	"dgd":                          "suy giảm",
	"operational":                  "hoạt động",
	"non operational":              "không hoạt động",
	"replace batteries":            "cần thay pin",
	"replace batteries/capacitors": "cần thay pin/tụ",
	"charging":                     "đang sạc",
	"discharging":                  "đang xả",
	"learning":                     "đang chạy learn cycle",
	"temporarily disabled":         "tạm tắt",
	"permanently disabled":         "tắt hẳn",
	// Storage Spaces
	"unhealthy":          "không tốt",
	"detached":           "đã tách (detached)",
	"incomplete":         "không đầy đủ",
	"in service":         "đang sửa chữa",
	"allocated":          "đã cấp phát",
	"auto-select":        "tự chọn (Auto-Select)",
	"autoselect":         "tự chọn (Auto-Select)",
	"manual-select":      "chọn tay (Manual-Select)",
	"manualselect":       "chọn tay (Manual-Select)",
	"retired":            "đã retire",
	"journal":            "journal",
	"lost communication": "mất liên lạc",
	"lostcommunication":  "mất liên lạc",
	"starting":           "đang khởi động",
	"not usable":         "không dùng được",
	"split":              "bị tách",
	"stale metadata":     "metadata cũ",
	"io error":           "lỗi I/O",
	"removing from pool": "đang gỡ khỏi pool",
	"transient error":    "lỗi tạm thời",
}

var raidPhrases = units.NewPhrases(raidWords)

// stateCell translates a state, progress or size cell (a Text is kept as
// is).
func stateCell(v any) model.Text {
	switch x := v.(type) {
	case model.Text:
		return x
	case string:
		return raidPhrases.Text(x)
	}
	return model.Text{}
}

// memberState matches the state a member list adds after a device name:
// "sdb(FAULTED)", "devid 3(MISSING)", "/dev/loop2 [unknown]".
var memberState = regexp.MustCompile(`[(\[][A-Za-z][A-Za-z -]*[)\]]`)

// memberPhrases are shorter words for member states, written in lower case
// inside the parentheses.
var memberPhrases = units.NewPhrases(raidWords, map[string]string{
	"faulted": "lỗi",
	"inuse":   "đang dùng",
	"avail":   "sẵn sàng",
})

// membersCell translates only the states in a member list, never the
// device names. A state it cannot translate whole (md's flags F, S, W, R)
// is kept exactly as written.
func membersCell(s string) model.Text {
	vi := memberState.ReplaceAllStringFunc(s, func(m string) string {
		in := strings.ToLower(m[1 : len(m)-1])
		t := memberPhrases.Whole(in)
		if t.VI == in {
			return m
		}
		return m[:1] + t.VI + m[len(m)-1:]
	})
	return model.T(s, vi)
}

// errCell summarises a controller disk's error counters.
func errCell(d *HWDrive) model.Text {
	var en, vi []string
	add := func(e, v string) { en, vi = append(en, e), append(vi, v) }
	if d.MediaErr > 0 {
		add(fmt.Sprintf("media %d", d.MediaErr), fmt.Sprintf("lỗi media %d", d.MediaErr))
	}
	if d.OtherErr > 0 {
		add(fmt.Sprintf("other %d", d.OtherErr), fmt.Sprintf("lỗi khác %d", d.OtherErr))
	}
	if d.PredFail > 0 {
		add(fmt.Sprintf("predictive %d", d.PredFail), fmt.Sprintf("báo sắp hỏng %d", d.PredFail))
	}
	if d.SmartWarn > 0 {
		add(fmt.Sprintf("SMART warnings %d", d.SmartWarn), fmt.Sprintf("cảnh báo S.M.A.R.T. %d", d.SmartWarn))
	}
	if d.SmartAlert {
		add("SMART alert", "cảnh báo S.M.A.R.T.")
	}
	if len(en) == 0 {
		if d.MediaErr == 0 || d.OtherErr == 0 || d.PredFail == 0 || d.SmartWarn == 0 {
			return model.T("0", "0")
		}
		return model.T("-", "-")
	}
	return model.T(strings.Join(en, ", "), strings.Join(vi, ", "))
}

// joinNonEmpty joins the non-empty parts with sep.
func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// joinTexts joins the non-empty texts with sep in each language.
func joinTexts(sep string, ts ...model.Text) model.Text {
	var en, vi []string
	for _, t := range ts {
		if !t.IsZero() {
			en, vi = append(en, t.EN), append(vi, t.VI)
		}
	}
	return model.T(strings.Join(en, sep), strings.Join(vi, sep))
}
