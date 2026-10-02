package ipmi

import (
	"strings"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// ipmiWords is Vietnamese for what the BMC tables show: sensor classes,
// ipmitool reading units, discrete sensor states and SEL event texts (IPMI
// 2.0 spec, table 42-3 "Sensor Type Codes"; ipmitool's ipmi_sel.c texts),
// and the row states this domain writes.
var ipmiWords = map[string]string{
	// sensor classes
	"fan":         "quạt",
	"temperature": "nhiệt độ",
	"voltage":     "điện áp",
	"current":     "dòng điện",
	"power":       "công suất",
	"psu":         "bộ nguồn",
	"battery":     "pin",
	"memory":      "bộ nhớ",
	"disk":        "ổ cứng",
	"intrusion":   "mở nắp máy",
	"power-unit":  "khối nguồn",
	"system":      "hệ thống",
	"bmc":         "BMC",
	"cpu":         "CPU",
	"watchdog":    "watchdog",
	// reading units
	"degrees c":   "°C",
	"degrees":     "độ",
	"volts":       "V",
	"amps":        "A",
	"watts":       "W",
	"percent":     "%",
	"unspecified": "(không rõ đơn vị)",
	// discrete states and SEL events
	"presence detected":                       "có lắp",
	"device present":                          "có thiết bị",
	"device absent":                           "không có thiết bị",
	"device removed":                          "thiết bị bị tháo",
	"device inserted":                         "thiết bị được cắm",
	"drive present":                           "có ổ",
	"drive fault":                             "ổ lỗi",
	"failure detected":                        "phát hiện hỏng",
	"predictive failure":                      "sắp hỏng",
	"power supply ac lost":                    "bộ nguồn mất điện AC",
	"ac lost":                                 "mất điện AC",
	"ac lost or out-of-range":                 "mất điện AC hoặc điện áp ngoài ngưỡng",
	"ac out-of-range, but present":            "điện AC ngoài ngưỡng",
	"power supply input lost (ac/dc)":         "bộ nguồn mất điện đầu vào (AC/DC)",
	"config error":                            "lỗi cấu hình",
	"configuration error":                     "lỗi cấu hình",
	"fully redundant":                         "đủ dự phòng",
	"redundancy lost":                         "mất dự phòng",
	"redundancy degraded":                     "dự phòng bị suy giảm",
	"redundancy regained":                     "có lại dự phòng",
	"non-redundant: sufficient resources":     "không dự phòng, vẫn đủ tài nguyên",
	"non-redundant: insufficient resources":   "không dự phòng, thiếu tài nguyên",
	"state asserted":                          "đang kích hoạt",
	"state deasserted":                        "không kích hoạt",
	"connected":                               "đã kết nối",
	"transition to ok":                        "chuyển về bình thường",
	"transition to critical from less severe": "chuyển sang nghiêm trọng",
	"transition to non-critical from ok":      "chuyển sang cảnh báo",
	"transition to non-recoverable":           "chuyển sang không phục hồi",
	"general chassis intrusion":               "nắp máy bị mở",
	"correctable ecc":                         "lỗi ECC đã sửa",
	"uncorrectable ecc":                       "lỗi ECC không sửa được",
	"correctable ecc logging limit reached":   "đạt giới hạn ghi lỗi ECC đã sửa",
	"memory device disabled":                  "thanh RAM bị tắt",
	"lower critical going low":                "xuống dưới ngưỡng tới hạn",
	"lower non-critical going low":            "xuống dưới ngưỡng cảnh báo",
	"lower non-recoverable going low":         "xuống dưới ngưỡng không phục hồi",
	"upper critical going high":               "vượt ngưỡng tới hạn",
	"upper non-critical going high":           "vượt ngưỡng cảnh báo",
	"upper non-recoverable going high":        "vượt ngưỡng không phục hồi",
	"hard reset":                              "reset cứng",
	"power cycle":                             "tắt bật lại nguồn",
	"power down":                              "tắt nguồn",
	"power off/down":                          "tắt nguồn",
	"timer expired":                           "watchdog hết giờ",
	"timer interrupt":                         "ngắt watchdog",
	"linux kernel panic":                      "kernel Linux bị panic",
	"os graceful shutdown":                    "hệ điều hành tắt bình thường",
	"thermal trip":                            "ngắt do quá nhiệt",
	"processor presence detected":             "có CPU",
	"rebuild/remap in progress":               "đang rebuild",
	"in failed array":                         "nằm trong mảng hỏng",
	"in critical array":                       "nằm trong mảng nguy cấp",
	"low":                                     "thấp",
	"failed":                                  "hỏng",
	"log area reset/cleared":                  "nhật ký đã bị xoá",
	"log full":                                "nhật ký đầy",
	"log almost full":                         "nhật ký sắp đầy",
	// more SEL event texts (ipmi_sel.c sensor-specific offsets)
	"power button pressed":                  "nút nguồn được bấm",
	"reset button pressed":                  "nút reset được bấm",
	"sleep button pressed":                  "nút sleep được bấm",
	"soft-power control failure":            "lỗi điều khiển nguồn mềm (soft-power)",
	"240va power down":                      "tắt nguồn do quá tải 240VA",
	"interlock power down":                  "tắt nguồn do khóa liên động (interlock)",
	"memory scrub failed":                   "scrub bộ nhớ thất bại",
	"critical overtemperature":              "quá nhiệt nghiêm trọng",
	"parity":                                "lỗi parity",
	"throttled":                             "bị giới hạn tốc độ (throttled)",
	"rebuild/remap aborted":                 "rebuild bị hủy",
	"parity check in progress":              "đang kiểm tra parity",
	"hot spare":                             "hot spare",
	"system restart":                        "khởi động lại hệ thống",
	"timestamp clock sync":                  "đồng bộ đồng hồ BMC",
	"correctable machine check error":       "lỗi machine check đã sửa",
	"uncorrectable machine check exception": "lỗi machine check không sửa được",
	"oem system boot event":                 "sự kiện khởi động của hãng (OEM)",
	"initiated by power up":                 "khởi động khi bật nguồn",
	"initiated by hard reset":               "khởi động sau reset cứng",
	"initiated by warm reset":               "khởi động sau reset mềm",
	"fru latch open":                        "chốt linh kiện (FRU) đang mở",
	// sensor status (ipmitool sdr: ok, ns = no reading)
	"ns": "không có số đo",
	// event states written by this domain
	"active": "đang xảy ra",
	"old":    "cũ",
}

var ipmiPhrases = units.NewPhrases(ipmiWords)

// cellText translates a BMC table cell: a sensor class, a reading, a list
// of discrete states or an event text. The text is translated whole or
// not at all: ipmitool's texts are a closed set larger than this
// dictionary, and a sentence with one known word ("Power Button pressed")
// must stay English rather than come out half Vietnamese.
func cellText(s string) model.Text { return ipmiPhrases.Whole(s) }

// eventCell is cellText for a SEL event text, which may end with the BMC's
// own detail in parentheses ("Correctable ECC ( @DIMMA1)"): the detail is
// kept as is.
func eventCell(s string) model.Text {
	if i := strings.Index(s, "("); i > 0 {
		head := cellText(strings.TrimRight(s[:i], " "))
		sp := s[len(strings.TrimRight(s[:i], " ")):i]
		return model.T(s, head.VI+sp+s[i:])
	}
	return cellText(s)
}
