package ipmi

import "testing"

// Event texts come from ipmitool's SEL tables (a closed set, but larger than
// the dictionary): a text is translated whole or kept in English, never
// half and half ("Công suất Button pressed").
func TestEventCellWholeOrEnglish(t *testing.T) {
	for in, want := range map[string]string{
		"Power Button pressed":                "Nút nguồn được bấm",
		"Soft-power control failure":          "Lỗi điều khiển nguồn mềm (soft-power)",
		"Memory Scrub Failed":                 "Scrub bộ nhớ thất bại",
		"Critical Overtemperature":            "Quá nhiệt nghiêm trọng",
		"Rebuild/Remap Aborted":               "Rebuild bị hủy",
		"System Restart":                      "Khởi động lại hệ thống",
		"Redundancy Lost":                     "Mất dự phòng",
		"Fan Redundancy Lost":                 "Quạt mất dự phòng",
		"Upper Critical going high":           "Vượt ngưỡng tới hạn",
		"Correctable ECC ( @DIMMA1)":          "Lỗi ECC đã sửa ( @DIMMA1)",
		"Presence detected, Failure detected": "Có lắp, phát hiện hỏng",
		// Unknown to the dictionary: English as is.
		"OEM Vendor Frobnicator engaged":        "OEM Vendor Frobnicator engaged",
		"Sensor access degraded or unavailable": "Sensor access degraded or unavailable",
		"No Reading":                            "No Reading",
		"0x01":                                  "0x01",
	} {
		if got := eventCell(in); got.EN != in || got.VI != want {
			t.Errorf("eventCell(%q) = %q, want %q", in, got.VI, want)
		}
	}
}

func TestReadingAndClassCells(t *testing.T) {
	for in, want := range map[string]string{
		"23 degrees C":      "23 °C",
		"0.60 Amps":         "0.60 A",
		"230 Volts":         "230 V",
		"5880 RPM":          "5880 RPM",
		"Presence detected": "Có lắp",
		"No Reading":        "No Reading",
		"State Deasserted":  "Không kích hoạt",
	} {
		if got := cellText(in); got.VI != want {
			t.Errorf("cellText(%q) = %q, want %q", in, got.VI, want)
		}
	}
	for in, want := range map[string]string{"power": "công suất", "psu": "bộ nguồn", "fan": "quạt", "other": "khác"} {
		if got := cellText(in); got.VI != want {
			t.Errorf("class %q = %q, want %q", in, got.VI, want)
		}
	}
}
