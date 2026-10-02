package redfish

import (
	"fmt"
	"strconv"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

func cols(pairs ...string) []model.Text {
	var out []model.Text
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, model.T(pairs[i], pairs[i+1]))
	}
	return out
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// fmtLimit shows a threshold or rating; 0 and negative values are BMC
// placeholders for "none" (iLO 4 sends UpperThresholdCritical: 0, and a
// PowerCapacityWatts of 0 while the server is off).
func fmtLimit(p *float64, unit string) string {
	if !pos(p) {
		return "-"
	}
	return fmtNum(p, unit)
}

func (c *checker) tables() {
	f := c.facts
	if len(f.Temperatures) > 0 {
		t := model.Table{ID: domain + ".temperatures", Title: model.T("Temperatures (BMC)", "Nhiệt độ (BMC)"),
			Columns: cols("Sensor", "Cảm biến", "Reading", "Số đo", "Warning at", "Ngưỡng cảnh báo", "Critical at", "Ngưỡng nguy hiểm", "Status", "Trạng thái")}
		for _, s := range f.Temperatures {
			crit := s.Crit
			if crit == nil {
				crit = s.Fatal
			}
			t.Rows = append(t.Rows, model.Row{Status: s.Severity, Cells: []string{dash(s.Name), fmtNum(s.Reading, "°C"), fmtLimit(s.Warn, "°C"), fmtLimit(crit, "°C"), s.Status.Text()}})
		}
		c.res.Tables = append(c.res.Tables, t)
	}
	if len(f.Fans) > 0 {
		t := model.Table{ID: domain + ".fans", Title: model.T("Fans (BMC)", "Quạt (BMC)"),
			Columns: cols("Fan", "Quạt", "Reading", "Số đo", "Critical below", "Ngưỡng tối thiểu", "Status", "Trạng thái")}
		for _, s := range f.Fans {
			unit := s.Units
			if unit == "Percent" {
				unit = "%"
			}
			t.Rows = append(t.Rows, model.Row{Status: s.Severity, Cells: []string{dash(s.Name), fmtNum(s.Reading, unit), fmtLimit(s.LowerCrit, unit), s.Status.Text()}})
		}
		c.res.Tables = append(c.res.Tables, t)
	}
	if len(f.PSUs) > 0 {
		t := model.Table{ID: domain + ".psus", Title: model.T("Power supplies (BMC)", "Bộ nguồn (BMC)"),
			Columns: cols("PSU", "Nguồn", "Model", "Model", "Serial", "Serial", "Capacity", "Công suất", "Input", "Điện vào", "Output", "Đang cấp", "Status", "Trạng thái")}
		for _, p := range f.PSUs {
			t.Rows = append(t.Rows, model.Row{Status: p.Severity, Cells: []string{dash(p.Name), dash(first(p.Model, p.Part)), dash(p.Serial), fmtLimit(p.CapacityW, "W"), fmtNum(p.InputV, "V"), fmtNum(p.OutputW, "W"), p.Status.Text()}})
		}
		if f.PowerWatts != nil {
			t.Note = model.Tf("Server power draw: %s", "Công suất server đang tiêu thụ: %s", fmtNum(f.PowerWatts, "W"))
		}
		c.res.Tables = append(c.res.Tables, t)
	}
	if len(f.Drives) > 0 {
		t := model.Table{ID: domain + ".drives", Title: model.T("Drives (BMC)", "Ổ cứng (BMC)"),
			Columns: cols("Drive", "Ổ", "Model", "Model", "Serial", "Serial", "Size", "Dung lượng", "Type", "Loại", "Life left", "Tuổi thọ còn", "Status", "Trạng thái")}
		for _, d := range f.Drives {
			size := "-"
			if d.CapacityBytes > 0 {
				size = units.SI(d.CapacityBytes)
			}
			typ := d.MediaType
			if d.Protocol != "" {
				typ = first(typ+" "+d.Protocol, d.Protocol)
			}
			life := "-"
			if d.LifeLeftPercent != nil {
				life = strconv.FormatFloat(*d.LifeLeftPercent, 'f', 0, 64) + "%"
			}
			st := d.Status.Text()
			if d.FailurePredicted != nil && *d.FailurePredicted {
				st += ", failure predicted"
			}
			t.Rows = append(t.Rows, model.Row{Status: d.Severity, Cells: []string{dash(driveName(d)), dash(d.Model), dash(d.Serial), size, dash(typ), life, st}})
		}
		c.res.Tables = append(c.res.Tables, t)
	}
	if len(f.Volumes) > 0 {
		t := model.Table{ID: domain + ".volumes", Title: model.T("RAID volumes (BMC)", "Volume RAID (BMC)"),
			Columns: cols("Volume", "Volume", "RAID", "RAID", "Size", "Dung lượng", "Status", "Trạng thái")}
		for _, v := range f.Volumes {
			size := "-"
			if v.CapacityBytes > 0 {
				size = units.SI(v.CapacityBytes)
			}
			st := v.Status.Text()
			if v.RaidStatus != "" {
				st += " / " + v.RaidStatus
			}
			if v.Rebuilding {
				st += " / rebuilding"
				if v.RebuildPct != nil {
					st += fmt.Sprintf(" %.0f%%", *v.RebuildPct)
				}
			}
			t.Rows = append(t.Rows, model.Row{Status: v.Severity, Cells: []string{dash(first(v.Name, v.ID)), dash(v.RAID), size, st}})
		}
		c.res.Tables = append(c.res.Tables, t)
	}
	if len(f.DIMMs) > 0 {
		t := model.Table{ID: domain + ".dimms", Title: model.T("Memory modules (BMC)", "Thanh RAM (BMC)"),
			Columns: cols("Slot", "Khe", "Size", "Dung lượng", "Type", "Loại", "Vendor", "Hãng", "Part number", "Part number", "Serial", "Serial", "Status", "Trạng thái")}
		for _, d := range f.DIMMs {
			size := "-"
			if d.CapacityMiB > 0 {
				size = units.IEC(uint64(d.CapacityMiB) << 20)
			}
			t.Rows = append(t.Rows, model.Row{Status: d.Severity, Cells: []string{dash(d.Slot), size, dash(d.Type), dash(d.Manufacturer), dash(d.PartNumber), dash(d.Serial), d.Status.Text()}})
		}
		c.res.Tables = append(c.res.Tables, t)
	}
	if len(f.Events) > 0 {
		t := model.Table{ID: domain + ".events", Title: model.Tf("BMC events, last %d days (critical and warning)", "Sự kiện BMC %d ngày qua (nghiêm trọng và cảnh báo)", f.WindowDays),
			Columns: cols("Severity", "Mức độ", "Last seen", "Lần cuối", "Count", "Số lần", "Log", "Nhật ký", "Message ID", "Mã", "Message", "Nội dung")}
		for _, g := range f.Events {
			last := "?"
			if g.Last != nil {
				last = c.when(*g.Last)
			}
			raw := g.Raw
			switch {
			case g.Repaired:
				raw += " (repaired)"
			case g.Cleared:
				raw += " (recovered)"
			}
			t.Rows = append(t.Rows, model.Row{Status: g.Severity, Cells: []string{raw, last, strconv.Itoa(g.Count), dash(g.Log), dash(g.MessageID), dash(g.Message)}})
		}
		c.res.Tables = append(c.res.Tables, t)
	}
}
