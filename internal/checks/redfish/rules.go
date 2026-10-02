package redfish

import (
	"fmt"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

// Thresholds. Redfish carries the vendor's own sensor limits (the same
// ones the BMC uses to raise its alerts), so readings are judged against
// them, never against guessed numbers. Definitions (DMTF DSP0268, Thermal
// and Sensor schemas): UpperThresholdNonCritical / UpperCaution = "above
// the normal range"; UpperThresholdCritical / UpperCritical = "above the
// normal range but not yet fatal"; Fatal = "the hardware may be damaged".
// The contract maps ≥ critical to Crit and ≥ non-critical to Warn.
const (
	// A reading outside this range is a broken sensor or an IPMI "no
	// reading" placeholder (255), not a temperature.
	minPlausibleC = -40
	maxPlausibleC = 200
	// SSD life left: ≤ 20 % is the contract's "wear ≥ 80 %" Warn level;
	// ≤ 10 % is where vendors flag end of rated endurance (Dell iDRAC and
	// HPE SSA raise a predictive-failure / "wear-out" alert around the last
	// 5-10 %; JEDEC JESD218 endurance is rated to 0 %, after which many
	// SSDs go read-only).
	wearWarnPct = 20
	wearCritPct = 10
)

func pos(p *float64) bool { return p != nil && *p > 0 }

func healthOK(st Status) bool { return strings.EqualFold(st.Health, "OK") }

func disabled(st Status) bool {
	s := strings.ToLower(st.State)
	return s == "disabled" || s == "absent" || strings.HasPrefix(s, "standby")
}

func evidenceKV(name string, kv ...string) []string {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" && kv[i+1] != "-" {
			parts = append(parts, kv[i]+"="+kv[i+1])
		}
	}
	return []string{name + ": " + strings.Join(parts, " ")}
}

// --- system -------------------------------------------------------------

func (c *checker) systemPower() {
	if !c.poweredOff {
		return
	}
	c.add(model.Finding{
		ID: domain + ".power_off", Component: model.CompSystem, Severity: model.Info,
		Target: c.facts.Systems[0].ID,
		Title:  model.T("The server is powered off", "Server đang tắt nguồn"),
		Detail: model.T("Fan, temperature and voltage readings mean little while the server is off; health states and the event log still do. If it will not power on, look at the power supply findings and the most recent BMC events.",
			"Khi server tắt, số đo quạt, nhiệt độ, điện áp không có nhiều ý nghĩa; trạng thái sức khỏe và nhật ký sự kiện vẫn đáng tin. Nếu server không lên nguồn được, xem các cảnh báo về bộ nguồn và các sự kiện BMC gần nhất."),
	})
}

func (c *checker) summary(rollups []rollup) {
	worst := model.OK
	var ev []string
	known := false
	for _, r := range rollups {
		if r.health == "" {
			continue
		}
		known = true
		ev = append(ev, r.what+": HealthRollup="+r.health)
		worst = model.Worst(worst, healthSev(r.health))
	}
	if !known {
		return
	}
	switch {
	case worst > model.OK && worst > c.worst:
		lvl := "Critical"
		if worst == model.Warn {
			lvl = "Warning"
		}
		c.add(model.Finding{
			ID: domain + ".system_health", Component: model.CompSystem, Severity: worst,
			Target:   c.sysTarget(),
			Title:    model.Tf("The BMC reports the server's overall health as %s", "BMC báo tình trạng tổng thể của server là %s", lvl),
			Detail:   model.T("Diagward found no specific failing part in the data the BMC exposes, so the fault is probably in a component it does not cover (GPU, PCIe card, backplane, cable, BMC sub-component).", "Diagward không tìm thấy linh kiện cụ thể nào bị lỗi trong dữ liệu BMC cung cấp, nên lỗi có thể nằm ở bộ phận chưa được kiểm tra (GPU, card PCIe, backplane, cáp, thành phần của BMC)."),
			Action:   model.T("Open the BMC web interface (system summary / health page, or the active fault list) to see which component is failing, then fix or replace it.", "Mở giao diện web của BMC (trang tổng quan / Health, hoặc danh sách lỗi đang hoạt động) để xem bộ phận nào đang lỗi, rồi xử lý hoặc thay thế."),
			Evidence: units.Evidence(ev, 10),
		})
	case worst == model.OK && c.worst == model.OK:
		c.add(model.Finding{
			ID: domain + ".system_health", Component: model.CompSystem, Severity: model.OK,
			Target:   c.sysTarget(),
			Title:    model.T("The BMC reports the server's overall health as OK", "BMC báo tình trạng tổng thể của server bình thường (OK)"),
			Evidence: units.Evidence(ev, 10),
		})
	}
}

func (c *checker) sysTarget() string {
	if len(c.facts.Systems) > 0 {
		s := c.facts.Systems[0]
		if s.Model != "" {
			return strings.TrimSpace(s.Manufacturer + " " + s.Model)
		}
		return s.ID
	}
	return "system"
}

// --- thermal ------------------------------------------------------------

func (c *checker) thermal() {
	bad := false
	for i := range c.facts.Temperatures {
		t := &c.facts.Temperatures[i]
		sev, limit, kind := tempSev(*t, c.poweredOff)
		t.Severity = sev
		if sev == model.OK {
			continue
		}
		bad = true
		ev := evidenceKV(t.Name, "Reading", fmtNum(t.Reading, "°C"), "NonCritical", fmtNum(t.Warn, ""), "Critical", fmtNum(t.Crit, ""), "Fatal", fmtNum(t.Fatal, ""), "Health", t.Status.Health, "State", t.Status.State)
		f := model.Finding{Component: model.CompThermal, Severity: sev, Target: t.Name, Evidence: ev}
		if sev == model.Crit {
			f.ID = domain + ".temp_critical"
			f.Action = model.T("Check the room temperature and airflow now: blocked front bezel or filters, failed fans, missing blanking panels, a failed air conditioner. Clean dust from the heatsinks. If only this sensor is hot, reseat the heatsink and renew the thermal paste. The server may shut down by itself to protect the hardware.",
				"Kiểm tra ngay nhiệt độ phòng máy và luồng gió: mặt trước hoặc lưới lọc bị chắn, quạt hỏng, thiếu tấm che khe trống, điều hòa phòng máy hỏng. Vệ sinh bụi trên tản nhiệt. Nếu chỉ riêng cảm biến này nóng, tháo lắp lại tản nhiệt và thay keo tản nhiệt. Server có thể tự tắt để bảo vệ phần cứng.")
		} else {
			f.ID = domain + ".temp_high"
			f.Action = model.T("Check the room temperature, the airflow (filters, bezel, blanking panels) and the fans, and clean dust from the heatsinks before it reaches the critical limit.",
				"Kiểm tra nhiệt độ phòng máy, luồng gió (lưới lọc, mặt trước, tấm che khe trống) và quạt, vệ sinh bụi tản nhiệt trước khi chạm ngưỡng nguy hiểm.")
		}
		switch {
		case kind == "reading" && t.Reading != nil:
			f.Title = model.Tf("Temperature %s is %s, at or above its %s limit (%s)", "Nhiệt độ %s đang ở %s, chạm ngưỡng %s (%s)",
				t.Name, fmtNum(t.Reading, "°C"), limitWord(sev, "en"), fmtNum(limit, "°C"))
			f.Title.VI = fmt.Sprintf("Nhiệt độ %s đang ở %s, chạm ngưỡng %s (%s)", t.Name, fmtNum(t.Reading, "°C"), limitWord(sev, "vi"), fmtNum(limit, "°C"))
			f.Detail = model.T("The limit is the one the vendor programmed into the BMC for this sensor. Prolonged overheating shortens component life and makes the server throttle or shut down.",
				"Ngưỡng này do hãng cài sẵn trong BMC cho cảm biến này. Quá nhiệt kéo dài làm giảm tuổi thọ linh kiện, khiến server tự giảm hiệu năng hoặc tự tắt.")
		default:
			f.Title = model.Tf("Temperature sensor %s reports %s", "Cảm biến nhiệt %s báo %s", t.Name, t.Status.Health)
		}
		c.add(f)
	}
	for i := range c.facts.Fans {
		fan := &c.facts.Fans[i]
		sev, why := fanSev(*fan, c.poweredOff)
		fan.Severity = sev
		if sev == model.OK {
			continue
		}
		bad = true
		f := model.Finding{
			Component: model.CompFan, Severity: sev, Target: fan.Name,
			Evidence: evidenceKV(fan.Name, "Reading", fmtNum(fan.Reading, fan.Units), "LowerCritical", fmtNum(fan.LowerCrit, ""), "Health", fan.Status.Health, "State", fan.Status.State),
			Part:     fanPart(*fan),
		}
		if sev == model.Crit {
			f.ID = domain + ".fan_failed"
			f.Title = model.Tf("Fan %s has failed (%s)", "Quạt %s bị hỏng (%s)", fan.Name, why.EN)
			f.Title.VI = fmt.Sprintf("Quạt %s bị hỏng (%s)", fan.Name, why.VI)
			f.Action = model.Tf("Replace fan %s (hot-swappable on most rack servers). Until then keep the room cool and watch the temperatures; the other fans speed up to compensate.",
				"Thay quạt %s (đa số server rack cho phép thay nóng). Trong lúc chờ, giữ phòng máy mát và theo dõi nhiệt độ; các quạt còn lại sẽ chạy nhanh hơn để bù.", fan.Name)
		} else {
			f.ID = domain + ".fan_warning"
			f.Title = model.Tf("Fan %s needs attention (%s)", "Quạt %s cần kiểm tra (%s)", fan.Name, why.EN)
			f.Title.VI = fmt.Sprintf("Quạt %s cần kiểm tra (%s)", fan.Name, why.VI)
			f.Action = model.Tf("Check that fan %s is installed and seated, clean dust from it, and replace it if the warning stays.",
				"Kiểm tra quạt %s đã lắp và cắm chắc chưa, vệ sinh bụi, nếu vẫn còn cảnh báo thì thay quạt.", fan.Name)
		}
		c.add(f)
	}
	bad = c.redundancy("fan") || bad
	if !bad && (len(c.facts.Temperatures) > 0 || len(c.facts.Fans) > 0) && !c.poweredOff {
		c.add(model.Finding{
			ID: domain + ".thermal_ok", Component: model.CompThermal, Severity: model.OK,
			Title: model.Text{
				EN: fmt.Sprintf("%s and %s are within limits", plural(len(c.facts.Temperatures), "temperature sensor", "temperature sensors"), plural(len(c.facts.Fans), "fan", "fans")),
				VI: fmt.Sprintf("%d cảm biến nhiệt và %d quạt đều trong ngưỡng bình thường", len(c.facts.Temperatures), len(c.facts.Fans)),
			},
		})
	}
}

func limitWord(sev model.Severity, lang string) string {
	if lang == "vi" {
		if sev == model.Crit {
			return "nguy hiểm"
		}
		return "cảnh báo"
	}
	if sev == model.Crit {
		return "critical"
	}
	return "warning"
}

// tempSev judges one temperature sensor: the BMC health, and the reading
// against the sensor's own thresholds.
func tempSev(t Temperature, off bool) (model.Severity, *float64, string) {
	if t.Status.Absent() || (disabled(t.Status) && t.Status.Sev() == model.OK) {
		return model.OK, nil, ""
	}
	sev, limit, kind := model.OK, (*float64)(nil), ""
	if r := t.Reading; r != nil && !off && *r > minPlausibleC && *r < maxPlausibleC {
		switch {
		case pos(t.Fatal) && *r >= *t.Fatal:
			sev, limit, kind = model.Crit, t.Fatal, "reading"
		case pos(t.Crit) && *r >= *t.Crit:
			sev, limit, kind = model.Crit, t.Crit, "reading"
		case pos(t.Warn) && *r >= *t.Warn:
			sev, limit, kind = model.Warn, t.Warn, "reading"
		}
	}
	if hs := t.Status.Sev(); hs > sev {
		return hs, nil, "health"
	}
	return sev, limit, kind
}

// fanSev judges one fan. A stopped or too-slow fan is Crit unless the BMC
// itself says the fan is OK (some BMCs list empty fan headers as enabled
// at 0 RPM): then it is a Warn to check.
func fanSev(f Fan, off bool) (model.Severity, model.Text) {
	if f.Status.Absent() {
		return model.OK, model.Text{}
	}
	hs := f.Status.Sev()
	sev, why := model.OK, model.Text{}
	rpm := strings.EqualFold(f.Units, "RPM")
	if r := f.Reading; r != nil && rpm && !off && !disabled(f.Status) {
		switch {
		case *r <= 0:
			sev, why = model.Crit, model.T("0 RPM", "0 vòng/phút")
		case pos(f.LowerCrit) && *r < *f.LowerCrit:
			sev, why = model.Crit, model.Tf("%s, below the critical limit %s", "%s, dưới ngưỡng nguy hiểm %s", fmtNum(r, "RPM"), fmtNum(f.LowerCrit, "RPM"))
		}
		if sev == model.Crit && healthOK(f.Status) {
			sev = model.Warn
		}
	}
	if hs > sev {
		return hs, model.Tf("BMC health %s", "BMC báo %s", f.Status.Health)
	}
	return sev, why
}

func fanPart(f Fan) *model.Part {
	return &model.Part{Kind: "fan", Model: first(f.Model, f.Part), Serial: f.Serial, Location: f.Name}
}

// redundancy reports lost fan or PSU redundancy; it returns true when it
// found a problem.
func (c *checker) redundancy(kind string) bool {
	bad := false
	for _, r := range c.facts.Redundancy {
		if r.Kind != kind || disabled(r.Status) || r.Status.Sev() == model.OK {
			continue
		}
		bad = true
		name := first(r.Name, kind)
		f := model.Finding{
			Severity: model.Warn, Target: name,
			Evidence: evidenceKV(name, "Mode", r.Mode, "Health", r.Status.Health, "State", r.Status.State),
		}
		if kind == "fan" {
			f.ID, f.Component = domain+".fan_redundancy_lost", model.CompFan
			f.Title = model.Tf("Fan redundancy lost (%s)", "Mất dự phòng quạt (%s)", name)
			f.Detail = model.T("The server still runs, but one more fan failure can make it overheat.", "Server vẫn chạy, nhưng hỏng thêm một quạt nữa là có thể quá nhiệt.")
			f.Action = model.T("Find the failed or missing fan (see the fan findings or the BMC thermal page) and replace it.", "Tìm quạt hỏng hoặc bị thiếu (xem cảnh báo về quạt hoặc trang Thermal trên BMC) và thay thế.")
		} else {
			f.ID, f.Component = domain+".psu_redundancy_lost", model.CompPower
			f.Title = model.Tf("Power supply redundancy lost (%s)", "Mất dự phòng nguồn (%s)", name)
			f.Detail = model.T("The server now depends on a single power supply or power feed: one more failure turns it off.", "Server đang phụ thuộc vào một bộ nguồn hoặc một đường điện duy nhất: hỏng thêm một cái nữa là server tắt.")
			f.Action = model.T("Check that every power supply is plugged in and its feed (PDU/UPS) is live; replace the failed power supply (see the power supply findings).", "Kiểm tra tất cả bộ nguồn đã cắm điện và đường điện (PDU/UPS) có điện; thay bộ nguồn hỏng (xem cảnh báo về bộ nguồn).")
		}
		c.add(f)
	}
	return bad
}

// --- power --------------------------------------------------------------

func (c *checker) power() {
	bad := false
	anyInput := false
	present := 0
	for _, p := range c.facts.PSUs {
		if p.Status.Absent() {
			continue
		}
		present++
		if p.InputV != nil && *p.InputV > 0 {
			anyInput = true
		}
	}
	for i := range c.facts.PSUs {
		p := &c.facts.PSUs[i]
		if p.Status.Absent() {
			continue
		}
		lis := strings.ToLower(p.LineInputStatus)
		// No input is certain when the PSU says so (LineInputStatus), or
		// when it reads 0 V while another PSU in the same server has input.
		noInput := lis == "noinput" || lis == "lossofinput" || (p.InputV != nil && *p.InputV == 0 && anyInput)
		hs := p.Status.Sev()
		part := &model.Part{Kind: "psu", Vendor: p.Manufacturer, Model: first(p.Model, p.Part), Serial: p.Serial, Location: p.Name, Firmware: p.Firmware}
		if p.CapacityW != nil && *p.CapacityW > 0 {
			part.Size = fmtNum(p.CapacityW, "W")
		}
		ev := evidenceKV(p.Name, "Health", p.Status.Health, "State", p.Status.State, "LineInputVoltage", fmtNum(p.InputV, "V"), "LineInputStatus", p.LineInputStatus, "Output", fmtNum(p.OutputW, "W"), "Model", p.Model, "Serial", p.Serial)
		serial := first(p.Serial, "?")
		switch {
		case noInput:
			p.Severity = model.Crit
			c.add(model.Finding{
				ID: domain + ".psu_no_input", Component: model.CompPower, Severity: model.Crit, Target: p.Name, Evidence: ev, Part: part,
				Title:  model.Tf("Power supply %s has no input power", "Nguồn %s mất điện đầu vào", p.Name),
				Detail: model.T("The power supply gets no AC/DC input, so the server has lost power redundancy.", "Bộ nguồn không nhận được điện đầu vào, server đã mất nguồn dự phòng."),
				Action: model.Tf("Check the power cord and the PDU/UPS outlet feeding %s, then the breaker. If the cord and outlet are fine, replace the power supply (serial %s).",
					"Kiểm tra dây nguồn và ổ cắm PDU/UPS cấp cho %s, rồi đến CB/aptomat. Nếu dây và ổ cắm vẫn tốt thì thay bộ nguồn (serial %s).", p.Name, serial),
			})
			bad = true
		case hs == model.Crit:
			p.Severity = model.Crit
			c.add(model.Finding{
				ID: domain + ".psu_failed", Component: model.CompPower, Severity: model.Crit, Target: p.Name, Evidence: ev, Part: part,
				Title:  model.Tf("Power supply %s has failed", "Bộ nguồn %s bị hỏng", p.Name),
				Detail: model.T("The BMC reports this power supply's health as Critical.", "BMC báo tình trạng bộ nguồn này là Critical (nghiêm trọng)."),
				Action: model.Tf("Check that its power cord is plugged in and look at its LED. Replace power supply %s (serial %s, model %s); it is hot-swappable on most servers.",
					"Kiểm tra dây nguồn đã cắm chắc và xem đèn báo trên nguồn. Thay bộ nguồn %s (serial %s, model %s); đa số server cho phép thay nóng.", p.Name, serial, first(p.Model, p.Part, "?")),
			})
			bad = true
		case hs == model.Warn || lis == "outofrange":
			p.Severity = model.Warn
			c.add(model.Finding{
				ID: domain + ".psu_warning", Component: model.CompPower, Severity: model.Warn, Target: p.Name, Evidence: ev, Part: part,
				Title:  model.Tf("Power supply %s reports a warning", "Bộ nguồn %s đang báo cảnh báo", p.Name),
				Detail: model.T("A warning on a power supply usually means input voltage out of range, a firmware mismatch between power supplies, or a part starting to fail.", "Cảnh báo trên bộ nguồn thường do điện áp vào lệch chuẩn, firmware giữa các bộ nguồn không khớp, hoặc linh kiện bắt đầu hỏng."),
				Action: model.Tf("Check the input power of %s and the BMC event log for the exact cause; update the power supply firmware to match the others; replace it (serial %s) if the warning stays.",
					"Kiểm tra điện đầu vào của %s và nhật ký sự kiện BMC để biết nguyên nhân cụ thể; cập nhật firmware nguồn cho đồng bộ; nếu vẫn cảnh báo thì thay bộ nguồn (serial %s).", p.Name, serial),
			})
			bad = true
		}
	}
	bad = c.redundancy("psu") || bad
	for _, v := range c.facts.Voltages {
		sev, why := voltSev(v, c.poweredOff)
		if sev == model.OK {
			continue
		}
		bad = true
		id := domain + ".voltage_warning"
		if sev == model.Crit {
			id = domain + ".voltage_critical"
		}
		c.add(model.Finding{
			ID: id, Component: model.CompPower, Severity: sev, Target: v.Name,
			Title:    model.Tf("Voltage %s is out of range (%s)", "Điện áp %s lệch ngưỡng (%s)", v.Name, why),
			Evidence: evidenceKV(v.Name, "Reading", fmtNum(v.Reading, "V"), "LowerCritical", fmtNum(v.LowerCrit, ""), "UpperCritical", fmtNum(v.UpperCrit, ""), "Health", v.Status.Health),
			Action: model.T("A voltage rail out of range usually means a failing power supply or a failing voltage regulator on the motherboard. Check the power supply findings; if the power supplies are fine, ask the vendor to check the motherboard.",
				"Điện áp lệch ngưỡng thường do bộ nguồn hoặc mạch ổn áp (VRM) trên mainboard sắp hỏng. Xem các cảnh báo về bộ nguồn; nếu nguồn vẫn tốt, liên hệ hãng kiểm tra mainboard."),
		})
	}
	if !bad && present > 0 {
		c.add(model.Finding{
			ID: domain + ".power_ok", Component: model.CompPower, Severity: model.OK,
			Title: model.Text{EN: plural(present, "power supply is", "power supplies are") + " healthy", VI: fmt.Sprintf("%d bộ nguồn hoạt động bình thường", present)},
		})
	}
}

// voltSev judges a voltage against its own thresholds. As with fans, a
// threshold crossing the BMC itself rates OK is downgraded to Warn.
func voltSev(v Voltage, off bool) (model.Severity, string) {
	if v.Status.Absent() || (disabled(v.Status) && v.Status.Sev() == model.OK) {
		return model.OK, ""
	}
	sev, why := model.OK, ""
	// 0 V on a rail the BMC itself does not flag is "no reading" (an IPMI
	// sensor of an empty CPU socket or a powered-down rail), not a failure.
	if r := v.Reading; r != nil && !off && !(*r == 0 && v.Status.Sev() == model.OK) {
		switch {
		case pos(v.UpperCrit) && *r >= *v.UpperCrit, pos(v.LowerCrit) && *r <= *v.LowerCrit:
			sev = model.Crit
		case pos(v.UpperWarn) && *r >= *v.UpperWarn, pos(v.LowerWarn) && *r <= *v.LowerWarn:
			sev = model.Warn
		}
		why = fmtNum(r, "V")
		if sev == model.Crit && healthOK(v.Status) {
			sev = model.Warn
		}
	}
	if hs := v.Status.Sev(); hs > sev {
		return hs, "Health " + v.Status.Health
	}
	return sev, why
}

// --- storage ------------------------------------------------------------

func driveName(d Drive) string { return first(d.Location, d.Name, d.ID) }

func drivePart(d Drive) *model.Part {
	p := &model.Part{Kind: "disk", Vendor: d.Manufacturer, Model: d.Model, Serial: d.Serial, Location: driveName(d), Firmware: d.Firmware}
	if d.CapacityBytes > 0 {
		p.Size = units.SI(d.CapacityBytes)
	}
	return p
}

func (c *checker) storage() {
	bad := false
	for i := range c.facts.Drives {
		d := &c.facts.Drives[i]
		if d.Status.Absent() {
			continue
		}
		name := driveName(*d)
		serial := first(d.Serial, "?")
		ev := evidenceKV(name, "Model", d.Model, "Serial", d.Serial, "Health", d.Status.Health, "State", d.Status.State, "FailurePredicted", boolText(d.FailurePredicted), "LifeLeft%", fmtNum(d.LifeLeftPercent, ""))
		replace := model.Tf("Back up the data now. Replace drive %s (serial %s). If it is in a RAID volume, make sure no other member has failed and let the rebuild finish before touching any other drive.",
			"Sao lưu dữ liệu ngay. Thay ổ %s (serial %s). Nếu ổ nằm trong RAID, kiểm tra không còn ổ thành viên nào khác bị lỗi và chờ rebuild xong rồi mới đụng đến ổ khác.", name, serial)
		pred := d.FailurePredicted != nil && *d.FailurePredicted
		hs := d.Status.Sev()
		switch {
		case hs == model.Crit:
			d.Severity = model.Crit
			c.add(model.Finding{
				ID: domain + ".drive_failed", Component: model.CompDisk, Severity: model.Crit, Target: name, Evidence: ev, Part: drivePart(*d), Action: replace,
				Title:  model.Tf("Drive %s has failed", "Ổ %s bị hỏng", name),
				Detail: model.T("The BMC reports this drive's health as Critical (failed, offline or unreadable), as seen by its RAID controller or by the drive itself.", "BMC báo tình trạng ổ này là Critical (hỏng, offline hoặc không đọc được), theo controller RAID hoặc chính ổ cứng."),
			})
			bad = true
		case pred:
			d.Severity = model.Crit
			c.add(model.Finding{
				ID: domain + ".drive_predicted_failure", Component: model.CompDisk, Severity: model.Crit, Target: name, Evidence: ev, Part: drivePart(*d), Action: replace,
				Title:  model.Tf("Drive %s is predicted to fail", "Ổ %s được dự báo sắp hỏng", name),
				Detail: model.T("The drive's own S.M.A.R.T. self-monitoring tripped its failure prediction, as reported by the controller. Drives in this state usually fail within days to weeks.", "Cơ chế tự giám sát S.M.A.R.T. của ổ đã báo dự đoán hỏng (controller ghi nhận). Ổ ở trạng thái này thường hỏng trong vài ngày đến vài tuần."),
			})
			bad = true
		}
		if d.Severity == model.Crit {
			continue
		}
		// Some BMCs fill PredictedMediaLifeLeftPercent with 0 for hard
		// disks, which have no flash to wear out.
		if l := d.LifeLeftPercent; l != nil && *l <= wearWarnPct && !strings.EqualFold(d.MediaType, "HDD") {
			sev := model.Warn
			if *l <= wearCritPct {
				sev = model.Crit
			}
			d.Severity = sev
			c.add(model.Finding{
				ID: domain + ".ssd_wear", Component: model.CompDisk, Severity: sev, Target: name, Evidence: ev, Part: drivePart(*d),
				Title:  model.Tf("SSD %s has %.0f%% of its rated life left", "SSD %s chỉ còn %.0f%% tuổi thọ ghi", name, *l),
				Detail: model.T("Flash wears out with writes; near the end of its rated endurance an SSD may switch to read-only or fail.", "Chip flash mòn dần theo lượng dữ liệu ghi; gần hết độ bền định mức, SSD có thể chuyển sang chỉ đọc hoặc hỏng."),
				Action: model.Tf("Plan the replacement of SSD %s (serial %s) and order the part now. Make sure backups are current.", "Lên kế hoạch thay SSD %s (serial %s) và đặt linh kiện ngay. Đảm bảo bản sao lưu luôn mới.", name, serial),
			})
			bad = true
			continue
		}
		if hs == model.Warn {
			d.Severity = model.Warn
			c.add(model.Finding{
				ID: domain + ".drive_warning", Component: model.CompDisk, Severity: model.Warn, Target: name, Evidence: ev, Part: drivePart(*d),
				Title:  model.Tf("Drive %s reports a warning", "Ổ %s đang báo cảnh báo", name),
				Detail: model.T("The BMC rates this drive's health as Warning (media errors, predictive alerts or a rebuild in progress).", "BMC đánh giá ổ này ở mức Warning (lỗi bề mặt, cảnh báo dự đoán hoặc đang rebuild)."),
				Action: model.Tf("Check drive %s in the BMC storage page and the event log for the reason; make sure backups are current and prepare a replacement (serial %s).", "Xem chi tiết ổ %s trên trang Storage của BMC và nhật ký sự kiện để biết lý do; đảm bảo sao lưu đầy đủ và chuẩn bị ổ thay thế (serial %s).", name, serial),
			})
			bad = true
		}
	}
	byRef := map[string]Drive{}
	for _, d := range c.facts.Drives {
		if d.ref != "" {
			byRef[d.ref] = d
		}
	}
	for i := range c.facts.Volumes {
		v := &c.facts.Volumes[i]
		if v.Status.Absent() {
			continue
		}
		name := first(v.Name, v.ID)
		raid := first(v.RAID, "RAID")
		ev := evidenceKV(name, "RAIDType", v.RAID, "Health", v.Status.Health, "State", v.Status.State, "RaidStatus", v.RaidStatus, "Rebuild%", fmtNum(v.RebuildPct, ""))
		rs := strings.ToLower(v.RaidStatus)
		failed := rs == "failed" || rs == "offline"
		degraded := rs == "degraded" || strings.EqualFold(v.Status.State, "Degraded") || v.Status.Sev() == model.Crit
		// A Warning volume with a failed or missing member drive is degraded:
		// that is how Dell and HPE report a RAID that lost redundancy.
		for _, m := range v.members {
			if d, ok := byRef[m]; ok && v.Status.Sev() == model.Warn && (d.Severity == model.Crit || d.Status.Absent()) {
				degraded = true
			}
		}
		f := model.Finding{Component: model.CompRAID, Target: name, Evidence: ev}
		switch {
		case failed:
			f.ID, f.Severity = domain+".raid_failed", model.Crit
			f.Title = model.Tf("RAID volume %s (%s) has failed", "RAID %s (%s) đã hỏng", name, raid)
			f.Action = model.T("Do not initialise or recreate the volume. Stop writes, note which drives failed and in what order, and contact the vendor or a data-recovery service before replacing anything; restore from backup if needed.",
				"Không khởi tạo lại hay tạo lại volume. Ngừng ghi dữ liệu, ghi lại ổ nào hỏng và thứ tự hỏng, liên hệ hãng hoặc dịch vụ cứu dữ liệu trước khi thay bất cứ thứ gì; khôi phục từ bản sao lưu nếu cần.")
		case v.Rebuilding:
			f.ID, f.Severity = domain+".raid_rebuilding", model.Warn
			pct := ""
			if v.RebuildPct != nil {
				pct = fmt.Sprintf(" (%.0f%%)", *v.RebuildPct)
			}
			f.Title = model.Tf("RAID volume %s is rebuilding%s", "RAID %s đang rebuild%s", name, pct)
			f.Action = model.T("Avoid heavy I/O and do not remove any drive until the rebuild finishes; check again later.", "Hạn chế tải I/O nặng và không rút ổ nào cho đến khi rebuild xong; kiểm tra lại sau.")
		case degraded:
			f.ID, f.Severity = domain+".raid_degraded", model.Crit
			f.Title = model.Tf("RAID volume %s (%s) is degraded", "RAID %s (%s) đang bị suy giảm (degraded)", name, raid)
			f.Detail = model.T("The volume has lost redundancy: one more drive failure can lose its data.", "Volume đã mất khả năng dự phòng: hỏng thêm một ổ nữa là có thể mất dữ liệu.")
			f.Action = model.T("Back up the data now. Find the failed or missing member drive (see the drive findings and the BMC storage page), replace it, and check that the rebuild starts and completes.",
				"Sao lưu dữ liệu ngay. Tìm ổ thành viên bị lỗi hoặc bị rút (xem cảnh báo về ổ và trang Storage trên BMC), thay ổ và kiểm tra rebuild đã chạy và chạy xong.")
		case v.Status.Sev() == model.Warn:
			f.ID, f.Severity = domain+".raid_warning", model.Warn
			f.Title = model.Tf("RAID volume %s (%s) reports a warning", "RAID %s (%s) đang báo cảnh báo", name, raid)
			f.Detail = model.T("On most controllers a Warning volume is degraded or running a background task that needs attention.", "Trên đa số controller, volume ở mức Warning nghĩa là đang suy giảm hoặc có tác vụ nền cần chú ý.")
			f.Action = model.T("Check the volume and its member drives in the BMC storage page; if a member is missing or failed, back up and replace it.", "Xem volume và các ổ thành viên trên trang Storage của BMC; nếu có ổ bị thiếu hoặc hỏng, sao lưu rồi thay ổ.")
		default:
			continue
		}
		v.Severity = f.Severity
		bad = true
		c.add(f)
	}
	driveSev := map[string]model.Severity{}
	for _, d := range c.facts.Drives {
		if d.Serial != "" {
			driveSev[strings.ToLower(d.Serial)] = d.Severity
		}
	}
	for _, ct := range c.facts.Controllers {
		// An NVMe drive is its own controller: HPE and Dell list a
		// "controller" with the drive's serial for each one. The drive
		// finding already covers it.
		if ds, ok := driveSev[strings.ToLower(ct.Serial)]; ok && ct.Serial != "" && ds >= ct.Status.Sev() {
			continue
		}
		name := first(ct.Name, ct.Model, "controller")
		part := &model.Part{Kind: "controller", Model: ct.Model, Serial: ct.Serial, Firmware: ct.Firmware, Location: name}
		ev := evidenceKV(name, "Model", ct.Model, "Health", ct.Status.Health, "State", ct.Status.State, "CacheHealth", ct.Cache.Health, "Firmware", ct.Firmware)
		if hs := ct.Status.Sev(); hs > model.OK {
			id := domain + ".controller_warning"
			title := model.Tf("Storage controller %s reports a warning", "Controller lưu trữ %s đang báo cảnh báo", name)
			if hs == model.Crit {
				id = domain + ".controller_failed"
				title = model.Tf("Storage controller %s has failed", "Controller lưu trữ %s bị lỗi nghiêm trọng", name)
			}
			c.add(model.Finding{
				ID: id, Component: model.CompRAID, Severity: hs, Target: name, Evidence: ev, Part: part, Title: title,
				Action: model.Tf("Check the controller in the BMC storage page and the event log; update the controller firmware. If it keeps reporting errors, ask the vendor to replace it (serial %s).",
					"Xem controller trên trang Storage của BMC và nhật ký sự kiện; cập nhật firmware controller. Nếu vẫn báo lỗi, liên hệ hãng để thay controller (serial %s).", first(ct.Serial, "?")),
			})
			bad = true
		}
		if ct.Cache.Sev() > model.OK {
			c.add(model.Finding{
				ID: domain + ".controller_cache", Component: model.CompRAID, Severity: model.Warn, Target: name, Evidence: ev, Part: &model.Part{Kind: "battery", Location: name + " cache"},
				Title:  model.Tf("Cache/battery of controller %s reports %s", "Bộ nhớ đệm/pin của controller %s báo %s", name, ct.Cache.Health),
				Detail: model.T("A failed cache battery or capacitor disables write-back caching (slower writes) and can lose cached writes on a power cut.", "Pin hoặc tụ của bộ nhớ đệm hỏng sẽ tắt chế độ write-back (ghi chậm hơn) và có thể mất dữ liệu đang đệm khi mất điện."),
				Action: model.T("Replace the cache battery / supercapacitor module and update the controller firmware.", "Thay module pin/tụ bộ nhớ đệm (BBU/supercap) và cập nhật firmware controller."),
			})
			bad = true
		}
	}
	for i := range c.facts.Batteries {
		if c.battery(&c.facts.Batteries[i]) {
			bad = true
		}
	}
	n := 0
	for _, d := range c.facts.Drives {
		if !d.Status.Absent() {
			n++
		}
	}
	if !bad && n > 0 {
		title := model.Text{
			EN: fmt.Sprintf("%s and %s healthy", plural(n, "drive", "drives"), plural(len(c.facts.Volumes), "RAID volume", "RAID volumes")+" are"),
			VI: fmt.Sprintf("%d ổ cứng và %d volume RAID đều bình thường", n, len(c.facts.Volumes)),
		}
		if len(c.facts.Volumes) == 0 {
			title = model.Text{EN: plural(n, "drive is", "drives are") + " healthy", VI: fmt.Sprintf("%d ổ cứng đều bình thường", n)}
		}
		c.add(model.Finding{ID: domain + ".storage_ok", Component: model.CompDisk, Severity: model.OK, Title: title})
	}
}

// battery reports a failed HPE Smart Storage Battery: Warn, the contract's
// level for a controller battery/cache problem (writes slow down and the
// cache is no longer protected, but no data is lost while power stays on).
func (c *checker) battery(b *Battery) bool {
	cond := strings.ToLower(b.Condition)
	bad := b.Status.Sev() > model.OK || (cond != "" && cond != "ok" && cond != "charging")
	if !bad {
		return false
	}
	b.Severity = model.Warn
	state := first(b.Condition, b.Status.Health)
	c.add(model.Finding{
		ID: domain + ".storage_battery", Component: model.CompRAID, Severity: model.Warn, Target: b.Name,
		Part:     &model.Part{Kind: "battery", Vendor: "HPE", Model: first(b.Model, b.Spare), Serial: b.Serial, Location: b.Name, Firmware: b.Firmware},
		Evidence: evidenceKV(b.Name, "Condition", b.Condition, "Health", b.Status.Health, "State", b.Status.State, "Model", b.Model, "Spare", b.Spare, "Serial", b.Serial),
		Title:    model.Tf("Controller cache battery %s reports %s", "Pin bộ nhớ đệm controller %s báo %s", b.Name, state),
		Detail: model.T("This battery backs the Smart Array write cache. While it is failed the controller turns write caching off (slower writes) and cached writes are no longer protected against a power cut. iLO raises the server's overall health to Warning for it.",
			"Pin này bảo vệ bộ nhớ đệm ghi (write cache) của controller Smart Array. Khi pin hỏng, controller tắt write cache (ghi chậm hơn) và dữ liệu đang đệm không còn được bảo vệ khi mất điện. iLO vì thế báo tình trạng tổng thể của server là Warning."),
		Action: model.Tf("Replace the HPE Smart Storage Battery (part %s, spare %s, serial %s), then check in iLO that the battery warning has cleared.",
			"Thay pin HPE Smart Storage Battery (part %s, mã spare %s, serial %s), sau đó kiểm tra trên iLO cảnh báo pin đã hết.", first(b.Model, "?"), first(b.Spare, "?"), first(b.Serial, "?")),
	})
	return true
}

func boolText(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

// --- memory, cpu, bmc, nic ---------------------------------------------

func (c *checker) memory() {
	bad := false
	var total float64
	for i := range c.facts.DIMMs {
		d := &c.facts.DIMMs[i]
		total += d.CapacityMiB
		hs := d.Status.Sev()
		d.Severity = hs
		if hs == model.OK {
			continue
		}
		bad = true
		part := &model.Part{Kind: "dimm", Vendor: d.Manufacturer, Model: d.PartNumber, Serial: d.Serial, Location: d.Slot}
		if d.CapacityMiB > 0 {
			part.Size = units.IEC(uint64(d.CapacityMiB) << 20)
		}
		f := model.Finding{
			Component: model.CompMemory, Severity: hs, Target: d.Slot, Part: part,
			Evidence: evidenceKV(d.Slot, "Health", d.Status.Health, "State", d.Status.State, "Part", d.PartNumber, "Serial", d.Serial),
			Action: model.Tf("Check the BMC event log for ECC errors on slot %s. Replace the DIMM in slot %s (serial %s, part %s); for a one-off error, reseating it may be enough.",
				"Xem nhật ký sự kiện BMC về lỗi ECC của khe %s. Thay thanh RAM ở khe %s (serial %s, part %s); nếu chỉ lỗi một lần, có thể thử tháo lắp lại.", d.Slot, d.Slot, first(d.Serial, "?"), first(d.PartNumber, "?")),
		}
		if hs == model.Crit {
			f.ID = domain + ".dimm_failed"
			f.Title = model.Tf("Memory module %s has failed", "Thanh RAM %s bị lỗi nghiêm trọng", d.Slot)
			f.Detail = model.T("The BMC rates this DIMM Critical: typically uncorrectable ECC errors, or the module was disabled by the BIOS.", "BMC đánh giá thanh RAM này ở mức Critical: thường do lỗi ECC không sửa được, hoặc BIOS đã vô hiệu hóa thanh RAM.")
		} else {
			f.ID = domain + ".dimm_warning"
			f.Title = model.Tf("Memory module %s reports a warning", "Thanh RAM %s đang báo cảnh báo", d.Slot)
			f.Detail = model.T("The BMC rates this DIMM Warning: typically a rising rate of correctable ECC errors.", "BMC đánh giá thanh RAM này ở mức Warning: thường do lỗi ECC sửa được tăng nhanh.")
		}
		c.add(f)
	}
	if !bad && len(c.facts.DIMMs) > 0 {
		c.add(model.Finding{
			ID: domain + ".memory_ok", Component: model.CompMemory, Severity: model.OK,
			Title: model.Text{
				EN: fmt.Sprintf("%s healthy (%s)", plural(len(c.facts.DIMMs), "memory module is", "memory modules are"), units.IEC(uint64(total)<<20)),
				VI: fmt.Sprintf("%d thanh RAM đều bình thường (%s)", len(c.facts.DIMMs), units.IEC(uint64(total)<<20)),
			},
		})
	}
}

func (c *checker) cpus() {
	for _, p := range c.facts.CPUs {
		hs := p.Status.Sev()
		if hs == model.OK {
			continue
		}
		id := domain + ".cpu_warning"
		if hs == model.Crit {
			id = domain + ".cpu_failed"
		}
		c.add(model.Finding{
			ID: id, Component: model.CompCPU, Severity: hs, Target: p.Socket,
			Title:    model.Tf("Processor %s reports %s", "CPU %s báo %s", p.Socket, p.Status.Health),
			Evidence: evidenceKV(p.Socket, "Model", p.Model, "Health", p.Status.Health, "State", p.Status.State),
			Part:     &model.Part{Kind: "cpu", Model: p.Model, Location: p.Socket},
			Action: model.T("Check the BMC event log for machine-check (IERR/MCE) or thermal-trip events on this CPU. Update the BIOS and BMC firmware; if the error persists, contact the vendor.",
				"Xem nhật ký sự kiện BMC có lỗi machine check (IERR/MCE) hoặc quá nhiệt của CPU này không. Cập nhật BIOS và firmware BMC; nếu vẫn lỗi, liên hệ hãng."),
		})
	}
}

func (c *checker) managers() {
	for _, m := range c.facts.Managers {
		hs := m.Status.Sev()
		if hs == model.OK {
			continue
		}
		name := first(m.Model, m.ID)
		c.add(model.Finding{
			ID: domain + ".bmc_health", Component: model.CompBMC, Severity: hs, Target: name,
			Title:    model.Tf("The BMC (%s) reports its own health as %s", "BMC (%s) tự báo tình trạng %s", name, m.Status.Health),
			Evidence: evidenceKV(name, "Firmware", m.FirmwareVersion, "Health", m.Status.Health, "State", m.Status.State),
			Action: model.T("Reset the BMC (resetting iDRAC/iLO/XCC does not affect the running OS), then update the BMC firmware. If the health stays bad, contact the vendor.",
				"Reset BMC (reset iDRAC/iLO/XCC không ảnh hưởng hệ điều hành đang chạy), sau đó cập nhật firmware BMC. Nếu tình trạng không cải thiện, liên hệ hãng."),
		})
	}
}

func (c *checker) nics() {
	for _, n := range c.facts.NICs {
		if n.Status.Sev() == model.OK {
			continue
		}
		c.add(model.Finding{
			ID: domain + ".nic_health", Component: model.CompNetwork, Severity: model.Warn, Target: n.Name,
			Title:    model.Tf("Network interface %s reports %s", "Card mạng %s báo %s", n.Name, n.Status.Health),
			Evidence: evidenceKV(n.Name, "MAC", n.MAC, "LinkStatus", n.LinkStatus, "Health", n.Status.Health, "State", n.Status.State),
			Action: model.T("Check the cable, the transceiver and the switch port; update the NIC firmware; replace the adapter if errors continue.",
				"Kiểm tra cáp mạng, module quang/transceiver và cổng switch; cập nhật firmware card mạng; nếu vẫn lỗi thì thay card."),
		})
	}
}

// --- events -------------------------------------------------------------

// maxEventFindings limits individual event findings; the table lists all.
const maxEventFindings = 15

func (c *checker) eventFindings() {
	shown, info := 0, 0
	for _, g := range c.facts.Events {
		if g.Severity <= model.Info {
			info++
			continue
		}
		if shown >= maxEventFindings {
			info++
			continue
		}
		shown++
		last := model.T("time unknown (BMC clock not set)", "không rõ thời điểm (đồng hồ BMC chưa đặt)")
		if g.Last != nil {
			ago := units.Duration(c.env.Now.Sub(*g.Last))
			last = model.Text{
				EN: fmt.Sprintf("%s, %s ago", c.when(*g.Last), ago.EN),
				VI: fmt.Sprintf("%s, %s trước", c.when(*g.Last), ago.VI),
			}
		}
		msg := g.Message
		if r := []rune(msg); len(r) > 140 {
			msg = string(r[:140]) + "…"
		}
		id := domain + ".event_warning"
		if g.Severity == model.Crit {
			id = domain + ".event_critical"
		}
		c.add(model.Finding{
			ID: id, Component: g.Component, Severity: g.Severity, Target: first(g.MessageID, g.Log),
			Title: model.Text{
				EN: fmt.Sprintf("BMC log: %s (%d×, last %s)", msg, g.Count, last.EN),
				VI: fmt.Sprintf("Nhật ký BMC: %s (%d lần, lần cuối %s)", msg, g.Count, last.VI),
			},
			Detail: model.Tf("%s event in the %s log, message ID %s. Events from the last %d days are treated as current.",
				"Sự kiện mức %s trong nhật ký %s, mã %s. Sự kiện trong %d ngày gần đây được coi là vấn đề hiện tại.", g.Raw, g.Log, first(g.MessageID, "-"), recentDays),
			Action: model.T("Read the full entry in the BMC log and fix its cause; the finding for the matching part (power supply, fan, drive, DIMM) says what to replace. If that part looks healthy now, the fault is intermittent: keep watching.",
				"Đọc chi tiết sự kiện trong nhật ký BMC và xử lý nguyên nhân; cảnh báo của linh kiện tương ứng (nguồn, quạt, ổ cứng, RAM) cho biết cần thay gì. Nếu linh kiện hiện đã bình thường thì đây là lỗi chập chờn: tiếp tục theo dõi."),
			Evidence: units.Evidence([]string{fmt.Sprintf("[%s] %s %s: %s", g.Log, g.Raw, g.MessageID, g.Message)}, 10),
		})
	}
	if info > 0 {
		c.add(model.Finding{
			ID: domain + ".event_history", Component: model.CompLogs, Severity: model.Info,
			Title:  model.Tf("%d more BMC event type(s) in the last %d days: older than %d days, repaired or recovered, or beyond the list", "Còn %d loại sự kiện BMC khác trong %d ngày qua: cũ hơn %d ngày, đã sửa hoặc đã tự hết, hoặc vượt quá danh sách hiển thị", info, c.facts.WindowDays, recentDays),
			Detail: model.T("They are listed in the BMC events table. Old faults that are fixed need no action; a fault that keeps coming back does.", "Các sự kiện này nằm trong bảng sự kiện BMC. Lỗi cũ đã khắc phục thì không cần làm gì; lỗi lặp lại nhiều lần thì cần xử lý."),
		})
	}
	if len(c.facts.Events) == 0 && c.logsRead {
		c.add(model.Finding{
			ID: domain + ".logs_ok", Component: model.CompLogs, Severity: model.OK,
			Title: model.Tf("No critical or warning events in the BMC logs in the last %d days", "Không có sự kiện nghiêm trọng hay cảnh báo nào trong nhật ký BMC %d ngày qua", c.facts.WindowDays),
		})
	}
}

// when shows an event time in the reader's time zone (that of env.Now):
// BMCs stamp entries in their own zone (iDRAC "-05:00", iLO "Z"), and a
// table mixing zones without saying so misleads.
func (c *checker) when(t time.Time) string {
	if loc := c.env.Now.Location(); !c.env.Now.IsZero() && loc != nil {
		t = t.In(loc)
	}
	return t.Format("2006-01-02 15:04 MST")
}

// plural formats "1 fan" / "3 fans" (English only; Vietnamese has no plural).
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
