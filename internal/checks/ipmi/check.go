// Package ipmi is the "ipmi" domain check: it reads the BMC (iDRAC, iLO,
// XCC, Supermicro...) through ipmitool: sensor records (SDR), the system
// event log (SEL), chassis status, FRU inventory, LAN settings and DCMI
// power. The same section names are written in-band (Linux, Windows) and by
// the out-of-band BMC collector, so the parser never depends on env.OS.
package ipmi

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "ipmi"

// Facts is the typed data of this domain.
type Facts struct {
	BMC        BMC       `json:"bmc"`
	System     *System   `json:"system,omitempty"`
	Sensors    []*Sensor `json:"sensors,omitempty"`
	PSUs       []*PSU    `json:"psus,omitempty"`
	SEL        *SELInfo  `json:"sel,omitempty"`
	Events     []Event   `json:"events,omitempty"`
	Chassis    *Chassis  `json:"chassis,omitempty"`
	PowerWatts *float64  `json:"powerWatts,omitempty"`
	FRUs       []*FRU    `json:"frus,omitempty"`
	// BMCClockOffset is BMC clock minus collection time, in seconds
	// (includes the host's UTC offset: ipmitool prints local time).
	BMCClockOffset *int64 `json:"bmcClockOffsetSec,omitempty"`
	Window         int    `json:"windowDays"`
}

// System is the board/product identity from FRU 0.
type System struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Serial       string `json:"serial,omitempty"`
	BoardSerial  string `json:"boardSerial,omitempty"`
}

// Event is one grouped SEL event kind.
type Event struct {
	Sensor    string         `json:"sensor"`
	Event     string         `json:"event"`
	Class     string         `json:"class"`
	Count     int            `json:"count"`
	Recent    int            `json:"recent"`
	First     *time.Time     `json:"first,omitempty"`
	Last      *time.Time     `json:"last,omitempty"`
	Recovered bool           `json:"recovered,omitempty"`
	Severity  model.Severity `json:"severity"`
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	if len(b.Prefix("ipmi.")) == 0 {
		return res
	}
	c := &checker{b: b, env: env, res: &res}
	// SEL window: the log window, but at least 30 days — BMC events are
	// rare and a PSU or DIMM fault from three weeks ago still matters.
	c.window = env.SinceDays
	if c.window < 30 {
		c.window = 30
	}
	c.facts.Window = c.window
	c.devices()
	c.identity()
	c.sdr()
	c.chassis()
	c.selInfo()
	c.sel()
	c.coverage()
	res.Facts = c.facts
	return res
}

type checker struct {
	b      *collect.Bundle
	env    model.Env
	res    *model.Result
	facts  Facts
	window int

	evidence bool // a BMC is known to exist
	sensors  []*Sensor
	psus     []*PSU
	frus     []*FRU
	psuFRU   map[int]*FRU
	// sdrIdx maps a sensor to the index of its current-state finding, so a
	// SEL event on the same sensor can be folded into it (foldSEL).
	sdrIdx map[*Sensor]int

	sdrParsed, selParsed, chassisParsed bool
}

func (c *checker) add(f model.Finding) { c.res.Findings = append(c.res.Findings, f) }

// ---- identity ----

func (c *checker) devices() {
	if c.env.OS == collect.OSBMC {
		c.evidence = true
	}
	if s := c.b.Get("ipmi.devices"); s.Ran() {
		kv := s.KV()
		c.facts.BMC.Device = kv["node"]
		c.facts.BMC.Interface = kv["dmi_interface"]
		c.facts.BMC.Tool = kv["ipmitool_version"]
		if kv["smbios38"] == "1" || kv["dmi_interface"] != "" || kv["node"] != "" || kv["class"] != "" ||
			kv["module_ipmi_si"] != "" || kv["module_ipmi_ssif"] != "" {
			c.evidence = true
		}
	}
	if s := c.b.Get("ipmi.win_devices"); s.Ran() {
		var d []struct {
			PNP []struct {
				Name string `json:"Name"`
			} `json:"pnp"`
			WMI *int `json:"wmiIpmi"`
		}
		if collect.DecodeJSON(s.Out, &d) == nil && len(d) > 0 {
			if len(d[0].PNP) > 0 || (d[0].WMI != nil && *d[0].WMI > 0) {
				c.evidence = true
			}
			if len(d[0].PNP) > 0 {
				c.facts.BMC.Interface = d[0].PNP[0].Name
			}
		}
	}
}

func (c *checker) identity() {
	if s := c.b.Get("ipmi.mc"); s.Ran() && parseMC(s.Out, &c.facts.BMC) {
		c.evidence = true
	}
	lanOK := false
	if s := c.b.Get("ipmi.lan"); s.Ran() {
		lanOK = parseLAN(s.Out, &c.facts.BMC)
	}
	if s := c.b.Get("ipmi.fru"); s.Ran() {
		c.frus = parseFRU(s.Out)
		c.facts.FRUs = c.frus
		for _, f := range c.frus {
			if f.ID == 0 && !f.Absent {
				c.facts.System = &System{
					Manufacturer: f.get("Product Manufacturer", "Board Mfg"),
					Product:      f.get("Product Name", "Board Product"),
					Serial:       f.get("Product Serial", "Chassis Serial"),
					BoardSerial:  f.get("Board Serial"),
				}
			}
		}
		c.psuFRU = psuFRUs(c.frus)
	}
	if s := c.b.Get("ipmi.power"); s.Ran() {
		c.facts.PowerWatts = parsePower(s.Out)
	}
	bm := c.facts.BMC
	if bm.Firmware == "" && !lanOK {
		return
	}
	vendor := firstNonEmpty(bm.Manufacturer, "BMC")
	addr := bm.Address
	noIP := lanOK && (addr == "" || addr == "0.0.0.0")
	en := fmt.Sprintf("BMC answers: %s, firmware %s", vendor, firstNonEmpty(bm.Firmware, "?"))
	vi := fmt.Sprintf("BMC phản hồi: %s, firmware %s", vendor, firstNonEmpty(bm.Firmware, "?"))
	if lanOK && !noIP {
		en += fmt.Sprintf(", management IP %s (%s)", addr, firstNonEmpty(bm.IPSource, "?"))
		vi += fmt.Sprintf(", IP quản trị %s (%s)", addr, firstNonEmpty(bm.IPSource, "?"))
	}
	tgt := "BMC"
	if lanOK && !noIP {
		tgt = addr
	}
	f := model.Finding{ID: domain + ".bmc_ok", Component: model.CompBMC, Severity: model.OK, Target: tgt,
		Title: model.T(en, vi)}
	if bm.MAC != "" {
		f.Evidence = []string{"MAC " + bm.MAC}
	}
	c.add(f)
	if noIP {
		c.add(model.Finding{ID: domain + ".bmc_no_ip", Component: model.CompBMC, Severity: model.Info, Target: "BMC",
			Title: model.T("The BMC has no network address", "BMC chưa có địa chỉ mạng"),
			Detail: model.T("Without an IP address the BMC (iDRAC/iLO/XCC) cannot be reached when the OS is down, so remote power control, console and hardware logs are unavailable.",
				"Không có IP thì không truy cập được BMC (iDRAC/iLO/XCC) khi hệ điều hành bị treo: mất khả năng bật/tắt máy, xem màn hình và nhật ký phần cứng từ xa."),
			Action: model.T("Give it an address on the management network: ipmitool lan set 1 ipsrc static; ipmitool lan set 1 ipaddr <IP>; ipmitool lan set 1 netmask <mask>; ipmitool lan set 1 defgw ipaddr <gateway> (or ipmitool lan set 1 ipsrc dhcp).",
				"Đặt địa chỉ trong mạng quản trị: ipmitool lan set 1 ipsrc static; ipmitool lan set 1 ipaddr <IP>; ipmitool lan set 1 netmask <mask>; ipmitool lan set 1 defgw ipaddr <gateway> (hoặc ipmitool lan set 1 ipsrc dhcp)."),
			Evidence: []string{"IP Address Source : " + bm.IPSource, "IP Address : " + addr},
		})
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// ---- SDR ----

var genericNames = map[string]bool{"status": true, "presence": true, "temp": true, "current": true, "voltage": true, "ambient temp": true}

func sensorTarget(s *Sensor) string {
	if genericNames[strings.ToLower(s.Name)] && s.Entity != "" {
		return s.Name + " (entity " + s.Entity + ")"
	}
	// Dell's aggregate "Drive" sensor names no slot: the entity (26 = disk
	// drive bay, instance) is all the SDR says about where it is.
	if s.Class == clDisk && !hasInstance(s.Name) && s.Entity != "" {
		return s.Name + " (entity " + s.Entity + ")"
	}
	return s.Name
}

var statusMeaning = map[string]model.Text{
	"lnc": model.T("below its lower warning threshold", "dưới ngưỡng cảnh báo dưới"),
	"unc": model.T("above its upper warning threshold", "trên ngưỡng cảnh báo trên"),
	"nc":  model.T("past a warning threshold", "vượt ngưỡng cảnh báo"),
	"lcr": model.T("below its lower critical threshold", "dưới ngưỡng tới hạn dưới"),
	"ucr": model.T("above its upper critical threshold", "trên ngưỡng tới hạn trên"),
	"cr":  model.T("past a critical threshold", "vượt ngưỡng tới hạn"),
	"lnr": model.T("below its lower non-recoverable threshold", "dưới ngưỡng không phục hồi dưới"),
	"unr": model.T("above its upper non-recoverable threshold", "trên ngưỡng không phục hồi trên"),
	"nr":  model.T("past a non-recoverable threshold", "vượt ngưỡng không phục hồi"),
}

func (c *checker) sdr() {
	s := c.b.Get("ipmi.sdr")
	if !s.Ran() {
		return
	}
	c.sensors = parseSDR(s.Out)
	c.sdrParsed = len(c.sensors) > 0
	if !c.sdrParsed {
		return
	}
	c.facts.Sensors = c.sensors
	c.psus = buildPSUs(c.sensors)
	for _, p := range c.psus {
		if f := c.psuFRU[p.Number]; f != nil {
			p.Vendor = f.get("Board Mfg", "Product Manufacturer")
			p.Model = f.get("Board Product", "Product Name")
			p.PartNumber = f.get("Board Part Number", "Product Part Number", "Part Number")
			p.Serial = f.get("Board Serial", "Product Serial", "Serial Number")
		}
	}
	c.facts.PSUs = c.psus
	c.sdrIdx = map[*Sensor]int{}

	seen := map[string]bool{}
	worst := model.OK
	readable := 0
	single := c.singlePSU()
	for _, sn := range c.sensors {
		if sn.Readable() {
			readable++
		}
		if single && sn.key == "redundancy_lost" && sn.Severity == model.Warn && (sn.Class == clPowerUnit || sn.Class == clPSU) {
			sn.Severity = model.Info
			c.add(singlePSUFinding(sensorTarget(sn), []string{sn.line}))
			continue
		}
		if sn.Severity >= model.Warn {
			worst = model.Worst(worst, sn.Severity)
		}
		f, ok := c.sensorFinding(sn)
		if !ok {
			continue
		}
		k := f.ID + "\x00" + f.Target
		if seen[k] {
			// same problem reported by several sensors of one PSU: keep the evidence
			for i := range c.res.Findings {
				if c.res.Findings[i].ID == f.ID && c.res.Findings[i].Target == f.Target {
					c.sdrIdx[sn] = i
					if len(c.res.Findings[i].Evidence) < 10 {
						c.res.Findings[i].Evidence = append(c.res.Findings[i].Evidence, sn.line)
					}
				}
			}
			continue
		}
		seen[k] = true
		c.add(f)
		c.sdrIdx[sn] = len(c.res.Findings) - 1
	}
	if worst < model.Warn && readable > 0 {
		c.add(model.Finding{ID: domain + ".sensors_ok", Component: model.CompBMC, Severity: model.OK,
			Title: model.Tf("All %d readable BMC sensors are within their thresholds", "Tất cả %d cảm biến BMC đọc được đều trong ngưỡng", readable)})
	}
	c.psuSummary()
	c.sdrTables()
}

// singlePSU: exactly one supply is known to be present, every other bay
// the BMC knows of is empty, and the present one is healthy. Dell iDRAC
// keeps reporting "Redundancy Lost" on such a server while its power
// redundancy policy is "PSU Redundant" (the default), which is a setting,
// not a fault.
func (c *checker) singlePSU() bool {
	present := 0
	for _, p := range c.psus {
		switch {
		case p.Present == nil:
			return false
		case *p.Present:
			present++
			if p.Failed || p.InputLost || p.Predictive {
				return false
			}
		}
	}
	return present == 1
}

func singlePSUFinding(target string, ev []string) model.Finding {
	return model.Finding{ID: domain + ".redundancy_lost", Component: model.CompPower, Severity: model.Info, Target: target,
		Title: model.Tf("%s: no power redundancy, only one power supply is installed", "%s: không có nguồn dự phòng vì máy chỉ lắp một bộ nguồn", target),
		Detail: model.T("The BMC reports redundancy lost because only one PSU is fitted while its redundancy policy expects two. The server runs normally, but one PSU or power-feed failure takes it down.",
			"BMC báo mất dự phòng vì máy chỉ lắp một bộ nguồn trong khi chính sách nguồn của BMC yêu cầu hai. Máy vẫn chạy bình thường, nhưng chỉ cần bộ nguồn hoặc đường điện đó hỏng là máy sập."),
		Action: model.T("If the server should be redundant, install a second PSU of the same model and plug it into a separate power feed. Otherwise set the power redundancy policy to \"Not Redundant\" in the BMC (iDRAC: Configuration > Power Management) to clear the warning.",
			"Nếu máy cần nguồn dự phòng, lắp thêm bộ nguồn cùng model và cắm vào một đường điện riêng. Nếu không, đặt chính sách nguồn thành \"Not Redundant\" trong BMC (iDRAC: Configuration > Power Management) để tắt cảnh báo."),
		Evidence: ev}
}

func (c *checker) psuOf(name string, entityID, instance int) *PSU {
	n := 0
	if entityID == 10 && instance > 0 {
		n = instance
	} else {
		n = psuNumber(name)
	}
	for _, p := range c.psus {
		if p.Number == n {
			return p
		}
	}
	return nil
}

func (c *checker) sensorFinding(sn *Sensor) (model.Finding, bool) {
	threshold := sn.Status != "ok" && sn.Status != "ns" && statusMeaning[sn.Status] != (model.Text{})
	if sn.Severity < model.Warn && !(sn.Severity == model.Info && (strings.HasSuffix(sn.key, "_absent") || sn.key == "psu_inactive")) {
		return model.Finding{}, false
	}
	// A discrete key wins unless the threshold status is worse.
	useKey := sn.key != "" && !(threshold && sn.Severity > judgeKeySev(sn))
	f := model.Finding{Severity: sn.Severity, Evidence: []string{sn.line}}
	target := sensorTarget(sn)
	var psu *PSU
	if sn.Class == clPSU || sn.entityID == 10 {
		if psu = c.psuOf(sn.Name, sn.entityID, sn.instance); psu != nil {
			target = psu.Label()
		}
	}
	reading := firstNonEmpty(sn.Reading, "—")
	if useKey {
		t := textFor(sn.key)
		f.ID = domain + "." + sn.key
		f.Component = sn.comp
		f.Title = model.Tf(t.title.EN, t.title.VI, target)
		f.Detail = model.T(t.detail.EN+" BMC reading: "+reading+".", t.detail.VI+" BMC đọc được: "+reading+".")
		f.Action = t.action
	} else {
		t := thresholdText(sn.Class, sn.Severity == model.Crit)
		m := statusMeaning[sn.Status]
		f.ID = domain + ".sensor_warning"
		if sn.Severity == model.Crit {
			f.ID = domain + ".sensor_critical"
		}
		f.Component = classComponent(sn.Class)
		f.Title = model.Tf(t.title.EN+": %s", t.title.VI+": %s", target, reading)
		f.Detail = model.T(fmt.Sprintf("%s The sensor is %s (status %s).", t.detail.EN, m.EN, sn.Status),
			fmt.Sprintf("%s Cảm biến đang %s (trạng thái %s).", t.detail.VI, m.VI, sn.Status))
		f.Action = t.action
	}
	f.Target = target
	if psu != nil && sn.key != "psu_absent" && (strings.HasPrefix(sn.key, "psu_") || f.Component == model.CompPower) {
		f.Part = psu.part()
	}
	if sn.Class == clFan && (sn.key == "fan_failed" || f.ID == domain+".sensor_critical") {
		f.Part = &model.Part{Kind: "fan", Location: sn.Name}
	}
	if sn.key == "drive_fault" && useKey {
		f.Part = &model.Part{Kind: "disk", Location: target}
	}
	return f, true
}

// judgeKeySev is the severity the discrete states alone give.
func judgeKeySev(sn *Sensor) model.Severity {
	best := model.OK
	for _, st := range sn.States {
		if v := judge(st, sn.Class, sn.Name); v.ok && v.sev > best {
			best = v.sev
		}
	}
	return best
}

func (c *checker) psuSummary() {
	if len(c.psus) == 0 {
		return
	}
	present, bad := 0, 0
	for _, p := range c.psus {
		if p.Present == nil || *p.Present {
			present++
		}
		if p.Severity >= model.Warn {
			bad++
		}
	}
	red := ""
	for _, sn := range c.sensors {
		if sn.Class == clPowerUnit && sn.Readable() {
			for _, st := range sn.States {
				if strings.Contains(strings.ToLower(st), "redundan") {
					red = st
				}
			}
		}
	}
	if bad == 0 && present > 0 {
		en := fmt.Sprintf("%d power supplies present and healthy", present)
		vi := fmt.Sprintf("%d bộ nguồn đang hoạt động bình thường", present)
		if present == 1 {
			en, vi = "1 power supply present and healthy", "1 bộ nguồn đang hoạt động bình thường"
		}
		if red != "" {
			en += " (" + red + ")"
			vi += " (" + red + ")"
		}
		c.add(model.Finding{ID: domain + ".psu_ok", Component: model.CompPower, Severity: model.OK, Title: model.T(en, vi)})
	}
}

func (c *checker) sdrTables() {
	var rows []model.Row
	hidden := 0
	for _, sn := range c.sensors {
		if !sn.Readable() {
			hidden++
			continue
		}
		rows = append(rows, model.Row{Status: sn.Severity, Cells: []string{sn.Name, sn.Class, firstNonEmpty(sn.Reading, "—"), sn.Status}})
	}
	if len(rows) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:      domain + ".sensors",
			Title:   model.T("BMC sensors (IPMI SDR)", "Cảm biến BMC (IPMI SDR)"),
			Columns: []model.Text{model.T("Sensor", "Cảm biến"), model.T("Type", "Loại"), model.T("Reading", "Giá trị"), model.T("Status", "Trạng thái")},
			Rows:    rows,
			Note: model.Tf("%d sensors without a reading (absent parts, disabled sensors) are not listed. Status: ok; lnc/unc = warning; lcr/ucr = critical; lnr/unr = non-recoverable.",
				"Không liệt kê %d cảm biến không có số đo (linh kiện không lắp, cảm biến bị tắt). Trạng thái: ok; lnc/unc = cảnh báo; lcr/ucr = tới hạn; lnr/unr = không phục hồi.", hidden),
		})
	}
	var pr []model.Row
	for _, p := range c.psus {
		state := "present"
		switch {
		case p.Present != nil && !*p.Present:
			state = "absent"
		case p.Failed:
			state = "FAILED"
		case p.InputLost:
			state = "AC lost"
		case p.Predictive:
			state = "predictive failure"
		case p.Present == nil:
			state = "?"
		}
		var rd []string
		if p.Watts != nil {
			rd = append(rd, strconv.FormatFloat(*p.Watts, 'f', -1, 64)+" W")
		}
		if p.Volts != nil {
			rd = append(rd, strconv.FormatFloat(*p.Volts, 'f', -1, 64)+" V")
		}
		if p.Amps != nil {
			rd = append(rd, strconv.FormatFloat(*p.Amps, 'f', -1, 64)+" A")
		}
		model_ := strings.TrimSpace(p.Model + " " + p.PartNumber)
		pr = append(pr, model.Row{Status: p.Severity, Cells: []string{p.Label(), state, strings.Join(p.States, ", "), strings.Join(rd, " / "), firstNonEmpty(model_, "—"), firstNonEmpty(p.Serial, "—")}})
	}
	if len(pr) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    domain + ".psus",
			Title: model.T("Power supplies (BMC)", "Bộ nguồn (BMC)"),
			Columns: []model.Text{model.T("PSU", "Bộ nguồn"), model.T("State", "Tình trạng"), model.T("BMC states", "Trạng thái BMC"),
				model.T("Readings", "Số đo"), model.T("Model / part", "Model / mã linh kiện"), model.T("Serial", "Serial")},
			Rows: pr,
		})
	}
}

// ---- chassis ----

func (c *checker) chassis() {
	s := c.b.Get("ipmi.chassis")
	if !s.Ran() {
		return
	}
	ch, ok := parseChassis(s.Out)
	if !ok {
		return
	}
	c.chassisParsed = true
	c.facts.Chassis = &ch
	ev := func(k string) []string { return []string{k + " : " + ch.Raw[k]} }
	type flag struct {
		on      bool
		key, id string
		sev     model.Severity
		comp    string
		title   model.Text
		detail  model.Text
		action  model.Text
	}
	flags := []flag{
		{ch.MainPowerFault, "Main Power Fault", "chassis_power_fault", model.Crit, model.CompPower,
			model.T("The BMC reports a main power fault", "BMC báo lỗi nguồn chính (Main Power Fault)"),
			model.T("A fault was detected in the main power subsystem (IPMI chassis status).", "Phát hiện lỗi trong hệ thống nguồn chính (trạng thái chassis IPMI)."),
			model.T("Check every power supply (PSU table) and the power feed; replace the failed supply.", "Kiểm tra từng bộ nguồn (bảng PSU) và nguồn điện cấp vào; thay bộ nguồn hỏng.")},
		{ch.Overload, "Power Overload", "chassis_power_overload", model.Crit, model.CompPower,
			model.T("The system was shut down by a power overload", "Hệ thống bị ngắt do quá tải nguồn (Power Overload)"),
			model.T("The BMC reports that power was cut because of an overload.", "BMC báo nguồn đã bị ngắt do quá tải."),
			model.T("Check the power supplies' rating against the installed hardware and look for a shorted component; check the SEL for details.",
				"So sánh công suất bộ nguồn với cấu hình phần cứng, tìm linh kiện bị chập; xem SEL để biết chi tiết.")},
		{ch.ControlFault, "Power Control Fault", "chassis_power_control_fault", model.Warn, model.CompPower,
			model.T("The BMC reports a power control fault", "BMC báo lỗi điều khiển nguồn (Power Control Fault)"),
			model.T("The BMC tried to switch the system power but the system did not reach the requested state.", "BMC đã ra lệnh bật/tắt nguồn nhưng hệ thống không chuyển sang trạng thái yêu cầu."),
			model.T("Check the power supplies and the SEL; contact the vendor if it repeats.", "Kiểm tra bộ nguồn và SEL; liên hệ hãng nếu lặp lại.")},
		{ch.CoolingFault, "Cooling/Fan Fault", "chassis_cooling_fault", model.Crit, model.CompFan,
			model.T("The BMC reports a cooling/fan fault", "BMC báo lỗi làm mát/quạt (Cooling/Fan Fault)"),
			model.T("The chassis status says a fan or the cooling system has failed.", "Trạng thái chassis cho biết quạt hoặc hệ thống làm mát đã hỏng."),
			model.T("Find the failed fan in the sensor table or the BMC web interface and replace it; watch the temperatures.",
				"Tìm quạt hỏng trong bảng cảm biến hoặc giao diện web BMC rồi thay; theo dõi nhiệt độ.")},
		{ch.DriveFault, "Drive Fault", "chassis_drive_fault", model.Crit, model.CompDisk,
			model.T("The BMC reports a drive fault", "BMC báo lỗi ổ cứng (Drive Fault)"),
			model.T("The chassis status says a drive has failed.", "Trạng thái chassis cho biết có ổ cứng bị hỏng."),
			model.T("Back up now; check the disk and RAID sections and replace the failed drive.", "Sao lưu ngay; kiểm tra phần ổ cứng và RAID rồi thay ổ hỏng.")},
		{ch.Intrusion, "Chassis Intrusion", "chassis_intrusion", model.Warn, model.CompSystem,
			model.T("Chassis intrusion is active", "Đang báo mở nắp thùng máy (Chassis Intrusion)"),
			textFor("intrusion").detail, textFor("intrusion").action},
		{ch.Interlock, "Power Interlock", "chassis_interlock", model.Warn, model.CompPower,
			model.T("The power interlock is active", "Khóa liên động nguồn đang bật (Power Interlock)"),
			model.T("The chassis interlock switch (cover/PSU interlock) prevents or cut power.", "Công tắc liên động (nắp máy/bộ nguồn) đang ngăn hoặc đã ngắt nguồn."),
			model.T("Check that the cover and the power supplies are fully seated.", "Kiểm tra nắp máy và các bộ nguồn đã được lắp chặt.")},
	}
	for _, f := range flags {
		if !f.on {
			continue
		}
		c.add(model.Finding{ID: domain + "." + f.id, Component: f.comp, Severity: f.sev, Target: "chassis",
			Title: f.title, Detail: f.detail, Action: f.action, Evidence: ev(f.key)})
	}
	lpe := strings.ToLower(ch.LastPowerEvent)
	switch {
	case strings.Contains(lpe, "ac-failed"):
		c.add(model.Finding{ID: domain + ".last_power_event", Component: model.CompPower, Severity: model.Warn, Target: "chassis",
			Title: model.T("The last power loss was an AC failure", "Lần mất nguồn gần nhất là do mất điện AC"),
			Detail: model.T("IPMI \"Last Power Event: ac-failed\": the server last went down because its input power was lost (outage, tripped breaker, UPS fault or unplugged), not because of a shutdown command. The flag stays until the next power event, so it may be old.",
				"IPMI \"Last Power Event: ac-failed\": lần gần nhất máy chủ tắt là do mất điện đầu vào (cúp điện, nhảy CB, UPS lỗi hoặc bị rút điện), không phải do lệnh tắt máy. Cờ này giữ tới lần sự kiện nguồn tiếp theo nên có thể là chuyện cũ."),
			Action: model.T("Compare with the uptime and the SEL; check the UPS/PDU and make sure both PSUs are on separate feeds.",
				"Đối chiếu với thời gian uptime và SEL; kiểm tra UPS/PDU và đảm bảo hai bộ nguồn cắm vào hai nguồn điện riêng."),
			Evidence: ev("Last Power Event")})
	case strings.Contains(lpe, "overload") || strings.Contains(lpe, "fault"):
		c.add(model.Finding{ID: domain + ".last_power_event", Component: model.CompPower, Severity: model.Warn, Target: "chassis",
			Title:  model.Tf("The last power loss was caused by a power %s", "Lần mất nguồn gần nhất là do %s", ch.LastPowerEvent),
			Detail: model.T("IPMI chassis status says the server last lost power because of a power fault or overload.", "Trạng thái chassis IPMI cho biết lần gần nhất máy mất nguồn là do lỗi nguồn hoặc quá tải."),
			Action: model.T("Check the power supplies and the SEL around the last boot.", "Kiểm tra bộ nguồn và SEL quanh thời điểm khởi động gần nhất."), Evidence: ev("Last Power Event")})
	}
}

// ---- SEL ----

// SEL "almost full" threshold: 90 %. A BMC SEL holds a few hundred to a few
// thousand entries and one flapping PSU or DIMM logs dozens per day; when it
// is full (or the overflow flag is set) new events are dropped (IPMI 2.0
// §31.2 "Get SEL Info", overflow flag).
const selFullPct = 90

func (c *checker) selInfo() {
	s := c.b.Get("ipmi.sel_info")
	if !s.Ran() {
		return
	}
	si, ok := parseSELInfo(s.Out)
	if !ok {
		return
	}
	c.facts.SEL = &si
	full := si.Overflow || (si.PercentUsed != nil && *si.PercentUsed >= selFullPct) || (si.FreeBytes != nil && *si.FreeBytes == 0 && si.Entries > 0)
	if !full {
		return
	}
	pct := "?"
	if si.PercentUsed != nil {
		pct = strconv.Itoa(*si.PercentUsed) + "%"
	}
	t := textFor("sel_full")
	what := model.Tf("%d entries, %s used", "%d mục, đã dùng %s", si.Entries, pct)
	if si.Overflow {
		what.EN += ", overflow"
		what.VI += ", đã tràn"
	}
	var ev []string
	for _, l := range strings.Split(s.Out, "\n") {
		if strings.HasPrefix(l, "Entries") || strings.HasPrefix(l, "Percent Used") || strings.HasPrefix(l, "Overflow") || strings.HasPrefix(l, "Free Space") {
			ev = append(ev, strings.TrimSpace(l))
		}
	}
	c.add(model.Finding{ID: domain + ".sel_full", Component: model.CompBMC, Severity: model.Warn, Target: "SEL",
		Title: model.T(fmt.Sprintf(t.title.EN, what.EN), fmt.Sprintf(t.title.VI, what.VI)), Detail: t.detail, Action: t.action, Evidence: ev})
}

func (c *checker) sel() {
	s := c.b.Get("ipmi.sel")
	if !s.Ran() {
		return
	}
	now := c.env.Now
	if now.IsZero() {
		now = c.b.Finished
	}
	dayFirst := dayFirstDates(s.Out)
	entries := parseSELShift(s.Out, now, c.bmcClock(now, dayFirst), dayFirst)
	empty := strings.Contains(s.Out, "SEL has no entries")
	c.selParsed = len(entries) > 0 || empty
	if !c.selParsed {
		return
	}
	window := time.Duration(c.window) * 24 * time.Hour
	groups := groupSEL(entries, now, window)
	var history []*selGroup
	problems := 0
	clockBad := 0
	for _, e := range entries {
		if !e.TimeOK {
			clockBad++
		}
	}
	for _, g := range groups {
		c.currentState(g)
		if g.v.ok && g.v.sev > model.OK {
			c.facts.Events = append(c.facts.Events, eventFact(g))
		}
		switch {
		case g.Severity >= model.Warn:
			problems++
			if i, ok := c.sdrFindingFor(g); ok {
				c.foldSEL(i, g) // the SDR already reports it: one fault, one finding
				continue
			}
			c.add(c.selFinding(g))
		case g.v.key == "sel_cleared" && g.Recent > 0:
			c.add(model.Finding{ID: domain + ".sel_cleared", Component: model.CompBMC, Severity: model.Info, Target: "SEL",
				Title:    model.Tf("The BMC event log was cleared on %s", "Nhật ký sự kiện BMC đã bị xóa vào %s", fmtTime(g.Last)),
				Detail:   model.T("Events from before that date are gone, so older hardware history cannot be checked.", "Các sự kiện trước ngày đó đã mất nên không kiểm tra được lịch sử phần cứng cũ."),
				Evidence: units.Evidence(g.lines, 3)})
		case g.v.ok && g.v.sev >= model.Warn:
			history = append(history, g)
		}
	}
	if len(history) > 0 {
		sort.SliceStable(history, func(i, j int) bool { return history[i].Last.After(history[j].Last) })
		var ev []string
		for _, g := range history {
			state := ""
			switch {
			case g.Recovered():
				state = ", recovered"
			case g.healthyNow:
				state = ", healthy now"
			}
			last := "time unknown"
			if !g.Last.IsZero() {
				last = "last " + fmtTime(g.Last)
			}
			ev = append(ev, fmt.Sprintf("%d× %s — %s (%s%s)", g.Count, g.Sensor, g.Event, last, state))
		}
		c.add(model.Finding{ID: domain + ".sel_history", Component: model.CompBMC, Severity: model.Info, Target: "SEL",
			Title: model.T(plural(len(history), "older or recovered hardware event type", "older or recovered hardware event types")+" in the BMC log",
				fmt.Sprintf("%d loại sự kiện phần cứng cũ hoặc đã phục hồi trong nhật ký BMC", len(history))),
			Detail: model.Tf("These happened more than %d days ago, have no usable time stamp, or are over: cleared (deasserted) afterwards, or the live BMC sensor shows the part healthy now. Useful history when the same part fails again.",
				"Các sự kiện này xảy ra hơn %d ngày trước, không có thời gian hợp lệ, hoặc đã qua: sau đó đã hết (deasserted), hay cảm biến BMC hiện tại cho thấy linh kiện đã bình thường. Hữu ích để đối chiếu khi linh kiện đó hỏng lại.", c.window),
			Evidence: units.Evidence(ev, 10)})
	}
	if problems == 0 {
		en := fmt.Sprintf("No hardware faults in the BMC event log in the last %d days (%d entries)", c.window, len(entries))
		vi := fmt.Sprintf("Không có lỗi phần cứng trong nhật ký sự kiện BMC %d ngày qua (%d mục)", c.window, len(entries))
		if empty || len(entries) == 0 {
			en, vi = "The BMC event log is empty", "Nhật ký sự kiện BMC đang trống"
		}
		c.add(model.Finding{ID: domain + ".sel_ok", Component: model.CompBMC, Severity: model.OK, Target: "SEL", Title: model.T(en, vi)})
	}
	if len(entries) > 0 && clockBad*2 > len(entries) {
		c.add(model.Finding{ID: domain + ".sel_clock", Component: model.CompBMC, Severity: model.Info, Target: "SEL",
			Title: model.T("Most BMC log entries have no valid date", "Phần lớn mục trong nhật ký BMC không có ngày giờ hợp lệ"),
			Detail: model.T("The BMC clock was not set (Pre-Init or dates before 2008), so recent events cannot be told from old ones and are all treated as history.",
				"Đồng hồ BMC chưa được đặt (Pre-Init hoặc ngày trước 2008) nên không phân biệt được sự kiện mới và cũ; tất cả được coi là lịch sử."),
			Action: model.T("Set the BMC time (BMC web interface, NTP, or ipmitool sel time set \"MM/DD/YYYY HH:MM:SS\").",
				"Đặt lại giờ cho BMC (giao diện web BMC, NTP, hoặc ipmitool sel time set \"MM/DD/YYYY HH:MM:SS\")."),
		})
	}
	c.eventTable()
}

// clockTolerance: below this the BMC clock is only a time zone away from
// the OS (ipmitool prints SEL times in the host's zone, UTC+14 at most)
// and nothing is shifted.
const clockTolerance = 48 * time.Hour

// bmcClock compares `ipmitool sel time get` with the collection time.
// SEL time stamps come from the BMC clock; when it is wrong by days or
// years (never set, CMOS battery flat, reset to the firmware build date)
// recent faults look old and are missed. It returns the offset to remove
// from every SEL time and reports the wrong clock.
func (c *checker) bmcClock(now time.Time, dayFirst bool) time.Duration {
	s := c.b.Get("ipmi.sel_time")
	if !s.Ran() || now.IsZero() {
		return 0
	}
	var bmc time.Time
	ok := false
	for _, l := range s.Lines() {
		fs := strings.Fields(l)
		if len(fs) >= 2 {
			if bmc, ok = parseSELTimeOrder(fs[0], strings.Join(fs[1:], " "), dayFirst); ok {
				break
			}
		}
	}
	if !ok {
		return 0
	}
	off := bmc.Sub(now)
	sec := int64(off / time.Second)
	c.facts.BMCClockOffset = &sec
	if off < clockTolerance && off > -clockTolerance {
		return 0
	}
	d := units.Duration(off)
	dir := model.T("behind", "chậm")
	if off > 0 {
		dir = model.T("ahead", "nhanh")
	}
	c.add(model.Finding{ID: domain + ".bmc_clock", Component: model.CompBMC, Severity: model.Info, Target: "BMC",
		Title: model.T(fmt.Sprintf("The BMC clock is %s %s (BMC %s, OS %s UTC)", d.EN, dir.EN, fmtTime(bmc), fmtTime(now.UTC())),
			fmt.Sprintf("Đồng hồ BMC %s %s (BMC %s, hệ điều hành %s UTC)", dir.VI, d.VI, fmtTime(bmc), fmtTime(now.UTC()))),
		Detail: model.T("The BMC stamps its event log with its own clock. Diagward moved the SEL times by this offset to tell recent events from old ones, so the dates shown are corrected; events logged before the clock went wrong may show wrong dates.",
			"BMC ghi thời gian vào nhật ký sự kiện theo đồng hồ của chính nó. Diagward đã bù độ lệch này để phân biệt sự kiện mới và cũ, nên ngày giờ hiển thị là đã hiệu chỉnh; các sự kiện ghi trước khi đồng hồ bị sai có thể hiện sai ngày."),
		Action: model.T("Set the BMC clock: enable NTP in the BMC web interface (iDRAC/iLO/XCC), or on the server run ipmitool sel time set \"$(date '+%m/%d/%Y %H:%M:%S')\". If the clock is lost again after a power cut, replace the CMOS battery.",
			"Đặt lại giờ BMC: bật NTP trên giao diện web của BMC (iDRAC/iLO/XCC), hoặc chạy trên máy chủ: ipmitool sel time set \"$(date '+%m/%d/%Y %H:%M:%S')\". Nếu mất điện xong lại sai giờ, hãy thay pin CMOS."),
		Evidence: units.Evidence(s.Lines(), 2)})
	return off
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// currentState lowers a SEL group one step when the live SDR shows the
// same sensor healthy now: the SEL is history, Crit means "failing now".
// Only where the SDR state is unambiguous: a PSU by number, threshold and
// drive sensors matched by name (matchSensors), and a PSU redundancy
// sensor that reads "Fully Redundant" again (Warn -> Info, history).
func (c *checker) currentState(g *selGroup) {
	if g.v.key == "redundancy_lost" && g.Severity == model.Warn && c.sdrParsed && (g.Class == clPowerUnit || g.Class == clPSU) && c.singlePSU() {
		g.Severity = model.Info // one PSU by design: see singlePSU
		return
	}
	if g.Severity < model.Warn || !c.sdrParsed {
		return
	}
	_, sname, _ := splitSELSensor(g.Sensor)
	healthy := false
	switch {
	case g.v.key == "psu_failed" || g.v.key == "psu_ac_lost":
		n := psuNumber(sname)
		for _, p := range c.psus {
			if p.Number == n && n > 0 && p.Present != nil && *p.Present && !p.Failed && !p.InputLost {
				healthy = true
			}
		}
	case strings.HasPrefix(g.v.key, "sensor_"):
		ms := c.matchSensors(g)
		healthy = len(ms) > 0
		for _, sn := range ms { // every sensor of that name: "Temp" can be several
			if sn.Status != "ok" || sn.Value == nil {
				healthy = false
			}
		}
	case strings.HasPrefix(g.v.key, "drive_"):
		ms := c.matchSensors(g)
		healthy = len(ms) > 0
		for _, sn := range ms {
			if !sn.Readable() || len(sn.States) == 0 || sn.Severity >= model.Warn {
				healthy = false
			}
		}
	case g.v.key == "redundancy_lost":
		ms := c.matchSensors(g)
		healthy = len(ms) > 0
		for _, sn := range ms {
			full := false
			for _, st := range sn.States {
				full = full || normEvent(st) == "fully redundant"
			}
			if !sn.Readable() || !full || sn.Severity >= model.Warn {
				healthy = false
			}
		}
	}
	if !healthy {
		return
	}
	switch {
	case g.Severity == model.Crit:
		g.Severity, g.healthyNow = model.Warn, true
	case g.v.key == "redundancy_lost":
		g.Severity, g.healthyNow = model.Info, true
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	return t.Format("2006-01-02 15:04")
}

func eventFact(g *selGroup) Event {
	e := Event{Sensor: g.Sensor, Event: g.Event, Class: g.Class, Count: g.Count, Recent: g.Recent, Recovered: g.Recovered(), Severity: g.Severity}
	if !g.First.IsZero() {
		f, l := g.First, g.Last
		e.First, e.Last = &f, &l
	}
	return e
}

var cpuRe = regexp.MustCompile(`\bCPU ?[0-9]+\b`)

func (c *checker) selFinding(g *selGroup) model.Finding {
	key := g.v.key
	name := g.Sensor
	_, sname, _ := splitSELSensor(g.Sensor)
	if sname == "" {
		sname = g.Sensor
	}
	target := sname
	var part *model.Part
	if strings.HasPrefix(key, "psu_") || g.Class == clPSU {
		if n := psuNumber(sname); n > 0 {
			target = "PSU " + strconv.Itoa(n)
			p := &PSU{Number: n}
			for _, x := range c.psus {
				if x.Number == n {
					p = x
				}
			}
			if f := c.psuFRU[n]; f != nil && p.Serial == "" {
				p.Vendor, p.Model = f.get("Board Mfg", "Product Manufacturer"), f.get("Board Product", "Product Name")
				p.PartNumber, p.Serial = f.get("Board Part Number", "Product Part Number"), f.get("Board Serial", "Product Serial")
			}
			part = p.part()
		}
	}
	if strings.HasPrefix(sname, "#") {
		target = g.Sensor // "Processor #0x09": the bare number means nothing
	}
	if strings.HasPrefix(key, "cpu_") {
		if m := cpuRe.FindString(g.Event); m != "" {
			target = m
		}
	}
	if strings.HasPrefix(key, "memory_") && len(g.dimms) > 0 {
		target = strings.Join(g.dimms, ", ")
		part = &model.Part{Kind: "dimm", Location: target}
	}
	if key == "fan_failed" {
		part = &model.Part{Kind: "fan", Location: sname}
	}
	if strings.HasPrefix(key, "drive_") {
		target = driveTarget(g.Sensor, sname, g.Event)
		if key == "drive_fault" {
			part = &model.Part{Kind: "disk", Location: target}
		}
	}
	var t keyText
	if strings.HasPrefix(key, "sensor_") {
		t = thresholdText(g.Class, g.Severity == model.Crit)
	} else {
		t = textFor(key)
	}
	phrase := model.Tf(t.title.EN, t.title.VI, target)
	recov := model.Text{}
	if g.Recovered() {
		recov = model.T(", recovered", ", đã phục hồi")
	}
	total := model.Text{}
	if g.Count > g.Recent {
		total = model.Tf(" (%d× in total)", " (tổng %d lần)", g.Count)
	}
	f := model.Finding{
		ID:        domain + ".sel_" + key,
		Component: g.v.comp,
		Severity:  g.Severity,
		Target:    target,
		Title: model.T(
			fmt.Sprintf("%s — BMC log: %s, %d× in the last %d days%s, last %s%s", phrase.EN, g.Event, g.Recent, c.window, total.EN, fmtTime(g.Last), recov.EN),
			fmt.Sprintf("%s — nhật ký BMC: %s, %d lần trong %d ngày qua%s, gần nhất %s%s", phrase.VI, g.Event, g.Recent, c.window, total.VI, fmtTime(g.Last), recov.VI)),
		Detail: model.T(
			fmt.Sprintf("%s Sensor %q logged %q, first %s, last %s.", t.detail.EN, name, g.Event, fmtTime(g.First), fmtTime(g.Last)),
			fmt.Sprintf("%s Cảm biến %q ghi nhận %q, lần đầu %s, gần nhất %s.", t.detail.VI, name, g.Event, fmtTime(g.First), fmtTime(g.Last))),
		Action:   t.action,
		Evidence: units.Evidence(g.lines, 10),
		Part:     part,
	}
	if g.Recovered() {
		f.Detail.EN += " The condition was cleared (deasserted) afterwards."
		f.Detail.VI += " Sau đó trạng thái này đã hết (deasserted)."
	}
	if g.healthyNow {
		f.Detail.EN += " The live BMC sensors show it healthy now, so this is recent history: watch for it to come back."
		f.Detail.VI += " Cảm biến BMC hiện tại cho thấy đã bình thường, đây là sự cố gần đây: theo dõi xem có tái diễn không."
	}
	if f.Component == "" {
		f.Component = classComponent(g.Class)
	}
	return f
}

func (c *checker) eventTable() {
	evs := append([]Event(nil), c.facts.Events...)
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].Severity != evs[j].Severity {
			return evs[i].Severity > evs[j].Severity
		}
		return evs[i].Last != nil && (evs[j].Last == nil || evs[i].Last.After(*evs[j].Last))
	})
	if len(evs) > 30 {
		evs = evs[:30]
	}
	var rows []model.Row
	for _, e := range evs {
		first, last := "?", "?"
		if e.First != nil {
			first, last = fmtTime(*e.First), fmtTime(*e.Last)
		}
		state := "active"
		switch {
		case e.Recovered:
			state = "recovered"
		case e.Recent == 0:
			state = "old"
		}
		rows = append(rows, model.Row{Status: e.Severity, Cells: []string{e.Sensor, e.Event, strconv.Itoa(e.Count), first, last, state}})
	}
	if len(rows) == 0 {
		return
	}
	c.res.Tables = append(c.res.Tables, model.Table{
		ID:    domain + ".events",
		Title: model.T("Hardware events in the BMC log (SEL)", "Sự kiện phần cứng trong nhật ký BMC (SEL)"),
		Columns: []model.Text{model.T("Sensor", "Cảm biến"), model.T("Event", "Sự kiện"), model.T("Count", "Số lần"),
			model.T("First", "Lần đầu"), model.T("Last", "Gần nhất"), model.T("State", "Tình trạng")},
		Rows: rows,
		Note: model.Tf("Times are the BMC clock. Only events from the last %d days raise warnings; \"recovered\" = deasserted afterwards.",
			"Thời gian theo đồng hồ BMC. Chỉ sự kiện trong %d ngày qua mới gây cảnh báo; \"recovered\" = sau đó đã hết (deasserted).", c.window),
	})
}

// ---- coverage ----

// errText is the first lines of stderr. stdout is used only when nothing
// was parsed from it (then it holds the error message, not data).
func (c *checker) errText(s *collect.Section, parsed bool) string {
	src := s.Err
	if strings.TrimSpace(src) == "" && !parsed {
		src = s.Out
	}
	var lines []string
	for _, l := range strings.Split(src, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
		if len(lines) == 2 {
			break
		}
	}
	t := strings.Join(lines, " / ")
	if r := []rune(t); len(r) > 240 {
		t = string(r[:240]) + "…"
	}
	if t == "" {
		t = fmt.Sprintf("exit code %d", s.RC)
	}
	return t
}

// driverCmd loads the IPMI system interface (KCS/SMIC/BT through ipmi_si)
// and the /dev/ipmi0 character device (ipmi_devintf).
const driverCmd = "modprobe ipmi_devintf ipmi_si"

var (
	driverFix = model.T(`Load the IPMI driver (boards with an SSIF BMC need ipmi_ssif instead of ipmi_si), then run Diagward again. To load it at every boot: printf 'ipmi_devintf\nipmi_si\n' > /etc/modules-load.d/ipmi.conf`,
		`Nạp driver IPMI (bo mạch dùng BMC kiểu SSIF thì nạp ipmi_ssif thay cho ipmi_si), rồi chạy lại Diagward. Để tự nạp mỗi lần khởi động: printf 'ipmi_devintf\nipmi_si\n' > /etc/modules-load.d/ipmi.conf`)
	resetFix = model.T("Check the BMC web interface. Reset the BMC with ipmitool mc reset cold (this restarts only the BMC, not the server) and run Diagward again; or read it over the network: diagward bmc <address>.",
		"Kiểm tra giao diện web của BMC. Reset BMC bằng ipmitool mc reset cold (chỉ khởi động lại BMC, không ảnh hưởng máy chủ) rồi chạy lại Diagward; hoặc đọc qua mạng: diagward bmc <địa chỉ>.")
)

func (c *checker) installFix() (model.Text, string) {
	if c.env.OS == collect.OSWindows {
		return model.T("Install ipmitool for Windows (for example Dell OpenManage BMC Utility) and run Diagward as Administrator, or read the BMC over the network: diagward bmc <iDRAC/iLO/XCC address>.",
			"Cài ipmitool cho Windows (ví dụ Dell OpenManage BMC Utility) rồi chạy Diagward bằng quyền Administrator, hoặc đọc BMC qua mạng: diagward bmc <địa chỉ iDRAC/iLO/XCC>."), ""
	}
	return hint.InstallFix(c.env, "ipmitool")
}

func (c *checker) asRoot(cmd string) string {
	if c.env.Root || c.env.OS == collect.OSWindows {
		return cmd
	}
	return "sudo " + cmd
}

func (c *checker) covState(cv *model.Coverage, s *collect.Section, parsed bool) {
	virtual := !c.env.Bare() && c.env.OS != collect.OSBMC
	switch {
	case s.Skipped == "container":
		cv.State, cv.Reason = model.CovSkipped, hint.Virtual(c.env)
	case s.Missing != "":
		cv.State = model.CovSkipped
		switch {
		case virtual:
			cv.Reason = hint.Virtual(c.env)
		case c.evidence:
			m := hint.Missing("ipmitool")
			cv.Reason = model.T(m.EN+" This server has a BMC.", m.VI+" Máy chủ này có BMC.")
			cv.Fix, cv.Cmd = c.installFix()
		default:
			m := hint.Missing("ipmitool")
			cv.Reason = model.T(m.EN+" No BMC was detected either.", m.VI+" Cũng không phát hiện BMC nào.")
			cv.Fix, cv.Cmd = c.installFix()
		}
	case s.Skipped == "not-root" || s.Skipped == "not-admin":
		cv.State, cv.Reason, cv.Fix = model.CovSkipped, hint.NeedRoot(c.env), hint.RunAsRoot(c.env)
		if c.env.OS != collect.OSWindows {
			cv.Cmd = "sudo diagward check"
		}
	case s.Skipped == "not-applicable":
		cv.State = model.CovSkipped
		switch {
		case c.evidence:
			cv.Reason = model.T("A BMC is present (SMBIOS type 38) but the IPMI driver is not loaded: /dev/ipmi0 does not exist.",
				"Máy có BMC (SMBIOS type 38) nhưng chưa nạp driver IPMI: không có /dev/ipmi0.")
			cv.Fix, cv.Cmd = driverFix, c.asRoot(driverCmd)
		case virtual:
			cv.Reason = hint.Virtual(c.env)
		default:
			cv.Reason = model.T("No BMC found: no IPMI device in SMBIOS and no /dev/ipmi0.", "Không tìm thấy BMC: SMBIOS không có thiết bị IPMI và không có /dev/ipmi0.")
			cv.Fix = model.T("If this server has a BMC (iDRAC, iLO, XCC, IPMI), load the driver (modprobe ipmi_si ipmi_devintf) or read it over the network: diagward bmc <address>.",
				"Nếu máy chủ có BMC (iDRAC, iLO, XCC, IPMI), hãy nạp driver (modprobe ipmi_si ipmi_devintf) hoặc đọc qua mạng: diagward bmc <địa chỉ>.")
		}
	case s.Skipped == "bmc-timeout":
		cv.State = model.CovFailed
		cv.Reason = model.T("Not read: the BMC did not answer an earlier ipmitool command in time (BMC hung or very busy).",
			"Không đọc được: BMC không trả lời lệnh ipmitool trước đó kịp thời gian (BMC bị treo hoặc quá tải).")
		cv.Fix = resetFix
	case s.Skipped != "":
		cv.State, cv.Reason = model.CovSkipped, model.Tf("Skipped by the collector (%s).", "Bộ thu thập đã bỏ qua (%s).", s.Skipped)
	case s.Timeout && !parsed:
		cv.State = model.CovFailed
		to := c.b.Options.WithDefaults().Timeout
		cv.Reason = model.Tf("ipmitool did not finish in time (timeout %d s or more): the BMC is hung or very slow.",
			"ipmitool không chạy xong kịp (quá %d giây trở lên): BMC bị treo hoặc rất chậm.", to)
		cv.Fix = resetFix
	case parsed && s.Timeout && s.Name == "ipmi.sel":
		// ipmitool lists the SEL oldest first: a cut-off read lacks the newest entries.
		cv.State = model.CovPartial
		cv.Reason = model.T("ipmitool timed out while reading the event log: the newest entries may be missing, so recent faults can be unreported.",
			"ipmitool hết thời gian khi đọc nhật ký sự kiện: có thể thiếu các mục mới nhất nên lỗi gần đây có thể không được báo.")
		cv.Fix = model.T("Read the log in the BMC web interface, or run ipmitool sel elist on the server and look at the last lines.",
			"Xem nhật ký trên giao diện web của BMC, hoặc chạy ipmitool sel elist trên máy chủ và xem các dòng cuối.")
	case parsed && s.Timeout:
		cv.State = model.CovPartial
		cv.Reason = model.T("ipmitool timed out halfway: some records are missing.", "ipmitool hết thời gian giữa chừng: thiếu một phần dữ liệu.")
	case parsed && s.RC != 0:
		e := c.errText(s, true)
		cv.State, cv.Reason = model.CovPartial, model.Tf("ipmitool reported errors, some data may be missing: %s", "ipmitool báo lỗi, có thể thiếu dữ liệu: %s", e)
	case parsed:
		cv.State = model.CovRan
	case s.RC != 0:
		e := c.errText(s, false)
		cv.State, cv.Reason = model.CovFailed, model.Tf("ipmitool could not read the BMC: %s", "ipmitool không đọc được BMC: %s", e)
		if strings.Contains(e, "Could not open device") || strings.Contains(e, "No such file") {
			cv.Fix, cv.Cmd = driverFix, c.asRoot(driverCmd)
		} else {
			cv.Fix = resetFix
		}
	default:
		cv.State, cv.Reason = model.CovFailed, model.T("ipmitool output was not recognised.", "Không nhận dạng được kết quả của ipmitool.")
	}
}

func (c *checker) coverage() {
	type item struct {
		id, sec string
		name    model.Text
		parsed  bool
	}
	items := []item{
		{"ipmi.sdr", "ipmi.sdr", model.T("BMC sensors (IPMI SDR)", "Cảm biến BMC (IPMI SDR)"), c.sdrParsed},
		{"ipmi.sel", "ipmi.sel", model.T("BMC event log (IPMI SEL)", "Nhật ký sự kiện BMC (IPMI SEL)"), c.selParsed},
		{"ipmi.chassis", "ipmi.chassis", model.T("Chassis status (IPMI)", "Trạng thái chassis (IPMI)"), c.chassisParsed},
	}
	for _, it := range items {
		s := c.b.Get(it.sec)
		if s == nil {
			continue
		}
		cv := model.Coverage{ID: it.id, Component: model.CompBMC, Name: it.name}
		c.covState(&cv, s, it.parsed)
		c.res.Coverage = append(c.res.Coverage, cv)
	}
	if !c.sdrParsed {
		return
	}
	var temps, fans, power bool
	for _, sn := range c.sensors {
		if !sn.Readable() {
			continue
		}
		switch sn.Class {
		case clTemp:
			temps = true
		case clFan:
			fans = true
		case clPSU, clPowerUnit:
			power = true
		}
	}
	if power {
		c.res.Coverage = append(c.res.Coverage, model.Coverage{ID: "ipmi.power", Component: model.CompPower, State: model.CovRan,
			Name: model.T("Power supplies (BMC)", "Bộ nguồn (BMC)")})
	}
	if fans {
		c.res.Coverage = append(c.res.Coverage, model.Coverage{ID: "ipmi.fans", Component: model.CompFan, State: model.CovRan,
			Name: model.T("Fans (BMC)", "Quạt (BMC)")})
	}
	if temps {
		c.res.Coverage = append(c.res.Coverage, model.Coverage{ID: "ipmi.temperature", Component: model.CompThermal, State: model.CovRan,
			Name: model.T("Temperatures (BMC)", "Nhiệt độ (BMC)")})
	}
}
