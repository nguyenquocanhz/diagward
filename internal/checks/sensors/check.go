// Package sensors is the "sensors" domain check: temperatures, fan speeds,
// voltages and power readings as the operating system sees them (Linux
// lm-sensors / hwmon / thermal zones; Windows ACPI thermal zones,
// LibreHardwareMonitor). Readings from the BMC are the ipmi domain's job.
package sensors

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "sensors"

// Facts is the typed data of this domain.
type Facts struct {
	Sources      []string      `json:"sources,omitempty"`
	Temperatures []Temperature `json:"temperatures,omitempty"`
	Fans         []Fan         `json:"fans,omitempty"`
	Voltages     []Voltage     `json:"voltages,omitempty"`
	Power        []Power       `json:"power,omitempty"`
}

// Temperature is one temperature sensor (°C).
type Temperature struct {
	Chip    string         `json:"chip"`
	Sensor  string         `json:"sensor"`
	Celsius *float64       `json:"celsius,omitempty"`
	High    *float64       `json:"high,omitempty"`
	Crit    *float64       `json:"crit,omitempty"`
	Ignored bool           `json:"ignored,omitempty"` // implausible or faulty reading, not judged
	Status  model.Severity `json:"status"`
	Source  string         `json:"source"`
}

// Fan is one fan header (RPM).
type Fan struct {
	Chip      string         `json:"chip"`
	Sensor    string         `json:"sensor"`
	RPM       *float64       `json:"rpm,omitempty"`
	Min       *float64       `json:"min,omitempty"`
	Connected bool           `json:"connected"`
	Status    model.Severity `json:"status"`
	Source    string         `json:"source"`
}

// Voltage is one voltage input (V).
type Voltage struct {
	Chip   string         `json:"chip"`
	Sensor string         `json:"sensor"`
	Volts  *float64       `json:"volts,omitempty"`
	Min    *float64       `json:"min,omitempty"`
	Max    *float64       `json:"max,omitempty"`
	Alarm  bool           `json:"alarm,omitempty"`
	Status model.Severity `json:"status"`
	Source string         `json:"source"`
}

// Power is a power (W) or current (A) reading.
type Power struct {
	Chip   string  `json:"chip"`
	Sensor string  `json:"sensor"`
	Value  float64 `json:"value"`
	Unit   string  `json:"unit"` // "W" or "A"
	Source string  `json:"source"`
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	if len(b.Prefix("sensors.")) == 0 {
		return res
	}
	c := &checker{b: b, env: env, res: &res}
	c.gather()
	c.analyze()
	c.coverage()
	res.Facts = c.facts
	return res
}

type checker struct {
	b     *collect.Bundle
	env   model.Env
	res   *model.Result
	facts Facts

	readings []*reading
	sources  map[string]bool

	temps, fans, volts, power []*judged
}

// judged is a reading with its verdict.
type judged struct {
	r         *reading
	sev       model.Severity
	rule      string
	note      model.Text
	ignored   bool // implausible / no reading: not judged, not counted
	connected bool // fans: something is plugged in
	disk      bool // drive temperature: shown, judged by the disk domain
}

// gather reads every source and merges them. lm-sensors and hwmon read the
// same kernel drivers: lm-sensors wins for the chips it reports (it applies
// sensors.conf labels and voltage scaling), raw hwmon fills in the chips it
// does not, and thermal zones are added only when no hwmon chip of the same
// name exists (acpitz is exported both ways).
func (c *checker) gather() {
	c.sources = map[string]bool{}
	var lm []*reading
	if s := c.b.Get("sensors.lmsensors_json"); s.Ran() && strings.TrimSpace(s.Out) != "" {
		if rs, ok := parseLMJSON(s.Out); ok {
			lm = rs
		}
	}
	if lm == nil {
		if s := c.b.Get("sensors.lmsensors"); s.Ran() {
			lm = parseLMRaw(s.Out)
		}
	}
	drivers := map[string]bool{}
	add := func(rs []*reading) {
		for _, r := range rs {
			if ignoredChip(r.Driver) {
				continue
			}
			c.readings = append(c.readings, r)
			c.sources[r.Source] = true
		}
	}
	for _, r := range lm {
		drivers[r.Driver] = true
	}
	add(lm)
	if s := c.b.Get("sensors.hwmon"); s.Ran() {
		hw := parseHwmon(s)
		var extra []*reading
		for _, r := range hw {
			if r.Driver == "" || !drivers[r.Driver] {
				extra = append(extra, r)
			}
		}
		for _, r := range hw {
			drivers[r.Driver] = true
		}
		add(extra)
	}
	if s := c.b.Get("sensors.thermal"); s.Ran() {
		var zs []*reading
		for _, r := range parseThermal(s) {
			// x86_pkg_temp reads the same package MSR as coretemp.
			if !drivers[r.Driver] && !(r.Driver == "x86_pkg_temp" && drivers["coretemp"]) {
				zs = append(zs, r)
			}
		}
		add(zs)
	}
	if s := c.b.Get("sensors.win_thermalzone"); s.Ran() {
		add(parseWinThermal(s))
	}
	if s := c.b.Get("sensors.win_probe"); s.Ran() {
		add(parseWinProbe(s))
	}
	if s := c.b.Get("sensors.win_fan"); s.Ran() {
		add(parseWinFan(s))
	}
	if s := c.b.Get("sensors.win_lhm"); s.Ran() {
		add(parseHM(s, srcLHM))
	}
	if s := c.b.Get("sensors.win_ohm"); s.Ran() && !c.sources[srcLHM] {
		add(parseHM(s, srcOHM))
	}
	for s := range c.sources {
		c.facts.Sources = append(c.facts.Sources, s)
	}
	sort.Strings(c.facts.Sources)
}

// ignoredChip drops hwmon devices that are not server hardware health:
// batteries and AC adapters (power_supply class, named after the supply:
// AC, ACAD, ADP1, BAT0), USB-C PD, Wi-Fi radios. Real chips whose driver
// merely starts with "ac"/"ad" (acbel_fsg032 PSU, adt7475, adm1275) stay.
func ignoredChip(drv string) bool {
	d := strings.ToLower(drv)
	if powerSupplyRe.MatchString(d) {
		return true
	}
	for _, p := range []string{"ucsi", "hidpp_battery", "iwlwifi", "mt76", "mt79", "ath1", "ath9"} {
		if strings.HasPrefix(d, p) {
			return true
		}
	}
	return false
}

var powerSupplyRe = regexp.MustCompile(`^(ac|acad|adp|bat|battery)[0-9]*$`)

// Plausibility limits. Super-I/O inputs that are not wired read 0, -62 or
// 127 °C, and some BIOSes publish nonsense ACPI trip points (210 °C, 31 °C,
// 0 °C) — all seen in the test fixtures. Nothing in a running server is
// ≤ 0 °C or ≥ 150 °C, and real high/critical limits sit between ~35 and
// 130 °C (Intel TjMax 70–110 °C, NVMe WCTEMP/CCTEMP 70–95 °C, drives
// 55–70 °C).
func plausibleTemp(v float64) bool { return v > 0 && v < 150 }

func plausibleLimit(p *float64, lo float64) *float64 {
	if p == nil || *p < lo || *p > 130 {
		return nil
	}
	return p
}

// trustedAlarm lists drivers whose alarm bits mean what they say: CPU
// on-die sensors and drive firmware. Super-I/O and DIMM (jc42) chips set
// alarm bits whenever their limits are unconfigured (e.g. max = 0, seen in
// the nct6798/jc42 fixture), so their alarms only count together with a
// reading over a real limit.
func trustedAlarm(r *reading) bool {
	switch r.Driver {
	case "coretemp", "k10temp", "zenpower", "nvme", "drivetemp":
		return true
	}
	return r.Source == srcThermal || r.Source == srcACPI
}

func isCPU(r *reading) bool {
	switch r.Driver {
	case "coretemp", "k10temp", "zenpower", "k8temp", "via_cputemp", "cpu", "x86_pkg_temp", "cpu_thermal", "cpu-thermal":
		return true
	}
	l := strings.ToLower(r.Label)
	return strings.Contains(l, "cpu") || strings.Contains(l, "package") || strings.HasPrefix(l, "tctl") || strings.HasPrefix(l, "tdie")
}

func isDiskSensor(r *reading) bool { return r.Driver == "nvme" || r.Driver == "drivetemp" }

// cpuFallback is the temperature at which a CPU without published limits is
// called too hot. AMD's Tctl limit (Tjmax) is 95 °C on Zen parts (AMD
// product specifications, "Max. Operating Temperature (Tjmax)"); Intel
// server parts have TjMax between ~80 and 105 °C, so 90 °C is past the
// throttling point for most of them. Warn only: this is a heuristic.
func cpuFallback(r *reading) float64 {
	if r.Driver == "k10temp" || r.Driver == "zenpower" {
		return 95
	}
	return 90
}

func (c *checker) analyze() {
	// k10temp: Tctl may carry a +20/+27 °C offset on some Ryzen and
	// Threadripper parts (Documentation/hwmon/k10temp.rst); prefer Tdie
	// when the chip reports it.
	hasTdie := map[string]bool{}
	for _, r := range c.readings {
		if r.Driver == "k10temp" && strings.EqualFold(r.Label, "Tdie") {
			hasTdie[r.Chip] = true
		}
	}
	intrusions := map[string][]*reading{}
	var intrChips []string
	for _, r := range c.readings {
		switch r.Kind {
		case kTemp:
			if r.Driver == "k10temp" {
				// temp1_max is a constant 70 °C ("*val = 70 * 1000" in
				// drivers/hwmon/k10temp.c, exported on Zen by kernels
				// before ~5.6), not a limit: EPYCs run above it under load.
				r.Max = nil
			}
			j := evalTemp(r)
			if isDiskSensor(r) {
				// Contract: drive temperatures are the disk domain's.
				j.disk, j.rule = true, ""
				j.note = model.T("drive: see the disk section", "ổ cứng: xem phần ổ cứng")
			}
			if r.Driver == "k10temp" && strings.EqualFold(r.Label, "Tctl") && hasTdie[r.Chip] && j.sev > model.OK {
				j.sev, j.rule = model.OK, ""
				j.note = model.T("offset (see Tdie)", "có độ lệch (xem Tdie)")
			}
			c.temps = append(c.temps, j)
		case kFan:
			c.fans = append(c.fans, evalFan(r))
		case kIn:
			c.volts = append(c.volts, evalIn(r))
		case kPower, kCurr:
			if r.Input != nil {
				c.power = append(c.power, &judged{r: r})
			}
		case kIntrusion:
			if isTrue(r.Alarm) {
				if intrusions[r.Chip] == nil {
					intrChips = append(intrChips, r.Chip)
				}
				intrusions[r.Chip] = append(intrusions[r.Chip], r)
			}
		}
	}
	for _, chip := range intrChips {
		c.res.Findings = append(c.res.Findings, intrusionFinding(chip, intrusions[chip]))
	}
	c.findings()
	c.tables()
	c.buildFacts()
}

func intrusionFinding(chip string, rs []*reading) model.Finding {
	var names, ev []string
	for _, r := range rs {
		names = append(names, r.name())
		ev = append(ev, fmt.Sprintf("%s: %s_alarm = 1", r.Chip, r.Kind+r.Index))
	}
	return model.Finding{
		ID: domain + ".intrusion", Component: model.CompSystem, Severity: model.Info,
		Target: chip,
		Title:  model.Tf("Chassis-open switch is latched on %s (%s)", "Công tắc mở nắp thùng máy trên %s đang báo đã mở (%s)", chip, strings.Join(names, ", ")),
		Detail: model.T("The sensor chip latched a chassis-open event. It stays set until cleared, so it may come from an earlier service visit, or the switch may not be wired at all.",
			"Chip cảm biến đã ghi nhận nắp thùng máy bị mở. Cờ này giữ nguyên cho tới khi được xóa nên có thể là từ lần bảo trì trước, hoặc công tắc không hề được nối."),
		Action: model.T("If nobody opened the server, check physical access to the rack. The BMC intrusion sensor (IPMI) is the more reliable one.",
			"Nếu không ai mở máy, hãy kiểm tra quyền ra vào tủ rack. Cảm biến mở nắp của BMC (IPMI) đáng tin hơn."),
		Evidence: units.Evidence(ev, 10),
	}
}

func evalTemp(r *reading) *judged {
	j := &judged{r: r}
	if isTrue(r.Fault) {
		j.ignored, j.note = true, model.T("sensor fault", "cảm biến lỗi")
		return j
	}
	if r.Input == nil {
		j.ignored, j.note = true, model.T("no reading", "không có số đo")
		return j
	}
	v := *r.Input
	if !plausibleTemp(v) {
		j.ignored, j.note = true, model.T("ignored (not connected?)", "bỏ qua (chưa nối?)")
		return j
	}
	crit := plausibleLimit(r.Crit, 40)
	high := plausibleLimit(r.Max, 35)
	if high == nil {
		high = plausibleLimit(r.Passive, 35)
	}
	trusted := trustedAlarm(r)
	switch {
	case crit != nil && v >= *crit:
		j.sev, j.rule = model.Crit, "temp_critical"
		j.note = model.T("≥ critical", "≥ tới hạn")
	case isTrue(r.CritAlarm) && trusted:
		j.sev, j.rule = model.Warn, "temp_crit_alarm"
		j.note = model.T("critical alarm", "cờ tới hạn")
	case high != nil && v >= *high:
		j.sev, j.rule = model.Warn, "temp_high"
		j.note = model.T("≥ high", "≥ ngưỡng cao")
	case (isTrue(r.MaxAlarm) || isTrue(r.Alarm)) && trusted:
		j.sev, j.rule = model.Warn, "temp_alarm"
		j.note = model.T("alarm", "cảnh báo")
	case crit == nil && high == nil && isCPU(r) && v >= cpuFallback(r):
		j.sev, j.rule = model.Warn, "temp_high"
		j.note = model.Tf("≥ %s (no limit published)", "≥ %s (chip không báo ngưỡng)", degC(cpuFallback(r)))
	}
	return j
}

// evalFan: readings above 25,000 RPM are counter overflows of an
// unconnected header (server fans top out around 20,000 RPM, e.g. 40 mm
// Delta/Nidec fans).
func evalFan(r *reading) *judged {
	j := &judged{r: r}
	if r.Input == nil {
		j.ignored = true
		if r.Status != "" {
			j.note = model.T("status: "+r.Status, "trạng thái: "+r.Status)
		} else {
			j.note = model.T("no reading", "không có số đo")
		}
		return j
	}
	v := *r.Input
	if v < 0 || v > 25000 {
		j.ignored, j.note = true, model.T("ignored (implausible)", "bỏ qua (giá trị vô lý)")
		return j
	}
	var min *float64
	if r.Min != nil && *r.Min > 0 && *r.Min < 20000 {
		min = r.Min
	}
	alarm := isTrue(r.Alarm) || isTrue(r.MinAlarm)
	if v == 0 {
		if min != nil || alarm {
			j.sev, j.rule, j.connected = model.Crit, "fan_stopped", true
			j.note = model.T("stopped", "ngừng quay")
		} else {
			j.note = model.T("not connected", "không gắn quạt")
		}
		return j
	}
	j.connected = true
	switch {
	case min != nil && v < *min:
		j.sev, j.rule = model.Warn, "fan_slow"
		j.note = model.T("below minimum", "dưới mức tối thiểu")
	case alarm:
		j.sev, j.rule = model.Info, "fan_alarm"
		j.note = model.T("alarm flag", "cờ cảnh báo")
	}
	return j
}

// evalIn: unconfigured Super-I/O inputs commonly have min = max = 0 and the
// alarm bit set (nct6779/nct6798 fixtures), and raw sysfs values are
// unscaled without the board's sensors.conf. So a voltage is only judged
// when the chip flags an alarm, the limits are sane (max > min, max > 0)
// and the reading really is outside them.
func evalIn(r *reading) *judged {
	j := &judged{r: r}
	if r.Input == nil {
		j.ignored, j.note = true, model.T("no reading", "không có số đo")
		return j
	}
	alarm := isTrue(r.Alarm) || isTrue(r.MinAlarm) || isTrue(r.MaxAlarm)
	if !alarm {
		return j
	}
	sane := r.Min != nil && r.Max != nil && *r.Max > *r.Min && *r.Max > 0
	v := *r.Input
	if sane && (v < *r.Min || v > *r.Max) {
		j.sev, j.rule = model.Warn, "voltage_alarm"
		j.note = model.T("out of range", "ngoài ngưỡng")
		return j
	}
	j.note = model.T("alarm bit (limits not set)", "cờ cảnh báo (chưa đặt ngưỡng)")
	return j
}

// ---- findings ----

type group struct {
	rule, chip string
	items      []*judged
}

func (c *checker) findings() {
	var groups []*group
	idx := map[string]*group{}
	for _, list := range [][]*judged{c.temps, c.fans, c.volts} {
		for _, j := range list {
			if j.rule == "" {
				continue
			}
			k := j.rule + "\x00" + j.r.Chip
			g := idx[k]
			if g == nil {
				g = &group{rule: j.rule, chip: j.r.Chip}
				idx[k] = g
				groups = append(groups, g)
			}
			g.items = append(g.items, j)
		}
	}
	for _, g := range groups {
		c.res.Findings = append(c.res.Findings, groupFinding(g))
	}
	c.okFindings()
}

func degC(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0") + " °C"
}

func optC(p *float64) string {
	if p == nil {
		return "—"
	}
	return degC(*p)
}

func num(v float64, prec int) string {
	s := strconv.FormatFloat(v, 'f', prec, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

func opt(p *float64, prec int, unit string) string {
	if p == nil {
		return "—"
	}
	return num(*p, prec) + unit
}

func val(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func evidence(j *judged) string {
	r := j.r
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", r.Chip, r.name())
	if r.Input != nil {
		switch r.Kind {
		case kTemp:
			fmt.Fprintf(&b, " = %s", degC(*r.Input))
		case kFan:
			fmt.Fprintf(&b, " = %s RPM", num(*r.Input, 0))
		case kIn:
			fmt.Fprintf(&b, " = %s V", num(*r.Input, 3))
		}
	}
	add := func(k string, p *float64, prec int) {
		if p != nil {
			fmt.Fprintf(&b, " %s=%s", k, num(*p, prec))
		}
	}
	switch r.Kind {
	case kTemp:
		add("high", r.Max, 1)
		add("crit", r.Crit, 1)
		add("passive", r.Passive, 1)
	case kFan:
		add("min", r.Min, 0)
	case kIn:
		add("min", r.Min, 3)
		add("max", r.Max, 3)
	}
	for _, f := range []struct {
		n string
		v *bool
	}{{"alarm", r.Alarm}, {"max_alarm", r.MaxAlarm}, {"crit_alarm", r.CritAlarm}, {"min_alarm", r.MinAlarm}} {
		if f.v != nil {
			v := 0
			if *f.v {
				v = 1
			}
			fmt.Fprintf(&b, " %s=%d", f.n, v)
		}
	}
	fmt.Fprintf(&b, " [%s]", r.Source)
	return b.String()
}

func tempAction(r *reading) model.Text {
	switch {
	case isCPU(r):
		return model.T("Check the CPU cooling now: are all fans spinning, is the heatsink seated, is the airflow blocked (missing blanking panels, cables, dust filters)? Check the room/inlet temperature and compare with the BMC readings. Reduce the load or shut down if it keeps rising.",
			"Kiểm tra tản nhiệt CPU ngay: các quạt có quay đủ không, tản nhiệt có bị lỏng không, luồng gió có bị chặn không (thiếu tấm che khe trống, dây cáp, lưới lọc bụi)? Kiểm tra nhiệt độ phòng/khí vào và đối chiếu với số liệu BMC. Giảm tải hoặc tắt máy nếu nhiệt độ tiếp tục tăng.")
	}
	return model.T("Check the fans and the airflow inside the chassis and the room temperature; compare with the BMC readings (ipmitool sdr elist).",
		"Kiểm tra quạt, luồng gió trong thùng máy và nhiệt độ phòng; đối chiếu với số liệu của BMC (ipmitool sdr elist).")
}

// fanName avoids "Fan CPU FAN": drop the word when the label has it.
func fanName(r *reading) string {
	n := r.name()
	if strings.Contains(strings.ToLower(n), "fan") {
		return n
	}
	return "fan " + n
}

func groupFinding(g *group) model.Finding {
	sort.SliceStable(g.items, func(a, b int) bool {
		return val(g.items[a].r.Input) > val(g.items[b].r.Input)
	})
	top := g.items[0]
	r := top.r
	n := len(g.items)
	var ev []string
	for _, j := range g.items {
		ev = append(ev, evidence(j))
	}
	f := model.Finding{
		ID:       domain + "." + g.rule,
		Severity: top.sev,
		Target:   g.chip + " " + r.name(),
		Evidence: units.Evidence(ev, 10),
	}
	if n > 1 {
		f.Target = g.chip
	}
	in := val(r.Input)
	switch g.rule {
	case "temp_critical":
		f.Component = model.CompThermal
		if n == 1 {
			f.Title = model.Tf("%s %s is at its critical temperature: %s (critical %s)", "%s %s đang ở nhiệt độ tới hạn: %s (ngưỡng tới hạn %s)", g.chip, r.name(), degC(in), optC(r.Crit))
		} else {
			f.Title = model.Tf("%d sensors on %s are at their critical temperature (hottest %s)", "%d cảm biến trên %s đang ở nhiệt độ tới hạn (nóng nhất %s)", n, g.chip, degC(in))
		}
		f.Detail = model.T("The reading is at or above the critical limit set by the hardware itself. At this temperature parts throttle hard, the system may shut down, and components can be damaged.",
			"Số đo bằng hoặc vượt ngưỡng tới hạn do chính phần cứng đặt ra. Ở mức này linh kiện giảm xung mạnh, máy có thể tự tắt và linh kiện có thể bị hỏng.")
		f.Action = tempAction(r)
	case "temp_high", "temp_alarm":
		f.Component = model.CompThermal
		limit := optC(r.Max)
		if r.Max == nil && r.Passive != nil {
			limit = optC(r.Passive)
		}
		switch {
		case g.rule == "temp_alarm" && n == 1:
			f.Title = model.Tf("%s %s: the sensor raised a temperature alarm (%s)", "%s %s: cảm biến báo cảnh báo nhiệt độ (%s)", g.chip, r.name(), degC(in))
		case g.rule == "temp_alarm":
			f.Title = model.Tf("%d sensors on %s raised a temperature alarm", "%d cảm biến trên %s báo cảnh báo nhiệt độ", n, g.chip)
		case r.Max == nil && r.Passive == nil:
			f.Title = model.Tf("%s %s runs very hot: %s", "%s %s chạy rất nóng: %s", g.chip, r.name(), degC(in))
		case n == 1:
			f.Title = model.Tf("%s %s is above its high limit: %s (high %s)", "%s %s vượt ngưỡng nhiệt cao: %s (ngưỡng cao %s)", g.chip, r.name(), degC(in), limit)
		default:
			f.Title = model.Tf("%d sensors on %s are above their high limit (hottest %s)", "%d cảm biến trên %s vượt ngưỡng nhiệt cao (nóng nhất %s)", n, g.chip, degC(in))
		}
		f.Detail = model.T("Running this hot shortens component life and makes the CPU throttle (lower performance). The critical limit has not been reached yet.",
			"Chạy nóng như vậy làm giảm tuổi thọ linh kiện và khiến CPU tự giảm xung (chậm đi). Chưa tới ngưỡng tới hạn.")
		f.Action = tempAction(r)
	case "temp_crit_alarm":
		f.Component = model.CompThermal
		f.Title = model.Tf("%s %s reached its critical temperature since the last reset", "%s %s đã từng chạm nhiệt độ tới hạn kể từ lần khởi động gần nhất", g.chip, r.name())
		if n > 1 {
			f.Title = model.Tf("%d sensors on %s reached their critical temperature since the last reset", "%d cảm biến trên %s đã từng chạm nhiệt độ tới hạn kể từ lần khởi động gần nhất", n, g.chip)
		}
		f.Detail = model.Tf("The chip's critical-temperature alarm is set although it reads %s now. For coretemp this bit latches (\"never clears\", kernel hwmon documentation): the CPU ran out of spec at some point.",
			"Cờ cảnh báo tới hạn của chip đang bật dù hiện tại đo được %s. Với coretemp cờ này được giữ lại (\"không bao giờ tự xóa\" theo tài liệu hwmon của kernel): CPU đã từng chạy vượt thông số cho phép.", degC(in))
		f.Action = tempAction(r)
	case "fan_stopped":
		f.Component = model.CompFan
		f.Part = &model.Part{Kind: "fan", Location: g.chip + " " + r.name()}
		if n == 1 {
			f.Title = model.T(fmt.Sprintf("%s on %s has stopped (0 RPM)", upperFirst(fanName(r)), g.chip), fmt.Sprintf("Quạt %s trên %s đã ngừng quay (0 RPM)", r.name(), g.chip))
		} else {
			names := make([]string, 0, n)
			for _, j := range g.items {
				names = append(names, j.r.name())
			}
			f.Title = model.Tf("%d fans on %s have stopped (0 RPM): %s", "%d quạt trên %s đã ngừng quay (0 RPM): %s", n, g.chip, strings.Join(names, ", "))
			f.Part.Location = g.chip
		}
		f.Detail = model.T("The header reads 0 RPM while a minimum speed is configured or the chip raises a fan alarm, so a running fan is expected there. Without it parts overheat.",
			"Chân cắm quạt đo được 0 RPM trong khi có đặt tốc độ tối thiểu hoặc chip đang báo lỗi quạt, nghĩa là ở đây phải có quạt đang chạy. Thiếu quạt, linh kiện sẽ quá nhiệt.")
		f.Action = model.T("Check the fan now: is it spinning, is its cable plugged in, is it blocked by dust or a cable? Replace it if it does not spin, and watch the temperatures until then. If nothing is plugged into this header, set its minimum to 0 (BIOS or sensors.conf) to clear the alarm.",
			"Kiểm tra quạt ngay: quạt có quay không, dây cắm có lỏng không, có bị bụi hay dây cáp chặn không? Thay quạt nếu không quay và theo dõi nhiệt độ cho tới lúc đó. Nếu chân cắm này không gắn quạt, đặt tốc độ tối thiểu về 0 (trong BIOS hoặc sensors.conf) để tắt cảnh báo.")
	case "fan_slow":
		f.Component = model.CompFan
		f.Part = &model.Part{Kind: "fan", Location: g.chip + " " + r.name()}
		f.Title = model.T(fmt.Sprintf("%s on %s spins below its minimum: %s RPM (minimum %s)", upperFirst(fanName(r)), g.chip, num(in, 0), opt(r.Min, 0, "")), fmt.Sprintf("Quạt %s trên %s quay dưới mức tối thiểu: %s RPM (tối thiểu %s)", r.name(), g.chip, num(in, 0), opt(r.Min, 0, "")))
		if n > 1 {
			f.Title = model.Tf("%d fans on %s spin below their minimum speed", "%d quạt trên %s quay dưới mức tối thiểu", n, g.chip)
			f.Part.Location = g.chip
		}
		f.Detail = model.T("A fan that slows down below its configured minimum is usually worn out (bearing) or clogged with dust.",
			"Quạt quay chậm dưới mức tối thiểu đã đặt thường là do mòn bạc đạn hoặc bám bụi.")
		f.Action = model.T("Clean the fan and its intake; replace it if it stays slow. Watch the temperatures meanwhile.",
			"Vệ sinh quạt và khe hút gió; thay quạt nếu vẫn quay chậm. Trong lúc chờ hãy theo dõi nhiệt độ.")
	case "fan_alarm":
		f.Component = model.CompFan
		f.Title = model.T(fmt.Sprintf("%s on %s: the chip flags an alarm although it spins at %s RPM", upperFirst(fanName(r)), g.chip, num(in, 0)), fmt.Sprintf("Quạt %s trên %s: chip báo cảnh báo dù quạt vẫn quay %s RPM", r.name(), g.chip, num(in, 0)))
		f.Detail = model.T("The alarm bit may be left over from an earlier stall (some chips latch it until it is read).",
			"Cờ cảnh báo có thể còn sót lại từ một lần quạt bị kẹt trước đó (một số chip giữ cờ cho tới khi được đọc).")
		f.Action = model.T("Check that the fan runs smoothly; nothing else to do if the alarm clears.",
			"Kiểm tra quạt chạy êm; không cần làm gì thêm nếu cảnh báo tự hết.")
	case "voltage_alarm":
		f.Component = model.CompPower
		f.Title = model.Tf("Voltage %s on %s is out of range: %s V (allowed %s–%s V)", "Điện áp %s trên %s nằm ngoài ngưỡng: %s V (cho phép %s–%s V)", r.name(), g.chip, num(in, 3), opt(r.Min, 3, ""), opt(r.Max, 3, ""))
		if n > 1 {
			f.Title = model.Tf("%d voltages on %s are out of range", "%d điện áp trên %s nằm ngoài ngưỡng", n, g.chip)
		}
		f.Detail = model.T("The monitoring chip flags these rails as outside their limits. Unstable rails come from a failing power supply or a mainboard voltage regulator, and cause random crashes.",
			"Chip giám sát báo các đường điện này nằm ngoài ngưỡng. Điện áp không ổn định thường do bộ nguồn sắp hỏng hoặc mạch ổn áp trên mainboard, và gây treo/khởi động lại bất thường.")
		f.Action = model.T("Compare with the BMC and PSU readings (ipmitool sdr elist). If the rail stays out of range, have the power supply or the mainboard checked under warranty.",
			"Đối chiếu với số liệu của BMC và bộ nguồn (ipmitool sdr elist). Nếu điện áp vẫn ngoài ngưỡng, liên hệ bảo hành để kiểm tra bộ nguồn hoặc mainboard.")
	}
	return f
}

func (c *checker) okFindings() {
	var nT int
	var hot *judged
	worstT := model.OK
	for _, j := range c.temps {
		if j.ignored || j.disk {
			continue
		}
		nT++
		worstT = model.Worst(worstT, j.sev)
		if hot == nil || val(j.r.Input) > val(hot.r.Input) {
			hot = j
		}
	}
	if nT > 0 && worstT == model.OK {
		c.res.Findings = append(c.res.Findings, model.Finding{
			ID: domain + ".temperature_ok", Component: model.CompThermal, Severity: model.OK,
			Title: model.Tf("Temperatures normal: %d sensors, hottest %s (%s %s)", "Nhiệt độ bình thường: %d cảm biến, nóng nhất %s (%s %s)",
				nT, degC(val(hot.r.Input)), hot.r.Chip, hot.r.name()),
		})
	}
	var nF int
	lo, hi := 0.0, 0.0
	worstF := model.OK
	for _, j := range c.fans {
		if j.ignored || !j.connected {
			continue
		}
		worstF = model.Worst(worstF, j.sev)
		v := val(j.r.Input)
		if nF == 0 || v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
		nF++
	}
	if nF > 0 && worstF <= model.Info {
		c.res.Findings = append(c.res.Findings, model.Finding{
			ID: domain + ".fans_ok", Component: model.CompFan, Severity: model.OK,
			Title: model.Tf("%d fans spinning normally (%s–%s RPM)", "%d quạt quay bình thường (%s–%s RPM)", nF, num(lo, 0), num(hi, 0)),
		})
	}
}

// ---- tables ----

func noteText(j *judged) string {
	if j.note.IsZero() {
		return ""
	}
	if j.note.EN == j.note.VI {
		return j.note.EN
	}
	return j.note.EN + " / " + j.note.VI
}

func (c *checker) tables() {
	if rows := c.tempRows(); len(rows) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    domain + ".temperatures",
			Title: model.T("Temperatures (OS sensors)", "Nhiệt độ (cảm biến đọc từ hệ điều hành)"),
			Columns: []model.Text{model.T("Chip", "Chip"), model.T("Sensor", "Cảm biến"), model.T("Reading", "Nhiệt độ"),
				model.T("High", "Ngưỡng cao"), model.T("Critical", "Tới hạn"), model.T("Note", "Ghi chú")},
			Rows: rows,
			Note: model.T("Limits are the ones the hardware publishes; implausible values (unconnected inputs) are not judged.",
				"Ngưỡng là do phần cứng công bố; giá trị vô lý (đầu vào không nối cảm biến) không được đánh giá."),
		})
	}
	var fr []model.Row
	for _, j := range c.fans {
		speed := "—"
		if j.r.Input != nil {
			speed = num(*j.r.Input, 0) + " RPM"
		}
		fr = append(fr, model.Row{Status: j.sev, Cells: []string{j.r.Chip, j.r.name(), speed, opt(j.r.Min, 0, " RPM"), noteText(j)}})
	}
	if len(fr) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    domain + ".fans",
			Title: model.T("Fans (OS sensors)", "Quạt (cảm biến đọc từ hệ điều hành)"),
			Columns: []model.Text{model.T("Chip", "Chip"), model.T("Fan", "Quạt"), model.T("Speed", "Tốc độ"),
				model.T("Minimum", "Tối thiểu"), model.T("Note", "Ghi chú")},
			Rows: fr,
			Note: model.T("0 RPM without a minimum or an alarm is an empty fan header, not a fault.",
				"0 RPM mà không đặt mức tối thiểu hay cờ cảnh báo là chân cắm quạt bỏ trống, không phải lỗi."),
		})
	}
	var vr []model.Row
	for _, j := range c.volts {
		vr = append(vr, model.Row{Status: j.sev, Cells: []string{j.r.Chip, j.r.name(), opt(j.r.Input, 3, " V"), opt(j.r.Min, 3, " V"), opt(j.r.Max, 3, " V"), noteText(j)}})
	}
	for _, j := range c.power {
		unit := " W"
		if j.r.Kind == kCurr {
			unit = " A"
		}
		vr = append(vr, model.Row{Status: model.OK, Cells: []string{j.r.Chip, j.r.name(), opt(j.r.Input, 2, unit), "—", "—", ""}})
	}
	if len(vr) > 0 {
		c.res.Tables = append(c.res.Tables, model.Table{
			ID:    domain + ".voltages",
			Title: model.T("Voltages and power (OS sensors)", "Điện áp và công suất (cảm biến đọc từ hệ điều hành)"),
			Columns: []model.Text{model.T("Chip", "Chip"), model.T("Input", "Đầu vào"), model.T("Value", "Giá trị"),
				model.T("Min", "Tối thiểu"), model.T("Max", "Tối đa"), model.T("Note", "Ghi chú")},
			Rows: vr,
			Note: model.T("Super-I/O voltage inputs are only meaningful with the board's sensors.conf; they are judged only when the chip itself flags a rail outside sane limits.",
				"Điện áp từ chip Super-I/O chỉ có ý nghĩa khi có cấu hình sensors.conf của bo mạch; chỉ đánh giá khi chính chip báo một đường điện nằm ngoài ngưỡng hợp lệ."),
		})
	}
}

// tempRows lists temperatures; the healthy per-core rows of each coretemp
// chip are folded into one row (a 2 × 28-core server has 56 of them).
func (c *checker) tempRows() []model.Row {
	var rows []model.Row
	type fold struct {
		n   int
		max *judged
		at  int
	}
	folds := map[string]*fold{}
	var order []string
	for _, j := range c.temps {
		r := j.r
		if r.Driver == "coretemp" && strings.HasPrefix(r.Label, "Core ") && !j.ignored && j.sev == model.OK {
			f := folds[r.Chip]
			if f == nil {
				f = &fold{at: len(rows)}
				folds[r.Chip] = f
				order = append(order, r.Chip)
				rows = append(rows, model.Row{}) // placeholder, filled below
			}
			f.n++
			if f.max == nil || val(r.Input) > val(f.max.r.Input) {
				f.max = j
			}
			continue
		}
		rows = append(rows, model.Row{Status: j.sev, Cells: []string{r.Chip, r.name(), optC(r.Input), optC(r.Max), optC(r.Crit), noteText(j)}})
	}
	for _, chip := range order {
		f := folds[chip]
		m := f.max.r
		label := m.name()
		if f.n > 1 {
			label = fmt.Sprintf("%d cores, hottest %s", f.n, m.name())
		}
		rows[f.at] = model.Row{Status: model.OK, Cells: []string{chip, label, optC(m.Input), optC(m.Max), optC(m.Crit), ""}}
	}
	return rows
}

func (c *checker) buildFacts() {
	for _, j := range c.temps {
		c.facts.Temperatures = append(c.facts.Temperatures, Temperature{Chip: j.r.Chip, Sensor: j.r.name(), Celsius: j.r.Input,
			High: j.r.Max, Crit: j.r.Crit, Ignored: j.ignored, Status: j.sev, Source: j.r.Source})
	}
	for _, j := range c.fans {
		c.facts.Fans = append(c.facts.Fans, Fan{Chip: j.r.Chip, Sensor: j.r.name(), RPM: j.r.Input, Min: j.r.Min,
			Connected: j.connected, Status: j.sev, Source: j.r.Source})
	}
	for _, j := range c.volts {
		c.facts.Voltages = append(c.facts.Voltages, Voltage{Chip: j.r.Chip, Sensor: j.r.name(), Volts: j.r.Input, Min: j.r.Min, Max: j.r.Max,
			Alarm: isTrue(j.r.Alarm) || isTrue(j.r.MinAlarm) || isTrue(j.r.MaxAlarm), Status: j.sev, Source: j.r.Source})
	}
	for _, j := range c.power {
		unit := "W"
		if j.r.Kind == kCurr {
			unit = "A"
		}
		c.facts.Power = append(c.facts.Power, Power{Chip: j.r.Chip, Sensor: j.r.name(), Value: val(j.r.Input), Unit: unit, Source: j.r.Source})
	}
}

// ---- coverage ----

func (c *checker) coverage() {
	covT := model.Coverage{ID: domain + ".temperature", Component: model.CompThermal,
		Name: model.T("Temperature sensors (OS)", "Cảm biến nhiệt độ (từ hệ điều hành)")}
	covF := model.Coverage{ID: domain + ".fans", Component: model.CompFan,
		Name: model.T("Fan speeds (OS)", "Tốc độ quạt (từ hệ điều hành)")}

	nTemps, nDisk, nFans := 0, 0, 0
	for _, j := range c.temps {
		switch {
		case j.ignored:
		case j.disk:
			nDisk++
		default:
			nTemps++
		}
	}
	for _, j := range c.fans {
		if j.connected {
			nFans++
		}
	}
	// A sysfs read or `sensors` that hung (drivetemp on a dying drive, an
	// ACPI power meter waiting on the BMC) was cut by the collector.
	cut := false
	for _, n := range []string{"sensors.lmsensors_json", "sensors.lmsensors", "sensors.hwmon", "sensors.thermal"} {
		if s := c.b.Get(n); s.Ran() && s.Timeout {
			cut = true
		}
	}
	bmcT, bmcF := c.bmcCovers()
	container := c.env.Container
	if !container {
		// The collector skips every section with "container" when it
		// detects one, even if meta.virt missed it.
		all := true
		for _, s := range c.b.Prefix("sensors.") {
			if s.Skipped != "container" {
				all = false
			}
		}
		container = all
	}
	virtual := container || (!c.env.Bare() && c.env.OS != collect.OSBMC)
	set := func(cov *model.Coverage, n int, bmc bool, why model.Text, temp bool) {
		switch {
		case n > 0 && cut:
			cov.State = model.CovPartial
			cov.Reason = model.T("Reading the sensors timed out (a drive or the BMC did not answer), so some readings are missing.",
				"Đọc cảm biến bị quá thời gian (một ổ cứng hoặc BMC không phản hồi) nên thiếu một số số đo.")
		case n > 0:
			cov.State = model.CovRan
		case virtual:
			cov.State, cov.Reason = model.CovSkipped, hint.Virtual(c.env)
		case bmc:
			cov.State = model.CovSkipped
			cov.Reason = model.T("Not visible to the operating system; read from the BMC instead (see the IPMI results).",
				"Hệ điều hành không đọc được; đã đọc từ BMC thay thế (xem phần IPMI).")
		default:
			cov.State, cov.Reason = model.CovPartial, c.reasonNone(why, temp)
			cov.Fix, cov.Cmd = c.fix(temp)
		}
	}
	whyT := model.T("No temperature sensors are visible to the operating system.", "Hệ điều hành không thấy cảm biến nhiệt độ nào.")
	if nDisk > 0 {
		whyT = model.T("Only drive temperatures are visible to the operating system (they are judged in the disk section); no CPU or board sensor.",
			"Hệ điều hành chỉ thấy nhiệt độ ổ cứng (được đánh giá ở phần ổ cứng); không thấy cảm biến CPU hay bo mạch.")
	}
	set(&covT, nTemps, bmcT, whyT, true)
	set(&covF, nFans, bmcF, model.T("No fan speeds are visible to the operating system (on most servers only the BMC reads the fans).",
		"Hệ điều hành không đọc được tốc độ quạt (trên đa số máy chủ chỉ BMC mới đọc được quạt)."), false)
	c.res.Coverage = append(c.res.Coverage, covT, covF)
}

// reasonNone adds why the OS sees nothing: lm-sensors missing, not admin.
func (c *checker) reasonNone(base model.Text, temp bool) model.Text {
	if c.env.OS == collect.OSWindows {
		if !temp {
			return model.T(base.EN+" Windows has no generic fan interface and LibreHardwareMonitor is not running.",
				base.VI+" Windows không có giao diện đọc quạt chung và LibreHardwareMonitor không chạy.")
		}
		if s := c.b.Get("sensors.win_thermalzone"); s != nil && s.Skipped == "not-admin" {
			return model.T(base.EN+" Reading the ACPI thermal zones needs Administrator rights.", base.VI+" Đọc vùng nhiệt ACPI cần quyền Administrator.")
		}
		return model.T(base.EN+" Windows has no generic sensor interface: the ACPI thermal zone is not implemented on this machine and LibreHardwareMonitor is not running.",
			base.VI+" Windows không có giao diện cảm biến chung: máy này không hỗ trợ vùng nhiệt ACPI và LibreHardwareMonitor không chạy.")
	}
	if c.lmMissing() {
		return model.T(base.EN+" lm-sensors is not installed.", base.VI+" Chưa cài lm-sensors.")
	}
	return base
}

func (c *checker) lmMissing() bool {
	s := c.b.Get("sensors.lmsensors_json")
	return s != nil && s.Missing != ""
}

// fix follows the lm-sensors documentation (install it, let sensors-detect
// load the right drivers) and points at the BMC. The returned command goes
// into Coverage.Cmd.
func (c *checker) fix(temp bool) (model.Text, string) {
	if c.env.OS == collect.OSWindows {
		t := model.T("Read the sensors from the BMC: diagward bmc <iDRAC/iLO/XCC address>; or run LibreHardwareMonitor (it publishes its sensors to WMI) and collect again.",
			"Đọc cảm biến từ BMC: diagward bmc <địa chỉ iDRAC/iLO/XCC>; hoặc chạy LibreHardwareMonitor (phần mềm này đưa cảm biến lên WMI) rồi thu thập lại.")
		if s := c.b.Get("sensors.win_thermalzone"); temp && s != nil && s.Skipped == "not-admin" {
			pre := hint.RunAsRoot(c.env)
			return model.T(pre.EN+" "+t.EN, pre.VI+" "+t.VI), ""
		}
		return t, ""
	}
	detect := "sensors-detect --auto"
	if !c.env.Root {
		detect = "sudo " + detect
	}
	bmc := model.T(" Or read the BMC: ipmitool sdr elist (on the server) or diagward bmc <BMC address>.",
		" Hoặc đọc qua BMC: ipmitool sdr elist (ngay trên máy) hay diagward bmc <địa chỉ BMC>.")
	if c.lmMissing() {
		if inst := hint.InstallCommand(c.env, hint.Package(c.env, "sensors")); inst != "" {
			return model.T("Install lm-sensors, then let it detect the sensor chips ("+detect+") and run Diagward again."+bmc.EN,
				"Cài lm-sensors, sau đó cho nó dò chip cảm biến ("+detect+") rồi chạy lại Diagward."+bmc.VI), inst
		}
		return model.T("Install the lm-sensors package, then let it detect the sensor chips ("+detect+") and run Diagward again."+bmc.EN,
			"Cài gói lm-sensors, sau đó cho nó dò chip cảm biến ("+detect+") rồi chạy lại Diagward."+bmc.VI), ""
	}
	return model.T("Let lm-sensors detect and load the sensor drivers, then run Diagward again."+bmc.EN,
		"Cho lm-sensors dò và nạp driver cảm biến rồi chạy lại Diagward."+bmc.VI), detect
}

// bmcCovers reports whether the IPMI SDR in the same bundle has
// temperature / fan readings, so an empty OS view is not a gap.
func (c *checker) bmcCovers() (temps, fans bool) {
	s := c.b.Get("ipmi.sdr")
	if !s.Ran() {
		return false, false
	}
	for _, l := range s.Lines() {
		f := strings.Split(l, "|")
		if len(f) < 5 {
			continue
		}
		v := strings.TrimSpace(f[len(f)-1])
		if strings.Contains(v, "degrees C") {
			temps = true
		}
		if strings.Contains(v, " RPM") {
			fans = true
		}
	}
	return temps, fans
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
