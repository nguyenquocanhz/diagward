package cpu

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// winProcessor mirrors the properties 20-cpu.ps1 selects from
// Win32_Processor.
type winProcessor struct {
	DeviceID                  string `json:"DeviceID"`
	Name                      string `json:"Name"`
	Manufacturer              string `json:"Manufacturer"`
	SocketDesignation         string `json:"SocketDesignation"`
	NumberOfCores             int    `json:"NumberOfCores"`
	NumberOfEnabledCore       int    `json:"NumberOfEnabledCore"`
	NumberOfLogicalProcessors int    `json:"NumberOfLogicalProcessors"`
	CurrentClockSpeed         int    `json:"CurrentClockSpeed"`
	MaxClockSpeed             int    `json:"MaxClockSpeed"`
	LoadPercentage            *int   `json:"LoadPercentage"`
	Status                    string `json:"Status"`
	CpuStatus                 *int   `json:"CpuStatus"`
	ProcessorID               string `json:"ProcessorId"`
}

// Win32_Processor.CpuStatus values (Microsoft docs, Win32_Processor class;
// the same values as SMBIOS type 4 "CPU Status").
var cpuStatusText = map[int]string{
	0: "Unknown", 1: "CPU Enabled", 2: "CPU Disabled by User via BIOS Setup",
	3: "CPU Disabled By BIOS (POST Error)", 4: "CPU is Idle", 7: "Other",
}

func checkWindows(b *collect.Bundle, env model.Env, res *model.Result) {
	sec := b.Get("cpu.win_processor")
	cov := func(id string, name model.Text, state string, reason, fix model.Text) {
		res.Coverage = append(res.Coverage, model.Coverage{ID: id, Component: model.CompCPU, Name: name, State: state, Reason: reason, Fix: fix})
	}
	var procs []winProcessor
	switch {
	case sec == nil:
	case !sec.Ran():
		cov("cpu.inventory", nameInventory, model.CovSkipped, model.T("Not collected.", "Chưa thu thập dữ liệu này."), model.Text{})
	case collect.DecodeJSON(sec.Out, &procs) != nil || (len(procs) == 0 && sec.Err != ""):
		cov("cpu.inventory", nameInventory, model.CovFailed,
			model.Tf("Win32_Processor could not be read: %s", "Không đọc được Win32_Processor: %s", firstNonEmpty(oneLine(sec.Err), "invalid output")), model.Text{})
		procs = nil
	default:
		cov("cpu.inventory", nameInventory, model.CovRan, model.Text{}, model.Text{})
	}
	virtual := !env.Bare()
	facts := &Facts{}
	t := model.Table{
		ID:    "cpu.sockets",
		Title: model.T("Processors", "Bộ xử lý (CPU)"),
		Columns: []model.Text{
			model.T("Socket", "Socket"), model.T("Model", "Model"), model.T("Status", "Trạng thái"),
			model.T("Cores (enabled/total)", "Nhân (bật/tổng)"), model.T("Threads", "Luồng"),
			model.T("Speed MHz (now/max)", "Xung MHz (hiện tại/tối đa)"), model.T("Load %", "Tải %"),
		},
	}
	bad := 0
	for _, p := range procs {
		sock := firstNonEmpty(p.SocketDesignation, p.DeviceID, "CPU")
		mdl := strings.Join(strings.Fields(p.Name), " ")
		cs := -1
		if p.CpuStatus != nil {
			cs = *p.CpuStatus
		}
		stText := cpuStatusText[cs]
		if stText == "" && cs >= 0 {
			stText = fmt.Sprintf("CpuStatus %d", cs)
		}
		if p.Status != "" && p.Status != "OK" {
			stText = strings.TrimSpace(stText + " / " + p.Status)
		}
		row := model.OK
		pr := Processor{
			Socket: sock, Status: stText, Populated: true, Enabled: cs == 1 || cs == 4,
			DisabledBIOS: cs == 3, DisabledUser: cs == 2, Manufacturer: p.Manufacturer, Model: mdl,
			Cores: p.NumberOfCores, CoresEnabled: p.NumberOfEnabledCore, Threads: p.NumberOfLogicalProcessors,
			CurrentMHz: p.CurrentClockSpeed, MaxMHz: p.MaxClockSpeed,
		}
		facts.Processors = append(facts.Processors, pr)
		facts.Model = firstNonEmpty(facts.Model, mdl)
		facts.Logical += p.NumberOfLogicalProcessors
		facts.Sockets++
		switch {
		case cs == 3 && !virtual:
			bad++
			row = model.Crit
			res.Findings = append(res.Findings, model.Finding{
				ID: "cpu.socket_disabled", Component: model.CompCPU, Severity: model.Crit, Target: sock,
				Title: model.Tf("CPU in socket %s is disabled by the BIOS (POST error)", "CPU ở socket %s bị BIOS vô hiệu hoá (lỗi POST)", sock),
				Detail: model.Tf("Win32_Processor reports CpuStatus 3 (\"CPU Disabled By BIOS (POST Error)\") for %s: the firmware turned this processor off after a power-on self-test error, so the server runs with fewer CPUs.",
					"Win32_Processor báo CpuStatus 3 (\"CPU Disabled By BIOS (POST Error)\") cho %s: firmware đã tắt CPU này sau lỗi tự kiểm tra lúc khởi động, máy đang chạy thiếu CPU.", firstNonEmpty(mdl, sock)),
				Action: model.Tf("Read the POST/hardware event log in the BMC (iDRAC Lifecycle Log, iLO IML, IPMI SEL) for socket %[1]s. Power off, reseat the CPU and heatsink, check the socket pins; swap CPUs between sockets to tell a bad CPU from a bad motherboard, then open a warranty case.",
					"Xem log POST/sự kiện phần cứng trên BMC (iDRAC Lifecycle Log, iLO IML, IPMI SEL) cho socket %[1]s. Tắt máy, gắn lại CPU và tản nhiệt, kiểm tra chân socket; đổi chéo CPU giữa các socket để phân biệt hỏng CPU hay hỏng bo mạch chủ, rồi mở case bảo hành.", sock),
				Evidence: []string{fmt.Sprintf("DeviceID=%s SocketDesignation=%s CpuStatus=%d Status=%s", p.DeviceID, p.SocketDesignation, cs, p.Status)},
				Part:     &model.Part{Kind: "cpu", Vendor: p.Manufacturer, Model: mdl, Location: sock},
			})
		case cs == 2 && !virtual:
			row = model.Info
			res.Findings = append(res.Findings, model.Finding{
				ID: "cpu.socket_disabled_by_user", Component: model.CompCPU, Severity: model.Info, Target: sock,
				Title:  model.Tf("CPU in socket %s is disabled in the BIOS setup", "CPU ở socket %s bị tắt trong BIOS setup", sock),
				Detail: model.T("CpuStatus 2: someone turned this processor off in the BIOS setup (not a fault).", "CpuStatus 2: CPU này đã được tắt thủ công trong BIOS setup (không phải lỗi)."),
				Action: model.T("If this was not intended, enable the processor again in the BIOS setup.", "Nếu không cố ý, bật lại CPU trong BIOS setup."),
			})
		case !virtual && isBadWinStatus(p.Status):
			// Win32 Status strings come from WMI's generic CIM status, which
			// vendors rarely set for CPUs; not proof of failure, so Warn.
			bad++
			row = model.Warn
			res.Findings = append(res.Findings, model.Finding{
				ID: "cpu.win_status", Component: model.CompCPU, Severity: model.Warn, Target: sock,
				Title: model.Tf("Windows reports CPU %s as \"%s\"", "Windows báo CPU %s ở trạng thái \"%s\"", sock, p.Status),
				Detail: model.T("Win32_Processor.Status is not \"OK\". Windows sets this from the firmware/driver status; it often accompanies machine-check (WHEA) errors.",
					"Win32_Processor.Status không phải \"OK\". Windows lấy trạng thái này từ firmware/driver; thường đi kèm lỗi machine-check (WHEA)."),
				Action: model.T("Check the System log section for WHEA-Logger errors and the BMC event log for this CPU; update BIOS and chipset drivers.",
					"Xem phần System log có lỗi WHEA-Logger không và log sự kiện BMC cho CPU này; cập nhật BIOS và driver chipset."),
				Evidence: []string{fmt.Sprintf("DeviceID=%s Status=%s CpuStatus=%d", p.DeviceID, p.Status, cs)},
			})
		}
		if !virtual && p.NumberOfCores > 0 && p.NumberOfEnabledCore > 0 && p.NumberOfEnabledCore < p.NumberOfCores {
			res.Findings = append(res.Findings, model.Finding{
				ID: "cpu.cores_disabled", Component: model.CompCPU, Severity: model.Info, Target: sock,
				Title: model.Tf("Socket %s: only %d of %d cores are enabled", "Socket %s: chỉ bật %d/%d nhân", sock, p.NumberOfEnabledCore, p.NumberOfCores),
				Detail: model.T("The BIOS enables fewer cores than the processor has. This is usually a BIOS setting (core licensing, power saving); a core disabled after a fault shows up the same way.",
					"BIOS bật ít nhân hơn số nhân CPU có. Thường là do cấu hình BIOS (giới hạn license, tiết kiệm điện); nhân bị tắt do lỗi cũng hiện ra như vậy."),
				Action: model.T("Check the \"enabled cores\" setting in the BIOS. If nobody changed it, look for CPU errors in the BMC event log.",
					"Kiểm tra mục số nhân được bật (enabled cores) trong BIOS. Nếu không ai chỉnh, xem log sự kiện BMC có lỗi CPU không."),
			})
		}
		load := ""
		if p.LoadPercentage != nil {
			load = fmt.Sprintf("%d", *p.LoadPercentage)
		}
		cores := ""
		if p.NumberOfCores > 0 {
			cores = fmt.Sprintf("%d/%d", firstPos(p.NumberOfEnabledCore, p.NumberOfCores), p.NumberOfCores)
		}
		t.Rows = append(t.Rows, model.NewRow(row,
			sock, mdl, statusCell(firstNonEmpty(stText, p.Status)), cores, itoa(p.NumberOfLogicalProcessors), speeds(p.CurrentClockSpeed, p.MaxClockSpeed), load,
		))
	}
	if len(t.Rows) > 0 {
		res.Tables = append(res.Tables, t)
	}
	if len(procs) > 0 && bad == 0 && !virtual {
		res.Findings = append(res.Findings, okFinding("cpu.sockets_ok",
			fmt.Sprintf("%d CPU socket(s) enabled and reporting OK (%s)", len(procs), facts.Model),
			fmt.Sprintf("%d socket CPU đang hoạt động bình thường (%s)", len(procs), facts.Model)))
	}
	if sec != nil {
		// Windows has no per-CPU throttle counters; machine checks are
		// WHEA-Logger events, which the logs domain reads.
		cov("cpu.throttle", nameThrottle, model.CovSkipped,
			model.T("Windows does not expose CPU thermal throttle counters.", "Windows không cung cấp bộ đếm giảm xung do nhiệt của CPU."),
			model.T("Check CPU temperatures and fan status in the BMC (iDRAC/iLO) or the sensors section.", "Xem nhiệt độ CPU và quạt trên BMC (iDRAC/iLO) hoặc phần cảm biến."))
		cov("cpu.mce", nameMCE, model.CovSkipped,
			model.T("On Windows, machine-check errors are WHEA-Logger events: they are checked in the System log section.", "Trên Windows, lỗi machine-check là sự kiện WHEA-Logger: được kiểm tra ở phần System log."),
			model.Text{})
		for i := range res.Coverage {
			if id := res.Coverage[i].ID; id == "cpu.throttle" || id == "cpu.mce" {
				res.Coverage[i].NotApplicable = true
			}
		}
	}
	res.Facts = facts
}

func isBadWinStatus(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "degraded", "pred fail", "nonrecover", "stressed":
		return true
	}
	return false
}
