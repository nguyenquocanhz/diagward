// Package redfish is the "redfish" domain check. It analyses the Redfish
// resources the out-of-band BMC collector (package bmc) stored as
// "redfish.res:<path>" sections: overall health, temperatures, fans, power
// supplies, voltages, drives, RAID volumes and controllers, DIMMs, CPUs, the
// BMC itself and the recent BMC log entries (SEL, Dell Lifecycle log, HPE
// IML/IEL, Supermicro, Lenovo, OpenBMC).
//
// The analysis follows @odata.id links from the service root, the way the
// collector walked them, so vendor paths (Dell System.Embedded.1, HPE
// Systems/1, ...) are never hard-coded.
package redfish

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

const domain = "redfish"

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: domain}
	if b == nil || len(b.Prefix(SectionPrefix)) == 0 {
		return res // not a Redfish bundle (in-band, or IPMI-only BMC bundle)
	}
	s := newStore(b)
	window := env.SinceDays
	if window <= 0 {
		window = 30
	}
	c := &checker{res: &res, env: env, facts: &Facts{WindowDays: window}}
	c.ipmiCmd, c.retryCmd = rerunCmds(b)

	root, oc, why := s.get("/redfish/v1")
	if root == nil {
		reason := model.T("The Redfish service root (/redfish/v1) could not be read.", "Không đọc được gốc dịch vụ Redfish (/redfish/v1).")
		if why != "" {
			reason = model.Tf("The Redfish service root could not be read: %s.", "Không đọc được gốc dịch vụ Redfish: %s.", why)
		}
		state := model.CovFailed
		if oc == outNotFound {
			state = model.CovSkipped
		}
		res.Coverage = append(res.Coverage, model.Coverage{
			ID: domain + ".service", Component: model.CompBMC, State: state,
			Name:   model.T("Redfish service", "Dịch vụ Redfish"),
			Reason: reason,
			Fix: model.T("Check that Redfish is enabled in the BMC settings and that the BMC firmware is recent; old BMCs (iDRAC 7/8 before 2.40, iLO 4 before 2.30) only offer IPMI, which Diagward reads over the LAN with ipmitool.",
				"Kiểm tra Redfish đã được bật trong cài đặt BMC và firmware BMC đủ mới; BMC đời cũ (iDRAC 7/8 trước 2.40, iLO 4 trước 2.30) chỉ hỗ trợ IPMI, Diagward đọc qua mạng LAN bằng ipmitool."),
			Cmd: c.ipmiCmd,
		})
		return res
	}

	w := &walker{s: s, f: c.facts, areas: map[string]*area{}}
	for _, a := range areaDefs {
		aa := a
		w.areas[a.id] = &aa
	}
	w.walk(root)
	c.facts.Events = w.events(env.Now, window)
	c.poweredOff = c.isPoweredOff()
	c.logsRead = len(w.logs) > 0 && w.areas["logs"].ok > 0
	f := c.facts
	c.items = map[string]int{
		"system":  len(f.Systems),
		"thermal": len(f.Temperatures) + len(f.Fans),
		"power":   len(f.PSUs) + len(f.Voltages),
		"storage": len(f.Drives) + len(f.Volumes) + len(f.Controllers) + len(f.Batteries),
		"memory":  len(f.DIMMs),
		"logs":    len(w.logs),
	}
	if f.PowerWatts != nil {
		c.items["power"]++
	}

	c.systemPower()
	c.thermal()
	c.power()
	c.storage()
	c.memory()
	c.cpus()
	c.managers()
	c.nics()
	c.eventFindings()
	c.summary(w.rollups)
	c.tables()
	base := map[string]model.Coverage{}
	for _, a := range areaDefs {
		cv := coverageOf(w.areas[a.id], c)
		base[a.id] = cv
		res.Coverage = append(res.Coverage, cv)
	}
	// Components read as part of a wider area get their own entry, so the
	// report shows fans, RAID, CPUs, NICs and the BMC as checked.
	for _, d := range []struct {
		id, from, comp string
		name           model.Text
		n              int
	}{
		{"fans", "thermal", model.CompFan, model.T("Fans (Redfish)", "Quạt (Redfish)"), len(f.Fans)},
		{"raid", "storage", model.CompRAID, model.T("RAID volumes and controllers (Redfish)", "Volume RAID và controller (Redfish)"), len(f.Volumes) + len(f.Controllers) + len(f.Batteries)},
		{"cpu", "system", model.CompCPU, model.T("Processors (Redfish)", "CPU (Redfish)"), len(f.CPUs)},
		{"network", "system", model.CompNetwork, model.T("Network interfaces (Redfish)", "Card mạng (Redfish)"), len(f.NICs)},
		{"bmc", "system", model.CompBMC, model.T("BMC health (Redfish)", "Tình trạng BMC (Redfish)"), len(f.Managers)},
	} {
		cv := base[d.from]
		cv.ID, cv.Component, cv.Name = domain+"."+d.id, d.comp, d.name
		if d.n == 0 && (cv.State == model.CovRan || cv.State == model.CovPartial) {
			cv.State = model.CovSkipped
			cv.Reason = model.T("The BMC lists none over Redfish.", "BMC không liệt kê mục nào qua Redfish.")
			cv.Fix, cv.Cmd = model.Text{}, ""
		}
		res.Coverage = append(res.Coverage, cv)
	}
	res.Facts = c.facts
	return res
}

var areaDefs = []area{
	{id: "system", comp: model.CompSystem, name: model.T("System health (Redfish)", "Tình trạng hệ thống (Redfish)")},
	{id: "thermal", comp: model.CompThermal, name: model.T("Temperatures and fans (Redfish)", "Nhiệt độ và quạt (Redfish)")},
	{id: "power", comp: model.CompPower, name: model.T("Power supplies (Redfish)", "Bộ nguồn (Redfish)")},
	{id: "storage", comp: model.CompDisk, name: model.T("Drives and RAID (Redfish)", "Ổ cứng và RAID (Redfish)")},
	{id: "memory", comp: model.CompMemory, name: model.T("Memory modules (Redfish)", "Thanh RAM (Redfish)")},
	{id: "logs", comp: model.CompLogs, name: model.T("BMC event logs (Redfish)", "Nhật ký sự kiện BMC (Redfish)")},
}

type checker struct {
	res        *model.Result
	env        model.Env
	facts      *Facts
	poweredOff bool
	logsRead   bool           // at least one log service with entries was read
	items      map[string]int // inventory found per coverage area
	// Commands to collect again: over IPMI, or with a longer timeout.
	ipmiCmd, retryCmd string
	// worst is the most severe finding so far, to decide whether the BMC's
	// overall health rollup is already explained by a specific finding.
	worst model.Severity
}

func (c *checker) add(f model.Finding) {
	if f.Severity > c.worst && f.ID != domain+".event_history" {
		c.worst = f.Severity
	}
	c.res.Findings = append(c.res.Findings, f)
}

func (c *checker) isPoweredOff() bool {
	if len(c.facts.Systems) == 0 {
		return false
	}
	for _, s := range c.facts.Systems {
		if !strings.EqualFold(s.PowerState, "Off") {
			return false
		}
	}
	return true
}

func coverageOf(a *area, c *checker) model.Coverage {
	cov := model.Coverage{ID: domain + "." + a.id, Component: a.comp, Name: a.name, State: model.CovRan}
	list := func(xs []string) string {
		if len(xs) > 3 {
			return strings.Join(xs[:3], "; ") + fmt.Sprintf("; +%d more", len(xs)-3)
		}
		return strings.Join(xs, "; ")
	}
	denyFix := model.T("Use a BMC account with at least read-only rights to inventory and logs (Dell: Read Only, HPE: Login, Supermicro: Operator), then collect again.",
		"Dùng tài khoản BMC có tối thiểu quyền đọc thông tin phần cứng và nhật ký (Dell: Read Only, HPE: Login, Supermicro: Operator), rồi thu thập lại.")
	fwFix := model.T("Update the BMC firmware (older firmware exposes less over Redfish); IPMI over LAN may still show it.",
		"Cập nhật firmware BMC (firmware cũ cung cấp ít dữ liệu qua Redfish hơn); đọc qua IPMI trên mạng LAN có thể vẫn lấy được.")
	switch {
	case a.ok == 0 && len(a.denied) > 0:
		cov.State = model.CovFailed
		cov.Reason = model.Tf("The BMC refused access (%s).", "BMC từ chối truy cập (%s).", list(a.denied))
		cov.Fix = denyFix
	case a.ok == 0 && len(a.failed) > 0:
		cov.State = model.CovFailed
		cov.Reason = model.Tf("Could not read it from the BMC: %s.", "Không đọc được từ BMC: %s.", list(a.failed))
		cov.Cmd = c.retryCmd
		cov.Fix = model.T("Check the network to the BMC and collect again with a longer timeout; if it keeps failing, reset the BMC (this does not affect the running OS).",
			"Kiểm tra kết nối mạng tới BMC rồi thu thập lại với thời gian chờ dài hơn; nếu vẫn lỗi, reset BMC (không ảnh hưởng hệ điều hành đang chạy).")
	case a.ok == 0 && len(a.missing) > 0:
		cov.State = model.CovFailed
		cov.Reason = model.T("Not collected: the collection hit its time or request limit.", "Chưa thu thập được: quá trình thu thập chạm giới hạn thời gian hoặc số yêu cầu.")
		cov.Fix = model.T("Collect again with a longer timeout.", "Thu thập lại với thời gian chờ dài hơn.")
		cov.Cmd = c.retryCmd
	case a.ok == 0:
		cov.State = model.CovSkipped
		cov.Reason = model.T("This BMC does not provide this data over Redfish.", "BMC này không cung cấp dữ liệu này qua Redfish.")
		cov.Fix = fwFix
		cov.Cmd = c.ipmiCmd
	case len(a.denied) > 0:
		cov.State = model.CovPartial
		cov.Reason = model.Tf("Some resources were refused (%s).", "Một số mục bị BMC từ chối (%s).", list(a.denied))
		cov.Fix = denyFix
	case len(a.failed) > 0:
		cov.State = model.CovPartial
		cov.Reason = model.Tf("Some resources could not be read: %s.", "Một số mục không đọc được: %s.", list(a.failed))
	case len(a.missing) > 0:
		cov.State = model.CovPartial
		cov.Reason = model.Tf("%d resources were not collected (time or request limit).", "%d mục chưa được thu thập (giới hạn thời gian hoặc số yêu cầu).", len(a.missing))
	}
	if cov.State == model.CovRan && c.items[a.id] == 0 {
		// The resources were read but listed nothing: do not claim the
		// check ran (e.g. Thermal 404 and no ThermalSubsystem, an empty
		// Memory collection, only dump/audit logs).
		cov.State = model.CovSkipped
		cov.Reason = model.T("The BMC answered but lists none of this data over Redfish.", "BMC có phản hồi nhưng không cung cấp dữ liệu này qua Redfish.")
		if a.id == "logs" {
			cov.Reason = model.T("The BMC offers no hardware event log over Redfish (only audit, dump or diagnostic logs).", "BMC không cung cấp nhật ký sự kiện phần cứng qua Redfish (chỉ có nhật ký audit, dump hoặc chẩn đoán).")
		}
		cov.Fix = fwFix
		cov.Cmd = c.ipmiCmd
	}
	if a.id == "thermal" && cov.State == model.CovRan && c.poweredOff {
		cov.State = model.CovPartial
		cov.Reason = model.T("The server is powered off: most sensors have no reading.", "Server đang tắt nguồn: phần lớn cảm biến không có số đo.")
	}
	return cov
}

// rerunCmds builds the "diagward bmc" commands for coverage entries from
// the address the bundle was collected from ("" when unknown or unsafe to
// paste into a shell).
func rerunCmds(b *collect.Bundle) (ipmi, retry string) {
	addr := strings.TrimSpace(b.Host)
	if addr == "" {
		addr = strings.TrimSpace(b.Get("meta.bmc").KV()["address"])
	}
	if addr == "" {
		return "", ""
	}
	for _, r := range addr {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(".:-_[]%/", r)
		if !ok {
			return "", ""
		}
	}
	return "diagward bmc " + addr + " --protocol ipmi", "diagward bmc " + addr + " --timeout 600"
}
