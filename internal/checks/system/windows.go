package system

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

type winPerf struct {
	ProcessorQueueLength *float64
	PercentProcessorTime *float64
	DiskPercentIdleTime  *float64
	DiskAvgQueueLength   *float64
}

func checkWindows(b *collect.Bundle, env model.Env, res *model.Result) {
	ident := windowsIdentity(b)
	facts := &Facts{Identity: ident}
	res.Facts = facts

	c := model.Coverage{ID: "system.identity", Component: model.CompSystem,
		Name: model.T("Server identity (vendor, model, service tag, BIOS)", "Thông tin máy chủ (hãng, model, serial/service tag, BIOS)")}
	if ident.Source == "cim" {
		c.State = model.CovRan
	} else {
		c.State = model.CovFailed
		c.Reason = model.T("Win32_ComputerSystem could not be read.", "Không đọc được Win32_ComputerSystem.")
		if s := b.Get("system.win_computer"); s != nil && strings.TrimSpace(s.Err) != "" {
			c.Reason = model.Tf("Win32_ComputerSystem could not be read: %s", "Không đọc được Win32_ComputerSystem: %s", firstLine(s.Err))
		}
	}
	res.Coverage = append(res.Coverage, c)
	h := windowsHost(b, env)
	facts.UptimeSeconds = h.Uptime
	identityTable(ident, h, res)
	if env.Bare() {
		biosAge(ident, env, res)
	}

	ld, ok := windowsLoad(b, ident)
	loadCoverage(b, env, ok, res)
	if ok {
		facts.Load = ld
		if !windowsLoadFindings(ld, res) {
			okLoad(ld, res)
		}
	}

	var rb []struct {
		CbsRebootPending, WuRebootRequired, PendingFileRename bool
	}
	if collect.DecodeJSON(b.Get("system.win_reboot").Text(), &rb) == nil && len(rb) > 0 {
		var ev []string
		if rb[0].CbsRebootPending {
			ev = append(ev, `HKLM\...\Component Based Servicing\RebootPending exists`)
		}
		if rb[0].WuRebootRequired {
			ev = append(ev, `HKLM\...\WindowsUpdate\Auto Update\RebootRequired exists`)
		}
		// PendingFileRenameOperations alone is set by many installers and
		// often lingers; it only counts together with the servicing keys.
		if len(ev) > 0 {
			if rb[0].PendingFileRename {
				ev = append(ev, `Session Manager\PendingFileRenameOperations is set`)
			}
			facts.RebootRequired = true
			addReboot(ev, res)
		}
	}
}

func windowsLoad(b *collect.Bundle, id Identity) (*Load, bool) {
	var ps []winPerf
	if collect.DecodeJSON(b.Get("system.win_perf").Text(), &ps) != nil || len(ps) == 0 {
		return nil, false
	}
	avg := func(get func(winPerf) *float64) *float64 {
		var sum float64
		n := 0
		for _, p := range ps {
			if v := get(p); v != nil && *v >= 0 {
				sum += *v
				n++
			}
		}
		if n == 0 {
			return nil
		}
		a := sum / float64(n)
		return &a
	}
	ld := &Load{CPUs: id.Threads}
	ld.CPUPct = avg(func(p winPerf) *float64 { return p.PercentProcessorTime })
	q := avg(func(p winPerf) *float64 { return p.ProcessorQueueLength })
	if q != nil && ld.CPUs > 0 {
		v := *q / float64(ld.CPUs)
		ld.QueuePerCPU = &v
	}
	ld.DiskIdlePct = avg(func(p winPerf) *float64 { return p.DiskPercentIdleTime })
	ld.DiskQueueLen = avg(func(p winPerf) *float64 { return p.DiskAvgQueueLength })
	if ld.CPUPct == nil && q == nil && ld.DiskIdlePct == nil {
		return nil, false
	}
	return ld, true
}

func windowsLoadFindings(ld *Load, res *model.Result) bool {
	added := false
	ev := []string{fmt.Sprintf("3 samples, 1 s apart: CPU %.0f%%, processor queue %.1f per CPU (%d CPUs), disk idle %.0f%%, disk queue %.1f",
		deref(ld.CPUPct), deref(ld.QueuePerCPU), ld.CPUs, deref(ld.DiskIdlePct), deref(ld.DiskQueueLen))}
	if ld.CPUPct != nil && ld.QueuePerCPU != nil && *ld.CPUPct >= winCPUWarn && *ld.QueuePerCPU > winQueuePerCPUWarn {
		added = true
		res.Findings = append(res.Findings, model.Finding{
			ID: "system.overloaded", Component: model.CompSystem, Severity: model.Warn,
			Title: model.Tf("Server is overloaded: CPU %.0f%% busy with %.1f threads waiting per CPU", "Máy chủ đang quá tải: CPU bận %.0f%%, trung bình %.1f luồng chờ mỗi CPU", *ld.CPUPct, *ld.QueuePerCPU),
			Detail: model.T("Threads are queueing for the processors, so applications respond slowly. This is a short sample taken while Diagward ran; confirm it in Task Manager or Performance Monitor.",
				"Các luồng phải xếp hàng chờ CPU nên ứng dụng phản hồi chậm. Đây là mẫu ngắn lấy lúc Diagward chạy; hãy xác nhận lại bằng Task Manager hoặc Performance Monitor."),
			Action: model.T("Find the busy processes (Task Manager > Details, sort by CPU, or Get-Process | Sort-Object CPU -Descending | Select -First 10). Stop runaway jobs, reschedule heavy tasks, or add CPU capacity.",
				"Tìm tiến trình chiếm CPU (Task Manager > Details, sắp xếp theo CPU, hoặc Get-Process | Sort-Object CPU -Descending | Select -First 10). Dừng tiến trình bất thường, dời tác vụ nặng, hoặc nâng cấp CPU."),
			Evidence: ev,
		})
	}
	if ld.DiskIdlePct != nil && ld.DiskQueueLen != nil && *ld.DiskIdlePct < winDiskIdleWarn && *ld.DiskQueueLen >= winDiskQueueWarn {
		added = true
		res.Findings = append(res.Findings, model.Finding{
			ID: "system.io_bottleneck", Component: model.CompSystem, Severity: model.Warn,
			Title: model.Tf("Storage is the bottleneck: disks idle only %.0f%% of the time", "Ổ cứng đang là điểm nghẽn: ổ đĩa chỉ rảnh %.0f%% thời gian", *ld.DiskIdlePct),
			Detail: model.Tf("Physical disks were busy almost all the time with %.1f requests waiting on average. A failing disk or a degraded/rebuilding RAID or Storage Spaces pool is a common cause.",
				"Ổ đĩa vật lý gần như bận liên tục, trung bình %.1f yêu cầu đang chờ. Nguyên nhân hay gặp là ổ sắp hỏng hoặc RAID/Storage Spaces đang suy giảm hoặc rebuild.", *ld.DiskQueueLen),
			Action: model.T("Check the Disks and RAID sections first. Then find the busy disk and process in Resource Monitor (resmon.exe, Disk tab).",
				"Xem mục Ổ cứng và RAID trước. Sau đó tìm ổ và tiến trình đọc/ghi nhiều trong Resource Monitor (resmon.exe, tab Disk)."),
			Evidence: ev,
		})
	}
	return added
}
