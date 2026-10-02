// Package diag turns a collected Bundle into a Report: it runs every domain
// check and combines their findings, tables and coverage.
package diag

import (
	"fmt"
	"runtime/debug"
	"sort"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/cpu"
	"github.com/nguyenquocanhz/diagward/internal/checks/disk"
	"github.com/nguyenquocanhz/diagward/internal/checks/filesystem"
	"github.com/nguyenquocanhz/diagward/internal/checks/ipmi"
	"github.com/nguyenquocanhz/diagward/internal/checks/logs"
	"github.com/nguyenquocanhz/diagward/internal/checks/memory"
	"github.com/nguyenquocanhz/diagward/internal/checks/network"
	"github.com/nguyenquocanhz/diagward/internal/checks/raid"
	"github.com/nguyenquocanhz/diagward/internal/checks/redfish"
	"github.com/nguyenquocanhz/diagward/internal/checks/sensors"
	"github.com/nguyenquocanhz/diagward/internal/checks/system"
	"github.com/nguyenquocanhz/diagward/model"
)

// Version is set at build time (-ldflags "-X .../diag.Version=0.1.0").
var Version = "dev"

// Check is one domain analysis.
type Check func(b *collect.Bundle, env model.Env) model.Result

var checks = []struct {
	domain string
	fn     Check
}{
	{"system", system.Check},
	{"cpu", cpu.Check},
	{"memory", memory.Check},
	{"disk", disk.Check},
	{"raid", raid.Check},
	{"filesystem", filesystem.Check},
	{"sensors", sensors.Check},
	{"ipmi", ipmi.Check},
	{"redfish", redfish.Check},
	{"network", network.Check},
	{"logs", logs.Check},
}

// Analyze runs every check on b. It never fails: a check that panics is
// reported as failed coverage and the rest of the report is still produced.
func Analyze(b *collect.Bundle) *model.Report {
	env := collect.EnvOf(b)
	rep := &model.Report{
		Tool:      "diagward",
		Version:   Version,
		Env:       env,
		Collected: b.Finished,
	}
	if !b.Started.IsZero() && b.Finished.After(b.Started) {
		rep.Seconds = b.Finished.Sub(b.Started).Seconds()
	}
	rep.Host = safeHost(b, env)
	if rep.Host.Hostname == "" {
		rep.Host.Hostname = b.Host
	}
	for _, c := range checks {
		res := run(c.domain, c.fn, b, env)
		if res.Domain == "" {
			res.Domain = c.domain
		}
		rep.Results = append(rep.Results, res)
		rep.Findings = append(rep.Findings, res.Findings...)
		rep.Coverage = append(rep.Coverage, res.Coverage...)
	}
	order := map[string]int{}
	for i, c := range model.Components {
		order[c] = i
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if order[a.Component] != order[b.Component] {
			return order[a.Component] < order[b.Component]
		}
		return a.Target < b.Target
	})
	rep.Summary = summarize(rep)
	for _, f := range rep.Findings {
		rep.Verdict = model.Worst(rep.Verdict, f.Severity)
	}
	rep.Notes = notes(b, env)
	return rep
}

func safeHost(b *collect.Bundle, env model.Env) (h model.HostInfo) {
	defer func() {
		if r := recover(); r != nil {
			h = model.HostInfo{Hostname: b.Host}
		}
	}()
	return system.HostInfo(b, env)
}

func run(domain string, fn Check, b *collect.Bundle, env model.Env) (res model.Result) {
	defer func() {
		if r := recover(); r != nil {
			res = model.Result{
				Domain: domain,
				Coverage: []model.Coverage{{
					ID:     domain + ".internal",
					Name:   model.Tf("%s analysis", "Phân tích %s", domain),
					State:  model.CovFailed,
					Reason: model.Tf("Internal error: %v. Please report it with the saved bundle.", "Lỗi nội bộ: %v. Vui lòng báo lỗi kèm tệp bundle đã lưu.", r),
				}},
			}
			_ = debug.Stack()
		}
	}()
	return fn(b, env)
}

func summarize(rep *model.Report) []model.ComponentSummary {
	idx := map[string]*model.ComponentSummary{}
	var out []model.ComponentSummary
	for _, c := range model.Components {
		out = append(out, model.ComponentSummary{Component: c, Name: model.ComponentName(c)})
	}
	for i := range out {
		idx[out[i].Component] = &out[i]
	}
	for _, c := range rep.Coverage {
		if s := idx[c.Component]; s != nil && (c.State == model.CovRan || c.State == model.CovPartial) {
			s.Checked = true
		}
	}
	for _, f := range rep.Findings {
		s := idx[f.Component]
		if s == nil {
			continue
		}
		s.Checked = true
		s.Severity = model.Worst(s.Severity, f.Severity)
		switch f.Severity {
		case model.Crit:
			s.Crit++
		case model.Warn:
			s.Warn++
		case model.Info:
			s.Info++
		}
	}
	return out
}

func notes(b *collect.Bundle, env model.Env) []model.Text {
	var n []model.Text
	if env.OS != collect.OSBMC && !env.Root {
		if env.OS == collect.OSWindows {
			n = append(n, model.T("Diagward ran without Administrator rights, so some checks were skipped. Run it again as Administrator for a complete report.",
				"Diagward chạy không có quyền Administrator nên một số mục đã bị bỏ qua. Hãy chạy lại bằng quyền Administrator để có báo cáo đầy đủ."))
		} else {
			n = append(n, model.T("Diagward ran without root, so some checks were skipped. Run it again with sudo for a complete report.",
				"Diagward chạy không có quyền root nên một số mục đã bị bỏ qua. Hãy chạy lại bằng sudo để có báo cáo đầy đủ."))
		}
	}
	if !env.Bare() && env.OS != collect.OSBMC {
		n = append(n, model.Tf("This machine is virtual (%s). Disks, RAM, fans and power supplies belong to the host, so hardware checks are limited; check the physical host for hardware faults.",
			"Máy này là máy ảo (%s). Ổ cứng, RAM, quạt, nguồn thuộc về máy host nên phần kiểm tra phần cứng bị giới hạn; hãy kiểm tra máy chủ vật lý nếu nghi lỗi phần cứng.", env.Virtual))
	}
	if b.Get("meta.done") == nil && b.OS != collect.OSBMC {
		n = append(n, model.T("Collection did not finish (it was interrupted or timed out); the report may be incomplete.",
			"Quá trình thu thập chưa hoàn tất (bị ngắt hoặc quá thời gian); báo cáo có thể thiếu."))
	}
	return n
}

// String is a short one-line summary, for logs.
func String(rep *model.Report) string {
	var c, w int
	for _, f := range rep.Findings {
		switch f.Severity {
		case model.Crit:
			c++
		case model.Warn:
			w++
		}
	}
	return fmt.Sprintf("%s: %s (%d critical, %d warnings)", rep.Host.Hostname, rep.Verdict, c, w)
}
