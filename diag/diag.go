// Package diag turns a collected Bundle into a Report: it runs every domain
// check and combines their findings, tables and coverage.
package diag

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"

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
	"github.com/nguyenquocanhz/diagward/internal/units"
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
		if res.Findings == nil {
			res.Findings = []model.Finding{}
		}
		rep.Results = append(rep.Results, res)
	}
	enrichParts(rep.Results)
	foldDiskLogFindings(rep.Results)
	if rep.Host.BMC == "" {
		rep.Host.BMC = bmcAddress(rep.Results)
	}
	rep.Findings = []model.Finding{}
	rep.Coverage = []model.Coverage{}
	for _, res := range rep.Results {
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
	if b.OS == collect.OSBMC {
		return redfish.HostInfo(b)
	}
	return system.HostInfo(b, env)
}

// enrichParts fills in vendor/model/serial on disk parts that other domains
// (logs, raid) could only name by device, using the disk domain's
// inventory, so the "parts to replace" list carries serial numbers.
func enrichParts(results []model.Result) {
	var disks []disk.DiskFact
	for _, r := range results {
		switch f := r.Facts.(type) {
		case disk.Facts:
			disks = f.Disks
		case *disk.Facts:
			if f != nil {
				disks = f.Disks
			}
		}
	}
	if len(disks) == 0 {
		return
	}
	byDev := map[string]disk.DiskFact{}
	for _, d := range disks {
		for _, k := range deviceKeys(d.Device) {
			byDev[k] = d
		}
	}
	for ri := range results {
		for fi := range results[ri].Findings {
			f := &results[ri].Findings[fi]
			if f.Part == nil || f.Part.Kind != "disk" || f.Part.Serial != "" {
				continue
			}
			var d disk.DiskFact
			found := false
			for _, k := range append(deviceKeys(f.Part.Location), deviceKeys(f.Target)...) {
				if d, found = byDev[k]; found {
					break
				}
			}
			if !found || d.Serial == "" {
				continue
			}
			q := *f.Part
			q.Vendor, q.Model, q.Serial = firstNonEmpty(q.Vendor, d.Vendor), firstNonEmpty(q.Model, d.Model), d.Serial
			q.Firmware = firstNonEmpty(q.Firmware, d.Firmware)
			if q.Size == "" && d.SizeBytes > 0 {
				q.Size = units.SI(d.SizeBytes)
			}
			f.Part = &q
		}
	}
}

// foldDiskLogFindings merges a kernel/event-log finding about a disk into the
// disk domain's own warning or critical finding for the same disk, so one
// failing disk reads as one problem with two kinds of evidence (S.M.A.R.T.
// counters and the log lines), not two separate problems. The merged finding
// keeps the higher severity. Log findings about disks the disk domain found
// healthy stay as they are: the log may be the only sign of trouble.
func foldDiskLogFindings(results []model.Result) {
	var diskRes, logRes *model.Result
	for i := range results {
		switch results[i].Domain {
		case "disk":
			diskRes = &results[i]
		case "logs":
			logRes = &results[i]
		}
	}
	if diskRes == nil || logRes == nil {
		return
	}
	keysOf := func(f model.Finding) []string {
		var k []string
		if f.Part != nil {
			k = append(k, deviceKeys(f.Part.Location)...)
		}
		return append(k, deviceKeys(f.Target)...)
	}
	// The most severe disk finding per device.
	target := map[string]int{}
	for i, f := range diskRes.Findings {
		if f.Severity < model.Warn || f.Component != model.CompDisk {
			continue
		}
		for _, k := range keysOf(f) {
			if j, ok := target[k]; !ok || diskRes.Findings[j].Severity < f.Severity {
				target[k] = i
			}
		}
	}
	if len(target) == 0 {
		return
	}
	kept := logRes.Findings[:0]
	for _, f := range logRes.Findings {
		j := -1
		if f.Component == model.CompDisk && f.Severity >= model.Warn {
			for _, k := range keysOf(f) {
				if i, ok := target[k]; ok {
					j = i
					break
				}
			}
		}
		if j < 0 {
			kept = append(kept, f)
			continue
		}
		d := &diskRes.Findings[j]
		d.Severity = model.Worst(d.Severity, f.Severity)
		d.Detail = model.Text{
			EN: strings.TrimSpace(d.Detail.EN + " The kernel/event log confirms it: " + f.Title.EN + "."),
			VI: strings.TrimSpace(d.Detail.VI + " Log hệ thống cũng xác nhận: " + f.Title.VI + "."),
		}
		for _, e := range f.Evidence {
			if len(d.Evidence) >= 12 {
				break
			}
			d.Evidence = append(d.Evidence, e)
		}
	}
	logRes.Findings = kept
}

// deviceKeys normalises a device name for matching: "/dev/sda", "sda" and
// "sda1" match the disk sda; Windows "PhysicalDrive1", "PhysicalDisk1" and
// `\\.\PhysicalDrive1` match disk number 1.
func deviceKeys(s string) []string {
	s = strings.TrimSpace(s)
	qual := ""
	if i := strings.IndexAny(s, " [,("); i > 0 {
		// A qualifier with a number names one disk behind a controller
		// ("/dev/bus/0 [megaraid,3]", "/dev/sda,cciss,1"): it must be part of
		// the key, or every disk on that controller would share one key and
		// get the wrong serial. Plain types ("sat", "nvme") are dropped.
		q := strings.ToLower(strings.Join(strings.FieldsFunc(s[i:], func(r rune) bool {
			return r == ' ' || r == '[' || r == ']' || r == '(' || r == ')'
		}), ""))
		q = strings.Trim(q, ",")
		if strings.ContainsAny(q, "0123456789") && q != "" && q[0] >= 'a' && q[0] <= 'z' {
			qual = q
		}
		s = s[:i]
	}
	low := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(s, `\\.\`), "/dev/"))
	if low == "" {
		return nil
	}
	if qual != "" {
		return []string{low + "#" + qual}
	}
	for _, p := range []string{"physicaldrive", "physicaldisk"} {
		if strings.HasPrefix(low, p) {
			return []string{"win:" + strings.TrimPrefix(low, p)}
		}
	}
	keys := []string{low}
	// The NVMe controller name (nvme0, from the driver or smartd) means its
	// first namespace.
	if strings.HasPrefix(low, "nvme") && strings.Trim(low[4:], "0123456789") == "" && len(low) > 4 {
		keys = append(keys, low+"n1")
	}
	// Strip a partition suffix: sda1 -> sda, nvme0n1p2 -> nvme0n1.
	if strings.HasPrefix(low, "nvme") {
		if i := strings.LastIndexByte(low, 'p'); i > strings.IndexByte(low, 'n') && i > 4 {
			keys = append(keys, low[:i])
		}
	} else if t := strings.TrimRight(low, "0123456789"); t != low && t != "" && !strings.HasPrefix(low, "md") {
		keys = append(keys, t)
	}
	return keys
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// bmcAddress reports the BMC's LAN address from the in-band IPMI data.
func bmcAddress(results []model.Result) string {
	for _, r := range results {
		var b ipmi.BMC
		switch f := r.Facts.(type) {
		case ipmi.Facts:
			b = f.BMC
		case *ipmi.Facts:
			if f == nil {
				continue
			}
			b = f.BMC
		default:
			continue
		}
		if b.Address != "" && b.Address != "0.0.0.0" {
			return b.Address
		}
	}
	return ""
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
		s := idx[c.Component]
		if s == nil {
			continue
		}
		switch c.State {
		case model.CovRan:
			s.Checked = true
		case model.CovPartial:
			s.Checked, s.Partial = true, true
		}
	}
	// A skipped or failed check makes a component "partial" only when
	// another check of it ran (otherwise it simply was not checked), and not
	// for opt-in tests nobody asked for.
	for _, c := range rep.Coverage {
		if s := idx[c.Component]; s != nil && s.Checked && (c.State == model.CovFailed || (c.State == model.CovSkipped && !optIn(c) && !c.NotApplicable)) {
			s.Partial = true
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

// optIn reports whether a coverage entry is an opt-in active test (disk
// benchmark, memory test) that is skipped unless requested.
func optIn(c model.Coverage) bool {
	return c.ID == "disk.bench" || c.ID == "memory.memtest"
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
	if st := b.Get("meta.stalled"); st != nil {
		kv := st.KV()
		n = append(n, model.Tf("Collection was stopped because step %q hung for %s seconds (a stuck driver, disk, controller or WMI provider). Steps after it are missing from this report; the hang itself points at that component.",
			"Quá trình thu thập bị dừng vì bước %q bị treo %s giây (driver, ổ, card RAID hoặc WMI bị kẹt). Các bước sau đó không có trong báo cáo; chính việc treo cũng là dấu hiệu lỗi ở thành phần đó.", kv["section"], kv["seconds"]))
	} else if b.Get("meta.done") == nil && b.OS != collect.OSBMC {
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
