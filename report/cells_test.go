package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/model"
)

// cellsReport has one bilingual table row, one legacy row (Cells only, as
// written by an older Diagward) and a host whose CPU line has its parts.
func cellsReport() *model.Report {
	h := model.HostInfo{Hostname: "srv-db01"}
	h.SetCPU("Intel Xeon Gold 6154", 2, 36, 72)
	return &model.Report{
		Host: h, Verdict: model.OK,
		Results: []model.Result{{
			Domain: "network",
			Tables: []model.Table{{
				ID: "network.nics", Title: model.T("Network ports", "Cổng mạng"),
				Columns: []model.Text{model.T("Port", "Cổng"), model.T("Link", "Link"), model.T("Uptime", "Thời gian chạy")},
				Rows: []model.Row{
					model.NewRow(model.Warn, "enp0s8", model.T("down (unused)", "mất link (không dùng)"), model.T("1d 6h", "1 ngày 6 giờ")),
					{Status: model.OK, Cells: []string{"enp0s9", "up", "5m"}},
				},
			}},
		}},
	}
}

func TestCellsInLanguage(t *testing.T) {
	r := cellsReport()
	vi := render(t, "text", r, Options{Lang: "vi", Verbose: true, Width: 120})
	for _, want := range []string{"mất link (không dùng)", "1 ngày 6 giờ", "2 × Intel Xeon Gold 6154 (36 nhân, 72 luồng)", "enp0s9", "5m"} {
		if !strings.Contains(vi, want) {
			t.Errorf("vi text lacks %q:\n%s", want, vi)
		}
	}
	for _, bad := range []string{"down (unused)", "1d 6h", "36 cores"} {
		if strings.Contains(vi, bad) {
			t.Errorf("vi text contains English %q", bad)
		}
	}
	en := render(t, "text", r, Options{Lang: "en", Verbose: true, Width: 120})
	for _, want := range []string{"down (unused)", "1d 6h", "2 × Intel Xeon Gold 6154 (36 cores, 72 threads)"} {
		if !strings.Contains(en, want) {
			t.Errorf("en text lacks %q:\n%s", want, en)
		}
	}
	if strings.Contains(en, "mất link") || strings.Contains(en, "nhân") {
		t.Error("en text contains Vietnamese cells")
	}
	html := render(t, "html", r, Options{Lang: "vi"})
	for _, want := range []string{
		`<span lang="vi">mất link (không dùng)</span><span lang="en">down (unused)</span>`,
		`<td>enp0s9</td>`,
		`<span lang="vi">2 × Intel Xeon Gold 6154 (36 nhân, 72 luồng)</span><span lang="en">2 × Intel Xeon Gold 6154 (36 cores, 72 threads)</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html lacks %q", want)
		}
	}
}

// Old consumers (Termward) read results[].tables[].rows[].cells and
// host.cpu: those keep their English content; the Vietnamese cells and the
// CPU parts are additional fields.
func TestCellsJSONCompatible(t *testing.T) {
	out := render(t, "json", cellsReport(), Options{})
	var v struct {
		Host    struct{ CPU, CPUModel string }
		Results []struct {
			Tables []struct {
				Rows []struct {
					Cells []string `json:"cells"`
					VI    []string `json:"vi"`
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v.Host.CPU != "2 × Intel Xeon Gold 6154 (36 cores, 72 threads)" || v.Host.CPUModel != "Intel Xeon Gold 6154" {
		t.Errorf("host %+v", v.Host)
	}
	rows := v.Results[0].Tables[0].Rows
	if rows[0].Cells[1] != "down (unused)" || rows[0].VI[1] != "mất link (không dùng)" || rows[0].VI[0] != "enp0s8" {
		t.Errorf("row 0 %+v", rows[0])
	}
	if rows[1].VI != nil || strings.Contains(out, `"vi": null`) {
		t.Errorf("a row without Vietnamese cells must leave vi out: %+v", rows[1])
	}
}

// A report saved before HostInfo had the CPU parts shows its CPU string in
// both languages.
func TestLegacyCPULine(t *testing.T) {
	r := &model.Report{Host: model.HostInfo{Hostname: "old", CPU: "2 × Intel Xeon (24 cores, 48 threads)"}}
	if vi := render(t, "text", r, Options{Lang: "vi", Verbose: true}); !strings.Contains(vi, "2 × Intel Xeon (24 cores, 48 threads)") {
		t.Errorf("legacy CPU line missing:\n%s", vi)
	}
}
