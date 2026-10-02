package model

import (
	"reflect"
	"testing"
)

func TestNewRow(t *testing.T) {
	r := NewRow(Warn, "eth0", T("down", "mất link"), 3, nil)
	if !reflect.DeepEqual(r.Cells, []string{"eth0", "down", "3", ""}) || !reflect.DeepEqual(r.VI, []string{"eth0", "mất link", "3", ""}) {
		t.Errorf("%+v", r)
	}
	if got := r.CellsIn("vi"); !reflect.DeepEqual(got, []string{"eth0", "mất link", "3", ""}) {
		t.Errorf("CellsIn(vi) = %q", got)
	}
	if got := r.CellsIn("en"); !reflect.DeepEqual(got, r.Cells) {
		t.Errorf("CellsIn(en) = %q", got)
	}
	if r.Cell(1, "vi-VN") != "mất link" || r.Cell(9, "vi") != "" || r.CellText(1) != T("down", "mất link") {
		t.Errorf("Cell: %q %q %+v", r.Cell(1, "vi-VN"), r.Cell(9, "vi"), r.CellText(1))
	}

	// No words to translate: VI stays nil (JSON omits it).
	if r := NewRow(OK, "sda", "4 TB"); r.VI != nil {
		t.Errorf("VI set for language-neutral row: %+v", r)
	}
	// A Text with only one language is used for both.
	if r := NewRow(OK, Text{EN: "x"}, Text{VI: "y"}); !reflect.DeepEqual(r.Cells, []string{"x", "y"}) || r.VI != nil {
		t.Errorf("one-language texts: %+v", r)
	}
}

func TestRowSetCellAndLegacy(t *testing.T) {
	r := NewRow(OK, "a", "b", "c")
	r.SetCell(2, T("ok", "ổn"))
	r.SetCell(7, "ignored")
	if !reflect.DeepEqual(r.VI, []string{"a", "b", "ổn"}) || r.Cells[2] != "ok" {
		t.Errorf("%+v", r)
	}
	r.Add(T("up", "có link"))
	if len(r.VI) != len(r.Cells) || r.VI[3] != "có link" {
		t.Errorf("Add: %+v", r)
	}
	// A row written by an older version (or by hand) without VI, or with a
	// short VI, falls back to the English cells.
	old := Row{Cells: []string{"x", "y"}, VI: []string{"ix"}}
	if got := old.CellsIn("vi"); !reflect.DeepEqual(got, []string{"ix", "y"}) {
		t.Errorf("short VI: %q", got)
	}
}

func TestCPUSummary(t *testing.T) {
	for _, c := range []struct {
		model                   string
		sockets, cores, threads int
		en, vi                  string
	}{
		{"Intel Xeon Gold 6154", 2, 36, 72, "2 × Intel Xeon Gold 6154 (36 cores, 72 threads)", "2 × Intel Xeon Gold 6154 (36 nhân, 72 luồng)"},
		{"Intel Core i5-10300H", 1, 1, 2, "Intel Core i5-10300H (1 core, 2 threads)", "Intel Core i5-10300H (1 nhân, 2 luồng)"},
		{"", 0, 0, 72, "CPU (72 threads)", "CPU (72 luồng)"},
		{"AMD EPYC 7763", 2, 0, 0, "2 × AMD EPYC 7763", "2 × AMD EPYC 7763"},
		{"", 0, 0, 0, "", ""},
	} {
		if got := CPUSummary(c.model, c.sockets, c.cores, c.threads); got != T(c.en, c.vi) {
			t.Errorf("CPUSummary(%q, %d, %d, %d) = %+v", c.model, c.sockets, c.cores, c.threads, got)
		}
	}
	var h HostInfo
	h.SetCPU("Intel Xeon Silver 4214", 2, 24, 48)
	if h.CPU != "2 × Intel Xeon Silver 4214 (24 cores, 48 threads)" || h.CPUText().VI != "2 × Intel Xeon Silver 4214 (24 nhân, 48 luồng)" {
		t.Errorf("%+v %+v", h, h.CPUText())
	}
	if old := (HostInfo{CPU: "2 CPU"}); old.CPUText() != T("2 CPU", "2 CPU") {
		t.Errorf("legacy: %+v", old.CPUText())
	}
}
