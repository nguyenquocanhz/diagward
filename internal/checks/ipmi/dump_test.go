package ipmi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
)

// TestDump prints findings for fixtures named in DW_* variables:
// DW_DUMP=1 DW_SDR=x DW_SEL=y DW_FRU=z go test -run Dump -v
func TestDump(t *testing.T) {
	if os.Getenv("DW_DUMP") == "" {
		t.Skip("set DW_DUMP=1")
	}
	var secs []*collect.Section
	for env, sec := range map[string]string{"DW_SDR": "ipmi.sdr", "DW_SEL": "ipmi.sel", "DW_FRU": "ipmi.fru", "DW_SELINFO": "ipmi.sel_info",
		"DW_CHASSIS": "ipmi.chassis", "DW_MC": "ipmi.mc", "DW_LAN": "ipmi.lan", "DW_POWER": "ipmi.power"} {
		if f := os.Getenv(env); f != "" {
			secs = append(secs, testkit.S(sec, testkit.Read(t, f)))
		}
	}
	res := Check(testkit.Bundle(collect.OSLinux, secs...), testkit.Env(collect.OSLinux))
	var b strings.Builder
	for _, f := range res.Findings {
		fmt.Fprintf(&b, "\n[%s] %s @ %s (%s)\n  EN: %s\n  VI: %s\n", f.Severity, f.ID, f.Target, f.Component, f.Title.EN, f.Title.VI)
		if f.Part != nil {
			fmt.Fprintf(&b, "  part: %+v\n", *f.Part)
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "    | %s\n", e)
		}
	}
	for _, c := range res.Coverage {
		fmt.Fprintf(&b, "cov %s %s %s\n", c.ID, c.State, c.Reason.EN)
	}
	for _, tb := range res.Tables {
		fmt.Fprintf(&b, "table %s (%d rows)\n", tb.ID, len(tb.Rows))
		for _, r := range tb.Rows {
			fmt.Fprintf(&b, "   %s %v\n", r.Status, r.Cells)
		}
	}
	t.Log(b.String())
}
