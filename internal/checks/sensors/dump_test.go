package sensors

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
)

// TestDump prints the analysis of a fixture set (DW_DUMP=1 go test -run Dump -v).
func TestDump(t *testing.T) {
	if os.Getenv("DW_DUMP") == "" {
		t.Skip("set DW_DUMP=1")
	}
	b := testkit.Bundle(collect.OSLinux,
		testkit.S("sensors.lmsensors", testkit.Read(t, os.Getenv("DW_RAW"))),
		testkit.S("sensors.lmsensors_json", testkit.Read(t, os.Getenv("DW_JSON"))),
		testkit.S("sensors.hwmon", testkit.Read(t, os.Getenv("DW_HWMON"))),
	)
	res := Check(b, testkit.Env(collect.OSLinux))
	out, _ := json.MarshalIndent(res, "", "  ")
	t.Log(string(out))
}
