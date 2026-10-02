package bmc

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/redfish"
)

// TestLive reads a real Redfish service (or the DMTF Redfish Mockup
// Server) when DW_BMC_LIVE is set, e.g.
//
//	DW_BMC_LIVE=http://127.0.0.1:8000 DW_BMC_USER=root DW_BMC_PASS=... go test ./bmc -run Live -v
//
// It prints what was collected and the analysis; it never fails on the
// findings themselves.
func TestLive(t *testing.T) {
	host := os.Getenv("DW_BMC_LIVE")
	if host == "" {
		t.Skip("set DW_BMC_LIVE to run against a real BMC or the DMTF mockup server")
	}
	o := Options{Host: host, User: os.Getenv("DW_BMC_USER"), Password: os.Getenv("DW_BMC_PASS"),
		Insecure: os.Getenv("DW_BMC_INSECURE") != "", Protocol: os.Getenv("DW_BMC_PROTO"), Timeout: 2 * time.Minute}
	start := time.Now()
	b, err := Collect(context.Background(), o)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	fmt.Printf("collected %d sections in %s\n%s\n", len(b.Sections), time.Since(start).Round(time.Millisecond), b.Get("meta.bmc").Text())
	bad := 0
	for _, s := range b.Sections {
		if s.RC != 200 && strings.HasPrefix(s.Name, "redfish.res:") {
			bad++
			if bad <= 15 {
				fmt.Printf("  %s rc=%d %s\n", s.Name, s.RC, s.Err)
			}
		}
	}
	env := collect.EnvOf(b)
	res := redfish.Check(b, env)
	for _, f := range res.Findings {
		fmt.Printf("%-5s %-32s %-28s %s\n", f.Severity, f.ID, f.Target, f.Title.VI)
	}
	for _, c := range res.Coverage {
		fmt.Printf("cov %-18s %-8s %s\n", c.ID, c.State, c.Reason.EN)
	}
	fmt.Printf("host %+v\n", redfish.HostInfo(b))
}
