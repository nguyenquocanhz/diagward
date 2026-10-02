package bmc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nguyenquocanhz/diagward/collect"
)

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in       string
		port     int
		ipmi     bool
		base     string
		ipmiPort string
		display  string
		err      bool
	}{
		{in: "10.0.0.5", base: "https://10.0.0.5", display: "10.0.0.5"},
		{in: "10.0.0.5:8443", base: "https://10.0.0.5:8443", display: "10.0.0.5:8443"},
		{in: "10.0.0.5", port: 8443, base: "https://10.0.0.5:8443", display: "10.0.0.5:8443"},
		{in: "https://bmc.example", base: "https://bmc.example", display: "bmc.example"},
		{in: "https://bmc.example:4443/", base: "https://bmc.example:4443", display: "bmc.example:4443"},
		{in: "https://bmc.example/redfish/v1/", base: "https://bmc.example", display: "bmc.example"},
		{in: "http://127.0.0.1:8000", base: "http://127.0.0.1:8000", display: "http://127.0.0.1:8000"},
		{in: "fe80::1", base: "https://[fe80::1]", display: "[fe80::1]"},
		{in: "[fe80::1]:443", base: "https://[fe80::1]:443", display: "[fe80::1]:443"},
		{in: "10.0.0.5", ipmi: true, port: 6230, base: "https://10.0.0.5", ipmiPort: "6230", display: "10.0.0.5:6230"},
		{in: "  idrac-01  ", base: "https://idrac-01", display: "idrac-01"},
		{in: "", err: true},
		{in: "https://root:calvin@10.0.0.5", err: true},
		{in: "root@10.0.0.5", err: true},
		{in: "ftp://10.0.0.5", err: true},
		{in: "10.0.0.5:99999", err: true},
		{in: "https://bmc/some/path", err: true},
		{in: "bmc .lan", err: true},
	}
	for _, c := range cases {
		a, err := parseAddress(c.in, c.port, c.ipmi)
		if c.err {
			if err == nil || !errors.Is(err, ErrAddress) {
				t.Errorf("%q: want ErrAddress, got %v", c.in, err)
			}
			if err != nil && strings.Contains(err.Error(), "calvin") {
				t.Errorf("%q: password echoed in error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if a.baseURL().String() != c.base || a.ipmiPort != c.ipmiPort || a.display != c.display {
			t.Errorf("%q: base %s ipmi %q display %q", c.in, a.baseURL(), a.ipmiPort, a.display)
		}
	}
}

func TestCollectBadInput(t *testing.T) {
	if _, err := Collect(context.Background(), Options{Host: "10.0.0.5", Protocol: "snmp"}); err == nil {
		t.Error("unknown protocol accepted")
	}
	if b, err := Collect(context.Background(), Options{Host: "https://u:pw@h"}); err == nil || b != nil {
		t.Error("credentials in URL accepted")
	}
}

func TestScrub(t *testing.T) {
	s := `{"UserName":"admin","Password":"hunter2","Message":"Successfully logged in using admin, from 10.0.0.9","Role":"Administrator","Token":"abcdef0123456789"}`
	got := scrubText(s, "admin", "hunter2", "abcdef0123456789")
	for _, bad := range []string{`"hunter2"`, "using admin,", `"admin"`, "abcdef0123456789"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q left in %s", bad, got)
		}
	}
	if !strings.Contains(got, "Administrator") {
		t.Errorf("whole-word scrub broke a word: %s", got)
	}
	// Short passwords are only removed as JSON strings, not as substrings.
	if got := scrubText("test passed", "", "test", ""); got != "test passed" {
		t.Errorf("short password scrubbed a word: %q", got)
	}
	if got := redactLan("IP Address : 1.2.3.4\nSNMP Community String   : public\n"); strings.Contains(got, "public") {
		t.Errorf("lan %q", got)
	}
	b := &collect.Bundle{}
	b.Add(&collect.Section{Name: "x", Out: "pw=Very-Long-Secret", Err: "Very-Long-Secret"})
	scrubBundle(b, "", "Very-Long-Secret", "")
	if strings.Contains(b.Sections[0].Out+b.Sections[0].Err, "Very-Long-Secret") {
		t.Error("bundle not scrubbed")
	}
	err := scrubError(errors.Join(ErrAuth, errors.New("bad Very-Long-Secret")), "", "Very-Long-Secret")
	if !errors.Is(err, ErrAuth) || strings.Contains(err.Error(), "Very-Long-Secret") {
		t.Errorf("scrubError %v", err)
	}
}

func TestEntryOrder(t *testing.T) {
	mk := func(ts ...string) []any {
		var out []any
		for _, s := range ts {
			out = append(out, map[string]any{"Created": s})
		}
		return out
	}
	if entryOrder(mk("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")) != 1 ||
		entryOrder(mk("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")) != -1 ||
		entryOrder(mk("0000-00-00T00:00:00Z", "2026-01-01T00:00:00Z")) != 0 ||
		entryOrder(nil) != 0 {
		t.Error("entryOrder")
	}
}
