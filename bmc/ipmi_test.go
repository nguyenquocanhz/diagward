package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
)

type call struct {
	env  []string
	name string
	args []string
}

// fakeRunner answers ipmitool commands from the ipmi domain's fixtures.
type fakeRunner struct {
	mu       sync.Mutex
	calls    []call
	failMC   string // stderr for "mc info" with rc 1
	selLines int
}

func fixture(name string) string {
	b, err := os.ReadFile(filepath.Join("..", "internal", "checks", "redfish", "testdata", name))
	if err != nil {
		return ""
	}
	return string(b)
}

func (f *fakeRunner) run(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{env: env, name: name, args: args})
	f.mu.Unlock()
	cmd := strings.Join(args[len(args)-2:], " ")
	switch {
	case strings.HasSuffix(strings.Join(args, " "), "mc info"):
		if f.failMC != "" {
			return nil, []byte(f.failMC), 1, nil
		}
		return []byte(fixture("mc_info_dell.txt")), nil, 0, nil
	case cmd == "fru print":
		return []byte(fixture("fru_dell_r640.txt")), nil, 0, nil
	case cmd == "lan print":
		return []byte("IP Address              : 10.0.0.50\nSNMP Community String   : TopSecret#$\nMAC Address             : 00:15:17:8f:48:32\n"), nil, 0, nil
	case cmd == "sel elist":
		var sb strings.Builder
		for i := 1; i <= f.selLines; i++ {
			fmt.Fprintf(&sb, "%4x | 09/30/2026 | 22:14:%02d | Power Supply PS2 Status | Power Supply AC lost | Asserted\n", i, i%60)
		}
		return []byte(sb.String()), nil, 0, nil
	}
	return []byte("ok\n"), nil, 0, nil
}

func useRunner(t *testing.T, f *fakeRunner) {
	t.Helper()
	oldRun, oldLook := runCommand, lookPath
	runCommand = f.run
	lookPath = func(string) (string, error) { return "/usr/bin/ipmitool", nil }
	t.Cleanup(func() { runCommand, lookPath = oldRun, oldLook })
}

func TestIPMICommandsPasswordOnlyInEnv(t *testing.T) {
	fr := &fakeRunner{selLines: 3500}
	useRunner(t, fr)
	o := Options{Host: "10.0.0.50", Port: 6230, User: "ADMIN", Password: "Sup3r-S3cret!", Protocol: "ipmi"}
	b, err := Collect(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != len(ipmiCommands) {
		t.Fatalf("%d calls", len(fr.calls))
	}
	for _, c := range fr.calls {
		line := strings.Join(c.args, " ")
		if strings.Contains(line, o.Password) || strings.Contains(c.name, o.Password) {
			t.Fatalf("password on the command line: %s", line)
		}
		if !strings.HasPrefix(line, "-I lanplus -H 10.0.0.50 -p 6230 -U ADMIN -E ") {
			t.Errorf("args %q", line)
		}
		if len(c.env) != 1 || c.env[0] != "IPMI_PASSWORD="+o.Password {
			t.Errorf("env %v", c.env)
		}
	}
	want := map[string]string{"ipmi.sdr": "sdr elist", "ipmi.sel_info": "sel info", "ipmi.sel": "sel elist", "ipmi.chassis": "chassis status",
		"ipmi.mc": "mc info", "ipmi.fru": "fru print", "ipmi.lan": "lan print", "ipmi.power": "dcmi power reading"}
	for sec, cmd := range want {
		if b.Get(sec) == nil {
			t.Errorf("missing section %s", sec)
		}
		found := false
		for _, c := range fr.calls {
			if strings.HasSuffix(strings.Join(c.args, " "), " "+cmd) {
				found = true
			}
		}
		if !found {
			t.Errorf("command %q not run", cmd)
		}
	}
	sel := b.Get("ipmi.sel")
	if n := len(sel.Lines()); n != ipmiMaxSELLines || !sel.Truncated || !strings.HasPrefix(sel.Lines()[n-1], " dac") {
		t.Errorf("sel: %d lines truncated=%v last=%q", n, sel.Truncated, sel.Lines()[n-1])
	}
	if lan := b.Get("ipmi.lan").Out; strings.Contains(lan, "TopSecret") || !strings.Contains(lan, "10.0.0.50") {
		t.Errorf("lan %q", lan)
	}
	m := b.Get("meta.bmc").KV()
	if m["protocol"] != "ipmi" || m["firmware"] != "6.10" || m["serial"] != "2RJF153" || m["model"] != "PowerEdge R640" {
		t.Errorf("meta %v", m)
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), o.Password) {
		t.Fatal("password in bundle")
	}
	if b.Host != "10.0.0.50" || b.OS != collect.OSBMC {
		t.Errorf("bundle %s %s", b.Host, b.OS)
	}
}

func TestIPMINoPasswordNoUser(t *testing.T) {
	fr := &fakeRunner{}
	useRunner(t, fr)
	if _, err := Collect(context.Background(), Options{Host: "bmc.lan", Protocol: "ipmi"}); err != nil {
		t.Fatal(err)
	}
	line := strings.Join(fr.calls[0].args, " ")
	if line != "-I lanplus -H bmc.lan mc info" || len(fr.calls[0].env) != 0 {
		t.Errorf("args %q env %v", line, fr.calls[0].env)
	}
}

func TestIPMIMissingTool(t *testing.T) {
	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { lookPath = old })
	b, err := Collect(context.Background(), Options{Host: "10.0.0.50", Protocol: "ipmi", User: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ipmiCommands {
		s := b.Get(c.section)
		if s == nil || s.Missing != "ipmitool" || s.Ran() {
			t.Errorf("%s: %+v", c.section, s)
		}
	}
}

func TestIPMISessionFailureStops(t *testing.T) {
	fr := &fakeRunner{failMC: "Error: Unable to establish IPMI v2 / RMCP+ session\n"}
	useRunner(t, fr)
	b, err := Collect(context.Background(), Options{Host: "10.0.0.50", Protocol: "ipmi", User: "ADMIN", Password: "wrong-pass"})
	if !errors.Is(err, ErrNoProtocol) || !strings.Contains(err.Error(), "IPMI over LAN is enabled") {
		t.Errorf("err %v", err)
	}
	if len(fr.calls) != 1 {
		t.Errorf("kept going after the session failed: %d calls", len(fr.calls))
	}
	if s := b.Get("ipmi.mc"); s == nil || s.RC != 1 || !strings.Contains(s.Err, "RMCP+") {
		t.Errorf("mc %+v", s)
	}
}

func TestIPMITimeout(t *testing.T) {
	old := ipmiCmdTimeout
	ipmiCmdTimeout = 50 * time.Millisecond
	t.Cleanup(func() { ipmiCmdTimeout = old })
	oldRun, oldLook := runCommand, lookPath
	runCommand = func(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	lookPath = func(string) (string, error) { return "ipmitool", nil }
	t.Cleanup(func() { runCommand, lookPath = oldRun, oldLook })
	b, err := Collect(context.Background(), Options{Host: "10.0.0.50", Protocol: "ipmi"})
	if !errors.Is(err, ErrNoProtocol) || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("err %v", err)
	}
	if s := b.Get("ipmi.mc"); s == nil || !s.Timeout || s.RC != 124 {
		t.Errorf("mc %+v", s)
	}
}

func TestRealExecRunner(t *testing.T) {
	// The real runner passes the extra environment and reports exit codes.
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	_ = exe
	name, args := "sh", []string{"-c", `printf '%s' "$IPMI_PASSWORD"; exit 3`}
	if _, err := lookPath(name); err != nil {
		t.Skip("no sh")
	}
	out, _, rc, err := execRunner(context.Background(), []string{"IPMI_PASSWORD=abc"}, name, args...)
	if err != nil || rc != 3 || string(out) != "abc" {
		t.Errorf("out %q rc %d err %v", out, rc, err)
	}
}
