package bmc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// Runner runs an external command with extra environment variables
// ("NAME=value") and returns its output and exit code. err is set when the
// command could not be started or was killed (timeout, cancel).
type Runner func(ctx context.Context, env []string, name string, args ...string) (stdout, stderr []byte, rc int, err error)

// Replaceable in tests.
var (
	lookPath               = exec.LookPath
	runCommand      Runner = execRunner
	ipmiCmdTimeout         = 60 * time.Second // one ipmitool command (sel elist gets the rest of the budget)
	ipmiMaxSELLines        = 3000
)

func execRunner(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	rc := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ctx.Err() == nil:
		rc, err = ee.ExitCode(), nil
	default:
		rc = -1
	}
	return out.Bytes(), errb.Bytes(), rc, err
}

// The ipmitool commands, in the order they run: quick ones first so a slow
// SEL read over the LAN cannot starve them; the SEL last, with whatever
// time is left. Section names match the in-band collectors exactly.
var ipmiCommands = []struct {
	section string
	args    []string
}{
	{"ipmi.mc", []string{"mc", "info"}},
	{"ipmi.chassis", []string{"chassis", "status"}},
	{"ipmi.sdr", []string{"sdr", "elist"}},
	{"ipmi.sel_info", []string{"sel", "info"}},
	// The BMC clock, read before the SEL so the ipmi domain can tell event
	// times written by a BMC whose clock is wrong.
	{"ipmi.sel_time", []string{"sel", "time", "get"}},
	{"ipmi.fru", []string{"fru", "print"}},
	{"ipmi.lan", []string{"lan", "print"}},
	{"ipmi.power", []string{"dcmi", "power", "reading"}},
	{"ipmi.sel", []string{"sel", "elist"}},
}

// ipmiArgs builds the ipmitool command line. The password is never on it:
// -E makes ipmitool read IPMI_PASSWORD from the environment. LC_ALL=C keeps
// the output in the format the ipmi domain parses: ipmitool formats SEL
// dates with strftime and the user's locale (a de_DE or vi_VN laptop would
// otherwise produce day-first or translated dates), as the in-band
// collectors do.
func ipmiArgs(a address, user, pass string, cmd []string) (args, env []string) {
	env = []string{"LC_ALL=C"}
	args = []string{"-I", "lanplus", "-H", a.host}
	if a.ipmiPort != "" {
		args = append(args, "-p", a.ipmiPort)
	}
	if user != "" {
		args = append(args, "-U", user)
	}
	if pass != "" {
		args = append(args, "-E")
		env = append(env, "IPMI_PASSWORD="+pass)
	}
	return append(args, cmd...), env
}

// Messages of ipmitool when no RMCP+ session could be opened: wrong user or
// password, IPMI over LAN disabled, or nothing answering on UDP 623.
var ipmiSessionFailures = []string{
	"unable to establish ipmi v2",
	"unable to establish lan session",
	"rakp",
	"unauthorized name",
	"invalid user name",
	"password invalid",
	"error: unable to establish",
	"insufficient privilege",
}

func collectIPMI(ctx context.Context, b *collect.Bundle, o Options, a address, meta map[string]string) error {
	meta["protocol"] = "ipmi"
	target := a.host
	if a.ipmiPort != "" {
		target = net.JoinHostPort(a.host, a.ipmiPort)
	}
	exe, err := lookPath("ipmitool")
	if err != nil {
		for _, c := range ipmiCommands {
			b.Add(&collect.Section{Name: c.section, RC: 127, Missing: "ipmitool"})
		}
		return nil
	}
	for i, c := range ipmiCommands {
		if ctx.Err() != nil {
			b.Add(&collect.Section{Name: c.section, RC: -1, Err: "not run: time limit reached", Timeout: true})
			continue
		}
		args, env := ipmiArgs(a, o.User, o.Password, c.args)
		cctx, cancel := ctx, context.CancelFunc(func() {})
		if c.section != "ipmi.sel" {
			cctx, cancel = context.WithTimeout(ctx, ipmiCmdTimeout)
		}
		start := time.Now()
		stdout, stderr, rc, rerr := runCommand(cctx, env, exe, args...)
		timedOut := cctx.Err() != nil
		cancel()
		s := &collect.Section{
			Name: c.section,
			RC:   rc,
			MS:   int(time.Since(start) / time.Millisecond),
			Out:  strings.TrimRight(strings.ReplaceAll(string(stdout), "\r\n", "\n"), "\n"),
			Err:  strings.TrimRight(strings.ReplaceAll(string(stderr), "\r\n", "\n"), "\n"),
		}
		if rerr != nil {
			if s.RC == 0 {
				s.RC = -1
			}
			if s.Err == "" {
				s.Err = rerr.Error()
			}
		}
		if timedOut {
			s.Timeout = true
			if s.RC == 0 || s.RC == -1 {
				s.RC = 124
			}
		}
		switch c.section {
		case "ipmi.sel":
			if lines := strings.Split(s.Out, "\n"); len(lines) > ipmiMaxSELLines {
				s.Out = strings.Join(lines[len(lines)-ipmiMaxSELLines:], "\n")
				s.Truncated = true
			}
		case "ipmi.lan":
			s.Out = redactLan(s.Out)
		case "ipmi.mc":
			kv := colonKV(s.Out, false)
			meta["firmware"] = kv["Firmware Revision"]
			meta["vendor"] = kv["Manufacturer Name"]
		case "ipmi.fru":
			kv := colonKV(s.Out, true)
			meta["manufacturer"] = first(kv["Product Manufacturer"], kv["Board Mfg"])
			meta["model"] = first(kv["Product Name"], kv["Board Product"])
			meta["serial"] = first(kv["Product Serial"], kv["Chassis Serial"], kv["Board Serial"])
		}
		b.Add(s)
		// The first command opens the session. If it could not, every
		// other command would fail the same way after ipmitool's retries;
		// stop instead of hammering the BMC (and its lockout counter).
		if i == 0 && s.RC != 0 {
			low := strings.ToLower(s.Err + "\n" + s.Out)
			for _, f := range ipmiSessionFailures {
				if strings.Contains(low, f) {
					return kindErr(ErrNoProtocol, ": ", model.Tf(
						"IPMI over LAN to %s failed (%s). Check the user name and password, and that IPMI over LAN is enabled in the BMC settings",
						"IPMI qua LAN tới %s không thành công (%s). Kiểm tra tài khoản, mật khẩu và đã bật IPMI over LAN trong cài đặt BMC chưa",
						target, firstLine(s.Err)))
				}
			}
			if s.Timeout {
				return kindErr(ErrNoProtocol, ": ", model.Tf("IPMI over LAN to %s did not answer (UDP port %s)",
					"IPMI qua LAN tới %s không trả lời (cổng UDP %s)", target, first(a.ipmiPort, "623")))
			}
		}
	}
	return nil
}

// colonKV parses "Key : value" lines. With firstBlock, only the first
// paragraph (FRU device 0, the system board) is read.
func colonKV(s string, firstBlock bool) map[string]string {
	m := map[string]string{}
	seen := false
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			if firstBlock && seen {
				break
			}
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		seen = true
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, dup := m[k]; !dup && k != "" {
			m[k] = v
		}
	}
	return m
}

func first(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" {
		return "no output"
	}
	return s
}
