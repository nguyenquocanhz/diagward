package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nguyenquocanhz/diagward/bmc"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/model"
)

type bmcOpts struct {
	out      outOpts
	host     string
	user     string
	port     int
	insecure bool
	protocol string
	since    sinceFlag
	timeout  int
}

// passwordFlags are refused outright: a password on the command line shows
// up in `ps`, shell history and audit logs.
var passwordFlags = []string{"password", "pass", "passwd", "pw", "p"}

func isPasswordFlag(arg string) bool {
	if !strings.HasPrefix(arg, "-") {
		return false
	}
	name := strings.TrimLeft(arg, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	for _, p := range passwordFlags {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

func (a *app) parseBMC(args []string) (*bmcOpts, error) {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if isPasswordFlag(arg) {
			return nil, errors.New(a.t(
				"the BMC password is never taken on the command line (it would be visible in ps and shell history). Set DIAGWARD_BMC_PASSWORD or type it when asked. (The port is --port.)",
				"không nhận mật khẩu BMC trên dòng lệnh (sẽ lộ trong ps và lịch sử shell). Hãy đặt biến DIAGWARD_BMC_PASSWORD hoặc gõ khi được hỏi. (Cổng là --port.)"))
		}
	}
	o := &bmcOpts{protocol: "auto"}
	fs := newFlagSet("bmc", a)
	addOutFlags(fs, &o.out, true)
	fs.StringVar(&o.user, "user", "", "")
	fs.StringVar(&o.user, "u", "", "")
	fs.IntVar(&o.port, "port", 0, "")
	fs.BoolVar(&o.insecure, "insecure", false, "")
	fs.BoolVar(&o.insecure, "k", false, "")
	fs.StringVar(&o.protocol, "protocol", "auto", "")
	fs.Var(&o.since, "since", "")
	fs.IntVar(&o.timeout, "timeout", 0, "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return nil, err
	}
	switch {
	case len(pos) == 0:
		return nil, errors.New(a.t("which BMC? Usage: diagward bmc HOST --user USER", "BMC nào? Cách dùng: diagward bmc ĐỊA_CHỈ --user TÀI_KHOẢN"))
	case len(pos) > 1:
		return nil, fmt.Errorf("unexpected argument %q", pos[1])
	}
	o.host = strings.TrimSpace(pos[0])
	if o.host == "" || strings.ContainsAny(o.host, " \t\r\n") {
		return nil, fmt.Errorf("invalid BMC address %q", pos[0])
	}
	o.protocol = strings.ToLower(o.protocol)
	switch o.protocol {
	case "auto", "redfish", "ipmi":
	default:
		return nil, fmt.Errorf("--protocol %q: use auto, redfish or ipmi", o.protocol)
	}
	if o.port < 0 || o.port > 65535 {
		return nil, fmt.Errorf("--port %d: use 1 to 65535", o.port)
	}
	if o.timeout != 0 && (o.timeout < 5 || o.timeout > 3600) {
		return nil, fmt.Errorf("--timeout %d: use 5 to 3600 seconds", o.timeout)
	}
	if o.user == "" {
		o.user = a.getenv("DIAGWARD_BMC_USER")
	}
	return o, o.out.validate()
}

func (a *app) cmdBMC(args []string) int {
	o, err := a.parseBMC(args)
	if errors.Is(err, flag.ErrHelp) {
		a.printHelp("bmc")
		return exitOK
	}
	if err != nil {
		return a.flagError("bmc", err)
	}
	interactive := a.isTerm(a.stdin)
	if o.user == "" {
		if !interactive {
			a.errorf(a.t("bmc: give the BMC user with --user (or DIAGWARD_BMC_USER)", "bmc: hãy cho biết tài khoản BMC bằng --user (hoặc DIAGWARD_BMC_USER)"))
			return exitError
		}
		fmt.Fprint(a.stderr, a.t("BMC user: ", "Tài khoản BMC: "))
		o.user = a.readLine()
		if o.user == "" {
			return exitError
		}
	}
	pass := a.getenv("DIAGWARD_BMC_PASSWORD")
	if pass == "" {
		if !interactive {
			a.errorf(a.t("bmc: set DIAGWARD_BMC_PASSWORD (no terminal to ask for the password)", "bmc: hãy đặt biến DIAGWARD_BMC_PASSWORD (không có terminal để hỏi mật khẩu)"))
			return exitError
		}
		fmt.Fprintf(a.stderr, a.t("Password for %s@%s: ", "Mật khẩu của %s@%s: "), o.user, o.host)
		p, err := a.readPassword()
		fmt.Fprintln(a.stderr)
		if err != nil {
			a.errorf("%v", err)
			return exitError
		}
		pass = p
	}
	bo := bmc.Options{
		Host:      o.host,
		Port:      o.port,
		User:      o.user,
		Password:  pass,
		Insecure:  o.insecure,
		Protocol:  o.protocol,
		SinceDays: o.since.days, // 0 = the bmc package's default window
	}
	if o.timeout > 0 {
		bo.Timeout = time.Duration(o.timeout) * time.Second
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	sp := a.newSpinner(a.stderr, o.out.quiet)
	sp.Start(model.Tf("Reading the BMC %s", "Đang đọc BMC %s", o.host))
	b, err := a.collectBMC(ctx, bo)
	sp.Stop()
	stop()
	if b == nil {
		if err == nil {
			err = errors.New("no data")
		}
		a.errorf("bmc %s: %s", o.host, a.bmcErrorText(err))
		return exitError
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "%s %s\n", a.t("Warning:", "Cảnh báo:"), a.bmcErrorText(err))
	}
	code := exitOK
	var saved string
	if o.out.save != "" {
		if serr := saveBundle(o.out.save, b); serr != nil {
			a.errorf(a.t("cannot save the bundle: %v", "không lưu được tệp bundle: %v"), serr)
			code = exitError
		} else {
			saved = o.out.save
		}
	}
	rep := diag.Analyze(b)
	if rc := a.emit(rep, &o.out, saved); rc != exitOK {
		return rc
	}
	if code != exitOK || err != nil {
		return exitError
	}
	return exitFor(rep.Verdict)
}

// isTLSError recognises a BMC certificate that failed verification (most
// BMCs ship a self-signed certificate).
func isTLSError(err error) bool {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	if errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cv) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "x509:") || strings.Contains(s, "--insecure") ||
		strings.Contains(s, "certificate signed by unknown authority") || strings.Contains(s, "tls: failed to verify certificate")
}

// bmcErrorText explains a BMC error, adding (or translating) the hint about
// --insecure for certificate problems.
func (a *app) bmcErrorText(err error) string {
	s := err.Error()
	if !isTLSError(err) {
		return s
	}
	if a.lang == "vi" {
		return s + "\nChứng chỉ TLS của BMC không được xác thực (BMC thường dùng chứng chỉ tự ký). Nếu chắc chắn địa chỉ này đúng là BMC của bạn, hãy chạy lại với --insecure."
	}
	if strings.Contains(s, "--insecure") {
		return s
	}
	return s + "\nThe BMC's TLS certificate could not be verified (BMCs usually ship a self-signed certificate). If you are sure this address is your BMC, run again with --insecure."
}
