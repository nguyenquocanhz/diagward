// Package bmc reads a server's management controller (BMC) out of band:
// Redfish over HTTPS (Dell iDRAC, HPE iLO, Lenovo XClarity, Supermicro,
// Fujitsu iRMC, Huawei iBMC, Inspur, OpenBMC) or, for old firmware without
// Redfish, IPMI over LAN through a locally installed ipmitool.
//
// The result is an ordinary collect.Bundle with OS = collect.OSBMC, so a
// server that hangs, will not boot or runs an OS nobody can log into can
// still be diagnosed from a laptop, saved as a .dwb file and analysed later.
//
// Sections written:
//
//   - "redfish.res:<path>" — one per Redfish resource read: Out is the JSON
//     body, RC the HTTP status (-1 on a transport error, with Err set).
//   - "ipmi.sdr", "ipmi.sel_info", "ipmi.sel_time", "ipmi.sel",
//     "ipmi.chassis", "ipmi.mc", "ipmi.fru", "ipmi.lan", "ipmi.power" —
//     ipmitool output (run with LC_ALL=C), the same sections the in-band
//     collectors write, so the ipmi domain parses them.
//   - "meta.bmc" — key=value lines: vendor, product, redfishVersion,
//     firmware, protocol, address, and the system identity when known.
//
// Credentials never appear in URLs, errors, sections or the bundle: the
// password travels only in the session login body, the HTTP Basic header or
// the IPMI_PASSWORD environment variable of ipmitool, and every stored text
// is scrubbed of the password and session token before Collect returns.
package bmc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// Options select the BMC and how to reach it.
type Options struct {
	Host      string // address or URL of the BMC (iDRAC, iLO, XClarity, Supermicro, OpenBMC)
	Port      int    // 0 = default (443 for Redfish, 623 for IPMI)
	User      string
	Password  string
	Insecure  bool          // skip TLS certificate verification (self-signed BMC certificates)
	Protocol  string        // "auto" (Redfish, then IPMI), "redfish" or "ipmi"
	Timeout   time.Duration // whole collection; 0 = 2 minutes
	SinceDays int           // event log window; 0 = 30
}

// Errors Collect can return (test them with errors.Is / errors.As). Every
// error Collect returns has a Vietnamese message too: Message(err) returns
// both languages (most errors are an *Error carrying them).
var (
	// ErrAuth means the BMC rejected the user name or password. Collect
	// stops at the first rejection so that it never triggers the account or
	// IP lockout most BMCs apply after repeated failed logins.
	ErrAuth = errors.New("the BMC rejected the user name or password")
	// ErrNoProtocol means neither Redfish nor IPMI over LAN could be used.
	ErrNoProtocol = errors.New("could not read the BMC over Redfish or IPMI")
	// ErrAddress means the BMC address is not usable.
	ErrAddress = errors.New("invalid BMC address")
	// ErrRedfishUnavailable means nothing answered as a Redfish service at
	// the address (Protocol "redfish"; "auto" then tries IPMI).
	ErrRedfishUnavailable = errors.New("Redfish is not available at this address")
)

// TLSError is returned when the BMC's TLS certificate cannot be verified.
type TLSError struct {
	Host string
	Err  error
}

func (e *TLSError) Error() string {
	return fmt.Sprintf("the TLS certificate of %s could not be verified (%v). BMCs usually use self-signed certificates; use --insecure if you trust this address", e.Host, e.Err)
}

func (e *TLSError) Unwrap() error { return e.Err }

// Defaults.
const (
	defaultTimeout   = 2 * time.Minute
	defaultSinceDays = 30
)

// Collect reads the BMC into a bundle with OS = collect.OSBMC.
//
// It returns an error only when nothing useful could be read: a bad
// address, an untrusted certificate (*TLSError), rejected credentials
// (ErrAuth), neither protocol available (ErrNoProtocol) or the caller's
// context being cancelled. Whenever there is an error the bundle collected
// so far (possibly nil) is returned with it, for troubleshooting. When
// Options.Timeout expires part-way, the partial bundle is returned without
// an error and "meta.bmc" carries timeout=1.
func Collect(ctx context.Context, o Options) (*collect.Bundle, error) {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.SinceDays <= 0 {
		o.SinceDays = defaultSinceDays
	}
	proto := strings.ToLower(strings.TrimSpace(o.Protocol))
	if proto == "" {
		proto = "auto"
	}
	switch proto {
	case "auto", "redfish", "ipmi":
	default:
		return nil, &Error{Msg: model.Tf("unknown BMC protocol %q (use auto, redfish or ipmi)", "giao thức BMC %q không hợp lệ (dùng auto, redfish hoặc ipmi)", o.Protocol)}
	}
	addr, err := parseAddress(o.Host, o.Port, proto == "ipmi")
	if err != nil {
		return nil, err
	}

	b := &collect.Bundle{
		Format:  collect.BundleFormat,
		Tool:    "diagward " + collect.CollectorVersion,
		OS:      collect.OSBMC,
		Host:    strings.TrimSpace(o.Host),
		Started: now(),
		Options: collect.Options{SinceDays: o.SinceDays},
	}
	meta := map[string]string{"address": addr.display}

	cctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	var cerr error
	switch proto {
	case "redfish":
		cerr = collectRedfish(cctx, b, o, addr, meta)
	case "ipmi":
		cerr = collectIPMI(cctx, b, o, addr, meta)
	case "auto":
		cerr = collectRedfish(cctx, b, o, addr, meta)
		var un *unavailableError
		if errors.As(cerr, &un) && ctx.Err() == nil {
			if _, lerr := lookPath("ipmitool"); lerr != nil {
				m := un.Text()
				cerr = kindErr(ErrNoProtocol, ": ", model.T(m.EN+"; IPMI over LAN: ipmitool is not installed", m.VI+"; IPMI qua LAN: chưa cài ipmitool"))
				meta["protocol"] = "none"
			} else {
				meta["redfishError"] = un.Err.Error()
				cerr = collectIPMI(cctx, b, o, addr, meta)
			}
		}
	}

	switch {
	case ctx.Err() != nil:
		if cerr == nil {
			cerr = ctx.Err()
		}
	case cctx.Err() != nil:
		meta["timeout"] = "1"
		var un *unavailableError
		if errors.As(cerr, &un) {
			cerr = kindErr(ErrNoProtocol, ": ", un.Text())
		}
	}
	b.Finished = now()
	b.Add(metaSection(meta))
	sort.SliceStable(b.Sections, func(i, j int) bool { return b.Sections[i].Name < b.Sections[j].Name })
	scrubBundle(b, o.User, o.Password, "")
	if cerr != nil {
		var te *TLSError
		if errors.As(cerr, &te) {
			return b, cerr // carries no credentials; keep the type for errors.As
		}
		if errors.Is(cerr, context.Canceled) || errors.Is(cerr, context.DeadlineExceeded) {
			return b, cerr
		}
		return b, scrubError(cerr, o.User, o.Password)
	}
	return b, nil
}

// now is replaceable in tests.
var now = time.Now

func metaSection(m map[string]string) *collect.Section {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		v := strings.TrimSpace(strings.NewReplacer("\n", " ", "\r", " ").Replace(m[k]))
		if v == "" {
			continue
		}
		fmt.Fprintf(&sb, "%s=%s\n", k, v)
	}
	return &collect.Section{Name: "meta.bmc", Out: strings.TrimSuffix(sb.String(), "\n")}
}

// address is a parsed BMC address.
type address struct {
	scheme   string // "https" (default) or "http" when given explicitly
	host     string // host name or IP, without brackets
	port     string // HTTPS port ("" = scheme default)
	ipmiPort string // IPMI port ("" = 623)
	display  string // normalised address for reports (never contains credentials)
}

// baseURL is scheme://host[:port].
func (a address) baseURL() *url.URL {
	h := a.host
	if a.port != "" {
		h = net.JoinHostPort(a.host, a.port)
	} else if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return &url.URL{Scheme: a.scheme, Host: h}
}

// parseAddress accepts "10.0.0.5", "10.0.0.5:8443", "bmc.example",
// "https://bmc.example[:port][/]", "[fe80::1]:443" and bare IPv6. port, when
// non-zero, applies when the address has none. ipmiOnly means the port is
// the IPMI (UDP) port rather than the HTTPS one.
func parseAddress(h string, port int, ipmiOnly bool) (address, error) {
	h = strings.TrimSpace(h)
	a := address{scheme: "https"}
	if h == "" {
		return a, addrErr("no BMC address given", "chưa nhập địa chỉ BMC")
	}
	if strings.ContainsAny(h, " \t\r\n") {
		return a, addrErr("the address contains spaces", "địa chỉ có khoảng trắng")
	}
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil {
			return a, addrErr("cannot parse it as a URL", "không đọc được dạng URL")
		}
		if u.User != nil {
			return a, addrErr("do not put the user name or password in the address; pass them as the user and password options",
				"đừng ghi tài khoản hay mật khẩu vào địa chỉ; hãy dùng tùy chọn tài khoản và mật khẩu")
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "http":
			a.scheme = strings.ToLower(u.Scheme)
		default:
			return a, addrErr("unsupported scheme %q (use https)", "không hỗ trợ %q (dùng https)", u.Scheme)
		}
		if p := strings.Trim(u.Path, "/"); p != "" && p != "redfish/v1" && p != "redfish" {
			return a, addrErr("give only the BMC address, without a path", "chỉ nhập địa chỉ BMC, không kèm đường dẫn")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return a, addrErr("give only the BMC address, without a query", "chỉ nhập địa chỉ BMC, không kèm tham số")
		}
		a.host, a.port = u.Hostname(), u.Port()
	} else {
		if strings.ContainsAny(h, "@/?#") {
			return a, addrErr("give only the host name or IP address (and optionally :port)", "chỉ nhập tên máy hoặc địa chỉ IP (có thể kèm :cổng)")
		}
		switch {
		case strings.HasPrefix(h, "["):
			if hh, p, err := net.SplitHostPort(h); err == nil {
				a.host, a.port = hh, p
			} else {
				a.host = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
			}
		case strings.Count(h, ":") == 1:
			hh, p, err := net.SplitHostPort(h)
			if err != nil {
				return a, &Error{Kind: ErrAddress, Msg: model.Tf("invalid BMC address: %v", "địa chỉ BMC không hợp lệ: %v", err), Err: err}
			}
			a.host, a.port = hh, p
		default:
			a.host = h // name, IPv4 or bare IPv6
		}
	}
	if a.host == "" || strings.ContainsAny(a.host, "[]") {
		return a, addrErr("no usable host name", "không có tên máy dùng được")
	}
	if ipmiOnly {
		a.ipmiPort, a.port = a.port, ""
		if a.ipmiPort == "" && port > 0 {
			a.ipmiPort = strconv.Itoa(port)
		}
	} else if a.port == "" && port > 0 {
		a.port = strconv.Itoa(port)
	}
	for _, p := range []string{a.port, a.ipmiPort} {
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return a, addrErr("bad port %q", "cổng %q không hợp lệ", p)
		}
	}
	a.display = a.host
	if strings.Contains(a.host, ":") {
		a.display = "[" + a.host + "]"
	}
	switch {
	case a.port != "":
		a.display = net.JoinHostPort(a.host, a.port)
	case a.ipmiPort != "":
		a.display = net.JoinHostPort(a.host, a.ipmiPort)
	}
	if a.scheme == "http" {
		a.display = "http://" + a.display
	}
	return a, nil
}

// unavailableError marks "Redfish is not offered at this address", the
// case where auto mode falls back to IPMI.
type unavailableError struct {
	Err error
	VI  string // Err in Vietnamese ("" = Err as is)
}

func (e *unavailableError) Error() string { return "Redfish is not available: " + e.Err.Error() }
func (e *unavailableError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrRedfishUnavailable) true.
func (e *unavailableError) Is(target error) bool { return target == ErrRedfishUnavailable }
