package bmc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/redfish"
	"github.com/nguyenquocanhz/diagward/model"
)

// Limits of the Redfish walk. Variables so tests can shrink them.
var (
	requestTimeout       = 30 * time.Second // one HTTP request
	maxBody        int64 = 8 << 20          // one response body (8 MiB)
	maxRequests          = 1500             // whole walk
	concurrency          = 4                // requests in flight; BMCs are small embedded systems
	maxMembers           = 128              // members read per collection (DIMM slots, drives, ...)
	maxSensors           = 300              // Sensor resources read per chassis (newer schema only)
	maxLogEntries        = 500              // entries kept per log service
	maxLogPages          = 25               // pages read per log service
	maxEntryFetch        = 100              // entries fetched one by one when a collection lists links only
	logoutTimeout        = 10 * time.Second
	maxRetries           = 1               // extra tries of a GET answered 429/503
	retryWait            = 2 * time.Second // when the BMC sends no Retry-After
	maxRetryWait         = 5 * time.Second
	maxSkipPages         = 10 // $skip pages tried when a log omits its nextLink
)

type rfClient struct {
	base       *url.URL
	hc         *http.Client
	user, pass string
	token      string // session token (X-Auth-Token)
	session    string // session URL to DELETE at the end
	basic      bool   // use HTTP Basic instead of a session
	b          *collect.Bundle
	since      time.Time

	sem     chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	seen    map[string]bool
	secIdx  map[string]int
	nreq    int
	limited bool

	firstSystem, firstManager map[string]any
}

func newRFClient(o Options, a address, b *collect.Bundle) *rfClient {
	base := a.baseURL()
	tr := &http.Transport{
		Proxy: nil, // a BMC sits on the management LAN; never route it through a proxy
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: o.Insecure, // #nosec G402 -- only when the user asks for it (--insecure)
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		MaxIdleConnsPerHost:   concurrency,
		IdleConnTimeout:       30 * time.Second,
	}
	c := &rfClient{
		base:   base,
		user:   o.User,
		pass:   o.Password,
		b:      b,
		since:  now().AddDate(0, 0, -o.SinceDays),
		sem:    make(chan struct{}, concurrency),
		seen:   map[string]bool{},
		secIdx: map[string]int{},
	}
	c.hc = &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !sameHost(base, req.URL) {
				return http.ErrUseLastResponse // never follow a BMC to another host
			}
			return nil
		},
	}
	return c
}

func collectRedfish(ctx context.Context, b *collect.Bundle, o Options, a address, meta map[string]string) (err error) {
	c := newRFClient(o, a, b)
	meta["protocol"] = "redfish"
	defer func() {
		c.wg.Wait()
		scrubBundle(b, "", "", c.token)
		c.hc.CloseIdleConnections()
	}()

	root, sec := c.fetchRoot(ctx)
	if sec.RC == -1 {
		rerr := errors.New(sec.Err)
		if sec.tlsErr != nil {
			return &TLSError{Host: a.display, Err: sec.tlsErr}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &unavailableError{Err: rerr}
	}
	needAuthRoot := sec.RC == http.StatusUnauthorized || sec.RC == http.StatusForbidden
	if !needAuthRoot && (sec.RC != http.StatusOK || root == nil || !looksLikeServiceRoot(root)) {
		return notRedfish(sec.RC, a.display)
	}

	if o.User != "" || o.Password != "" {
		if err := c.login(ctx, root); err != nil {
			return err
		}
		defer func() {
			c.wg.Wait() // the walk may still be running on an early return
			c.logout()
		}()
		if c.token != "" {
			meta["auth"] = "session"
		} else {
			meta["auth"] = "basic"
		}
	} else {
		meta["auth"] = "none"
	}
	if needAuthRoot {
		if o.User == "" && o.Password == "" {
			return errNeedCredentials()
		}
		c.forget("/redfish/v1")
		root, sec = c.fetchRoot(ctx)
		if sec.RC == http.StatusUnauthorized || sec.RC == http.StatusForbidden {
			return errAuthHTTP(sec.RC)
		}
		if root == nil || !looksLikeServiceRoot(root) {
			return notRedfish(sec.RC, a.display)
		}
	}
	vendor := str(root, "Vendor")
	if vendor == "" {
		if oem, ok := root["Oem"].(map[string]any); ok {
			keys := make([]string, 0, len(oem))
			for k := range oem {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > 0 {
				vendor = keys[0]
			}
		}
	}
	meta["vendor"] = vendor
	meta["product"] = str(root, "Product")
	meta["redfishVersion"] = str(root, "RedfishVersion")
	meta["logsSince"] = c.since.UTC().Format(time.RFC3339)

	// Probe with the systems collection first: it tells whether the
	// credentials work before dozens of requests are fired.
	if sys := link(root, "Systems"); sys != "" {
		obj, s := c.fetch(ctx, sys)
		// 401 without a session means Basic credentials (or none) were
		// refused. With a session, 401/403 means a privilege problem: keep
		// going and let the analysis report what could not be read.
		if s != nil && s.RC == http.StatusUnauthorized && c.token == "" {
			if o.User == "" && o.Password == "" {
				return errNeedCredentials()
			}
			return errAuthHTTP(s.RC)
		}
		if obj != nil {
			c.eachMember(ctx, obj, maxMembers, c.system)
		}
	}
	c.collection(ctx, link(root, "Chassis"), 16, c.chassis)
	c.collection(ctx, link(root, "Managers"), 8, c.manager)
	c.wg.Wait()

	if s := c.firstSystem; s != nil {
		meta["manufacturer"] = str(s, "Manufacturer")
		meta["model"] = str(s, "Model")
		meta["systemSerial"] = str(s, "SerialNumber")
		serial := str(s, "SerialNumber")
		if sku := str(s, "SKU"); sku != "" && strings.Contains(strings.ToLower(str(s, "Manufacturer")), "dell") {
			serial = sku // Dell's service tag is the SKU; support asks for it
			meta["serviceTag"] = sku
		}
		meta["serial"] = serial
		meta["bios"] = str(s, "BiosVersion")
		meta["hostname"] = str(s, "HostName")
		meta["powerState"] = str(s, "PowerState")
		if meta["vendor"] == "" {
			meta["vendor"] = str(s, "Manufacturer")
		}
	}
	if m := c.firstManager; m != nil {
		meta["firmware"] = str(m, "FirmwareVersion")
		meta["managerModel"] = str(m, "Model")
	}
	meta["requests"] = strconv.Itoa(c.nreq)
	if c.limited {
		meta["truncated"] = "request-limit"
	}
	return nil
}

// errNeedCredentials: the BMC wants a login and none was given.
func errNeedCredentials() error {
	return kindErr(ErrAuth, ": ", model.T("the BMC requires a user name and password", "BMC yêu cầu tài khoản và mật khẩu"))
}

// errAuthHTTP: the credentials were refused with this HTTP status.
func errAuthHTTP(rc int) error {
	return kindErr(ErrAuth, " ", model.Tf("(HTTP %d)", "(HTTP %d)", rc))
}

// looksLikeServiceRoot tells a Redfish service root from some other JSON.
func looksLikeServiceRoot(root map[string]any) bool {
	return str(root, "RedfishVersion") != "" || link(root, "Systems") != "" || link(root, "Chassis") != ""
}

// rfSection is a stored section plus the TLS error behind a transport
// failure, if any (not stored).
type rfSection struct {
	*collect.Section
	tlsErr error
}

func (c *rfClient) fetchRoot(ctx context.Context) (map[string]any, rfSection) {
	u := *c.base
	u.Path = "/redfish/v1/"
	c.mu.Lock()
	c.seen["/redfish/v1"] = true
	c.nreq++
	c.mu.Unlock()
	return c.get(ctx, &u, "/redfish/v1")
}

func (c *rfClient) forget(key string) {
	c.mu.Lock()
	delete(c.seen, key)
	c.mu.Unlock()
}

// login opens a Redfish session, falling back to HTTP Basic when the
// service has no usable session service. A rejected login stops here:
// retrying with Basic would count as a second failed login.
func (c *rfClient) login(ctx context.Context, root map[string]any) error {
	ref := link(root, "Links", "Sessions")
	if ref == "" {
		ref = "/redfish/v1/SessionService/Sessions"
	}
	u, _, ok := c.resolve(ref)
	if !ok {
		u, _, ok = c.resolve("/redfish/v1/SessionService/Sessions")
	}
	if !ok {
		c.basic = true
		return nil
	}
	body, _ := json.Marshal(map[string]string{"UserName": c.user, "Password": c.pass})
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		c.basic = true
		return nil
	}
	setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		if t := tlsCause(err); t != nil {
			return &TLSError{Host: c.base.Host, Err: t}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.basic = true
		return nil
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return kindErr(ErrAuth, " ", model.T("(HTTP 401 from the session service)", "(dịch vụ phiên trả về HTTP 401)"))
	case resp.StatusCode == http.StatusForbidden:
		// 403 is not "wrong password": the account exists but may not log in
		// (locked out after failed attempts, disabled, or without the Login
		// privilege / Redfish interface right). Retrying with Basic would
		// fail the same way and count against the lockout.
		return &Error{Kind: ErrAuth, Msg: model.T(
			"the BMC refused this account (HTTP 403 from the session service): it may be locked out after failed logins, disabled, or lack the right to log in over Redfish. Check the account in the BMC user settings (it needs at least the Login / Read Only role, and on Supermicro the Redfish interface enabled for it)",
			"BMC từ chối tài khoản này (dịch vụ phiên trả về HTTP 403): tài khoản có thể đang bị khóa do đăng nhập sai nhiều lần, bị vô hiệu hóa, hoặc không có quyền đăng nhập qua Redfish. Kiểm tra tài khoản trong phần quản lý người dùng của BMC (cần ít nhất quyền Login / Read Only; trên Supermicro phải bật giao diện Redfish cho tài khoản)")}
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.Header.Get("X-Auth-Token") != "":
		c.token = resp.Header.Get("X-Auth-Token")
		loc := resp.Header.Get("Location")
		if loc == "" {
			var s map[string]any
			if json.Unmarshal(rb, &s) == nil {
				loc = str(s, "@odata.id")
			}
		}
		if lu, _, ok := c.resolve(loc); ok {
			c.session = lu.String()
		}
	default:
		c.basic = true
	}
	return nil
}

// logout deletes the session. It runs even when the walk was cancelled or
// timed out, with its own short deadline, so sessions never pile up on the
// BMC (most allow only a handful at a time).
func (c *rfClient) logout() {
	if c.token == "" || c.session == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), logoutTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.session, nil)
	if err != nil {
		return
	}
	setHeaders(req)
	req.Header.Set("X-Auth-Token", c.token)
	if resp, err := c.hc.Do(req); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
	}
}

func setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OData-Version", "4.0")
	req.Header.Set("User-Agent", "diagward/"+collect.CollectorVersion)
}

func (c *rfClient) authorize(req *http.Request) {
	switch {
	case c.token != "":
		req.Header.Set("X-Auth-Token", c.token)
	case c.basic:
		req.SetBasicAuth(c.user, c.pass)
	}
}

// resolve turns an @odata.id (or nextLink / Location) into a request URL on
// the BMC and the section key. Links to other hosts, outside /redfish/v1 or
// that are not absolute paths are refused.
func (c *rfClient) resolve(ref string) (*url.URL, string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, "", false
	}
	u, err := url.Parse(ref)
	if err != nil || u.Opaque != "" {
		return nil, "", false
	}
	if u.Host != "" && !sameHost(c.base, u) {
		return nil, "", false
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") {
		return nil, "", false
	}
	clean := path.Clean(p)
	if clean != "/redfish/v1" && !strings.HasPrefix(clean, "/redfish/v1/") {
		return nil, "", false
	}
	key := clean
	if u.RawQuery != "" {
		key += "?" + u.RawQuery
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return nil, "", false
	}
	reqPath := clean
	if strings.HasSuffix(p, "/") {
		reqPath += "/" // some BMCs (iLO) list links with a trailing slash; keep it
	}
	// Build the URL from the parsed base rather than by concatenating
	// strings: a link-local IPv6 host carries a zone ("fe80::1%eth0") that
	// must be escaped as %25 in a URL.
	pu, err := url.Parse(reqPath)
	if err != nil {
		return nil, "", false
	}
	target := &url.URL{Scheme: c.base.Scheme, Host: c.base.Host, Path: pu.Path, RawPath: pu.RawPath, RawQuery: u.RawQuery}
	return target, key, true
}

// sameHost compares scheme-independent host and port (default 443/80).
func sameHost(base, u *url.URL) bool {
	if u.Host == "" {
		return true
	}
	if !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return false
	}
	return portOf(u, base.Scheme) == portOf(base, base.Scheme)
}

func portOf(u *url.URL, defScheme string) string {
	if p := u.Port(); p != "" {
		return p
	}
	s := u.Scheme
	if s == "" {
		s = defScheme
	}
	if strings.EqualFold(s, "http") {
		return "80"
	}
	return "443"
}

// fetch GETs a resource once per walk. It returns nil when the link is
// refused, was already read, or the request budget is spent.
func (c *rfClient) fetch(ctx context.Context, ref string) (map[string]any, *collect.Section) {
	u, key, ok := c.resolve(ref)
	if !ok {
		return nil, nil
	}
	c.mu.Lock()
	if c.seen[key] {
		c.mu.Unlock()
		return nil, nil
	}
	if c.nreq >= maxRequests {
		c.limited = true
		c.mu.Unlock()
		return nil, nil
	}
	c.seen[key] = true
	c.nreq++
	c.mu.Unlock()
	obj, s := c.get(ctx, u, key)
	return obj, s.Section
}

func (c *rfClient) get(ctx context.Context, u *url.URL, key string) (map[string]any, rfSection) {
	sec := &collect.Section{Name: "redfish.res:" + key}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		sec.RC, sec.Err, sec.Timeout = -1, ctx.Err().Error(), true
		c.add(sec)
		return nil, rfSection{Section: sec}
	}
	start := time.Now()
	var (
		resp      *http.Response
		body      []byte
		truncated bool
		err       error
	)
	for attempt := 0; ; attempt++ {
		resp, body, truncated, err = c.do(ctx, u)
		// A busy BMC answers 429 Too Many Requests or 503 Service
		// Unavailable (iDRAC, iLO, Supermicro under load): wait as told
		// (Retry-After, capped) and try once more.
		if resp == nil || attempt >= maxRetries || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) {
			break
		}
		if !sleepCtx(ctx, retryDelay(resp.Header.Get("Retry-After"))) {
			break
		}
	}
	<-c.sem
	sec.MS = int(time.Since(start) / time.Millisecond)

	out := rfSection{Section: sec}
	switch {
	case resp == nil:
		sec.RC = -1
		sec.Err = errText(err)
		sec.Timeout = isTimeout(err)
		out.tlsErr = tlsCause(err)
	case truncated:
		sec.RC = resp.StatusCode
		sec.Truncated = true
		sec.Err = fmt.Sprintf("response larger than %d MiB; not stored", maxBody>>20)
	case err != nil:
		sec.RC = resp.StatusCode
		sec.Err = "reading the response: " + errText(err)
		sec.Timeout = isTimeout(err)
	default:
		sec.RC = resp.StatusCode
		sec.Out = string(body)
	}
	c.add(sec)
	if sec.RC != http.StatusOK || sec.Out == "" {
		return nil, out
	}
	var obj map[string]any
	if jerr := json.Unmarshal(body, &obj); jerr != nil {
		sec.Err = "invalid JSON: " + jerr.Error()
		return nil, out
	}
	return obj, out
}

// do sends one GET and reads the body (at most maxBody).
func (c *rfClient) do(ctx context.Context, u *url.URL) (*http.Response, []byte, bool, error) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, false, err
	}
	setHeaders(req)
	c.authorize(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, false, err
	}
	body, truncated, err := readCapped(resp.Body, maxBody)
	resp.Body.Close()
	return resp, body, truncated, err
}

// retryDelay reads a Retry-After header (seconds; an HTTP date is ignored),
// defaulting to retryWait and capped at maxRetryWait so a BMC cannot stall
// the collection.
func retryDelay(h string) time.Duration {
	d := retryWait
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n >= 0 {
		d = time.Duration(n) * time.Second
	}
	if d > maxRetryWait {
		d = maxRetryWait
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *rfClient) add(s *collect.Section) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i, ok := c.secIdx[s.Name]; ok {
		c.b.Sections[i] = s // a re-read (service root after login) replaces the first try
		return
	}
	c.secIdx[s.Name] = len(c.b.Sections)
	c.b.Add(s)
}

func readCapped(r io.Reader, max int64) ([]byte, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if int64(len(b)) > max {
		return nil, true, nil
	}
	return b, false, err
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// tlsCause returns the certificate verification error inside err, if any.
func tlsCause(err error) error {
	if err == nil {
		return nil
	}
	var (
		ua x509.UnknownAuthorityError
		he x509.HostnameError
		ci x509.CertificateInvalidError
		cv *tls.CertificateVerificationError
	)
	switch {
	case errors.As(err, &cv):
		return cv.Err
	case errors.As(err, &ua):
		return ua
	case errors.As(err, &he):
		return he
	case errors.As(err, &ci):
		return ci
	}
	return nil
}

// --- the walk ---------------------------------------------------------

// visit fetches ref in the background and hands the parsed object to fn.
func (c *rfClient) visit(ctx context.Context, ref string, fn func(context.Context, map[string]any)) {
	if ref == "" || ctx.Err() != nil {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if obj, _ := c.fetch(ctx, ref); obj != nil && fn != nil {
			fn(ctx, obj)
		}
	}()
}

// collection reads a collection and up to max of its members.
func (c *rfClient) collection(ctx context.Context, ref string, max int, fn func(context.Context, map[string]any)) {
	c.visit(ctx, ref, func(ctx context.Context, coll map[string]any) {
		c.eachMember(ctx, coll, max, fn)
	})
}

func (c *rfClient) eachMember(ctx context.Context, coll map[string]any, max int, fn func(context.Context, map[string]any)) {
	for i, m := range memberLinks(coll) {
		if i >= max {
			c.mu.Lock()
			c.limited = true
			c.mu.Unlock()
			break
		}
		c.visit(ctx, m, fn)
	}
	if next := nextLink(coll); next != "" {
		c.visit(ctx, next, func(ctx context.Context, page map[string]any) {
			c.eachMember(ctx, page, max, fn)
		})
	}
}

func (c *rfClient) system(ctx context.Context, s map[string]any) {
	c.mu.Lock()
	if c.firstSystem == nil {
		c.firstSystem = s
	}
	c.mu.Unlock()
	for _, k := range []string{"Processors", "Memory", "EthernetInterfaces", "SimpleStorage"} {
		// iLO 4 links Processors only under "links" and Memory only
		// under Oem.Hp.links (its "Memory" is a summary object).
		c.collection(ctx, first(link(s, k), link(s, "links", k), link(s, "Oem", "Hp", "links", k)), maxMembers, nil)
	}
	c.collection(ctx, link(s, "Storage"), 32, c.storage)
	c.logServices(ctx, link(s, "LogServices"))
	// HPE iLO 4/5: Smart Array controllers are described under Oem.Hpe
	// (iLO 4: Oem.Hp) SmartStorage on firmware that has no standard Storage
	// for them.
	c.visit(ctx, first(link(s, "Oem", "Hpe", "Links", "SmartStorage"), link(s, "Oem", "Hp", "links", "SmartStorage")), func(ctx context.Context, ss map[string]any) {
		c.collection(ctx, first(link(ss, "Links", "ArrayControllers"), link(ss, "links", "ArrayControllers")), 16, func(ctx context.Context, ac map[string]any) {
			c.collection(ctx, first(link(ac, "Links", "PhysicalDrives"), link(ac, "links", "PhysicalDrives")), maxMembers, nil)
			c.collection(ctx, first(link(ac, "Links", "LogicalDrives"), link(ac, "links", "LogicalDrives")), maxMembers, nil)
		})
	})
}

func (c *rfClient) storage(ctx context.Context, st map[string]any) {
	for i, d := range arrLinks(st, "Drives") {
		if i >= maxMembers {
			break
		}
		c.visit(ctx, d, nil)
	}
	c.collection(ctx, link(st, "Volumes"), maxMembers, nil)
	c.collection(ctx, link(st, "Controllers"), 16, nil)
}

func (c *rfClient) chassis(ctx context.Context, ch map[string]any) {
	thermal, power := link(ch, "Thermal"), link(ch, "Power")
	thermalSub := func(ctx context.Context) {
		c.visit(ctx, link(ch, "ThermalSubsystem"), func(ctx context.Context, ts map[string]any) {
			c.collection(ctx, link(ts, "Fans"), maxMembers, nil)
			c.visit(ctx, link(ts, "ThermalMetrics"), nil)
		})
		// Temperatures with thresholds live in Sensors in the newer model.
		c.collection(ctx, link(ch, "Sensors"), maxSensors, nil)
	}
	powerSub := func(ctx context.Context) {
		c.visit(ctx, link(ch, "PowerSubsystem"), func(ctx context.Context, ps map[string]any) {
			c.collection(ctx, link(ps, "PowerSupplies"), maxMembers, func(ctx context.Context, psu map[string]any) {
				c.visit(ctx, link(psu, "Metrics"), nil)
			})
		})
		c.visit(ctx, link(ch, "EnvironmentMetrics"), nil)
	}
	// Prefer the classic Thermal/Power resources every BMC still offers;
	// fall back to the newer subsystems when they are absent or fail.
	c.withFallback(ctx, thermal, thermalSub)
	c.withFallback(ctx, power, powerSub)
	c.logServices(ctx, link(ch, "LogServices"))
}

func (c *rfClient) withFallback(ctx context.Context, ref string, fallback func(context.Context)) {
	if ref == "" {
		fallback(ctx)
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		obj, sec := c.fetch(ctx, ref)
		if obj == nil && sec != nil && ctx.Err() == nil {
			fallback(ctx)
		}
	}()
}

func (c *rfClient) manager(ctx context.Context, m map[string]any) {
	c.mu.Lock()
	if c.firstManager == nil {
		c.firstManager = m
	}
	c.mu.Unlock()
	c.logServices(ctx, link(m, "LogServices"))
}

func (c *rfClient) logServices(ctx context.Context, ref string) {
	c.collection(ctx, ref, 32, func(ctx context.Context, ls map[string]any) {
		if skipLog(ls) {
			return
		}
		if e := link(ls, "Entries"); e != "" {
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				c.entries(ctx, e)
			}()
		}
	})
}

// skipLog uses the analysis' own rule, so that every log the analysis reads
// is collected and nothing else.
func skipLog(ls map[string]any) bool {
	id := str(ls, "Id")
	if id == "" {
		id = path.Base(str(ls, "@odata.id"))
	}
	return redfish.SkipLogService(id, str(ls, "Name"))
}

// entries reads one log service's entries: newest ones only, at most
// maxLogEntries and back to the SinceDays window.
//
// Services order entries differently (Dell newest first, HPE iLO, OpenBMC
// and Supermicro oldest first). For a log longer than the cap that is not
// newest first, the first page is followed by a jump to $skip=count-cap so
// the newest entries are read; iLO, iDRAC and bmcweb support $skip.
//
// Some services page without a nextLink (Members@odata.count is larger than
// the page and nothing says where the rest is): the following pages are then
// asked for with $skip, so that the newest entries of an oldest-first log
// are not missed. A service that ignores $skip (returns the same page) or
// rejects it (400) simply ends the walk.
func (c *rfClient) entries(ctx context.Context, ref string) {
	total, first, next := 0, true, ref
	count, pos, skipPages := 0, 0, 0
	firstID := ""
	for page := 0; next != "" && page < maxLogPages && total < maxLogEntries && ctx.Err() == nil; page++ {
		obj, _ := c.fetch(ctx, next)
		if obj == nil {
			return
		}
		members := entryList(obj)
		nl := nextLink(obj)
		if first {
			first = false
			count = intOf(obj["Members@odata.count"])
			firstID = memberID(members)
			if entryOrder(members) >= 0 && count > len(members) && count > maxLogEntries {
				jump := addQuery(ref, "$skip="+strconv.Itoa(count-maxLogEntries))
				jumped := false
				if o2, _ := c.fetch(ctx, jump); o2 != nil {
					if m2 := entryList(o2); len(m2) > 0 && memberID(m2) != firstID {
						members, nl = m2, nextLink(o2)
						pos = count - maxLogEntries
						jumped = true
					}
				}
				// iLO 4 ignores $skip and pages with ?page=N instead.
				if per := len(members); !jumped && per > 0 && strings.Contains(nl, "?page=") {
					last := (count + per - 1) / per
					if start := last - maxLogEntries/per + 1; start > 2 {
						if o2, _ := c.fetch(ctx, nl[:strings.Index(nl, "?page=")]+"?page="+strconv.Itoa(start)); o2 != nil {
							if m2 := entryList(o2); len(m2) > 0 {
								members, nl = m2, nextLink(o2)
								pos = (start - 1) * per
							}
						}
					}
				}
			}
		} else if nl == "" && memberID(members) == firstID {
			return // $skip ignored: the first page again
		}
		pos += len(members)
		total += len(members)
		c.fetchLinkOnly(ctx, members)
		if entryOrder(members) < 0 {
			if t, ok := oldest(members); ok && t.Before(c.since) {
				return // newest first and already past the window
			}
		}
		if nl == "" && count > pos && len(members) > 0 && skipPages < maxSkipPages {
			skipPages++
			nl = addQuery(ref, "$skip="+strconv.Itoa(pos))
		}
		next = nl
	}
}

// memberID is the @odata.id of the first member of a page ("" if none).
func memberID(members []any) string {
	for _, m := range members {
		if mo, ok := m.(map[string]any); ok {
			return str(mo, "@odata.id")
		}
	}
	return ""
}

// fetchLinkOnly reads entries one by one when a collection lists only
// their links (no Created/Message inline).
func (c *rfClient) fetchLinkOnly(ctx context.Context, members []any) {
	n := 0
	for _, m := range members {
		mo, _ := m.(map[string]any)
		if mo == nil || len(mo) > 2 {
			continue // inline entry
		}
		if _, inline := mo["Message"]; inline {
			continue
		}
		if n >= maxEntryFetch {
			return
		}
		n++
		c.visit(ctx, str(mo, "@odata.id"), nil)
	}
}

func addQuery(ref, q string) string {
	if strings.Contains(ref, "?") {
		return ref + "&" + q
	}
	return ref + "?" + q
}

// entryOrder is +1 when entries run oldest to newest, -1 when newest
// first, 0 when unknown.
func entryOrder(members []any) int {
	var ts []time.Time
	for _, m := range members {
		mo, _ := m.(map[string]any)
		if t, ok := entryTime(mo); ok {
			ts = append(ts, t)
		}
	}
	if len(ts) < 2 {
		return 0
	}
	switch {
	case ts[len(ts)-1].After(ts[0]):
		return 1
	case ts[len(ts)-1].Before(ts[0]):
		return -1
	}
	return 0
}

func oldest(members []any) (time.Time, bool) {
	var o time.Time
	found := false
	for _, m := range members {
		mo, _ := m.(map[string]any)
		if t, ok := entryTime(mo); ok && (!found || t.Before(o)) {
			o, found = t, true
		}
	}
	return o, found
}

func entryTime(e map[string]any) (time.Time, bool) {
	for _, k := range []string{"Created", "EventTimestamp"} {
		if t, ok := parseTime(str(e, k)); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseTime reads Redfish timestamps; it rejects the zero dates BMCs use
// when their clock is unset ("0000-00-00T00:00:00Z", 1970).
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(l, s); err == nil {
			if t.Year() < 2000 {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// --- JSON helpers -----------------------------------------------------

func str(m map[string]any, keys ...string) string {
	v := dig(m, keys...)
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func dig(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

// link returns the @odata.id of the object at keys, or its "href" (HPE
// iLO 4 keeps some links only in the pre-1.0 form {"href": ...}).
func link(m map[string]any, keys ...string) string {
	o, _ := dig(m, keys...).(map[string]any)
	if o == nil {
		return ""
	}
	if id := str(o, "@odata.id"); id != "" {
		return id
	}
	return str(o, "href")
}

func arrLinks(m map[string]any, key string) []string {
	a, _ := m[key].([]any)
	var out []string
	for _, v := range a {
		if o, ok := v.(map[string]any); ok {
			if id := str(o, "@odata.id"); id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

func memberLinks(coll map[string]any) []string { return arrLinks(coll, "Members") }

// nextLink is the next page of a collection: Members@odata.nextLink, or
// HPE iLO 4's own paging, "links": {"NextPage": {"page": 2}}, read as
// "?page=2" (iLO 4 ignores $skip and $top).
func nextLink(coll map[string]any) string {
	if n := str(coll, "Members@odata.nextLink"); n != "" {
		return n
	}
	if n := str(coll, "@odata.nextLink"); n != "" {
		return n
	}
	if p := intOf(dig(coll, "links", "NextPage", "page")); p > 1 {
		base := str(coll, "links", "self", "href")
		if base == "" {
			base = str(coll, "@odata.id")
		}
		if i := strings.IndexByte(base, '?'); i >= 0 {
			base = base[:i]
		}
		if base != "" {
			return base + "?page=" + strconv.Itoa(p)
		}
	}
	return ""
}

// entryList returns a log page's entries: iLO 4 lists only links in
// Members and the entries themselves in "Items".
func entryList(coll map[string]any) []any {
	if items, _ := coll["Items"].([]any); len(items) > 0 {
		return items
	}
	members, _ := coll["Members"].([]any)
	return members
}

func intOf(v any) int {
	switch x := v.(type) {
	case float64:
		if x > 0 && x < 1e9 {
			return int(x)
		}
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
