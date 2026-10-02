package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/checks/redfish"
	"github.com/nguyenquocanhz/diagward/internal/testkit"
	"github.com/nguyenquocanhz/diagward/model"
)

// fixedNow pins the log window to the mockups' dates.
func fixedNow(t *testing.T) {
	old := now
	now = func() time.Time { return time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = old })
}

func analyze(t *testing.T, b *collect.Bundle) model.Result {
	t.Helper()
	env := collect.EnvOf(b)
	res := redfish.Check(b, env)
	testkit.Validate(t, res)
	return res
}

func TestCollectLocalStorage(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "localstorage")
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if b.OS != collect.OSBMC || b.Host != f.addr() || b.Options.SinceDays != 30 || b.Finished.Before(b.Started) {
		t.Errorf("bundle header %+v", b)
	}
	for _, p := range []string{
		"/redfish/v1", "/redfish/v1/Systems", "/redfish/v1/Systems/437XR1138R2",
		"/redfish/v1/Systems/437XR1138R2/Memory/DIMM1", "/redfish/v1/Chassis/1U/Thermal", "/redfish/v1/Chassis/1U/Power",
		"/redfish/v1/Chassis/1U/Drives/3D58ECBC375FD9F2", "/redfish/v1/Systems/437XR1138R2/Storage/1/Volumes/2",
		"/redfish/v1/Managers/BMC", "/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries",
	} {
		s := b.Get("redfish.res:" + p)
		if s == nil || s.RC != 200 || !strings.HasPrefix(strings.TrimSpace(s.Out), "{") {
			t.Errorf("section %s: %+v", p, s)
		}
	}
	meta := b.Get("meta.bmc").KV()
	if meta["protocol"] != "redfish" || meta["auth"] != "session" || meta["vendor"] != "Contoso" || meta["redfishVersion"] == "" ||
		meta["firmware"] == "" || meta["address"] != f.addr() || meta["serial"] != "437XR1138R2" {
		t.Errorf("meta %v", meta)
	}
	if f.logins != 1 || len(f.deleted) != 1 || f.liveSessions() != 0 {
		t.Errorf("logins %d deleted %v live %d", f.logins, f.deleted, f.liveSessions())
	}
	for p := range f.hits {
		if strings.Contains(p, "AccountService") {
			t.Errorf("AccountService must not be read: %s", p)
		}
		if f.hits[p] > 1 && !strings.HasPrefix(p, "/redfish/v1/SessionService") {
			t.Errorf("%s fetched %d times", p, f.hits[p])
		}
	}
	res := analyze(t, b)
	if testkit.Find(res, "redfish.psu_warning") == nil || testkit.Find(res, "redfish.storage_ok") == nil {
		t.Errorf("analysis %v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "redfish.memory"); c == nil || c.State != model.CovRan {
		t.Errorf("memory coverage %+v", c)
	}
}

func TestCredentialsNeverStored(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "dell")
	f.user, f.pass = "root", "calvin-S3cret-42"
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	text := string(raw)
	if strings.Contains(text, f.pass) {
		t.Fatal("password in bundle")
	}
	for _, h := range f.authHdrs {
		tok := strings.TrimPrefix(h, "Basic ")
		if strings.Contains(text, tok) {
			t.Fatalf("auth header value %q in bundle", h)
		}
	}
	for _, s := range b.Sections {
		if strings.Contains(s.Name, "SessionService") {
			t.Errorf("session resource stored: %s", s.Name)
		}
	}
	// The Dell login audit entry names the user; it is scrubbed.
	lc := b.Get("redfish.res:/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Lclog/Entries").Out
	if strings.Contains(lc, "using root,") || !strings.Contains(lc, "using ***,") {
		t.Errorf("user name not scrubbed: %.300s", lc)
	}
	// Pagination: the second Lclog page was read.
	if b.Get("redfish.res:/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Lclog/Entries?$skip=3") == nil {
		t.Error("nextLink page not read")
	}
	// Memory/Storage do not exist in this mockup: stored as 404.
	if s := b.Get("redfish.res:/redfish/v1/Systems/System.Embedded.1/Memory"); s == nil || s.RC != 404 {
		t.Errorf("404 section %+v", s)
	}
	res := analyze(t, b)
	if f := testkit.Find(res, "redfish.event_critical", "PSU0003"); f == nil || f.Severity != model.Crit {
		t.Errorf("PSU0003 %v", testkit.IDs(res))
	}
	if c := testkit.Cov(res, "redfish.memory"); c == nil || c.State != model.CovSkipped {
		t.Errorf("memory coverage %+v", c)
	}
}

func TestBasicFallback(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "hpe")
	f.sessions = false
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if m := b.Get("meta.bmc").KV(); m["auth"] != "basic" {
		t.Errorf("auth %v", m)
	}
	if s := b.Get("redfish.res:/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives/1"); s == nil || s.RC != 200 {
		t.Errorf("HPE SmartStorage not followed: %+v", s)
	}
	if b.Get("redfish.res:/redfish/v1/Managers/1/LogServices/SL") == nil {
		t.Error("log service resource itself should be read")
	}
	if b.Get("redfish.res:/redfish/v1/Managers/1/LogServices/SL/Entries") != nil {
		t.Error("HPE security log entries must be skipped")
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), f.pass) {
		t.Fatal("password in bundle")
	}
	res := analyze(t, b)
	if testkit.Find(res, "redfish.drive_failed", "1I:1:2") == nil {
		t.Errorf("analysis %v", testkit.IDs(res))
	}
}

func TestWrongPasswordStopsAtFirstFailure(t *testing.T) {
	f := newFake(t, "localstorage")
	o := f.opts()
	o.Password = "wrong-password-123"
	b, err := Collect(context.Background(), o)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), o.Password) {
		t.Error("password in error")
	}
	if f.logins != 1 {
		t.Errorf("logins %d", f.logins)
	}
	for _, r := range f.requests {
		if strings.HasPrefix(r, "GET ") && r != "GET /redfish/v1" {
			t.Errorf("request after rejected login: %s", r)
		}
	}
	if b == nil || b.Get("meta.bmc") == nil {
		t.Error("partial bundle expected with the error")
	}
}

func TestBasicRejected(t *testing.T) {
	f := newFake(t, "localstorage")
	f.sessions = false
	o := f.opts()
	o.Password = "nope-nope-nope"
	_, err := Collect(context.Background(), o)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err %v", err)
	}
	if n := f.hitCount("/redfish/v1/Chassis"); n != 0 {
		t.Errorf("kept crawling after 401: %d", n)
	}
}

func TestTLSVerification(t *testing.T) {
	f := newFake(t, "localstorage")
	o := f.opts()
	o.Insecure = false
	_, err := Collect(context.Background(), o)
	var te *TLSError
	if !errors.As(err, &te) {
		t.Fatalf("want TLSError, got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "--insecure") || !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("message %q", err)
	}
	if f.logins != 0 {
		t.Error("credentials sent over an unverified connection")
	}
	// auto mode must not silently fall back to IPMI on a TLS problem.
	o.Protocol = "auto"
	_, err = Collect(context.Background(), o)
	if !errors.As(err, &te) {
		t.Fatalf("auto: want TLSError, got %v", err)
	}
}

func TestLinkLoopsAndForeignHosts(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "localstorage")
	// A collection whose nextLink points to itself, members pointing back
	// up the tree and to other hosts, and a drive list that loops.
	sys := f.mock["/redfish/v1/Systems"]
	sys["Members@odata.nextLink"] = "/redfish/v1/Systems"
	sys["Members"] = append(sys["Members"].([]any),
		map[string]any{"@odata.id": "/redfish/v1/Systems"},
		map[string]any{"@odata.id": "https://evil.example/redfish/v1/Systems/x"},
		map[string]any{"@odata.id": "//evil.example/redfish/v1/Systems/y"},
		map[string]any{"@odata.id": "/redfish/v1/../../etc/passwd"},
		map[string]any{"@odata.id": "/other/api"},
	)
	st := f.mock["/redfish/v1/Systems/437XR1138R2/Storage/1"]
	st["Drives"] = append(st["Drives"].([]any), map[string]any{"@odata.id": "/redfish/v1/Systems/437XR1138R2/Storage/1"}, map[string]any{"@odata.id": "/redfish/v1/Systems/437XR1138R2"})
	f.mock["/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries"]["Members@odata.nextLink"] = "/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries"
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	for p, n := range f.hits {
		if n > 1 && !strings.HasPrefix(p, "/redfish/v1/SessionService") {
			t.Errorf("%s fetched %d times", p, n)
		}
		if strings.Contains(p, "etc/passwd") || strings.HasPrefix(p, "/other") {
			t.Errorf("followed bad link %s", p)
		}
	}
	for _, s := range b.Sections {
		if strings.Contains(s.Name, "evil") || strings.Contains(s.Name, " ") {
			t.Errorf("bad section %q", s.Name)
		}
	}
	analyze(t, b)

	c := newRFClient(Options{}, address{scheme: "https", host: "10.0.0.5"}, &collect.Bundle{})
	for ref, ok := range map[string]bool{
		"/redfish/v1/Systems/1/":                         true,
		"https://10.0.0.5/redfish/v1/Systems/1":          true,
		"https://10.0.0.5:443/redfish/v1/Systems/1":      true,
		"https://10.0.0.5:8443/redfish/v1/Systems/1":     false,
		"https://redfishpdu.contoso.com/redfish/v1/x":    false,
		"/redfish/v1/Chassis/1/Thermal#/Fans/0":          true,
		"/redfish/v1/x/../../../root":                    false,
		"redfish/v1/Systems":                             false,
		"":                                               false,
		"/redfish/v1/Entries?$skip=50":                   true,
		"javascript:alert(1)":                            false,
		"/redfish/v1/Chassis/Enclosure.Internal.0-1:RAI": true,
	} {
		if _, _, got := c.resolve(ref); got != ok {
			t.Errorf("resolve(%q) = %v, want %v", ref, got, ok)
		}
	}
	if u, key, _ := c.resolve("/redfish/v1/Systems/1/"); u.String() != "https://10.0.0.5/redfish/v1/Systems/1/" || key != "/redfish/v1/Systems/1" {
		t.Errorf("resolve keeps trailing slash for the request, not the key: %s %s", u, key)
	}
}

func TestAscendingLogJumpsToNewest(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "localstorage")
	const total, page = 1200, 50
	entries := "/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries"
	var asked []string
	f.dynamic = func(w http.ResponseWriter, r *http.Request) bool {
		if cleanKey(r.URL.Path) != entries {
			return false
		}
		asked = append(asked, r.URL.RawQuery)
		skip, _ := strconv.Atoi(r.URL.Query().Get("$skip"))
		var members []any
		for i := skip; i < total && i < skip+page; i++ {
			ts := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 2 * time.Hour)
			members = append(members, map[string]any{"@odata.id": fmt.Sprintf("%s/%d", entries, i), "Id": strconv.Itoa(i), "Created": ts.Format(time.RFC3339), "Severity": "OK", "Message": "x"})
		}
		body := map[string]any{"Members": members, "Members@odata.count": total}
		if skip+page < total {
			body["Members@odata.nextLink"] = fmt.Sprintf("%s?$skip=%d", entries, skip+page)
		}
		_ = json.NewEncoder(w).Encode(body)
		return true
	}
	if _, err := Collect(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	if len(asked) < 2 || asked[1] != "$skip=700" {
		t.Fatalf("queries %v", asked)
	}
	if len(asked) > 2+maxLogEntries/page {
		t.Errorf("read %d pages", len(asked))
	}
}

func TestTimeoutAndCancelStillLogOut(t *testing.T) {
	f := newFake(t, "localstorage")
	f.delay["/redfish/v1/Chassis/1U/Thermal"] = 5 * time.Second
	o := f.opts()
	o.Timeout = 700 * time.Millisecond
	start := time.Now()
	b, err := Collect(context.Background(), o)
	if err != nil {
		t.Fatalf("own timeout should return the partial bundle: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	if b.Get("meta.bmc").KV()["timeout"] != "1" {
		t.Error("timeout not recorded")
	}
	s := b.Get("redfish.res:/redfish/v1/Chassis/1U/Thermal")
	if s == nil || s.RC != -1 || !s.Timeout {
		t.Errorf("thermal section %+v", s)
	}
	if f.liveSessions() != 0 || len(f.deleted) != 1 {
		t.Errorf("session not deleted after timeout: live %d deleted %v", f.liveSessions(), f.deleted)
	}
	res := analyze(t, b)
	if c := testkit.Cov(res, "redfish.thermal"); c == nil || c.State == model.CovRan {
		t.Errorf("thermal coverage %+v", c)
	}

	f2 := newFake(t, "localstorage")
	f2.delay["/redfish/v1/Chassis"] = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	_, err = Collect(ctx, f2.opts())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	if f2.liveSessions() != 0 {
		t.Error("session not deleted after cancel")
	}
}

func TestSizeCap(t *testing.T) {
	old := maxBody
	maxBody = 2048
	t.Cleanup(func() { maxBody = old })
	f := newFake(t, "localstorage")
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	s := b.Get("redfish.res:/redfish/v1/Chassis/1U/Thermal")
	if s == nil || !s.Truncated || s.Out != "" || !strings.Contains(s.Err, "larger") {
		t.Errorf("thermal %+v", s)
	}
	analyze(t, b)
}

func TestRedfishUnavailable(t *testing.T) {
	f := newFake(t, "localstorage")
	delete(f.mock, "/redfish/v1")
	o := f.opts()
	_, err := Collect(context.Background(), o)
	var un *unavailableError
	if !errors.As(err, &un) || !errors.Is(err, ErrRedfishUnavailable) {
		t.Fatalf("err %T %v", err, err)
	}
	// auto without ipmitool: a clear error.
	oldLook := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { lookPath = oldLook })
	o.Protocol = "auto"
	b, err := Collect(context.Background(), o)
	if !errors.Is(err, ErrNoProtocol) || !strings.Contains(err.Error(), "ipmitool is not installed") {
		t.Errorf("err %v", err)
	}
	if b == nil || b.Get("redfish.res:/redfish/v1") == nil {
		t.Error("bundle with the failed root expected")
	}
	// auto with ipmitool: falls back.
	fr := &fakeRunner{}
	useRunner(t, fr)
	b, err = Collect(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if m := b.Get("meta.bmc").KV(); m["protocol"] != "ipmi" || m["redfishError"] == "" {
		t.Errorf("meta %v", m)
	}
	if b.Get("ipmi.sdr") == nil {
		t.Error("ipmi sections missing")
	}
}

func TestNewSchemaFallback(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "rackmount1")
	delete(f.mock, "/redfish/v1/Chassis/1U/Thermal") // 404: use ThermalSubsystem + Sensors
	ch := f.mock["/redfish/v1/Chassis/1U"]
	delete(ch, "Power") // no link: use PowerSubsystem
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/redfish/v1/Chassis/1U/ThermalSubsystem/Fans/Bay1", "/redfish/v1/Chassis/1U/Sensors/CPU1Temp", "/redfish/v1/Chassis/1U/PowerSubsystem/PowerSupplies/Bay1/Metrics"} {
		if s := b.Get("redfish.res:" + p); s == nil || s.RC != 200 {
			t.Errorf("%s: %+v", p, s)
		}
	}
	res := analyze(t, b)
	if c := testkit.Cov(res, "redfish.thermal"); c == nil || c.State != model.CovRan {
		t.Errorf("thermal coverage %+v", c)
	}
	if testkit.Find(res, "redfish.psu_warning", "PSU 1") == nil {
		t.Errorf("findings %v", testkit.IDs(res))
	}
}

func TestNoCredentials(t *testing.T) {
	f := newFake(t, "localstorage")
	o := f.opts()
	o.User, o.Password = "", ""
	_, err := Collect(context.Background(), o)
	if !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "requires a user name") {
		t.Errorf("err %v", err)
	}
}
