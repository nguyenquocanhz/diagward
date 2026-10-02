package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/internal/checks/redfish"
	"github.com/nguyenquocanhz/diagward/model"
)

// newFakeCapture serves a real BMC capture (testdata/captures/<name>.json in
// the redfish package: {"/redfish/v1/...": resource}).
func newFakeCapture(t testing.TB, name string) *fakeBMC {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(mockupDir, "..", "captures", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	m := mockup{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f := &fakeBMC{t: t, mock: m, user: "root", pass: "Xcc-Pa55word-2024", sessions: true, basic: true,
		tokens: map[string]bool{}, hits: map[string]int{}, delay: map[string]time.Duration{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// Collect from real Dell, HPE, Lenovo and Supermicro captures, analyse the
// bundle with diag.Analyze (what "diagward bmc" does) and check the report
// is coherent and carries no credentials.
func TestCapturesEndToEnd(t *testing.T) {
	fixedNow(t)
	for _, c := range []struct {
		name, vendor, model, serial string
		verdict                     model.Severity
		mustHave                    string
	}{
		{"dell", "Dell Inc.", "PowerEdge R750", "F54P1G3", model.OK, "redfish.storage_ok"},
		{"hpe", "HPE", "ProLiant DL385 Gen10 Plus v2", "MXQ302099S", model.Crit, "redfish.drive_failed"},
		{"lenovo", "Lenovo", "ThinkSystem SR670 V2", "J105958B", model.OK, "redfish.logs_ok"},
		{"supermicro", "Supermicro", "SYS-821GE-TNHR", "S889914X3710910", model.OK, "redfish.logs_ok"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeCapture(t, c.name)
			b, err := Collect(context.Background(), f.opts())
			if err != nil {
				t.Fatal(err)
			}
			if f.liveSessions() != 0 {
				t.Error("session left open")
			}
			rep := diag.Analyze(b)
			if rep.Host.Vendor != c.vendor || rep.Host.Model != c.model || rep.Host.Serial != c.serial || !strings.HasPrefix(rep.Host.OS, "Redfish ") {
				t.Errorf("host %+v", rep.Host)
			}
			if rep.Verdict != c.verdict {
				var ids []string
				for _, f := range rep.Findings {
					ids = append(ids, f.ID+"="+f.Severity.String())
				}
				t.Errorf("verdict %s, want %s: %v", rep.Verdict, c.verdict, ids)
			}
			found := false
			for _, f := range rep.Findings {
				found = found || f.ID == c.mustHave
			}
			if !found {
				t.Errorf("no %s", c.mustHave)
			}
			for _, cv := range rep.Coverage {
				if strings.HasSuffix(cv.ID, ".internal") {
					t.Errorf("analysis panicked: %+v", cv)
				}
				if strings.HasPrefix(cv.ID, "redfish.") && cv.State != model.CovRan {
					t.Errorf("coverage %s %s: %s", cv.ID, cv.State, cv.Reason.EN)
				}
			}
			for _, x := range []any{b, rep} {
				raw, _ := json.Marshal(x)
				if strings.Contains(string(raw), f.pass) {
					t.Fatalf("password in %T", x)
				}
				for _, h := range f.authHdrs {
					if strings.Contains(string(raw), strings.TrimPrefix(h, "Basic ")) {
						t.Fatalf("auth header in %T", x)
					}
				}
			}
			for _, s := range b.Sections {
				if strings.Contains(s.Name, "/AuditLog/Entries") || strings.Contains(s.Name, "/MaintenanceLog/Entries") {
					t.Errorf("audit/maintenance log read: %s", s.Name)
				}
			}
			if c.name == "supermicro" && b.Get("redfish.res:/redfish/v1/Managers/1/LogServices/Log1/Entries") != nil {
				t.Error("Supermicro maintenance log (Managers/1 Log1) read")
			}
		})
	}
}

// A 403 from the session service is not "wrong password": the error says
// so, wraps ErrAuth, and Basic is not tried (a second refused login).
func TestSessionForbidden(t *testing.T) {
	f := newFake(t, "localstorage")
	f.dynamic = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost {
			f.mu.Lock()
			f.logins++
			f.mu.Unlock()
			http.Error(w, `{"error":{"code":"Base.1.8.InsufficientPrivilege"}}`, http.StatusForbidden)
			return true
		}
		return false
	}
	_, err := Collect(context.Background(), f.opts())
	if !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "locked out") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "user name or password") || strings.Contains(err.Error(), f.pass) {
		t.Errorf("misleading or leaking error: %v", err)
	}
	if f.logins != 1 || len(f.authHdrs) != 0 {
		t.Errorf("logins %d, auth headers %v", f.logins, f.authHdrs)
	}
}

// A busy BMC answers 503 (or 429) with Retry-After: the request is retried
// once, and the resource is stored.
func TestRetryWhenBusy(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "localstorage")
	var busy atomic.Int32
	f.dynamic = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && cleanKey(r.URL.Path) == "/redfish/v1/Systems" && busy.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"error":"busy"}`, http.StatusServiceUnavailable)
			return true
		}
		if r.Method == http.MethodGet && cleanKey(r.URL.Path) == "/redfish/v1/Chassis" {
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"error":"too many"}`, http.StatusTooManyRequests)
			return true
		}
		return false
	}
	start := time.Now()
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if s := b.Get("redfish.res:/redfish/v1/Systems"); s == nil || s.RC != 200 {
		t.Errorf("Systems after 503: %+v", s)
	}
	if n := f.hitCount("/redfish/v1/Systems"); n != 2 {
		t.Errorf("Systems asked %d times", n)
	}
	// Always 429: one retry, then the 429 is stored.
	if s := b.Get("redfish.res:/redfish/v1/Chassis"); s == nil || s.RC != 429 || f.hitCount("/redfish/v1/Chassis") != 2 {
		t.Errorf("Chassis %+v asked %d times", s, f.hitCount("/redfish/v1/Chassis"))
	}
	if time.Since(start) > 15*time.Second {
		t.Error("retry waited too long")
	}
	if retryDelay("3600") != maxRetryWait || retryDelay("") != retryWait || retryDelay("Wed, 21 Oct 2015 07:28:00 GMT") != retryWait {
		t.Error("retryDelay")
	}
}

// A log that pages without a nextLink (Members@odata.count larger than the
// page) is read on with $skip, so the newest entries of an oldest-first log
// are not missed; a service that ignores $skip does not loop.
func TestLogPagesWithoutNextLink(t *testing.T) {
	fixedNow(t)
	for _, ignoreSkip := range []bool{false, true} {
		f := newFake(t, "localstorage")
		const total, page = 120, 40
		entries := "/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries"
		var asked []string
		f.dynamic = func(w http.ResponseWriter, r *http.Request) bool {
			if cleanKey(r.URL.Path) != entries {
				return false
			}
			asked = append(asked, r.URL.RawQuery)
			skip, _ := strconv.Atoi(r.URL.Query().Get("$skip"))
			if ignoreSkip {
				skip = 0
			}
			var members []any
			for i := skip; i < total && i < skip+page; i++ {
				ts := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 6 * time.Hour)
				sev, msg := "OK", "x"
				if i == total-1 {
					sev, msg = "Critical", "The power input for power supply 2 is lost."
				}
				members = append(members, map[string]any{"@odata.id": fmt.Sprintf("%s/%d", entries, i), "Id": strconv.Itoa(i), "Created": ts.Format(time.RFC3339), "Severity": sev, "Message": msg, "MessageId": "PSU0003"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Members": members, "Members@odata.count": total})
			return true
		}
		b, err := Collect(context.Background(), f.opts())
		if err != nil {
			t.Fatal(err)
		}
		if ignoreSkip {
			if len(asked) != 2 {
				t.Errorf("ignored $skip: queries %v", asked)
			}
			continue
		}
		if strings.Join(asked, ",") != ",$skip=40,$skip=80" {
			t.Errorf("queries %v", asked)
		}
		res := analyze(t, b)
		found := false
		for _, f := range res.Findings {
			found = found || (f.ID == "redfish.event_critical" && f.Severity == model.Crit)
		}
		if !found {
			t.Errorf("newest critical entry missed: %v", res.Findings)
		}
	}
}

// A link-local IPv6 BMC address carries a zone; every resolved link must
// keep it escaped (it used to make url.Parse fail and login panic).
func TestIPv6ZoneLinks(t *testing.T) {
	a, err := parseAddress("fe80::1%eth0", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	c := newRFClient(Options{SinceDays: 30}, a, &collect.Bundle{})
	u, key, ok := c.resolve("/redfish/v1/Systems/1")
	if !ok || key != "/redfish/v1/Systems/1" || u.String() != "https://[fe80::1%25eth0]/redfish/v1/Systems/1" || u.Hostname() != "fe80::1%eth0" {
		t.Fatalf("resolve: %v %q %v", u, key, ok)
	}
	if _, _, ok := c.resolve("https://[fe80::1%25eth0]/redfish/v1/Chassis"); !ok {
		t.Error("absolute link to the same zoned host refused")
	}
	if _, _, ok := c.resolve("https://[fe80::2%25eth0]/redfish/v1/Chassis"); ok {
		t.Error("link to another host accepted")
	}
	// login must not panic; nothing listens there, so it falls back to Basic.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.login(ctx, nil)
}

// iLO 4 2.77 (real capture): links in the pre-1.0 "href" form, IML paged
// with links.NextPage (?page=N; $skip is silently ignored) and entries inline
// in Items. The collector must follow ?page=, never fetch the 175 entries one
// by one, and find Memory/Processors/SmartStorage where iLO 4 links them.
func TestILO4Collect(t *testing.T) {
	fixedNow(t)
	f := newFakeCapture(t, "ilo4")
	b, err := Collect(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	entries := "/redfish/v1/Systems/1/LogServices/IML/Entries"
	for _, p := range []string{entries, entries + "?page=2", entries + "?page=3", "/redfish/v1/Systems/1/Memory", "/redfish/v1/Systems/1/Memory/proc1dimm1",
		"/redfish/v1/Systems/1/Processors/1", "/redfish/v1/Systems/1/SmartStorage"} {
		if f.hitCount(p) != 1 {
			t.Errorf("%s asked %d times", p, f.hitCount(p))
		}
	}
	for p := range f.hits {
		if strings.HasPrefix(p, entries+"/") || strings.Contains(p, "$skip") {
			t.Errorf("unexpected request %s", p)
		}
	}
	res := analyze(t, b)
	facts := res.Facts.(*redfish.Facts)
	if len(facts.DIMMs) != 2 || len(facts.CPUs) != 1 || len(facts.Batteries) != 1 {
		t.Errorf("dimms %d cpus %d batteries %d", len(facts.DIMMs), len(facts.CPUs), len(facts.Batteries))
	}
}

// A long iLO 4 IML (oldest first, ?page= paging, $skip ignored): the
// collector jumps to the last pages so the newest entries are read.
func TestILO4LongLogJumpsToLastPages(t *testing.T) {
	fixedNow(t)
	f := newFake(t, "localstorage")
	const total, per = 900, 30
	entries := "/redfish/v1/Systems/437XR1138R2/LogServices/Log1/Entries"
	var asked []string
	f.dynamic = func(w http.ResponseWriter, r *http.Request) bool {
		if cleanKey(r.URL.Path) != entries {
			return false
		}
		asked = append(asked, r.URL.RawQuery)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1 // $skip / $top are ignored, as on iLO 4
		}
		var members, items []any
		for i := (page - 1) * per; i < total && i < page*per; i++ {
			id := fmt.Sprintf("%s/%d/", entries, i+1)
			members = append(members, map[string]any{"@odata.id": id})
			ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 6 * time.Hour)
			items = append(items, map[string]any{"@odata.id": id, "Id": strconv.Itoa(i + 1), "Created": ts.Format(time.RFC3339), "Severity": "OK", "Message": "x", "Oem": map[string]any{"Hp": map[string]any{"Class": 1, "Code": 1}}})
		}
		links := map[string]any{"self": map[string]any{"href": fmt.Sprintf("%s/?page=%d", entries, page)}}
		if page*per < total {
			links["NextPage"] = map[string]any{"page": page + 1, "count": per}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Members": members, "Items": items, "Members@odata.count": total, "links": links})
		return true
	}
	if _, err := Collect(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	if len(asked) < 3 || asked[1] != "$skip=400" || asked[2] != "page=15" || asked[len(asked)-1] != "page=30" {
		t.Errorf("queries %v", asked)
	}
}
