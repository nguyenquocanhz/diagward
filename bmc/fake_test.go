package bmc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The mockups live with the redfish analysis tests (DMTF DSP2043 public
// mockups and vendor captures; see its testdata/SOURCES.md).
const mockupDir = "../internal/checks/redfish/testdata/mockups"

type mockup map[string]map[string]any

func loadMockup(t testing.TB, name string) mockup {
	t.Helper()
	root := filepath.Join(mockupDir, name)
	m := mockup{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		key := "/redfish/v1"
		if rel != "." {
			key += "/" + filepath.ToSlash(rel)
		}
		base := filepath.Base(p)
		if q, ok := strings.CutPrefix(strings.TrimSuffix(base, ".json"), "index@"); ok {
			key += "?" + q
		} else if base != "index.json" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var o map[string]any
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		m[key] = o
		return nil
	})
	if err != nil || len(m) == 0 {
		t.Fatalf("mockup %s: %v (%d resources)", name, err, len(m))
	}
	return m
}

// fakeBMC is a Redfish service serving a mockup, with sessions, Basic
// auth and knobs for failure cases.
type fakeBMC struct {
	t        testing.TB
	mock     mockup
	user     string
	pass     string
	sessions bool // session service available (else 405 → Basic)
	basic    bool // HTTP Basic accepted

	mu       sync.Mutex
	tokens   map[string]bool
	logins   int
	deleted  []string
	hits     map[string]int
	requests []string
	authHdrs []string // every Authorization / X-Auth-Token header seen

	delay   map[string]time.Duration // per path
	dynamic func(w http.ResponseWriter, r *http.Request) bool
	srv     *httptest.Server
}

func newFake(t testing.TB, name string) *fakeBMC {
	f := &fakeBMC{t: t, mock: loadMockup(t, name), user: "root", pass: "S3cr3t-Pa55word!", sessions: true, basic: true,
		tokens: map[string]bool{}, hits: map[string]int{}, delay: map[string]time.Duration{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // aborted handshakes are expected
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBMC) addr() string { return strings.TrimPrefix(f.srv.URL, "https://") }

func (f *fakeBMC) opts() Options {
	return Options{Host: f.addr(), User: f.user, Password: f.pass, Insecure: true, Protocol: "redfish", Timeout: 20 * time.Second, SinceDays: 30}
}

func cleanKey(p string) string {
	k := path.Clean(p)
	if k == "." {
		k = "/"
	}
	return k
}

func (f *fakeBMC) serve(w http.ResponseWriter, r *http.Request) {
	key := cleanKey(r.URL.EscapedPath())
	full := key
	if r.URL.RawQuery != "" {
		full += "?" + r.URL.RawQuery
	}
	f.mu.Lock()
	f.hits[full]++
	f.requests = append(f.requests, r.Method+" "+full)
	if a := r.Header.Get("Authorization"); a != "" {
		f.authHdrs = append(f.authHdrs, a)
	}
	if a := r.Header.Get("X-Auth-Token"); a != "" {
		f.authHdrs = append(f.authHdrs, a)
	}
	d := f.delay[key]
	f.mu.Unlock()
	if d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	if f.dynamic != nil && f.dynamic(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodPost && key == "/redfish/v1/SessionService/Sessions":
		if !f.sessions {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var body struct{ UserName, Password string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
		f.mu.Lock()
		f.logins++
		f.mu.Unlock()
		if body.UserName != f.user || body.Password != f.pass {
			http.Error(w, `{"error":{"code":"Base.1.8.NoValidSession"}}`, http.StatusUnauthorized)
			return
		}
		var b [16]byte
		_, _ = rand.Read(b[:])
		tok := hex.EncodeToString(b[:])
		id := tok[:8]
		f.mu.Lock()
		f.tokens[tok] = true
		f.mu.Unlock()
		w.Header().Set("X-Auth-Token", tok)
		w.Header().Set("Location", "/redfish/v1/SessionService/Sessions/"+id)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// A careless BMC echoing the token and user in the body.
		_ = json.NewEncoder(w).Encode(map[string]any{"@odata.id": "/redfish/v1/SessionService/Sessions/" + id, "UserName": body.UserName, "Token": tok})
		return
	case r.Method == http.MethodDelete && strings.HasPrefix(key, "/redfish/v1/SessionService/Sessions/"):
		tok := r.Header.Get("X-Auth-Token")
		f.mu.Lock()
		ok := f.tokens[tok]
		if ok {
			delete(f.tokens, tok)
			f.deleted = append(f.deleted, key)
		}
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case r.Method != http.MethodGet:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if key != "/redfish/v1" && !f.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="BMC"`)
		http.Error(w, `{"error":{"code":"Base.1.8.InsufficientPrivilege"}}`, http.StatusUnauthorized)
		return
	}
	o, ok := f.mock[full]
	if !ok {
		http.Error(w, `{"error":{"code":"Base.1.8.ResourceMissingAtURI"}}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(o)
}

func (f *fakeBMC) authorized(r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tok := r.Header.Get("X-Auth-Token"); tok != "" {
		return f.tokens[tok]
	}
	if !f.basic {
		return false
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(f.user+":"+f.pass))
	return r.Header.Get("Authorization") == want
}

func (f *fakeBMC) hitCount(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[p]
}

func (f *fakeBMC) liveSessions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tokens)
}
