package notify

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

var fastOpts = Options{Attempts: 3, Backoff: time.Millisecond, MaxWait: time.Second}

func problemMessage(lang string) *Message {
	f := fnd("disk.smart_pending", "/dev/sda", model.CompDisk, model.Crit, "Disk /dev/sda <failing> & co")
	m, _ := Diff(rep([]model.Finding{f, ramCE}, nil), nil, DiffOptions{Lang: lang, Version: "0.1.0"})
	return m
}

func mustParse(t *testing.T, cfg string) *Config {
	t.Helper()
	c, err := Parse(strings.NewReader(cfg), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type captured struct {
	mu     sync.Mutex
	paths  []string
	bodies [][]byte
	hdrs   []http.Header
}

func (c *captured) add(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths = append(c.paths, r.URL.Path)
	c.bodies = append(c.bodies, b)
	c.hdrs = append(c.hdrs, r.Header.Clone())
	return b
}

func sendOne(t *testing.T, cfg string, m *Message) error {
	t.Helper()
	c := mustParse(t, cfg)
	res := Send(context.Background(), c, m, fastOpts)
	if len(res) != 1 {
		t.Fatalf("results %v", res)
	}
	return res[0].Err
}

const tgToken = "123456789:AAHsecretTelegramToken"

func TestTelegram(t *testing.T) {
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
		}
		io.WriteString(w, `{"ok":true,"result":{"message_id":1}}`)
	}))
	defer srv.Close()
	cfg := fmt.Sprintf("[telegram]\ntoken=%s\nchat_id=-1001234\nthread_id=7\napi_url=%s\n", tgToken, srv.URL)
	if err := sendOne(t, cfg, problemMessage("vi")); err != nil {
		t.Fatal(err)
	}
	if got.paths[0] != "/bot"+tgToken+"/sendMessage" {
		t.Errorf("path %s", got.paths[0])
	}
	var p struct {
		ChatID    int64           `json:"chat_id"`
		Text      string          `json:"text"`
		ParseMode string          `json:"parse_mode"`
		Thread    int64           `json:"message_thread_id"`
		Preview   map[string]bool `json:"link_preview_options"`
	}
	if err := json.Unmarshal(got.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.ChatID != -1001234 || p.ParseMode != "HTML" || p.Thread != 7 || !p.Preview["is_disabled"] {
		t.Errorf("payload %+v", p)
	}
	if !strings.Contains(p.Text, "&lt;failing&gt; &amp; co") || !strings.Contains(p.Text, "<b>") || !strings.Contains(p.Text, "Vấn đề mới (2):") {
		t.Errorf("text:\n%s", p.Text)
	}
	if strings.Contains(p.Text, tgToken) {
		t.Error("token in text")
	}
}

func TestTelegramErrorsHideToken(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(400)
		io.WriteString(w, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found (bot`+tgToken+`)"}`)
	}))
	defer srv.Close()
	cfg := fmt.Sprintf("[telegram]\ntoken=%s\nchat_id=1\napi_url=%s\n", tgToken, srv.URL)
	err := sendOne(t, cfg, problemMessage("en"))
	if err == nil || !strings.Contains(err.Error(), "chat not found") || !strings.Contains(err.Error(), "telegram: HTTP 400") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "AAHsecretTelegramToken") || strings.Contains(Text(err, "vi"), "AAHsecretTelegramToken") {
		t.Errorf("token leaked: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("400 retried %d times", calls.Load())
	}

	// Connection refused: the URL (with the token) must not appear.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	cfg = fmt.Sprintf("[telegram]\ntoken=%s\nchat_id=1\napi_url=http://%s\n", tgToken, addr)
	err = sendOne(t, cfg, problemMessage("en"))
	if err == nil || strings.Contains(err.Error(), "AAHsecret") || strings.Contains(err.Error(), "/bot") || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Errorf("refused: %v", err)
	}
	// "ok": false with HTTP 200 is a failure too.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":false,"description":"strange"}`)
	}))
	defer srv2.Close()
	cfg = fmt.Sprintf("[telegram]\ntoken=%s\nchat_id=1\napi_url=%s\n", tgToken, srv2.URL)
	if err := sendOne(t, cfg, problemMessage("en")); err == nil || !strings.Contains(err.Error(), "strange") {
		t.Errorf("ok=false: %v", err)
	}
}

func TestRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(429)
			io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 0","parameters":{"retry_after":0.01}}`)
		case 2:
			w.WriteHeader(502)
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf("[telegram]\ntoken=%s\nchat_id=1\napi_url=%s\n", tgToken, srv.URL)
	if err := sendOne(t, cfg, problemMessage("en")); err != nil || calls.Load() != 3 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}

	// Always 503: gives up after the attempts.
	calls.Store(0)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}))
	defer srv2.Close()
	err := sendOne(t, "[slack]\nurl="+srv2.URL+"/services/T0/B0/slackSecretToken\n", problemMessage("vi"))
	if err == nil || calls.Load() != 3 || !strings.Contains(Text(err, "vi"), "sau 3 lần thử") || strings.Contains(err.Error(), "slackSecretToken") {
		t.Errorf("503: %v (%d calls)", err, calls.Load())
	}

	// A Retry-After beyond MaxWait gives up at once.
	calls.Store(0)
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
	}))
	defer srv3.Close()
	err = sendOne(t, "[discord]\nurl="+srv3.URL+"/api/webhooks/1/discordSecretToken\n", problemMessage("en"))
	if err == nil || calls.Load() != 1 || !strings.Contains(err.Error(), "wait") {
		t.Errorf("retry-after: %v (%d calls)", err, calls.Load())
	}

	// Redirects are not followed.
	calls.Store(0)
	srv4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer srv4.Close()
	err = sendOne(t, "[webhook]\nurl="+srv4.URL+"/hook\n", problemMessage("en"))
	if err == nil || !strings.Contains(err.Error(), "redirects") || calls.Load() != 1 {
		t.Errorf("redirect: %v", err)
	}
}

func TestZalo(t *testing.T) {
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		io.WriteString(w, `{"ok":true,"result":{"message_id":"82599fa32f56d00e8941","date":1749632637199}}`)
	}))
	defer srv.Close()
	cfg := "[zalo]\ntoken=1234567890:zaloSecretToken\nchat_id=abc123def\napi_url=" + srv.URL + "\n"
	if err := sendOne(t, cfg, bigMessage("vi", 100)); err != nil {
		t.Fatal(err)
	}
	if got.paths[0] != "/bot1234567890:zaloSecretToken/sendMessage" {
		t.Errorf("path %s", got.paths[0])
	}
	var p map[string]any
	if err := json.Unmarshal(got.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	text, _ := p["text"].(string)
	if p["chat_id"] != "abc123def" || p["parse_mode"] != nil || len([]rune(text)) > 2000 || len([]rune(text)) == 0 {
		t.Errorf("payload chat=%v mode=%v len=%d", p["chat_id"], p["parse_mode"], len([]rune(text)))
	}
	if !strings.Contains(text, "<failing>") {
		t.Errorf("zalo text should be plain:\n%s", text)
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
	}))
	defer srv2.Close()
	err := sendOne(t, "[zalo]\ntoken=1234567890:zaloSecretToken\nchat_id=x\napi_url="+srv2.URL+"\n", problemMessage("vi"))
	if err == nil || !strings.Contains(Text(err, "vi"), "kiểm tra lại token") || strings.Contains(err.Error(), "zaloSecret") {
		t.Errorf("401: %v", err)
	}
}

func TestSlackAndDiscord(t *testing.T) {
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		if strings.HasPrefix(r.URL.Path, "/api/webhooks/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	cfg := "[slack]\nurl=" + srv.URL + "/services/T0/B0/slackSecretToken\n[discord]\nurl=" + srv.URL + "/api/webhooks/1/discordSecretToken\nusername=Kho máy\n"
	c := mustParse(t, cfg)
	for _, r := range Send(context.Background(), c, problemMessage("en"), fastOpts) {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	for i, path := range got.paths {
		var p map[string]any
		if err := json.Unmarshal(got.bodies[i], &p); err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.HasPrefix(path, "/services/"):
			text, _ := p["text"].(string)
			if !strings.Contains(text, "&lt;failing&gt; &amp; co") || !strings.Contains(text, "*New problems (2):*") {
				t.Errorf("slack text:\n%s", text)
			}
		case strings.HasPrefix(path, "/api/webhooks/"):
			content, _ := p["content"].(string)
			am, _ := p["allowed_mentions"].(map[string]any)
			parse, ok := am["parse"].([]any)
			if !ok || len(parse) != 0 || p["username"] != "Kho máy" {
				t.Errorf("discord payload %v", p)
			}
			if !strings.Contains(content, `\<failing\>`) || !strings.Contains(content, "**") {
				t.Errorf("discord content:\n%s", content)
			}
		default:
			t.Errorf("path %s", path)
		}
	}
	if len(got.paths) != 2 {
		t.Errorf("calls %v", got.paths)
	}
}

func TestWebhook(t *testing.T) {
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		w.WriteHeader(202)
	}))
	defer srv.Close()
	cfg := "[webhook]\nurl=" + srv.URL + "/hook?key=querySecretValue\nheader = Authorization: Bearer headerSecretValue\nsecret = hmacSecretValue\ninclude_report = true\n"
	m := problemMessage("vi")
	if err := sendOne(t, cfg, m); err != nil {
		t.Fatal(err)
	}
	h := got.hdrs[0]
	if h.Get("Authorization") != "Bearer headerSecretValue" || h.Get("X-Diagward-Event") != "problem" {
		t.Errorf("headers %v", h)
	}
	mac := hmac.New(sha256.New, []byte("hmacSecretValue"))
	mac.Write(got.bodies[0])
	if h.Get("X-Diagward-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Error("bad signature")
	}
	var p Payload
	if err := json.Unmarshal(got.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.Tool != "diagward" || p.Host != "srv01" || p.Verdict != "crit" || p.Event != EventProblem || p.Counts.Crit != 1 || p.Counts.Warn != 1 ||
		len(p.New) != 2 || p.New[0].Severity != "crit" || p.New[0].Title != "VI Disk /dev/sda <failing> & co" || p.New[0].Action != "Sửa /dev/sda" ||
		p.Serial != "8XK2LM2" || p.Report == nil || p.Report.Host.Hostname != "srv01" || p.Lang != "vi" || !strings.Contains(p.Text, "Vấn đề mới") {
		t.Errorf("payload %+v", p)
	}
	if p.Resolved == nil || p.Worsened == nil {
		t.Error("empty lists must be [] not null")
	}
	// Without include_report there is no report.
	got = captured{}
	if err := sendOne(t, "[webhook]\nurl="+srv.URL+"/hook\n", m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got.bodies[0]), `"report"`) {
		t.Error("report included")
	}

	// A server that echoes the credentials back in its error page.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprintf(w, "denied for %s at %s", r.Header.Get("Authorization"), r.URL.String())
	}))
	defer srv2.Close()
	err := sendOne(t, "[webhook]\nurl="+srv2.URL+"/hook/pathSecretValue12?key=querySecretValue\nheader = Authorization: Bearer headerSecretValue\n", m)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("err %v", err)
	}
	for _, s := range []string{"headerSecretValue", "querySecretValue", "pathSecretValue12"} {
		if strings.Contains(err.Error(), s) || strings.Contains(Text(err, "vi"), s) {
			t.Errorf("secret %s in %q", s, err)
		}
	}
}

func TestOneChannelFailingDoesNotStopOthers(t *testing.T) {
	var good atomic.Int32
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { good.Add(1) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer bad.Close()
	c := mustParse(t, "[slack]\nurl="+bad.URL+"/services/x/y/z\n[webhook a]\nurl="+ok.URL+"/1\n[webhook b]\nurl="+ok.URL+"/2\n")
	res := Send(context.Background(), c, problemMessage("en"), fastOpts)
	if res[0].Err == nil || res[1].Err != nil || res[2].Err != nil || good.Load() != 2 {
		t.Errorf("results %+v good=%d", res, good.Load())
	}
	if res[1].Channel != "webhook a" || !strings.Contains(res[0].Err.Error(), "404") {
		t.Errorf("names %+v", res)
	}
}

func TestTLSWebhook(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the untrusted handshake below is expected
	srv.StartTLS()
	defer srv.Close()
	cfg := "[webhook]\nurl=" + srv.URL + "/hook\n"
	// Untrusted certificate: a clear error, not retried.
	c := mustParse(t, cfg)
	res := Send(context.Background(), c, problemMessage("en"), fastOpts)
	if res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "certificate") || strings.Contains(res[0].Err.Error(), "attempts") {
		t.Errorf("untrusted: %v", res[0].Err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	o := fastOpts
	o.TLS = &tls.Config{RootCAs: pool}
	if res := Send(context.Background(), c, problemMessage("en"), o); res[0].Err != nil {
		t.Errorf("trusted: %v", res[0].Err)
	}
}

// fakeSMTP is a minimal SMTP server: EHLO, optional STARTTLS, AUTH PLAIN,
// MAIL, RCPT, DATA, QUIT.
type fakeSMTP struct {
	ln       net.Listener
	tls      *tls.Config // nil: no STARTTLS offered
	mu       sync.Mutex
	auth     string
	rcpt     []string
	data     string
	sawTLS   bool
	commands []string
}

func newFakeSMTP(t *testing.T, cfg *tls.Config) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, tls: cfg}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) port() string { _, p, _ := net.SplitHostPort(f.ln.Addr().String()); return p }

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := func(s string) { io.WriteString(conn, s+"\r\n") }
	w("220 fake ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		f.mu.Lock()
		f.commands = append(f.commands, cmd)
		f.mu.Unlock()
		switch cmd {
		case "EHLO", "HELO":
			w("250-fake")
			if f.tls != nil && !secure {
				w("250-STARTTLS")
			}
			w("250-AUTH PLAIN")
			w("250 8BITMIME")
		case "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(conn, f.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, r, secure = tc, bufio.NewReader(tc), true
			f.mu.Lock()
			f.sawTLS = true
			f.mu.Unlock()
		case "AUTH":
			parts := strings.Fields(line)
			if len(parts) == 3 {
				b, _ := base64.StdEncoding.DecodeString(parts[2])
				f.mu.Lock()
				f.auth = string(b)
				f.mu.Unlock()
			}
			w("235 ok")
		case "MAIL":
			w("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.rcpt = append(f.rcpt, line)
			f.mu.Unlock()
			w("250 ok")
		case "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			w("250 queued")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("502 unknown")
		}
	}
}

func TestEmailStartTLS(t *testing.T) {
	// Borrow httptest's certificate (valid for 127.0.0.1) for the fake
	// SMTP server, and trust it in the client.
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	ts.Close()

	f := newFakeSMTP(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	cfg := "[email]\nhost=127.0.0.1\nport=" + f.port() + "\nuser=alerts@example.com\npassword=mailPasswordSecret\nfrom=Diagward <alerts@example.com>\nto=ops@example.com, \"Trực ca\" <oncall@example.com>\n"
	c := mustParse(t, cfg)
	o := fastOpts
	o.TLS = &tls.Config{RootCAs: pool}
	res := Send(context.Background(), c, problemMessage("vi"), o)
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sawTLS || f.auth != "\x00alerts@example.com\x00mailPasswordSecret" || len(f.rcpt) != 2 {
		t.Errorf("tls=%v auth=%q rcpt=%v", f.sawTLS, f.auth, f.rcpt)
	}
	head, body, _ := strings.Cut(f.data, "\r\n\r\n")
	var subject string
	for _, l := range strings.Split(head, "\r\n") {
		if s, ok := strings.CutPrefix(l, "Subject: "); ok {
			subject, _ = new(mime.WordDecoder).DecodeHeader(s)
		}
	}
	if subject != "[Diagward] srv01: CẦN XỬ LÝ NGAY (2 vấn đề mới)" {
		t.Errorf("subject %q\n%s", subject, head)
	}
	for _, want := range []string{"Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable", "Message-ID: <", "Date: "} {
		if !strings.Contains(head, want) {
			t.Errorf("missing header %q", want)
		}
	}
	dec, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if !strings.Contains(string(dec), "Vấn đề mới (2):") || !strings.Contains(string(dec), "Sửa /dev/sda") {
		t.Errorf("body:\n%s", dec)
	}
}

func TestEmailRefusesWithoutSTARTTLS(t *testing.T) {
	f := newFakeSMTP(t, nil) // offers no STARTTLS
	cfg := "[email]\nhost=127.0.0.1\nport=" + f.port() + "\nuser=a@example.com\npassword=mailPasswordSecret\nfrom=a@example.com\nto=b@example.com\n"
	res := Send(context.Background(), mustParse(t, cfg), problemMessage("vi"), fastOpts)
	err := res[0].Err
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") || !strings.Contains(Text(err, "vi"), "không gửi khi chưa mã hóa") {
		t.Fatalf("err %v", err)
	}
	f.mu.Lock()
	if f.auth != "" || f.data != "" {
		t.Error("password or mail sent without TLS")
	}
	for _, c := range f.commands {
		if c == "AUTH" {
			t.Error("AUTH sent")
		}
	}
	f.mu.Unlock()

	// tls = none is fine for a local relay without a password.
	cfg = "[email]\nhost=127.0.0.1\nport=" + f.port() + "\ntls=none\nfrom=a@example.com\nto=b@example.com\n"
	if res := Send(context.Background(), mustParse(t, cfg), problemMessage("en"), fastOpts); res[0].Err != nil {
		t.Errorf("local relay: %v", res[0].Err)
	}
}

func TestEmailImplicitTLS(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	ts.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln} // TLS from the first byte, no STARTTLS
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	cfg := "[email]\nhost=127.0.0.1\nport=" + f.port() + "\ntls=tls\nuser=a@example.com\npassword=mailPasswordSecret\nfrom=a@example.com\nto=b@example.com\n"
	o := fastOpts
	o.TLS = &tls.Config{RootCAs: pool}
	if res := Send(context.Background(), mustParse(t, cfg), problemMessage("en"), o); res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "\x00a@example.com\x00mailPasswordSecret" || !strings.Contains(f.data, "Subject: [Diagward] srv01: ACTION NEEDED NOW (2 new problems)") {
		t.Errorf("auth=%q data=%q", f.auth, f.data)
	}

	// Without trusting the certificate: a clear error, not retried, no password.
	res := Send(context.Background(), mustParse(t, cfg), problemMessage("en"), fastOpts)
	if res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "certificate") || strings.Contains(res[0].Err.Error(), "attempts") {
		t.Errorf("untrusted: %v", res[0].Err)
	}
}
