// Package notify sends Diagward's verdict to chat and mail channels
// (Telegram, Zalo Bot, Slack, Discord, a generic JSON webhook, SMTP e-mail)
// for unattended runs, and remembers the previous run so that it reports
// only what changed. See docs/notify.md.
//
// Secrets (bot tokens, webhook URLs, passwords) come only from the config
// file (or the env:/file: references in it). They never appear in errors,
// logs, the state file, bundles or reports: every error a channel returns
// is passed through the config's redactor.
package notify

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// Config is a parsed notification config file.
type Config struct {
	Lang     string         // "vi" or "en"; "" = the program's language
	Top      int            // problems listed per message (default 5)
	MinSev   model.Severity // lowest severity that counts as a problem (Warn or Crit)
	Timeout  time.Duration  // per HTTP request / SMTP session (default 15s)
	Channels []Channel

	secrets []string
}

// Channel is one configured destination.
type Channel interface {
	// Name is "telegram", "slack", ... or "telegram ops" when the section
	// was named; it never contains a secret.
	Name() string
	send(ctx sendCtx, m *Message) error
}

// ConfigError is a problem in the config file. It never quotes a value.
type ConfigError struct {
	Line int
	EN   string
	VI   string
}

func (e *ConfigError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.EN)
	}
	return e.EN
}

// In returns the message in lang.
func (e *ConfigError) In(lang string) string {
	msg := model.T(e.EN, e.VI).In(lang)
	if e.Line > 0 {
		if strings.HasPrefix(lang, "vi") {
			return fmt.Sprintf("dòng %d: %s", e.Line, msg)
		}
		return fmt.Sprintf("line %d: %s", e.Line, msg)
	}
	return msg
}

func cerr(line int, en, vi string, args ...any) error {
	return &ConfigError{Line: line, EN: fmt.Sprintf(en, args...), VI: fmt.Sprintf(vi, args...)}
}

// LoadOptions controls Load.
type LoadOptions struct {
	GOOS   string              // runtime.GOOS; decides whether file modes are checked
	Force  bool                // accept a config readable by group/others
	Getenv func(string) string // for env: references
}

// ErrInsecureMode is returned (wrapped in a ConfigError) when the config
// file can be read by other users and Force is not set.
var ErrInsecureMode = errors.New("config file readable by group or others")

// Load reads and parses the config file at path. Warnings (an insecure mode
// accepted with Force) are returned separately.
func Load(path string, o LoadOptions) (*Config, []model.Text, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, fileErr(path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, cerr(0, "%s is not a regular file", "%s không phải tệp thường", path)
	}
	var warns []model.Text
	if insecureMode(fi.Mode(), o.GOOS) {
		if !o.Force {
			return nil, nil, &insecureErr{path: path, mode: fi.Mode().Perm()}
		}
		warns = append(warns, model.Tf(
			"%s can be read by other users (mode %04o) and holds secrets; fix it with: chmod 600 %s",
			"%s đang cho người dùng khác đọc được (quyền %04o) mà lại chứa thông tin bí mật; sửa bằng: chmod 600 %s",
			path, fi.Mode().Perm(), path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fileErr(path, err)
	}
	defer f.Close()
	c, err := Parse(f, o.Getenv)
	return c, warns, err
}

type insecureErr struct {
	path string
	mode fs.FileMode
}

func (e *insecureErr) Error() string {
	return fmt.Sprintf("%s can be read by other users (mode %04o) and holds secrets: run chmod 600 %s (or pass --force)", e.path, e.mode, e.path)
}

func (e *insecureErr) Unwrap() error { return ErrInsecureMode }

// In returns the message in lang.
func (e *insecureErr) In(lang string) string {
	return model.Tf(
		"%s can be read by other users (mode %04o) and holds secrets: run chmod 600 %s (or pass --force)",
		"%s đang cho người dùng khác đọc được (quyền %04o) mà lại chứa thông tin bí mật: chạy chmod 600 %s (hoặc thêm --force)",
		e.path, e.mode, e.path).In(lang)
}

func fileErr(path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return cerr(0, "%s does not exist", "không có tệp %s", path)
	case errors.Is(err, fs.ErrPermission):
		return cerr(0, "%s: permission denied (run as the user that owns it, e.g. root)", "%s: không có quyền đọc (chạy bằng người dùng sở hữu tệp, ví dụ root)", path)
	}
	return cerr(0, "%s: cannot read it", "%s: không đọc được tệp", path)
}

// insecureMode reports whether a config file's mode lets group or others
// read or write it. Windows has ACLs instead of mode bits (Go reports
// 0666/0444 there), so it is not checked; docs/notify.md shows icacls.
func insecureMode(m fs.FileMode, goos string) bool {
	if goos == "windows" || goos == "plan9" {
		return false
	}
	return m.Perm()&0o077 != 0
}

// Text returns err in lang when it is one of this package's errors.
func Text(err error, lang string) string {
	var ce *ConfigError
	if errors.As(err, &ce) {
		return ce.In(lang)
	}
	var ie *insecureErr
	if errors.As(err, &ie) {
		return ie.In(lang)
	}
	var se *SendError
	if errors.As(err, &se) {
		return se.In(lang)
	}
	return err.Error()
}

// section is one [kind name] block while parsing.
type section struct {
	kind, name string
	line       int
	kv         map[string]string
	lines      map[string]int
	headers    []string
}

var (
	sectionRe = regexp.MustCompile(`^\[\s*([A-Za-z]+)(?:\s+([A-Za-z0-9_.-]+))?\s*\]$`)
	keyRe     = regexp.MustCompile(`^[a-z_]+$`)
)

// Parse parses a config. The format is INI-like:
//
//	lang = vi
//	top = 5
//	[telegram]
//	token = 123456:ABC...
//	chat_id = -1001234567890
//
// Lines starting with # or ; are comments; a value may be quoted, or be
// env:NAME (an environment variable) or file:/path (the file's content).
func Parse(r io.Reader, getenv func(string) string) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	c := &Config{Top: 5, MinSev: model.Warn, Timeout: 15 * time.Second}
	global := &section{kv: map[string]string{}, lines: map[string]int{}}
	var secs []*section
	cur := global
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			line = strings.TrimPrefix(line, string(rune(0xFEFF))) // Notepad's UTF-8 BOM
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			m := sectionRe.FindStringSubmatch(line)
			if m == nil {
				return nil, cerr(n, "bad section header (use e.g. [telegram] or [telegram ops])", "tiêu đề mục không hợp lệ (ví dụ đúng: [telegram] hoặc [telegram ops])")
			}
			kind := strings.ToLower(m[1])
			if _, ok := channelKeys[kind]; !ok {
				return nil, cerr(n, "unknown channel [%s] (use telegram, zalo, slack, discord, webhook or email)", "không có kênh [%s] (dùng telegram, zalo, slack, discord, webhook hoặc email)", kind)
			}
			cur = &section{kind: kind, name: m[2], line: n, kv: map[string]string{}, lines: map[string]int{}}
			secs = append(secs, cur)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, cerr(n, "expected key = value", "cần dạng khóa = giá trị")
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if !keyRe.MatchString(k) {
			return nil, cerr(n, "bad key name", "tên khóa không hợp lệ")
		}
		allowed := globalKeys
		if cur != global {
			allowed = channelKeys[cur.kind]
		}
		if !allowed[k] {
			if cur == global {
				return nil, cerr(n, "unknown key %q at the top of the file (before any [section])", "khóa %q không dùng được ở phần đầu tệp (trước mục [..] đầu tiên)", k)
			}
			return nil, cerr(n, "unknown key %q in [%s]", "khóa %q không dùng được trong mục [%s]", k, cur.kind)
		}
		val, err := resolveValue(n, k, unquote(strings.TrimSpace(v)), getenv)
		if err != nil {
			return nil, err
		}
		if secretKeys[k] && cur != global {
			c.addSecret(val)
		}
		if k == "header" {
			cur.headers = append(cur.headers, val)
			continue
		}
		if _, dup := cur.kv[k]; dup {
			return nil, cerr(n, "%q is set twice", "khóa %q bị khai báo hai lần", k)
		}
		cur.kv[k] = val
		cur.lines[k] = n
	}
	if err := sc.Err(); err != nil {
		return nil, cerr(n, "cannot read the file: line too long or not text", "không đọc được tệp: dòng quá dài hoặc không phải văn bản")
	}
	if err := c.applyGlobal(global); err != nil {
		return nil, err
	}
	if len(secs) == 0 {
		return nil, cerr(0, "no channel configured (add a [telegram], [zalo], [slack], [discord], [webhook] or [email] section)",
			"chưa cấu hình kênh nào (thêm mục [telegram], [zalo], [slack], [discord], [webhook] hoặc [email])")
	}
	seen := map[string]int{}
	for _, s := range secs {
		ch, err := c.build(s)
		if err != nil {
			return nil, err
		}
		if l, dup := seen[ch.Name()]; dup {
			return nil, cerr(s.line, "a second [%s] section: give each one a name, e.g. [%s ops] (first one at line %d)",
				"mục [%s] thứ hai: hãy đặt tên riêng cho từng mục, ví dụ [%s ops] (mục đầu ở dòng %d)", s.kind, s.kind, l)
		}
		seen[ch.Name()] = s.line
		c.Channels = append(c.Channels, ch)
	}
	return c, nil
}

var globalKeys = map[string]bool{"lang": true, "top": true, "min_severity": true, "timeout": true}

var channelKeys = map[string]map[string]bool{
	"telegram": {"token": true, "chat_id": true, "thread_id": true, "api_url": true},
	"zalo":     {"token": true, "chat_id": true, "api_url": true},
	"slack":    {"url": true},
	"discord":  {"url": true, "username": true},
	"webhook":  {"url": true, "header": true, "secret": true, "include_report": true},
	"email":    {"host": true, "port": true, "tls": true, "user": true, "password": true, "from": true, "to": true},
}

// secretKeys hold values that must never be printed. Webhook URLs are
// secrets: for Slack and Discord the URL itself is the credential.
var secretKeys = map[string]bool{"token": true, "url": true, "password": true, "secret": true, "header": true}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// resolveValue expands env:NAME and file:/path. Errors name the variable or
// the path, never the value.
func resolveValue(line int, key, v string, getenv func(string) string) (string, error) {
	switch {
	case strings.HasPrefix(v, "env:"):
		name := strings.TrimPrefix(v, "env:")
		if !envNameRe.MatchString(name) {
			return "", cerr(line, "%s: bad environment variable name after env:", "%s: tên biến môi trường sau env: không hợp lệ", key)
		}
		val := strings.TrimSpace(getenv(name))
		if val == "" {
			return "", cerr(line, "%s: environment variable %s is not set", "%s: biến môi trường %s chưa được đặt", key, name)
		}
		return val, nil
	case strings.HasPrefix(v, "file:"):
		p := strings.TrimPrefix(v, "file:")
		b, err := os.ReadFile(p)
		if err != nil {
			return "", cerr(line, "%s: cannot read %s", "%s: không đọc được %s", key, p)
		}
		val := strings.TrimSpace(string(b))
		if val == "" || strings.ContainsAny(val, "\r\n") {
			return "", cerr(line, "%s: %s must hold the value on one line", "%s: tệp %s phải chứa giá trị trên đúng một dòng", key, p)
		}
		return val, nil
	}
	return v, nil
}

func (c *Config) addSecret(v string) {
	if len(v) < 4 {
		return
	}
	c.secrets = append(c.secrets, v)
	// A URL may show up re-encoded, or as its path, a path segment (the
	// token part of a Slack or Discord URL) or a query value alone.
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		if len(u.Path) > 8 {
			c.secrets = append(c.secrets, u.Path, u.EscapedPath())
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if len(seg) >= 12 {
				c.secrets = append(c.secrets, seg)
			}
		}
		if len(u.RawQuery) >= 4 {
			c.secrets = append(c.secrets, u.RawQuery)
		}
		for _, vals := range u.Query() {
			for _, q := range vals {
				if len(q) >= 4 {
					c.secrets = append(c.secrets, q)
				}
			}
		}
		return
	}
	// Header values are "Name: value" (often "Bearer xyz"): hide the value
	// and its last word on their own too.
	if _, val, ok := strings.Cut(v, ":"); ok {
		val = strings.TrimSpace(val)
		if len(val) >= 4 {
			c.secrets = append(c.secrets, val)
		}
		if f := strings.Fields(val); len(f) > 1 && len(f[len(f)-1]) >= 4 {
			c.secrets = append(c.secrets, f[len(f)-1])
		}
	}
}

// Redact removes every configured secret from s.
func (c *Config) Redact(s string) string {
	if c == nil {
		return s
	}
	// Longest first, so a secret that contains another is hidden whole.
	secrets := slices.Clone(c.secrets)
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, v := range secrets {
		s = strings.ReplaceAll(s, v, "***")
	}
	return s
}

func (c *Config) applyGlobal(s *section) error {
	if v, ok := s.kv["lang"]; ok {
		l := strings.ToLower(v)
		switch {
		case strings.HasPrefix(l, "vi"):
			c.Lang = "vi"
		case strings.HasPrefix(l, "en"):
			c.Lang = "en"
		default:
			return cerr(s.lines["lang"], "lang: use vi or en", "lang: dùng vi hoặc en")
		}
	}
	if v, ok := s.kv["top"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 50 {
			return cerr(s.lines["top"], "top: use a number from 1 to 50", "top: dùng số từ 1 đến 50")
		}
		c.Top = n
	}
	if v, ok := s.kv["min_severity"]; ok {
		switch strings.ToLower(v) {
		case "warn", "warning":
			c.MinSev = model.Warn
		case "crit", "critical":
			c.MinSev = model.Crit
		default:
			return cerr(s.lines["min_severity"], "min_severity: use warn or crit", "min_severity: dùng warn hoặc crit")
		}
	}
	if v, ok := s.kv["timeout"]; ok {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "s"))
		if err != nil || n < 2 || n > 120 {
			return cerr(s.lines["timeout"], "timeout: use 2 to 120 seconds", "timeout: dùng từ 2 đến 120 giây")
		}
		c.Timeout = time.Duration(n) * time.Second
	}
	return nil
}

func (s *section) need(keys ...string) error {
	for _, k := range keys {
		if s.kv[k] == "" {
			return cerr(s.line, "[%s] needs %s", "mục [%s] thiếu %s", s.kind, k)
		}
	}
	return nil
}

func (s *section) label() string {
	if s.name != "" {
		return s.kind + " " + s.name
	}
	return s.kind
}

// tokenRe: bot tokens go into the URL path, so only safe characters.
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9:_-]{8,200}$`)

func (c *Config) build(s *section) (Channel, error) {
	switch s.kind {
	case "telegram", "zalo":
		if err := s.need("token", "chat_id"); err != nil {
			return nil, err
		}
		if !tokenRe.MatchString(s.kv["token"]) {
			return nil, cerr(s.lines["token"], "[%s] token: not a bot token (letters, digits, ':', '_' and '-' only)", "mục [%s] token: không đúng dạng bot token (chỉ gồm chữ, số, ':', '_' và '-')", s.kind)
		}
		chat := s.kv["chat_id"]
		if strings.ContainsAny(chat, " \t") {
			return nil, cerr(s.lines["chat_id"], "[%s] chat_id: no spaces allowed", "mục [%s] chat_id: không được có dấu cách", s.kind)
		}
		def := "https://api.telegram.org"
		if s.kind == "zalo" {
			def = "https://bot-api.zaloplatforms.com"
		}
		api := strings.TrimRight(s.kv["api_url"], "/")
		if api == "" {
			api = def
		} else if err := checkURL(s, "api_url", api); err != nil {
			return nil, err
		}
		if s.kind == "zalo" {
			return &zalo{name: s.label(), api: api, token: s.kv["token"], chat: chat}, nil
		}
		t := &telegram{name: s.label(), api: api, token: s.kv["token"], chat: chat}
		if v := s.kv["thread_id"]; v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				return nil, cerr(s.lines["thread_id"], "[telegram] thread_id: use a positive number", "mục [telegram] thread_id: dùng số nguyên dương")
			}
			t.thread = n
		}
		return t, nil
	case "slack", "discord":
		if err := s.need("url"); err != nil {
			return nil, err
		}
		if err := checkURL(s, "url", s.kv["url"]); err != nil {
			return nil, err
		}
		if s.kind == "slack" {
			return &slack{name: s.label(), url: s.kv["url"]}, nil
		}
		user := s.kv["username"]
		if user == "" {
			user = "Diagward"
		}
		return &discord{name: s.label(), url: s.kv["url"], username: user}, nil
	case "webhook":
		if err := s.need("url"); err != nil {
			return nil, err
		}
		if err := checkURL(s, "url", s.kv["url"]); err != nil {
			return nil, err
		}
		w := &webhook{name: s.label(), url: s.kv["url"], secret: s.kv["secret"]}
		for _, h := range s.headers {
			k, v, ok := strings.Cut(h, ":")
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if !ok || k == "" || !headerNameRe.MatchString(k) || strings.ContainsAny(v, "\r\n") {
				return nil, cerr(s.line, "[%s] header: use header = Name: value", "mục [%s] header: dùng dạng header = Tên: giá_trị", s.kind)
			}
			w.headers = append(w.headers, [2]string{k, v})
		}
		if v, ok := s.kv["include_report"]; ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, cerr(s.lines["include_report"], "include_report: use true or false", "include_report: dùng true hoặc false")
			}
			w.report = b
		}
		return w, nil
	case "email":
		return buildEmail(s)
	}
	return nil, cerr(s.line, "unknown channel", "kênh không hợp lệ")
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// checkURL accepts https URLs, and http only to the local machine (a relay
// on localhost, tests). The URL is never quoted in the error.
func checkURL(s *section, key, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return cerr(s.lines[key], "[%s] %s: not a valid URL", "mục [%s] %s: URL không hợp lệ", s.kind, key)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
	}
	return cerr(s.lines[key], "[%s] %s: must start with https:// (plain http only to localhost)", "mục [%s] %s: phải bắt đầu bằng https:// (http thường chỉ dùng cho localhost)", s.kind, key)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func buildEmail(s *section) (Channel, error) {
	if err := s.need("host", "from", "to"); err != nil {
		return nil, err
	}
	e := &email{name: s.label(), host: s.kv["host"], user: s.kv["user"], pass: s.kv["password"]}
	if strings.ContainsAny(e.host, " /:\r\n") {
		return nil, cerr(s.lines["host"], "[email] host: a host name only (put the port in port =)", "mục [email] host: chỉ ghi tên máy chủ (cổng ghi ở port =)")
	}
	switch mode := strings.ToLower(s.kv["tls"]); mode {
	case "", "starttls":
		e.mode, e.port = "starttls", 587
	case "tls", "ssl", "implicit":
		e.mode, e.port = "tls", 465
	case "none":
		if !isLoopback(e.host) {
			return nil, cerr(s.lines["tls"], "[email] tls = none is only allowed for a relay on localhost", "mục [email] tls = none chỉ dùng được với máy chủ mail chạy trên localhost")
		}
		e.mode, e.port = "none", 25
	default:
		return nil, cerr(s.lines["tls"], "[email] tls: use starttls, tls or none", "mục [email] tls: dùng starttls, tls hoặc none")
	}
	if v := s.kv["port"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return nil, cerr(s.lines["port"], "[email] port: use 1 to 65535", "mục [email] port: dùng từ 1 đến 65535")
		}
		e.port = n
	}
	if (e.user == "") != (e.pass == "") {
		return nil, cerr(s.line, "[email] user and password go together", "mục [email] user và password phải có cả hai")
	}
	from, err := mail.ParseAddress(s.kv["from"])
	if err != nil {
		return nil, cerr(s.lines["from"], "[email] from: not an e-mail address", "mục [email] from: không phải địa chỉ e-mail")
	}
	e.from = from
	list, err := mail.ParseAddressList(s.kv["to"])
	if err != nil || len(list) == 0 {
		return nil, cerr(s.lines["to"], "[email] to: use addresses separated by commas", "mục [email] to: ghi các địa chỉ cách nhau bởi dấu phẩy")
	}
	e.to = list
	return e, nil
}
