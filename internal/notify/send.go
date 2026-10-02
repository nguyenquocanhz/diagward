package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// Options controls Send.
type Options struct {
	// Attempts per channel for transient errors (default 3).
	Attempts int
	// Backoff before the second attempt; doubled each time (default 2s).
	Backoff time.Duration
	// MaxWait caps a server's Retry-After (default 30s); a longer wait
	// gives up instead.
	MaxWait time.Duration
	// TLS overrides the TLS settings (tests trust their own CA with it).
	TLS *tls.Config
}

// Result is the outcome for one channel.
type Result struct {
	Channel string
	Err     error // nil on success; already free of secrets
}

// SendError is a channel failure, with the reason in both languages. It
// never contains a secret: tokens and webhook URLs are not part of it, and
// the text is passed through the config's redactor as well.
type SendError struct {
	Channel string
	EN, VI  string
}

func (e *SendError) Error() string { return e.Channel + ": " + e.EN }

// In returns the message in lang.
func (e *SendError) In(lang string) string {
	return e.Channel + ": " + model.T(e.EN, e.VI).In(lang)
}

// sendCtx is what a channel needs to send.
type sendCtx struct {
	ctx    context.Context
	client *http.Client
	o      Options
	c      *Config
	sleep  func(context.Context, time.Duration) error
}

// Send delivers m to every channel in parallel. One failing channel never
// stops the others.
func Send(ctx context.Context, c *Config, m *Message, o Options) []Result {
	if o.Attempts <= 0 {
		o.Attempts = 3
	}
	if o.Backoff <= 0 {
		o.Backoff = 2 * time.Second
	}
	if o.MaxWait <= 0 {
		o.MaxWait = 30 * time.Second
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = o.TLS
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		// A webhook that redirects is misconfigured; following it would
		// send the payload (and headers) somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	sc := sendCtx{ctx: ctx, client: client, o: o, c: c, sleep: sleepCtx}
	res := make([]Result, len(c.Channels))
	var wg sync.WaitGroup
	for i, ch := range c.Channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					res[i] = Result{Channel: ch.Name(), Err: &SendError{Channel: ch.Name(), EN: "internal error", VI: "lỗi nội bộ"}}
				}
			}()
			err := ch.send(sc, m)
			res[i] = Result{Channel: ch.Name(), Err: c.clean(ch.Name(), err)}
		}()
	}
	wg.Wait()
	tr.CloseIdleConnections()
	return res
}

// clean turns any error into a redacted SendError.
func (c *Config) clean(name string, err error) error {
	if err == nil {
		return nil
	}
	var se *SendError
	if !errors.As(err, &se) {
		se = &SendError{EN: err.Error(), VI: err.Error()}
	}
	return &SendError{Channel: name, EN: c.Redact(se.EN), VI: c.Redact(se.VI)}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func serr(en, vi string, args ...any) *SendError {
	return &SendError{EN: fmt.Sprintf(en, args...), VI: fmt.Sprintf(vi, args...)}
}

// reply is an HTTP response as the channels see it.
type reply struct {
	status int
	body   []byte
	header http.Header
}

// checkFunc decides about a response: nil = delivered; otherwise the error
// and whether it is worth retrying.
type checkFunc func(r reply) (err *SendError, retry bool)

// postJSON POSTs a JSON body with retries and backoff. Errors never include
// the URL (it holds the token or is itself the secret).
func (s sendCtx) postJSON(rawURL string, payload any, hdr [][2]string, check checkFunc) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return serr("cannot encode the message", "không mã hóa được tin nhắn")
	}
	return s.post(rawURL, "application/json", body, hdr, check)
}

func (s sendCtx) post(rawURL, ctype string, body []byte, hdr [][2]string, check checkFunc) error {
	host := hostOf(rawURL)
	backoff := s.o.Backoff
	var last *SendError
	for attempt := 1; attempt <= s.o.Attempts; attempt++ {
		if attempt > 1 {
			if err := s.sleep(s.ctx, backoff); err != nil {
				return withAttempts(last, attempt-1)
			}
			backoff *= 2
		}
		req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, rawURL, bytes.NewReader(body))
		if err != nil {
			return serr("bad URL", "URL không hợp lệ")
		}
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("User-Agent", "diagward-notify")
		for _, h := range hdr {
			req.Header.Set(h[0], h[1])
		}
		resp, err := s.client.Do(req)
		if err != nil {
			last = transportErr(host, err)
			if s.ctx.Err() != nil || isCertErr(err) {
				return withAttempts(last, attempt)
			}
			continue
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		r := reply{status: resp.StatusCode, body: rb, header: resp.Header}
		e, retry := check(r)
		if e == nil {
			return nil
		}
		last = e
		if !retry {
			return e
		}
		if wait, ok := retryAfter(r); ok {
			if wait > s.o.MaxWait {
				return withAttempts(serr("%s (the server asks to wait %s)", "%s (máy chủ yêu cầu chờ %s)", e.EN, wait.Round(time.Second)), attempt)
			}
			if wait > backoff {
				backoff = wait
			}
		}
	}
	return withAttempts(last, s.o.Attempts)
}

func withAttempts(e *SendError, n int) *SendError {
	if e == nil {
		return serr("cancelled", "đã hủy")
	}
	if n <= 1 {
		return e
	}
	return &SendError{EN: fmt.Sprintf("%s (after %d attempts)", e.EN, n), VI: fmt.Sprintf("%s (sau %d lần thử)", e.VI, n)}
}

// hostOf returns "https://host" for messages; never the path or query.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "?"
	}
	return u.Host
}

// transportErr describes a network error without the request URL
// (*url.Error prints it in full).
func transportErr(host string, err error) *SendError {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "timeout"):
		return serr("%s did not answer in time", "%s không phản hồi kịp", host)
	case errors.Is(err, context.Canceled):
		return serr("cancelled", "đã hủy")
	case isCertErr(err):
		return serr("%s: TLS certificate not trusted (%s)", "%s: chứng chỉ TLS không tin cậy được (%s)", host, short(msg))
	}
	return serr("cannot reach %s (%s)", "không kết nối được %s (%s)", host, short(msg))
}

func isCertErr(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci)
}

func short(s string) string { return clip(s, 200) }

// retryAfter reads Retry-After (seconds) or a JSON retry_after (Telegram's
// parameters.retry_after, Discord's retry_after in seconds).
func retryAfter(r reply) (time.Duration, bool) {
	if v := r.header.Get("Retry-After"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 {
			return time.Duration(n * float64(time.Second)), true
		}
	}
	var j struct {
		RetryAfter float64 `json:"retry_after"`
		Parameters struct {
			RetryAfter float64 `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(r.body, &j) == nil {
		if j.Parameters.RetryAfter > 0 {
			return time.Duration(j.Parameters.RetryAfter * float64(time.Second)), true
		}
		if j.RetryAfter > 0 {
			return time.Duration(j.RetryAfter * float64(time.Second)), true
		}
	}
	return 0, false
}

// httpCheck is the default response check: 2xx is delivered; 408, 429 and
// 5xx are retried; anything else is final. detail extracts the reason from
// the body.
func httpCheck(detail func([]byte) string) checkFunc {
	return func(r reply) (*SendError, bool) {
		if r.status >= 200 && r.status < 300 {
			return nil, false
		}
		why := ""
		if detail != nil {
			why = detail(r.body)
		}
		if why == "" {
			why = short(strings.TrimSpace(string(r.body)))
		}
		if why == "" {
			why = http.StatusText(r.status)
		}
		retry := r.status == 408 || r.status == 429 || r.status >= 500
		var e *SendError
		switch {
		case r.status >= 300 && r.status < 400:
			e = serr("HTTP %d: the URL redirects elsewhere; check the URL in the config", "HTTP %d: URL chuyển hướng sang nơi khác; kiểm tra lại URL trong tệp cấu hình", r.status)
		case r.status == 401 || r.status == 403:
			e = serr("HTTP %d: rejected, check the token or webhook URL (%s)", "HTTP %d: bị từ chối, kiểm tra lại token hoặc URL webhook (%s)", r.status, why)
		case r.status == 404:
			e = serr("HTTP 404: not found, the token or webhook URL is wrong or was revoked (%s)", "HTTP 404: không tìm thấy, token hoặc URL webhook sai hoặc đã bị thu hồi (%s)", why)
		case r.status == 429:
			e = serr("HTTP 429: too many messages, rate limited (%s)", "HTTP 429: gửi quá nhiều, đang bị giới hạn (%s)", why)
		default:
			e = serr("HTTP %d (%s)", "HTTP %d (%s)", r.status, why)
		}
		return e, retry
	}
}
