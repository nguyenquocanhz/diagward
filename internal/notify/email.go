package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// email sends a plain-text message over SMTP: STARTTLS (required, port 587
// by default), implicit TLS (port 465), or no TLS to a relay on localhost.
type email struct {
	name       string
	host       string
	port       int
	mode       string // "starttls", "tls" or "none"
	user, pass string
	from       *mail.Address
	to         []*mail.Address
}

func (e *email) Name() string { return e.name }

func (e *email) send(s sendCtx, m *Message) error {
	msg := e.build(m, time.Now())
	backoff := s.o.Backoff
	var last *SendError
	for attempt := 1; attempt <= s.o.Attempts; attempt++ {
		if attempt > 1 {
			if err := s.sleep(s.ctx, backoff); err != nil {
				return withAttempts(last, attempt-1)
			}
			backoff *= 2
		}
		err, retry := e.deliver(s, m, msg)
		if err == nil {
			return nil
		}
		last = err
		if !retry || s.ctx.Err() != nil {
			return withAttempts(err, attempt)
		}
	}
	return withAttempts(last, s.o.Attempts)
}

var heloRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// deliver runs one SMTP session. SMTP 4xx replies and network errors are
// worth retrying; 5xx replies are final.
func (e *email) deliver(s sendCtx, m *Message, msg []byte) (*SendError, bool) {
	timeout := s.c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	addr := net.JoinHostPort(e.host, strconv.Itoa(e.port))
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.o.TLS != nil {
		cfg = s.o.TLS.Clone()
	}
	cfg.ServerName = e.host
	ctx, cancel := context.WithTimeout(s.ctx, 2*timeout)
	defer cancel()
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if e.mode == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		se := transportErr(addr, err)
		return se, !isCertErr(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * timeout))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		return smtpErr("connect", err)
	}
	defer c.Close()
	helo := "localhost"
	if heloRe.MatchString(m.Host) {
		helo = m.Host
	}
	if err := c.Hello(helo); err != nil {
		return smtpErr("EHLO", err)
	}
	if e.mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return serr("%s does not offer STARTTLS; refusing to send without encryption (use tls = tls for port 465)",
				"%s không hỗ trợ STARTTLS; không gửi khi chưa mã hóa (dùng tls = tls cho cổng 465)", addr), false
		}
		if err := c.StartTLS(cfg); err != nil {
			if isCertErr(err) {
				return serr("%s: TLS certificate not trusted (%s)", "%s: chứng chỉ TLS không tin cậy được (%s)", addr, short(err.Error())), false
			}
			return smtpErr("STARTTLS", err)
		}
	}
	if e.user != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return serr("%s does not offer AUTH; remove user/password or use the submission port", "%s không hỗ trợ AUTH; bỏ user/password hoặc dùng cổng submission", addr), false
		}
		if err := c.Auth(smtp.PlainAuth("", e.user, e.pass, e.host)); err != nil {
			se, retry := smtpErr("AUTH", err)
			return serr("login failed: %s", "đăng nhập thất bại: %s", se.EN), retry
		}
	}
	if err := c.Mail(e.from.Address); err != nil {
		return smtpErr("MAIL FROM", err)
	}
	for _, t := range e.to {
		if err := c.Rcpt(t.Address); err != nil {
			return smtpErr("RCPT TO", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpErr("DATA", err)
	}
	if _, err := w.Write(msg); err != nil {
		w.Close()
		return smtpErr("DATA", err)
	}
	if err := w.Close(); err != nil {
		return smtpErr("DATA", err)
	}
	_ = c.Quit()
	return nil, false
}

// smtpErr describes an SMTP failure; the server's reply text is kept (it
// explains the problem and holds no secret of ours; it is redacted anyway).
func smtpErr(step string, err error) (*SendError, bool) {
	var te *textproto.Error
	if errors.As(err, &te) {
		return serr("SMTP %s: %d %s", "SMTP %s: %d %s", step, te.Code, short(te.Msg)), te.Code >= 400 && te.Code < 500
	}
	return serr("SMTP %s: %s", "SMTP %s: %s", step, short(err.Error())), true
}

// build writes the RFC 5322 message: UTF-8 plain text, quoted-printable.
func (e *email) build(m *Message, now time.Time) []byte {
	var b bytes.Buffer
	var to []string
	for _, t := range e.to {
		to = append(to, t.String())
	}
	subject := strings.Join(strings.Fields(m.Subject()), " ")
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := "diagward.local"
	if at := strings.LastIndex(e.from.Address, "@"); at >= 0 {
		domain = e.from.Address[at+1:]
	}
	fmt.Fprintf(&b, "From: %s\r\n", e.from.String())
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	fmt.Fprintf(&b, "X-Diagward-Event: %s\r\n", m.Event)
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(m.Render() + "\n"))
	_ = qp.Close()
	return b.Bytes()
}
