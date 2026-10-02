package bmc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/model"
)

// Every error Collect returns can be shown in Vietnamese (bmc.Message), and
// the English text stays the error string the CLI showed before.
func TestErrorMessagesBilingual(t *testing.T) {
	// Address errors.
	for _, in := range []string{"", "bmc .lan", "ftp://10.0.0.5", "10.0.0.5:99999", "https://bmc/some/path", "root@10.0.0.5"} {
		_, err := Collect(context.Background(), Options{Host: in, Protocol: "redfish"})
		m := Message(err)
		if !errors.Is(err, ErrAddress) || m.EN != err.Error() || !strings.HasPrefix(m.EN, "invalid BMC address: ") ||
			!strings.HasPrefix(m.VI, "địa chỉ BMC không hợp lệ: ") || !utf8.ValidString(m.VI) {
			t.Errorf("%q: %v / %q", in, err, m.VI)
		}
	}
	_, err := Collect(context.Background(), Options{Host: "10.0.0.5", Protocol: "snmp"})
	if m := Message(err); !strings.Contains(m.EN, `unknown BMC protocol "snmp"`) || !strings.Contains(m.VI, "giao thức BMC") {
		t.Errorf("protocol: %q / %q", m.EN, m.VI)
	}

	// Redfish: no credentials, rejected credentials, 403 lockout.
	f := newFake(t, "localstorage")
	o := f.opts()
	o.User, o.Password = "", ""
	_, err = Collect(context.Background(), o)
	if m := Message(err); !errors.Is(err, ErrAuth) || m.EN != "the BMC rejected the user name or password: the BMC requires a user name and password" ||
		m.VI != "BMC từ chối tài khoản hoặc mật khẩu: BMC yêu cầu tài khoản và mật khẩu" {
		t.Errorf("no credentials: %q / %q", m.EN, m.VI)
	}
	o = f.opts()
	o.Password = "wrong-password-123"
	_, err = Collect(context.Background(), o)
	if m := Message(err); !errors.Is(err, ErrAuth) || !strings.HasPrefix(m.VI, "BMC từ chối tài khoản hoặc mật khẩu") || strings.Contains(m.VI, o.Password) {
		t.Errorf("rejected: %q / %q", m.EN, m.VI)
	}

	// Redfish not offered; auto without ipmitool.
	g := newFake(t, "localstorage")
	delete(g.mock, "/redfish/v1")
	o = g.opts()
	_, err = Collect(context.Background(), o)
	if m := Message(err); !errors.Is(err, ErrRedfishUnavailable) || !strings.HasPrefix(m.VI, "Không dùng được Redfish: ") || m.EN != err.Error() {
		t.Errorf("unavailable: %q / %q", m.EN, m.VI)
	}
	oldLook := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { lookPath = oldLook })
	o.Protocol = "auto"
	_, err = Collect(context.Background(), o)
	if m := Message(err); !errors.Is(err, ErrNoProtocol) || !strings.Contains(m.VI, "chưa cài ipmitool") || !strings.Contains(m.EN, "ipmitool is not installed") {
		t.Errorf("auto: %q / %q", m.EN, m.VI)
	}
}

func TestMessageFallbacks(t *testing.T) {
	if m := Message(nil); !m.IsZero() {
		t.Errorf("nil: %+v", m)
	}
	if m := Message(context.Canceled); m.VI != "đã hủy" {
		t.Errorf("cancel: %+v", m)
	}
	if m := Message(fmt.Errorf("wrapped: %w", &TLSError{Host: "10.0.0.5", Err: errors.New("x509: unknown authority")})); !strings.Contains(m.VI, "--insecure") || !strings.Contains(m.EN, "--insecure") {
		t.Errorf("tls: %+v", m)
	}
	if m := Message(errors.New("connection refused")); m.EN != "connection refused" || m.VI != "connection refused" {
		t.Errorf("plain: %+v", m)
	}
}

// A password echoed in an error is removed from both languages, and the
// sentinel survives.
func TestScrubErrorBilingual(t *testing.T) {
	err := kindErr(ErrNoProtocol, ": ", model.T("failed with Very-Long-Secret", "lỗi với Very-Long-Secret"))
	got := scrubError(err, "admin", "Very-Long-Secret")
	m := Message(got)
	if !errors.Is(got, ErrNoProtocol) || strings.Contains(m.EN+m.VI, "Very-Long-Secret") || !strings.Contains(m.VI, "lỗi với ***") {
		t.Errorf("scrubbed: %v / %q", got, m.VI)
	}
	if e := scrubError(errors.New("plain"), "u", "Very-Long-Secret"); e.Error() != "plain" {
		t.Errorf("untouched error changed: %v", e)
	}
}
