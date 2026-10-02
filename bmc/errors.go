package bmc

import (
	"context"
	"errors"
	"fmt"

	"github.com/nguyenquocanhz/diagward/model"
)

// Error is an error from Collect with its message in English and
// Vietnamese, so a caller can show it in the user's language:
//
//	if err != nil { fmt.Println(bmc.Message(err).In(lang)) }
//
// Error() is the English message. errors.Is(err, ErrAuth) (and the other
// sentinels) works through Kind.
type Error struct {
	Kind error      // ErrAuth, ErrNoProtocol, ErrAddress, ErrRedfishUnavailable or nil
	Msg  model.Text // the full message
	Err  error      // underlying cause, if any (not shown; for errors.As)
}

func (e *Error) Error() string { return e.Msg.EN }

// Unwrap returns the sentinel and the cause.
func (e *Error) Unwrap() []error {
	var out []error
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

// Vietnamese for the sentinels' own messages.
var kindVI = map[error]string{
	ErrAuth:               "BMC từ chối tài khoản hoặc mật khẩu",
	ErrNoProtocol:         "không đọc được BMC qua Redfish hay IPMI",
	ErrAddress:            "địa chỉ BMC không hợp lệ",
	ErrRedfishUnavailable: "địa chỉ này không có dịch vụ Redfish",
}

// kindErr builds an Error whose message starts with the sentinel's text,
// as fmt.Errorf("%w: ...", kind) did: "<kind>: <detail>". sep is ": " or
// " " (for "(HTTP 401)").
func kindErr(kind error, sep string, detail model.Text) *Error {
	en, vi := kind.Error(), kindVI[kind]
	if !detail.IsZero() {
		en += sep + detail.EN
		vi += sep + detail.VI
	}
	return &Error{Kind: kind, Msg: model.T(en, vi)}
}

// addrErr is an ErrAddress with an explanation.
func addrErr(en, vi string, args ...any) *Error {
	return kindErr(ErrAddress, ": ", model.Tf(en, vi, args...))
}

// Message returns the message of an error returned by Collect in English
// and Vietnamese. Errors that carry no translation (a Go network error
// inside a wrapper, say) are returned as is in both languages.
func Message(err error) model.Text {
	if err == nil {
		return model.Text{}
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Msg
	}
	var te *TLSError
	if errors.As(err, &te) {
		return te.Text()
	}
	var un *unavailableError
	if errors.As(err, &un) {
		return un.Text()
	}
	switch {
	case errors.Is(err, context.Canceled):
		return model.T("cancelled", "đã hủy")
	case errors.Is(err, context.DeadlineExceeded):
		return model.T("the time limit was reached", "đã hết thời gian chờ")
	}
	return model.T(err.Error(), err.Error())
}

// Text is the TLS error in both languages.
func (e *TLSError) Text() model.Text {
	return model.T(e.Error(),
		fmt.Sprintf("không xác thực được chứng chỉ TLS của %s (%v). BMC thường dùng chứng chỉ tự ký; nếu tin địa chỉ này, hãy chạy lại với --insecure", e.Host, e.Err))
}

// Text is "Redfish is not available" in both languages.
func (e *unavailableError) Text() model.Text {
	vi := e.VI
	if vi == "" {
		vi = e.Err.Error()
	}
	return model.T(e.Error(), "Không dùng được Redfish: "+vi)
}

// notRedfish is the reason when /redfish/v1/ answered but is no Redfish
// service root.
func notRedfish(rc int, display string) *unavailableError {
	return &unavailableError{
		Err: fmt.Errorf("HTTP %d from %s/redfish/v1/ (not a Redfish service)", rc, display),
		VI:  fmt.Sprintf("%s/redfish/v1/ trả về HTTP %d (không phải dịch vụ Redfish)", display, rc),
	}
}
