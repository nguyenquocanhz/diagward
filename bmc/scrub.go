package bmc

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

const redacted = "***"

// scrubBundle removes the password, the user name and the session token
// from every stored text. Diagward never writes them itself; this is the
// safety net for a BMC that echoes them (a login audit message, a buggy
// session resource).
func scrubBundle(b *collect.Bundle, user, pass, token string) {
	for _, s := range b.Sections {
		// The user name is scrubbed from response bodies only: it is not a
		// secret, and a short one could match part of an address in Err.
		u := user
		if s.Name == "meta.bmc" {
			u = ""
		}
		s.Out = scrubText(s.Out, u, pass, token)
		s.Err = scrubText(s.Err, "", pass, token)
	}
	b.Noise = scrubText(b.Noise, "", pass, token)
}

// scrubText replaces secrets in s:
//   - the token, wherever it appears;
//   - the password as a JSON string value ("…") when it is at least 4
//     characters, and as a raw substring when it is at least 6 (shorter
//     strings would match Redfish values such as "OK" by coincidence);
//   - the user name as a whole word, when it is at least 3 characters.
func scrubText(s, user, pass, token string) string {
	if s == "" {
		return s
	}
	if token != "" {
		s = strings.ReplaceAll(s, token, redacted)
	}
	if pass != "" {
		if q, err := json.Marshal(pass); err == nil && len(pass) >= 4 {
			s = strings.ReplaceAll(s, string(q), `"`+redacted+`"`)
		}
		if len(pass) >= 6 {
			s = strings.ReplaceAll(s, pass, redacted)
		}
	}
	if len(user) >= 3 {
		s = replaceWord(s, user, redacted)
	}
	return s
}

// replaceWord replaces whole-word occurrences of w (case-sensitive).
func replaceWord(s, w, repl string) string {
	if !strings.Contains(s, w) {
		return s
	}
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(s[i:], w)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		j += i
		end := j + len(w)
		before, _ := utf8.DecodeLastRuneInString(s[:j])
		after, _ := utf8.DecodeRuneInString(s[end:])
		b.WriteString(s[i:j])
		if (j == 0 || !isWord(before)) && (end == len(s) || !isWord(after)) {
			b.WriteString(repl)
		} else {
			b.WriteString(w)
		}
		i = end
	}
	return b.String()
}

func isWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

func scrubError(err error, user, pass string) error {
	if err == nil {
		return nil
	}
	full := Message(err)
	msg := model.T(scrubText(full.EN, "", pass, ""), scrubText(full.VI, "", pass, ""))
	if msg == full && scrubText(err.Error(), "", pass, "") == err.Error() {
		return err // nothing to hide: keep the chain for errors.Is
	}
	// Keep the sentinel and both languages; drop the cause, whose text may
	// hold the secret.
	for _, target := range []error{ErrAuth, ErrNoProtocol, ErrAddress, ErrRedfishUnavailable} {
		if errors.Is(err, target) {
			return &Error{Kind: target, Msg: msg}
		}
	}
	return &Error{Msg: msg}
}

// snmpRe matches the SNMP community line of "ipmitool lan print", a shared
// secret that has no diagnostic value.
var snmpRe = regexp.MustCompile(`(?m)^(SNMP Community String\s*:).*$`)

func redactLan(s string) string { return snmpRe.ReplaceAllString(s, "${1} "+redacted) }
