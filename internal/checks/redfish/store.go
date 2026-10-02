package redfish

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// SectionPrefix is the prefix of the sections the BMC collector writes, one
// per Redfish resource: "redfish.res:<path>".
const SectionPrefix = "redfish.res:"

// store gives access to the stored Redfish resources by @odata.id.
type store struct {
	secs   map[string]*collect.Section
	parsed map[string]map[string]any
	keys   []string // sorted
}

func newStore(b *collect.Bundle) *store {
	s := &store{secs: map[string]*collect.Section{}, parsed: map[string]map[string]any{}}
	for _, sec := range b.Prefix(SectionPrefix) {
		k := normKey(strings.TrimPrefix(sec.Name, SectionPrefix))
		if k == "" {
			continue
		}
		s.secs[k] = sec
	}
	for k := range s.secs {
		s.keys = append(s.keys, k)
	}
	sort.Strings(s.keys)
	return s
}

// normKey normalises an @odata.id the way the collector names sections:
// path only (absolute URLs reduced to their path), no fragment, no
// trailing slash, query kept.
func normKey(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	k := path.Clean(p)
	if u.RawQuery != "" {
		k += "?" + u.RawQuery
	}
	return k
}

// outcome of reading one resource.
type outcome int

const (
	outOK       outcome = iota
	outMissing          // not in the bundle (not collected)
	outNotFound         // 404/405/501: not supported
	outDenied           // 401/403
	outFailed           // transport error, 5xx, bad JSON, too large
)

// get returns the parsed resource, the outcome and a short description of
// a failure.
func (s *store) get(ref string) (map[string]any, outcome, string) {
	k := normKey(ref)
	if k == "" {
		return nil, outMissing, ""
	}
	sec := s.secs[k]
	if sec == nil {
		return nil, outMissing, k
	}
	switch {
	case sec.RC == http.StatusOK && sec.Truncated:
		return nil, outFailed, fmt.Sprintf("%s: %s", k, first(sec.Err, "response too large"))
	case sec.RC == http.StatusOK:
		if o, ok := s.parsed[k]; ok {
			if o == nil {
				return nil, outFailed, k + ": invalid JSON"
			}
			return o, outOK, ""
		}
		var o map[string]any
		if err := json.Unmarshal([]byte(sec.Out), &o); err != nil || o == nil {
			s.parsed[k] = nil
			return nil, outFailed, k + ": invalid JSON"
		}
		s.parsed[k] = o
		return o, outOK, ""
	case sec.RC == http.StatusUnauthorized || sec.RC == http.StatusForbidden:
		return nil, outDenied, fmt.Sprintf("%s: HTTP %d", k, sec.RC)
	case sec.RC == http.StatusNotFound || sec.RC == http.StatusMethodNotAllowed || sec.RC == http.StatusNotImplemented || sec.RC == http.StatusGone:
		return nil, outNotFound, fmt.Sprintf("%s: HTTP %d", k, sec.RC)
	case sec.RC == -1 || sec.Timeout:
		return nil, outFailed, fmt.Sprintf("%s: %s", k, first(oneLine(sec.Err), "no response"))
	default:
		return nil, outFailed, fmt.Sprintf("%s: HTTP %d", k, sec.RC)
	}
}

// withPrefix lists stored keys that start with prefix.
func (s *store) withPrefix(prefix string) []string {
	i := sort.SearchStrings(s.keys, prefix)
	var out []string
	for ; i < len(s.keys) && strings.HasPrefix(s.keys[i], prefix); i++ {
		out = append(out, s.keys[i])
	}
	return out
}

// area tracks what could be read for one coverage entry.
type area struct {
	id, comp string
	name     model.Text
	ok       int
	notFound []string
	denied   []string
	failed   []string
	missing  []string
}

func (a *area) note(o outcome, why string) {
	if a == nil {
		return
	}
	switch o {
	case outOK:
		a.ok++
	case outNotFound:
		a.notFound = append(a.notFound, why)
	case outDenied:
		a.denied = append(a.denied, why)
	case outFailed:
		a.failed = append(a.failed, why)
	case outMissing:
		if why != "" {
			a.missing = append(a.missing, why)
		}
	}
}

// read gets ref and records the outcome in a (a may be nil).
func (s *store) read(a *area, ref string) map[string]any {
	if ref == "" {
		return nil
	}
	o, out, why := s.get(ref)
	if a != nil {
		a.note(out, why)
	}
	return o
}

// members returns the resources of a collection: each member's own
// section when it was read, else the inline (expanded) member. Follows
// Members@odata.nextLink pages that were collected.
func (s *store) members(a *area, coll map[string]any) []map[string]any {
	var out []map[string]any
	seen := map[string]bool{}
	for page := 0; coll != nil && page < 50; page++ {
		ms, _ := coll["Members"].([]any)
		for _, m := range ms {
			mo, _ := m.(map[string]any)
			if mo == nil {
				continue
			}
			id := str(mo, "@odata.id")
			if id != "" {
				if seen[normKey(id)] {
					continue
				}
				seen[normKey(id)] = true
				if o, oc, why := s.get(id); oc == outOK {
					a.note(oc, why)
					out = append(out, o)
					continue
				} else if len(mo) <= 2 {
					a.note(oc, why)
					continue
				}
			}
			if len(mo) > 2 {
				out = append(out, mo)
			}
		}
		next := nextLink(coll)
		if next == "" || seen["next:"+normKey(next)] {
			break
		}
		seen["next:"+normKey(next)] = true
		coll, _, _ = s.get(next)
	}
	return out
}

// --- JSON helpers -----------------------------------------------------

func dig(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

func str(m map[string]any, keys ...string) string {
	switch x := dig(m, keys...).(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// num returns a number, or nil when absent, null or not numeric.
func num(m map[string]any, keys ...string) *float64 {
	switch x := dig(m, keys...).(type) {
	case float64:
		return &x
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
			return &f
		}
	}
	return nil
}

func boolp(m map[string]any, keys ...string) *bool {
	if b, ok := dig(m, keys...).(bool); ok {
		return &b
	}
	return nil
}

func obj(m map[string]any, keys ...string) map[string]any {
	o, _ := dig(m, keys...).(map[string]any)
	return o
}

func objs(m map[string]any, keys ...string) []map[string]any {
	a, _ := dig(m, keys...).([]any)
	var out []map[string]any
	for _, v := range a {
		if o, ok := v.(map[string]any); ok {
			out = append(out, o)
		}
	}
	return out
}

func link(m map[string]any, keys ...string) string { return str(obj(m, keys...), "@odata.id") }

func links(m map[string]any, keys ...string) []string {
	var out []string
	for _, o := range objs(m, keys...) {
		if id := str(o, "@odata.id"); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func nextLink(coll map[string]any) string {
	if n := str(coll, "Members@odata.nextLink"); n != "" {
		return n
	}
	return str(coll, "@odata.nextLink")
}

// Status is the common Redfish Status object.
type Status struct {
	State        string `json:"state,omitempty"`
	Health       string `json:"health,omitempty"`
	HealthRollup string `json:"healthRollup,omitempty"`
}

func statusOf(m map[string]any) Status {
	return Status{State: str(m, "Status", "State"), Health: str(m, "Status", "Health"), HealthRollup: str(m, "Status", "HealthRollup")}
}

// Absent reports an empty slot or bay.
func (s Status) Absent() bool { return strings.EqualFold(s.State, "Absent") }

// Sev maps Health to a severity: Critical → Crit, Warning → Warn, for any
// state except Absent (an empty slot has no health). A Disabled part with
// Critical health is still reported: BMCs disable failed DIMMs and CPUs.
func (s Status) Sev() model.Severity {
	if s.Absent() {
		return model.OK
	}
	return healthSev(s.Health)
}

func healthSev(h string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "critical":
		return model.Crit
	case "warning":
		return model.Warn
	}
	return model.OK
}

// Text shows the status in a table cell.
func (s Status) Text() string {
	switch {
	case s.Absent():
		return "Absent"
	case s.Health != "" && s.State != "" && !strings.EqualFold(s.State, "Enabled"):
		return s.Health + " (" + s.State + ")"
	case s.Health != "":
		return s.Health
	case s.State != "":
		return s.State
	}
	return "-"
}

func first(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func fmtNum(p *float64, unit string) string {
	if p == nil {
		return "-"
	}
	s := strconv.FormatFloat(*p, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	if unit != "" {
		s += " " + unit
	}
	return s
}
