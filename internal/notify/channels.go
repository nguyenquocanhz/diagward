package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/model"
)

// botReply is the answer of the Telegram Bot API and of the Zalo Bot API,
// which follows the same shape: {"ok":true,"result":...} or
// {"ok":false,"error_code":400,"description":"..."}.
type botReply struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
}

// botCheck accepts HTTP 2xx with "ok": true.
func botCheck(r reply) (*SendError, bool) {
	var b botReply
	jsonErr := json.Unmarshal(r.body, &b)
	if r.status >= 200 && r.status < 300 {
		if jsonErr == nil && b.OK {
			return nil, false
		}
		if jsonErr != nil {
			return serr("unexpected answer (not JSON)", "phản hồi lạ (không phải JSON)"), false
		}
		why := short(b.Description)
		if why == "" {
			why = "ok: false"
		}
		return serr("rejected: %s", "bị từ chối: %s", why), false
	}
	return httpCheck(func([]byte) string { return short(b.Description) })(r)
}

// telegram sends with the Bot API's sendMessage, parse_mode HTML.
// https://core.telegram.org/bots/api#sendmessage
type telegram struct {
	name, api, token, chat string
	thread                 int64
}

func (t *telegram) Name() string { return t.name }

func (t *telegram) send(s sendCtx, m *Message) error {
	p := map[string]any{
		"chat_id":              chatID(t.chat),
		"text":                 render(m, telegramDialect),
		"parse_mode":           "HTML",
		"link_preview_options": map[string]bool{"is_disabled": true},
	}
	if t.thread > 0 {
		p["message_thread_id"] = t.thread
	}
	return s.postJSON(t.api+"/bot"+t.token+"/sendMessage", p, nil, botCheck)
}

// chatID sends numeric ids as numbers and "@channel" names as strings.
func chatID(s string) any {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return s
}

// zalo sends with the Zalo Bot Platform's sendMessage (plain text, 1 to
// 2000 characters). https://docs.zaloplatforms.com/docs/BOT/apis/sendMessage
type zalo struct {
	name, api, token, chat string
}

func (z *zalo) Name() string { return z.name }

func (z *zalo) send(s sendCtx, m *Message) error {
	p := map[string]any{"chat_id": z.chat, "text": render(m, zaloDialect)}
	return s.postJSON(z.api+"/bot"+z.token+"/sendMessage", p, nil, botCheck)
}

// slack posts to an incoming webhook: {"text": "..."} in mrkdwn.
// https://api.slack.com/messaging/webhooks
type slack struct{ name, url string }

func (k *slack) Name() string { return k.name }

func (k *slack) send(s sendCtx, m *Message) error {
	text := render(m, slackDialect)
	p := map[string]any{"text": text, "mrkdwn": true, "unfurl_links": false}
	return s.postJSON(k.url, p, nil, httpCheck(nil))
}

// discord posts to a channel webhook; mentions are disabled so a log line
// with "@everyone" cannot ping a whole server.
// https://discord.com/developers/docs/resources/webhook#execute-webhook
type discord struct{ name, url, username string }

func (d *discord) Name() string { return d.name }

func (d *discord) send(s sendCtx, m *Message) error {
	p := map[string]any{
		"content":          render(m, discordDialect),
		"username":         d.username,
		"allowed_mentions": map[string][]string{"parse": {}},
	}
	return s.postJSON(d.url, p, nil, httpCheck(func(b []byte) string {
		var j struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &j) == nil {
			return short(j.Message)
		}
		return ""
	}))
}

// webhook posts Diagward's own JSON payload (see Payload).
type webhook struct {
	name, url, secret string
	headers           [][2]string
	report            bool
}

func (w *webhook) Name() string { return w.name }

// Payload is the JSON body of the generic webhook. Field names are stable.
type Payload struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version,omitempty"`
	Event      Event         `json:"event"`
	Host       string        `json:"host"`
	Vendor     string        `json:"vendor,omitempty"`
	Model      string        `json:"model,omitempty"`
	Serial     string        `json:"serial,omitempty"`
	Verdict    string        `json:"verdict"`
	Headline   string        `json:"headline"`
	Summary    string        `json:"summary"`
	Counts     PayloadCounts `json:"counts"`
	New        []PayloadItem `json:"new"`
	Worsened   []PayloadItem `json:"worsened"`
	Improved   []PayloadItem `json:"improved"`
	Resolved   []PayloadItem `json:"resolved"`
	Current    []PayloadItem `json:"current"`
	NotChecked []string      `json:"notChecked,omitempty"`
	CheckedNow []string      `json:"checkedAgain,omitempty"`
	Incomplete bool          `json:"incomplete,omitempty"`
	Lang       string        `json:"lang"`
	Time       time.Time     `json:"time,omitzero"`
	Text       string        `json:"text"`
	Report     *model.Report `json:"report,omitempty"`
}

// PayloadCounts counts the current findings.
type PayloadCounts struct {
	Crit int `json:"crit"`
	Warn int `json:"warn"`
	Info int `json:"info"`
}

// PayloadItem is one problem.
type PayloadItem struct {
	ID        string `json:"id"`
	Target    string `json:"target,omitempty"`
	Component string `json:"component,omitempty"`
	Severity  string `json:"severity"`
	Previous  string `json:"previous,omitempty"`
	Title     string `json:"title"`
	Action    string `json:"action,omitempty"`
	Part      string `json:"part,omitempty"`
}

// BuildPayload builds the webhook body for m.
func BuildPayload(m *Message, withReport bool) Payload {
	items := func(in []Item) []PayloadItem {
		out := make([]PayloadItem, 0, len(in))
		for _, it := range in {
			p := PayloadItem{ID: it.ID, Target: it.Target, Component: it.Component, Severity: it.Severity.String(),
				Title: it.Title.In(m.Lang), Action: it.Action.In(m.Lang), Part: it.Part}
			if it.Previous != model.OK || it.Severity == model.OK {
				p.Previous = it.Previous.String()
			}
			out = append(out, p)
		}
		return out
	}
	texts := func(in []model.Text) []string {
		var out []string
		for _, t := range in {
			out = append(out, t.In(m.Lang))
		}
		return out
	}
	p := Payload{
		Tool: "diagward", Version: m.Version, Event: m.Event, Host: m.Host,
		Vendor: m.Vendor, Model: m.Model, Serial: m.Serial,
		Verdict: m.Verdict.String(), Headline: m.Headline.In(m.Lang), Summary: m.Subject(),
		Counts: PayloadCounts{Crit: m.Counts.Crit, Warn: m.Counts.Warn, Info: m.Counts.Info},
		New:    items(m.New), Worsened: items(m.Worsened), Improved: items(m.Improved),
		Resolved: items(m.Resolved), Current: items(m.Current),
		NotChecked: texts(m.GapsNew), CheckedNow: texts(m.GapsBack),
		Incomplete: m.Incomplete, Lang: m.Lang, Time: m.Collected, Text: m.Render(),
	}
	if m.Event == EventTest {
		p.Verdict, p.Headline = "", ""
	}
	if withReport {
		p.Report = m.Report
	}
	return p
}

func (w *webhook) send(s sendCtx, m *Message) error {
	body, err := json.Marshal(BuildPayload(m, w.report))
	if err != nil {
		return serr("cannot encode the message", "không mã hóa được tin nhắn")
	}
	hdr := append([][2]string{}, w.headers...)
	if w.secret != "" {
		// Lets the receiver check the sender: hex HMAC-SHA256 of the body.
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		hdr = append(hdr, [2]string{"X-Diagward-Signature", "sha256=" + hex.EncodeToString(mac.Sum(nil))})
	}
	hdr = append(hdr, [2]string{"X-Diagward-Event", string(m.Event)})
	return s.post(w.url, "application/json", body, hdr, httpCheck(func(b []byte) string {
		return short(strings.TrimSpace(string(b)))
	}))
}
