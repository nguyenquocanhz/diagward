package notify

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/model"
	"github.com/nguyenquocanhz/diagward/report"
)

// dialect is how one channel formats text.
type dialect struct {
	esc       func(string) string // escape raw text
	bold      func(string) string // wrap already-escaped text
	limit     int                 // max length in characters (runes); 0 = none
	actionMax int                 // max characters of one action (raw); 0 = none
	maxItems  int                 // items per section; 0 = the message's Top
}

func identity(s string) string { return s }

var (
	plainDialect = dialect{esc: identity, bold: identity}
	// Telegram: 4096 characters after entity parsing; counting the HTML
	// source is an upper bound. https://core.telegram.org/bots/api#sendmessage
	telegramDialect = dialect{esc: telegramEscape, bold: func(s string) string { return "<b>" + s + "</b>" }, limit: 4000, actionMax: 400}
	// Zalo Bot sendMessage: text of 1 to 2000 characters, sent as plain text.
	// https://docs.zaloplatforms.com/docs/BOT/apis/sendMessage
	zaloDialect = dialect{esc: identity, bold: identity, limit: 1900, actionMax: 250}
	// Discord: message content up to 2000 characters.
	discordDialect = dialect{esc: discordEscape, bold: func(s string) string { return "**" + s + "**" }, limit: 1900, actionMax: 250}
	// Slack: text over 40,000 characters is truncated and 4,000 is the
	// recommended maximum for a readable message.
	slackDialect = dialect{esc: slackEscape, bold: func(s string) string { return "*" + s + "*" }, limit: 3800, actionMax: 400}
	emailDialect = dialect{esc: identity, bold: identity, maxItems: 50}
)

// telegramEscape escapes text for parse_mode=HTML: Telegram requires <, >
// and & to be replaced by entities ("&quot;" is accepted too).
func telegramEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackEscape escapes the three characters Slack's mrkdwn treats as
// control characters (https://api.slack.com/reference/surfaces/formatting).
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// discordEscape backslash-escapes Discord markdown so log lines with *, _
// or ` do not turn into formatting; mentions are disabled by the payload's
// allowed_mentions as well.
func discordEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '_', '~', '`', '|', '>', '<', '#', '[', ']', '(', ')', '@', ':':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// clip shortens raw text to n characters with an ellipsis.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimRight(string(r[:n-1]), " ,.;:") + "…"
}

func mark(s model.Severity) string {
	switch {
	case s >= model.Crit:
		return "✗"
	case s == model.Warn:
		return "⚠"
	case s == model.Info:
		return "i"
	}
	return "✓"
}

// vi picks the Vietnamese or English text.
func (m *Message) t(en, vi string) string {
	if strings.HasPrefix(m.Lang, "vi") {
		return vi
	}
	return en
}

// Subject is a one-line summary (e-mail subject, webhook "summary").
func (m *Message) Subject() string {
	host := m.hostName()
	switch m.Event {
	case EventTest:
		return m.t("[Diagward] Test message from ", "[Diagward] Tin nhắn thử từ ") + host
	case EventProblem:
		n := len(m.New) + len(m.Worsened)
		return fmt.Sprintf("[Diagward] %s: %s (%s)", host, m.Headline.In(m.Lang),
			m.t(plural(n, "new problem", "new problems"), fmt.Sprintf("%d vấn đề mới", n)))
	case EventRecovery:
		n := len(m.Resolved)
		return fmt.Sprintf("[Diagward] %s: %s (%s)", host, m.Headline.In(m.Lang),
			m.t(plural(n, "problem resolved", "problems resolved"), fmt.Sprintf("đã hết %d vấn đề", n)))
	}
	return fmt.Sprintf("[Diagward] %s: %s", host, m.Headline.In(m.Lang))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (m *Message) hostName() string {
	if m.Host == "" {
		return "?"
	}
	return m.Host
}

// block is a section of the message: a heading and its items.
type block struct {
	title string
	items []string // rendered items (at most the message's Top)
	total int      // items behind the block
	more  string   // "… and %d more", with %d
}

// Render renders the message as plain text (e-mail body, webhook "text").
func (m *Message) Render() string { return render(m, emailDialect) }

func render(m *Message, d dialect) string {
	esc, bold := d.esc, d.bold
	top := d.maxItems
	if top == 0 {
		top = m.Top
	}
	if top <= 0 {
		top = 5
	}
	host := esc(clip(m.hostName(), 100))

	var head []string
	var foot []string
	var blocks []block

	if m.Event == EventTest {
		head = append(head,
			bold(esc(m.t("Diagward: test message from ", "Diagward: tin nhắn thử từ "))+host),
			esc(m.t("If you can read this, the channel is ready for Diagward's hardware alerts.", "Nếu bạn đọc được tin này, kênh đã sẵn sàng nhận cảnh báo phần cứng từ Diagward.")))
		foot = append(foot, esc(footer(m)))
		return assemble(head, nil, foot, d.limit)
	}

	head = append(head, bold(esc(headMark(m)+" ")+host+esc(": "+m.Headline.In(m.Lang))))
	var id []string
	if hw := strings.TrimSpace(m.Vendor + " " + m.Model); hw != "" {
		id = append(id, clip(hw, 80))
	}
	if m.Serial != "" {
		id = append(id, "serial "+clip(m.Serial, 40))
	}
	if len(id) > 0 {
		head = append(head, esc(strings.Join(id, " · ")))
	}
	head = append(head, esc(countLine(m)))

	item := func(it Item, withPrev, withAction bool) string {
		sev := report.SeverityText(it.Severity).In(m.Lang)
		if withPrev {
			sev += m.t(" (was ", " (trước: ") + report.SeverityText(it.Previous).In(m.Lang) + ")"
		}
		line := esc(mark(it.Severity)+" "+sev+": ") + esc(clip(it.Title.In(m.Lang), 300))
		if withAction {
			if a := clip(it.Action.In(m.Lang), d.actionMax); a != "" {
				line += "\n   " + esc("→ "+a)
			}
			if it.Part != "" {
				line += "\n   " + esc(m.t("Part: ", "Linh kiện: ")+clip(it.Part, 160))
			}
		}
		return line
	}
	section := func(title string, items []Item, render func(Item) string, more string) {
		if len(items) == 0 {
			return
		}
		b := block{title: bold(esc(fmt.Sprintf("%s (%d):", title, len(items)))), total: len(items), more: more}
		for i, it := range items {
			if i == top {
				break
			}
			b.items = append(b.items, render(it))
		}
		blocks = append(blocks, b)
	}
	moreText := m.t("… and %d more", "… và %d mục khác")

	switch m.Event {
	case EventStatus:
		section(m.t("Current problems", "Vấn đề hiện có"), m.Current, func(it Item) string { return item(it, false, true) }, moreText)
	default:
		section(m.t("New problems", "Vấn đề mới"), m.New, func(it Item) string { return item(it, false, true) }, moreText)
		section(m.t("Worse than before", "Nặng hơn trước"), m.Worsened, func(it Item) string { return item(it, true, true) }, moreText)
	}
	section(m.t("Resolved", "Đã hết lỗi"), m.Resolved, func(it Item) string {
		return esc("✓ " + clip(it.Title.In(m.Lang), 300))
	}, moreText)
	if m.Event != EventStatus {
		section(m.t("Better than before", "Đỡ hơn trước"), m.Improved, func(it Item) string { return item(it, true, false) }, moreText)
	}

	if m.Event == EventStatus && !m.Changed() {
		foot = append(foot, esc(m.t("Nothing changed since the last run.", "Không có gì thay đổi so với lần chạy trước.")))
	}
	if m.Event != EventStatus {
		if rest := len(m.Current) - len(m.New) - len(m.Worsened); rest > 0 {
			foot = append(foot, esc(m.t(
				fmt.Sprintf("%s still open (reported before).", plural(rest, "other problem is", "other problems are")),
				fmt.Sprintf("Còn %d vấn đề khác chưa xử lý (đã báo trước đây).", rest))))
		}
	}
	if len(m.GapsNew) > 0 {
		foot = append(foot, esc(m.t("Could not be checked this time: ", "Lần này không kiểm tra được: ")+names(m.GapsNew, m.Lang)))
	}
	if len(m.GapsBack) > 0 {
		foot = append(foot, esc(m.t("Checked again: ", "Đã kiểm tra lại được: ")+names(m.GapsBack, m.Lang)))
	}
	if m.Incomplete {
		foot = append(foot, esc(m.t("The collection did not finish: the result is partial, and problems not seen this time are not treated as fixed.",
			"Lần thu thập này bị dừng giữa chừng nên kết quả chưa đầy đủ; lỗi nào lần này không thấy cũng chưa được coi là đã hết.")))
	}
	foot = append(foot, esc(footer(m)))

	if d.limit <= 0 {
		var body []string
		for _, b := range blocks {
			body = append(body, blockText(b, len(b.items)))
		}
		return assemble(head, body, foot, 0)
	}
	// Fit the blocks into the limit: whole items only (escaping and tags
	// are never cut), then "… and N more".
	budget := d.limit - runes(strings.Join(head, "\n")) - runes(strings.Join(foot, "\n")) - 4
	var body []string
	for _, b := range blocks {
		n := len(b.items)
		for ; n >= 0; n-- {
			t := blockText(b, n)
			if runes(t)+2 <= budget {
				body = append(body, t)
				budget -= runes(t) + 2
				break
			}
		}
		if n < 0 {
			break // not even the heading fits: stop here
		}
	}
	return assemble(head, body, foot, d.limit)
}

func blockText(b block, n int) string {
	lines := []string{b.title}
	lines = append(lines, b.items[:n]...)
	if b.total > n {
		lines = append(lines, fmt.Sprintf(b.more, b.total-n))
	}
	return strings.Join(lines, "\n")
}

func assemble(head, body, foot []string, limit int) string {
	parts := []string{strings.Join(head, "\n")}
	parts = append(parts, body...)
	parts = append(parts, strings.Join(foot, "\n"))
	s := strings.Join(parts, "\n\n")
	if limit > 0 && runes(s) > limit {
		// Only reachable with absurd host names; cut at a line boundary.
		r := []rune(s)[:limit]
		if i := strings.LastIndex(string(r), "\n"); i > 0 {
			return string(r)[:i]
		}
		return string(r)
	}
	return s
}

func runes(s string) int { return utf8.RuneCountInString(s) }

func countLine(m *Message) string {
	c := m.Counts
	var p []string
	if strings.HasPrefix(m.Lang, "vi") {
		if c.Crit > 0 {
			p = append(p, fmt.Sprintf("%d lỗi nghiêm trọng", c.Crit))
		}
		if c.Warn > 0 {
			p = append(p, fmt.Sprintf("%d cảnh báo", c.Warn))
		}
		if len(p) == 0 {
			return "Không có lỗi hay cảnh báo nào"
		}
		return strings.Join(p, " · ")
	}
	if c.Crit > 0 {
		p = append(p, plural(c.Crit, "critical problem", "critical problems"))
	}
	if c.Warn > 0 {
		p = append(p, plural(c.Warn, "warning", "warnings"))
	}
	if len(p) == 0 {
		return "No problems or warnings"
	}
	return strings.Join(p, " · ")
}

func names(ts []model.Text, lang string) string {
	var out []string
	for i, t := range ts {
		if i == 6 {
			out = append(out, fmt.Sprintf("… (+%d)", len(ts)-6))
			break
		}
		out = append(out, t.In(lang))
	}
	return clip(strings.Join(out, ", "), 400)
}

func footer(m *Message) string {
	s := "Diagward"
	if m.Version != "" {
		s += " " + m.Version
	}
	if !m.Collected.IsZero() {
		s += " · " + m.Collected.Format("2006-01-02 15:04 -07:00")
	}
	return s
}

// headMark is the verdict symbol; a healthy verdict whose headline is not
// the plain "no problems" one (a VM or container, not enough data) gets
// "i" rather than a reassuring tick.
func headMark(m *Message) string {
	if m.Verdict < model.Warn && m.Headline != report.VerdictText(m.Verdict) {
		return "i"
	}
	return mark(m.Verdict)
}
