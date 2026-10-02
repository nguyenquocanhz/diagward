package main

import (
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
)

// pinTheme makes a copy of the HTML report that ignores the viewer's colour
// scheme: the report's stylesheet honours data-theme on <html> (its theme
// toggle sets the same attribute).
func pinTheme(page, theme string) (string, error) {
	switch theme {
	case "":
		return page, nil
	case "light", "dark":
	default:
		return "", fmt.Errorf("-theme %q: want light or dark", theme)
	}
	if !strings.Contains(page, "<html ") {
		return "", fmt.Errorf("-theme: no <html> tag in the report")
	}
	return strings.Replace(page, "<html ", `<html data-theme="`+theme+`" `, 1), nil
}

var problemStart = regexp.MustCompile(`^\s+(\d+)\. `)

// firstProblems cuts the text report before problem n+1 (n = 0: no cut), so
// a screenshot shows the header, the verdict, the components and the first
// problems.
func firstProblems(text string, n int) string {
	if n <= 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		m := problemStart.FindStringSubmatch(ansiCode.ReplaceAllString(l, ""))
		if m == nil {
			continue
		}
		if k, _ := strconv.Atoi(m[1]); k == n+1 {
			for i > 0 && strings.TrimSpace(ansiCode.ReplaceAllString(lines[i-1], "")) == "" {
				i--
			}
			return strings.Join(lines[:i], "\n") + "\n"
		}
	}
	return text
}

var ansiCode = regexp.MustCompile("\x1b\\[([0-9;]*)m")

// The SGR codes report.Text uses (1 bold, 2 dim, 31/32/33 red/green/yellow)
// in the colours of a GitHub-dark-like terminal.
var sgrStyle = map[string]string{
	"1":  "font-weight:700;color:#f0f3f6",
	"2":  "color:#8b949e",
	"31": "color:#f47067",
	"32": "color:#57d18a",
	"33": "color:#e3b341",
}

// Status symbols that monospace fonts usually lack: the fallback glyphs are
// wider than one cell, so each is pinned to one cell to keep the columns.
var wideSymbol = regexp.MustCompile("[✓✗⚠◐→]")

// terminalPage renders ANSI-coloured text as an HTML page that looks like a
// dark terminal window with cmd typed at the prompt.
func terminalPage(text, cmd string) string {
	var b strings.Builder
	open := 0
	pos := 0
	for _, m := range ansiCode.FindAllStringSubmatchIndex(text, -1) {
		b.WriteString(html.EscapeString(text[pos:m[0]]))
		pos = m[1]
		codes := strings.Split(text[m[2]:m[3]], ";")
		if len(codes) == 1 && (codes[0] == "" || codes[0] == "0") {
			b.WriteString(strings.Repeat("</span>", open))
			open = 0
			continue
		}
		var style []string
		for _, c := range codes {
			if s, ok := sgrStyle[c]; ok {
				style = append(style, s)
			}
		}
		b.WriteString(`<span style="` + strings.Join(style, ";") + `">`)
		open++
	}
	b.WriteString(html.EscapeString(text[pos:]))
	b.WriteString(strings.Repeat("</span>", open))
	body := wideSymbol.ReplaceAllString(b.String(), `<span class="g">$0</span>`)

	prompt := "[root@" + hostname + " ~]#"
	return `<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>` + html.EscapeString(cmd) + `</title>
<style>
html,body{margin:0;background:#0d1117}
.win{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}
.bar{height:34px;background:#21262d;display:flex;align-items:center;gap:8px;padding:0 14px;border-bottom:1px solid #30363d}
.dot{width:12px;height:12px;border-radius:50%}
.title{margin-left:12px;color:#8b949e;font:13px "Segoe UI",system-ui,sans-serif}
pre{margin:0;padding:14px 18px 18px;color:#c9d1d9;font:13.5px/1.42 "Cascadia Mono",Consolas,"DejaVu Sans Mono",Menlo,monospace;white-space:pre}
.prompt{color:#57d18a}
.g{display:inline-block;width:1ch;text-align:center;overflow:visible;font-size:.86em;line-height:1}
</style></head><body><div class="win">
<div class="bar"><span class="dot" style="background:#ff5f56"></span><span class="dot" style="background:#ffbd2e"></span><span class="dot" style="background:#27c93f"></span><span class="title">root@` + hostname + `: ~</span></div>
<pre><span class="prompt">` + html.EscapeString(prompt) + `</span> ` + html.EscapeString(cmd) + "\n" + body + `</pre>
</div></body></html>
`
}
