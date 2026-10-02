# report/testdata

All files here are generated previews, not fixtures read by tests:

    go generate ./report        # = go test -run TestWriteSamples -update

They are rendered from `richReport()` in `report_test.go`, a synthetic
report built for this package (all severities, every component, parts,
tables, every coverage state, long Vietnamese text, CJK/emoji, and HTML /
control characters in untrusted fields). The disk, RAID and ECC values in it
are modelled on real tool output (smartctl -a attribute lines, /proc/mdstat
`[2/1] [_U]`), but the report as a whole is invented.

| File | Format |
|---|---|
| `sample.html` | HTML, Vietnamese by default (toggle to English in the page) |
| `sample-ok.html` | HTML of a healthy server, English by default |
| `sample-vi.txt`, `sample-en.txt` | terminal text, width 100 |
| `sample-verbose-en.txt` | terminal text with tables and evidence |
| `sample-ascii-80.txt` | ASCII-only terminal text, width 80 |
| `sample-vi.md` | Markdown for tickets/chat |
| `sample.json` | JSON |

To preview a real machine instead, render the JSON from
`go run ./internal/devtools/dwdev -os linux -analyze > r.json` with
`DIAGWARD_REPORT_JSON=r.json go test -run TestRenderReportFile ./report`
(outputs are written next to `r.json`).

`partialReport()` (tests only, no preview file) adds components that were
only partly checked (`ComponentSummary.Partial`) and coverage entries in the
current contract: `Fix` from `hint.InstallFix` plus a copyable `Cmd`.

## Checking the HTML layout on a phone width

Headless Chrome on Windows clamps `--window-size` to at least 504 px wide
and crops the screenshot, so a 390 px screenshot of the report itself looks
cut off even when the page fits. Load the report in an `<iframe>` of the
wanted width instead (media queries follow the iframe width), served over
`http://127.0.0.1` so the page can read its theme from `localStorage`, and
screenshot the outer page with `--window-size=504,<height>`. The reports were
checked this way at 360, 390 and 1280 px, in light (`dw-theme=light`) and dark
(`dw-theme=dark`) mode, with real reports from a Windows 10 machine and from
WSL Ubuntu 26.04, and printed with `--print-to-pdf` (A4).
