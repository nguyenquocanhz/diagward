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
