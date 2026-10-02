package collect

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
)

// Collector scripts print each section as
//
//	==DW:<boundary>:BEGIN <name>
//	<stdout>
//	==DW:<boundary>:ERR
//	<stderr>
//	==DW:<boundary>:END rc=<n> ms=<n> [missing=<what>] [skipped=<why>] [timeout] [truncated]
//
// Before a slow step the collector may also print "==DW:<boundary>:RUN
// <name>", which callers use for progress and to spot a hung step.
//
// The script always writes one extra "\n" after stdout and after stderr, so
// the parser strips exactly one trailing newline from each and the content
// round-trips exactly. The boundary is random per run, so command output
// cannot fake a marker by accident.

// NewBoundary returns a random boundary token.
func NewBoundary() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

const maxNoise = 16 << 10

// ParseFramed splits collector output into sections. Output outside any
// section goes to the returned noise (capped). A section cut off by the end
// of the stream (the collector was killed) is kept with RC -1 and Timeout set.
func ParseFramed(out, boundary string) (sections []*Section, noise string) {
	out = strings.ReplaceAll(out, "\r\n", "\n")
	pfx := "==DW:" + boundary + ":"
	var (
		cur     *Section
		inErr   bool
		body    strings.Builder
		errBody strings.Builder
		nb      strings.Builder
	)
	finish := func() {
		cur.Out = strings.TrimSuffix(body.String(), "\n")
		cur.Err = strings.TrimSuffix(errBody.String(), "\n")
		sections = append(sections, cur)
		cur, inErr = nil, false
		body.Reset()
		errBody.Reset()
	}
	rest := out
	for len(rest) > 0 {
		var line string
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			line, rest = rest, ""
		}
		bare := strings.TrimRight(line, "\n")
		if strings.HasPrefix(bare, pfx) {
			marker := bare[len(pfx):]
			switch {
			case strings.HasPrefix(marker, "RUN "):
				// A step started (progress and the stall watchdog); not data.
				continue
			case strings.HasPrefix(marker, "BEGIN "):
				if cur != nil { // unterminated section: keep what we have
					cur.RC, cur.Timeout = -1, true
					finish()
				}
				cur = &Section{Name: strings.TrimSpace(marker[len("BEGIN "):])}
				continue
			case marker == "ERR" && cur != nil:
				inErr = true
				continue
			case strings.HasPrefix(marker, "END") && cur != nil:
				parseEnd(cur, strings.TrimSpace(strings.TrimPrefix(marker, "END")))
				finish()
				continue
			}
		}
		switch {
		case cur == nil:
			if nb.Len() < maxNoise {
				nb.WriteString(line)
			}
		case inErr:
			errBody.WriteString(line)
		default:
			body.WriteString(line)
		}
	}
	if cur != nil {
		cur.RC, cur.Timeout = -1, true
		finish()
	}
	noise = strings.TrimSpace(nb.String())
	if len(noise) > maxNoise {
		noise = noise[:maxNoise]
	}
	return sections, noise
}

func parseEnd(s *Section, attrs string) {
	for _, f := range strings.Fields(attrs) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "rc":
			s.RC, _ = strconv.Atoi(v)
		case "ms":
			s.MS, _ = strconv.Atoi(v)
		case "missing":
			s.Missing = v
		case "skipped":
			s.Skipped = v
		case "timeout":
			s.Timeout = true
		case "truncated":
			s.Truncated = true
		}
	}
	if s.Timeout && s.RC == 0 {
		s.RC = 124
	}
}
