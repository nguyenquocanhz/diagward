// Package collect gathers raw evidence from a server into a Bundle.
//
// Collection is a shell script (POSIX sh on Linux, PowerShell on Windows)
// assembled from per-domain snippets. The script prints framed sections (see
// frame.go); nothing is analysed on the server. The same script runs locally
// or over SSH, and a Bundle can be saved to a .dwb file and analysed on
// another machine.
package collect

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Target operating systems.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
	OSBMC     = "bmc" // out-of-band: data read from a BMC (Redfish / IPMI over LAN)
)

// BundleFormat is the version of the saved bundle layout.
const BundleFormat = 1

// Limits for reading bundles that come from elsewhere (a customer's .dwb
// file): real bundles are a few MB with a few hundred sections, so these
// leave ample room while keeping a crafted file from exhausting memory.
const (
	MaxBundleBytes = 128 << 20
	MaxSections    = 20000
)

// Section is the captured output of one command or file.
type Section struct {
	Name string `json:"name"`
	RC   int    `json:"rc"`
	MS   int    `json:"ms,omitempty"`
	Out  string `json:"out,omitempty"`
	Err  string `json:"err,omitempty"`
	// Missing names the tool or file that was not present; the command did
	// not run.
	Missing string `json:"missing,omitempty"`
	// Skipped is the reason the collector chose not to run the command
	// ("not-root", "virtual", "disabled", ...).
	Skipped   string `json:"skipped,omitempty"`
	Timeout   bool   `json:"timeout,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Ran reports whether the command actually ran (it may still have failed).
func (s *Section) Ran() bool { return s != nil && s.Missing == "" && s.Skipped == "" }

// OK reports whether the command ran and exited 0.
func (s *Section) OK() bool { return s.Ran() && s.RC == 0 && !s.Timeout }

// Text returns the output, or "" for a nil section.
func (s *Section) Text() string {
	if s == nil {
		return ""
	}
	return s.Out
}

// Lines splits the output into lines without the trailing empty line.
func (s *Section) Lines() []string {
	t := strings.TrimRight(s.Text(), "\n")
	if t == "" {
		return nil
	}
	return strings.Split(t, "\n")
}

// KV parses "key=value" lines (the format of meta sections and sysfs
// dumps). Later keys win.
func (s *Section) KV() map[string]string {
	m := map[string]string{}
	for _, l := range s.Lines() {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// Options control what the collector does. Zero values mean defaults.
type Options struct {
	SinceDays int    `json:"sinceDays"`          // log window in days (default 7)
	BenchDir  string `json:"benchDir,omitempty"` // run a disk write/read test in this directory ("" = off)
	BenchMB   int    `json:"benchMB,omitempty"`  // size of the disk test file (default 256)
	Memtest   string `json:"memtest,omitempty"`  // run memtester with this size, e.g. "512M" ("" = off)
	MaxLines  int    `json:"maxLines"`           // cap for log sections (default 3000)
	Timeout   int    `json:"timeout"`            // per-command timeout in seconds (default 30)
}

// WithDefaults fills in zero values.
func (o Options) WithDefaults() Options {
	if o.SinceDays <= 0 {
		o.SinceDays = 7
	}
	if o.BenchMB <= 0 {
		o.BenchMB = 256
	}
	if o.MaxLines <= 0 {
		o.MaxLines = 3000
	}
	if o.Timeout <= 0 {
		o.Timeout = 30
	}
	return o
}

// Bundle is everything collected from one machine.
type Bundle struct {
	Format   int        `json:"format"`
	Tool     string     `json:"tool"` // "diagward 0.1.0"
	OS       string     `json:"os"`
	Host     string     `json:"host"` // how the target was addressed (hostname, SSH alias, BMC address)
	Started  time.Time  `json:"started"`
	Finished time.Time  `json:"finished"`
	Options  Options    `json:"options"`
	Sections []*Section `json:"sections"`
	// Noise is output that appeared outside any section (warnings printed by
	// the shell, banners). Kept short, for troubleshooting the collector.
	Noise string `json:"noise,omitempty"`

	index map[string]*Section
}

func (b *Bundle) reindex() {
	b.index = make(map[string]*Section, len(b.Sections))
	for _, s := range b.Sections {
		b.index[s.Name] = s // later duplicates win
	}
}

// Get returns the named section, or nil.
func (b *Bundle) Get(name string) *Section {
	if b.index == nil || len(b.index) != len(b.Sections) {
		b.reindex()
	}
	return b.index[name]
}

// Prefix returns every section whose name starts with prefix, sorted by name.
func (b *Bundle) Prefix(prefix string) []*Section {
	var out []*Section
	for _, s := range b.Sections {
		if strings.HasPrefix(s.Name, prefix) {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Add appends a section (used by collectors written in Go, such as BMC).
func (b *Bundle) Add(s *Section) {
	b.Sections = append(b.Sections, s)
	b.index = nil
}

// Write saves the bundle as gzip-compressed JSON (a .dwb file).
func Write(w io.Writer, b *Bundle) error {
	zw := gzip.NewWriter(w)
	enc := json.NewEncoder(zw)
	if err := enc.Encode(b); err != nil {
		zw.Close()
		return err
	}
	return zw.Close()
}

// Read loads a bundle saved by Write. Plain (uncompressed) JSON is accepted
// too.
func Read(r io.Reader) (*Bundle, error) {
	br := newPeekReader(r)
	var src io.Reader = br
	if head, _ := br.peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		src = zr
	}
	lr := &io.LimitedReader{R: src, N: MaxBundleBytes + 1}
	b, err := decodeBundle(json.NewDecoder(lr))
	if err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("bundle is larger than %d MiB uncompressed", MaxBundleBytes>>20)
		}
		return nil, fmt.Errorf("not a Diagward bundle: %w", err)
	}
	if b.Format == 0 || b.Format > BundleFormat {
		return nil, fmt.Errorf("unsupported bundle format %d (this build reads %d)", b.Format, BundleFormat)
	}
	b.reindex()
	return b, nil
}

// decodeBundle decodes a bundle while streaming the sections array, so the
// section limit holds before memory is spent on millions of tiny entries.
func decodeBundle(dec *json.Decoder) (*Bundle, error) {
	if t, err := dec.Token(); err != nil {
		return nil, err
	} else if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	rest := map[string]json.RawMessage{}
	var secs []*Section
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := kt.(string)
		if key != "sections" {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, err
			}
			rest[key] = raw
			continue
		}
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if t == nil {
			continue
		}
		if d, ok := t.(json.Delim); !ok || d != '[' {
			return nil, fmt.Errorf("sections must be an array")
		}
		for dec.More() {
			if len(secs) >= MaxSections {
				return nil, fmt.Errorf("more than %d sections", MaxSections)
			}
			var s Section
			if err := dec.Decode(&s); err != nil {
				return nil, err
			}
			secs = append(secs, &s)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
	}
	head, err := json.Marshal(rest)
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(head, &b); err != nil {
		return nil, err
	}
	b.Sections = secs
	return &b, nil
}

type peekReader struct {
	r   io.Reader
	buf []byte
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) peek(n int) ([]byte, error) {
	for len(p.buf) < n {
		tmp := make([]byte, n-len(p.buf))
		k, err := p.r.Read(tmp)
		p.buf = append(p.buf, tmp[:k]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf[:n], nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}
