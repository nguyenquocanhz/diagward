package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nguyenquocanhz/diagward/model"
)

// spinner draws a one-line progress indicator on a terminal:
//
//	⠹ Đang kiểm tra: Ổ cứng (S.M.A.R.T.) · 23 mục · 12s
//
// It is silent when the stream is not a terminal or in quiet mode.
type spinner struct {
	w       io.Writer
	lang    string
	ascii   bool
	vt      bool
	width   int
	enabled bool

	mu      sync.Mutex
	label   model.Text
	count   int
	bench   bool // --bench given: the disk domain ends with the speed test
	memtest bool // --memtest given: the memory domain ends with memtester
	started time.Time
	lastLen int
	stop    chan struct{}
	done    chan struct{}
}

func (a *app) newSpinner(w io.Writer, quiet bool) *spinner {
	width := a.termWidth(w)
	return &spinner{
		w:       w,
		lang:    a.lang,
		ascii:   !a.con.utf8,
		vt:      a.con.vt,
		width:   width,
		enabled: !quiet && a.isTerm(w),
	}
}

// Start begins drawing with an initial label.
func (s *spinner) Start(label model.Text) {
	s.mu.Lock()
	s.label = label
	s.started = time.Now()
	s.mu.Unlock()
	if !s.enabled {
		return
	}
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go s.loop()
}

// Section is the collector's progress callback.
func (s *spinner) Section(name string) {
	s.mu.Lock()
	s.count++
	s.label = sectionLabel(name)
	switch {
	case s.memtest && strings.HasPrefix(name, "memory."):
		s.label = model.T("Testing RAM with memtester (takes minutes)", "Đang test RAM bằng memtester (mất vài phút)")
	case s.bench && strings.HasPrefix(name, "disk."):
		s.label = model.T("Checking disks and testing disk speed", "Đang kiểm tra ổ cứng và đo tốc độ ổ")
	}
	s.mu.Unlock()
}

// SetLabel changes the label (for steps without sections).
func (s *spinner) SetLabel(t model.Text) {
	s.mu.Lock()
	s.label = t
	s.mu.Unlock()
}

// Stop erases the line.
func (s *spinner) Stop() {
	if !s.enabled || s.stop == nil {
		return
	}
	close(s.stop)
	<-s.done
	s.stop = nil
}

func (s *spinner) loop() {
	defer close(s.done)
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	if s.ascii {
		frames = []string{"|", "/", "-", `\`}
	}
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	for i := 0; ; i++ {
		s.draw(frames[i%len(frames)])
		select {
		case <-s.stop:
			s.clear()
			return
		case <-tick.C:
		}
	}
}

func (s *spinner) draw(frame string) {
	s.mu.Lock()
	label := s.label.In(s.lang)
	n := s.count
	el := time.Since(s.started).Round(time.Second)
	s.mu.Unlock()
	sep := " · "
	if s.ascii {
		sep = " - "
		label = asciiFold(label)
	}
	line := frame + " " + label
	if n > 0 {
		if s.lang == "vi" {
			line += fmt.Sprintf("%s%d mục", sep, n)
		} else {
			line += fmt.Sprintf("%s%d sections", sep, n)
		}
	}
	line += fmt.Sprintf("%s%ds", sep, int(el.Seconds()))
	line = truncRunes(line, s.width-1)
	pad := ""
	if s.vt {
		pad = "\x1b[K"
	} else if l := utf8.RuneCountInString(line); l < s.lastLen {
		pad = strings.Repeat(" ", s.lastLen-l)
	}
	s.lastLen = utf8.RuneCountInString(line)
	fmt.Fprint(s.w, "\r"+line+pad)
}

func (s *spinner) clear() {
	if s.vt {
		fmt.Fprint(s.w, "\r\x1b[K")
		return
	}
	fmt.Fprint(s.w, "\r"+strings.Repeat(" ", s.lastLen)+"\r")
}

func truncRunes(s string, n int) string {
	if n < 10 {
		n = 10
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// asciiFold strips Vietnamese diacritics for consoles that cannot show
// them ("Ổ cứng" -> "O cung").
func asciiFold(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 {
			b.WriteRune(r)
			continue
		}
		if f, ok := viFold[r]; ok {
			b.WriteRune(f)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

var viFold = func() map[rune]rune {
	m := map[rune]rune{'·': '-', '…': '.'}
	groups := map[rune]string{
		'a': "àáảãạăằắẳẵặâầấẩẫậ", 'A': "ÀÁẢÃẠĂẰẮẲẴẶÂẦẤẨẪẬ",
		'e': "èéẻẽẹêềếểễệ", 'E': "ÈÉẺẼẸÊỀẾỂỄỆ",
		'i': "ìíỉĩị", 'I': "ÌÍỈĨỊ",
		'o': "òóỏõọôồốổỗộơờớởỡợ", 'O': "ÒÓỎÕỌÔỒỐỔỖỘƠỜỚỞỠỢ",
		'u': "ùúủũụưừứửữự", 'U': "ÙÚỦŨỤƯỪỨỬỮỰ",
		'y': "ỳýỷỹỵ", 'Y': "ỲÝỶỸỴ",
		'd': "đ", 'D': "Đ",
	}
	for base, rs := range groups {
		for _, r := range rs {
			m[r] = base
		}
	}
	return m
}()

// sectionLabel maps a collector section to a friendly progress label.
// Sections are printed when their command has finished, and the snippets
// run domain by domain, so the domain of the last section is the one being
// checked.
func sectionLabel(name string) model.Text {
	switch {
	case strings.HasPrefix(name, "disk.smart"):
		return model.T("Checking disks: S.M.A.R.T.", "Đang kiểm tra ổ cứng: S.M.A.R.T.")
	case name == "meta.done":
		return model.T("Finishing", "Đang hoàn tất")
	}
	domain, _, _ := strings.Cut(name, ".")
	if t, ok := domainLabels[domain]; ok {
		return t
	}
	return model.T("Checking", "Đang kiểm tra")
}

var domainLabels = map[string]model.Text{
	"meta":       model.T("Identifying the machine", "Đang nhận diện máy"),
	"system":     model.T("Checking system information", "Đang kiểm tra thông tin hệ thống"),
	"cpu":        model.T("Checking the CPU", "Đang kiểm tra CPU"),
	"memory":     model.T("Checking RAM (ECC)", "Đang kiểm tra RAM (ECC)"),
	"disk":       model.T("Checking disks", "Đang kiểm tra ổ cứng"),
	"raid":       model.T("Checking RAID", "Đang kiểm tra RAID"),
	"sensors":    model.T("Checking temperatures and fans", "Đang kiểm tra nhiệt độ, quạt"),
	"ipmi":       model.T("Reading the BMC (IPMI)", "Đang đọc BMC (IPMI)"),
	"network":    model.T("Checking network cards", "Đang kiểm tra card mạng"),
	"filesystem": model.T("Checking filesystems", "Đang kiểm tra phân vùng"),
	"logs":       model.T("Reading system logs", "Đang đọc nhật ký hệ thống"),
}
