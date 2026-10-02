package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/model"
	"github.com/nguyenquocanhz/diagward/report"
)

// checkOpts is everything "diagward check" was asked to do.
type checkOpts struct {
	out outOpts
	col colOpts
}

func (a *app) parseCheck(args []string) (*checkOpts, error) {
	o := &checkOpts{}
	fs := newFlagSet("check", a)
	addOutFlags(fs, &o.out, true)
	fs.Var(&o.col.since, "since", "")
	fs.StringVar(&o.col.benchDir, "bench", "", "")
	fs.StringVar(&o.col.benchDir, "bench-dir", "", "") // alias used in some coverage texts
	fs.StringVar(&o.col.benchSize, "bench-size", "", "")
	fs.StringVar(&o.col.benchSize, "bench-mb", "", "")
	fs.StringVar(&o.col.memtest, "memtest", "", "")
	fs.IntVar(&o.col.timeout, "timeout", 0, "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return nil, err
	}
	if len(pos) > 0 {
		return nil, unexpectedArg(pos[0])
	}
	return o, o.validate()
}

func (o *checkOpts) validate() error {
	if err := o.out.validate(); err != nil {
		return err
	}
	if o.col.benchSize != "" {
		if _, err := parseBenchSize(o.col.benchSize); err != nil {
			return err
		}
		if o.col.benchDir == "" {
			return ue("--bench-size needs --bench DIR (e.g. --bench /var/tmp --bench-size 1G)",
				"--bench-size cần đi kèm --bench THƯ_MỤC (ví dụ --bench /var/tmp --bench-size 1G)")
		}
	}
	if o.col.memtest != "" {
		v, err := normMemtest(o.col.memtest)
		if err != nil {
			return err
		}
		o.col.memtest = v
	}
	if err := fileArg("--bench", o.col.benchDir); err != nil {
		return err
	}
	return checkTimeout(o.col.timeout)
}

// options converts the flags to collector options.
func (c colOpts) options() collect.Options {
	o := collect.Options{SinceDays: c.since.days, Timeout: c.timeout, Memtest: c.memtest}
	if c.benchDir != "" {
		if abs, err := filepath.Abs(c.benchDir); err == nil {
			o.BenchDir = abs
		} else {
			o.BenchDir = c.benchDir
		}
		if c.benchSize != "" {
			o.BenchMB, _ = parseBenchSize(c.benchSize)
		}
	}
	return o
}

func (a *app) cmdCheck(args []string, doubleClick bool) int {
	o, err := a.parseCheck(args)
	if errors.Is(err, flag.ErrHelp) {
		a.printHelp("check")
		return exitOK
	}
	if err != nil {
		return a.flagError("check", err)
	}
	if doubleClick && o.out.html == "" {
		o.out.html = a.doubleClickHTMLPath()
	}
	diagOut := a.stderr // notes and progress never mix with the report on stdout
	if !a.checkTestFlags(o, diagOut) {
		return exitError
	}
	if !o.out.quiet {
		a.privilegeNote(diagOut)
	}
	b, cerr := a.collectLocal(o.col.options(), o.out.quiet, diagOut)
	if b == nil {
		a.errorf("%v", a.collectErrorText(cerr))
		return exitError
	}
	code := exitOK
	if cerr != nil {
		fmt.Fprintf(diagOut, "%s %s\n", a.t("Warning:", "Cảnh báo:"), a.collectErrorText(cerr))
		fmt.Fprintln(diagOut, a.t("The report below uses what was collected so far.", "Báo cáo dưới đây dựa trên phần dữ liệu đã thu được."))
	}
	var saved string
	if o.out.save != "" {
		if err := saveBundle(o.out.save, b); err != nil {
			a.errorf(a.t("cannot save the bundle: %v", "không lưu được tệp bundle: %v"), err)
			code = exitError
		} else {
			saved = o.out.save
		}
	}
	rep := diag.Analyze(b)
	rc := a.emit(rep, &o.out, saved, cerr != nil || incomplete(b))
	if doubleClick && rc == exitOK && o.out.html != "" && o.out.html != "-" {
		if err := a.openBrowser(o.out.html); err != nil {
			fmt.Fprintf(diagOut, a.t("Open the report yourself: %s\n", "Hãy tự mở báo cáo: %s\n"), o.out.html)
		}
	}
	switch {
	case rc != exitOK:
		return rc
	case code != exitOK || cerr != nil:
		return exitError
	}
	return exitFor(rep.Verdict)
}

// checkTestFlags warns about the opt-in tests and rejects impossible ones.
func (a *app) checkTestFlags(o *checkOpts, w io.Writer) bool {
	c := &o.col
	if c.benchDir != "" {
		if a.goos == "windows" {
			fmt.Fprintln(w, a.t("Note: --bench (disk speed test) is not available on Windows yet; it is ignored.",
				"Lưu ý: --bench (đo tốc độ ổ) chưa hỗ trợ trên Windows nên sẽ bị bỏ qua."))
			c.benchDir, c.benchSize = "", ""
		} else {
			fi, err := os.Stat(c.benchDir)
			if err != nil || !fi.IsDir() {
				a.errorf(a.t("--bench %s: not a directory", "--bench %s: không phải thư mục"), c.benchDir)
				return false
			}
			mb := 256
			if c.benchSize != "" {
				mb, _ = parseBenchSize(c.benchSize)
			}
			if !o.out.quiet {
				fmt.Fprintf(w, a.t("Disk speed test: writes and reads back a %d MiB file in %s (deleted afterwards). It adds disk load; you asked for it with --bench.\n",
					"Đo tốc độ ổ: ghi rồi đọc lại một tệp %d MiB trong %s (xóa ngay sau đó). Ổ sẽ tải nặng trong lúc đo; chỉ chạy vì bạn đã bật --bench.\n"), mb, c.benchDir)
			}
		}
	}
	if c.memtest != "" {
		if a.goos == "windows" {
			fmt.Fprintln(w, a.t("Note: --memtest uses memtester, which does not exist on Windows. Use Windows Memory Diagnostic instead (run mdsched.exe, it tests at the next reboot); Diagward reads its result.",
				"Lưu ý: --memtest dùng memtester, không có trên Windows. Hãy dùng Windows Memory Diagnostic (chạy mdsched.exe, máy sẽ kiểm tra RAM ở lần khởi động lại); Diagward sẽ đọc kết quả đó."))
			c.memtest = ""
		} else if !o.out.quiet {
			fmt.Fprintf(w, a.t("RAM test: memtester will test %s of RAM. It takes several minutes and loads the CPU and memory; run it outside busy hours.\n",
				"Kiểm tra RAM: memtester sẽ test %s RAM. Mất vài phút và làm CPU, RAM tải nặng; nên chạy ngoài giờ cao điểm.\n"), c.memtest)
		}
	}
	return true
}

// privilegeNote tells a non-root user that some checks will be skipped.
func (a *app) privilegeNote(w io.Writer) {
	if a.privileged() {
		return
	}
	if a.goos == "windows" {
		fmt.Fprintln(w, a.t("Note: Diagward is not running as Administrator, so some checks (disk S.M.A.R.T., storage pools, some event logs) will be skipped. For a full check: right-click diagward.exe > Run as administrator, or run it from PowerShell opened as administrator.",
			"Lưu ý: Diagward đang chạy không có quyền Administrator nên một số mục (S.M.A.R.T. ổ cứng, Storage Spaces, một số nhật ký) sẽ bị bỏ qua. Để kiểm tra đầy đủ: chuột phải diagward.exe > Run as administrator, hoặc chạy trong PowerShell mở bằng quyền administrator."))
	} else {
		fmt.Fprintln(w, a.t("Note: Diagward is not running as root, so some checks (disk S.M.A.R.T., RAM slots, IPMI/BMC, RAID controllers) will be skipped. For a full check run: sudo diagward",
			"Lưu ý: Diagward đang chạy không có quyền root nên một số mục (S.M.A.R.T. ổ cứng, khe RAM, IPMI/BMC, card RAID) sẽ bị bỏ qua. Để kiểm tra đầy đủ, chạy: sudo diagward"))
	}
	fmt.Fprintln(w)
}

// collectLocal runs the collector with a progress line and Ctrl+C handling.
func (a *app) collectLocal(o collect.Options, quiet bool, w io.Writer) (*collect.Bundle, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sp := a.newSpinner(w, quiet)
	sp.bench, sp.memtest = o.BenchDir != "", o.Memtest != ""
	sp.Start(model.T("Starting", "Đang khởi động"))
	b, err := a.runLocal(ctx, o, sp.Section)
	sp.Stop()
	return b, err
}

func (a *app) collectErrorText(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.Canceled):
		return a.t("collection interrupted (Ctrl+C).", "đã dừng thu thập (Ctrl+C).")
	case errors.Is(err, collect.ErrUnsupportedOS):
		return a.t(err.Error(), "Diagward chỉ thu thập được trên máy chủ Linux và Windows. Hãy chạy Diagward ngay trên máy chủ; còn \"diagward bmc\" và \"diagward analyze\" chạy được ở mọi nơi.")
	}
	return err.Error()
}

func (a *app) cmdCollect(args []string) int {
	var out string
	var col colOpts
	quiet := false
	fs := newFlagSet("collect", a)
	fs.StringVar(&out, "o", "", "")
	fs.StringVar(&out, "output", "", "")
	fs.Var(&col.since, "since", "")
	fs.IntVar(&col.timeout, "timeout", 0, "")
	fs.BoolVar(&quiet, "q", false, "")
	fs.BoolVar(&quiet, "quiet", false, "")
	pos, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		a.printHelp("collect")
		return exitOK
	}
	if err == nil && len(pos) > 0 {
		if out == "" && strings.HasSuffix(strings.ToLower(pos[0]), ".dwb") && len(pos) == 1 {
			out = pos[0]
		} else {
			err = unexpectedArg(pos[0])
		}
	}
	if err == nil {
		err = checkTimeout(col.timeout)
	}
	if err == nil && strings.HasPrefix(out, "-") {
		err = ue("-o needs a file name, e.g. -o srv01.dwb", "-o cần tên tệp, ví dụ -o srv01.dwb")
	}
	if err == nil && out != "" {
		err = outDirOK("-o", out)
	}
	if err != nil {
		return a.flagError("collect", err)
	}
	if !quiet {
		a.privilegeNote(a.stderr)
	}
	b, cerr := a.collectLocal(col.options(), quiet, a.stderr)
	if b == nil {
		a.errorf("%v", a.collectErrorText(cerr))
		return exitError
	}
	if out == "" {
		out = defaultName(b.Host, b.Finished, ".dwb")
	}
	saveFailed := false
	if err := saveBundle(out, b); err != nil {
		// Do not throw away minutes of collection because the current
		// directory is read-only (non-root in / or /root): fall back to
		// the temp directory.
		a.errorf(a.t("cannot save the bundle: %v", "không lưu được tệp bundle: %v"), err)
		alt := filepath.Join(os.TempDir(), filepath.Base(defaultName(b.Host, b.Finished, ".dwb")))
		if alt == out || saveBundle(alt, b) != nil {
			return exitError
		}
		out = alt
		fmt.Fprintln(a.stderr, a.t("Saved in the temp directory instead.", "Đã lưu vào thư mục tạm thay thế."))
		saveFailed = true
	}
	abs, _ := filepath.Abs(out)
	if abs == "" {
		abs = out
	}
	if cerr != nil {
		fmt.Fprintf(a.stderr, "%s %s\n", a.t("Warning:", "Cảnh báo:"), a.collectErrorText(cerr))
	}
	if quiet {
		fmt.Fprintln(a.stdout, abs)
	} else {
		if incomplete(b) {
			fmt.Fprintf(a.stdout, a.t("Saved (incomplete, collection did not finish): %s (%d sections)\n",
				"Đã lưu (chưa đầy đủ, thu thập chưa xong): %s (%d mục)\n"), abs, len(b.Sections))
		} else {
			fmt.Fprintf(a.stdout, a.t("Saved: %s (%d sections)\n", "Đã lưu: %s (%d mục)\n"), abs, len(b.Sections))
		}
		fmt.Fprintln(a.stdout, a.t("Send this file to your support team. To analyse it on any computer:",
			"Gửi tệp này cho bộ phận hỗ trợ. Để phân tích trên máy bất kỳ:"))
		fmt.Fprintf(a.stdout, "  diagward analyze %s\n", quoteArg(filepath.Base(abs)))
	}
	if cerr != nil || saveFailed {
		return exitError
	}
	return exitOK
}

// outDirOK checks before a long collection that an output file can be
// created where asked (the directory exists), so the run is not wasted.
func outDirOK(flagName, path string) error {
	if path == "" || path == "-" {
		return nil
	}
	dir := filepath.Dir(path)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return ue("%s %s: folder %s does not exist", "%s %s: không có thư mục %s", flagName, path, dir)
	}
	return nil
}

func (a *app) cmdAnalyze(args []string) int {
	var o outOpts
	fs := newFlagSet("analyze", a)
	addOutFlags(fs, &o, false)
	pos, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		a.printHelp("analyze")
		return exitOK
	}
	if err == nil {
		switch {
		case len(pos) == 0:
			err = ue("which bundle? Usage: diagward analyze FILE.dwb", "phân tích tệp nào? Cách dùng: diagward analyze TỆP.dwb")
		case len(pos) > 1:
			err = unexpectedArg(pos[1])
		default:
			err = o.validate()
		}
	}
	if err != nil {
		return a.flagError("analyze", err)
	}
	b, err := loadBundle(pos[0])
	if err != nil {
		a.errorf("%s: %v", pos[0], err)
		return exitError
	}
	rep := diag.Analyze(b)
	inc := incomplete(b)
	if rc := a.emit(rep, &o, "", inc); rc != exitOK {
		return rc
	}
	if inc {
		// Same as "check" after an interrupted collection: the verdict
		// covers only part of the machine.
		return exitError
	}
	return exitFor(rep.Verdict)
}

// emit renders the report: text (or the quiet one-liner) and the requested
// files. It returns exitError when a file could not be written.
func (a *app) emit(rep *model.Report, o *outOpts, saved string, incomplete bool) int {
	textW := a.stdout
	if o.stdoutTaken() {
		textW = a.stderr
	}
	ropts := report.Options{
		Lang:    a.lang,
		Color:   a.useColor(textW, o.noColor),
		ASCII:   o.ascii || !a.con.utf8,
		Width:   a.termWidth(textW),
		Verbose: o.verbose,
		// The footer's "add --html ..." hints are noise when files were
		// asked for: the user already knows the output options.
		NoHints: o.html != "" || o.md != "" || o.json != "" || saved != "",
	}
	if o.quiet {
		fmt.Fprintln(textW, quietLine(rep, a.lang, incomplete))
	} else if err := report.Text(textW, rep, ropts); err != nil {
		a.errorf("%v", err)
	}
	code := exitOK
	type file struct {
		path, kind string
	}
	var written []file
	fileOpts := report.Options{Lang: a.lang, Verbose: o.verbose}
	for _, f := range []struct {
		path, kind string
		render     func(io.Writer) error
	}{
		{o.html, "HTML", func(w io.Writer) error { return report.HTML(w, rep, fileOpts) }},
		{o.md, "Markdown", func(w io.Writer) error { return report.Markdown(w, rep, fileOpts) }},
		{o.json, "JSON", func(w io.Writer) error { return report.JSON(w, rep) }},
	} {
		if f.path == "" {
			continue
		}
		if f.path == "-" {
			if err := f.render(a.stdout); err != nil {
				a.errorf("%s: %v", f.kind, err)
				code = exitError
			}
			continue
		}
		if err := writeFile(f.path, f.render); err != nil {
			a.errorf(a.t("cannot write the %s report: %v", "không ghi được báo cáo %s: %v"), f.kind, err)
			code = exitError
			continue
		}
		written = append(written, file{f.path, f.kind})
	}
	if saved != "" {
		written = append(written, file{saved, a.t("Bundle", "Bundle")})
	}
	if len(written) > 0 && !o.quiet {
		fmt.Fprintln(textW)
		fmt.Fprintln(textW, a.t("Files written:", "Đã ghi các tệp:"))
		for _, f := range written {
			p := f.path
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			fmt.Fprintf(textW, "  %-9s %s\n", f.kind, p)
		}
		if saved != "" {
			fmt.Fprintf(textW, a.t("Analyse the bundle anywhere with: diagward analyze %s\n", "Phân tích bundle ở máy bất kỳ: diagward analyze %s\n"), quoteArg(filepath.Base(saved)))
		}
	}
	return code
}

// useColor: ANSI colours only on a terminal that understands them, and not
// when --no-color, NO_COLOR (https://no-color.org) or TERM=dumb say no.
func (a *app) useColor(w io.Writer, noColor bool) bool {
	if noColor || a.getenv("NO_COLOR") != "" || a.getenv("TERM") == "dumb" || !a.con.vt {
		return false
	}
	return a.isTerm(w)
}

// quietLine is the one-line verdict for cron and monitoring.
func quietLine(rep *model.Report, lang string, incomplete bool) string {
	c := report.CountFindings(rep)
	head := report.Headline(rep).In(lang)
	host := rep.Host.Hostname
	if host == "" {
		host = "-"
	}
	var b strings.Builder
	vi := strings.HasPrefix(lang, "vi")
	if vi {
		fmt.Fprintf(&b, "%s: %s (%d lỗi nghiêm trọng, %d cảnh báo)", host, head, c.Crit, c.Warn)
	} else {
		fmt.Fprintf(&b, "%s: %s (%d critical, %d warnings)", host, head, c.Crit, c.Warn)
	}
	if incomplete {
		if vi {
			b.WriteString(" [thu thập chưa xong, kết quả chưa đầy đủ]")
		} else {
			b.WriteString(" [collection incomplete, partial result]")
		}
	}
	for _, f := range rep.Findings {
		if f.Severity >= model.Warn {
			b.WriteString(": ")
			b.WriteString(strings.Join(strings.Fields(f.Title.In(lang)), " "))
			break
		}
	}
	return b.String()
}

// incomplete reports whether a local collection stopped before its last
// section (Ctrl+C, collector crash). BMC bundles have no meta.done.
func incomplete(b *collect.Bundle) bool {
	return b != nil && b.OS != collect.OSBMC && b.Get("meta.done") == nil
}

func writeFile(path string, render func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(f)
	if err := render(bw); err != nil {
		f.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func saveBundle(path string, b *collect.Bundle) error {
	return writeFile(path, func(w io.Writer) error { return collect.Write(w, b) })
}

func loadBundle(path string) (*collect.Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return collect.Read(f)
}

// defaultName is "diagward-<host>-<yyyymmdd-hhmm><ext>".
func defaultName(host string, t time.Time, ext string) string {
	var hb strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			hb.WriteRune(r)
		default:
			hb.WriteByte('_')
		}
	}
	h := strings.Trim(hb.String(), "._")
	if h == "" {
		h = "host"
	}
	if len(h) > 48 {
		h = h[:48]
	}
	if t.IsZero() {
		t = time.Now()
	}
	return "diagward-" + h + "-" + t.Format("20060102-1504") + ext
}

// quoteArg quotes a file name for a command line shown to the user.
func quoteArg(s string) string {
	if s == "" || strings.ContainsAny(s, " \t'\"$`\\&|;<>()*?!") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
