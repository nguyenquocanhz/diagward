package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// detectLang picks the language when --lang is not given: DIAGWARD_LANG,
// then LC_ALL / LC_MESSAGES / LANG starting with "vi", then (on Windows)
// the user's default locale, else English.
func detectLang(getenv func(string) string, locale func() string) string {
	if v, err := parseLang(getenv("DIAGWARD_LANG")); err == nil {
		return v
	}
	// POSIX precedence: the first of LC_ALL, LC_MESSAGES, LANG that is set
	// decides (LC_ALL=C in a cron job means English even with LANG=vi_VN).
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(strings.TrimSpace(getenv(k)))
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "vi") {
			return "vi"
		}
		break
	}
	if locale != nil && strings.HasPrefix(strings.ToLower(locale()), "vi") {
		return "vi"
	}
	return "en"
}

// parseLang accepts vi / en (and vi-VN, vi_VN.UTF-8, en-US, english...).
func parseLang(s string) (string, error) {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(l, "vi"):
		return "vi", nil
	case strings.HasPrefix(l, "en"):
		return "en", nil
	}
	return "", ue("language %q: use vi or en", "ngôn ngữ %q: dùng vi hoặc en", s)
}

// preScanLang finds --lang before the flags are parsed, so usage errors and
// help come out in the right language.
func preScanLang(args []string) (string, bool) {
	for i, a := range args {
		if a == "--" {
			break
		}
		for _, p := range []string{"--lang", "-lang"} {
			if a == p && i+1 < len(args) {
				return args[i+1], true
			}
			if strings.HasPrefix(a, p+"=") {
				return a[len(p)+1:], true
			}
		}
	}
	return "", false
}

// parseSince parses the log window: "7", "7d" or "30D" days, 1..3650.
func parseSince(s string) (int, error) {
	v := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(s), "d"), "D")
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 3650 {
		return 0, ue("--since %q: use a number of days from 1 to 3650, e.g. 7 or 30d",
			"--since %q: nhập số ngày từ 1 đến 3650, ví dụ 7 hoặc 30d", s)
	}
	return n, nil
}

var sizeRe = regexp.MustCompile(`^([0-9]{1,9})\s*([kmgt]?)(i?b)?$`)

// parseSizeMiB parses "256M", "1G", "512" (MiB), "1024k" into MiB.
func parseSizeMiB(s string) (int, error) {
	m := sizeRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, ue("size %q: use a number with an optional K, M or G suffix, e.g. 256M or 1G",
			"dung lượng %q: nhập một số, có thể kèm K, M hoặc G, ví dụ 256M hoặc 1G", s)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	switch m[2] {
	case "k":
		n /= 1024
	case "g":
		n *= 1024
	case "t":
		n *= 1024 * 1024
	}
	return int(min(n, 1<<31-1)), nil
}

// parseBenchSize validates --bench-size. 16 MiB is the smallest test that
// still measures the disk rather than its cache warm-up; 64 GiB keeps a
// typo from filling a volume.
func parseBenchSize(s string) (int, error) {
	n, err := parseSizeMiB(s)
	if err != nil || n < 16 || n > 65536 {
		return 0, ue("--bench-size %q: use 16M to 64G, e.g. 256M or 1G", "--bench-size %q: dùng từ 16M đến 64G, ví dụ 256M hoặc 1G", s)
	}
	return n, nil
}

// normMemtest validates --memtest and returns it in the form the collector
// accepts (digits plus K/M/G, as memtester(8) takes it). memtester needs
// at least 1 MiB; the collector checks it against free RAM.
func normMemtest(s string) (string, error) {
	m := sizeRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil || m[2] == "t" {
		return "", ue("--memtest %q: use a size such as 512M or 2G", "--memtest %q: nhập dung lượng, ví dụ 512M hoặc 2G", s)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	suffix := strings.ToUpper(m[2])
	if suffix == "" {
		suffix = "M" // memtester's default unit is megabytes
	}
	mib := n
	switch suffix {
	case "K":
		mib = n / 1024
	case "G":
		mib = n * 1024
	}
	if mib < 1 || n > 999999 {
		return "", ue("--memtest %q: use a size from 1M to 999G, e.g. 512M or 2G", "--memtest %q: dùng từ 1M đến 999G, ví dụ 512M hoặc 2G", s)
	}
	return strconv.FormatInt(n, 10) + suffix, nil
}

// sinceFlag is --since: days, remembering whether it was given.
type sinceFlag struct {
	days int
	set  bool
}

func (f *sinceFlag) String() string {
	if f == nil || f.days == 0 {
		return ""
	}
	return strconv.Itoa(f.days)
}

func (f *sinceFlag) Set(s string) error {
	n, err := parseSince(s)
	if err != nil {
		return err
	}
	f.days, f.set = n, true
	return nil
}

// langFlag is --lang.
type langFlag struct{ v *string }

func (f langFlag) String() string {
	if f.v == nil {
		return ""
	}
	return *f.v
}

func (f langFlag) Set(s string) error {
	v, err := parseLang(s)
	if err == nil {
		*f.v = v
	}
	return err
}

// outOpts are the flags shared by check, analyze and bmc.
type outOpts struct {
	html, md, json, save string
	verbose, noColor     bool
	ascii, quiet         bool
}

// colOpts are the collection flags of check (and collect).
type colOpts struct {
	since     sinceFlag
	benchDir  string
	benchSize string
	memtest   string
	timeout   int
}

func newFlagSet(name string, a *app) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(langFlag{&a.lang}, "lang", "")
	return fs
}

func addOutFlags(fs *flag.FlagSet, o *outOpts, withSave bool) {
	fs.StringVar(&o.html, "html", "", "")
	fs.StringVar(&o.md, "md", "", "")
	fs.StringVar(&o.md, "markdown", "", "")
	fs.StringVar(&o.json, "json", "", "")
	if withSave {
		fs.StringVar(&o.save, "save", "", "")
	}
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.verbose, "verbose", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.BoolVar(&o.ascii, "ascii", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
}

// validate checks the output flags together.
func (o *outOpts) validate() error {
	n := 0
	for _, v := range []string{o.html, o.md, o.json} {
		if v == "-" {
			n++
		}
	}
	if n > 1 {
		return ue("only one of --html, --md and --json can be \"-\" (standard output)",
			"chỉ một trong --html, --md và --json được là \"-\" (stdout)")
	}
	if o.save == "-" {
		return ue("--save needs a file name, e.g. --save srv01.dwb", "--save cần tên tệp, ví dụ --save srv01.dwb")
	}
	for _, f := range []struct{ name, v string }{{"--html", o.html}, {"--md", o.md}, {"--json", o.json}, {"--save", o.save}} {
		if err := fileArg(f.name, f.v); err != nil {
			return err
		}
		if err := outDirOK(f.name, f.v); err != nil {
			return err
		}
	}
	return nil
}

// stdoutTaken reports whether a report file goes to standard output.
func (o *outOpts) stdoutTaken() bool { return o.html == "-" || o.md == "-" || o.json == "-" }

// parseArgs parses flags that may appear before, between or after the
// positional arguments ("diagward analyze x.dwb --html x.html").
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// uerr is a usage error in both languages; Error() is the English text.
type uerr struct{ en, vi string }

func (e uerr) Error() string { return e.en }

// ue formats a bilingual usage error (same arguments for both texts).
func ue(en, vi string, args ...any) error {
	return uerr{fmt.Sprintf(en, args...), fmt.Sprintf(vi, args...)}
}

// fileArg rejects a missing file name: "--html -v" would otherwise write
// the report to a file called "-v". "-" (standard output) is allowed by
// the caller where it makes sense.
func fileArg(flagName, v string) error {
	if len(v) > 1 && strings.HasPrefix(v, "-") {
		return ue("%s needs a file name (got %q); e.g. %s %s",
			"%s cần tên tệp (đang nhận %q); ví dụ %s %s", flagName, v, flagName, exampleFile(flagName))
	}
	return nil
}

// exampleFile is the file name shown in fileArg's message.
func exampleFile(flagName string) string {
	switch flagName {
	case "--notify-config":
		return "/etc/diagward/notify.conf"
	case "--state":
		return "/var/lib/diagward/state.json"
	case "--bench":
		return "/var/tmp"
	}
	return "report" + fileExt(flagName)
}

func fileExt(flagName string) string {
	switch flagName {
	case "--html":
		return ".html"
	case "--md":
		return ".md"
	case "--json":
		return ".json"
	}
	return ".dwb"
}

// flagValueParsers re-parse a rejected flag value to get its bilingual
// message: the flag package flattens Set errors into English text.
var flagValueParsers = map[string]func(string) error{
	"since": func(s string) error { _, err := parseSince(s); return err },
	"lang":  func(s string) error { _, err := parseLang(s); return err },
}

var invalidValueRe = regexp.MustCompile(`^invalid (?:boolean )?value "(.*)" for flag -([A-Za-z0-9-]+): (.*)$`)

// viFlagMessage translates an error of the flag package (or one of ours).
func viFlagMessage(err error) string {
	var u uerr
	if errors.As(err, &u) {
		return u.vi
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "flag provided but not defined: "):
		return "không có tùy chọn " + strings.TrimPrefix(msg, "flag provided but not defined: ")
	case strings.HasPrefix(msg, "flag needs an argument: "):
		return "tùy chọn " + strings.TrimPrefix(msg, "flag needs an argument: ") + " cần một giá trị"
	}
	if m := invalidValueRe.FindStringSubmatch(msg); m != nil {
		why := m[3]
		if p, ok := flagValueParsers[m[2]]; ok {
			var u uerr
			if errors.As(p(m[1]), &u) {
				why = u.vi
			}
		} else if why == "parse error" || why == "value out of range" {
			why = "cần một số nguyên"
		}
		return fmt.Sprintf("giá trị %q không hợp lệ cho tùy chọn -%s: %s", m[1], m[2], why)
	}
	return msg
}

// flagError prints a usage error (in Vietnamese when asked) and the hint
// to read the help.
func (a *app) flagError(cmd string, err error) int {
	msg := err.Error()
	if a.lang == "vi" {
		msg = viFlagMessage(err)
	}
	a.errorf("%s: %s", cmd, msg)
	fmt.Fprintf(a.stderr, a.t("Run 'diagward help %s' for the options.\n", "Chạy 'diagward help %s' để xem các tùy chọn.\n"), cmd)
	return exitError
}

func unexpectedArg(s string) error {
	return ue("unexpected argument %q", "thừa tham số %q", s)
}

// checkTimeout validates the per-command --timeout (0 = default).
func checkTimeout(n int) error {
	if n != 0 && (n < 5 || n > 3600) {
		return ue("--timeout %d: use 5 to 3600 seconds (per command)", "--timeout %d: dùng từ 5 đến 3600 giây (cho mỗi lệnh)", n)
	}
	return nil
}
