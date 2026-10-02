package collect

import (
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Snippets are concatenated in file-name order: 00-common first, 99-end last,
// one file per domain in between (10-system, 30-disk, ...).
//
//go:embed linux/*.sh
var linuxFS embed.FS

//go:embed windows/*.ps1
var windowsFS embed.FS

// CollectorVersion is reported by the scripts in meta.ident.
var CollectorVersion = "dev"

var memtestRe = regexp.MustCompile(`^[0-9]{1,6}[KMG]?$`)

// Script returns the complete collector script for os, with the options
// and boundary baked in.
func Script(os, boundary string, o Options) (string, error) {
	o = o.WithDefaults()
	if o.Memtest != "" && !memtestRe.MatchString(o.Memtest) {
		return "", fmt.Errorf("memtest size %q: use a number with an optional K, M or G suffix", o.Memtest)
	}
	if strings.ContainsAny(o.BenchDir, "\x00\n\r") {
		return "", fmt.Errorf("invalid benchmark directory")
	}
	var (
		fsys fs.FS
		glob string
		head strings.Builder
	)
	switch os {
	case OSLinux:
		fsys, glob = linuxFS, "linux/*.sh"
		head.WriteString("# Diagward collector (generated). Reads nothing back from the caller.\n")
		for _, kv := range [][2]string{
			{"DW_B", boundary},
			{"DW_VERSION", CollectorVersion},
			{"DW_SINCE_DAYS", strconv.Itoa(o.SinceDays)},
			{"DW_BENCH_DIR", o.BenchDir},
			{"DW_BENCH_MB", strconv.Itoa(o.BenchMB)},
			{"DW_MEMTEST", o.Memtest},
			{"DW_MAXLINES", strconv.Itoa(o.MaxLines)},
			{"DW_TIMEOUT", strconv.Itoa(o.Timeout)},
		} {
			fmt.Fprintf(&head, "%s=%s\n", kv[0], shQuote(kv[1]))
		}
	case OSWindows:
		fsys, glob = windowsFS, "windows/*.ps1"
		head.WriteString("# Diagward collector (generated).\n")
		for _, kv := range [][2]string{
			{"DW_B", boundary},
			{"DW_VERSION", CollectorVersion},
			{"DW_SINCE_DAYS", strconv.Itoa(o.SinceDays)},
			{"DW_BENCH_DIR", o.BenchDir},
			{"DW_BENCH_MB", strconv.Itoa(o.BenchMB)},
			{"DW_MEMTEST", o.Memtest},
			{"DW_MAXLINES", strconv.Itoa(o.MaxLines)},
			{"DW_TIMEOUT", strconv.Itoa(o.Timeout)},
		} {
			fmt.Fprintf(&head, "$%s = %s\n", kv[0], psQuote(kv[1]))
		}
	default:
		return "", fmt.Errorf("no collector script for %q", os)
	}
	names, err := fs.Glob(fsys, glob)
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(head.String())
	for _, n := range names {
		data, err := fs.ReadFile(fsys, n)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\n# ---- %s ----\n", n[strings.LastIndexByte(n, '/')+1:])
		b.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// Command returns the program and arguments that run a collector script
// read from standard input.
func Command(os string) (string, []string) {
	switch os {
	case OSWindows:
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", psBootstrap()}
	default:
		return "sh", []string{"-s"}
	}
}

// RemoteCommand is Command as one command line, for SSH. It works whether
// the remote login shell is sh, cmd.exe or PowerShell.
func RemoteCommand(os string) string {
	name, args := Command(os)
	return name + " " + strings.Join(args, " ")
}

// psBootstrap reads the whole script from stdin as UTF-8 and runs it. It is
// passed with -EncodedCommand so no shell on the way can mangle it.
func psBootstrap() string {
	const boot = `$ErrorActionPreference='Continue';` +
		`$in=New-Object System.IO.StreamReader([Console]::OpenStandardInput(),(New-Object System.Text.UTF8Encoding $false));` +
		`$s=$in.ReadToEnd();Invoke-Expression $s`
	u := utf16.Encode([]rune(boot))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// shQuote quotes s for POSIX sh.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// psQuote quotes s as a PowerShell single-quoted string.
func psQuote(s string) string {
	s = strings.NewReplacer("'", "''", "‘", "‘‘", "’", "’’",
		"‚", "‚‚", "‛", "‛‛").Replace(s)
	return "'" + s + "'"
}
