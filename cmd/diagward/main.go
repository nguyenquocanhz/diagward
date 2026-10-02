// Command diagward diagnoses server hardware (disks, RAID, RAM, CPU,
// temperatures, fans, power supplies, BMC, NICs) and explains every problem
// in Vietnamese or English with what to do next.
//
//	sudo diagward                       check this server
//	diagward collect -o srv01.dwb       collect only (send the file to support)
//	diagward analyze srv01.dwb          analyse a saved bundle anywhere
//	diagward bmc 10.0.0.5 --user root   read a server's BMC over the network
//	sudo diagward install-tools         install smartctl, sensors, ipmitool...
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/bmc"
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/internal/install"
	"github.com/nguyenquocanhz/diagward/internal/notify"
	"github.com/nguyenquocanhz/diagward/model"
)

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "dev"

// Exit codes (also printed by "diagward help").
const (
	exitOK    = 0 // no problem found (OK / Info)
	exitWarn  = 1 // warnings: plan a fix soon
	exitCrit  = 2 // critical: act today
	exitError = 3 // bad usage, collection failed, file errors
)

func main() {
	diag.Version = version
	collect.CollectorVersion = version
	con, restore := setupConsole()
	a := newApp(con)
	code := a.main(os.Args[1:])
	restore()
	os.Exit(code)
}

// app holds the program's environment, so commands can be tested with fake
// streams, collectors and privileges.
type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	goos           string
	con            consoleState
	lang           string
	// langExplicit: --lang was given (it then beats the notify config).
	langExplicit bool

	isTerm       func(f any) bool
	termWidth    func(f any) int
	privileged   func() bool
	runLocal     func(ctx context.Context, o collect.Options, progress func(string)) (*collect.Bundle, error)
	collectBMC   func(ctx context.Context, o bmc.Options) (*collect.Bundle, error)
	readPassword func() (string, error)
	installSys   install.System
	openBrowser  func(path string) error
	now          func() time.Time
	exeDir       func() string
	consoleCount func() (uint32, error)
	hostname     func() (string, error)
	notifyOpts   notify.Options // retries and TLS for notifications (tests shorten them)

	in *bufio.Reader
}

func newApp(con consoleState) *app {
	return &app{
		stdin:        os.Stdin,
		stdout:       os.Stdout,
		stderr:       os.Stderr,
		getenv:       os.Getenv,
		goos:         runtime.GOOS,
		con:          con,
		isTerm:       isTerminal,
		termWidth:    terminalWidth,
		privileged:   isPrivileged,
		runLocal:     collect.RunLocal,
		collectBMC:   bmc.Collect,
		readPassword: readPasswordStdin,
		installSys:   install.OS{},
		openBrowser:  openInBrowser,
		now:          time.Now,
		exeDir:       exeDir,
		consoleCount: consoleProcessCount,
		hostname:     os.Hostname,
	}
}

// main dispatches the subcommand and returns the exit code.
func (a *app) main(args []string) int {
	a.lang = detectLang(a.getenv, userLocale)
	if l, ok := preScanLang(args); ok {
		if v, err := parseLang(l); err == nil {
			a.lang = v
			a.langExplicit = true
		}
	}
	if len(args) == 0 {
		if a.goos == "windows" && isDoubleClick(a.consoleCount, a.isTerm(a.stdin), a.getenv("DIAGWARD_NO_PAUSE")) {
			return a.doubleClick()
		}
		return a.cmdCheck(nil, false)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "check":
		return a.cmdCheck(rest, false)
	case "collect":
		return a.cmdCollect(rest)
	case "analyze", "analyse":
		return a.cmdAnalyze(rest)
	case "bmc":
		return a.cmdBMC(rest)
	case "install-tools":
		return a.cmdInstall(rest)
	case "notify-test":
		return a.cmdNotifyTest(rest)
	case "version", "--version", "-version":
		a.printVersion()
		return exitOK
	case "help", "-h", "--help", "-help":
		return a.cmdHelp(rest)
	}
	if strings.HasPrefix(cmd, "-") {
		return a.cmdCheck(args, false)
	}
	a.errorf(a.t("unknown command %q", "không có lệnh %q"), cmd)
	fmt.Fprintln(a.stderr, a.t("Run 'diagward help' to see the commands.", "Chạy 'diagward help' để xem các lệnh."))
	return exitError
}

// t picks the English or Vietnamese text.
func (a *app) t(en, vi string) string {
	if a.lang == "vi" {
		return vi
	}
	return en
}

func (a *app) tx(t model.Text) string { return t.In(a.lang) }

func (a *app) errorf(format string, args ...any) {
	fmt.Fprintf(a.stderr, "diagward: "+format+"\n", args...)
}

func (a *app) printVersion() {
	fmt.Fprintf(a.stdout, "diagward %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// exitFor maps the report verdict to the exit code.
func exitFor(s model.Severity) int {
	switch {
	case s >= model.Crit:
		return exitCrit
	case s == model.Warn:
		return exitWarn
	default:
		return exitOK
	}
}

// isDoubleClick reports whether Diagward was started by double-clicking the
// exe in Explorer: Windows then creates a console for this process alone,
// so the console's process list holds just us. From cmd.exe or PowerShell
// the shell is attached too (count >= 2). Stdin must be that console (not a
// pipe), and DIAGWARD_NO_PAUSE turns the behaviour off (e.g. for a
// scheduled task that starts diagward.exe with its own console).
func isDoubleClick(count func() (uint32, error), stdinIsConsole bool, noPause string) bool {
	if noPause != "" || !stdinIsConsole || count == nil {
		return false
	}
	n, err := count()
	return err == nil && n == 1
}
