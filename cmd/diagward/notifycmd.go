package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nguyenquocanhz/diagward/internal/notify"
	"github.com/nguyenquocanhz/diagward/model"
)

// notifyOpts are the notification flags of check (and notify-test).
type notifyOpts struct {
	config string // --notify-config or DIAGWARD_NOTIFY_CONFIG
	state  string // --state
	always bool   // --notify-always
	force  bool   // --force: accept a config readable by others
}

func addNotifyFlags(fs *flag.FlagSet, n *notifyOpts, withState bool) {
	fs.StringVar(&n.config, "notify-config", "", "")
	fs.BoolVar(&n.force, "force", false, "")
	if withState {
		fs.StringVar(&n.state, "state", "", "")
		fs.BoolVar(&n.always, "notify-always", false, "")
	}
}

// validate fills the config path from the environment and rejects flags
// that make no sense without it.
func (n *notifyOpts) validate(getenv func(string) string) error {
	if n.config == "" {
		n.config = getenv("DIAGWARD_NOTIFY_CONFIG")
	}
	for _, f := range []struct{ name, v string }{{"--notify-config", n.config}, {"--state", n.state}} {
		if err := fileArg(f.name, f.v); err != nil {
			return err
		}
	}
	if n.config != "" {
		return nil
	}
	switch {
	case n.state != "":
		return ue("--state is used with --notify-config FILE", "--state chỉ dùng cùng --notify-config TỆP")
	case n.always:
		return ue("--notify-always needs --notify-config FILE", "--notify-always cần đi kèm --notify-config TỆP")
	case n.force:
		return ue("--force is used with --notify-config FILE", "--force chỉ dùng cùng --notify-config TỆP")
	}
	return nil
}

// notifySetup is a loaded notification config, ready after the check.
type notifySetup struct {
	cfg   *notify.Config
	opts  notifyOpts
	lang  string
	state string
}

// loadNotify reads the config before the (long) collection, so a mistake
// shows up at once. It returns nil, true when notifications are off.
func (a *app) loadNotify(n notifyOpts, w io.Writer) (*notifySetup, bool) {
	if n.config == "" {
		return nil, true
	}
	cfg, warns, err := notify.Load(n.config, notify.LoadOptions{GOOS: a.goos, Force: n.force, Getenv: a.getenv})
	if err != nil {
		a.errorf("%s %s", a.t("notification config:", "cấu hình thông báo:"), notify.Text(err, a.lang))
		return nil, false
	}
	for _, t := range warns {
		fmt.Fprintf(w, "%s %s\n", a.t("Warning:", "Cảnh báo:"), a.tx(t))
	}
	s := &notifySetup{cfg: cfg, opts: n, lang: a.lang, state: n.state}
	if cfg.Lang != "" && !a.langExplicit {
		s.lang = cfg.Lang // --lang wins, then the config, then the environment
	}
	return s, true
}

// notifyContext bounds all sending: channels run in parallel, each with
// its own timeout and retries; Ctrl+C or SIGTERM stops it.
func notifyContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Minute)
	return ctx2, func() { cancel(); stop() }
}

// notifyAfterCheck compares the report with the saved state and sends a
// message when something changed (or always, with --notify-always). It
// only prints: the check's exit code never depends on it.
func (a *app) notifyAfterCheck(s *notifySetup, rep *model.Report, incomplete, quiet bool, w io.Writer) {
	path := s.state
	if path == "" {
		path = notify.DefaultStatePath(a.goos, a.privileged(), a.getenv)
	}
	var prev *notify.State
	if path == "" {
		fmt.Fprintf(w, "%s %s\n", a.t("Warning:", "Cảnh báo:"), a.t(
			"no place to keep the notification state (HOME is not set); every run is treated as the first. Use --state FILE.",
			"không có chỗ lưu trạng thái thông báo (chưa đặt HOME) nên mỗi lần chạy đều coi như lần đầu. Hãy dùng --state TỆP."))
	} else {
		p, err := notify.LoadState(path)
		if err != nil {
			fmt.Fprintf(w, "%s %s: %v\n", a.t("Warning: notification state", "Cảnh báo: tệp trạng thái thông báo"), path, a.stateErrText(err))
		}
		prev = p
	}
	msg, next := notify.Diff(rep, prev, notify.DiffOptions{
		Lang: s.lang, Top: s.cfg.Top, MinSev: s.cfg.MinSev, Incomplete: incomplete, Version: version,
	})
	send := msg.Changed() || s.opts.always
	delivered := 0
	if send {
		ctx, cancel := notifyContext()
		res := notify.Send(ctx, s.cfg, msg, a.notifyOpts)
		cancel()
		for _, r := range res {
			if r.Err != nil {
				fmt.Fprintf(w, "%s %s\n", a.t("Warning: notification not sent:", "Cảnh báo: không gửi được thông báo:"), notify.Text(r.Err, a.lang))
				continue
			}
			delivered++
		}
		if !quiet && delivered > 0 {
			fmt.Fprintf(w, a.t("Notification sent to %d of %d channels (%s).\n", "Đã gửi thông báo tới %d/%d kênh (%s).\n"),
				delivered, len(res), a.eventText(msg.Event))
		}
	} else if !quiet {
		if prev == nil {
			fmt.Fprintln(w, a.t("Notifications: first run, no problem to report; the result is saved for the next run.",
				"Thông báo: lần chạy đầu, không có lỗi cần báo; kết quả đã được lưu để so sánh lần sau."))
		} else {
			fmt.Fprintln(w, a.t("Notifications: nothing changed since the last run, nothing sent.",
				"Thông báo: không có thay đổi so với lần trước nên không gửi."))
		}
	}
	if path == "" {
		return
	}
	if send && delivered == 0 {
		// Keep the old state: the change is sent again on the next run
		// instead of being lost.
		if msg.Changed() {
			fmt.Fprintln(w, a.t("The change will be notified again on the next run.", "Thay đổi này sẽ được gửi lại ở lần chạy sau."))
		}
		return
	}
	if err := notify.SaveState(path, next); err != nil {
		fmt.Fprintf(w, "%s %s: %v\n", a.t("Warning: cannot save the notification state", "Cảnh báo: không lưu được tệp trạng thái thông báo"), path, a.stateErrText(err))
		if s.state == "" && !a.privileged() && a.goos != "windows" {
			fmt.Fprintln(w, a.t("Pass --state FILE with a writable path.", "Hãy dùng --state TỆP với đường dẫn ghi được."))
		}
	}
}

func (a *app) stateErrText(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return a.t("permission denied", "không có quyền")
	}
	return err.Error()
}

func (a *app) eventText(e notify.Event) string {
	switch e {
	case notify.EventProblem:
		return a.t("new problems", "có lỗi mới")
	case notify.EventRecovery:
		return a.t("problems resolved", "lỗi đã hết")
	case notify.EventTest:
		return a.t("test", "thử")
	}
	return a.t("current status", "tình trạng hiện tại")
}

// cmdNotifyTest sends a test message to every configured channel.
func (a *app) cmdNotifyTest(args []string) int {
	var n notifyOpts
	fs := newFlagSet("notify-test", a)
	addNotifyFlags(fs, &n, false)
	pos, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		a.printHelp("notify-test")
		return exitOK
	}
	if err == nil && len(pos) > 0 {
		err = unexpectedArg(pos[0])
	}
	if err == nil {
		err = n.validate(a.getenv)
	}
	if err == nil && n.config == "" {
		err = ue("which config? Usage: diagward notify-test --notify-config FILE", "dùng tệp cấu hình nào? Cách dùng: diagward notify-test --notify-config TỆP")
	}
	if err != nil {
		return a.flagError("notify-test", err)
	}
	s, ok := a.loadNotify(n, a.stderr)
	if !ok {
		return exitError
	}
	host := "?"
	if a.hostname != nil {
		if h, err := a.hostname(); err == nil && h != "" {
			host = h
		}
	}
	msg := notify.TestMessage(host, s.lang, version, a.now())
	ctx, cancel := notifyContext()
	res := notify.Send(ctx, s.cfg, msg, a.notifyOpts)
	cancel()
	failed := 0
	fmt.Fprintf(a.stdout, a.t("Test message from %s:\n", "Tin nhắn thử từ %s:\n"), host)
	for _, r := range res {
		if r.Err != nil {
			failed++
			fmt.Fprintf(a.stdout, "  %s %s\n", a.mark(false), notify.Text(r.Err, a.lang))
			continue
		}
		fmt.Fprintf(a.stdout, "  %s %s: %s\n", a.mark(true), r.Channel, a.t("sent", "đã gửi"))
	}
	if failed > 0 {
		return exitError
	}
	return exitOK
}

func (a *app) mark(ok bool) string {
	switch {
	case ok && a.con.utf8:
		return "✓"
	case ok:
		return "OK"
	case a.con.utf8:
		return "✗"
	}
	return "FAIL"
}
