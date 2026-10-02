package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nguyenquocanhz/diagward/internal/install"
)

func (a *app) cmdInstall(args []string) int {
	var yes, memtester bool
	fs := newFlagSet("install-tools", a)
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	fs.BoolVar(&memtester, "memtester", false, "")
	pos, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		a.printHelp("install-tools")
		return exitOK
	}
	if err == nil && len(pos) > 0 {
		err = unexpectedArg(pos[0])
	}
	if err != nil {
		return a.flagError("install-tools", err)
	}
	switch a.goos {
	case "linux":
	case "windows":
		fmt.Fprintln(a.stdout, a.t("On Windows Diagward does not install anything itself. Install these as needed, then run Diagward again (as Administrator):",
			"Trên Windows, Diagward không tự cài phần mềm. Hãy cài các công cụ sau nếu cần, rồi chạy lại Diagward (bằng quyền Administrator):"))
		for _, t := range install.WindowsAdvice() {
			fmt.Fprintf(a.stdout, "  - %s\n", a.tx(t))
		}
		return exitOK
	default:
		a.errorf(a.t("install-tools works on Linux servers (and prints advice on Windows).", "install-tools chạy trên máy chủ Linux (trên Windows chỉ in hướng dẫn)."))
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sys := a.installSys
	before := install.Detect(ctx, sys, install.Options{Memtester: memtester})
	a.printProbe(before)
	if before.Env.Container {
		fmt.Fprintf(a.stdout, "\n%s\n", a.t("This is a container: the disks, sensors and BMC belong to the host. Install the tools and run Diagward on the host instead.",
			"Đây là container: ổ cứng, cảm biến và BMC thuộc máy host. Hãy cài công cụ và chạy Diagward trên máy host."))
		return exitOK
	}
	if before.Env.Virtual != "" {
		fmt.Fprintf(a.stdout, "\n"+a.t("This is a virtual machine (%s): hardware checks are limited; the host shows the real hardware.\n",
			"Đây là máy ảo (%s): kiểm tra phần cứng bị giới hạn; phần cứng thật nằm ở máy host.\n"), before.Env.Virtual)
	}
	for _, t := range install.VendorAdvice(before) {
		fmt.Fprintf(a.stdout, "%s %s\n", a.t("RAID controller:", "Card RAID:"), a.tx(t))
	}

	plan := install.MakePlan(before)
	interactive := a.isTerm(a.stdin)
	if !plan.Problem.IsZero() {
		fmt.Fprintf(a.stdout, "\n%s\n", a.tx(plan.Problem))
		return exitError
	}
	if plan.Empty() {
		fmt.Fprintf(a.stdout, "\n%s\n", a.t("All the helper tools Diagward needs here are installed.", "Đã có đủ các công cụ Diagward cần trên máy này."))
	} else {
		fmt.Fprintf(a.stdout, "\n%s\n  %s\n", a.t("Install command:", "Lệnh cài đặt:"), plan.Display())
		for _, n := range plan.Notes {
			fmt.Fprintf(a.stdout, "  %s\n", a.tx(n))
		}
		if !before.Env.Root {
			fmt.Fprintf(a.stdout, "\n%s\n  sudo diagward install-tools%s\n", a.t("Installing needs root. Run:", "Cần quyền root để cài. Hãy chạy:"), flagSuffix(memtester))
			return exitError
		}
		if !a.confirm(yes, interactive, a.t("Run it now?", "Chạy lệnh này ngay?")) {
			fmt.Fprintln(a.stdout, a.t("Nothing installed.", "Chưa cài gì."))
			return exitOK
		}
		err := plan.Run(ctx, sys, func(s install.Step, err error) {
			if len(s.Fallback) > 0 {
				fmt.Fprintf(a.stderr, a.t("Warning: %s failed (%v); installing the packages one by one.\n",
					"Cảnh báo: %s lỗi (%v); sẽ cài từng gói một.\n"), s.String(), err)
				return
			}
			fmt.Fprintf(a.stderr, a.t("Warning: %s failed (%v); continuing.\n", "Cảnh báo: %s lỗi (%v); vẫn tiếp tục.\n"), s.String(), err)
		})
		if err != nil {
			a.errorf(a.t("install failed: %v", "cài đặt lỗi: %v"), err)
			return exitError
		}
	}
	after := install.Detect(ctx, sys, install.Options{Memtester: memtester})
	code := exitOK
	if !plan.Empty() {
		var still []string
		for _, t := range after.Missing() {
			still = append(still, t.Name)
		}
		if len(still) > 0 {
			fmt.Fprintf(a.stdout, "\n%s %s\n", a.t("Still missing:", "Vẫn còn thiếu:"), strings.Join(still, ", "))
			if h := install.MissingHint(after, after.Missing()); !h.IsZero() {
				fmt.Fprintf(a.stdout, "  %s\n", a.tx(h))
			}
			code = exitError
		} else {
			fmt.Fprintf(a.stdout, "\n%s\n", a.t("Installed.", "Đã cài xong."))
		}
	}
	for _, f := range install.FollowUps(ctx, sys, before, after) {
		fmt.Fprintf(a.stdout, "\n%s\n  %s\n", a.tx(f.Title), f.Display())
		if !after.Env.Root {
			continue
		}
		if !a.confirm(yes, interactive, a.t("Run it now?", "Chạy lệnh này ngay?")) {
			continue
		}
		if err := (install.Plan{Steps: f.Steps}).Run(ctx, sys, nil); err != nil {
			a.errorf("%v", err)
			code = exitError
			continue
		}
		if !f.Note.IsZero() {
			fmt.Fprintf(a.stdout, "  %s\n", a.tx(f.Note))
		}
	}
	fmt.Fprintf(a.stdout, "\n%s\n  sudo diagward\n", a.t("Now check the server:", "Giờ hãy kiểm tra máy chủ:"))
	return code
}

func flagSuffix(memtester bool) string {
	if memtester {
		return " --memtester"
	}
	return ""
}

func (a *app) printProbe(p install.Probe) {
	distro := p.OSName
	if distro == "" {
		distro = p.Env.Distro
		if p.Env.DistroVer != "" {
			distro += " " + p.Env.DistroVer
		}
	}
	if distro == "" {
		distro = "?"
	}
	pm := p.Env.PM
	if pm == "" {
		pm = "?"
	}
	fmt.Fprintf(a.stdout, "%s %s (%s %s)\n\n", a.t("System:", "Hệ thống:"), distro, a.t("package manager", "trình quản lý gói"), pm)
	ok, miss, skip := "[ok]", "[--]", "[  ]"
	for _, t := range p.Tools {
		mark := skip
		switch {
		case t.Present:
			mark = ok
		case t.Wanted:
			mark = miss
		}
		fmt.Fprintf(a.stdout, "  %s %-11s %-14s %s\n", mark, t.Name, t.Package, a.tx(t.Why))
	}
	fmt.Fprintf(a.stdout, "  %s\n", a.t("[ok] installed  [--] missing  [  ] not needed here", "[ok] đã có  [--] còn thiếu  [  ] không cần trên máy này"))
}

// confirm asks a yes/no question; --yes answers yes, no terminal answers no.
func (a *app) confirm(yes, interactive bool, q string) bool {
	if yes {
		return true
	}
	if !interactive {
		fmt.Fprintln(a.stdout, a.t("(no terminal to ask: rerun with --yes to run it)", "(không có terminal để hỏi: chạy lại với --yes để thực hiện)"))
		return false
	}
	fmt.Fprintf(a.stdout, "%s %s ", q, a.t("[y/N]", "[c/K]"))
	return isYes(a.readLine())
}

// isYes accepts y/yes and the Vietnamese c/có/co.
func isYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "c", "co", "có", "ok", "đồng ý", "dong y":
		return true
	}
	return false
}
