package main

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"testing"
)

type fakeInstallSys struct {
	root  bool
	files map[string]string
	cmds  map[string]bool
	ran   []string
	// installs maps a command line to the commands it makes available.
	installs map[string][]string
}

func (f *fakeInstallSys) LookPath(n string) bool { return f.cmds[n] }
func (f *fakeInstallSys) ReadFile(p string) ([]byte, error) {
	if c, ok := f.files[p]; ok {
		return []byte(c), nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeInstallSys) Glob(pat string) []string {
	var out []string
	for p := range f.files {
		if ok, _ := path.Match(pat, p); ok {
			out = append(out, p)
		}
	}
	return out
}
func (f *fakeInstallSys) Output(_ context.Context, name string, args ...string) (string, error) {
	if name == "systemd-detect-virt" {
		return "none\n", nil
	}
	return "", errors.New("exit status 3")
}
func (f *fakeInstallSys) Run(_ context.Context, _ []string, name string, args ...string) error {
	k := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, k)
	for _, c := range f.installs[k] {
		f.cmds[c] = true
	}
	return nil
}
func (f *fakeInstallSys) Root() bool { return f.root }

func almaSys(root bool) *fakeInstallSys {
	return &fakeInstallSys{
		root: root,
		files: map[string]string{
			"/etc/os-release":                "ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n",
			"/proc/version":                  "Linux version 5.14.0-427.13.1.el9_4.x86_64",
			"/sys/firmware/dmi/entries/38-0": "",
		},
		cmds: map[string]bool{"dnf": true, "systemctl": true, "modprobe": true, "dmidecode": true, "ethtool": true},
		installs: map[string][]string{
			"dnf install -y smartmontools lm_sensors ipmitool nvme-cli rasdaemon": {"smartctl", "sensors", "sensors-detect", "ipmitool", "nvme", "ras-mc-ctl"},
		},
	}
}

func TestInstallToolsYes(t *testing.T) {
	a := newTestApp("linux")
	a.lang = "vi"
	sys := almaSys(true)
	a.installSys = sys
	rc := a.main([]string{"install-tools", "--yes", "--lang", "vi"})
	if rc != exitOK {
		t.Fatalf("rc %d\n%s\n%s", rc, a.out.String(), a.err.String())
	}
	want := []string{
		"dnf install -y smartmontools lm_sensors ipmitool nvme-cli rasdaemon",
		"sensors-detect --auto",
		"modprobe ipmi_devintf ipmi_si",
		"systemctl enable --now smartd rasdaemon",
	}
	if strings.Join(sys.ran, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ran:\n%s", strings.Join(sys.ran, "\n"))
	}
	out := a.out.String()
	for _, s := range []string{"Lệnh cài đặt:", "Đã cài xong.", "modules-load.d", "sudo diagward"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func TestInstallToolsNotRoot(t *testing.T) {
	a := newTestApp("linux")
	sys := almaSys(false)
	a.installSys = sys
	rc := a.main([]string{"install-tools", "--memtester"})
	if rc != exitError || len(sys.ran) != 0 {
		t.Fatalf("rc %d ran %v", rc, sys.ran)
	}
	if !strings.Contains(a.out.String(), "sudo diagward install-tools --memtester") || !strings.Contains(a.out.String(), "epel-release") {
		t.Fatalf("%s", a.out.String())
	}
}

func TestInstallToolsNoTerminalNoYes(t *testing.T) {
	a := newTestApp("linux")
	sys := almaSys(true)
	a.installSys = sys
	if rc := a.main([]string{"install-tools"}); rc != exitOK || len(sys.ran) != 0 {
		t.Fatalf("rc %d ran %v", rc, sys.ran)
	}
	if !strings.Contains(a.out.String(), "--yes") {
		t.Fatalf("%s", a.out.String())
	}
}

func TestInstallToolsAskDeclined(t *testing.T) {
	a := newTestApp("linux")
	sys := almaSys(true)
	a.installSys = sys
	a.isTerm = func(f any) bool { return f == a.stdin }
	a.stdin = strings.NewReader("n\n")
	if rc := a.main([]string{"install-tools"}); rc != exitOK || len(sys.ran) != 0 {
		t.Fatalf("rc %d ran %v", rc, sys.ran)
	}
	a = newTestApp("linux")
	sys = almaSys(true)
	a.installSys = sys
	a.isTerm = func(f any) bool { return f == a.stdin }
	a.stdin = strings.NewReader("y\nn\nn\nn\n")
	a.main([]string{"install-tools"})
	if len(sys.ran) != 1 {
		t.Fatalf("ran %v", sys.ran)
	}
}

func TestInstallToolsContainer(t *testing.T) {
	a := newTestApp("linux")
	sys := almaSys(true)
	sys.files["/proc/version"] = "Linux version 6.6.87.2-microsoft-standard-WSL2"
	a.installSys = sys
	if rc := a.main([]string{"install-tools", "-y"}); rc != exitOK || len(sys.ran) != 0 || !strings.Contains(a.out.String(), "container") {
		t.Fatalf("rc %d ran %v\n%s", rc, sys.ran, a.out.String())
	}
}

func TestInstallToolsWindows(t *testing.T) {
	a := newTestApp("windows")
	if rc := a.main([]string{"install-tools", "--lang", "vi"}); rc != exitOK {
		t.Fatal(rc)
	}
	if !strings.Contains(a.out.String(), "smartmontools.org") || !strings.Contains(a.out.String(), "Trên Windows") {
		t.Fatalf("%s", a.out.String())
	}
	if rc := newTestApp("darwin").main([]string{"install-tools"}); rc != exitError {
		t.Fatal("darwin")
	}
}
