package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fakeSys is a machine described by files, installed commands and command
// outputs.
type fakeSys struct {
	root    bool
	files   map[string]string // path -> content ("" for directories / device nodes)
	cmds    map[string]bool
	outputs map[string]string // "name args..." -> stdout; absent = error
	failRun map[string]bool   // command line -> Run fails
	ran     []string
}

func (f *fakeSys) LookPath(n string) bool { return f.cmds[n] }
func (f *fakeSys) ReadFile(p string) ([]byte, error) {
	if c, ok := f.files[p]; ok {
		return []byte(c), nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeSys) Glob(pat string) []string {
	var out []string
	for p := range f.files {
		if ok, _ := path.Match(pat, p); ok {
			out = append(out, p)
		}
	}
	return out
}
func (f *fakeSys) Output(_ context.Context, name string, args ...string) (string, error) {
	k := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if o, ok := f.outputs[k]; ok {
		return o, nil
	}
	return "", errors.New("exit status 1")
}
func (f *fakeSys) Run(_ context.Context, env []string, name string, args ...string) error {
	k := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, strings.TrimSpace(strings.Join(env, " ")+" "+k))
	if f.failRun[k] {
		return errors.New("exit status 100")
	}
	return nil
}
func (f *fakeSys) Root() bool { return f.root }

// Real /etc/os-release files (from the distributions' release images).
const (
	osAlma9 = `NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
`
	osCentOS7 = `NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
`
	osRHEL9 = `NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
`
	osUbuntu2404 = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
`
	osDebian12 = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
`
	osSLES15 = `NAME="SLES"
VERSION="15-SP5"
VERSION_ID="15.5"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP5"
ID="sles"
ID_LIKE="suse"
`
)

func baseSys(osr string, cmds ...string) *fakeSys {
	f := &fakeSys{
		root:    true,
		files:   map[string]string{"/etc/os-release": osr, "/proc/version": "Linux version 5.14.0-427.13.1.el9_4.x86_64 (mockbuild@x86-64-02.build.eng.rockylinux.org)"},
		cmds:    map[string]bool{"systemctl": true, "modprobe": true},
		outputs: map[string]string{"systemd-detect-virt --container": "none\n", "systemd-detect-virt --vm": "none\n"},
		failRun: map[string]bool{},
	}
	for _, c := range cmds {
		f.cmds[c] = true
	}
	return f
}

func TestAlmaLinuxWithBMCAndMemtester(t *testing.T) {
	f := baseSys(osAlma9, "dnf", "yum", "mdadm", "ethtool", "dmidecode")
	f.files["/sys/firmware/dmi/entries/38-0"] = ""
	f.files["/proc/mdstat"] = "Personalities : [raid1]\nmd0 : active raid1 sdb1[1] sda1[0]\n      1046528 blocks super 1.2 [2/2] [UU]\n\nunused devices: <none>\n"
	p := Detect(context.Background(), f, Options{Memtester: true})
	if p.Env.Distro != "almalinux" || p.Env.PM != "dnf" || p.Env.Virtual != "" || !p.BMC || p.IPMIDev || !p.MD {
		t.Fatalf("probe: %+v", p)
	}
	pl := MakePlan(p)
	want := "dnf install -y epel-release; dnf install -y smartmontools lm_sensors ipmitool nvme-cli rasdaemon memtester"
	if got := pl.Display(); got != want {
		t.Fatalf("plan:\n got %s\nwant %s", got, want)
	}
	if !reflect.DeepEqual(pl.Tools, []string{"smartctl", "sensors", "ipmitool", "nvme", "ras-mc-ctl", "memtester"}) {
		t.Fatalf("tools %v", pl.Tools)
	}
	if err := pl.Run(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.ran) != 2 || f.ran[0] != "dnf install -y epel-release" {
		t.Fatalf("ran %q", f.ran)
	}

	// Without --memtester no EPEL is needed.
	pl = MakePlan(Detect(context.Background(), f, Options{}))
	if strings.Contains(pl.Display(), "epel") || strings.Contains(pl.Display(), "memtester") {
		t.Fatalf("unexpected EPEL: %s", pl.Display())
	}
	// EPEL already configured.
	f.files["/etc/yum.repos.d/epel.repo"] = "[epel]"
	pl = MakePlan(Detect(context.Background(), f, Options{Memtester: true}))
	if strings.Contains(pl.Display(), "epel-release") || !strings.HasSuffix(pl.Display(), "memtester") {
		t.Fatalf("EPEL present: %s", pl.Display())
	}
}

func TestCentOS7Yum(t *testing.T) {
	f := baseSys(osCentOS7, "yum")
	p := Detect(context.Background(), f, Options{Memtester: true})
	pl := MakePlan(p)
	want := "yum install -y epel-release; yum install -y smartmontools lm_sensors nvme-cli dmidecode ethtool rasdaemon memtester"
	if got := pl.Display(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestRHEL9EPELFromURL(t *testing.T) {
	f := baseSys(osRHEL9, "dnf", "yum")
	pl := MakePlan(Detect(context.Background(), f, Options{Memtester: true}))
	if !strings.HasPrefix(pl.Display(), "dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm; dnf install -y ") {
		t.Fatalf("got %s", pl.Display())
	}
	if len(pl.Notes) == 0 || !strings.Contains(pl.Notes[0].VI, "CodeReady") {
		t.Fatalf("notes %+v", pl.Notes)
	}
}

func TestUbuntuApt(t *testing.T) {
	f := baseSys(osUbuntu2404, "apt-get", "smartctl")
	f.files["/dev/ipmi0"] = ""
	f.files["/sys/class/nvme/nvme0"] = ""
	p := Detect(context.Background(), f, Options{Memtester: true})
	if p.Env.PM != "apt" || !p.BMC || !p.IPMIDev || !p.NVMe {
		t.Fatalf("probe %+v", p)
	}
	pl := MakePlan(p)
	want := "apt-get update; apt-get install -y --no-install-recommends lm-sensors ipmitool nvme-cli dmidecode ethtool rasdaemon memtester"
	if got := pl.Display(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// apt-get update failing (broken repository) does not stop the install.
	f.failRun["apt-get update"] = true
	var warned bool
	if err := pl.Run(context.Background(), f, func(Step, error) { warned = true }); err != nil || !warned {
		t.Fatalf("err=%v warned=%v", err, warned)
	}
	if len(f.ran) != 2 || !strings.HasPrefix(f.ran[1], "DEBIAN_FRONTEND=noninteractive apt-get install") {
		t.Fatalf("ran %q", f.ran)
	}
	// One package missing from the repositories (Ubuntu without
	// "universe": "E: Unable to locate package lm-sensors") makes apt-get
	// reject the whole command; the fallback installs the others one by
	// one.
	bulk := "apt-get install -y --no-install-recommends lm-sensors ipmitool nvme-cli dmidecode ethtool rasdaemon memtester"
	f.failRun[bulk] = true
	f.failRun["apt-get install -y --no-install-recommends lm-sensors"] = true
	f.ran = nil
	var failed []string
	if err := pl.Run(context.Background(), f, func(s Step, _ error) { failed = append(failed, s.String()) }); err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if len(f.ran) != 2+7 || f.ran[len(f.ran)-1] != "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends memtester" {
		t.Fatalf("ran %q", f.ran)
	}
	if !reflect.DeepEqual(failed, []string{"apt-get update", bulk, "apt-get install -y --no-install-recommends lm-sensors"}) {
		t.Fatalf("warned %q", failed)
	}
	// Nothing installable at all is an error.
	for _, pkg := range pl.Packages {
		f.failRun["apt-get install -y --no-install-recommends "+pkg] = true
	}
	if err := pl.Run(context.Background(), f, nil); err == nil {
		t.Fatal("want error")
	}
	// Ubuntu's universe packages get a hint when still missing.
	h := MissingHint(p, []Tool{{Name: "sensors", Package: "lm-sensors"}, {Name: "nvme", Package: "nvme-cli"}})
	if !strings.Contains(h.EN, "universe") || !strings.Contains(h.EN, "lm-sensors") || strings.Contains(h.EN, "nvme-cli") || !strings.Contains(h.VI, "add-apt-repository") {
		t.Fatalf("hint %+v", h)
	}
	if h := MissingHint(p, []Tool{{Name: "nvme", Package: "nvme-cli"}}); !h.IsZero() {
		t.Fatalf("hint for a main package: %+v", h)
	}
}

func TestEPELFailureStillInstallsTheRest(t *testing.T) {
	f := baseSys(osAlma9, "dnf")
	pl := MakePlan(Detect(context.Background(), f, Options{Memtester: true}))
	f.failRun["dnf install -y epel-release"] = true
	f.failRun["dnf install -y "+strings.Join(pl.Packages, " ")] = true
	f.failRun["dnf install -y memtester"] = true
	if err := pl.Run(context.Background(), f, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.ran, "dnf install -y smartmontools") || !slices.Contains(f.ran, "dnf install -y rasdaemon") {
		t.Fatalf("ran %q", f.ran)
	}
	if h := MissingHint(Detect(context.Background(), f, Options{Memtester: true}), []Tool{{Name: "memtester", Package: "memtester"}}); !strings.Contains(h.EN, "EPEL") {
		t.Fatalf("hint %+v", h)
	}
}

func TestDebianVM(t *testing.T) {
	f := baseSys(osDebian12, "apt-get")
	f.outputs["systemd-detect-virt --vm"] = "kvm\n"
	p := Detect(context.Background(), f, Options{})
	if p.Env.Virtual != "kvm" || p.Env.Container {
		t.Fatalf("env %+v", p.Env)
	}
	for _, n := range []string{"sensors", "ras-mc-ctl", "ipmitool"} {
		if tl, _ := p.Tool(n); tl.Wanted || tl.Why.VI == "" {
			t.Errorf("%s should not be wanted on a VM: %+v", n, tl)
		}
	}
	pl := MakePlan(p)
	if got := pl.Display(); got != "apt-get update; apt-get install -y --no-install-recommends smartmontools nvme-cli dmidecode ethtool" {
		t.Fatalf("got %s", got)
	}
}

func TestProxmox(t *testing.T) {
	f := baseSys(osDebian12, "apt-get", "smartctl", "pveversion")
	f.files["/etc/pve"] = ""
	p := Detect(context.Background(), f, Options{})
	if p.Env.Distro != "proxmox" || p.Env.PM != "apt" {
		t.Fatalf("env %+v", p.Env)
	}
	if got := MakePlan(p).Display(); got != "apt-get update; apt-get install -y --no-install-recommends lm-sensors nvme-cli dmidecode ethtool rasdaemon" {
		t.Fatalf("got %s", got)
	}
}

func TestSUSE(t *testing.T) {
	f := baseSys(osSLES15, "zypper")
	pl := MakePlan(Detect(context.Background(), f, Options{Memtester: true}))
	if got := pl.Display(); got != "zypper --non-interactive install smartmontools sensors nvme-cli dmidecode ethtool rasdaemon memtester" {
		t.Fatalf("got %s", got)
	}
}

func TestContainerNothing(t *testing.T) {
	f := baseSys(osUbuntu2404, "apt-get")
	f.files["/proc/version"] = "Linux version 6.6.87.2-microsoft-standard-WSL2 (root@439a258ad544) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025"
	f.outputs["systemd-detect-virt --container"] = "wsl\n"
	p := Detect(context.Background(), f, Options{Memtester: true})
	if !p.Env.Container || p.Env.Virtual != "wsl" {
		t.Fatalf("env %+v", p.Env)
	}
	if pl := MakePlan(p); !pl.Empty() || len(p.Missing()) != 0 {
		t.Fatalf("container plan: %s", pl.Display())
	}
	if fu := FollowUps(context.Background(), f, p, p); len(fu) != 0 {
		t.Fatalf("followups in container: %+v", fu)
	}
}

func TestUnknownPM(t *testing.T) {
	f := baseSys("ID=mystery\n")
	pl := MakePlan(Detect(context.Background(), f, Options{}))
	if !pl.Empty() || pl.Problem.EN == "" || !strings.Contains(pl.Problem.VI, "smartmontools") {
		t.Fatalf("plan %+v", pl)
	}
}

func TestAllPresent(t *testing.T) {
	f := baseSys(osAlma9, "dnf", "smartctl", "sensors", "nvme", "dmidecode", "ethtool", "ras-mc-ctl")
	p := Detect(context.Background(), f, Options{})
	if pl := MakePlan(p); !pl.Empty() || !pl.Problem.IsZero() {
		t.Fatalf("plan %+v", pl)
	}
}

func TestFollowUps(t *testing.T) {
	ctx := context.Background()
	f := baseSys(osUbuntu2404, "apt-get")
	f.files["/sys/firmware/dmi/entries/38-0"] = ""
	before := Detect(ctx, f, Options{})
	for _, c := range []string{"smartctl", "sensors", "sensors-detect", "ipmitool", "ras-mc-ctl", "nvme", "dmidecode", "ethtool"} {
		f.cmds[c] = true
	}
	// rasdaemon already running.
	f.outputs["systemctl is-active --quiet rasdaemon"] = ""
	after := Detect(ctx, f, Options{})
	fu := FollowUps(ctx, f, before, after)
	var got []string
	for _, x := range fu {
		got = append(got, x.ID+": "+x.Display())
		if x.Title.EN == "" || x.Title.VI == "" {
			t.Errorf("%s: title needs both languages", x.ID)
		}
	}
	want := []string{
		"sensors_detect: sensors-detect --auto",
		"ipmi_modules: modprobe ipmi_devintf ipmi_si",
		"services: systemctl enable --now smartmontools",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}

	// RHEL family uses smartd.service; sensors already present before: no
	// sensors-detect; the IPMI device exists: no modprobe.
	g := baseSys(osAlma9, "dnf", "smartctl", "sensors", "sensors-detect", "ras-mc-ctl")
	g.files["/dev/ipmi0"] = ""
	p := Detect(ctx, g, Options{})
	got = nil
	for _, x := range FollowUps(ctx, g, p, p) {
		got = append(got, x.ID+": "+x.Display())
	}
	if !reflect.DeepEqual(got, []string{"services: systemctl enable --now smartd rasdaemon"}) {
		t.Fatalf("rhel: %q", got)
	}
}

func TestVendorTools(t *testing.T) {
	f := baseSys(osAlma9, "dnf")
	// Dell PERC H730 (LSI SAS3108, subsystem Dell) and an HPE Smart Array
	// P408i-a (Microsemi SmartPQI, subsystem HPE); class from sysfs.
	f.files["/sys/bus/pci/devices/0000:18:00.0/class"] = "0x010400\n"
	f.files["/sys/bus/pci/devices/0000:18:00.0/vendor"] = "0x1000\n"
	f.files["/sys/bus/pci/devices/0000:18:00.0/subsystem_vendor"] = "0x1028\n"
	f.files["/sys/bus/pci/devices/0000:5c:00.0/class"] = "0x010700\n" // SAS HBA, not RAID
	f.files["/sys/bus/pci/devices/0000:5c:00.0/vendor"] = "0x1000\n"
	f.files["/sys/bus/pci/devices/0000:3b:00.0/class"] = "0x010400\n"
	f.files["/sys/bus/pci/devices/0000:3b:00.0/vendor"] = "0x9005\n"
	f.files["/sys/bus/pci/devices/0000:3b:00.0/subsystem_vendor"] = "0x1590\n"
	p := Detect(context.Background(), f, Options{})
	if !reflect.DeepEqual(p.VendorTools, []string{"perccli", "ssacli"}) {
		t.Fatalf("vendor tools %v", p.VendorTools)
	}
	if adv := VendorAdvice(p); len(adv) != 2 || !strings.Contains(adv[0].VI, "PERC") {
		t.Fatalf("advice %+v", adv)
	}
	f.cmds["perccli64"] = true
	if p := Detect(context.Background(), f, Options{}); !reflect.DeepEqual(p.VendorTools, []string{"ssacli"}) {
		t.Fatalf("installed perccli64 still advised: %v", p.VendorTools)
	}
}

func TestWindowsAdvice(t *testing.T) {
	adv := WindowsAdvice()
	if len(adv) < 2 || !strings.Contains(adv[0].EN, "smartmontools.org") || adv[0].VI == "" {
		t.Fatalf("%+v", adv)
	}
}

func TestShellJoin(t *testing.T) {
	if got := shellJoin([]string{"printf", "a b", "it's", "x"}); got != `printf 'a b' 'it'\''s' x` {
		t.Fatal(got)
	}
}

func TestGarbageInputs(t *testing.T) {
	f := baseSys("\x00\xff garbage ===\n\"")
	f.files["/proc/mdstat"] = "md"
	f.files["/sys/bus/pci/devices/x/class"] = ""
	p := Detect(context.Background(), f, Options{Memtester: true})
	_ = MakePlan(p)
	_ = FollowUps(context.Background(), f, p, p)
}

// TestRealOS runs Detect and the command runner against the machine the
// test runs on (on the dev box: WSL Ubuntu, which is a container).
func TestRealOS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	var out bytes.Buffer
	sys := OS{Stdout: &out, Stderr: &out}
	if err := sys.Run(context.Background(), []string{"DW_X=42"}, "sh", "-c", "echo $DW_X; exit 3"); err == nil || strings.TrimSpace(out.String()) != "42" {
		t.Fatalf("Run: %v %q", err, out.String())
	}
	if s, err := sys.Output(context.Background(), "sh", "-c", "echo hi"); err != nil || s != "hi\n" {
		t.Fatalf("Output: %q %v", s, err)
	}
	if !sys.LookPath("sh") || sys.LookPath("no-such-tool-diagward") {
		t.Fatal("LookPath")
	}
	p := Detect(context.Background(), sys, Options{Memtester: true})
	if _, err := os.Stat("/etc/os-release"); err == nil && (p.Env.Distro == "" || p.Env.PM == "") {
		t.Fatalf("env %+v", p.Env)
	}
	pl := MakePlan(p)
	t.Logf("env=%+v bmc=%v md=%v nvme=%v vendor=%v plan=%q fu=%d", p.Env, p.BMC, p.MD, p.NVMe, p.VendorTools, pl.Display(), len(FollowUps(context.Background(), sys, p, p)))
}
