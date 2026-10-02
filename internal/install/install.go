// Package install finds which helper tools Diagward needs on a Linux server
// (smartctl, sensors, ipmitool, ...), plans one install command for the
// distribution and runs it, then offers the follow-up steps that make the
// tools useful (sensors-detect, IPMI kernel modules, smartd/rasdaemon).
//
// Everything that touches the machine goes through System, so planning is
// tested per distribution without root or real hardware.
package install

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/model"
)

// System is the machine the installer inspects and changes.
type System interface {
	// LookPath reports whether a command is installed (PATH plus the sbin
	// directories, which a non-root PATH often lacks).
	LookPath(name string) bool
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) []string
	// Output runs a command quietly and returns its stdout.
	Output(ctx context.Context, name string, args ...string) (string, error)
	// Run runs a command with its output shown to the user.
	Run(ctx context.Context, env []string, name string, args ...string) error
	Root() bool
}

// Options select optional tools.
type Options struct {
	Memtester bool // also install memtester (for "diagward check --memtest")
}

// Tool is one helper tool and whether this machine needs it.
type Tool struct {
	Name    string     `json:"name"`    // command, e.g. "smartctl"
	Package string     `json:"package"` // package that provides it here
	Present bool       `json:"present"`
	Wanted  bool       `json:"wanted"`
	Why     model.Text `json:"why"` // what it is for, or why it is not needed here
}

// Probe is what Detect found.
type Probe struct {
	Env       model.Env `json:"env"`
	OSName    string    `json:"osName,omitempty"` // PRETTY_NAME from os-release, e.g. "Ubuntu 24.04.1 LTS"
	BMC       bool      `json:"bmc"`              // an IPMI BMC is described by SMBIOS or has a device node
	IPMIDev   bool      `json:"ipmiDev"`          // /dev/ipmi* exists (driver loaded)
	MD        bool      `json:"md"`               // Linux software RAID arrays exist
	NVMe      bool      `json:"nvme"`             // NVMe controllers exist
	Systemctl bool      `json:"systemctl"`        // systemd is available
	EPEL      bool      `json:"epel"`             // EPEL repository configured (RHEL family)
	// VendorTools are RAID controller CLIs this machine needs and lacks
	// (storcli, perccli, ssacli, arcconf); they are not in distribution
	// repositories, so they are only advised.
	VendorTools []string `json:"vendorTools,omitempty"`
	Tools       []Tool   `json:"tools"`
}

// Missing returns the wanted tools that are not installed.
func (p Probe) Missing() []Tool {
	var out []Tool
	for _, t := range p.Tools {
		if t.Wanted && !t.Present {
			out = append(out, t)
		}
	}
	return out
}

// Tool returns the named tool entry.
func (p Probe) Tool(name string) (Tool, bool) {
	for _, t := range p.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Detect inspects the machine.
func Detect(ctx context.Context, sys System, o Options) Probe {
	var p Probe
	p.Env, p.OSName = detectEnv(ctx, sys)
	p.Systemctl = sys.LookPath("systemctl")
	p.BMC, p.IPMIDev = detectBMC(sys)
	p.MD = detectMD(sys)
	p.NVMe = len(sys.Glob("/sys/class/nvme/nvme*")) > 0
	p.EPEL = len(sys.Glob("/etc/yum.repos.d/epel*.repo")) > 0
	for _, t := range detectVendorTools(sys) {
		if !sys.LookPath(t) && !sys.LookPath(t+"64") {
			p.VendorTools = append(p.VendorTools, t)
		}
	}

	bare := p.Env.Virtual == "" && !p.Env.Container
	add := func(name string, wanted bool, why model.Text) {
		t := Tool{Name: name, Package: hint.Package(p.Env, name), Present: sys.LookPath(name), Wanted: wanted, Why: why}
		if t.Package == "" {
			t.Package = name
		}
		p.Tools = append(p.Tools, t)
	}
	vmWhy := model.T("not needed: virtual machine (the hardware belongs to the host)", "không cần: máy ảo (phần cứng thuộc máy host)")
	if p.Env.Container {
		vmWhy = model.T("not needed: container (check the host instead)", "không cần: container (hãy kiểm tra máy host)")
	}
	pick := func(wantBare bool, why model.Text) (bool, model.Text) {
		if p.Env.Container {
			return false, vmWhy
		}
		if !bare && wantBare {
			return false, vmWhy
		}
		return true, why
	}

	w, why := pick(false, model.T("disk health (S.M.A.R.T.)", "sức khỏe ổ cứng (S.M.A.R.T.)"))
	add("smartctl", w, why)
	w, why = pick(true, model.T("CPU/board temperatures, fans, voltages", "nhiệt độ CPU/mainboard, quạt, điện áp"))
	add("sensors", w, why)
	switch {
	case p.Env.Container:
		add("ipmitool", false, vmWhy)
	case p.BMC:
		add("ipmitool", true, model.T("BMC sensors, event log (SEL), power supplies", "cảm biến BMC, nhật ký sự kiện (SEL), nguồn"))
	default:
		add("ipmitool", false, model.T("not needed: no IPMI BMC found", "không cần: không thấy BMC IPMI"))
	}
	w, why = pick(false, model.T("NVMe health and error log", "sức khỏe và nhật ký lỗi NVMe"))
	add("nvme", w, why)
	switch {
	case p.Env.Container:
		add("mdadm", false, vmWhy)
	case p.MD:
		add("mdadm", true, model.T("software RAID (md) details", "chi tiết RAID mềm (md)"))
	default:
		add("mdadm", false, model.T("not needed: no software RAID arrays", "không cần: không có RAID mềm"))
	}
	w, why = pick(false, model.T("serial numbers, RAM slots, BIOS (for warranty)", "serial, khe RAM, BIOS (để bảo hành)"))
	add("dmidecode", w, why)
	w, why = pick(false, model.T("network link speed, duplex, NIC errors", "tốc độ link mạng, duplex, lỗi card mạng"))
	add("ethtool", w, why)
	w, why = pick(true, model.T("RAM ECC and CPU machine-check errors (rasdaemon)", "lỗi ECC RAM và lỗi machine-check CPU (rasdaemon)"))
	add("ras-mc-ctl", w, why)
	if o.Memtester {
		w, why = pick(false, model.T("RAM test (diagward check --memtest)", "kiểm tra RAM (diagward check --memtest)"))
		add("memtester", w, why)
	}
	return p
}

func detectEnv(ctx context.Context, sys System) (model.Env, string) {
	env := model.Env{OS: collect.OSLinux, Root: sys.Root()}
	data, err := sys.ReadFile("/etc/os-release")
	if err != nil {
		data, _ = sys.ReadFile("/usr/lib/os-release")
	}
	osr := collect.ParseOSRelease(string(data))
	pretty := strings.TrimSpace(osr["PRETTY_NAME"])
	env.Distro, env.DistroVer, env.Like = strings.ToLower(osr["ID"]), osr["VERSION_ID"], strings.ToLower(osr["ID_LIKE"])
	if env.Distro == "debian" && (len(sys.Glob("/etc/pve")) > 0 || sys.LookPath("pveversion")) {
		env.Distro = "proxmox"
	}
	env.PM = detectPM(sys, env)

	// Virtualisation, the same way the collector decides it.
	if v, _ := sys.Output(ctx, "systemd-detect-virt", "--container"); strings.TrimSpace(v) != "" && strings.TrimSpace(v) != "none" {
		env.Virtual, env.Container = strings.TrimSpace(v), true
	}
	if !env.Container {
		ver, _ := sys.ReadFile("/proc/version")
		lv := strings.ToLower(string(ver))
		switch {
		case strings.Contains(lv, "microsoft") || strings.Contains(lv, "wsl"):
			env.Virtual, env.Container = "wsl", true
		case len(sys.Glob("/.dockerenv")) > 0:
			env.Virtual, env.Container = "docker", true
		case len(sys.Glob("/run/.containerenv")) > 0:
			env.Virtual, env.Container = "podman", true
		case len(sys.Glob("/proc/vz")) > 0 && len(sys.Glob("/proc/bc")) == 0:
			env.Virtual, env.Container = "openvz", true
		}
	}
	if !env.Container {
		if v, _ := sys.Output(ctx, "systemd-detect-virt", "--vm"); strings.TrimSpace(v) != "" && strings.TrimSpace(v) != "none" {
			env.Virtual = strings.TrimSpace(v)
		}
	}
	return env, pretty
}

// detectPM picks the package manager that belongs to the distribution
// family (a Debian box with dnf installed for some reason still uses apt).
func detectPM(sys System, env model.Env) string {
	byFamily := map[string][]string{
		"rhel":   {"dnf", "yum"},
		"debian": {"apt-get"},
		"suse":   {"zypper"},
		"alpine": {"apk"},
		"arch":   {"pacman"},
	}
	cands := byFamily[hint.Family(env)]
	cands = append(cands, "dnf", "yum", "apt-get", "zypper", "apk", "pacman")
	for _, c := range cands {
		if sys.LookPath(c) {
			return strings.TrimSuffix(c, "-get")
		}
	}
	return ""
}

// detectBMC looks for an IPMI BMC. SMBIOS type 38 ("IPMI Device
// Information", DMTF DSP0134 §7.39) is present on servers with a BMC even
// before the ipmi_si driver is loaded; /dev/ipmi0 and /sys/class/ipmi exist
// once it is.
func detectBMC(sys System) (bmc, dev bool) {
	dev = len(sys.Glob("/dev/ipmi[0-9]*"))+len(sys.Glob("/dev/ipmi/[0-9]*"))+len(sys.Glob("/dev/ipmidev/[0-9]*")) > 0
	bmc = dev || len(sys.Glob("/sys/firmware/dmi/entries/38-*")) > 0 || len(sys.Glob("/sys/class/ipmi/*")) > 0
	return bmc, dev
}

// detectMD reports whether /proc/mdstat lists any array ("md0 : active ...").
func detectMD(sys System) bool {
	data, err := sys.ReadFile("/proc/mdstat")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "md") && strings.Contains(l, " : ") {
			return true
		}
	}
	return false
}

// RAID controllers are PCI class 0x0104 (RAID bus controller). Vendor IDs
// from the PCI ID repository (pci-ids.ucw.cz): 0x1000 LSI/Broadcom
// MegaRAID (Dell PERC when the subsystem vendor is 0x1028 Dell), 0x9005
// Adaptec/Microsemi (HPE Smart Array Gen10 when the subsystem vendor is
// 0x1590 HPE), 0x103c HP Smart Array (older generations).
func detectVendorTools(sys System) []string {
	set := map[string]bool{}
	for _, cls := range sys.Glob("/sys/bus/pci/devices/*/class") {
		c, err := sys.ReadFile(cls)
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(c)), "0x0104") {
			continue
		}
		dir := path.Dir(cls)
		read := func(n string) string {
			b, _ := sys.ReadFile(dir + "/" + n)
			return strings.ToLower(strings.TrimSpace(string(b)))
		}
		vendor, sub := read("vendor"), read("subsystem_vendor")
		switch {
		case vendor == "0x1000" && sub == "0x1028":
			set["perccli"] = true
		case vendor == "0x1000":
			set["storcli"] = true
		case vendor == "0x9005" && sub == "0x1590", vendor == "0x103c":
			set["ssacli"] = true
		case vendor == "0x9005":
			set["arcconf"] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Step is one command of a plan.
type Step struct {
	Args      []string `json:"args"`
	Env       []string `json:"env,omitempty"`
	AllowFail bool     `json:"allowFail,omitempty"` // a failure is reported but the plan goes on
	// Fallback runs when the step fails: one install per package, so a
	// single package missing from the configured repositories (Ubuntu
	// without "universe", RHEL without EPEL, an Arch AUR-only package)
	// does not stop the others from being installed. apt-get, dnf (strict
	// by default), zypper, apk and pacman all reject the whole command
	// when one name is unknown.
	Fallback []Step `json:"fallback,omitempty"`
}

func (s Step) String() string { return shellJoin(s.Args) }

// Plan is how to install the missing tools.
type Plan struct {
	Tools    []string `json:"tools"`    // commands that will be installed
	Packages []string `json:"packages"` // packages to install
	Steps    []Step   `json:"steps"`
	// Problem explains why no plan could be made (unknown package manager,
	// container). Steps is then empty.
	Problem model.Text `json:"problem,omitzero"`
	// Notes are warnings to show with the plan (EPEL needed, ...).
	Notes []model.Text `json:"notes,omitempty"`
}

// Empty reports whether there is nothing to install.
func (pl Plan) Empty() bool { return len(pl.Steps) == 0 }

// Display is the plan as one shell line the user can also run by hand.
func (pl Plan) Display() string {
	var b strings.Builder
	for i, s := range pl.Steps {
		if i > 0 {
			if pl.Steps[i-1].AllowFail {
				b.WriteString("; ")
			} else {
				b.WriteString(" && ")
			}
		}
		b.WriteString(s.String())
	}
	return b.String()
}

// MakePlan builds the install command for the missing tools.
func MakePlan(p Probe) Plan {
	var pl Plan
	missing := p.Missing()
	if len(missing) == 0 {
		return pl
	}
	seen := map[string]bool{}
	for _, t := range missing {
		pl.Tools = append(pl.Tools, t.Name)
		if !seen[t.Package] {
			seen[t.Package] = true
			pl.Packages = append(pl.Packages, t.Package)
		}
	}
	if p.Env.PM == "" {
		pl.Problem = model.Tf("Unknown package manager: install these packages by hand: %s",
			"Không nhận ra trình quản lý gói: hãy tự cài các gói sau: %s", strings.Join(pl.Packages, " "))
		return pl
	}
	fam := hint.Family(p.Env)
	if fam == "rhel" && p.Env.Distro != "fedora" && !p.EPEL && needsEPEL(pl.Packages) {
		step, note := epelStep(p.Env)
		if step != nil {
			// Without EPEL only memtester/edac-utils fail to install; the
			// other tools must still be installed.
			step.AllowFail = true
			pl.Steps = append(pl.Steps, *step)
		}
		if !note.IsZero() {
			pl.Notes = append(pl.Notes, note)
		}
	}
	defer func() {
		// The last step is the install command: give it its per-package
		// fallback.
		if n := len(pl.Steps); n > 0 && len(pl.Packages) > 1 && pl.Problem.IsZero() {
			last := pl.Steps[n-1]
			base := last.Args[:len(last.Args)-len(pl.Packages)]
			for _, pkg := range pl.Packages {
				args := append(append([]string{}, base...), pkg)
				last.Fallback = append(last.Fallback, Step{Args: args, Env: last.Env, AllowFail: true})
			}
			pl.Steps[n-1] = last
		}
	}()
	switch p.Env.PM {
	case "dnf", "yum":
		pl.Steps = append(pl.Steps, Step{Args: append([]string{p.Env.PM, "install", "-y"}, pl.Packages...)})
	case "apt":
		// Package lists on a fresh server are often stale ("Unable to
		// locate package"). A broken third-party repository (Proxmox
		// enterprise without subscription: 401) makes "apt-get update"
		// fail although installing still works, so its failure is not
		// fatal. --no-install-recommends keeps smartmontools from pulling
		// in an MTA (postfix asks interactive questions).
		env := []string{"DEBIAN_FRONTEND=noninteractive"}
		pl.Steps = append(pl.Steps,
			Step{Args: []string{"apt-get", "update"}, Env: env, AllowFail: true},
			Step{Args: append([]string{"apt-get", "install", "-y", "--no-install-recommends"}, pl.Packages...), Env: env})
	case "zypper":
		pl.Steps = append(pl.Steps, Step{Args: append([]string{"zypper", "--non-interactive", "install"}, pl.Packages...)})
	case "apk":
		pl.Steps = append(pl.Steps, Step{Args: append([]string{"apk", "add"}, pl.Packages...)})
	case "pacman":
		pl.Steps = append(pl.Steps, Step{Args: append([]string{"pacman", "-S", "--needed", "--noconfirm"}, pl.Packages...)})
	default:
		pl.Problem = model.Tf("Package manager %s is not supported: install these packages by hand: %s",
			"Chưa hỗ trợ trình quản lý gói %s: hãy tự cài các gói sau: %s", p.Env.PM, strings.Join(pl.Packages, " "))
	}
	return pl
}

// needsEPEL: memtester and edac-utils are not in the RHEL/Alma/Rocky base
// repositories, only in EPEL (https://packages.fedoraproject.org/pkgs/memtester/).
func needsEPEL(pkgs []string) bool {
	for _, p := range pkgs {
		if p == "memtester" || p == "edac-utils" {
			return true
		}
	}
	return false
}

// epelStep returns the command that enables EPEL on this RHEL-family
// distribution (https://docs.fedoraproject.org/en-US/epel/getting-started/).
func epelStep(env model.Env) (*Step, model.Text) {
	major := env.DistroVer
	if i := strings.IndexByte(major, '.'); i >= 0 {
		major = major[:i]
	}
	pm := env.PM
	switch env.Distro {
	case "rhel":
		if major == "" {
			return nil, model.T("EPEL is needed for memtester: see https://docs.fedoraproject.org/en-US/epel/getting-started/",
				"Cần kho EPEL để cài memtester: xem https://docs.fedoraproject.org/en-US/epel/getting-started/")
		}
		return &Step{Args: []string{pm, "install", "-y", "https://dl.fedoraproject.org/pub/epel/epel-release-latest-" + major + ".noarch.rpm"}},
			model.T("On RHEL, some EPEL packages also need the CodeReady Builder repository (subscription-manager repos --enable codeready-builder-for-rhel-<version>-<arch>-rpms).",
				"Trên RHEL, một số gói EPEL cần thêm kho CodeReady Builder (subscription-manager repos --enable codeready-builder-for-rhel-<phiên bản>-<arch>-rpms).")
	case "ol":
		if major == "" {
			major = "9"
		}
		return &Step{Args: []string{pm, "install", "-y", "oracle-epel-release-el" + major}}, model.Text{}
	case "amzn":
		if major == "2" {
			return &Step{Args: []string{"amazon-linux-extras", "install", "-y", "epel"}}, model.Text{}
		}
		return nil, model.T("Amazon Linux 2023 has no EPEL: memtester may not be available.",
			"Amazon Linux 2023 không có EPEL: có thể không cài được memtester.")
	}
	// AlmaLinux, Rocky, CentOS (7 included), CloudLinux...: epel-release
	// is in the distribution's extras repository.
	return &Step{Args: []string{pm, "install", "-y", "epel-release"}}, model.Text{}
}

// Run executes the plan's steps in order, showing their output. It stops
// at the first failing step that is not AllowFail.
func (pl Plan) Run(ctx context.Context, sys System, warn func(step Step, err error)) error {
	for _, s := range pl.Steps {
		if len(s.Args) == 0 {
			continue
		}
		err := sys.Run(ctx, s.Env, s.Args[0], s.Args[1:]...)
		if err == nil {
			continue
		}
		if len(s.Fallback) > 0 && ctx.Err() == nil {
			if warn != nil {
				warn(s, err)
			}
			ok := 0
			for _, f := range s.Fallback {
				if ferr := sys.Run(ctx, f.Env, f.Args[0], f.Args[1:]...); ferr != nil {
					if warn != nil {
						warn(f, ferr)
					}
					continue
				}
				ok++
			}
			if ok > 0 {
				continue
			}
		}
		if s.AllowFail {
			if warn != nil {
				warn(s, err)
			}
			continue
		}
		return fmt.Errorf("%s: %w", s.String(), err)
	}
	return nil
}

// FollowUp is a step offered after installing.
type FollowUp struct {
	ID    string     `json:"id"` // sensors_detect, ipmi_modules, services
	Title model.Text `json:"title"`
	Steps []Step     `json:"steps"`
	Note  model.Text `json:"note,omitzero"` // shown after it ran
}

// Display is the follow-up as a shell line.
func (f FollowUp) Display() string { return Plan{Steps: f.Steps}.Display() }

// FollowUps lists what to do after installing. before is the probe from
// before the install, after the probe from after it.
func FollowUps(ctx context.Context, sys System, before, after Probe) []FollowUp {
	var out []FollowUp
	if after.Env.Container {
		return nil
	}
	// lm_sensors finds nothing until sensors-detect has loaded the right
	// hwmon drivers; --auto answers every question with the default
	// (lm-sensors documentation, sensors-detect(8)).
	if t, _ := before.Tool("sensors"); t.Wanted && !t.Present {
		if a, _ := after.Tool("sensors"); a.Present && sys.LookPath("sensors-detect") {
			out = append(out, FollowUp{
				ID:    "sensors_detect",
				Title: model.T("Detect the temperature/fan sensor chips (lm_sensors)", "Dò chip cảm biến nhiệt độ/quạt (lm_sensors)"),
				Steps: []Step{{Args: []string{"sensors-detect", "--auto"}}},
			})
		}
	}
	// ipmitool talks to the BMC through /dev/ipmi0, which needs the
	// ipmi_si (system interface) and ipmi_devintf (device node) drivers.
	if after.BMC && !after.IPMIDev && sys.LookPath("modprobe") {
		out = append(out, FollowUp{
			ID:    "ipmi_modules",
			Title: model.T("Load the IPMI drivers so ipmitool can reach the BMC", "Nạp driver IPMI để ipmitool đọc được BMC"),
			Steps: []Step{{Args: []string{"modprobe", "ipmi_devintf", "ipmi_si"}}},
			Note: model.T("To load them at every boot: printf 'ipmi_devintf\\nipmi_si\\n' > /etc/modules-load.d/ipmi.conf",
				"Để tự nạp mỗi lần khởi động: printf 'ipmi_devintf\\nipmi_si\\n' > /etc/modules-load.d/ipmi.conf"),
		})
	}
	// smartd watches disks between Diagward runs; rasdaemon records ECC
	// and machine-check errors so they survive a reboot.
	if after.Systemctl {
		var units []string
		if t, _ := after.Tool("smartctl"); t.Present {
			// Debian/Ubuntu ship smartmontools.service with smartd.service
			// only as an alias, and "systemctl enable" refuses aliases.
			u := "smartd"
			if hint.Family(after.Env) == "debian" {
				u = "smartmontools"
			}
			units = append(units, u)
		}
		if t, _ := after.Tool("ras-mc-ctl"); t.Present {
			units = append(units, "rasdaemon")
		}
		var todo []string
		for _, u := range units {
			if _, err := sys.Output(ctx, "systemctl", "is-active", "--quiet", u); err != nil {
				todo = append(todo, u)
			}
		}
		if len(todo) > 0 {
			out = append(out, FollowUp{
				ID:    "services",
				Title: model.T("Start disk and memory error monitoring now and at boot", "Bật giám sát lỗi ổ cứng và RAM (chạy ngay và tự chạy khi khởi động)"),
				Steps: []Step{{Args: append([]string{"systemctl", "enable", "--now"}, todo...)}},
			})
		}
	}
	return out
}

// ubuntuUniverse are the packages Diagward installs that Ubuntu ships in
// its "universe" component (packages.ubuntu.com), which some minimal or
// hardened servers do not enable.
var ubuntuUniverse = map[string]bool{"lm-sensors": true, "ipmitool": true, "rasdaemon": true, "memtester": true, "edac-utils": true}

// MissingHint explains why tools may still be missing after the install
// ran, or returns an empty Text.
func MissingHint(p Probe, still []Tool) model.Text {
	var uni []string
	for _, t := range still {
		if ubuntuUniverse[t.Package] {
			uni = append(uni, t.Package)
		}
	}
	switch {
	case len(uni) > 0 && p.Env.Distro == "ubuntu":
		return model.Tf("Ubuntu ships these packages in its \"universe\" repository: %s. Enable it, then run sudo diagward install-tools again: sudo add-apt-repository -y universe && sudo apt-get update",
			"Ubuntu để các gói này trong kho \"universe\": %s. Bật kho này rồi chạy lại sudo diagward install-tools: sudo add-apt-repository -y universe && sudo apt-get update",
			strings.Join(uni, ", "))
	case hint.Family(p.Env) == "rhel" && p.Env.Distro != "fedora" && !p.EPEL && len(still) > 0:
		return model.T("Some packages may need the EPEL repository: dnf install -y epel-release (on RHEL see https://docs.fedoraproject.org/en-US/epel/getting-started/).",
			"Một số gói có thể cần kho EPEL: dnf install -y epel-release (trên RHEL xem https://docs.fedoraproject.org/en-US/epel/getting-started/).")
	}
	return model.Text{}
}

// VendorAdvice returns the install advice for RAID controller CLIs.
func VendorAdvice(p Probe) []model.Text {
	var out []model.Text
	for _, t := range p.VendorTools {
		out = append(out, hint.Install(p.Env, t))
	}
	return out
}

// WindowsAdvice is what to install on a Windows server, which has no
// package manager the installer can rely on (winget is missing on Server
// 2016/2019).
func WindowsAdvice() []model.Text {
	return []model.Text{
		model.T("smartmontools (disk S.M.A.R.T.): download the Windows installer from https://www.smartmontools.org/wiki/Download , or run: winget install --id smartmontools.smartmontools",
			"smartmontools (S.M.A.R.T. ổ cứng): tải bản cài cho Windows tại https://www.smartmontools.org/wiki/Download , hoặc chạy: winget install --id smartmontools.smartmontools"),
		hint.Install(model.Env{OS: "windows"}, "storcli"),
		hint.Install(model.Env{OS: "windows"}, "perccli"),
		hint.Install(model.Env{OS: "windows"}, "ssacli"),
		model.T("Dell servers: Dell OpenManage Server Administrator or iDRAC Service Module; HPE servers: Agentless Management Service. They expose fan, power supply and controller health.",
			"Máy Dell: Dell OpenManage Server Administrator hoặc iDRAC Service Module; máy HPE: Agentless Management Service. Các phần mềm này cho biết tình trạng quạt, nguồn và card RAID."),
	}
}

// shellJoin quotes args for display.
func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`;&|<>()*?[]#~!{}") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		q[i] = a
	}
	return strings.Join(q, " ")
}

// OS is the real machine.
type OS struct {
	Stdout, Stderr io.Writer // where Run shows output (default os.Stdout/os.Stderr)
}

var sbinDirs = []string{"/usr/local/sbin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/bin", "/bin"}

func (s OS) LookPath(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	for _, d := range sbinDirs {
		if fi, err := os.Stat(filepath.Join(d, name)); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

func (OS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (OS) Glob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

func (s OS) find(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range sbinDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return name
}

func (s OS) Output(ctx context.Context, name string, args ...string) (string, error) {
	var out bytes.Buffer
	c := exec.CommandContext(ctx, s.find(name), args...)
	c.Stdout = &out
	err := c.Run()
	return out.String(), err
}

func (s OS) Run(ctx context.Context, env []string, name string, args ...string) error {
	c := exec.CommandContext(ctx, s.find(name), args...)
	c.Stdin = os.Stdin
	c.Stdout, c.Stderr = s.Stdout, s.Stderr
	if c.Stdout == nil {
		c.Stdout = os.Stdout
	}
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	if len(env) > 0 {
		c.Env = append(os.Environ(), env...)
	}
	return c.Run()
}

func (OS) Root() bool { return os.Geteuid() == 0 }
