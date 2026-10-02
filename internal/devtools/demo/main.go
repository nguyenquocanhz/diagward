// Command demo builds the demo server report shown in the README. It is a
// developer tool and is not shipped.
//
// The bundle describes one machine, "srv-db01": a Dell PowerEdge R740 running
// AlmaLinux 9.4 with a few real problems: a disk with unreadable sectors, a
// degraded RAID volume on the PERC with a failed and a failing SSD, a failed
// power supply, corrected ECC errors piling up on one DIMM and a bond running
// on one port. The tool output in it is real fixture output from
// internal/checks/*/testdata, put under the section name its domain parses,
// and the analysis is the real diag.Analyze. Composed here are only the
// meta.* sections the framework writes about the run, and a few sections
// that restate what a fixture already says in the form another collector
// step prints it (the smartctl --scan-open lines of the two disks, the bond's
// ports as network.topology/network.sysfs, nproc from the processor count);
// /proc/loadavg is the one the system tests use. -sources lists every
// section with its origin.
//
// Where a fixture holds more than one machine's worth of lines (the logs and
// SEL fixtures collect lines from many public reports), only the lines that
// fit this machine are kept; the selection is noted next to each section.
//
//	go run ./internal/devtools/demo -o docs/demo/srv-db01.dwb
//	go run ./internal/devtools/demo -html docs/demo/report-vi.html -lang vi
//	go run ./internal/devtools/demo -html docs/demo/report-en.html -lang en
//	go run ./internal/devtools/demo -sources
//
// Screenshots for the README (headless Chrome; -theme pins the colour scheme
// of that copy, -term writes the coloured text report as a terminal-like
// page; a phone-width capture needs an iframe of 390 px, because headless
// Chrome lays a narrower window out at its minimum width):
//
//	go run ./internal/devtools/demo -html /tmp/light.html -lang en -theme light
//	go run ./internal/devtools/demo -term /tmp/term.html -lang vi -width 118
//	chrome --headless=new --hide-scrollbars --window-size=1280,2200 --screenshot=/tmp/light.png file:///tmp/light.html
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
	"github.com/nguyenquocanhz/diagward/report"
)

// The demo machine and when it was "collected". The fixtures' events are
// dated up to 2026-10-01 (the test clock); the kernel log is in +07:00.
const (
	hostname = "srv-db01"
	kernel   = "5.14.0-427.13.1.el9_4.x86_64" // AlmaLinux 9.4 GA kernel
	version  = "0.1.0"
	// uptime matches the EDAC counters' seconds_since_reset (10 days) plus
	// the few seconds the collector ran before reading them.
	uptime = "864012.53"
)

var (
	started  = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	finished = time.Date(2026, 10, 1, 9, 0, 27, 0, time.UTC)
)

// AlmaLinux 9.4's /etc/os-release.
const osRelease = `NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
ANSI_COLOR="0;34"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:almalinux:almalinux:9::baseos"
HOME_URL="https://almalinux.org/"
DOCUMENTATION_URL="https://wiki.almalinux.org/"
BUG_REPORT_URL="https://bugs.almalinux.org/"

ALMALINUX_MANTISBT_PROJECT="AlmaLinux-9"
ALMALINUX_MANTISBT_PROJECT_VERSION="9.4"
REDHAT_SUPPORT_PRODUCT="AlmaLinux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.4"
SUPPORT_END=2032-06-01
`

func main() {
	out := flag.String("o", "", "write the bundle (.dwb) to this file")
	htmlOut := flag.String("html", "", "write the HTML report to this file")
	mdOut := flag.String("md", "", "write the Markdown report to this file")
	txtOut := flag.String("txt", "", "write the text report to this file (- = stdout)")
	lang := flag.String("lang", "vi", "report language: vi or en")
	color := flag.Bool("color", false, "text report: ANSI colours")
	verbose := flag.Bool("v", false, "text/Markdown report: tables, evidence and full coverage")
	width := flag.Int("width", 100, "text report width")
	theme := flag.String("theme", "", "HTML report: pin the colour scheme (light or dark) instead of following the viewer")
	termOut := flag.String("term", "", "write the coloured text report as a dark terminal-like HTML page (for a screenshot)")
	termProblems := flag.Int("term-problems", 3, "-term: show the report up to this many problems (0 = all)")
	sources := flag.Bool("sources", false, "list each section and the fixture it comes from")
	root := flag.String("root", "", "repository root (default: found from the working directory)")
	flag.Parse()

	if *root == "" {
		r, err := findRoot()
		check(err)
		*root = r
	}
	b, src, err := Build(*root)
	check(err)
	if *sources {
		for _, s := range src {
			fmt.Printf("%-34s %s\n", s.Section, s.From)
			if s.Note != "" {
				fmt.Printf("%-34s   (%s)\n", "", s.Note)
			}
		}
	}
	if *out != "" {
		check(writeFile(*out, func(w io.Writer) error { return collect.Write(w, b) }))
	}
	if *htmlOut == "" && *mdOut == "" && *txtOut == "" && *termOut == "" {
		return
	}
	diag.Version = version
	rep := diag.Analyze(b)
	o := report.Options{Lang: *lang, Color: *color, Verbose: *verbose, Width: *width, NoHints: true}
	if *htmlOut != "" {
		check(writeFile(*htmlOut, func(w io.Writer) error {
			var buf bytes.Buffer
			if err := report.HTML(&buf, rep, o); err != nil {
				return err
			}
			page, err := pinTheme(buf.String(), *theme)
			if err != nil {
				return err
			}
			_, err = io.WriteString(w, page)
			return err
		}))
	}
	if *mdOut != "" {
		check(writeFile(*mdOut, func(w io.Writer) error { return report.Markdown(w, rep, o) }))
	}
	if *txtOut != "" {
		check(writeFile(*txtOut, func(w io.Writer) error { return report.Text(w, rep, o) }))
	}
	if *termOut != "" {
		to := o
		to.Color = true
		check(writeFile(*termOut, func(w io.Writer) error {
			var buf bytes.Buffer
			if err := report.Text(&buf, rep, to); err != nil {
				return err
			}
			_, err := io.WriteString(w, terminalPage(firstProblems(buf.String(), *termProblems), "diagward check --lang "+*lang))
			return err
		}))
	}
}

// Source records where a section of the demo bundle comes from.
type Source struct {
	Section string
	From    string // fixture path relative to the repository root, or "composed"
	Note    string // what was selected or changed, if anything
}

type builder struct {
	root string
	b    *collect.Bundle
	src  []Source
	errs []error
}

// Build assembles the demo bundle from the fixtures under root.
func Build(root string) (*collect.Bundle, []Source, error) {
	bl := &builder{root: root, b: &collect.Bundle{
		Format:   collect.BundleFormat,
		Tool:     "diagward " + version,
		OS:       collect.OSLinux,
		Host:     hostname,
		Started:  started,
		Finished: finished,
		Options:  collect.Options{}.WithDefaults(),
	}}
	bl.meta()
	bl.system()
	bl.cpu()
	bl.memory()
	bl.disk()
	bl.raid()
	bl.ipmi()
	bl.network()
	bl.filesystem()
	bl.logs()
	bl.add("meta.done", "now="+finished.Format(time.RFC3339)+"\n", "composed", "")
	return bl.b, bl.src, errors.Join(bl.errs...)
}

// ---- meta: what the framework writes about the run (00-common.sh) ----

func (bl *builder) meta() {
	bl.add("meta.ident", kvLines(
		"hostname", hostname,
		"fqdn", hostname,
		"uid", "0",
		"user", "root",
		"kernel", kernel,
		"arch", "x86_64",
		"now", started.Add(1*time.Second).Format(time.RFC3339),
		"uptime", uptime,
		"collector", version,
		"shell", "/usr/bin/bash",
	), "composed", "")
	bl.add("meta.osrelease", osRelease, "composed", "AlmaLinux 9.4 /etc/os-release")
	// _dw_virt on bare metal: systemd-detect-virt prints "none"; the DMI
	// strings are those of the R740 dmidecode fixture (chassis type 23 =
	// Rack Mount Chassis).
	bl.add("meta.virt", kvLines(
		"vm", "none",
		"container", "none",
		"sys_vendor", "Dell Inc.",
		"product_name", "PowerEdge R740",
		"product_version", "",
		"board_vendor", "Dell Inc.",
		"bios_vendor", "Dell Inc.",
		"chassis_type", "23",
	), "composed", "")
	bl.add("meta.pm", kvLines("dnf", "1", "yum", "1", "sudo", "1", "timeout", "1", "systemctl", "1", "journalctl", "1"), "composed", "")
}

// ---- system ----

func (bl *builder) system() {
	bl.fromFixture("system.dmidecode", "system", "dmidecode_dell_r740.txt", "", nil)
	// The system snippet keeps four lines of /proc/meminfo (grep -E
	// "^(MemTotal|MemAvailable|SwapTotal|SwapFree):"); same file as memory.meminfo.
	bl.fromFixture("system.meminfo", "memory", "meminfo_r740.txt",
		"the collector's grep of MemTotal/MemAvailable/SwapTotal/SwapFree",
		keepPrefix("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"))
	// No load fixture exists outside the developer's own captures; this is
	// the healthy /proc/loadavg the system tests use (check_test.go linuxBase).
	bl.add("system.loadavg", "0.52 0.48 0.40 1/512 12345\n", "internal/checks/system/check_test.go", "linuxBase's /proc/loadavg")
	// nproc: both sockets enabled with 36 threads each (cpu.dmidecode).
	bl.add("system.nproc", "72\n", "composed", "2 x Thread Count 36 from the processor dmidecode fixture")
}

// ---- cpu ----

func (bl *builder) cpu() {
	bl.fromFixture("cpu.dmidecode", "cpu", "dmidecode_processor_dell_r740.txt", "", nil)
}

// ---- memory ----

func (bl *builder) memory() {
	bl.fromFixture("memory.dmidecode", "memory", "dmidecode_memory_dell_r740.txt", "", nil)
	bl.fromFixture("memory.meminfo", "memory", "meminfo_r740.txt", "", nil)
	bl.fromFixture("memory.edac", "memory", "edac_skx_ce250.txt", "", nil)
}

// ---- disk ----

func (bl *builder) disk() {
	// smartctl --scan-open prints "DEV -d TYPE # INFO_NAME, PROTOCOL device".
	bl.add("disk.smart_scan",
		"/dev/sda -d sat # /dev/sda [SAT], ATA device\n/dev/sdb -d scsi # /dev/sdb, SCSI device\n",
		"composed", "the --scan-open lines of the two disks below")
	bl.fromFixture("disk.smart:/dev/sda", "disk", "text540_ata_pending_selftest.txt",
		"without the shell prompt line the source page shows above the output",
		dropPrefix("root@"))
	bl.fromFixture("disk.smart:/dev/sdb", "disk", "scsi_seagate_healthy.json", "", nil)
}

// ---- raid ----

func (bl *builder) raid() {
	// The collector runs MegaCli -LDInfo and -PDList; the fixture is the
	// combined -LDPDInfo, which carries both (the tests read it the same way).
	bl.fromFixture("raid.megacli_ld", "raid", "megacli-ldpdinfo-degraded.txt", "", nil)
	bl.fromFixture("raid.megacli_pd", "raid", "megacli-ldpdinfo-degraded.txt", "", nil)
	bl.fromFixture("raid.megacli_bbu", "raid", "megacli-bbu-recent.txt", "", nil)
	bl.fromFixture("raid.pci", "raid", "pci_perc_hba.txt", "only the PERC H730P Mini block", firstBlock)
}

// ---- ipmi ----

func (bl *builder) ipmi() {
	bl.fromFixture("ipmi.mc", "ipmi", "mc_info_dell.txt", "", nil)
	bl.fromFixture("ipmi.chassis", "ipmi", "chassis_supermicro_ok.txt", "", nil)
	bl.fromFixture("ipmi.sel_info", "ipmi", "sel_info_ok.txt", "", nil)
	bl.fromFixture("ipmi.sdr", "ipmi", "sdr_dell_faults.txt",
		"without the Fan3, CPU temperature, intrusion, drive and PS Redundancy lines",
		dropContains("Fan3 ", "| ucr |", "Intrusion ", "Drive 0 ", "PS Redundancy "))
	bl.fromFixture("ipmi.sel", "ipmi", "sel_recent_faults.txt",
		"record 29 (PSU redundancy lost on 2026-09-24)",
		keepSEL("29"))
	bl.fromFixture("ipmi.fru", "ipmi", "fru_dell_r640.txt", "only the PS1 and PS2 records", keepBlocks("PS1 (", "PS2 ("))
	// 45-ipmi.sh replaces the SNMP community string before it leaves the server.
	bl.fromFixture("ipmi.lan", "ipmi", "lan_print_huawei_rh1288v3.txt", "SNMP community redacted as the collector does",
		redactSNMP)
}

// ---- network ----

func (bl *builder) network() {
	bl.fromFixture("network.bonding:bond0", "network", "bonding_8023ad_slave_down_insights.txt", "", nil)
	// network.topology lists the bond and its ports the way _nw_topo prints
	// them; the names come from the bonding file (a bond's slaves are the
	// machine's physical ports). The driver is not in that file, so it stays
	// empty.
	// network.sysfs repeats what the bonding file says about each port
	// (MII status = carrier, speed, duplex) in the kernel's sysfs form.
	s := bl.b.Get("network.bonding:bond0")
	if s == nil {
		return
	}
	topo := "if=bond0 kind=bond master= lower= driver=\n"
	var sys strings.Builder
	port := ""
	for _, l := range s.Lines() {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		p := "/sys/class/net/" + port + "/"
		switch {
		case k == "Slave Interface":
			port = v
			topo += "if=" + port + " kind=phys master=bond0 lower= driver=\n"
		case port == "":
		case k == "MII Status":
			carrier := "0"
			if v == "up" {
				carrier = "1"
			}
			sys.WriteString(p + "operstate=" + v + "\n" + p + "carrier=" + carrier + "\n")
		case k == "Speed":
			sp := "-1" // "Unknown": the kernel prints -1 without link
			if n, ok := strings.CutSuffix(v, " Mbps"); ok {
				sp = n
			}
			sys.WriteString(p + "speed=" + sp + "\n")
		case k == "Duplex":
			sys.WriteString(p + "duplex=" + strings.ToLower(v) + "\n")
		}
	}
	bl.add("network.topology", topo, "composed", "bond0 and its ports, from the bonding fixture")
	bl.add("network.sysfs", sys.String(), "composed", "operstate/carrier/speed/duplex of the ports, from the bonding fixture")
}

// ---- filesystem ----

func (bl *builder) filesystem() {
	bl.fromFixture("filesystem.mounts", "filesystem", "proc_mounts_rhel6.txt", "", nil)
}

// ---- logs ----

func (bl *builder) logs() {
	bl.fromFixture("logs.kernel_match", "logs", "linux_failing_match.txt",
		"header and the three sd [sda] medium-error lines of 2026-09-30; host name srv01 -> "+hostname,
		func(s string) string {
			s = keepContains("# source=", "[sda]")(s)
			return strings.ReplaceAll(s, " srv01 kernel: ", " "+hostname+" kernel: ")
		})
	bl.add("logs.kernel", "# source=journal persistent=1 tz=+0700\n# rc=0\n", "composed", "header only, as in the logs tests")
}

// ---- helpers ----

func (bl *builder) add(name, out, from, note string) {
	bl.b.Add(&collect.Section{Name: name, Out: out})
	bl.src = append(bl.src, Source{Section: name, From: from, Note: note})
}

// fromFixture adds a section with the content of
// internal/checks/<domain>/testdata/<file>, passed through sel when given.
func (bl *builder) fromFixture(name, domain, file, note string, sel func(string) string) {
	rel := filepath.ToSlash(filepath.Join("internal", "checks", domain, "testdata", file))
	data, err := os.ReadFile(filepath.Join(bl.root, filepath.FromSlash(rel)))
	if err != nil {
		bl.errs = append(bl.errs, err)
		return
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	if sel != nil {
		s = sel(s)
		if strings.TrimSpace(s) == "" {
			bl.errs = append(bl.errs, fmt.Errorf("%s: the selection kept nothing", rel))
		}
	}
	bl.add(name, s, rel, note)
}

func kvLines(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteString(kv[i] + "=" + kv[i+1] + "\n")
	}
	return b.String()
}

func filterLines(s string, keep func(string) bool) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(s, "\n") {
		if l != "" && keep(strings.TrimRight(l, "\n")) {
			b.WriteString(l)
		}
	}
	return b.String()
}

func keepPrefix(p ...string) func(string) string {
	return func(s string) string {
		return filterLines(s, func(l string) bool {
			for _, x := range p {
				if strings.HasPrefix(l, x) {
					return true
				}
			}
			return false
		})
	}
}

func dropPrefix(p ...string) func(string) string {
	return func(s string) string {
		return filterLines(s, func(l string) bool {
			for _, x := range p {
				if strings.HasPrefix(l, x) {
					return false
				}
			}
			return true
		})
	}
}

func keepContains(sub ...string) func(string) string {
	return func(s string) string {
		return filterLines(s, func(l string) bool {
			for _, x := range sub {
				if strings.Contains(l, x) {
					return true
				}
			}
			return false
		})
	}
}

func dropContains(sub ...string) func(string) string {
	return func(s string) string {
		return filterLines(s, func(l string) bool {
			for _, x := range sub {
				if strings.Contains(l, x) {
					return false
				}
			}
			return true
		})
	}
}

// keepSEL keeps the `sel elist` records with the given record IDs.
func keepSEL(ids ...string) func(string) string {
	return func(s string) string {
		return filterLines(s, func(l string) bool {
			id, _, ok := strings.Cut(l, "|")
			if !ok {
				return false
			}
			for _, x := range ids {
				if strings.TrimSpace(id) == x {
					return true
				}
			}
			return false
		})
	}
}

// firstBlock keeps the first blank-line separated block.
func firstBlock(s string) string {
	if i := strings.Index(s, "\n\n"); i >= 0 {
		return s[:i+1]
	}
	return s
}

// keepBlocks keeps the `fru print` records whose description line contains
// one of the given strings.
func keepBlocks(sub ...string) func(string) string {
	return func(s string) string {
		var out []string
		for _, blk := range strings.Split(strings.TrimRight(s, "\n"), "\n\n") {
			first, _, _ := strings.Cut(blk, "\n")
			for _, x := range sub {
				if strings.Contains(first, x) {
					out = append(out, blk)
					break
				}
			}
		}
		return strings.Join(out, "\n\n") + "\n"
	}
}

// redactSNMP is the collector's sed "s/^\(SNMP Community String *:\).*/\1 <redacted>/".
func redactSNMP(s string) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(s, "\n") {
		if strings.HasPrefix(l, "SNMP Community String") {
			if i := strings.IndexByte(l, ':'); i >= 0 {
				nl := ""
				if strings.HasSuffix(l, "\n") {
					nl = "\n"
				}
				l = l[:i+1] + " <redacted>" + nl
			}
		}
		b.WriteString(l)
	}
	return b.String()
}

// findRoot walks up from the working directory to the directory holding
// go.mod.
func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found; pass -root")
		}
		dir = parent
	}
}

func writeFile(path string, fn func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		return err
	}
	if path == "-" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}
