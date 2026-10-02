// Package model holds the types every part of Diagward shares: findings,
// tables, coverage and the final report. It has no dependencies so that other
// programs (such as Termward) can consume reports without pulling in the
// collectors.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity orders how much a finding matters. The zero value is OK.
type Severity int

const (
	OK   Severity = iota // checked and healthy
	Info                 // worth knowing, nothing to do now
	Warn                 // needs attention soon (degraded, wearing out, rising errors)
	Crit                 // failed or failing now; act today
)

var sevNames = [...]string{"ok", "info", "warn", "crit"}

func (s Severity) String() string {
	if s < OK || s > Crit {
		return "unknown"
	}
	return sevNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	for i, n := range sevNames {
		if n == v {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", v)
}

// Worst returns the most severe of the given severities.
func Worst(ss ...Severity) Severity {
	w := OK
	for _, s := range ss {
		if s > w {
			w = s
		}
	}
	return w
}

// Text is a message in both supported languages. Vietnamese is required, not
// a translation afterthought: Diagward is written for Vietnamese IT support
// first.
type Text struct {
	EN string `json:"en"`
	VI string `json:"vi"`
}

// T builds a Text.
func T(en, vi string) Text { return Text{EN: en, VI: vi} }

// Tf builds a Text, formatting both strings with the same arguments.
func Tf(en, vi string, args ...any) Text {
	return Text{EN: fmt.Sprintf(en, args...), VI: fmt.Sprintf(vi, args...)}
}

// In returns the text in lang ("vi" or "en"); it falls back to the other
// language when one is empty.
func (t Text) In(lang string) string {
	if strings.HasPrefix(strings.ToLower(lang), "vi") {
		if t.VI != "" {
			return t.VI
		}
		return t.EN
	}
	if t.EN != "" {
		return t.EN
	}
	return t.VI
}

func (t Text) IsZero() bool { return t.EN == "" && t.VI == "" }

// Components, in display order. Every Finding uses one of these.
const (
	CompSystem     = "system"
	CompCPU        = "cpu"
	CompMemory     = "memory"
	CompDisk       = "disk"
	CompRAID       = "raid"
	CompFilesystem = "filesystem"
	CompThermal    = "thermal"
	CompFan        = "fan"
	CompPower      = "power"
	CompNetwork    = "network"
	CompBMC        = "bmc"
	CompLogs       = "logs"
)

// Components lists every component in display order.
var Components = []string{
	CompSystem, CompCPU, CompMemory, CompDisk, CompRAID, CompFilesystem,
	CompThermal, CompFan, CompPower, CompNetwork, CompBMC, CompLogs,
}

var componentNames = map[string]Text{
	CompSystem:     T("System", "Hệ thống"),
	CompCPU:        T("CPU", "CPU"),
	CompMemory:     T("Memory (RAM)", "Bộ nhớ (RAM)"),
	CompDisk:       T("Disks", "Ổ cứng"),
	CompRAID:       T("RAID & storage pools", "RAID & nhóm lưu trữ"),
	CompFilesystem: T("Filesystems", "Phân vùng & hệ thống tệp"),
	CompThermal:    T("Temperature", "Nhiệt độ"),
	CompFan:        T("Fans", "Quạt"),
	CompPower:      T("Power supply", "Nguồn điện"),
	CompNetwork:    T("Network", "Mạng"),
	CompBMC:        T("Management controller (BMC)", "Bộ điều khiển quản trị (BMC)"),
	CompLogs:       T("System logs", "Nhật ký hệ thống"),
}

// ComponentName returns the display name of a component.
func ComponentName(c string) Text {
	if t, ok := componentNames[c]; ok {
		return t
	}
	return T(c, c)
}

// Part identifies a physical part, so support staff can order a replacement
// or open a warranty case without opening the chassis first.
type Part struct {
	Kind     string `json:"kind"`               // "disk", "dimm", "psu", "fan", "cpu", "nic", "controller", "battery"
	Vendor   string `json:"vendor,omitempty"`   // manufacturer
	Model    string `json:"model,omitempty"`    // model or part number
	Serial   string `json:"serial,omitempty"`   // serial number
	Location string `json:"location,omitempty"` // slot, bay, DIMM locator, /dev path
	Firmware string `json:"firmware,omitempty"`
	Size     string `json:"size,omitempty"` // human readable capacity
}

// Finding is one conclusion a check reached.
type Finding struct {
	// ID is a stable rule identifier, "<domain>.<rule>", e.g.
	// "disk.smart_failed". Tools may key on it, so do not rename casually.
	ID        string   `json:"id"`
	Component string   `json:"component"`
	Severity  Severity `json:"severity"`
	// Target names the affected thing: "/dev/sda", "md0", "DIMM A1", "PSU 2".
	Target string `json:"target,omitempty"`
	Title  Text   `json:"title"`  // one line, says what is wrong (or right)
	Detail Text   `json:"detail"` // what was measured and why it matters
	Action Text   `json:"action"` // what to do next, concretely
	// Evidence holds the raw lines the conclusion is based on (at most ~10).
	Evidence []string `json:"evidence,omitempty"`
	Part     *Part    `json:"part,omitempty"`
}

// Table is a generic table the report renders as is. Domains use tables to
// show inventory and measurements (disks with SMART values, DIMMs, sensors).
type Table struct {
	ID      string `json:"id"`
	Title   Text   `json:"title"`
	Columns []Text `json:"columns"`
	Rows    []Row  `json:"rows"`
	Note    Text   `json:"note,omitempty"`
}

// Row is one table row. Status colours the row; Cells align with Columns.
//
// Cells are in English, or language-neutral (numbers, device names, model
// and serial strings). VI, when set, holds the Vietnamese version of every
// cell (same length as Cells); it is left out when no cell has words to
// translate. Build rows with NewRow and read them with CellsIn or Cell;
// consumers that only know Cells keep working (they see English).
type Row struct {
	Status Severity `json:"status"`
	Cells  []string `json:"cells"`
	VI     []string `json:"vi,omitempty"`
}

// NewRow builds a row. Each cell is a string (the same in both languages)
// or a Text (English and Vietnamese); any other value is formatted with
// fmt.Sprint. VI is set only when some cell differs between the languages.
func NewRow(status Severity, cells ...any) Row {
	r := Row{Status: status, Cells: make([]string, 0, len(cells))}
	for _, c := range cells {
		r.Add(c)
	}
	return r
}

// cellText turns a NewRow cell into a Text with both languages filled.
func cellText(v any) Text {
	switch c := v.(type) {
	case nil:
		return Text{}
	case string:
		return Text{EN: c, VI: c}
	case Text:
		return Text{EN: c.In("en"), VI: c.In("vi")}
	case *Text:
		if c == nil {
			return Text{}
		}
		return Text{EN: c.In("en"), VI: c.In("vi")}
	}
	s := fmt.Sprint(v)
	return Text{EN: s, VI: s}
}

// Add appends a cell (string or Text, as in NewRow).
func (r *Row) Add(v any) {
	t := cellText(v)
	r.Cells = append(r.Cells, t.EN)
	if r.VI != nil || t.VI != t.EN {
		r.fillVI()
		r.VI[len(r.VI)-1] = t.VI
	}
}

// SetCell replaces cell i (string or Text); it does nothing when i is out
// of range.
func (r *Row) SetCell(i int, v any) {
	if i < 0 || i >= len(r.Cells) {
		return
	}
	t := cellText(v)
	r.Cells[i] = t.EN
	if r.VI != nil || t.VI != t.EN {
		r.fillVI()
		r.VI[i] = t.VI
	}
}

// fillVI makes VI as long as Cells, copying the cells it lacks (those are
// language-neutral).
func (r *Row) fillVI() {
	if len(r.VI) > len(r.Cells) {
		r.VI = r.VI[:len(r.Cells)]
	}
	for i := len(r.VI); i < len(r.Cells); i++ {
		r.VI = append(r.VI, r.Cells[i])
	}
}

// Cell returns cell i in lang ("vi" or "en"), or "" when there is no such
// cell. A Vietnamese cell falls back to the English one when VI is absent,
// shorter, or empty at i.
func (r Row) Cell(i int, lang string) string {
	if i < 0 || i >= len(r.Cells) {
		return ""
	}
	if isVI(lang) && i < len(r.VI) && r.VI[i] != "" {
		return r.VI[i]
	}
	return r.Cells[i]
}

// CellsIn returns the cells in lang ("vi" or "en").
func (r Row) CellsIn(lang string) []string {
	if !isVI(lang) || len(r.VI) == 0 {
		return r.Cells
	}
	out := make([]string, len(r.Cells))
	for i := range r.Cells {
		out[i] = r.Cell(i, lang)
	}
	return out
}

// CellText returns cell i in both languages.
func (r Row) CellText(i int) Text { return Text{EN: r.Cell(i, "en"), VI: r.Cell(i, "vi")} }

func isVI(lang string) bool { return strings.HasPrefix(strings.ToLower(lang), "vi") }

// Coverage states, so a report never implies that something was checked
// when it was not.
const (
	CovRan     = "ran"     // check ran fully
	CovPartial = "partial" // ran, but some data was unavailable
	CovSkipped = "skipped" // not applicable or not possible (tool missing, not root, VM)
	CovFailed  = "failed"  // tried and failed unexpectedly
)

// Coverage records whether one check ran.
type Coverage struct {
	ID        string `json:"id"`               // "<domain>.<check>", e.g. "disk.smart"
	Component string `json:"component"`        // which component this check covers (Comp* constant)
	Name      Text   `json:"name"`             // "S.M.A.R.T. health"
	State     string `json:"state"`            // one of the Cov* constants
	Reason    Text   `json:"reason,omitempty"` // why it was skipped/partial
	Fix       Text   `json:"fix,omitempty"`    // how to enable it, in words
	// Cmd is the one command that enables the check, ready to copy and
	// paste (e.g. "dnf install -y smartmontools"). Optional; when set, Fix
	// should not repeat it.
	Cmd string `json:"cmd,omitempty"`
	// NotApplicable marks a skipped check that cannot exist on this
	// platform or is covered by another check (Windows has no throttle
	// counters; machine checks are read from the event log). It is not a
	// gap: the component is not "partially checked" because of it.
	NotApplicable bool `json:"notApplicable,omitempty"`
}

// Result is what one domain check returns.
type Result struct {
	Domain   string     `json:"domain"`
	Findings []Finding  `json:"findings"`
	Tables   []Table    `json:"tables,omitempty"`
	Coverage []Coverage `json:"coverage,omitempty"`
	// Facts is the domain's typed data for JSON consumers.
	Facts any `json:"facts,omitempty"`
}

// Env describes the machine a bundle came from.
type Env struct {
	OS        string    `json:"os"`                // "linux", "windows" or "bmc" (out-of-band)
	Root      bool      `json:"root"`              // ran as root / Administrator
	Virtual   string    `json:"virtual,omitempty"` // "" on bare metal, else e.g. "kvm", "vmware", "microsoft", "wsl", "lxc"
	Container bool      `json:"container,omitempty"`
	Distro    string    `json:"distro,omitempty"`    // os-release ID (almalinux, ubuntu, debian, rhel, centos, proxmox...) or "windows"
	DistroVer string    `json:"distroVer,omitempty"` // os-release VERSION_ID
	Like      string    `json:"like,omitempty"`      // os-release ID_LIKE
	PM        string    `json:"pm,omitempty"`        // package manager: dnf, yum, apt, zypper, apk, pacman
	SinceDays int       `json:"sinceDays"`           // log window
	Now       time.Time `json:"now"`                 // when collection finished (on the target's clock)
}

// Bare reports whether the machine looks like physical hardware.
func (e Env) Bare() bool { return e.Virtual == "" && !e.Container }

// HostInfo identifies the server at the top of a report.
type HostInfo struct {
	Hostname string    `json:"hostname"`
	OS       string    `json:"os,omitempty"`     // "AlmaLinux 9.4 (Seafoam Ocelot)", "Windows Server 2022 Standard"
	Kernel   string    `json:"kernel,omitempty"` // kernel or build number
	Arch     string    `json:"arch,omitempty"`
	Vendor   string    `json:"vendor,omitempty"` // "Dell Inc."
	Model    string    `json:"model,omitempty"`  // "PowerEdge R740"
	Serial   string    `json:"serial,omitempty"` // chassis/system serial (service tag)
	BIOS     string    `json:"bios,omitempty"`   // "2.12.2 (2021-07-09)"
	Board    string    `json:"board,omitempty"`
	CPU      string    `json:"cpu,omitempty"` // "2 × Intel Xeon Silver 4214 (24 cores, 48 threads)" (English; see CPUText)
	MemBytes uint64    `json:"memBytes,omitempty"`
	Uptime   float64   `json:"uptime,omitempty"` // seconds
	BootTime time.Time `json:"bootTime,omitzero"`
	Virtual  string    `json:"virtual,omitempty"`
	BMC      string    `json:"bmc,omitempty"` // BMC address or firmware, when known
	// The parts of the CPU line, so it can be written in either language:
	// CPUModel "Intel Xeon Silver 4214", Sockets 2, Cores 24 (all sockets),
	// Threads 48. Zero when unknown.
	CPUModel string `json:"cpuModel,omitempty"`
	Sockets  int    `json:"sockets,omitempty"`
	Cores    int    `json:"cores,omitempty"`
	Threads  int    `json:"threads,omitempty"`
}

// SetCPU fills the CPU line and its parts.
func (h *HostInfo) SetCPU(model string, sockets, cores, threads int) {
	h.CPUModel, h.Sockets, h.Cores, h.Threads = model, sockets, cores, threads
	h.CPU = CPUSummary(model, sockets, cores, threads).EN
}

// CPUText is the CPU line in both languages. Reports written before the
// parts existed only have CPU, which is then used for both.
func (h HostInfo) CPUText() Text {
	if h.CPUModel == "" && h.Cores == 0 && h.Threads == 0 {
		return Text{EN: h.CPU, VI: h.CPU}
	}
	return CPUSummary(h.CPUModel, h.Sockets, h.Cores, h.Threads)
}

// CPUSummary formats "2 × Intel Xeon Silver 4214 (24 cores, 48 threads)" /
// "2 × Intel Xeon Silver 4214 (24 nhân, 48 luồng)". Cores and threads are
// totals over all sockets; zero values are left out. It returns an empty
// Text when nothing is known.
func CPUSummary(model string, sockets, cores, threads int) Text {
	if model == "" && cores <= 0 && threads <= 0 {
		return Text{}
	}
	var en, vi []string
	if cores > 0 {
		en = append(en, plural(cores, "core", "cores"))
		vi = append(vi, fmt.Sprintf("%d nhân", cores))
	}
	if threads > 0 {
		en = append(en, plural(threads, "thread", "threads"))
		vi = append(vi, fmt.Sprintf("%d luồng", threads))
	}
	s := model
	if s == "" {
		s = "CPU"
	}
	if sockets > 1 {
		s = fmt.Sprintf("%d × %s", sockets, s)
	}
	t := Text{EN: s, VI: s}
	if len(en) > 0 {
		t.EN += " (" + strings.Join(en, ", ") + ")"
		t.VI += " (" + strings.Join(vi, ", ") + ")"
	}
	return t
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// ComponentSummary is the worst severity and the finding counts per component.
type ComponentSummary struct {
	Component string   `json:"component"`
	Name      Text     `json:"name"`
	Severity  Severity `json:"severity"`
	Crit      int      `json:"crit"`
	Warn      int      `json:"warn"`
	Info      int      `json:"info"`
	Checked   bool     `json:"checked"` // at least one check for it ran
	// Partial is set when the component was checked but some of its checks
	// were skipped, partial or failed (e.g. disks listed but S.M.A.R.T.
	// unreadable without root).
	Partial bool `json:"partial,omitempty"`
}

// Report is the complete result of one diagnosis.
type Report struct {
	Tool      string             `json:"tool"`
	Version   string             `json:"version"`
	Host      HostInfo           `json:"host"`
	Env       Env                `json:"env"`
	Collected time.Time          `json:"collected"`
	Seconds   float64            `json:"seconds"` // how long collection took
	Verdict   Severity           `json:"verdict"`
	Summary   []ComponentSummary `json:"summary"`
	Findings  []Finding          `json:"findings"` // most severe first
	Results   []Result           `json:"results"`
	Coverage  []Coverage         `json:"coverage"`
	Notes     []Text             `json:"notes,omitempty"` // report-wide notes (VM, not root, ...)
}
