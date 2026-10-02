package system

import (
	"strconv"
	"strings"
)

// Load is the load/pressure snapshot.
type Load struct {
	CPUs         int            `json:"cpus,omitempty"`
	Load1        float64        `json:"load1"`
	Load5        float64        `json:"load5"`
	Load15       float64        `json:"load15"`
	IOWaitPct    *float64       `json:"iowaitPct,omitempty"` // over a 1 s sample
	StealPct     *float64       `json:"stealPct,omitempty"`
	ProcsBlocked int            `json:"procsBlocked,omitempty"`
	PSI          map[string]PSI `json:"psi,omitempty"` // "cpu some", "io full", ...
	// Windows
	CPUPct       *float64 `json:"cpuPct,omitempty"`
	QueuePerCPU  *float64 `json:"queuePerCpu,omitempty"`
	DiskIdlePct  *float64 `json:"diskIdlePct,omitempty"`
	DiskQueueLen *float64 `json:"diskQueueLen,omitempty"`
}

// PSI is one line of /proc/pressure/* (percentages of wall time).
type PSI struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
}

// parseLoadavg parses /proc/loadavg: "0.98 0.62 0.30 2/182 1796".
func parseLoadavg(s string) (l1, l5, l15 float64, ok bool) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return 0, 0, 0, false
	}
	var err1, err2, err3 error
	l1, err1 = strconv.ParseFloat(f[0], 64)
	l5, err2 = strconv.ParseFloat(f[1], 64)
	l15, err3 = strconv.ParseFloat(f[2], 64)
	if err1 != nil || err2 != nil || err3 != nil || l1 < 0 || l5 < 0 || l15 < 0 {
		return 0, 0, 0, false
	}
	return l1, l5, l15, true
}

// parsePSI parses the collector's "cpu some avg10=0.72 avg60=2.01 avg300=2.73 total=…"
// lines (the resource name prefixed to the kernel's format, see
// Documentation/accounting/psi.rst).
func parsePSI(s string) map[string]PSI {
	m := map[string]PSI{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || (f[1] != "some" && f[1] != "full") {
			continue
		}
		var p PSI
		n := 0
		for _, kv := range f[2:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil || x < 0 || x > 100 {
				continue
			}
			switch k {
			case "avg10":
				p.Avg10 = x
				n++
			case "avg60":
				p.Avg60 = x
				n++
			case "avg300":
				p.Avg300 = x
				n++
			}
		}
		if n == 3 {
			m[f[0]+" "+f[1]] = p
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

type statSample struct {
	iowait, steal, total uint64
}

// parseStat reads the collector's two /proc/stat samples and returns
// iowait and steal as a percentage of all CPU time between them, plus
// btime and procs_blocked. Field order (proc(5)): user nice system idle
// iowait irq softirq steal guest guest_nice; guest time is already counted
// in user, so only the first eight fields make up the total.
func parseStat(s string) (iowait, steal *float64, btime int64, blocked int) {
	var samples []statSample
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "cpu":
			var v [8]uint64
			n := 0
			for i := 1; i < len(f) && i <= 8; i++ {
				x, err := strconv.ParseUint(f[i], 10, 64)
				if err != nil {
					break
				}
				v[i-1] = x
				n++
			}
			if n < 5 {
				continue
			}
			var t statSample
			for i := 0; i < n; i++ {
				t.total += v[i]
			}
			t.iowait = v[4]
			if n >= 8 {
				t.steal = v[7]
			}
			samples = append(samples, t)
		case "btime":
			if len(f) > 1 {
				btime, _ = strconv.ParseInt(f[1], 10, 64)
			}
		case "procs_blocked":
			if len(f) > 1 {
				blocked, _ = strconv.Atoi(f[1])
			}
		}
	}
	if len(samples) < 2 {
		return nil, nil, btime, blocked
	}
	a, b := samples[0], samples[len(samples)-1]
	if b.total <= a.total || b.iowait < a.iowait || b.steal < a.steal {
		return nil, nil, btime, blocked
	}
	d := float64(b.total - a.total)
	io := float64(b.iowait-a.iowait) * 100 / d
	st := float64(b.steal-a.steal) * 100 / d
	return &io, &st, btime, blocked
}

// parseUptime parses /proc/uptime ("527.16 900.79") or meta.ident's value.
func parseUptime(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	x, err := strconv.ParseFloat(f[0], 64)
	if err != nil || x < 0 {
		return 0
	}
	return x
}

// Kernel taint flags, from Documentation/admin-guide/tainted-kernels.rst.
// Only flags that hint at hardware or firmware trouble are reported.
const (
	taintOutOfSpec  = 2  // S: SMP with CPUs not designed for it / out-of-spec system
	taintMCE        = 4  // M: a machine check exception occurred
	taintBadPage    = 5  // B: bad page referenced or unexpected page flags
	taintDied       = 7  // D: kernel died recently (OOPS or BUG)
	taintWarn       = 9  // W: kernel issued a warning
	taintFirmware   = 11 // I: workaround for a platform firmware bug
	taintSoftLockup = 14 // L: soft lockup occurred
)

func parseTaint(s string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return v, err == nil
}

// clockSynced reads timedatectl ("System clock synchronized: yes", or
// "NTP synchronized: yes" on systemd < 239 such as CentOS 7) or chronyc
// tracking ("Leap status : Normal" / "Not synchronised").
func clockSynced(timedatectl, chrony string) (synced, known bool, line string) {
	for _, l := range strings.Split(timedatectl, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "system clock synchronized", "ntp synchronized":
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "yes":
				return true, true, strings.TrimSpace(l)
			case "no":
				return false, true, strings.TrimSpace(l)
			}
		}
	}
	for _, l := range strings.Split(chrony, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) != "Leap status" {
			continue
		}
		v = strings.TrimSpace(v)
		if strings.EqualFold(v, "Not synchronised") {
			return false, true, strings.TrimSpace(l)
		}
		if v != "" {
			return true, true, strings.TrimSpace(l)
		}
	}
	return false, false, ""
}
