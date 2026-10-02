// Package logs is the "logs" domain check: kernel log / journal patterns that
// reveal failing hardware, unexpected reboots and kernel crash dumps on
// Linux, and the System event log (disk, NTFS, WHEA, bugchecks, NIC) on
// Windows.
package logs

import (
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// Facts is the typed data of the logs domain.
type Facts struct {
	Sources          []string    `json:"sources,omitempty"` // journal, syslog, dmesg, eventlog
	Persistent       bool        `json:"persistentJournal,omitempty"`
	WindowDays       int         `json:"windowDays"`
	LinesChecked     int         `json:"linesChecked,omitempty"`
	Events           []EventFact `json:"events,omitempty"`
	Boots            []BootFact  `json:"boots,omitempty"`
	UncleanShutdowns int         `json:"uncleanShutdowns"`
	CrashDumps       []CrashDump `json:"crashDumps,omitempty"`
	WinProviders     []WinCount  `json:"winProviders,omitempty"`
}

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	res := model.Result{Domain: "logs"}
	if b == nil {
		return res
	}
	facts := &Facts{WindowDays: env.SinceDays}
	switch {
	case b.Get("logs.win_events") != nil:
		windowsEvents(b, env, &res, facts)
	default:
		linuxKernel(b, env, &res, facts)
		linuxReboots(b, env, &res, facts)
	}
	if len(res.Findings) == 0 && len(res.Coverage) == 0 && len(res.Tables) == 0 {
		return res
	}
	res.Facts = facts
	return res
}
