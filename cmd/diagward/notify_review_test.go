package main

import (
	"strings"
	"testing"
)

// A missing value after --notify-config or --state must suggest a config
// or state path, not "report.dwb".
func TestNotifyFileArgExample(t *testing.T) {
	for flag, want := range map[string]string{
		"--notify-config": "e.g. --notify-config /etc/diagward/notify.conf",
		"--state":         "e.g. --state /var/lib/diagward/state.json",
	} {
		ta := notifyTestApp()
		args := []string{"check", flag, "-q"}
		if flag == "--state" {
			args = append(args, "--notify-config", "x.conf")
		}
		if code := ta.main(args); code != exitError {
			t.Errorf("%s: exit %d", flag, code)
		}
		if !strings.Contains(ta.err.String(), want) {
			t.Errorf("%s: %s", flag, ta.err)
		}
	}
}
