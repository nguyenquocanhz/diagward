//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

func setupConsole() (consoleState, func()) { return unixConsole(os.Getenv), func() {} }

func consoleProcessCount() (uint32, error) { return 0, errors.New("not windows") }

func userLocale() string { return "" }

func isPrivileged() bool { return os.Geteuid() == 0 }

func openInBrowser(path string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.Command(name, path).Start()
}
