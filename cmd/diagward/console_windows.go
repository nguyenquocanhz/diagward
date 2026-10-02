//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList    = kernel32.NewProc("GetConsoleProcessList")
	procGetUserDefaultLocaleName = kernel32.NewProc("GetUserDefaultLocaleName")
)

// setupConsole switches the console to UTF-8 output (code page 65001) and
// enables ANSI escape processing (Windows 10 1511+ / Server 2016+). When
// either fails on a real console, output falls back to ASCII without
// colour. The returned function restores the previous settings.
func setupConsole() (consoleState, func()) {
	st := consoleState{utf8: true, vt: true}
	var undo []func()
	if cp, err := windows.GetConsoleOutputCP(); err == nil && cp != 0 && cp != 65001 {
		if windows.SetConsoleOutputCP(65001) == nil {
			undo = append(undo, func() { windows.SetConsoleOutputCP(cp) })
		} else {
			st.utf8, st.vt = false, false
		}
	}
	for _, std := range []uint32{windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		h, err := windows.GetStdHandle(std)
		if err != nil || h == 0 || h == windows.InvalidHandle {
			continue
		}
		var mode uint32
		if windows.GetConsoleMode(h, &mode) != nil {
			continue // redirected to a file or pipe: nothing to set up
		}
		if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
			continue
		}
		if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT) != nil {
			st.utf8, st.vt = false, false
			continue
		}
		old := mode
		undo = append(undo, func() { windows.SetConsoleMode(h, old) })
	}
	return st, func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
}

// consoleProcessCount is the number of processes attached to our console
// (GetConsoleProcessList).
func consoleProcessCount() (uint32, error) {
	if err := procGetConsoleProcessList.Find(); err != nil {
		return 0, err
	}
	var list [8]uint32
	n, _, err := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&list[0])), uintptr(len(list)))
	if n == 0 {
		return 0, err
	}
	return uint32(n), nil
}

// userLocale is the user's default locale name, e.g. "vi-VN".
func userLocale() string {
	if procGetUserDefaultLocaleName.Find() != nil {
		return ""
	}
	var buf [85]uint16 // LOCALE_NAME_MAX_LENGTH
	n, _, _ := procGetUserDefaultLocaleName.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

func isPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

func openInBrowser(path string) error {
	c := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", path)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return c.Start()
}
