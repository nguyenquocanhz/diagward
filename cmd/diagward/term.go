package main

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// consoleState is what the console can show.
type consoleState struct {
	utf8 bool // can show UTF-8 (box drawing, Vietnamese); false = --ascii
	vt   bool // understands ANSI escape sequences (colour, line clearing)
}

type fder interface{ Fd() uintptr }

func isTerminal(f any) bool {
	if x, ok := f.(fder); ok {
		return term.IsTerminal(int(x.Fd()))
	}
	return false
}

// terminalWidth is the width of the terminal f is attached to, or 100.
func terminalWidth(f any) int {
	if x, ok := f.(fder); ok {
		if w, _, err := term.GetSize(int(x.Fd())); err == nil && w >= 20 {
			return w
		}
	}
	return 100
}

func readPasswordStdin() (string, error) {
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	return string(b), err
}

// unixConsole decides what a Unix terminal can show: UTF-8 unless the
// locale explicitly is not (LANG=C, ISO-8859-x) or it is the Linux text
// console (TERM=linux), whose default font has no Vietnamese glyphs.
func unixConsole(getenv func(string) string) consoleState {
	st := consoleState{utf8: true, vt: true}
	if getenv("TERM") == "linux" {
		st.utf8 = false
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := strings.ToLower(getenv(k))
		if v == "" {
			continue
		}
		if !strings.Contains(v, "utf-8") && !strings.Contains(v, "utf8") {
			st.utf8 = false
		}
		break
	}
	return st
}
