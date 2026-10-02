package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// doubleClick is "diagward" started from Explorer: check, write an HTML
// report next to the exe (or in %TEMP%), open it in the browser and keep
// the console window open until Enter.
func (a *app) doubleClick() int {
	fmt.Fprintf(a.stdout, "Diagward %s: %s\n\n", version, a.t("server hardware check", "kiểm tra phần cứng máy chủ"))
	code := a.cmdCheck(nil, true)
	fmt.Fprintln(a.stdout)
	fmt.Fprint(a.stdout, a.t("Press Enter to close this window...", "Nhấn Enter để đóng cửa sổ..."))
	a.readLine()
	return code
}

// doubleClickHTMLPath picks where the HTML report goes: next to the exe
// when that folder is writable, else the temp folder.
func (a *app) doubleClickHTMLPath() string {
	host, _ := os.Hostname()
	name := defaultName(host, a.now(), ".html")
	for _, dir := range []string{a.exeDir(), os.TempDir()} {
		if dir != "" && writable(dir) {
			return filepath.Join(dir, name)
		}
	}
	return name
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".diagward-w*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return filepath.Dir(p)
}

// readLine reads one line from stdin (for confirmations and "press Enter").
func (a *app) readLine() string {
	if a.in == nil {
		a.in = bufio.NewReader(a.stdin)
	}
	s, _ := a.in.ReadString('\n')
	return strings.TrimSpace(s)
}
