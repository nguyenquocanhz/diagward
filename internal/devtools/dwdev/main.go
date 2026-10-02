// Command dwdev is a developer tool: it runs the collector locally (or in
// WSL for Linux when started on Windows), prints sections, saves bundles and
// prints the analysis as JSON. It is not shipped.
//
//	go run ./internal/devtools/dwdev -os linux -list
//	go run ./internal/devtools/dwdev -os linux -section disk.lsblk
//	go run ./internal/devtools/dwdev -os windows -analyze
//	go run ./internal/devtools/dwdev -os linux -save /tmp/x.dwb
//	go run ./internal/devtools/dwdev -load x.dwb -analyze
//	go run ./internal/devtools/dwdev -os linux -script > collector.sh
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/diag"
)

func main() {
	osName := flag.String("os", runtime.GOOS, "linux or windows")
	list := flag.Bool("list", false, "list sections")
	section := flag.String("section", "", "print one section (prefix match)")
	analyze := flag.Bool("analyze", false, "print the analysis as JSON")
	save := flag.String("save", "", "save the bundle to this .dwb file")
	load := flag.String("load", "", "analyse a saved bundle instead of collecting")
	script := flag.Bool("script", false, "print the assembled script and exit")
	since := flag.Int("since", 7, "log window in days")
	flag.Parse()

	if *script {
		s, err := collect.Script(*osName, "SCRIPTTEST", collect.Options{SinceDays: *since})
		check(err)
		fmt.Print(s)
		return
	}

	var b *collect.Bundle
	if *load != "" {
		f, err := os.Open(*load)
		check(err)
		b, err = collect.Read(f)
		f.Close()
		check(err)
	} else {
		b = run(*osName, collect.Options{SinceDays: *since})
	}
	if *save != "" {
		f, err := os.Create(*save)
		check(err)
		check(collect.Write(f, b))
		check(f.Close())
		fmt.Fprintln(os.Stderr, "saved", *save)
	}
	if *list {
		for _, s := range b.Sections {
			st := fmt.Sprintf("rc=%d", s.RC)
			if s.Missing != "" {
				st = "missing=" + s.Missing
			}
			if s.Skipped != "" {
				st = "skipped=" + s.Skipped
			}
			if s.Timeout {
				st += " timeout"
			}
			fmt.Printf("%-40s %-24s %6d bytes %5d ms\n", s.Name, st, len(s.Out), s.MS)
		}
		if b.Noise != "" {
			fmt.Printf("\nnoise:\n%s\n", b.Noise)
		}
	}
	if *section != "" {
		for _, s := range b.Prefix(*section) {
			fmt.Printf("==== %s (rc=%d missing=%q skipped=%q)\n%s\n", s.Name, s.RC, s.Missing, s.Skipped, s.Out)
			if s.Err != "" {
				fmt.Printf("---- stderr\n%s\n", s.Err)
			}
		}
	}
	if *analyze {
		rep := diag.Analyze(b)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(rep))
	}
}

func run(osName string, o collect.Options) *collect.Bundle {
	bnd := collect.NewBoundary()
	s, err := collect.Script(osName, bnd, o)
	check(err)
	name, args := collect.Command(osName)
	if osName == collect.OSLinux && runtime.GOOS == "windows" {
		name, args = "wsl.exe", append([]string{"-e"}, append([]string{name}, args...)...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(s)
	cmd.Stderr = os.Stderr
	start := time.Now()
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "collector:", err)
	}
	secs, noise := collect.ParseFramed(string(out), bnd)
	host, _ := os.Hostname()
	return &collect.Bundle{
		Format: collect.BundleFormat, Tool: "dwdev", OS: osName, Host: host,
		Started: start, Finished: time.Now(), Options: o, Sections: secs, Noise: noise,
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
