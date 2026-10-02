//go:build unix

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// prepareTree starts the collector in its own process group, so Ctrl+C in
// the terminal reaches only Diagward (which then stops the collector in an
// orderly way) and the whole group can be signalled at once.
func prepareTree(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

type unixTree struct{ pid int }

func attachTree(cmd *exec.Cmd) procTree { return &unixTree{pid: cmd.Process.Pid} }

func (t *unixTree) stop()  { t.signal(syscall.SIGTERM) }
func (t *unixTree) kill()  { t.signal(syscall.SIGKILL) }
func (t *unixTree) close() {}

// signal sends sig to the collector's process group and to every
// descendant found in /proc. The descendants matter because coreutils
// `timeout` (which the script wraps risky commands in) moves itself and its
// child into a new process group, out of reach of a group signal.
func (t *unixTree) signal(sig syscall.Signal) {
	if t.pid <= 0 {
		return
	}
	pids := descendants(t.pid)
	_ = syscall.Kill(-t.pid, sig)
	for _, p := range pids {
		_ = syscall.Kill(p, sig)
	}
}

// descendants lists the pids below root by reading /proc/<pid>/stat (Linux;
// elsewhere it returns nothing and the group signal has to do).
func descendants(root int) []int {
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	children := map[int][]int{}
	for _, f := range stats {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		pid, ppid, ok := parseProcStat(string(data))
		if ok {
			children[ppid] = append(children[ppid], pid)
		}
	}
	var out []int
	seen := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}
