//go:build windows

package collect

import (
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// prepareTree starts PowerShell in a new process group so that Ctrl+C in
// the console reaches only Diagward, which then stops the collector itself.
func prepareTree(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
}

// winTree holds the collector in a job object: terminating the job ends
// PowerShell and every program it started (smartctl, storcli, ...), and the
// job's kill-on-close limit cleans up even if Diagward itself dies.
type winTree struct {
	pid int
	job windows.Handle
}

func attachTree(cmd *exec.Cmd) procTree {
	t := &winTree{pid: cmd.Process.Pid}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return t
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return t
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(t.pid))
	if err != nil {
		windows.CloseHandle(job)
		return t
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		windows.CloseHandle(job)
		return t
	}
	t.job = job
	return t
}

// stop has no polite form on Windows (PowerShell in its own process group
// ignores Ctrl+C); the collector only reads, so terminating is safe.
func (t *winTree) stop() { t.kill() }

func (t *winTree) kill() {
	if t.job != 0 {
		if windows.TerminateJobObject(t.job, 1) == nil {
			return
		}
	}
	// No job (assignment failed, e.g. an old OS without nested jobs):
	// taskkill walks the tree by parent pid.
	c := exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(t.pid))
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = c.Run()
}

func (t *winTree) close() {
	if t.job != 0 {
		windows.CloseHandle(t.job)
		t.job = 0
	}
}
