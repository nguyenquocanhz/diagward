//go:build !unix && !windows

package collect

import "os/exec"

func prepareTree(*exec.Cmd) {}

type plainTree struct{ cmd *exec.Cmd }

func attachTree(cmd *exec.Cmd) procTree { return plainTree{cmd} }

func (t plainTree) stop()  { _ = t.cmd.Process.Kill() }
func (t plainTree) kill()  { _ = t.cmd.Process.Kill() }
func (t plainTree) close() {}
