//go:build !windows

package apply

import "os/exec"

func hideConsole(cmd *exec.Cmd) {}
