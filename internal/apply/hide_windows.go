//go:build windows

package apply

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// hideConsole prevents sc/netsh/tasklist console flashes when called from the UI.
func hideConsole(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
