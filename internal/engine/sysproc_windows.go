//go:build windows

package engine

import "syscall"

const createNoWindow = 0x08000000

// sysProcAttr hides the winws2 console. Without this, every strategy probe
// during search flashes a black command window.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
