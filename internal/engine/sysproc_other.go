//go:build !windows

package engine

import "syscall"

func sysProcAttr() *syscall.SysProcAttr { return nil }
