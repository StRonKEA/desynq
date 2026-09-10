package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// ErrUACDeclined means the user dismissed the elevation prompt. It is a normal
// answer, not a fault, so the window says so plainly instead of showing an
// error code.
var ErrUACDeclined = errors.New("yönetici onayı reddedildi")

const createNoWindow = 0x08000000

// processElevated reports whether this process already has administrator rights.
// When UAC is off, admin users usually land here already — ShellExecute "runas"
// is then unnecessary and was leaving the window stuck waiting on a prompt that
// never appears.
func processElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// shellExecuteRunas starts a program elevated. Used only when this process is
// not already admin; that is what raises the UAC prompt on machines that have it.
func shellExecuteRunas(file, args, cwd string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	f, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	a, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return err
	}
	d, err := windows.UTF16PtrFromString(cwd)
	if err != nil {
		return err
	}

	const swHide = 0
	if err := windows.ShellExecute(0, verb, f, a, d, swHide); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return ErrUACDeclined
		}
		return err
	}
	return nil
}

// runCmdsHidden runs dpi.exe argument lists with no console window.
//
// Going through cmd.exe made each console-subsystem dpi.exe flash a black
// window even with CREATE_NO_WINDOW on the parent. Spawning dpi.exe itself
// with CREATE_NO_WINDOW is what actually keeps the desktop quiet.
func runCmdsHidden(cli, cwd, logPath, donePath string, cmds [][]string) error {
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logF.Close()

	for _, args := range cmds {
		argv := make([]string, len(args))
		for i, a := range args {
			argv[i] = stripCmdQuotes(a)
		}
		fmt.Fprintf(logF, "+ %s %s\n", cli, strings.Join(argv, " "))
		cmd := exec.Command(cli, argv...)
		cmd.Dir = cwd
		cmd.Stdout = logF
		cmd.Stderr = logF
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: createNoWindow,
		}
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(logF, "exit: %v\n", err)
			_ = os.WriteFile(donePath, []byte("done\n"), 0o644)
			return err
		}
	}
	return os.WriteFile(donePath, []byte("done\n"), 0o644)
}

func stripCmdQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// writeElevateVBS elevates a pre-written .cmd via wscript with window style 0,
// so the UAC path does not flash a visible console for each dpi.exe line.
func writeElevateVBS(path, scriptPath string) error {
	// Run 0 = hidden. Wait True so the sentinel is written before wscript exits.
	body := fmt.Sprintf(
		"CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"%s\"\"\", 0, True\r\n",
		scriptPath,
	)
	return os.WriteFile(path, []byte(body), 0o644)
}
