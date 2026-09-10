package main

import (
	"errors"
	"os/exec"
	"path/filepath"

	"dpi/internal/apply"
	"golang.org/x/sys/windows/registry"
)

// cleanLegacyRunKey ensures Desynq is never added as a regular startup program
// in Task Manager -> Startup, keeping the application 100% headless service-based.
func cleanLegacyRunKey() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err == nil {
		defer k.Close()
		_ = k.DeleteValue("Desynq")
		_ = k.DeleteValue("dpi-ui")
	}
}

// autostartEnabled reports whether background Windows Service autostart is enabled.
func autostartEnabled() bool {
	cleanLegacyRunKey()
	dir := filepath.Join(appRoot(), "config")
	set, err := apply.LoadSettings(dir)
	if err != nil {
		return true // Default: true (Install & Forget model)
	}
	return set.AutostartEnabled()
}

func setAutostart(on bool) error {
	cleanLegacyRunKey()
	dir := filepath.Join(appRoot(), "config")
	set, err := apply.LoadSettings(dir)
	if err != nil && !errors.Is(err, apply.ErrNoHosts) {
		set = apply.Settings{}
	}
	set.Autostart = &on
	_ = apply.SaveSettings(dir, set)

	// Configure Windows Services start type if they exist
	startType := "demand"
	if on {
		startType = "auto"
	}

	_ = exec.Command("sc.exe", "config", "desynq-dpi", "start=", startType).Run()
	_ = exec.Command("sc.exe", "config", "dpi-bypass", "start=", startType).Run()
	_ = exec.Command("sc.exe", "config", "desynq-dns", "start=", startType).Run()
	return nil
}
