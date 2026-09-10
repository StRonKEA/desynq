package main

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"
	"sync/atomic"

	"fyne.io/systray"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// trayFlag starts the application with no window, which is what a sign-in
// should do: leave an icon in the notification area, not interrupt.
const trayFlag = "-tray"

//go:embed icon_green.ico
var trayIconGreen []byte

//go:embed icon_red.ico
var trayIconRed []byte

//go:embed icon_gray.ico
var trayIconGray []byte

var (
	trayLive       atomic.Bool
	trayAutostart  *systray.MenuItem
	trayLastStatus atomic.Value // string, so the tooltip is only rewritten on change
	trayLastIcon   atomic.Value // string, so icon bytes are only sent on change
)

// startTray puts the application in the notification area.
//
// Wails v2 has no tray of its own — the support prototyped for it never
// reached the public API — so fyne.io/systray runs on its own locked thread
// with its own message loop, beside the webview's. That is safe on Windows;
// the known conflict between the two is a macOS main-thread rule, and this
// application is Windows-only.
func (a *App) startTray() {
	go func() {
		runtime.LockOSThread()
		systray.Run(a.trayReady, func() {})
	}()
}

func (a *App) trayReady() {
	systray.SetIcon(trayIconGray)
	systray.SetTitle("Desynq")
	systray.SetTooltip("Desynq")

	// Left click opens the window, right click opens the menu — what Windows
	// users already expect of a tray icon.
	systray.SetOnTapped(a.ShowWindow)

	open := systray.AddMenuItem("Open Desynq", "Show the window")
	check := systray.AddMenuItem("Check now", "Re-measure the configured sites")
	systray.AddSeparator()
	trayAutostart = systray.AddMenuItemCheckbox(
		"Start with Windows", "Sign in to a tray icon, with no window", autostartEnabled())
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit", "Close the window and the tray icon")

	trayLive.Store(true)
	a.refreshTray(a.snapshot(false))

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				a.ShowWindow()
			case <-check.ClickedCh:
				// Routed through the window rather than measured here, so the
				// tray and the button share one code path and one place to
				// show progress.
				a.ShowWindow()
				a.emit("tray:check", "")
			case <-trayAutostart.ClickedCh:
				if msg := a.SetAutostart(!trayAutostart.Checked()); msg != "" {
					a.emit("app:error", msg)
				}
			case <-quit.ClickedCh:
				a.Quit()
			}
		}
	}()
}

// refreshTray keeps the tooltip honest about what is running, because the tray
// icon is the only thing on screen once the window is hidden.
func (a *App) refreshTray(s Snapshot) {
	if !trayLive.Load() {
		return
	}

	var status string
	switch {
	case !s.Installed && !anyPinned(s) && !s.DNSDiverter:
		status = "protection off"
	case s.DNSDiverter:
		status = "all traffic protected (DoH)"
	case s.Running:
		status = "service running"
	case anyPinned(s):
		status = "sites pinned (hosts)"
	default:
		status = "service " + s.Service
	}
	if s.Strays > 0 {
		status += fmt.Sprintf(" · %d stray engine(s)", s.Strays)
	}

	tip := fmt.Sprintf("Desynq — %s\n%d site(s)", status, len(s.Sites))
	if prev, _ := trayLastStatus.Load().(string); prev != tip {
		trayLastStatus.Store(tip)
		systray.SetTooltip(tip)
	}

	// Dynamic colored tray icon:
	// Green = Active & Healthy
	// Red = Active but issue with one or more sites
	// Gray = Inactive / Off
	var iconBytes []byte
	var iconKey string

	hasBad := false
	for _, site := range s.Sites {
		if site.Measured && site.System != "OK" {
			hasBad = true
			break
		}
	}

	isActive := s.Running || s.DNSDiverter || (s.Installed && anyPinned(s))
	if isActive {
		if hasBad {
			iconBytes = trayIconRed
			iconKey = "red"
		} else {
			iconBytes = trayIconGreen
			iconKey = "green"
		}
	} else {
		iconBytes = trayIconGray
		iconKey = "gray"
	}

	if prevIcon, _ := trayLastIcon.Load().(string); prevIcon != iconKey {
		trayLastIcon.Store(iconKey)
		systray.SetIcon(iconBytes)
	}

	if trayAutostart != nil {
		if autostartEnabled() {
			trayAutostart.Check()
		} else {
			trayAutostart.Uncheck()
		}
	}
}

func anyPinned(s Snapshot) bool {
	for _, site := range s.Sites {
		if site.Pinned {
			return true
		}
	}
	return false
}

// ShowWindow brings the window back from the tray.
func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	wruntime.WindowShow(a.ctx)
	wruntime.WindowUnminimise(a.ctx)
}

// Quit ends the application for real.
//
// Worth being explicit in the UI about what this does not do: an installed
// service and any hosts-file pins keep working, because they are the bypass
// and this window is only its instrument panel.
func (a *App) Quit() {
	a.quitting.Store(true)
	a.stopDNSDiverter()
	if trayLive.Load() {
		systray.Quit()
	}
	if a.ctx != nil {
		wruntime.Quit(a.ctx)
	}
}

// beforeClose sends the window to the tray instead of ending the process, so
// the icon survives the close button. Quit, from the menu or the window, is the
// way out.
func (a *App) beforeClose(ctx context.Context) bool {
	if a.quitting.Load() {
		return false
	}
	wruntime.WindowHide(ctx)
	return true
}
