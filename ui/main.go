package main

import (
	"embed"
	"os"

	"dpi/internal/cli"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wwindows "github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// If invoked with CLI arguments (e.g. from elevated UAC helper),
	// run the engine directly instead of spinning up the GUI.
	if len(os.Args) > 1 && os.Args[1] != trayFlag {
		os.Exit(cli.Run(os.Args[1:]))
	}

	app := NewApp()

	// Started from the Run key, the application should leave an icon in the
	// notification area rather than put a window in front of someone who was
	// only signing in.
	hidden := false
	for _, arg := range os.Args[1:] {
		if arg == trayFlag {
			hidden = true
		}
	}

	err := wails.Run(&options.App{
		Title:       "Desynq",
		Width:       520,
		Height:      720,
		MinWidth:    460,
		MinHeight:   600,
		StartHidden: hidden,
		// The window draws its own title bar: the wordmark, the caption buttons,
		// and the settings button sit on the same light surface as the cards.
		Frameless: true,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Matches --ground in the stylesheet, so a slow first paint does not
		// flash dark on a light window.
		BackgroundColour: &options.RGBA{R: 0xf6, G: 0xf7, B: 0xf9, A: 1},
		Windows: &wwindows.Options{
			Theme: wwindows.Light,
		},
		OnStartup:     app.startup,
		OnBeforeClose: app.beforeClose,
		Bind:          []interface{}{app},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
