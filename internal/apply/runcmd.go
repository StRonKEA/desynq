package apply

import (
	"context"
	"os/exec"
)

func runCombined(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	return cmd.CombinedOutput()
}

func runArgv(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	hideConsole(cmd)
	return cmd.CombinedOutput()
}
