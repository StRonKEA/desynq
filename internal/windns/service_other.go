//go:build !windows

package windns

import "fmt"

func RunService(toolsDir, dohURL string) error {
	return fmt.Errorf("windows service not supported on this platform")
}
