//go:build !windows

package apply

// FlushDNSCache is a no-op on non-Windows platforms.
func FlushDNSCache() error {
	return nil
}
