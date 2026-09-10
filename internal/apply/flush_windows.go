//go:build windows

package apply

import (
	"syscall"
)

var (
	modDnsapi         = syscall.NewLazyDLL("dnsapi.dll")
	procDnsFlushCache = modDnsapi.NewProc("DnsFlushResolverCache")
)

// FlushDNSCache clears the Windows DNS resolver cache immediately.
func FlushDNSCache() error {
	r1, _, err := procDnsFlushCache.Call()
	if r1 == 0 {
		return err
	}
	return nil
}
