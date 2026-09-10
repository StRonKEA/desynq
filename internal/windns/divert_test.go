package windns

import (
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

type WinDivertAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Data      [64]byte
}

func TestWinDivertOpenClose(t *testing.T) {
	dllPath, _ := filepath.Abs("../../tools/zapret-winws/WinDivert.dll")
	dll := syscall.NewLazyDLL(dllPath)
	procOpen := dll.NewProc("WinDivertOpen")
	procClose := dll.NewProc("WinDivertClose")

	filter, _ := syscall.BytePtrFromString("false")
	// layer=0 (network), priority=0, flags=0
	handle, _, err := procOpen.Call(uintptr(unsafe.Pointer(filter)), 0, 0, 0)
	if handle == ^uintptr(0) || handle == 0 {
		// Needs admin to actually open WinDivert handle.
		t.Logf("WinDivertOpen returned (needs admin to open): %v", err)
		return
	}
	t.Logf("WinDivertOpen handle: %v", handle)
	procClose.Call(handle)
}
