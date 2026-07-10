//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// enableVT turns on ANSI/virtual-terminal processing for the Windows console
// so escape codes render as colors instead of raw text. No-op on failure.
func enableVT() {
	const enableVirtualTerminalProcessing = 0x0004
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	for _, h := range []syscall.Handle{syscall.Stdout, syscall.Stderr} {
		var mode uint32
		if r, _, _ := getConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
			continue
		}
		setConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	}
}
