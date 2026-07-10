//go:build !windows

package main

// enableVT is a no-op on non-Windows platforms, where terminals handle ANSI
// escape codes natively.
func enableVT() {}
