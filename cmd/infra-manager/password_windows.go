//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode = kernel32.NewProc("GetConsoleMode")
	setConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableEchoInput = 0x0004 // ENABLE_ECHO_INPUT of the Windows console

// hideInput turns off the echo of the console on stdin and returns the function
// that puts it back. An error means "stdin is not a console" (a pipe): there is
// nothing to hide then.
func hideInput() (restore func(), err error) {
	handle := os.Stdin.Fd()
	var mode uint32
	if r, _, callErr := getConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return nil, callErr
	}
	if r, _, callErr := setConsoleMode.Call(handle, uintptr(mode&^enableEchoInput)); r == 0 {
		return nil, callErr
	}
	return func() { setConsoleMode.Call(handle, uintptr(mode)) }, nil
}
