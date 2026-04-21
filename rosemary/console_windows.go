// Rosemary - Cross-platform transparent tunneling platform
// Copyright (C) 2026 Chokri Hammedi (blue0x1)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build windows
// +build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func initConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	const enableVirtualTerminalProcessing = 0x0004

	handle := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {

		disableColors()
		return
	}
	r, _, _ = setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
	if r == 0 {

		disableColors()
	}
}

func disableColors() {
	colorReset = ""
	colorBold = ""
	colorDim = ""
	colorRed = ""
	colorGreen = ""
	colorYellow = ""
	colorCyan = ""
	colorBoldRed = ""
	colorBoldGreen = ""
	colorBoldYellow = ""
	colorBoldCyan = ""
	colorBoldWhite = ""
}
