//go:build windows

package console

import (
	"syscall"
	"unsafe"
)

var procGetConsoleProcessList = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// Processes conta os processos presos ao console atual. Num terminal aberto
// pela pessoa há pelo menos dois (o shell e o Crivo); no duplo clique, um.
func Processes() int {
	var ids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return int(n)
}
