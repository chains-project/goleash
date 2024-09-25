package monkey

import (
	"syscall"
	"unsafe"

	"github.com/chains-project/goleash/examples/monkey_example/std"
)

func init() {
	replace(std.WriteFile, WriteFileReplacement)
}

func WriteFileReplacement() string {
	return "WriteFile Replacement\n"
}

func replace(orig func() string, replacement func() string) {

	// Generate machine code to jump
	funcVal := *(*uintptr)(unsafe.Pointer(&replacement))
	bytes := []byte{
		0x48, 0xC7, 0xC2,
		byte(funcVal >> 0),
		byte(funcVal >> 8),
		byte(funcVal >> 16),
		byte(funcVal >> 24), // MOV rdx, funcVal
		0xFF, 0x22,          // JMP rdx
	}

	// Get the actual memory address of the original function
	functionLocation := **(**uintptr)(unsafe.Pointer(&orig))

	// Get a slice representing the function's raw memory
	window := (*(*[0xFF]byte)(unsafe.Pointer(functionLocation)))[:]

	// Get the memory page containing the function, and make it readable, writeable, and executable
	page := (*(*[0xFFFFFF]byte)(unsafe.Pointer(functionLocation & ^uintptr(syscall.Getpagesize()-1))))[:syscall.Getpagesize()]
	syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)

	// Overwrite the original function with the jump code
	copy(window, bytes)
}
