package main

import (
	"fmt"
	"syscall"
)

func main() {
	fmt.Println("Binary Executed")
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	syscall.Syscall(145, 0, 0, 0)
	/*
		cmd := exec.Command("ls")
		cmd.Stdout = os.Stdout
		_ = cmd.Run()
	*/
}
