package main

import (
	"fmt"

	"github.com/carminecesarano/mal_dependency/cgo"
)

func main() {

	/*
		os_syscall.Syscall(145, 0, 0, 0) // 145

		filePath := "/etc/passwd"
		fd, err := os_syscall.Open(filePath, os_syscall.O_RDONLY, 0) // 2
		if err != nil {
			fmt.Printf("Failed to open file: %v\n", err) // 1
			os.Exit(1)
		}
		defer os_syscall.Close(fd) // 3

		os_syscall.Syscall(145, 0, 0, 0) // 145

		fmt.Printf("File descriptor: %d\n", fd)
		buf := make([]byte, 1024)
		n, err := os_syscall.Read(fd, buf)
		if err != nil {
			fmt.Printf("Failed to read file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File content:\n%s\n", string(buf[:n]))

	*/

	fmt.Printf("Syscall 0 read\n")
	cgo.InvokeSyscall(0)

	fmt.Printf("\nSyscall 1 write\n")
	cgo.InvokeSyscall(1)

	fmt.Printf("\nSyscall 145 sched_getscheduler\n")
	cgo.InvokeSyscall(145)

	fmt.Printf("\nSyscall 170 sethostname\n")
	cgo.InvokeSyscall(170)

	fmt.Printf("\nSyscall 204 sched_getaffinity\n")
	cgo.InvokeSyscall(204)

	fmt.Printf("\nSyscall 252 ioprio_get\n")
	cgo.InvokeSyscall(252)

}
