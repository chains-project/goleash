package main

import (
	"fmt"

	"github.com/carminecesarano/mal_dependency/syscall"
)

func main() {
	fmt.Printf("Syscall 0 read\n")
	syscall.InvokeSyscall(0)

	fmt.Printf("\nSyscall 1 write\n")
	syscall.InvokeSyscall(1)

	fmt.Printf("\nSyscall 145 sched_getscheduler\n")
	syscall.InvokeSyscall(145)
	//time.Sleep(3 * time.Second)

	// Riesco a killare se c'è un timer. Altrimenti tutte le altre syscall vengono invocate.
	// Non è bloccante

	fmt.Printf("\nSyscall 170 sethostname\n")
	syscall.InvokeSyscall(170)

	fmt.Printf("\nSyscall 204 sched_getaffinity\n")
	syscall.InvokeSyscall(204)

	fmt.Printf("\nSyscall 252 ioprio_get\n")
	syscall.InvokeSyscall(252)
}
