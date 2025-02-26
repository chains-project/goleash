package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func PluginFunc() {
	syscall.Syscall(145, 0, 0, 0) // 145

	fmt.Println("PluginFunc called")
	cmd := exec.Command("ls")
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}
