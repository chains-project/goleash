package main

import "github.com/carminecesarano/mal_dependency/exec"

func main() {
	exec.ExecBinary("./binary/bin_hello", "5")
}
