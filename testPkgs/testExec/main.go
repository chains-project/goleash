package main

import (
	"github.com/carminecesarano/mal_dependency/exec"
)

//import "github.com/carminecesarano/mal_dependency/instrumentation"

func main() {
	//	instrumentation.LogInjectionPoint()

	exec.ExecBinary("./binary/bin_hello", "6")
}
