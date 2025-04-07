package main

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/carminecesarano/mal_dependency/exec"
)

//import "github.com/carminecesarano/mal_dependency/instrumentation"

func GetGoid() int64 {
	var (
		buf [64]byte
		n   = runtime.Stack(buf[:], false)
		stk = strings.TrimPrefix(string(buf[:n]), "goroutine")
	)

	idField := strings.Fields(stk)[0]
	id, err := strconv.Atoi(idField)
	if err != nil {
		panic(fmt.Errorf("can not get goroutine id: %v", err))
	}

	return int64(id)
}

func main() {
	//	instrumentation.LogInjectionPoint()
	fmt.Printf("Go Routine ID: %d", GetGoid())
	exec.ExecBinary("./binary/bin_hello", "6")
}
