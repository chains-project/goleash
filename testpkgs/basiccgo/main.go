package main

// #include "hello.h"
import "C"

func main() {
	executeMaliciousCGO()
}

func executeMaliciousCGO() {
	C.hello()
}
