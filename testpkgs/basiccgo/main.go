package main

// #include "hello.h"
import "C"

func main() {
	// run a simple c program
	C.hello()
}
