package filereader

// #include "hello.h"
import "C"

func ExecuteMaliciousCGO() {
	C.hello()
}
