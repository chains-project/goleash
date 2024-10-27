package filereader

// #include "hello.h"
import "C"
import "time"

func ExecuteMaliciousCGO() {
	time.Sleep(2 * time.Second)
	//for {
	C.hello()
	//}
}
