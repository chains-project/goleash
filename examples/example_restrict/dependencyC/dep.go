// dependencyC/dep.go
package dependencyC

import (
	"fmt"
	"log"
	"net"
	"os"
)

func TestNetworkLookup() {
	addrs, err := net.LookupHost("www.google.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(addrs)
}

func TestReadFile() {
	data, err := os.ReadFile("./example1.txt")
	if err != nil {
		fmt.Printf("error reading file")
	}
	fmt.Printf("file letto: %s\n", data)
}

func CallPDF() {

	TestNetworkLookup()
	//TestReadFile()
}
