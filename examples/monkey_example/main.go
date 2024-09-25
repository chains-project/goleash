package main

import (
	"fmt"

	"github.com/chains-project/goleash/examples/monkey_example/dependencyA"
	"github.com/chains-project/goleash/examples/monkey_example/dependencyB"

	_ "github.com/chains-project/goleash/examples/monkey_example/monkey"
)

func main() {
	fmt.Println("Invoking capabilities:")
	dependencyA.InvokeCapabilityWrite()
	dependencyB.InvokeCapabilityWrite()
}
