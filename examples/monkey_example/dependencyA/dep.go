package dependencyA

import (
	"fmt"

	"github.com/chains-project/goleash/examples/monkey_example/std"
)

func InvokeCapabilityWrite() {
	fmt.Printf("Dependency A invoked capability: %s", std.WriteFile())
}
