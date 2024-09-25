package dependencyB

import (
	"fmt"

	"github.com/chains-project/goleash/examples/monkey_example/std"
)

func InvokeCapabilityWrite() {
	fmt.Printf("Dependency B invoked capability: %s", std.WriteFile())
}
