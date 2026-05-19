package syscallfilter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// AppTraceEntry is the application-level allowlist entry: per-binary syscall
// and capability sets, with no per-package attribution or call-stack data.
// Used by `-mode build-app` runs of the eBPF probe.
type AppTraceEntry struct {
	Binary       string   `json:"binary"`
	Syscalls     []int    `json:"syscalls"`
	Capabilities []string `json:"capabilities"`
}

// AppTraceStore maps comm (binary name) to its admitted-syscall set.
type AppTraceStore map[string]*AppTraceEntry

// WriteAppTraceStore persists a comm -> syscall-ids map to
// app_tracestore.json, merging with any existing file so repeated build-app
// runs accumulate coverage.
func WriteAppTraceStore(perBinary map[string][]int) error {
	existing := readOrCreateAppTraceStore()

	for comm, ids := range perBinary {
		entry, ok := existing[comm]
		if !ok {
			entry = &AppTraceEntry{Binary: comm}
			existing[comm] = entry
		}
		entry.Syscalls = mergeUniqueInts(entry.Syscalls, ids)
	}

	for _, entry := range existing {
		sort.Ints(entry.Syscalls)
		entry.Capabilities = getUniqueCapabilities(entry.Syscalls)
	}

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling app trace data: %v", err)
	}
	return os.WriteFile(appTraceStoreFile, data, filePermissions)
}

func readOrCreateAppTraceStore() AppTraceStore {
	store := make(AppTraceStore)
	if _, err := os.Stat(appTraceStoreFile); err == nil {
		if data, err := os.ReadFile(appTraceStoreFile); err == nil {
			_ = json.Unmarshal(data, &store)
		}
	}
	return store
}
