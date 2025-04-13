package syscallfilter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type SyscallAllowlist struct {
	Dependencies map[string][]int `json:"dependencies"`
}

type TraceStore map[string]*TraceEntry

type TraceEntry struct {
	Type             string              `json:"type"`
	Path             string              `json:"path"`
	Syscalls         []int               `json:"syscalls"`
	Capabilities     []string            `json:"capabilities"`
	ExecutedBinaries []string            `json:"executed_binaries"`
	SyscallPaths     map[string][]uint32 `json:"syscalls_paths,omitempty"`
	Parent           string              `json:"caller_dep,omitempty"`
}

func LoadTraceStore() (TraceStore, error) {
	traceStore := make(TraceStore)
	jsonData, err := os.ReadFile(traceStoreFile)
	if err != nil {
		return traceStore, err
	}
	return traceStore, json.Unmarshal(jsonData, &traceStore)
}

func WriteTraceStore(traceStore TraceStore) error {
	existingTraceStore := readOrCreateTraceStore()
	mergeTraceStores(&existingTraceStore, traceStore)

	// Ensure syscall lists and capabilities are sorted and unique
	for _, entry := range existingTraceStore {
		sort.Ints(entry.Syscalls)
		entry.Capabilities = getUniqueCapabilities(entry.Syscalls)
	}

	traceData, err := json.MarshalIndent(existingTraceStore, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling trace data: %v", err)
	}

	return os.WriteFile(traceStoreFile, traceData, filePermissions)
}

func getUniqueCapabilities(syscalls []int) []string {
	capMap := make(map[string]bool)
	for _, syscall := range syscalls {
		if cap, exists := GetCapabilityForSyscall(syscall); exists {
			capMap[cap] = true
		}
	}
	return mapToSortedSlice(capMap)
}

func readOrCreateTraceStore() TraceStore {
	existingTraceStore := make(TraceStore)
	if _, err := os.Stat(traceStoreFile); err == nil {
		if data, err := os.ReadFile(traceStoreFile); err == nil {
			json.Unmarshal(data, &existingTraceStore)
		}
	}
	return existingTraceStore
}

func mergeTraceStores(existing *TraceStore, new TraceStore) {
	for key, newEntry := range new {
		if existingEntry, exists := (*existing)[key]; exists {
			existingEntry.Syscalls = mergeUniqueInts(existingEntry.Syscalls, newEntry.Syscalls)
			existingEntry.ExecutedBinaries = mergeUniqueStrings(existingEntry.ExecutedBinaries, newEntry.ExecutedBinaries)
		} else {
			(*existing)[key] = newEntry
		}
	}
}

func (store TraceStore) SyscallAllowed(callerPackage string, syscall int) bool {
	if entry, exists := store[callerPackage]; exists {
		return contains(entry.Syscalls, syscall)
	}
	return false
}

func (store TraceStore) CapabilityAllowed(callerPackage string, capability string) bool {
	if entry, exists := store[callerPackage]; exists {
		return contains(entry.Capabilities, capability)
	}
	return false
}

func GetCapabilityForSyscall(syscall int) (string, bool) {
	cap, exists := SyscallToCapability[syscall]
	return cap, exists
}
