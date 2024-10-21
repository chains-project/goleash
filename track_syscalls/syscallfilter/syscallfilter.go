package syscallfilter

import (
	"encoding/json"
	"os"
	"sort"
)

type Allowlist struct {
	Dependencies map[string][]int `json:"dependencies"`
}

func Load() (Allowlist, error) {
	var allowlist Allowlist
	jsonData, err := os.ReadFile("allowlist.json")
	if err != nil {
		return allowlist, err
	}
	err = json.Unmarshal(jsonData, &allowlist)
	return allowlist, err
}

func Write(newSyscalls map[string][]int) error {
	var existingAllowlist Allowlist

	// Read existing allowlist if it exists
	data, err := os.ReadFile("allowlist.json")
	if err == nil {
		json.Unmarshal(data, &existingAllowlist)
	}

	// Merge new syscalls with existing ones
	if existingAllowlist.Dependencies == nil {
		existingAllowlist.Dependencies = make(map[string][]int)
	}
	for pkg, syscalls := range newSyscalls {
		existingAllowlist.Dependencies[pkg] = mergeSyscalls(existingAllowlist.Dependencies[pkg], syscalls)
	}

	// Write merged data back to file
	jsonData, err := json.MarshalIndent(existingAllowlist, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("allowlist.json", jsonData, 0644)
}

func mergeSyscalls(existing, new []int) []int {
	merged := make(map[int]bool)
	for _, syscall := range existing {
		merged[syscall] = true
	}
	for _, syscall := range new {
		merged[syscall] = true
	}

	result := make([]int, 0, len(merged))
	for syscall := range merged {
		result = append(result, syscall)
	}
	sort.Ints(result)
	return result
}

func (a *Allowlist) SyscallAllowed(callerPkg string, syscall int) bool {
	allowed, ok := a.Dependencies[callerPkg]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == syscall {
			return true
		}
	}
	return false
}

func ConvertSyscallsMap(syscalls map[string]map[int]bool) map[string][]int {
	convertedSyscalls := make(map[string][]int)
	for pkg, syscallMap := range syscalls {
		syscallList := make([]int, 0, len(syscallMap))
		for syscall := range syscallMap {
			syscallList = append(syscallList, syscall)
		}
		convertedSyscalls[pkg] = syscallList
	}
	return convertedSyscalls
}
