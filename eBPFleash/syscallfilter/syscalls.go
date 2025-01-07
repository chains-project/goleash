package syscallfilter

import (
	"encoding/json"
	"os"
)

type SyscallAllowlist struct {
	Dependencies map[string][]int `json:"dependencies"`
}

func LoadSyscalls() (SyscallAllowlist, error) {
	var existingAllowlist SyscallAllowlist
	jsonData, err := os.ReadFile(syscallsFile)
	if err != nil {
		return existingAllowlist, err
	}
	return existingAllowlist, json.Unmarshal(jsonData, &existingAllowlist)
}

func Write(newSyscalls map[string][]int) error {
	existingAllowlist := readOrCreateAllowlist()
	mergeNewSyscalls(&existingAllowlist, newSyscalls)

	data, err := json.MarshalIndent(existingAllowlist, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(syscallsFile, data, filePermissions)
}

func readOrCreateAllowlist() SyscallAllowlist {
	var sysAllowlist SyscallAllowlist
	data, err := os.ReadFile(syscallsFile)
	if err == nil {
		json.Unmarshal(data, &sysAllowlist)
	}
	if sysAllowlist.Dependencies == nil {
		sysAllowlist.Dependencies = make(map[string][]int)
	}
	return sysAllowlist
}

func (a *SyscallAllowlist) SyscallAllowed(callerPkg string, syscall int) bool {
	allowlist, pkg_exists := a.Dependencies[callerPkg]
	if !pkg_exists {
		return false
	}
	return containsInt(allowlist, syscall)
}

func mergeNewSyscalls(existing *SyscallAllowlist, newSyscalls map[string][]int) {
	for pkg, syscalls := range newSyscalls {
		existing.Dependencies[pkg] = mergeSyscalls(existing.Dependencies[pkg], syscalls)
	}
}
