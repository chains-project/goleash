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

func Write(syscalls map[string][]int) error {
	data := Allowlist{
		Dependencies: syscalls,
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("allowlist.json", jsonData, 0644)
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
	result := make(map[string][]int)
	for pkg, calls := range syscalls {
		for call := range calls {
			result[pkg] = append(result[pkg], call)
		}
		sort.Ints(result[pkg])
	}
	return result
}
