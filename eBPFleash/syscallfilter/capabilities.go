package syscallfilter

import (
	"encoding/json"
	"os"
)

type CapabilityAllowlist struct {
	Dependencies map[string][]string `json:"dependencies"`
}

func LoadCapabilities() (CapabilityAllowlist, error) {
	var existingAllowlist CapabilityAllowlist
	jsonData, err := os.ReadFile(capabilitiesFile)
	if err != nil {
		return existingAllowlist, err
	}
	return existingAllowlist, json.Unmarshal(jsonData, &existingAllowlist)
}

func WriteCapabilities(newCapabilities CapabilityAllowlist) error {
	existingAllowlist := readOrCreateCapabilityAllowlist()
	mergeNewCapabilities(&existingAllowlist, newCapabilities.Dependencies)

	data, err := json.MarshalIndent(existingAllowlist, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(capabilitiesFile, data, filePermissions)
}

func readOrCreateCapabilityAllowlist() CapabilityAllowlist {
	var capAllowlist CapabilityAllowlist
	data, err := os.ReadFile(capabilitiesFile)
	if err == nil {
		json.Unmarshal(data, &capAllowlist)
	}
	if capAllowlist.Dependencies == nil {
		capAllowlist.Dependencies = make(map[string][]string)
	}
	return capAllowlist
}

func (a *CapabilityAllowlist) CapabilityAllowed(callerPkg string, capability string) bool {
	allowlist, pkg_exists := a.Dependencies[callerPkg]
	if !pkg_exists {
		return false
	}
	return containsString(allowlist, capability)
}

func mergeNewCapabilities(existing *CapabilityAllowlist, newCapabilities map[string][]string) {
	for pkg, caps := range newCapabilities {
		existing.Dependencies[pkg] = mergeCapabilities(existing.Dependencies[pkg], caps)
	}
}

func GenerateCapabilityMap(syscalls map[string][]int) CapabilityAllowlist {
	capAllowlist := CapabilityAllowlist{Dependencies: make(map[string][]string)}

	for pkg, syscallList := range syscalls {
		capabilities := make(map[string]bool)
		for _, syscall := range syscallList {
			if cap, exists := syscallToCapability[syscall]; exists {
				capabilities[cap] = true
			}
		}
		capAllowlist.Dependencies[pkg] = mapToSortedSlice(capabilities)
	}
	return capAllowlist
}

func GetCapabilityForSyscall(syscall int) (string, bool) {
	cap, exists := syscallToCapability[syscall]
	return cap, exists
}
