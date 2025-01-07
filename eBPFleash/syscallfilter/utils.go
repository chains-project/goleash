package syscallfilter

import "sort"

func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func mapToSortedSlice(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func ConvertSyscallsMap(syscalls map[string]map[int]bool) map[string][]int {
	result := make(map[string][]int)
	for pkg, syscallMap := range syscalls {
		syscallList := make([]int, 0, len(syscallMap))
		for syscall := range syscallMap {
			syscallList = append(syscallList, syscall)
		}
		result[pkg] = syscallList
	}
	return result
}

func mergeSyscalls(existing, new []int) []int {
	uniqueSyscalls := make(map[int]bool)
	for _, syscall := range append(existing, new...) {
		uniqueSyscalls[syscall] = true
	}

	result := make([]int, 0, len(uniqueSyscalls))
	for syscall := range uniqueSyscalls {
		result = append(result, syscall)
	}
	sort.Ints(result)
	return result
}

func mergeCapabilities(existing, new []string) []string {
	uniqueCaps := make(map[string]bool)
	for _, cap := range append(existing, new...) {
		uniqueCaps[cap] = true
	}

	result := mapToSortedSlice(uniqueCaps)
	return result
}
