package syscallfilter

import "sort"

const maxBytes = 256

func BytesToString(arr [maxBytes]int8) string {
	b := make([]byte, 0, maxBytes)
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func contains[T comparable](slice []T, item T) bool {
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

func mergeUniqueInts(existing, new []int) []int {
	syscallSet := make(map[int]bool)
	for _, syscall := range append(existing, new...) {
		syscallSet[syscall] = true
	}
	merged := make([]int, 0, len(syscallSet))
	for syscall := range syscallSet {
		merged = append(merged, syscall)
	}
	sort.Ints(merged)
	return merged
}

func mergeUniqueStrings(existing, new []string) []string {
	uniqueSet := make(map[string]bool)
	for _, item := range append(existing, new...) {
		uniqueSet[item] = true
	}
	return mapToSortedSlice(uniqueSet)
}
