package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

func loadAllowlist(filename string) (Allowlist, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Allowlist{}, fmt.Errorf("reading allowlist file: %w", err)
	}

	var allowlist Allowlist
	if err := json.Unmarshal(data, &allowlist); err != nil {
		return Allowlist{}, fmt.Errorf("parsing allowlist JSON: %w", err)
	}

	return allowlist, nil
}

func populateSymbolCache(binaryPath string) error {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("opening binary: %w", err)
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		return fmt.Errorf("reading symbols: %w", err)
	}

	for _, sym := range symbols {
		if sym.Value != 0 && sym.Size != 0 {
			symbolCache = append(symbolCache, symbolInfo{
				name:  sym.Name,
				start: sym.Value,
				end:   sym.Value + sym.Size,
			})
		}
	}

	sort.Slice(symbolCache, func(i, j int) bool {
		return symbolCache[i].start < symbolCache[j].start
	})

	return nil
}

func resolveSymbols(stackTrace []uint64) string {
	var result strings.Builder
	for _, addr := range stackTrace {
		symbol := resolveSymbol(addr)
		result.WriteString(fmt.Sprintf("%s\n", symbol))
	}
	return result.String()
}

func resolveSymbol(addr uint64) string {
	idx := sort.Search(len(symbolCache), func(i int) bool {
		return symbolCache[i].start > addr
	}) - 1

	if idx >= 0 && addr >= symbolCache[idx].start && addr < symbolCache[idx].end {
		return symbolCache[idx].name
	}

	return fmt.Sprintf("0x%x", addr)
}

func getStackTrace(stackMap *ebpf.Map, stackID uint32) ([]uint64, error) {
	var stackTrace [maxStackDepth]uint64
	err := stackMap.Lookup(stackID, &stackTrace)
	if err != nil {
		return nil, err
	}

	var result []uint64
	for _, addr := range stackTrace {
		if addr == 0 {
			break
		}
		result = append(result, addr)
	}

	return result, nil
}

func isGoPackageFunction(symbol string) bool {
	return strings.Contains(symbol, "github.com/")
}

func getFirstGoPackageFunction(stackTrace []uint64) string {
	for _, addr := range stackTrace {
		symbol := resolveSymbol(addr)
		if isGoPackageFunction(symbol) {
			return symbol
		}
	}
	return ""
}

func getCallerPackage(stackTrace []uint64) string {
	for _, addr := range stackTrace {
		symbol := resolveSymbol(addr)
		if isGoPackageFunction(symbol) {
			parts := strings.Split(symbol, ".")
			if len(parts) >= 2 {
				return strings.Join(parts[:2], ".")
			}
			return parts[0]
		}
	}
	return ""
}

func isSyscallAllowed(pkg string, syscall int, allowlist Allowlist) bool {
	allowed, ok := allowlist.Dependencies[pkg]
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
