package binanalyzer

import (
	"debug/elf"
	"fmt"
	"path/filepath"
)

type SymbolInfo struct {
	Name  string
	Start uint64
	End   uint64
}

var BinarySymbolsCacheMap = make(map[string][]SymbolInfo)

func LoadBinarySymbolsCache(binaryPaths []string) error {
	for _, binaryPath := range binaryPaths {
		fmt.Printf("Loading binary symbols from: %s\n", binaryPath)

		binaryName := filepath.Base(binaryPath)

		f, err := elf.Open(binaryPath)
		if err != nil {
			fmt.Printf("Error opening ELF file: %v\n", err)
			return err
		}
		defer f.Close()

		symbols, err := f.Symbols()
		if err != nil {
			fmt.Printf("Error reading symbols: %v\n", err)
			return err
		}

		var cache []SymbolInfo
		symbolCount := 0
		for _, sym := range symbols {
			if sym.Value != 0 {
				cache = append(cache, SymbolInfo{
					Name:  sym.Name,
					Start: sym.Value,
					End:   sym.Value + sym.Size,
				})
				symbolCount++
			}
		}

		// Store the cache in the dictionary with the binary path as the key
		BinarySymbolsCacheMap[binaryName] = cache
		fmt.Printf("Successfully cached %d symbols for binary: %s\n\n", symbolCount, binaryName)
	}
	return nil
}

func Resolve(binaryName string, address uint64) string {
	cache, exists := BinarySymbolsCacheMap[binaryName]
	if !exists {
		return fmt.Sprintf("Binary not loaded: %s", binaryName)
	}

	for _, sym := range cache {
		if address >= sym.Start && address < sym.End {
			return sym.Name
		}
	}
	return fmt.Sprintf("0x%x", address)
}

func ResolveStackTrace(binaryName string, addresses []uint64) []string {
	resolved := make([]string, len(addresses))
	for i, addr := range addresses {
		resolved[i] = Resolve(binaryName, addr)
	}
	return resolved
}
