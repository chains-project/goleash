package binanalyzer

import (
	"debug/elf"
	"fmt"
)

type SymbolInfo struct {
	Name  string
	Start uint64
	End   uint64
}

var BinarySymbolsCache []SymbolInfo

func LoadBinarySymbolsCache(binaryPath string) error {
	fmt.Printf("Loading binary symbols from: %s\n", binaryPath)

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

	fmt.Printf("Found %d symbols in total\n", len(symbols))

	symbolCount := 0
	for _, sym := range symbols {
		if sym.Value != 0 {
			BinarySymbolsCache = append(BinarySymbolsCache, SymbolInfo{
				Name:  sym.Name,
				Start: sym.Value,
				End:   sym.Value + sym.Size,
			})
			symbolCount++
			// fmt.Printf("Added symbol: %s (Start: 0x%x, Size: %d)\n", sym.Name, sym.Value, sym.Size)
		}
	}

	fmt.Printf("Successfully cached %d symbols\n", symbolCount)
	return nil
}

func Resolve(address uint64) string {
	for _, sym := range BinarySymbolsCache {
		if address >= sym.Start && address < sym.End {
			return sym.Name
		}
	}
	return fmt.Sprintf("0x%x", address)
}
