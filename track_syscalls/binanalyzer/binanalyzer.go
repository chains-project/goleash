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

var Cache []SymbolInfo

func Populate(binaryPath string) error {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		return err
	}

	for _, sym := range symbols {
		if sym.Value != 0 {
			Cache = append(Cache, SymbolInfo{
				Name:  sym.Name,
				Start: sym.Value,
				End:   sym.Value + sym.Size,
			})
		}
	}
	return nil
}

func Resolve(address uint64) string {
	for _, sym := range Cache {
		if address >= sym.Start && address < sym.End {
			return sym.Name
		}
	}
	return fmt.Sprintf("0x%x", address)
}
