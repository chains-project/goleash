package stackanalyzer

import (
	"fmt"
	"os"
	"strings"

	"github.com/chains-project/goleash/track_syscalls/binanalyzer"
	"github.com/cilium/ebpf"
	"golang.org/x/mod/modfile"
)

const (
	maxStackDepth = 20
)

type ImportedPackages struct {
	packages []string
}

// ToDo: do not use global variables
var ImportedPackagesCache *ImportedPackages

func LoadModuleCache(modManifest string) error {
	content, err := os.ReadFile(modManifest)
	if err != nil {
		return err
	}

	f, err := modfile.Parse(modManifest, content, nil)
	if err != nil {
		return err
	}

	ImportedPackagesCache = &ImportedPackages{
		packages: make([]string, 0, len(f.Require)),
	}

	for _, req := range f.Require {
		fmt.Printf("Caching module: %s %s\n", req.Mod.Path, req.Mod.Version)
		ImportedPackagesCache.packages = append(ImportedPackagesCache.packages, req.Mod.Path)
	}

	return nil
}

func GetStackTrace(stacktraces *ebpf.Map, stackID uint32) ([]uint64, error) {
	var stackTrace [maxStackDepth]uint64
	err := stacktraces.Lookup(stackID, &stackTrace)
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

func ResolveSymbols(stackTrace []uint64) string {
	var resolved []string
	for _, addr := range stackTrace {
		symbol := binanalyzer.Resolve(addr)
		resolved = append(resolved, symbol)
	}
	return strings.Join(resolved, "\n")
}

func ResolveCallerAndPackageNameFromStackTrace(stackTrace []uint64) (string, string, error) {

	if ImportedPackagesCache == nil {
		return "", "", fmt.Errorf("ImportedPackagesCache is not initialized")
	}

	// StackTrace is an array of addresses.
	for _, addr := range stackTrace {

		// Resolve the symbol at the address
		// A symbol has the form: "pkg.func"
		symbol := binanalyzer.Resolve(addr)

		// Check if the symbol contains an imported Go package
		pkgName, funcName, err := GetCallerPackageAndFunction(symbol)
		if err != nil {
			return "", "", err
		}
		if pkgName != "" && funcName != "" {
			return pkgName, funcName, nil
		}
	}
	return "", "", nil
}

func GetCallerPackageAndFunction(resolvedSymbol string) (string, string, error) {
	for _, pkgName := range ImportedPackagesCache.packages {
		if strings.Contains(resolvedSymbol, pkgName) {
			funcName := strings.TrimPrefix(resolvedSymbol, pkgName+".")
			return pkgName, funcName, nil
		}
	}
	return "", "", nil
}
