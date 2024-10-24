package stackanalyzer

import (
	"os"
	"strings"

	"github.com/chains-project/goleash/track_syscalls/binanalyzer"
	"github.com/cilium/ebpf"
)

const (
	maxStackDepth = 20
)

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

func isGoPackageFunction(symbol string, modManifest string) bool {
	// check inside go.mod manifest
	content, err := os.ReadFile(modManifest)
	if err == nil {
		return strings.Contains(string(content), symbol)
	} else {
		println("Error reading go.mod manifest file")
	}
	return false
}

func GetCallerPackage(stackTrace []uint64, modManifest string) string {
	for _, addr := range stackTrace {
		symbol := binanalyzer.Resolve(addr)
		if isGoPackageFunction(symbol, modManifest) {
			return symbol
		}
	}
	return ""
}

func GetFirstGoPackageFunction(stackTrace []uint64) string {
	for _, addr := range stackTrace {
		symbol := binanalyzer.Resolve(addr)
		if strings.Contains(symbol, ".") {
			return symbol
		}
	}
	return ""
}
