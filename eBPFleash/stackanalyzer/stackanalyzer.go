package stackanalyzer

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/mod/modfile"
)

const (
	maxStackDepth = 32
)

var thirdPartyPrefixes = []string{
	"github.com/", "gitlab.com/", "bitbucket.org/",
}

type ImportedPackages struct {
	packages []string
}

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
	if stackID == 0 {
		return nil, fmt.Errorf("invalid stack ID")
	}

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

	if len(result) == 0 {
		return nil, fmt.Errorf("empty stack trace")
	}

	return result, nil
}

func FindCallerPackage(stackTrace []string) (bool, string, string) {

	for _, frame := range stackTrace {
		for _, prefix := range thirdPartyPrefixes {
			if strings.HasPrefix(frame, prefix) {
				lastDotIndex := strings.LastIndex(frame, ".")
				if lastDotIndex != -1 {
					return true, frame[:lastDotIndex], frame[lastDotIndex+1:]
				}
				return true, frame, ""
			}
		}
	}
	return false, "", ""
}

func IsPackageInCache(pkgName string) bool {
	if ImportedPackagesCache == nil {
		return false
	}

	for _, cachedPkg := range ImportedPackagesCache.packages {
		if strings.HasPrefix(pkgName, cachedPkg+"/") {
			return true
		}
	}
	return false
}
