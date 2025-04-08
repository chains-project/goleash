package stackanalyzer

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	maxStackDepth = 32
)

var thirdPartyPrefixes = []string{
	//"golang.org",        // trusted
	//"google.golang.org", // trusted
	"github.com",
	"go.uber.org",
	"gopkg.in",
	"k8s.io",
	"sigs.k8s.io",
	"rsc.io",
	"4d63.com",
	"git.sr.ht",
	"gitlab.com",
	"go-simpler.org",
	"go.etcd.io",
	"go.opentelemetry.io",
	"gonum.org",
	"gotest.tools",
	"honnef.co",
	"k8s.io",
	"mvdan.cc",
	"bitbucket.org",
	"cloud.google.com",
	"go.tmz.dev",
	"lukechampine.com",
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

/*

func FindCallerPackage(stackTrace []string, thirdPartyPrefixes []string) (bool, string, string) {
	for _, frame := range stackTrace {
		for _, prefix := range thirdPartyPrefixes {
			if strings.HasPrefix(frame, prefix) {
				// Find the last slash
				slashIdx := strings.LastIndex(frame, "/")
				if slashIdx < 0 {
					// No slash => everything is package
					return true, frame, ""
				}

				// Split into packagePath / finalComponent
				packagePath := frame[:slashIdx]
				finalComponent := frame[slashIdx+1:]

				// Find the first dot in the final component
				dotIdx := strings.Index(finalComponent, ".")
				if dotIdx < 0 {
					// No dot => entire frame is package
					return true, frame, ""
				}

				// The package extends into the final component up to the dot
				return true,
					packagePath + "/" + finalComponent[:dotIdx],
					finalComponent[dotIdx+1:]
			}
		}
	}
	return false, "", ""
}*/

func FindCallerPackage(stackTrace []string) (bool, string, string) {
	for _, frame := range stackTrace {
		// Check if this frame is from a third-party package
		for _, prefix := range thirdPartyPrefixes {
			if strings.HasPrefix(frame, prefix) {
				// For Go package paths, we need to handle both dots and slashes
				// The function name always comes after the last component of the package path

				// First, find the last slash in the frame
				lastSlashIndex := strings.LastIndex(frame, "/")

				var packagePath string
				var functionPart string

				if lastSlashIndex != -1 {
					// If there's a slash, everything before the last slash is definitely part of the package path
					// The last component might be either part of the package or the start of the function name
					beforeLastSlash := frame[:lastSlashIndex]
					afterLastSlash := frame[lastSlashIndex+1:]

					// Check if there's a dot in the last component
					dotInLastComponent := strings.Index(afterLastSlash, ".")

					if dotInLastComponent != -1 {
						// The package path extends to the first dot in the last component
						packagePath = beforeLastSlash + "/" + afterLastSlash[:dotInLastComponent]
						functionPart = afterLastSlash[dotInLastComponent+1:]
					} else {
						// No dot in the last component, the whole frame is the package path
						packagePath = frame
						functionPart = ""
					}
				} else {
					// No slash in the frame, use the first dot as the separator between package and function
					firstDotIndex := strings.Index(frame, ".")

					if firstDotIndex != -1 {
						packagePath = frame[:firstDotIndex]
						functionPart = frame[firstDotIndex+1:]
					} else {
						// No dot either, the whole frame is the package path
						packagePath = frame
						functionPart = ""
					}
				}

				return true, packagePath, functionPart
			}
		}
	}
	return false, "", ""
}
