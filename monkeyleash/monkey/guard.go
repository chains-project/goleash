package monkey

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"bou.ke/monkey"
	"github.com/cespare/xxhash"
)

var (
	config *Config
)

const initialBufferSize = 1024
const maxStackDepth = 10

func init() {
	var err error

	config, err = LoadConfig("./go.cap", "../../goleash/interesting.cm")
	if err != nil {
		panic(fmt.Errorf("failed to load configuration: %v", err))
	}

	RegisterHooks()
}

func RegisterHooks() {
	if config.isHashMode {
		monkey.Patch(os.WriteFile, WriteFileReplaceHash)
		monkey.Patch(os.ReadFile, ReadFileReplaceHash)
		monkey.Patch(os.Create, CreateReplaceHash)
		monkey.Patch((*os.File).Chmod, FileChmodReplaceHash)
		monkey.Patch(os.Chmod, ChmodReplaceHash)
		monkey.Patch(net.LookupHost, LookupHostReplaceHash)

	} else {
		monkey.Patch(os.WriteFile, WriteFileReplace)
		monkey.Patch(os.ReadFile, ReadFileReplace)
		monkey.Patch(os.Create, CreateReplace)
		monkey.Patch((*os.File).Chmod, FileChmodReplace)
		monkey.Patch(os.Chmod, ChmodReplace)
		monkey.Patch(net.LookupHost, LookupHostReplace)
	}
}

func getStackTrace(funcName string, skip int) string {

	var sb strings.Builder
	sb.Grow(initialBufferSize)
	sb.WriteString(funcName)
	sb.WriteString("|")

	pcs := make([]uintptr, maxStackDepth)
	n := runtime.Callers(skip, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	for frame, more := frames.Next(); more; frame, more = frames.Next() {
		sb.WriteString(frame.Function)
		sb.WriteString("|")
	}

	return sb.String()
}

func generateHash(stackTrace string) string {
	hash := xxhash.Sum64String(stackTrace)
	// hash := sha256.Sum256([]byte(stackTrace))

	return hex.EncodeToString([]byte{
		byte(hash >> 56),
		byte(hash >> 48),
		byte(hash >> 40),
		byte(hash >> 32),
		byte(hash >> 24),
		byte(hash >> 16),
		byte(hash >> 8),
		byte(hash),
	})
	// return hex.EncodeToString(hash[:])
}

func UpdateStackHashes(funcName string) {
	stackTrace := getStackTrace(funcName, 4)
	stackHash := generateHash(stackTrace)
	invokedCapability := config.capFuncMapping[funcName]

	hashes := config.configCaps.Hashes[invokedCapability]
	if !contains(hashes, stackHash) {
		config.configCaps.Hashes[invokedCapability] = append(hashes, stackHash)
		writeConfigFile("./go.cap", config.configCaps)
	}
}

func getCallerDependency(stackTrace string) string {
	callerDepName := ""
	for depName := range config.configCaps.Allowlists {
		if strings.Contains(stackTrace, depName) {
			callerDepName = depName
			break
		}
	}

	return callerDepName
}

func CheckCapability(funcName string) error {
	stackTrace := getStackTrace(funcName, 4)
	stackHash := generateHash(stackTrace)
	callerDepName := getCallerDependency(stackTrace)

	invokedCapability, ok := config.capFuncMapping[funcName]
	if !ok {
		return nil
	}

	allowedHashes := config.configCaps.Hashes[invokedCapability]
	allowedCapabilities := config.configCaps.Allowlists[callerDepName]

	if len(allowedHashes) == 0 || !contains(allowedHashes, stackHash) || !contains(allowedCapabilities, invokedCapability) {
		return fmt.Errorf("capability '%s' denied for caller '%s'", invokedCapability, callerDepName)
	}

	return nil
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	_, exists := set[item]
	return exists
}
