package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/chains-project/goleash/eBPFleash/binanalyzer"
	"github.com/chains-project/goleash/eBPFleash/stackanalyzer"
	"github.com/chains-project/goleash/eBPFleash/syscallfilter"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cflags "-DTARGET_CMD='\"${TARGET_CMD}\"'" ebpf backend.c

type RuntimeConfig struct {
	BinaryPaths []string
	Mode        string
}

var (
	mu sync.Mutex // Mutex for concurrent writes
)

const (
	EventSysEnter = 0
	EventSysExit  = 1
)

func main() {
	log.SetFlags(log.Ltime)

	var config RuntimeConfig
	var binaryPaths string

	flag.StringVar(&binaryPaths, "binary", "", "Comma-separated list of paths to binaries for syscall tracking")
	flag.StringVar(&config.Mode, "mode", "enforce", "Execution mode: 'build', 'sys-enforce', 'cap-enforce'")
	flag.Parse()

	config.BinaryPaths = strings.Split(binaryPaths, ",")

	if len(config.BinaryPaths) == 0 || config.Mode == "" {
		log.Fatal("both -binary and -mode flags are required")
	}

	modes := map[string]func(RuntimeConfig){
		"build":       runBuildMode,
		"sys-enforce": runSysEnforceMode,
		"cap-enforce": runCapabilityEnforceMode,
	}

	if fn, exists := modes[config.Mode]; exists {
		fn(config)
	} else {
		log.Fatalf("Invalid mode: %s. Use 'build', 'sys-enforce', 'cap-enforce'", config.Mode)
	}
}

func runBuildMode(args RuntimeConfig) {
	traceStore := make(map[string]*syscallfilter.TraceEntry)
	syscalls := make(map[string]map[int]bool)
	syscallStacks := make(map[string]map[int]map[uint32]bool)

	setupAndRun(BUILD_MODE, args.BinaryPaths, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		execComm := unix.ByteSliceToString(event.ProcessName[:])
		resolvedStackTrace := binanalyzer.ResolveStackTrace(execComm, stackTrace)
		_, callerPackage, _ := stackanalyzer.FindCallerPackage(resolvedStackTrace)

		mu.Lock()
		defer mu.Unlock()

		// Handle execve/execveat syscalls (59/322) on SYS_EXIT
		if (event.SyscallId == 59 || event.SyscallId == 322) && event.EventType == EventSysExit {

			execPath := syscallfilter.BytesToString(event.ExecPath)
			execPath = filepath.Base(execPath)

			if execPath != "" {
				traceStore[execPath] = &syscallfilter.TraceEntry{
					Type:         "binary",
					Path:         execPath,
					Syscalls:     []int{},
					SyscallPaths: make(map[string][]uint32),
					Parent:       callerPackage,
				}

				if callerPackage != "" {
					if entry, exists := traceStore[callerPackage]; exists {
						entry.ExecutedBinaries = append(entry.ExecutedBinaries, execPath)
					}
				}
			}

			return
		}

		// Handle all other syscalls on SYS_ENTER
		if callerPackage != "" {

			// CASE A: Syscall from a Go package
			logEvent(event, stackTrace, "package")

			if _, exists := traceStore[callerPackage]; !exists {
				traceStore[callerPackage] = &syscallfilter.TraceEntry{
					Type:             "dep",
					Path:             callerPackage,
					Syscalls:         []int{},
					SyscallPaths:     make(map[string][]uint32),
					ExecutedBinaries: []string{},
				}
			}

			if _, ok := syscalls[callerPackage]; !ok {
				syscalls[callerPackage] = make(map[int]bool)
			}
			syscalls[callerPackage][int(event.SyscallId)] = true

			uniqueSyscalls := make([]int, 0, len(syscalls[callerPackage]))
			for syscall := range syscalls[callerPackage] {
				uniqueSyscalls = append(uniqueSyscalls, syscall)
			}
			traceStore[callerPackage].Syscalls = uniqueSyscalls

			/* NEW CODE*/
			if _, ok := syscallStacks[callerPackage]; !ok {
				syscallStacks[callerPackage] = make(map[int]map[uint32]bool)
			}

			syscallID := int(event.SyscallId)
			if _, ok := syscallStacks[callerPackage][syscallID]; !ok {
				syscallStacks[callerPackage][syscallID] = make(map[uint32]bool)
			}
			stackID := event.StackTraceId
			syscallStacks[callerPackage][syscallID][stackID] = true

			for syscallID, stackIDSet := range syscallStacks[callerPackage] {
				syscallIDStr := strconv.Itoa(syscallID)
				stackIDList := make([]uint32, 0, len(stackIDSet))
				for id := range stackIDSet {
					stackIDList = append(stackIDList, id)
				}
				traceStore[callerPackage].SyscallPaths[syscallIDStr] = stackIDList
			}

		} else if entry, exists := traceStore[execComm]; exists {

			// CASE B: Syscall from a binary
			logEvent(event, stackTrace, "binary")

			if _, ok := syscalls[execComm]; !ok {
				syscalls[execComm] = make(map[int]bool)
			}
			syscalls[execComm][int(event.SyscallId)] = true

			uniqueSyscalls := make([]int, 0, len(syscalls[execComm]))
			for syscall := range syscalls[execComm] {
				uniqueSyscalls = append(uniqueSyscalls, syscall)
			}
			entry.Syscalls = uniqueSyscalls

		} else {

			// CASE C: Syscall from a runtime / main
			logEvent(event, stackTrace, "runtime")
		}

	})

	if err := syscallfilter.WriteTraceStore(traceStore); err != nil {
		log.Fatalf("Writing trace store to file: %v", err)
	}

	log.Println("Build mode completed. Allowlist and capabilities JSON files created.")
}

func runSysEnforceMode(args RuntimeConfig) {
	var originalComm string
	traceStore, err := syscallfilter.LoadTraceStore()
	if err != nil {
		log.Fatalf("loading syscall allowlist: %v", err)
	}

	f := createLogFile("unauthorized_syscalls.log")
	defer f.Close()

	setupAndRun(ENFORCE_MODE, args.BinaryPaths, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {

		sysID := int(event.SyscallId)
		execComm := unix.ByteSliceToString(event.ProcessName[:])
		resolvedStackTrace := binanalyzer.ResolveStackTrace(execComm, stackTrace)
		_, callerPackage, _ := stackanalyzer.FindCallerPackage(resolvedStackTrace)

		if originalComm == "" {
			originalComm = execComm
		}

		if callerPackage != "" {
			// CASE A: Syscall from a Go package
			// logEvent(event, stackTrace, "package")

			if !traceStore.HasEntry(callerPackage) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: package %s not in allowlist for syscall %d",
						callerPackage, sysID),
					f)
				return
			}

			if !traceStore.SyscallAllowed(callerPackage, sysID) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: syscall %d from package %s not allowed",
						sysID, callerPackage),
					f)
				return
			}

			// Allowed package + allowed syscall
			return

		} else if callerPackage == "" && execComm != originalComm {
			// CASE B: Syscall from a binary
			// logEvent(event, stackTrace, "binary")

			if !traceStore.HasEntry(execComm) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: binary %q not in allowlist for syscall %d",
						execComm, sysID),
					f)
				return
			}

			if !traceStore.SyscallAllowed(execComm, sysID) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: syscall %d from binary %q not allowed",
						sysID, execComm),
					f)
				return
			}

			// Allowed binary + allowed syscall
			return

		} else if callerPackage == "" && execComm == originalComm {
			// CASE C: Syscall from a runtime / std libraries / local packages
			// logEvent(event, stackTrace, "runtime")

			// We assume that the syscall is allowed (trusted) if we reach this point
			return

		} else {
			KillUnauthorized(event.Pid,
				fmt.Sprintf("Deny: syscall %d. Unrecognized event.", sysID),
				f)
		}

	})
}

func runCapabilityEnforceMode(args RuntimeConfig) {
	var originalComm string
	traceStore, err := syscallfilter.LoadTraceStore()
	if err != nil {
		log.Fatalf("loading capability allowlist: %v", err)
	}

	f := createLogFile("unauthorized_capabilities.log")
	defer f.Close()

	setupAndRun(ENFORCE_MODE, args.BinaryPaths, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		execComm := unix.ByteSliceToString(event.ProcessName[:])
		resolvedStackTrace := binanalyzer.ResolveStackTrace(execComm, stackTrace)
		_, callerPackage, _ := stackanalyzer.FindCallerPackage(resolvedStackTrace)
		capability, exists := syscallfilter.GetCapabilityForSyscall(int(event.SyscallId))

		if event.EventType == EventSysExit {
			fmt.Printf("Exit Event: %d\n", event.SyscallId)
		}

		if originalComm == "" {
			originalComm = execComm
		}

		if callerPackage != "" {
			// CASE A: Capability from a Go package
			// logEvent(event, stackTrace, "package")

			if !traceStore.HasEntry(callerPackage) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: package %s not in allowlist for capability %s",
						callerPackage, capability),
					f)
				return

			}

			if exists && !traceStore.CapabilityAllowed(callerPackage, capability) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: capability %s (syscall %d) from package %s",
						capability, event.SyscallId, callerPackage),
					f)
			}

			// Allowed package + allowed capability
			return

		} else if callerPackage == "" && execComm != originalComm {
			// CASE B: Capability from a binary
			// logEvent(event, stackTrace, "binary")

			if !traceStore.HasEntry(execComm) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: binary %q not in allowlist for capability %s",
						execComm, capability),
					f)
				return
			}

			if exists && !traceStore.CapabilityAllowed(execComm, capability) {
				KillUnauthorized(event.Pid,
					fmt.Sprintf("Deny: capability %s (syscall %d) from binary %s",
						capability, event.SyscallId, execComm),
					f)
			}

			// Allowed binary + allowed syscall
			return

		} else if callerPackage == "" && execComm == originalComm {
			// CASE C: Capability from runtime / std libraries / local packages
			// logEvent(event, stackTrace, "runtime")

			// We assume that the syscall is allowed (trusted) if we reach this point
			return

		} else {
			KillUnauthorized(event.Pid,
				fmt.Sprintf("Deny: syscall %d. Unrecognized capability event.", event.SyscallId),
				f)
		}

		// logEvent(event, stackTrace, "none")
	})
}
