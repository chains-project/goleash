package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sync"

	"github.com/chains-project/goleash/eBPFleash/stackanalyzer"
	"github.com/chains-project/goleash/eBPFleash/syscallfilter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cflags "-DTARGET_CMD='\"${TARGET_CMD}\"'" ebpf backend.c

type RuntimeConfig struct {
	BinaryPath     string
	Mode           string
	ModuleManifest string
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
	flag.StringVar(&config.BinaryPath, "binary", "", "Path to the binary for syscall tracking")
	flag.StringVar(&config.Mode, "mode", "enforce", "Execution mode: 'build', 'sys-enforce', 'cap-enforce' or 'trace'")
	flag.StringVar(&config.ModuleManifest, "manifest", "", "Path to the go.mod manifest file")
	flag.Parse()

	if config.BinaryPath == "" || config.ModuleManifest == "" {
		log.Fatal("Both -binary and -manifest flags are required")
	}

	modes := map[string]func(RuntimeConfig){
		"build":       runBuildMode,
		"sys-enforce": runSysEnforceMode,
		"cap-enforce": runCapabilityEnforceMode,
		"trace":       runTraceMode,
	}

	if fn, exists := modes[config.Mode]; exists {
		fn(config)
	} else {
		log.Fatalf("Invalid mode: %s. Use 'build', 'sys-enforce', 'cap-enforce' or 'trace'", config.Mode)
	}
}

func runBuildMode(args RuntimeConfig) {
	traceStore := make(map[string]*syscallfilter.TraceEntry)
	syscalls := make(map[string]map[int]bool)

	setupAndRun(args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		// Handle execve/execveat syscalls (59/322) on SYS_EXIT
		if (event.SyscallId == 59 || event.SyscallId == 322) && event.EventType == EventSysExit {

			log.Printf("Sys_exit event: %d", event.SyscallId)

			execPath := syscallfilter.BytesToString(event.ExecPath)
			execPath = filepath.Base(execPath)

			if execPath != "" {
				traceStore[execPath] = &syscallfilter.TraceEntry{
					Type:     "binary",
					Path:     execPath,
					Syscalls: []int{},
					Parent:   callerPackage,
				}

				if callerPackage != "" {
					if entry, exists := traceStore[callerPackage]; exists {
						entry.ExecutedBinaries = append(entry.ExecutedBinaries, execPath)
					}
				}
			}

			logEvent(event, stackTrace, "binary")
			return
		}

		// Handle all other syscalls on SYS_ENTER
		if callerPackage != "" {

			// CASE A: Syscall from a Go package
			logEvent(event, stackTrace, "package")
			log.Printf("Sys_enter event: %d", event.SyscallId)

			if _, exists := traceStore[callerPackage]; !exists {
				traceStore[callerPackage] = &syscallfilter.TraceEntry{
					Type:             "dep",
					Path:             callerPackage,
					Syscalls:         []int{},
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

			logEvent(event, stackTrace, "package")

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
			logEvent(event, stackTrace, "binary")

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

func runTraceMode(args RuntimeConfig) {
	setupAndRun(args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		logEvent(event, stackTrace, "none")
	})
	log.Println("Trace mode completed.")
}

func runSysEnforceMode(args RuntimeConfig) {
	var originalComm string
	traceStore, err := syscallfilter.LoadTraceStore()
	if err != nil {
		log.Fatalf("loading syscall allowlist: %v", err)
	}

	f := createLogFile("unauthorized_syscalls.log")
	defer f.Close()

	setupAndRun(args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {

		sysID := int(event.SyscallId)
		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		if originalComm == "" {
			originalComm = execComm
		}

		if callerPackage != "" {
			// CASE A: Syscall from a Go package
			logEvent(event, stackTrace, "package")

			if !traceStore.HasEntry(callerPackage) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Deny: package %s not in allowlist for syscall %d", callerPackage, sysID),
					f)
				return
			}

			if !traceStore.SyscallAllowed(callerPackage, sysID) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Deny: syscall %d from package %s not allowed", sysID, callerPackage),
					f)
				return
			}

			// Allowed package + allowed syscall
			return

		} else if callerPackage == "" && execComm != originalComm {
			// CASE B: Syscall from a binary
			logEvent(event, stackTrace, "binary")

			if !traceStore.HasEntry(execComm) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Deny: binary %q not in allowlist for syscall %d", execComm, sysID),
					f)
				return
			}

			if !traceStore.SyscallAllowed(execComm, sysID) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Deny: syscall %d from binary %q not allowed", sysID, execComm),
					f)
				return
			}

			// Allowed binary + allowed syscall
			return

		} else if callerPackage == "" && execComm == originalComm {
			// CASE C: Syscall from a runtime / main
			logEvent(event, stackTrace, "runtime")

			// We assume that the syscall is allowed if we reach this point
			return

		} else {
			handleUnauthorized(event.Pid,
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

	setupAndRun(args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		capability, exists := syscallfilter.GetCapabilityForSyscall(int(event.SyscallId))

		if originalComm == "" {
			originalComm = execComm
		}

		if callerPackage != "" {
			// CASE A: Capability from a Go package
			logEvent(event, stackTrace, "package")
			if exists && !traceStore.CapabilityAllowed(callerPackage, capability) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized capability %s (syscall %d) from package %s",
						capability, event.SyscallId, callerPackage),
					f)
			}
			return

		} else if callerPackage == "" && execComm != originalComm {
			// CASE B: Capability from a binary
			logEvent(event, stackTrace, "binary")
			if exists && !traceStore.CapabilityAllowed(execComm, capability) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized capability %s (syscall %d) from binary %s",
						capability, event.SyscallId, execComm),
					f)
			}
			return

		} else if callerPackage == "" && execComm == originalComm {
			// CASE C: Capability from runtime / main
			logEvent(event, stackTrace, "runtime")
			return

		} else {
			handleUnauthorized(event.Pid,
				fmt.Sprintf("Deny: syscall %d. Unrecognized capability event.", event.SyscallId),
				f)
		}

		logEvent(event, stackTrace, "none")
	})
}
