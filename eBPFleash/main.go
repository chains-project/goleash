package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
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
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		// Name of the current executed command
		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		var eventType string

		// Case 1: syscall directly invoked by a package
		if callerPackage != "" {
			eventType = "package"
			if _, exists := traceStore[callerPackage]; !exists {
				traceStore[callerPackage] = &syscallfilter.TraceEntry{
					Type:             "dep",
					Path:             callerPackage,
					Syscalls:         []int{},
					ExecutedBinaries: []string{},
				}
			}

			handleExecSyscalls(event, callerPackage, traceStore)

			if _, ok := syscalls[callerPackage]; !ok {
				syscalls[callerPackage] = make(map[int]bool)
			}
			syscalls[callerPackage][int(event.SyscallId)] = true

			uniqueSyscalls := make([]int, 0, len(syscalls[callerPackage]))
			for syscall := range syscalls[callerPackage] {
				uniqueSyscalls = append(uniqueSyscalls, syscall)
			}
			traceStore[callerPackage].Syscalls = uniqueSyscalls

			// Case 2: syscall invoked by an external binary
		} else if entry, exists := traceStore[execComm]; exists {
			eventType = "binary"
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
			eventType = "runtime"
		}

		logEvent(event, stackTrace, eventType)
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
	traceStore, err := syscallfilter.LoadTraceStore()
	if err != nil {
		log.Fatalf("loading syscall allowlist: %v", err)
	}

	f := createLogFile("unauthorized_syscalls.log")
	defer f.Close()

	setupAndRun(args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		logEvent(event, stackTrace, "none")

		// Case 1: syscall directly invoked by a package
		if callerPackage != "" && !traceStore.SyscallAllowed(callerPackage, int(event.SyscallId)) {
			handleUnauthorized(event.Pid,
				fmt.Sprintf("Unauthorized syscall %d from package %s", event.SyscallId, callerPackage),
				f)

			// Case 2: syscall invoked by an external binary
		} else if _, exists := traceStore[execComm]; exists && !traceStore.SyscallAllowed(execComm, int(event.SyscallId)) {
			handleUnauthorized(event.Pid,
				fmt.Sprintf("Unauthorized syscall %d from binary %s", event.SyscallId, execComm),
				f)
		}
	})
}

func runCapabilityEnforceMode(args RuntimeConfig) {
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

		// Case 1: capability used by a package
		if exists {
			if callerPackage != "" && !traceStore.CapabilityAllowed(callerPackage, capability) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized capability %s (syscall %d) from package %s",
						capability, event.SyscallId, callerPackage),
					f)
				// Case 2: capability used by an external binary
			} else if _, exists := traceStore[execComm]; exists && !traceStore.CapabilityAllowed(execComm, capability) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized capability %s (syscall %d) from binary %s",
						capability, event.SyscallId, execComm),
					f)
			}
		} else {
			caller := callerPackage
			if caller == "" {
				caller = execComm
			}
			if !traceStore.SyscallAllowed(caller, int(event.SyscallId)) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Potentially privileged syscall %d from %s without capability mapping",
						event.SyscallId, caller),
					f)
			}
		}

		logEvent(event, stackTrace, "none")
	})
}
