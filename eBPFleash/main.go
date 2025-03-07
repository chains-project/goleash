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
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))

		mu.Lock()
		defer mu.Unlock()

		// Handle execve/execveat syscalls (59/322)
		if (event.SyscallId == 59 || event.SyscallId == 322) && event.EventType == EventSysExit {

			log.Printf("Sys_exit event: %d", event.SyscallId)

			execPath := syscallfilter.BytesToString(event.ExecPath)
			execPath = filepath.Base(execPath)

			if execPath != "" {
				// Create entry for the executed binary
				traceStore[execPath] = &syscallfilter.TraceEntry{
					Type:     "binary",
					Path:     execPath,
					Syscalls: []int{},
					Parent:   callerPackage,
				}

				// Update caller package's executed binaries list
				if callerPackage != "" {
					if entry, exists := traceStore[callerPackage]; exists {
						entry.ExecutedBinaries = append(entry.ExecutedBinaries, execPath)
					}
				}
			}

			logEvent(event, stackTrace, "binary")
			return
		}

		// Handle other syscalls from packages
		if callerPackage != "" {

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

			// Handle other syscalls from binaries
		} else if entry, exists := traceStore[execComm]; exists {

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

			// Just Log syscalls from runtime
		} else {
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

		if (event.SyscallId == 59 || event.SyscallId == 322) && event.EventType == EventSysExit {
			if callerPackage != "" && !traceStore.SyscallAllowed(callerPackage, int(event.SyscallId)) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized exec syscall %d from package %s", event.SyscallId, callerPackage),
					f)
			}
			return
		}

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

		// Handle execve/execveat syscalls
		if (event.SyscallId == 59 || event.SyscallId == 322) && event.EventType == EventSysExit {
			if exists && callerPackage != "" && !traceStore.CapabilityAllowed(callerPackage, capability) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized capability %s (exec syscall %d) from package %s",
						capability, event.SyscallId, callerPackage),
					f)
			}
			logEvent(event, stackTrace, "exec")
			return
		}

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
