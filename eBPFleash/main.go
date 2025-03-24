package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sync"

	"github.com/chains-project/goleash/eBPFleash/binanalyzer"
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
	flag.StringVar(&config.Mode, "mode", "enforce", "Execution mode: 'build', 'sys-enforce', 'cap-enforce'")
	flag.StringVar(&config.ModuleManifest, "manifest", "", "Path to the go.mod manifest file")
	flag.Parse()

	if config.BinaryPath == "" || config.ModuleManifest == "" {
		log.Fatal("Both -binary and -manifest flags are required")
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

	setupAndRun(BUILD_MODE, args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		resolvedStackTrace := binanalyzer.ResolveStackTrace(stackTrace)
		_, callerPackage, _ := stackanalyzer.FindCallerPackage(resolvedStackTrace)

		mu.Lock()
		defer mu.Unlock()

		// Handle execve/execveat syscalls (59/322) on SYS_EXIT
		if (event.SyscallId == 59 || event.SyscallId == 322) && event.EventType == EventSysExit {

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

	setupAndRun(ENFORCE_MODE, args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {

		sysID := int(event.SyscallId)
		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		resolvedStackTrace := binanalyzer.ResolveStackTrace(stackTrace)
		_, callerPackage, _ := stackanalyzer.FindCallerPackage(resolvedStackTrace)

		if originalComm == "" {
			originalComm = execComm
		}

		if callerPackage != "" {
			// CASE A: Syscall from a Go package
			logEvent(event, stackTrace, "package")

			if !traceStore.HasEntry(callerPackage) {
				if stackanalyzer.IsPackageInCache(callerPackage) {
					log.Printf("Warning: package %s not in allowlist but found in Go manifest", callerPackage)
					return
				} else {
					KillUnauthorized(event.Pid,
						fmt.Sprintf("Deny: package %s not in allowlist for syscall %d",
							callerPackage, sysID),
						f)
					return
				}
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
			logEvent(event, stackTrace, "binary")

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
			logEvent(event, stackTrace, "runtime")

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

	setupAndRun(ENFORCE_MODE, args.BinaryPath, args.ModuleManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		execComm := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		resolvedStackTrace := binanalyzer.ResolveStackTrace(stackTrace)
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
			logEvent(event, stackTrace, "package")

			if !traceStore.HasEntry(callerPackage) {
				if stackanalyzer.IsPackageInCache(callerPackage) {
					log.Printf("Warning: package %s not in allowlist but found in Go manifest", callerPackage)
					return
				} else {
					KillUnauthorized(event.Pid,
						fmt.Sprintf("Deny: package %s not in allowlist for capability %s",
							callerPackage, capability),
						f)
					return
				}
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
			logEvent(event, stackTrace, "binary")

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
			logEvent(event, stackTrace, "runtime")

			// We assume that the syscall is allowed (trusted) if we reach this point
			return

		} else {
			KillUnauthorized(event.Pid,
				fmt.Sprintf("Deny: syscall %d. Unrecognized capability event.", event.SyscallId),
				f)
		}

		logEvent(event, stackTrace, "none")
	})
}
