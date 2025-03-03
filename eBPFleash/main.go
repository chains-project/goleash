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

type Args struct {
	BinaryPath  string
	Mode        string
	ModManifest string
}

var (
	mu sync.Mutex // Mutex for concurrent writes
)

func main() {
	log.SetFlags(log.Ltime)

	var args Args
	flag.StringVar(&args.BinaryPath, "binary", "", "Path to the binary for syscall tracking")
	flag.StringVar(&args.Mode, "mode", "enforce", "Execution mode: 'build', 'sys-enforce', 'cap-enforce' or 'trace'")
	flag.StringVar(&args.ModManifest, "manifest", "", "Path to the go.mod manifest file")
	flag.Parse()

	if args.BinaryPath == "" || args.ModManifest == "" {
		log.Fatal("Both -binary and -manifest flags are required")
	}

	modes := map[string]func(Args){
		"build":       runBuildMode,
		"sys-enforce": runSysEnforceMode,
		"cap-enforce": runCapabilityEnforceMode,
		"trace":       runTraceMode,
	}

	if fn, exists := modes[args.Mode]; exists {
		fn(args)
	} else {
		log.Fatalf("Invalid mode: %s. Use 'build', 'sys-enforce', 'cap-enforce' or 'trace'", args.Mode)
	}
}

func runBuildMode(args Args) {
	traceStore := make(map[string]*syscallfilter.TraceEntry)
	syscalls := make(map[string]map[int]bool)

	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		// Name of the current executed command
		eventComm := string(bytes.TrimRight(event.Comm[:], "\x00"))
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
			syscalls[callerPackage][int(event.Syscall)] = true

			uniqueSyscalls := make([]int, 0, len(syscalls[callerPackage]))
			for syscall := range syscalls[callerPackage] {
				uniqueSyscalls = append(uniqueSyscalls, syscall)
			}
			traceStore[callerPackage].Syscalls = uniqueSyscalls

			// Case 2: syscall invoked (eventually) by an external binary
		} else if entry, exists := traceStore[eventComm]; exists {
			eventType = "binary"
			if _, ok := syscalls[eventComm]; !ok {
				syscalls[eventComm] = make(map[int]bool)
			}
			syscalls[eventComm][int(event.Syscall)] = true

			uniqueSyscalls := make([]int, 0, len(syscalls[eventComm]))
			for syscall := range syscalls[eventComm] {
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

func runTraceMode(args Args) {
	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		logEvent(event, stackTrace, "none")
	})
	log.Println("Trace mode completed.")
}

func runSysEnforceMode(args Args) {
	traceStore, err := syscallfilter.LoadTraceStore()
	if err != nil {
		log.Fatalf("loading syscall allowlist: %v", err)
	}

	f := createLogFile("unauthorized_syscalls.log")
	defer f.Close()

	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}
		logEvent(event, stackTrace, "none")

		if callerPackage != "" && !traceStore.SyscallAllowed(callerPackage, int(event.Syscall)) {
			handleUnauthorized(event.Pid,
				fmt.Sprintf("Unauthorized syscall %d from package %s", event.Syscall, callerPackage),
				f)
		}
	})
}

func runCapabilityEnforceMode(args Args) {
	traceStore, err := syscallfilter.LoadTraceStore()
	if err != nil {
		log.Fatalf("loading capability allowlist: %v", err)
	}

	f := createLogFile("unauthorized_capabilities.log")
	defer f.Close()

	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}

		capability, exists := syscallfilter.GetCapabilityForSyscall(int(event.Syscall))
		if exists && callerPackage != "" && !traceStore.CapabilityAllowed(callerPackage, capability) {
			handleUnauthorized(event.Pid,
				fmt.Sprintf("Unauthorized capability %s (syscall %d) from package %s",
					capability, event.Syscall, callerPackage),
				f)
		}
		logEvent(event, stackTrace, "none")
	})
}
