package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/chains-project/goleash/track_syscalls/stackanalyzer"
	"github.com/chains-project/goleash/track_syscalls/syscallfilter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event ebpf backend.c

func main() {
	log.SetFlags(log.Ltime)

	binaryPath := flag.String("binary", "", "Path to the binary for syscall tracking")
	mode := flag.String("mode", "enforce", "Execution mode: 'build', 'enforce' or 'trace'")
	flag.Parse()

	if *binaryPath == "" {
		log.Fatal("Please provide a binary path using the -binary flag")
	}

	switch *mode {
	case "build":
		runBuildMode(*binaryPath)
	case "enforce":
		runEnforceMode(*binaryPath)
	case "trace":
		runTraceMode(*binaryPath)
	default:
		log.Fatalf("Invalid mode: %s. Use 'build', 'enforce' or 'trace'", *mode)
	}

}

func runBuildMode(binaryPath string) {
	syscalls := make(map[string]map[int]bool)
	setupAndRun(binaryPath, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage := stackanalyzer.GetCallerPackage(stackTrace)
		if callerPackage != "" {
			if _, ok := syscalls[callerPackage]; !ok {
				syscalls[callerPackage] = make(map[int]bool)
			}
			syscalls[callerPackage][int(event.Syscall)] = true
		}
		logEvent(event, stackTrace, objs)
	})

	// Convert syscalls map to the format expected by syscallfilter.Write
	convertedSyscalls := syscallfilter.ConvertSyscallsMap(syscalls)

	if err := syscallfilter.Write(convertedSyscalls); err != nil {
		log.Fatalf("Writing allowlist JSON: %v", err)
	}
	log.Println("Build mode completed. Allowlist JSON file created.")
}

func runTraceMode(binaryPath string) {
	setupAndRun(binaryPath, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		// Just log the event
		logEvent(event, stackTrace, objs)
	})
	log.Println("Trace mode completed.")
}

func runEnforceMode(binaryPath string) {
	allowlist, err := syscallfilter.Load()
	if err != nil {
		log.Fatalf("loading allowlist: %v", err)
	}

	f, err := os.Create("unauthorized.log")
	if err != nil {
		log.Fatalf("creating unauthorized.log: %v", err)
	}
	defer f.Close()

	setupAndRun(binaryPath, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage := stackanalyzer.GetCallerPackage(stackTrace)
		logEvent(event, stackTrace, objs)
		if callerPackage != "" && !allowlist.SyscallAllowed(callerPackage, int(event.Syscall)) {
			log.Printf("Unauthorized syscall %d from package %s", event.Syscall, callerPackage)
			fmt.Fprintf(f, "Unauthorized syscall %d from package %s\n", event.Syscall, callerPackage)

			syscall.Kill(int(event.Pid), syscall.SIGKILL)
		}
	})
}
