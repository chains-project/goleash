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

type Args struct {
	BinaryPath  string
	Mode        string
	ModManifest string
}

func main() {
	log.SetFlags(log.Ltime)

	var args Args
	flag.StringVar(&args.BinaryPath, "binary", "", "Path to the binary for syscall tracking")
	flag.StringVar(&args.Mode, "mode", "enforce", "Execution mode: 'build', 'enforce' or 'trace'")
	flag.StringVar(&args.ModManifest, "mod-manifest", "", "Path to the go.mod manifest file")

	flag.Parse()

	if args.BinaryPath == "" {
		log.Fatal("Please provide a binary path using the -binary flag")
	}

	if args.ModManifest == "" {
		log.Fatal("Please provide a go.mod manifest file path using the -mod-manifest flag. This is required to determine the caller package of a syscall.")
	}

	switch args.Mode {
	case "build":
		runBuildMode(args)
	case "enforce":
		runEnforceMode(args)
	case "trace":
		runTraceMode(args)
	default:
		log.Fatalf("Invalid mode: %s. Use 'build', 'enforce' or 'trace'", args.Mode)
	}

}

func runBuildMode(args Args) {
	syscalls := make(map[string]map[int]bool)
	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.ResolveCallerAndPackageNameFromStackTrace(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}
		if callerPackage != "" {
			if _, ok := syscalls[callerPackage]; !ok {
				syscalls[callerPackage] = make(map[int]bool)
			}
			syscalls[callerPackage][int(event.Syscall)] = true
		}
		logEvent(event, stackTrace)
	})

	// Convert syscalls map to the format expected by syscallfilter.Write
	convertedSyscalls := syscallfilter.ConvertSyscallsMap(syscalls)

	if err := syscallfilter.Write(convertedSyscalls); err != nil {
		log.Fatalf("Writing allowlist JSON: %v", err)
	}
	log.Println("Build mode completed. Allowlist JSON file created.")
}

func runTraceMode(args Args) {
	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		// Just log the event
		logEvent(event, stackTrace)
	})
	log.Println("Trace mode completed.")
}

func runEnforceMode(args Args) {
	allowlist, err := syscallfilter.Load()
	if err != nil {
		log.Fatalf("loading allowlist: %v", err)
	}

	f, err := os.Create("unauthorized.log")
	if err != nil {
		log.Fatalf("creating unauthorized.log: %v", err)
	}
	defer f.Close()

	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.ResolveCallerAndPackageNameFromStackTrace(stackTrace)
		if err != nil {
			log.Printf("Error getting caller package: %v", err)
			return
		}
		logEvent(event, stackTrace)
		if callerPackage != "" && !allowlist.SyscallAllowed(callerPackage, int(event.Syscall)) {
			log.Printf("Unauthorized syscall %d from package %s", event.Syscall, callerPackage)
			fmt.Fprintf(f, "Unauthorized syscall %d from package %s\n", event.Syscall, callerPackage)

			syscall.Kill(int(event.Pid), syscall.SIGKILL)
		}
	})
}
