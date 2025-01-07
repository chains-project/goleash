package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/chains-project/goleash/eBPFleash/stackanalyzer"
	"github.com/chains-project/goleash/eBPFleash/syscallfilter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cflags "-DTARGET_CMD='\"${TARGET_CMD}\"'" ebpf backend.c

type Args struct {
	BinaryPath  string
	Mode        string
	ModManifest string
}

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

func createLogFile(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("creating %s: %v", filename, err)
	}
	return f
}

func handleUnauthorized(pid uint32, msg string, f *os.File) {
	log.Print(msg)
	fmt.Fprintln(f, msg)
	syscall.Kill(int(pid), syscall.SIGKILL)
}

func runBuildMode(args Args) {
	syscalls := make(map[string]map[int]bool)
	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		callerPackage, _, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
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

	// Generate and write capability allowlist
	capAllowlist := syscallfilter.GenerateCapabilityMap(convertedSyscalls)
	if err := syscallfilter.WriteCapabilities(capAllowlist); err != nil {
		log.Fatalf("Writing capabilities JSON: %v", err)
	}

	log.Println("Build mode completed. Allowlist and capabilities JSON files created.")
}

func runTraceMode(args Args) {
	setupAndRun(args.BinaryPath, args.ModManifest, func(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
		// Just log the event
		logEvent(event, stackTrace)
	})
	log.Println("Trace mode completed.")
}

func runSysEnforceMode(args Args) {
	sysAllowlist, err := syscallfilter.LoadSyscalls()
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
		logEvent(event, stackTrace)
		if callerPackage != "" && !sysAllowlist.SyscallAllowed(callerPackage, int(event.Syscall)) {
			handleUnauthorized(event.Pid,
				fmt.Sprintf("Unauthorized syscall %d from package %s", event.Syscall, callerPackage),
				f)
		}
	})
}

func runCapabilityEnforceMode(args Args) {
	capAllowlist, err := syscallfilter.LoadCapabilities()
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
		if exists && callerPackage != "" {
			if !capAllowlist.CapabilityAllowed(callerPackage, capability) {
				handleUnauthorized(event.Pid,
					fmt.Sprintf("Unauthorized capability %s (syscall %d) from package %s",
						capability, event.Syscall, callerPackage),
					f)
			}
		}
		logEvent(event, stackTrace)
	})
}
