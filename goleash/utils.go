package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/chains-project/goleash/goleash/binanalyzer"
	"github.com/chains-project/goleash/goleash/stackanalyzer"
	"github.com/chains-project/goleash/goleash/syscallfilter"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"
)

const (
	ENFORCE_MODE = 0
	BUILD_MODE   = 1
)

func createLogFile(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("creating %s: %v", filename, err)
	}
	return f
}

func KillUnauthorized(pid uint32, msg string, f *os.File) {
	syscall.Kill(int(pid), syscall.SIGKILL)
	log.Print(msg)
	fmt.Fprintln(f, msg)
}

func WarningAuthorized(pid uint32, msg string, f *os.File) {
	log.Print(msg)
	fmt.Fprintln(f, msg)
}

func logEvent(event ebpfEvent, stackTrace []uint64, eventType string) {

	resolvedStackTrace := binanalyzer.ResolveStackTrace(unix.ByteSliceToString(event.ProcessName[:]), stackTrace)
	_, callerPackage, callerFunction := stackanalyzer.FindCallerPackage(resolvedStackTrace)

	// Get capability associated with the syscall
	capability, hasCapability := syscallfilter.SyscallToCapability[int(event.SyscallId)]
	if !hasCapability {
		capability = "UNKNOWN"
	}

	fmt.Println()
	fmt.Print(color.WhiteString("+------------------------------------------------------------+\n"))
	fmt.Print(color.WhiteString("| Invoked syscall: %d\tPID: %d\tCommand: %s\n", event.SyscallId, event.Pid, unix.ByteSliceToString(event.ProcessName[:])))
	fmt.Print(color.WhiteString("| Required capability: %s\n", capability))
	fmt.Print(color.WhiteString("+------------------------------------------------------------+\n"))

	switch eventType {
	case "package":
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.WhiteString("GO_PKG"))
		fmt.Print(color.GreenString("Caller Package: "))
		fmt.Println(color.WhiteString("%s", callerPackage))
		fmt.Print(color.GreenString("Caller Function: "))
		fmt.Println(color.WhiteString("%s", callerFunction))
		fmt.Print(color.GreenString("Stack Trace "))
		fmt.Print(color.GreenString("(ID %d):\n", event.StackTraceId))
		for _, frame := range resolvedStackTrace {
			fmt.Println(color.WhiteString("%s", frame))
		}
	case "binary":
		ProcessName := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.WhiteString("EXT_BIN"))
		fmt.Print(color.GreenString("Caller Command: "))
		fmt.Println(color.WhiteString("%s", ProcessName))
		fmt.Print(color.GreenString("Stack Trace "))
		fmt.Print(color.GreenString("(ID %d):\n", event.StackTraceId))
		for _, frame := range resolvedStackTrace {
			fmt.Println(color.WhiteString("%s", frame))
		}
	case "runtime":
		color.Magenta("Event Type: GO_RUNTIME")
		for _, frame := range resolvedStackTrace {
			fmt.Println(color.MagentaString("%s", frame))
		}
	default:
		color.Red("Event Type: Unknown")
	}

	fmt.Println()

}

func loadEBPF(mode int) (*ebpfObjects, *ringbuf.Reader, []link.Link, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load pre-compiled eBPF program and maps into the kernel.
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("loading objects: %w", err)
	}

	var tps []link.Link

	// 1. ATTACH HOT PATH (Syscall Enter)
	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSyscallEnter, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sys_enter tracepoint: %w", err)
	}
	tps = append(tps, tpEnter)

	// 2. ATTACH EXEC HOOK (New Process Detection) - CRITICAL FOR TRACKING
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExecEvent, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sched_process_exec tracepoint: %w", err)
	}
	tps = append(tps, tpExec)

	// 3. ATTACH FORK HOOK (Worker Detection) - CRITICAL FOR WORKERS
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceFork, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sched_process_fork tracepoint: %w", err)
	}
	tps = append(tps, tpFork)

	// 4. ATTACH EXIT HOOK (Cleanup)
	tpProcessExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sched_process_exit tracepoint: %w", err)
	}
	tps = append(tps, tpProcessExit)

	// 5. ATTACH SYSCALL EXIT (Only in Build Mode)
	if mode == BUILD_MODE {
		tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.TraceSyscallExit, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("opening sys_exit tracepoint: %w", err)
		}
		tps = append(tps, tpExit)
	}

	// Open a ringbuf reader from userspace RINGBUF map described in the eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &objs, rd, tps, nil
}

func setupAndRun(mode int, binaryPaths []string, processEvent func(ebpfEvent, []uint64, *ebpfObjects)) {
	if err := binanalyzer.LoadBinarySymbolsCache(binaryPaths); err != nil {
		log.Fatalf("Populating symbol cache: %v", err)
	}

	objs, rd, tps, err := loadEBPF(mode)
	if err != nil {
		log.Fatalf("Setting up eBPF: %v", err)
	}
	defer objs.Close()
	defer rd.Close()
	for _, tp := range tps {
		defer tp.Close()
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	log.Println("\nTracking syscalls")
	log.Println("List of binaries being tracked...")
	for _, path := range binaryPaths {
		fmt.Println(path)
	}

	// -------------------------------------------------------------------------
	// STACK CACHE INITIALIZATION
	// -------------------------------------------------------------------------
	// We use this map to avoid querying the Kernel Map (syscall) for every event.
	// Map Key:   Stack ID (uint32)
	// Map Value: Slice of Instruction Pointers ([]uint64)
	stackCache := make(map[uint32][]uint64)

	go func() {
		var event ebpfEvent
		for {
			select {
			case <-stopChan:
				log.Println("Received signal, stopping syscall tracking...")
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Reading from reader: %s", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					log.Printf("Parsing ringbuf event: %s", err)
					continue
				}

				// -------------------------------------------------------------
				// CACHED STACK RETRIEVAL
				// -------------------------------------------------------------
				var stackTrace []uint64

				// Only resolve stacks for Syscall Events, not lifecycle events
				if event.EventType == EventSysEnter || event.EventType == EventSysExit {
					var ok bool
					// 1. Check User-Space Cache first
					if stackTrace, ok = stackCache[event.StackTraceId]; !ok {
						// 2. Cache Miss: Query the Kernel Map (Expensive Syscall)
						// Only done once per unique stack ID
						stackTrace, err = stackanalyzer.GetStackTrace(objs.Stacktraces, event.StackTraceId)
						if err != nil {
							// If the stack is missing (e.g., -EFAULT or overwritten),
							// we pass an empty slice to avoid crashing, but we don't cache the error.
							// log.Printf("Getting stack trace from kernel: %s", err)
							stackTrace = []uint64{}
						} else {
							// 3. Update Cache
							stackCache[event.StackTraceId] = stackTrace
						}
					}
				}

				processEvent(event, stackTrace, objs)
			}
		}
	}()

	<-stopChan
}
