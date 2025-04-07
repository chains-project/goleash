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

	"github.com/chains-project/goleash/eBPFleash/binanalyzer"
	"github.com/chains-project/goleash/eBPFleash/stackanalyzer"
	"github.com/chains-project/goleash/eBPFleash/syscallfilter"
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

	resolvedStackTrace := binanalyzer.ResolveStackTrace(stackTrace)
	_, callerPackage, callerFunction := stackanalyzer.FindCallerPackage(resolvedStackTrace)

	// Get capability associated with the syscall
	capability, hasCapability := syscallfilter.SyscallToCapability[int(event.SyscallId)]
	if !hasCapability {
		capability = "UNKNOWN"
	}

	fmt.Println()
	fmt.Print(color.BlackString("+------------------------------------------------------------+\n"))
	fmt.Print(color.BlackString("| Invoked syscall: %d\tPID: %d\tCommand: %s\n", event.SyscallId, event.Pid, unix.ByteSliceToString(event.ProcessName[:])))
	fmt.Print(color.BlackString("| Required capability: %s\n", capability))
	fmt.Print(color.BlackString("+------------------------------------------------------------+\n"))

	switch eventType {
	case "package":
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.BlackString("GO_PKG"))
		fmt.Print(color.GreenString("Caller Package: "))
		fmt.Println(color.BlackString("%s", callerPackage))
		fmt.Print(color.GreenString("Caller Function: "))
		fmt.Println(color.BlackString("%s", callerFunction))
		fmt.Print(color.GreenString("Stack Trace "))
		fmt.Print(color.GreenString("(ID %d):\n", event.StackTraceId))
		for _, frame := range resolvedStackTrace {
			fmt.Println(color.BlackString("%s", frame))
		}
	case "binary":
		ProcessName := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.BlackString("EXT_BIN"))
		fmt.Print(color.GreenString("Caller Command: "))
		fmt.Println(color.BlackString("%s", ProcessName))
		fmt.Print(color.GreenString("Stack Trace "))
		fmt.Print(color.GreenString("(ID %d):\n", event.StackTraceId))
		for _, frame := range resolvedStackTrace {
			fmt.Println(color.BlackString("%s", frame))
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

const (
	// The path to the ELF binary containing the function to trace.
	// On some distributions, the 'readline' function is provided by a
	// dynamically-linked library, so the path of the library will need
	// to be specified instead, e.g. /usr/lib/libreadline.so.8.
	// Use `ldd /bin/bash` to find these paths.
	binPath = "/home/carmine/projects/workspace_goleash/goleash/exp1/testMalicious/target/testMalicious"
	symbol  = "runtime.newproc"
)

func loadEBPF(mode int) (*ebpfObjects, *ringbuf.Reader, []*link.Link, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load pre-compiled eBPF program and maps into the kernel.
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("loading objects: %w", err)
	}

	// Open two tracepoint and attach the pre-compiled program.
	var tps []*link.Link
	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSyscallEnter, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sys_enter tracepoint: %w", err)
	}
	tps = append(tps, &tpEnter)

	if mode == BUILD_MODE {
		var tpExit link.Link
		tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.TraceSyscallExit, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("opening sys_exit tracepoint: %w", err)
		}
		tps = append(tps, &tpExit)
	}

	// Open a ringbuf reader from userspace RINGBUF map described in the eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &objs, rd, tps, nil
}

func setupAndRun(mode int, binaryPath string, processEvent func(ebpfEvent, []uint64, *ebpfObjects)) {
	if err := binanalyzer.LoadBinarySymbolsCache(binaryPath); err != nil {
		log.Fatalf("Populating symbol cache: %v", err)
	}

	objs, rd, tps, err := loadEBPF(mode)
	if err != nil {
		log.Fatalf("Setting up eBPF: %v", err)
	}
	defer objs.Close()
	defer rd.Close()
	for _, tp := range tps {
		defer (*tp).Close()
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	log.Println("Tracking syscalls...")

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

				stackTrace, err := stackanalyzer.GetStackTrace(objs.Stacktraces, event.StackTraceId)

				if err != nil {
					log.Printf("Getting stack trace: %s", err)
					continue
				}
				processEvent(event, stackTrace, objs)
			}
		}
	}()

	<-stopChan
}
