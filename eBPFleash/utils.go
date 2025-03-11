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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"
)

func createLogFile(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("creating %s: %v", filename, err)
	}
	return f
}

func handleUnauthorized(pid uint32, msg string, f *os.File) {
	syscall.Kill(int(pid), syscall.SIGKILL)
	log.Print(msg)
	fmt.Fprintln(f, msg)
}

func logEvent(event ebpfEvent, stackTrace []uint64, eventType string) {

	/*
		if len(stackTrace) == 0 {
			log.Printf("No valid stack trace available for syscall: %d", event.Syscall)
			return
		}
	*/

	resolvedStackTrace := stackanalyzer.ResolveSymbols(stackTrace)
	/*
		if resolvedStackTrace == "" {
			log.Printf("Could not resolve symbols for stack trace")
		}
	*/

	callerPackage, callerFunction, err := stackanalyzer.GetCallerPackageAndFunction(stackTrace)
	if err != nil {
		log.Printf("Error getting caller package: %v", err)
		return
	}

	fmt.Println()
	fmt.Print(color.WhiteString("+------------------------------------------------------------+\n"))
	fmt.Print(color.WhiteString("| Invoked syscall: %d\tPID: %d\tCommand: %s\n", event.SyscallId, event.Pid, unix.ByteSliceToString(event.ProcessName[:])))
	fmt.Print(color.WhiteString("+------------------------------------------------------------+\n"))

	switch eventType {
	case "package":
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.WhiteString("GO_PKG"))
		fmt.Print(color.GreenString("Caller Package: "))
		fmt.Println(color.WhiteString("%s", callerPackage))
		fmt.Print(color.GreenString("Caller Function: "))
		fmt.Println(color.WhiteString("%s", callerFunction))
		fmt.Print(color.GreenString("Stack Trace: \n"))
		fmt.Println(color.WhiteString("%s", resolvedStackTrace))

	case "binary":
		ProcessName := string(bytes.TrimRight(event.ProcessName[:], "\x00"))
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.WhiteString("EXT_BIN"))
		fmt.Print(color.GreenString("Caller Command: "))
		fmt.Println(color.WhiteString("%s", ProcessName))
		fmt.Print(color.GreenString("Stack Trace: \n"))
		fmt.Println(color.WhiteString("%s", resolvedStackTrace))
	case "runtime":
		color.Magenta("Event Type: GO_RUNTIME")
		fmt.Println(color.MagentaString("%s", resolvedStackTrace))
	default:
		color.Red("Event Type: Unknown")
	}

	fmt.Println()

}

func loadEBPF() (*ebpfObjects, *ringbuf.Reader, []*link.Link, error) {
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
		objs.Close()
		return nil, nil, nil, fmt.Errorf("opening sys_enter tracepoint: %w", err)
	}
	tps = append(tps, &tpEnter)

	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.TraceSyscallExit, nil)
	if err != nil {
		tpEnter.Close()
		objs.Close()
		return nil, nil, nil, fmt.Errorf("opening sys_exit tracepoint: %w", err)
	}
	tps = append(tps, &tpExit)

	// Open a ringbuf reader from userspace RINGBUF map described in the eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tpEnter.Close()
		tpExit.Close()
		objs.Close()
		return nil, nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &objs, rd, tps, nil
}

func setupAndRun(binaryPath string, modManifestPath string, processEvent func(ebpfEvent, []uint64, *ebpfObjects)) {
	if err := binanalyzer.LoadBinarySymbolsCache(binaryPath); err != nil {
		log.Fatalf("Populating symbol cache: %v", err)
	}

	// Load module cache
	if err := stackanalyzer.LoadModuleCache(modManifestPath); err != nil {
		log.Fatalf("Loading module cache: %v", err)
	}

	objs, rd, tps, err := loadEBPF()
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
