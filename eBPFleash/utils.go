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
	"golang.org/x/sys/unix"
)

func logEvent(event ebpfEvent, stackTrace []uint64) {

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

	fmt.Printf("\n")
	log.Printf("Invoked syscall: %d\tpid: %d\tcomm: %s\n",
		event.Syscall, event.Pid, unix.ByteSliceToString(event.Comm[:]))

	//if callerPackage != "" && callerFunction != "" {
	log.Printf("Stack Trace:\n%s", resolvedStackTrace)
	log.Printf("Go caller package: %s", callerPackage)
	log.Printf("Go caller function: %s", callerFunction)
	//} else {
	//	log.Printf("Go Runtime Invocation")
	//}

}

func loadEBPF() (*ebpfObjects, *ringbuf.Reader, *link.Link, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load pre-compiled eBPF program and maps into the kernel.
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("loading objects: %w", err)
	}

	// Open a tracepoint and attach the pre-compiled program.
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSyscall, nil)
	if err != nil {
		objs.Close()
		return nil, nil, nil, fmt.Errorf("opening tracepoint: %w", err)
	}

	// Open a ringbuf reader from userspace RINGBUF map described in the eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &objs, rd, &tp, nil
}

func setupAndRun(binaryPath string, modManifestPath string, processEvent func(ebpfEvent, []uint64, *ebpfObjects)) {
	if err := binanalyzer.LoadBinarySymbolsCache(binaryPath); err != nil {
		log.Fatalf("Populating symbol cache: %v", err)
	}

	// Load module cache
	if err := stackanalyzer.LoadModuleCache(modManifestPath); err != nil {
		log.Fatalf("Loading module cache: %v", err)
	}

	objs, rd, tp, err := loadEBPF()
	if err != nil {
		log.Fatalf("Setting up eBPF: %v", err)
	}
	defer objs.Close()
	defer rd.Close()
	defer (*tp).Close()

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

				stackTrace, err := stackanalyzer.GetStackTrace(objs.Stacktraces, event.StackId)
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
