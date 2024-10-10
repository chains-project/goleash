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

	"github.com/chains-project/goleash/track_syscalls/binanalyzer"
	"github.com/chains-project/goleash/track_syscalls/stackanalyzer"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func logEvent(event ebpfEvent, stackTrace []uint64, objs *ebpfObjects) {
	resolvedStackTrace := stackanalyzer.ResolveSymbols(stackTrace)
	firstGoFunc := stackanalyzer.GetFirstGoPackageFunction(stackTrace)
	callerPackage := stackanalyzer.GetCallerPackage(stackTrace)

	fmt.Printf("\n")
	log.Printf("Invoked syscall: %d\tpid: %d\tcomm: %s\n",
		event.Syscall, event.Pid, unix.ByteSliceToString(event.Comm[:]))
	log.Printf("Stack Trace:\n%s", resolvedStackTrace)
	log.Printf("Go caller function: %s", firstGoFunc)
	log.Printf("Go caller package: %s", callerPackage)
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

func setupAndRun(binaryPath string, processEvent func(ebpfEvent, []uint64, *ebpfObjects)) {
	if err := binanalyzer.Populate(binaryPath); err != nil {
		log.Fatalf("Populating symbol cache: %v", err)
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

				stackTrace, _ := stackanalyzer.GetStackTrace(objs.Stacktraces, event.StackId)
				processEvent(event, stackTrace, objs)
			}
		}
	}()

	<-stopChan
}
