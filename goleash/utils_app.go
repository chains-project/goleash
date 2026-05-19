package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// loadEBPFApp attaches only the tracepoints needed by app-mode.
// No raw_syscalls/sys_exit (no execve special-casing); no stacktrace map.
func loadEBPFApp() (*ebpfAppObjects, *ringbuf.Reader, []link.Link, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	objs := ebpfAppObjects{}
	if err := loadEbpfAppObjects(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("loading objects: %w", err)
	}

	var tps []link.Link

	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSyscallEnter, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sys_enter tracepoint: %w", err)
	}
	tps = append(tps, tpEnter)

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExecEvent, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sched_process_exec tracepoint: %w", err)
	}
	tps = append(tps, tpExec)

	tpFork, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceFork})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("attaching tp_btf sched_process_fork: %w", err)
	}
	tps = append(tps, tpFork)

	tpProcessExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening sched_process_exit tracepoint: %w", err)
	}
	tps = append(tps, tpProcessExit)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &objs, rd, tps, nil
}

// setupAndRunApp is the app-mode counterpart of setupAndRun. No
// binanalyzer.LoadBinarySymbolsCache, no per-event stack cache, no stack
// resolution. The probe emits one event per (tgid, syscall_id) pair; this
// loop just routes it to the caller for per-binary aggregation.
func setupAndRunApp(binaryPaths []string, processEvent func(ebpfAppEvent)) {
	objs, rd, tps, err := loadEBPFApp()
	if err != nil {
		log.Fatalf("Setting up eBPF (app mode): %v", err)
	}
	defer objs.Close()
	defer rd.Close()
	for _, tp := range tps {
		defer tp.Close()
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	log.Println("\nTracking syscalls (app mode — no stack capture)")
	log.Println("List of binaries being tracked...")
	for _, path := range binaryPaths {
		fmt.Println(path)
	}

	var (
		eventsProcessed   atomic.Int64
		maxLagNs          atomic.Int64
		processEventNsSum atomic.Int64
	)

	var monoTs unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &monoTs)
	monoToRealOffsetNs := time.Now().UnixNano() - (monoTs.Sec*int64(time.Second) + int64(monoTs.Nsec))

	doneChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastCount int64
		for {
			select {
			case <-doneChan:
				return
			case <-ticker.C:
				current := eventsProcessed.Load()
				rate := (current - lastCount) / 5
				lastCount = current
				maxLag := time.Duration(maxLagNs.Swap(0))
				log.Printf("[metrics] consumer (app): %d events/s | max lag: %v", rate, maxLag)
			}
		}
	}()

	go func() {
		var event ebpfAppEvent
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

				if event.EventType == EventTrackStart {
					updateProcessNameApp(event.Pid, unsafe.Pointer(&event.Payload))
					continue
				}

				eventsProcessed.Add(1)

				if event.KernelTs > 0 {
					lagNs := time.Now().UnixNano() - (int64(event.KernelTs) + monoToRealOffsetNs)
					if lagNs > maxLagNs.Load() {
						maxLagNs.Store(lagNs)
					}
				}

				peStart := time.Now()
				processEvent(event)
				processEventNsSum.Add(time.Since(peStart).Nanoseconds())
			}
		}
	}()

	<-stopChan
	close(doneChan)

	// probe_stats schema is identical to package mode (3 PERCPU counters):
	//   index 0 = ringbuf_drops
	//   index 1 = stackid_failures (always 0 in app-mode — no stack walks)
	//   index 2 = enter_admitted   (here: unique (tgid, syscall_id) pairs)
	statLabels := []string{"ringbuf_drops", "stackid_failures", "enter_admitted"}
	stats := make(map[string]uint64, len(statLabels))
	perCPU := make([]uint64, 0)
	for i, label := range statLabels {
		if err := objs.ProbeStats.Lookup(uint32(i), &perCPU); err == nil {
			var sum uint64
			for _, v := range perCPU {
				sum += v
			}
			stats[label] = sum
			log.Printf("[probe_stats] %s: %d", label, sum)
		}
	}

	consumed := eventsProcessed.Load()
	peSumNs := processEventNsSum.Load()
	var avgPeNs int64
	if consumed > 0 {
		avgPeNs = peSumNs / consumed
	}
	log.Printf("[probe_stats] consumer_total_processed: %d", consumed)
	log.Printf("[probe_stats] processEvent_total_ns: %d (avg %d ns/event)", peSumNs, avgPeNs)

	dump := map[string]interface{}{
		"timestamp_unix":           time.Now().Unix(),
		"mode":                     "app",
		"ringbuf_drops":            stats["ringbuf_drops"],
		"stackid_failures":         stats["stackid_failures"],
		"enter_admitted":           stats["enter_admitted"],
		"seen_pairs_unique":        uint64(0),
		"consumer_total_processed": consumed,
		"process_event_total_ns":   peSumNs,
		"process_event_avg_ns":     avgPeNs,
		"stack_cache_hits":         uint64(0),
		"stack_cache_misses":       uint64(0),
	}
	if data, err := json.MarshalIndent(dump, "", "  "); err == nil {
		if err := os.WriteFile("probe_stats.json", data, 0o644); err != nil {
			log.Printf("[probe_stats] failed to write probe_stats.json: %v", err)
		}
	}
}

// updateProcessNameApp reads comm out of the ebpfApp payload union. bpf2go
// generates a distinct payload type per .o, so we take an unsafe.Pointer to
// the payload region and read the first 16 bytes (the comm prefix of the
// 256-byte union).
func updateProcessNameApp(pid uint32, payloadPtr unsafe.Pointer) {
	raw := (*[256]byte)(payloadPtr)[:16]
	name := unix.ByteSliceToString(raw)
	commCacheMu.Lock()
	commCache[pid] = name
	commCacheMu.Unlock()
}
