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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/chains-project/goleash/goleash/binanalyzer"
	"github.com/chains-project/goleash/goleash/stackanalyzer"
	"github.com/chains-project/goleash/goleash/syscallfilter"
	"github.com/cilium/ebpf"
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

// commCache holds tgid -> comm, populated from EVENT_TRACK_START events
// emitted by trace_exec_event / trace_fork in backend.c. This replaces the
// per-syscall bpf_get_current_comm read on the BPF hot path (Fix 3) and lets
// us drop the 256-byte process_name field from the ringbuf event (Fix 2).
var (
	commCache   = make(map[uint32]string)
	commCacheMu sync.RWMutex
)

// getProcessName returns the comm for a tgid. Cache first; falls back to
// /proc/<pid>/comm in the rare case the lifecycle event was missed.
func getProcessName(pid uint32) string {
	commCacheMu.RLock()
	name, ok := commCache[pid]
	commCacheMu.RUnlock()
	if ok {
		return name
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	name = string(bytes.TrimRight(bytes.TrimRight(data, "\n"), "\x00"))
	commCacheMu.Lock()
	commCache[pid] = name
	commCacheMu.Unlock()
	return name
}

// updateProcessName is invoked when an EVENT_TRACK_START event arrives.
func updateProcessName(pid uint32, raw []byte) {
	name := unix.ByteSliceToString(raw)
	commCacheMu.Lock()
	commCache[pid] = name
	commCacheMu.Unlock()
}

// payloadBytes returns the 256-byte payload union of an event as a byte
// slice. bpf2go renders the union with only the first member named, so we
// re-expose the underlying bytes via unsafe to access both comm[:16] and
// exec_path[:256] views.
func payloadBytes(p *struct {
	Comm [16]int8
	_    [240]byte
}) []byte {
	return (*[256]byte)(unsafe.Pointer(p))[:]
}

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

	procName := getProcessName(event.Pid)
	resolvedStackTrace := binanalyzer.ResolveStackTrace(procName, stackTrace)
	_, callerPackage, callerFunction := stackanalyzer.FindCallerPackage(resolvedStackTrace)

	// Get capability associated with the syscall
	capability, hasCapability := syscallfilter.SyscallToCapability[int(event.SyscallId)]
	if !hasCapability {
		capability = "UNKNOWN"
	}

	fmt.Println()
	fmt.Print(color.WhiteString("+------------------------------------------------------------+\n"))
	fmt.Print(color.WhiteString("| Invoked syscall: %d\tPID: %d\tCommand: %s\n", event.SyscallId, event.Pid, procName))
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
		fmt.Print(color.GreenString("Event Type: "))
		fmt.Println(color.WhiteString("EXT_BIN"))
		fmt.Print(color.GreenString("Caller Command: "))
		fmt.Println(color.WhiteString("%s", procName))
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

	// 3. ATTACH FORK HOOK — propagates task_storage to new threads/children.
	// This is a tp_btf program (BPF_PROG_TYPE_TRACING attached at
	// BPF_TRACE_RAW_TP), required because the verifier needs the child
	// task as a *trusted* pointer to write task_storage on it; a plain
	// tracepoint only exposes pid_t fields, from which we'd have to walk
	// to a task via BPF_CORE_READ — and that yields a scalar pointer the
	// verifier rejects.
	tpFork, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TraceFork,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("attaching tp_btf sched_process_fork: %w", err)
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
	// stackCache avoids re-fetching raw instruction pointers from the kernel BPF
	// map on each event. Cache hit rate is shown in the periodic metrics log.
	//
	// NOTE: the next level of caching — avoiding ResolveStackTrace + FindCallerPackage
	// for the same stack_id — must live in each processEvent callback in main.go,
	// because resolution happens there, not here.
	stackCache := make(map[uint32][]uint64)

	// -------------------------------------------------------------------------
	// CONSUMER METRICS
	// -------------------------------------------------------------------------
	var (
		eventsProcessed   atomic.Int64
		stackCacheHits    atomic.Int64
		stackCacheMisses  atomic.Int64
		maxLagNs          atomic.Int64 // reset each reporting interval
		processEventNsSum atomic.Int64 // cumulative ns spent inside processEvent callback
	)

	// Compute the offset between CLOCK_MONOTONIC (used by bpf_ktime_get_ns) and
	// CLOCK_REALTIME (used by time.Now().UnixNano()), so we can convert kernel
	// timestamps to wall-clock time for lag measurement.
	var monoTs unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &monoTs)
	monoToRealOffsetNs := time.Now().UnixNano() - (monoTs.Sec*int64(time.Second) + int64(monoTs.Nsec))

	doneChan := make(chan struct{})

	// Periodic reporter: prints consumer throughput, stack cache hit rate, and
	// max observed consumer lag (time from kernel event creation to userspace read).
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
				hits := stackCacheHits.Load()
				misses := stackCacheMisses.Load()
				total := hits + misses
				hitRate := 0.0
				if total > 0 {
					hitRate = float64(hits) / float64(total) * 100
				}
				maxLag := time.Duration(maxLagNs.Swap(0))
				log.Printf("[metrics] consumer: %d events/s | stack cache: %.1f%% hit (%d/%d total) | max lag: %v",
					rate, hitRate, hits, total, maxLag)
			}
		}
	}()

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

				// Lifecycle event: just refresh the tgid -> comm cache and
				// move on (do not pass to processEvent — no syscall data).
				if event.EventType == EventTrackStart {
					updateProcessName(event.Pid, payloadBytes(&event.Payload))
					continue
				}

				eventsProcessed.Add(1)

				// Measure how old this event is: time elapsed since the kernel
				// wrote it into the ring buffer. Large values mean the consumer
				// is falling behind and the ring buffer is under pressure.
				// KernelTs is CLOCK_MONOTONIC; add monoToRealOffsetNs to align
				// it with time.Now().UnixNano() (CLOCK_REALTIME).
				if event.KernelTs > 0 {
					lagNs := time.Now().UnixNano() - (int64(event.KernelTs) + monoToRealOffsetNs)
					if lagNs > maxLagNs.Load() {
						maxLagNs.Store(lagNs)
					}
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
						stackCacheMisses.Add(1)
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
					} else {
						stackCacheHits.Add(1)
					}
				}

				peStart := time.Now()
				processEvent(event, stackTrace, objs)
				processEventNsSum.Add(time.Since(peStart).Nanoseconds())
			}
		}
	}()

	<-stopChan
	close(doneChan)

	// -------------------------------------------------------------------------
	// FINAL PROBE STATS (kernel-side counters + userspace timings)
	// -------------------------------------------------------------------------
	// ringbuf_drops:     events lost because the consumer was too slow.
	// stackid_failures:  bpf_get_stackid failures (Go relocatable stacks).
	// enter_for_tracked: every sys_enter for a tracked PID (before dedup).
	// enter_admitted:    events that passed dedup (or were execve) and tried
	//                    a ringbuf reserve.
	// Derived:
	//   dedup_dropped   = enter_for_tracked - enter_admitted
	//   submitted       = enter_admitted    - ringbuf_drops
	// probe_stats counters — all cold-path only, see trace.bpf.h.
	// The hot path of trace_syscall_enter does NOT increment any of these,
	// so they add zero overhead to syscall-throughput measurements.
	statLabels := []string{
		"ringbuf_drops",
		"stackid_failures",
		"enter_admitted",
	}
	// probe_stats is BPF_MAP_TYPE_PERCPU_ARRAY: Lookup returns a slice with
	// one value per CPU and we sum across CPUs ourselves. This is the price
	// of getting LOCK-XADD-contention-free counter increments inside the
	// kernel hot path.
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

	// seen_pairs map size = number of unique (syscall_id, stack_trace_id) pairs
	// kept by the kernel-side dedup. High value relative to enter_for_tracked
	// means low dedup effectiveness (high stack diversity).
	uniquePairs := countMapEntries(objs.SeenPairs)
	log.Printf("[probe_stats] seen_pairs_unique: %d", uniquePairs)

	consumed := eventsProcessed.Load()
	hits := stackCacheHits.Load()
	misses := stackCacheMisses.Load()
	peSumNs := processEventNsSum.Load()
	var avgPeNs int64
	if consumed > 0 {
		avgPeNs = peSumNs / consumed
	}
	log.Printf("[probe_stats] consumer_total_processed: %d", consumed)
	log.Printf("[probe_stats] processEvent_total_ns: %d (avg %d ns/event)", peSumNs, avgPeNs)
	log.Printf("[probe_stats] stack_cache_hits: %d  stack_cache_misses: %d", hits, misses)

	// Derived counters, dropped (silently) if the BPF counters are missing.
	if et, okT := stats["enter_for_tracked"]; okT {
		if ea, okA := stats["enter_admitted"]; okA {
			var dedupDropped uint64
			if et >= ea {
				dedupDropped = et - ea
			}
			log.Printf("[probe_stats] derived dedup_dropped: %d", dedupDropped)
			if rd, okR := stats["ringbuf_drops"]; okR && ea >= rd {
				log.Printf("[probe_stats] derived submitted_to_ringbuf: %d", ea-rd)
			}
		}
	}

	// Persist everything to probe_stats.json so benchmark scripts can pick
	// up per-iteration values without parsing the loader log.
	dump := map[string]interface{}{
		"timestamp_unix":           time.Now().Unix(),
		"ringbuf_drops":            stats["ringbuf_drops"],
		"stackid_failures":         stats["stackid_failures"],
		"enter_admitted":           stats["enter_admitted"],
		"seen_pairs_unique":        uniquePairs,
		"consumer_total_processed": consumed,
		"process_event_total_ns":   peSumNs,
		"process_event_avg_ns":     avgPeNs,
		"stack_cache_hits":         hits,
		"stack_cache_misses":       misses,
	}
	if data, err := json.MarshalIndent(dump, "", "  "); err == nil {
		if err := os.WriteFile("probe_stats.json", data, 0o644); err != nil {
			log.Printf("[probe_stats] failed to write probe_stats.json: %v", err)
		}
	}
}

// countMapEntries iterates a hash map and returns its size. Used for the
// seen_pairs map to report the number of unique (syscall_id, stack_id) pairs
// admitted past dedup. O(n) — only called once at exit.
func countMapEntries(m *ebpf.Map) uint64 {
	if m == nil {
		return 0
	}
	var (
		key [16]byte // struct seen_key is u64 + u32 + u32 = 16 bytes
		val uint8
		n   uint64
	)
	it := m.Iterate()
	for it.Next(&key, &val) {
		n++
	}
	return n
}
