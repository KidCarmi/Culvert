package main

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M3 runtime/host collector — gated at L2 (runtime facts), so the standard L1
// bundle is byte-unchanged and an operator opts into the deeper capture by
// raising the bundle debug level. Numeric, non-sensitive facts only: no
// goroutine stack dump (deferred to a scrubbed L3 collector), no network, no
// live-state mutation.

const bytesPerMB = 1 << 20

type runtimeSection struct {
	GoVersion     string  `json:"go_version" redact:"public"`
	OS            string  `json:"os" redact:"public"`
	Arch          string  `json:"arch" redact:"public"`
	NumCPU        int     `json:"num_cpu" redact:"public"`
	GOMAXPROCS    int     `json:"gomaxprocs" redact:"public"`
	NumGoroutine  int     `json:"num_goroutine" redact:"public"`
	NumGC         uint32  `json:"num_gc" redact:"public"`
	LastGCPauseMs float64 `json:"last_gc_pause_ms" redact:"public"`
	HeapAllocMB   uint64  `json:"heap_alloc_mb" redact:"public"`
	HeapSysMB     uint64  `json:"heap_sys_mb" redact:"public"`
	HeapObjects   uint64  `json:"heap_objects" redact:"public"`
	StackInuseMB  uint64  `json:"stack_inuse_mb" redact:"public"`
	TotalAllocMB  uint64  `json:"total_alloc_mb" redact:"public"`
	SysMB         uint64  `json:"sys_mb" redact:"public"`
	PID           int     `json:"pid" redact:"internal"` // mildly identifying
	Uptime        string  `json:"uptime" redact:"public"`
}

type runtimeCollector struct{}

func (runtimeCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "runtime", Path: "sections/runtime.json", Owner: "core", SchemaVersion: 1,
		Description: "Go runtime + host facts (goroutines, memstats, GC) — L2 capture", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L2,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (runtimeCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	sec := runtimeSection{
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		GOMAXPROCS:    runtime.GOMAXPROCS(0), // 0 = read current, does not mutate
		NumGoroutine:  runtime.NumGoroutine(),
		NumGC:         ms.NumGC,
		LastGCPauseMs: float64(ms.PauseNs[(ms.NumGC+255)%256]) / 1e6,
		HeapAllocMB:   ms.HeapAlloc / bytesPerMB,
		HeapSysMB:     ms.HeapSys / bytesPerMB,
		HeapObjects:   ms.HeapObjects,
		StackInuseMB:  ms.StackInuse / bytesPerMB,
		TotalAllocMB:  ms.TotalAlloc / bytesPerMB,
		SysMB:         ms.Sys / bytesPerMB,
		PID:           os.Getpid(),
		Uptime:        uptime(),
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

func init() { support.Register(runtimeCollector{}) }
