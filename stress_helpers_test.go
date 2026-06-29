//go:build proxystress || proxybinload || benchgate

package main

// Shared resilience/stress helpers (CI quality program — PR-3).
//
// Built only under a stress build tag, so they never enter the qa-gate test
// binary. Provide leak detection (goroutines + active-conn gauge + RSS) and
// pprof capture used by the weekly stress tests.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"
)

// flushProxyConnPools closes idle keep-alive connections on both sides of the
// proxy before a leak assertion: the client→proxy pools (passed in) and the
// proxy→upstream shared transport pool. Pooled idle connections are expected
// proxy behavior, not a leak, but they hold goroutines past the settle window —
// flushing them lets the goroutine assertion stay tight.
func flushProxyConnPools(clients ...*http.Client) {
	for _, c := range clients {
		c.CloseIdleConnections()
	}
	if tr := getUpstreamTransport(); tr != nil {
		tr.CloseIdleConnections()
	}
}

// stressEnvInt reads a positive int from env, else returns def. (Distinct name
// from the PR-2 load harness helpers to avoid any multi-tag build collision.)
func stressEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// raceDetectorOn is set true by a //go:build race companion file. The race
// detector adds ~5–10× shadow memory, so RSS-based leak detection is
// meaningless under -race; the goroutine + active-conn checks still apply.
var raceDetectorOn = false

// resourceSnapshot captures the leak-relevant counters at a point in time.
type resourceSnapshot struct {
	goroutines  int
	activeConns int64
	rssKB       int64
}

func snapshotResources() resourceSnapshot {
	runtime.GC()
	debug.FreeOSMemory()
	return resourceSnapshot{
		goroutines:  runtime.NumGoroutine(),
		activeConns: getActiveConns(),
		rssKB:       readRSSKB(os.Getpid()),
	}
}

// readRSSKB reads resident set size (KB) from /proc/<pid>/statm (Linux). Returns
// 0 on any failure (non-Linux / unreadable) so RSS assertions become no-ops
// rather than flaking.
func readRSSKB(pid int) int64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	resPages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return resPages * int64(os.Getpagesize()) / 1024
}

// assertNoResourceLeak waits for goroutines + the active-conn gauge to settle to
// baseline (within tolerance), then checks RSS growth is bounded. RSS growth max
// of 0 disables the RSS check.
func assertNoResourceLeak(t *testing.T, base resourceSnapshot, goroutineTol int, rssGrowthKBMax int64) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		runtime.GC()
		g := runtime.NumGoroutine()
		a := getActiveConns()
		settled := g <= base.goroutines+goroutineTol && a == 0
		if settled || time.Now().After(deadline) {
			debug.FreeOSMemory()
			rss := readRSSKB(os.Getpid())
			if g > base.goroutines+goroutineTol {
				t.Errorf("goroutine leak: %d active, baseline %d + tolerance %d", g, base.goroutines, goroutineTol)
			}
			if a != 0 {
				t.Errorf("active-connection leak: gauge=%d after teardown, want 0", a)
			}
			switch {
			case raceDetectorOn:
				t.Logf("RSS check skipped under -race (race detector inflates RSS); goroutine + active-conn checks still applied")
			case rssGrowthKBMax > 0 && base.rssKB > 0 && rss-base.rssKB > rssGrowthKBMax:
				t.Errorf("RSS grew %d KB (baseline %d → %d), exceeds bound %d KB", rss-base.rssKB, base.rssKB, rss, rssGrowthKBMax)
			}
			t.Logf("resources: goroutines %d→%d (tol %d), activeConns=%d, RSS %dKB→%dKB",
				base.goroutines, g, goroutineTol, a, base.rssKB, rss)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startStressProfiles begins a CPU profile (if CULVERT_STRESS_PPROF names a dir)
// and returns a stop func that also writes heap + goroutine profiles.
func startStressProfiles(t *testing.T, name string) func() {
	t.Helper()
	dir := os.Getenv("CULVERT_STRESS_PPROF")
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("pprof: mkdir %s: %v", dir, err)
		return func() {}
	}
	f, err := os.Create(filepath.Join(dir, name+"-cpu.prof"))
	if err != nil {
		t.Logf("pprof: create cpu: %v", err)
		return func() {}
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return func() {}
	}
	return func() {
		pprof.StopCPUProfile()
		f.Close()
		for _, p := range []string{"heap", "goroutine"} {
			pf, err := os.Create(filepath.Join(dir, name+"-"+p+".prof"))
			if err != nil {
				continue
			}
			pprof.Lookup(p).WriteTo(pf, 0) //nolint:errcheck
			pf.Close()
		}
		t.Logf("pprof: wrote %s-{cpu,heap,goroutine}.prof to %s", name, dir)
	}
}
