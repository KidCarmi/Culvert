//go:build agt900_e2e

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestE2EShimCountersSurviveConcurrentCalls: the agent runs docker
// concurrently (a /v1/status read during a reconcile). The shim's per-agent
// counters must stay exact and must never make a call fail. Unlocked, an
// interleaved write left "1\n7" in a counter on real runs; sh then
// exited 2 on every later call, and the reconcile saw Docker failing
// (rb_in_rollback_health, dockerd_down_at_verify). Needs no Docker.
func TestE2EShimCountersSurviveConcurrentCalls(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}
	dir := t.TempDir()
	ctl := filepath.Join(dir, "ctl")
	if err := os.Mkdir(ctl, 0o750); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "docker")
	body := strings.NewReplacer("__CTL__", ctl, "__HOST__", "unix:///nonexistent", "__CA__", "/nonexistent", "__REAL__", "/bin/true").Replace(e2eShim)
	if err := os.WriteFile(shim, []byte(body), 0o755); err != nil { // #nosec G306 -- test shim must be executable
		t.Fatal(err)
	}
	const workers, each = 32, 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				out, err := exec.CommandContext(t.Context(), shim, "compose", "-f", "x.yml", "ps", "--format", "json").CombinedOutput() // #nosec G204 -- test-owned shim
				if err != nil {
					mu.Lock()
					failures = append(failures, err.Error()+": "+strings.TrimSpace(string(out)))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d of %d shim calls failed, e.g. %s", len(failures), workers*each, failures[0])
	}
	for _, name := range []string{"count.ps_before", "count.ps_after"} {
		raw, err := os.ReadFile(filepath.Join(ctl, name))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := strconv.Atoi(strings.TrimSpace(string(raw))); err != nil || got != workers*each {
			t.Errorf("%s = %q, want %d", name, raw, workers*each)
		}
	}
}
