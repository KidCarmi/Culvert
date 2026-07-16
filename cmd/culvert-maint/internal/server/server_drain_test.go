package server

// server_drain_test.go — T2.4 SIGTERM drain: shutdown must wait for in-flight
// orchestrator goroutines (state-changing ops) instead of abandoning them.

import (
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
)

// newDrainTestServer builds a minimal Server for exercising goOp/drainOps
// directly (no socket / HTTP needed).
func newDrainTestServer(t *testing.T, drain time.Duration) *Server {
	t.Helper()
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	al, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	pol, err := auth.NewPolicy([]string{strconv.Itoa(os.Geteuid())})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	srv, err := New(Options{
		Cfg:            &config.Config{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", SocketPath: filepath.Join(tmp, "s.sock"), StateDir: tmp, PrivilegeMode: config.PrivilegeSudoers},
		Auth:           pol,
		Audit:          al,
		Ops:            ops.NewManager(nil),
		Status:         &fakeStatus{},
		StateDir:       tmp,
		AuditPath:      auditPath,
		OpDrainTimeout: drain,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// TestDrainOps_WaitsForInFlight: drainOps blocks until a tracked op finishes,
// and returns true (drained cleanly) within the timeout.
func TestDrainOps_WaitsForInFlight(t *testing.T) {
	srv := newDrainTestServer(t, 5*time.Second)
	started := make(chan struct{})
	var finished int32
	srv.goOp(func() {
		close(started)
		time.Sleep(150 * time.Millisecond)
		atomic.StoreInt32(&finished, 1)
	})
	<-started
	if !srv.drainOps() {
		t.Fatal("drainOps should return true (drained) within the timeout")
	}
	if atomic.LoadInt32(&finished) != 1 {
		t.Error("drainOps returned before the in-flight op finished — op was abandoned")
	}
}

// TestDrainOps_DeadlineElapses: an op that outlasts the drain window makes
// drainOps return false (the caller then exits and leaves it for restart
// recovery), but the goroutine is still tracked and completes eventually.
func TestDrainOps_DeadlineElapses(t *testing.T) {
	srv := newDrainTestServer(t, 80*time.Millisecond)
	release := make(chan struct{})
	srv.goOp(func() { <-release })
	if srv.drainOps() {
		t.Error("drainOps should return false when the deadline elapses with an op still running")
	}
	close(release)  // let it finish so the test doesn't leak the goroutine
	srv.opWG.Wait() // proves the op was tracked and drains once unblocked
}

// TestDrainOps_InstantWhenIdle: with nothing in flight, drainOps returns
// immediately (shutdown is not slowed on an idle agent).
func TestDrainOps_InstantWhenIdle(t *testing.T) {
	srv := newDrainTestServer(t, 10*time.Second)
	start := time.Now()
	if !srv.drainOps() {
		t.Fatal("idle drain must return true")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("idle drain took %s; must be near-instant", elapsed)
	}
}
