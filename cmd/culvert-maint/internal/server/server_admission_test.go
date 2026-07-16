package server

// server_admission_test.go — T2.3 admission control: read-only ops are capped by
// a semaphore (429 at capacity); state-changing ops bypass it (lock-serialized).

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
)

func newAdmissionTestServer(t *testing.T, maxRO int) *Server {
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
		Cfg:                      &config.Config{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", SocketPath: filepath.Join(tmp, "s.sock"), StateDir: tmp, PrivilegeMode: config.PrivilegeSudoers, OperationTimeout: 30 * time.Second},
		Auth:                     pol,
		Audit:                    al,
		Ops:                      ops.NewManager(nil),
		Status:                   &fakeStatus{},
		StateDir:                 tmp,
		AuditPath:                auditPath,
		MaxConcurrentReadOnlyOps: maxRO,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func blockingStages(release <-chan struct{}) func() ([]ops.FlowStage, *opError) {
	return func() ([]ops.FlowStage, *opError) {
		return []ops.FlowStage{{
			Name: "block",
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				select {
				case <-release:
				case <-ctx.Done():
				}
				return nil, nil, nil
			},
		}}, nil
	}
}

func quickStages() ([]ops.FlowStage, *opError) {
	return []ops.FlowStage{{
		Name: "x",
		Run:  func(_ context.Context) ([]byte, []byte, error) { return nil, nil, nil },
	}}, nil
}

// TestAdmission_ReadOnlyCappedWith429 fills the read-only slots with blocking
// ops, asserts the next read-only admission is rejected with 429, and that a
// freed slot allows a fresh admission.
func TestAdmission_ReadOnlyCappedWith429(t *testing.T) {
	srv := newAdmissionTestServer(t, 2)
	peer := auth.PeerInfo{UID: 1000, Username: "test-cp"}
	release := make(chan struct{})

	// Fill both read-only slots (the slot is acquired synchronously in
	// startAsyncOp before the goroutine spawns, so after 2 admits the sem is full).
	for i := 0; i < 2; i++ {
		if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, blockingStages(release)); e != nil {
			t.Fatalf("admit %d should succeed: %+v", i, e)
		}
	}
	// Third read-only op must be rejected with 429.
	_, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, blockingStages(release))
	if e == nil || e.Status != http.StatusTooManyRequests {
		t.Fatalf("read-only op at capacity must be 429, got %+v", e)
	}

	// Release the blocked ops → their goroutines finish and free the slots.
	close(release)
	srv.opWG.Wait()

	// A fresh read-only op now admits again.
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, quickStages); e != nil {
		t.Fatalf("admit after slots freed should succeed: %+v", e)
	}
	srv.opWG.Wait()
}

// TestAdmission_StateChangingBypassesSemaphore proves a state-changing op is not
// blocked by a saturated read-only semaphore (it is serialized by the lock).
func TestAdmission_StateChangingBypassesSemaphore(t *testing.T) {
	srv := newAdmissionTestServer(t, 1)
	peer := auth.PeerInfo{UID: 1000, Username: "test-cp"}
	release := make(chan struct{})

	// Saturate the single read-only slot.
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, blockingStages(release)); e != nil {
		t.Fatalf("read-only admit: %+v", e)
	}
	// A state-changing op must still admit (bypasses the read-only cap).
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupCreate, "", nil, quickStages); e != nil {
		t.Fatalf("state-changing op must bypass the read-only cap: %+v", e)
	}
	close(release)
	srv.opWG.Wait()
}

// TestAdmission_DedupReleasesSlot: a deduped read-only retry must not leak a
// slot (it returns the prior op without spawning a goroutine).
func TestAdmission_DedupReleasesSlot(t *testing.T) {
	srv := newAdmissionTestServer(t, 1)
	peer := auth.PeerInfo{UID: 1000, Username: "test-cp"}

	// First keyed op runs to completion (quick), leaving its terminal record for
	// dedup within the idempotency window.
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "dedup-key", nil, quickStages); e != nil {
		t.Fatalf("first admit: %+v", e)
	}
	srv.opWG.Wait()

	// A retry with the same key dedupes — must NOT consume/leak the only slot.
	_, deduped, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "dedup-key", nil, quickStages)
	if e != nil {
		t.Fatalf("dedup retry: %+v", e)
	}
	if !deduped {
		t.Fatal("same-key retry should dedupe")
	}
	// The slot was released on the dedup path, so a new distinct op still admits.
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, quickStages); e != nil {
		t.Fatalf("slot leaked on dedup — fresh admit failed: %+v", e)
	}
	srv.opWG.Wait()
}
