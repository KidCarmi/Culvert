package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// support_durable_write_chokepoint_test.go — CHAOS: the support domain's durable
// state must be written through the fileutil.AtomicWrite chokepoint.
//
// Two separate guarantees ride on that chokepoint, and a hand-rolled
// os.WriteFile(tmp)+os.Rename pair provides NEITHER:
//
//  1. DURABILITY. AtomicWrite fsyncs the file and then the parent directory.
//     A bare tmp+rename is atomic only with respect to a READER (no torn file
//     is ever visible) — it is not durable. After power loss or a kernel panic
//     the rename, the data blocks, or both can be absent, and the relative
//     ordering of two such renames is a filesystem/mount-option accident the
//     code never asserts.
//
//  2. VISIBILITY. Every AtomicWrite failure notifies the write-failure observer
//     storage_health.go installs, which is what drives storageDegraded(), the
//     rate-limited storage_write_failed alert, the degraded operator-contract
//     row and the Prometheus series. A write that bypasses the chokepoint fails
//     SILENTLY: on a full or read-only volume the operator contract keeps
//     reporting healthy while support state is quietly lost.
//
// This is the same defect class audit_writefail_test.go already pins for the
// audit JSONL (register item ST-8). The support domain's own sibling,
// support_telemetry_config.go:198, already writes through
// fileutil.AtomicWrite — these paths were simply never converted.

// durableWriteRecorder records every path committed through the chokepoint and
// restores the production observers on cleanup. The observer fires from
// whatever goroutine performed the write — including background workers in the
// test binary — so the map is mutex-guarded (-race).
type durableWriteRecorder struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (r *durableWriteRecorder) note(p string) {
	r.mu.Lock()
	r.seen[p] = true
	r.mu.Unlock()
}

func (r *durableWriteRecorder) sawPath(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[p]
}

func observeDurableWrites(t *testing.T) *durableWriteRecorder {
	t.Helper()
	rec := &durableWriteRecorder{seen: map[string]bool{}}
	fileutil.SetWriteSuccessObserver(rec.note)
	t.Cleanup(func() {
		// Re-arm the production wiring (storage_health.go's init), not nil:
		// a cleared observer would leave later tests unable to observe health.
		fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess)
		fileutil.SetWriteFailureObserver(noteStorageWriteFailure)
	})
	return rec
}

// chaosBundleID is a well-formed support bundle id (supportBundleIDRe:
// ^csb_[a-z2-7]{26}$ — the 26 lowercase letters all fall inside the class).
const chaosBundleID = "csb_abcdefghijklmnopqrstuvwxyz"

// TestSupportPersistence_RoutesThroughDurableChokepoint walks every support
// persistence entry point and asserts the committed path was observed at the
// fileutil chokepoint. A path missing from the recorder was written by a
// hand-rolled tmp+rename: not fsynced, and invisible to storage health.
func TestSupportPersistence_RoutesThroughDurableChokepoint(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// This test REPLACES the production success observer, so a background
	// goroutine's failing write during the test would latch storageEverFailed
	// without a matching success ever being recorded — leaving storage degraded
	// for a shuffled sibling. Reset the process-global record on both ends.
	withCleanStorageWriteHealth(t)
	rec := observeDurableWrites(t)

	// writeBundleState is the only one of these that does not MkdirAll its own
	// parent, so create the bundle directory the way createSupportBundle does.
	if err := os.MkdirAll(filepath.Join(supportBundlesDir(), chaosBundleID), 0o700); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}

	cases := []struct {
		name string
		path string
		save func(t *testing.T)
	}{
		{
			name: "upload config (support_upload.go)",
			path: uploadConfigPath(),
			save: func(t *testing.T) {
				uploadConfigMu.Lock()
				defer uploadConfigMu.Unlock()
				if err := saveUploadConfigLocked(uploadConfig{Enabled: true, Origin: "https://tac.example.com"}); err != nil {
					t.Fatalf("saveUploadConfigLocked: %v", err)
				}
			},
		},
		{
			name: "recipient registry (support_recipients.go)",
			path: supportRecipientsPath(),
			save: func(t *testing.T) {
				supportRecipientMu.Lock()
				defer supportRecipientMu.Unlock()
				if err := saveSupportRecipientsLocked([]supportRecipient{{Name: "tac", PublicKey: "k", Fingerprint: "f"}}); err != nil {
					t.Fatalf("saveSupportRecipientsLocked: %v", err)
				}
			},
		},
		{
			name: "debug-level elevation (support_debug_level.go)",
			path: debugLevelStatePath(),
			save: func(t *testing.T) {
				debugLevelMu.Lock()
				defer debugLevelMu.Unlock()
				st := debugLevelState{Level: 2, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
				if err := writeDebugLevelStateLocked(st); err != nil {
					t.Fatalf("writeDebugLevelStateLocked: %v", err)
				}
			},
		},
		{
			name: "upload queue entry (support_upload_queue.go)",
			path: uploadQueuePath(chaosBundleID),
			save: func(t *testing.T) {
				uploadQueueMu.Lock()
				defer uploadQueueMu.Unlock()
				e := uploadQueueEntry{BundleID: chaosBundleID, State: uploadStateQueued, CreatedAt: "t", UpdatedAt: "t"}
				if err := saveUploadQueueEntryLocked(e); err != nil {
					t.Fatalf("saveUploadQueueEntryLocked: %v", err)
				}
			},
		},
		{
			name: "sealed upload blob (support_upload_wire.go)",
			path: sealedUploadPath(chaosBundleID),
			save: func(t *testing.T) {
				if err := writeSealedUpload(chaosBundleID, []byte("sealed-bytes")); err != nil {
					t.Fatalf("writeSealedUpload: %v", err)
				}
			},
		},
		{
			name: "bundle approval state (ui_support.go)",
			path: supportBundleStatePath(chaosBundleID),
			save: func(t *testing.T) {
				if err := writeBundleState(chaosBundleID, supportBundleStateFile{State: bundleStatePending}); err != nil {
					t.Fatalf("writeBundleState: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		tc.save(t)
		if !rec.sawPath(tc.path) {
			t.Errorf("%s: %s was committed WITHOUT going through fileutil.AtomicWrite — "+
				"the write is not fsynced (lost on power loss) and its failures are invisible to "+
				"storageDegraded()/storage_write_failed", tc.name, filepath.Base(tc.path))
		}
	}
}

// TestSupportBundleState_WriteFailureReachesStorageHealthPlane is the
// visibility half, on the security-relevant path.
//
// writeBundleState persists the mandatory-preview approval gate, and
// createSupportBundle (ui_support.go) deliberately writes it FIRST, before the
// tgz and the manifest, because readBundleState grandfathers an ABSENT state
// file to READY — i.e. downloadable with no admin approval. That ordering is
// load-bearing for the gate, so losing the write must never be silent.
//
// Injection follows the established idiom (storage_health_test.go's
// failingWrite): a missing parent directory, because root bypasses mode bits
// and CI runs as root.
func TestSupportBundleState_WriteFailureReachesStorageHealthPlane(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	// No bundle directory is created: writeBundleState has no MkdirAll, so the
	// durable write genuinely fails the way a full/read-only volume would.
	err := writeBundleState(chaosBundleID, supportBundleStateFile{State: bundleStatePending})
	if err == nil {
		t.Fatalf("writeBundleState into a missing bundle directory unexpectedly succeeded")
	}

	if !storageDegraded() {
		t.Error("storageDegraded() = false after the approval-gate state write failed — " +
			"the operator contract still reports healthy while the mandatory-preview gate is unpersisted")
	}
	if len(*alerts) != 1 {
		t.Fatalf("fired %d storage_write_failed alerts; want exactly 1", len(*alerts))
	}
	// Inherited path-redaction contract: the alert detail is a viewer-visible
	// surface and must carry a bare base name, never the data-directory layout.
	if got := (*alerts)[0]; !strings.Contains(got, "state.json") {
		t.Errorf("alert detail %q does not name the failing file", got)
	}
	if snap := storageWriteFailures(); strings.ContainsRune(snap.Path, '/') {
		t.Errorf("recorded path %q is not a bare base name", snap.Path)
	}
}
