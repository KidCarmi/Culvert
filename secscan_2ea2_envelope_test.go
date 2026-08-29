package main

// secscan_2ea2_envelope_test.go — 2E-A-2 §2-C: the shared DPI envelope's
// writer domain must serialize the INTERACTIVE handler path against the BULK
// writer shapes (config-version rollback configversion.go, CP→DP snapshot
// apply controlplane_snapshot.go, inspection_rules.go seed, config import
// ui_config.go — all of which mutate dpiScanner then call Save()). At
// b60d4ed6 a parked interactive publication could land AFTER a
// happened-later bulk publication, leaving the file (what a restart trusts)
// on the interactive-era envelope while both callers were told success.
//
// Determinism: same select-valve pattern as
// internal/scanner/scanner_writer_domain_test.go — at the fixed tree the bulk
// Save provably cannot publish while the interactive Save is parked (mutual
// exclusion), so the valve arm is the only reachable one; at the unserialized
// candidate the bulk writer completes without help and releasing the parked
// handler lands the stale envelope last.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

func TestSec2EA2_InteractiveVsBulkEnvelopeDurableTruth(t *testing.T) {
	t.Cleanup(func() { _ = publishCurrentConfigSnapshot() }) // re-commit real state after restores
	path := snapshotDPIScanner(t)
	snapshotConfigVersionsDir(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	first := true
	dpiScanner.SetWriteFileForTest(func(p string, data []byte) error {
		if first {
			first = false
			close(entered)
			<-release
		}
		return fileutil.AtomicWrite(p, data, 0o600)
	})

	// Interactive writer: the REAL handler (POST /api/dpi — Add + Save),
	// parked at its publication boundary.
	handlerDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		apiContentScan(w, jsonReq("POST", "/api/dpi", map[string]any{"pattern": "interactive-pattern"}))
		handlerDone <- w.Code
	}()
	<-entered

	// Bulk writer: the config-version rollback shape (configversion.go —
	// whole-set Set + SetBypassHosts + Save), which happened-after the
	// interactive mutation and must therefore own the final durable envelope.
	bulkDone := make(chan error, 1)
	runBulk := func() {
		if err := dpiScanner.Set([]string{"bulk-pattern"}); err != nil {
			t.Errorf("bulk set: %v", err)
		}
		dpiScanner.SetBypassHosts([]string{"bulk-bypass.example"})
		bulkDone <- dpiScanner.Save()
	}
	go runBulk()

	var bulkErr error
	var handlerCode int
	select {
	case bulkErr = <-bulkDone:
		// Unserialized ordering: the bulk publication landed while the
		// interactive one was parked; releasing the handler lands its stale
		// envelope last.
		close(release)
		handlerCode = <-handlerDone
	case <-time.After(3 * time.Second):
		// Serialized tree: the bulk Save cannot publish while the handler is
		// parked; release and let both complete in snapshot order.
		close(release)
		handlerCode = <-handlerDone
		bulkErr = <-bulkDone
	}
	if handlerCode != 200 || bulkErr != nil {
		t.Fatalf("both writers must report success: handler=%d bulk=%v", handlerCode, bulkErr)
	}

	// Restart truth: the durable envelope must be the bulk writer's state (it
	// happened-after and replaced the interactive mutation wholesale).
	fresh := newContentScanner(1 << 20)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("restart load: %v", err)
	}
	patterns := fresh.List()
	bypass := fresh.BypassHosts()
	if len(patterns) != 1 || patterns[0] != "bulk-pattern" ||
		len(bypass) != 1 || bypass[0] != "bulk-bypass.example" {
		t.Fatalf("restart does not read the final successful management truth (stale interactive envelope published last): patterns=%v bypass=%v",
			patterns, bypass)
	}
}

// Control: the handler's decoded response stays the accepted contract on the
// serialized path (green at both trees — sequential, no interleaving).
func TestSec2EA2_InteractiveAddSequentialControl(t *testing.T) {
	t.Cleanup(func() { _ = publishCurrentConfigSnapshot() })
	path := snapshotDPIScanner(t)
	snapshotConfigVersionsDir(t)
	w := httptest.NewRecorder()
	apiContentScan(w, jsonReq("POST", "/api/dpi", map[string]any{"pattern": "seq-pattern"}))
	if w.Code != 200 {
		t.Fatalf("POST = %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n, ok := resp["added"].(float64); !ok || n != 1 {
		t.Fatalf("added = %v", resp["added"])
	}
	fresh := newContentScanner(1 << 20)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := fresh.List(); len(got) != 1 || got[0] != "seq-pattern" {
		t.Fatalf("durable: %v", got)
	}
}
