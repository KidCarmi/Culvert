package main

// blocklist_mode_saveconfigversion_test.go — regression coverage for
// the Category B "tiny first case" identified in
// roadmap/CONFIG-VERSIONING-TRIAGE.md.
//
// Background
// ==========
// apiBlocklistMode (ui_policy.go) handles GET/POST /api/blocklist/mode.
// On POST it mutates `bl.SetMode(body.Mode)` and emits auditEvent.
// Before this PR it did NOT call saveConfigVersion, even though:
//
//   - BlocklistMode is in the rollback surface
//     (captureConfigBackup at configversion.go:64 +
//     applyConfigBackup at configversion.go:336-338).
//   - Sibling apiBlocklist add/bulk_remove/remove handlers in the
//     same file (ui_policy.go:113, :139, :150) already call
//     saveConfigVersion for the same store.
//
// The triage doc flagged this as the only Category B (genuine gap)
// entry and recommended a one-line addition as a separate small PR.
// This file is that PR's regression coverage.
//
// What this test asserts
// ======================
// After a successful POST /api/blocklist/mode the on-disk config-
// versions directory must contain at least one envelope whose
// meta.action == "blocklist.mode" AND whose config.blocklistMode
// reflects the just-set value. Removing the saveConfigVersion line
// from ui_policy.go's apiBlocklistMode POST branch fails this test.
//
// No parallel tests; the package-global configVersionsDir +
// configVersionSeq + bl mode are snapshotted and restored via
// t.Cleanup.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestAPIBlocklistMode_POST_CreatesConfigVersion is the regression
// guard for the Category B fix. With the saveConfigVersion line
// removed from apiBlocklistMode POST, this test fails because no
// blocklist.mode version envelope is written to disk.
func TestAPIBlocklistMode_POST_CreatesConfigVersion(t *testing.T) {
	// Snapshot/restore the package globals this test mutates.
	tmp := t.TempDir()
	origDir := configVersionsDir
	configVersionsDir = tmp
	t.Cleanup(func() { configVersionsDir = origDir })

	configVersionMu.Lock()
	origSeq := configVersionSeq
	configVersionSeq = 0 // newly-created file becomes v1.json
	configVersionMu.Unlock()
	t.Cleanup(func() {
		configVersionMu.Lock()
		configVersionSeq = origSeq
		configVersionMu.Unlock()
	})

	origMode := bl.Mode()
	t.Cleanup(func() { bl.SetMode(origMode) })

	// Set baseline state distinct from the value we will post so the
	// final disk state is unambiguous.
	bl.SetMode("block")

	// POST /api/blocklist/mode with mode=allow. jsonReq injects
	// RoleAdmin into the request context via adminCtx (ui_test.go:17),
	// so requireRole(RoleOperator) inside the handler passes.
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/blocklist/mode", map[string]string{
		"mode": "allow",
	})
	apiBlocklistMode(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("apiBlocklistMode POST status = %d; want %d (body: %s)",
			w.Code, http.StatusOK, w.Body.String())
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no config version file created — apiBlocklistMode POST did not call saveConfigVersion")
	}

	// Inspect each envelope; we expect at least one with
	// Action="blocklist.mode" and Config.BlocklistMode reflecting the
	// just-set value. Use a struct literal (not the package's
	// configBackup name in scope) for clarity.
	type envelope struct {
		Meta struct {
			Version int    `json:"version"`
			Actor   string `json:"actor"`
			Action  string `json:"action"`
		} `json:"meta"`
		Config configBackup `json:"config"`
	}

	var found bool
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(tmp, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal %s: %v", e.Name(), err)
		}
		if env.Meta.Action != "blocklist.mode" {
			continue
		}
		if env.Config.BlocklistMode != "allow" {
			t.Errorf("envelope (%s) Config.BlocklistMode = %q; want %q (the value just POSTed)",
				e.Name(), env.Config.BlocklistMode, "allow")
		}
		found = true
		break
	}
	if !found {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("no config version envelope with Meta.Action=%q found in %d file(s): %v",
			"blocklist.mode", len(entries), names)
	}
}
