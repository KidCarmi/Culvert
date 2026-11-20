package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitTerminalAudit blocks until the audit log at path holds the terminal
// event for opID, failing the test after a generous deadline.
//
// The orchestrator's terminate step publishes the op's terminal STATE
// (Manager.Finish) before it writes the terminal AUDIT event, so a test that
// saw /v1/operations/{id} report a terminal state and then read the audit
// file at once could find only the "started" line. Every op-wait helper calls
// this, so an assertion on the audit trail reads it after it is complete.
//
// The terminal event is the one with the same op_id and kind as the op's
// "started" event and a terminal outcome. Matching the kind keeps an inline
// rollback's own events (same op_id, different kind) from satisfying it early.
func waitTerminalAudit(t *testing.T, path, opID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if hasTerminalAudit(path, opID) {
			return
		}
		if time.Now().After(deadline) {
			body, _ := os.ReadFile(filepath.Clean(path))
			t.Fatalf("op %s reached a terminal state but its terminal audit event never appeared in %s:\n%s", opID, path, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasTerminalAudit(path, opID string) bool {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return false
	}
	var startedKind string
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var ev struct {
			OpID    string `json:"op_id"`
			Kind    string `json:"kind"`
			Outcome string `json:"outcome"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.OpID != opID {
			continue
		}
		switch ev.Outcome {
		case "started":
			if startedKind == "" {
				startedKind = ev.Kind
			}
		case "succeeded", "failed", "cancelled":
			if startedKind != "" && ev.Kind == startedKind {
				return true
			}
		}
	}
	return false
}
