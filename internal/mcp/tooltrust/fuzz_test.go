package tooltrust

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzStoreLoad drives arbitrary bytes through the durable-store decode path. Load
// must ALWAYS fail closed (an error, or a clean empty store) and NEVER panic, admit
// an out-of-bound record, or accept an unknown schema — the file is operator-writable
// and, restored from a backup, attacker-influenceable.
func FuzzStoreLoad(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":1,"approvals":[]}`))
	f.Add([]byte(`{"schema_version":1,"approvals":[{"schema_version":1,"approval_id":"a","tenant":"t","server_id":"s","tool_name":"n","purpose":1,"status":2}]}`))
	f.Add([]byte(`{"schema_version":2,"approvals":[]}`))
	f.Add([]byte(`{"schema_version":1,"approvals":[{}],"evil":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "approvals.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		s, err := NewStore(Config{Path: path, Clock: func() time.Time { return time.Unix(1000, 0) }})
		if err != nil {
			return
		}
		// Must not panic. On success every loaded record must be structurally valid and
		// carry the only issuable purpose (shadow) — no decode may admit a live_execution
		// record or an unknown status.
		if err := s.Load(); err == nil {
			for _, a := range s.ActiveApprovals(time.Unix(1000, 0)) {
				if a.Purpose != PurposeShadowEvaluation || a.Status == StatusUnset {
					t.Fatalf("Load admitted an invalid record: purpose=%d status=%d", a.Purpose, a.Status)
				}
			}
		}
	})
}
