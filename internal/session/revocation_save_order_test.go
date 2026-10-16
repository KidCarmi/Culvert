package session

// revocation_save_order_test.go — CHAOS-73, review round.
//
// SaveRevocations released r.mu when exportPersisted returned, so snapshot and
// write were not atomic with respect to each other. Two writers — a logout
// request goroutine and the DP's 3 s revocation-sync loop — could each
// snapshot and then race to AtomicWrite: the rename landing LAST wins and may
// carry the OLDER snapshot, leaving the file without a revocation that is
// still live in memory. A restart inside that window resurrects the session.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The lock must be taken BEFORE the snapshot, or the serialization buys
// nothing: two writers would still snapshot concurrently and merely queue
// their writes, which is the same lost update with better manners.
//
// Structural rather than timing-based: the race needs a specific interleaving
// of two file writes, so a behavioural gate passes against the defect most of
// the time, and this repository's standing rule is that a gate which can flake
// gets muted.
func TestSaveRevocations_LocksBeforeSnapshotting(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("session.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		d, ok := n.(*ast.FuncDecl)
		if ok && d.Name.Name == "SaveRevocations" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("SaveRevocations not found; this gate is vacuous")
	}
	lockAt, snapshotAt := -1, -1
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "saveMu" && sel.Sel.Name == "Lock" && lockAt < 0 {
			lockAt = fset.Position(call.Pos()).Offset
		}
		if sel.Sel.Name == "exportPersisted" && snapshotAt < 0 {
			snapshotAt = fset.Position(call.Pos()).Offset
		}
		return true
	})
	if lockAt < 0 {
		t.Fatal("SaveRevocations does not take saveMu: concurrent writers can publish " +
			"snapshots out of order and an older one can overwrite a newer")
	}
	if snapshotAt < 0 {
		t.Fatal("SaveRevocations no longer calls exportPersisted; this gate is vacuous")
	}
	if lockAt > snapshotAt {
		t.Error("saveMu is taken AFTER the snapshot, so two writers still snapshot " +
			"concurrently and the later write can carry the older state")
	}
}

// Concurrent writers must leave the file matching memory, not an older
// snapshot. Run under -race; the assertion is on the final state, which holds
// deterministically once the whole save is serialized.
func TestSaveRevocations_ConcurrentWritersLeaveTheNewestState(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	path := withRevocationsFile(t)

	const n = 60
	exp := time.Now().Add(time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			Revoked.mu.Lock()
			Revoked.tokens[fmt.Sprintf("tok-%03d", i)] = exp
			Revoked.mu.Unlock()
			if err := Revoked.SaveRevocations(); err != nil {
				t.Errorf("save: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// One more save with everything present: the file must now hold them all.
	if err := Revoked.SaveRevocations(); err != nil {
		t.Fatalf("final save: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- temp path created by this test
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var entries []RevocationEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != n {
		t.Errorf("file holds %d entries; want %d — a writer published an older snapshot "+
			"over a newer one", len(entries), n)
	}
}
