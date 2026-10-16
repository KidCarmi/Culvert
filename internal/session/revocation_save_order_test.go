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
	file, err := parser.ParseFile(fset, "session.go", nil, 0)
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
// snapshot. Run under -race.
//
// The real assertion is the one INSIDE the goroutines: once a writer's own
// save has returned, the file must contain that writer's token, and must
// still contain it no matter who writes next. That holds deterministically
// once the whole save is serialized — every later snapshot is taken after
// this writer's insert, because the snapshot happens under the same lock the
// write does — and it is exactly what an out-of-order publish breaks: an
// older snapshot, taken before this token existed, landing after this
// writer already saw its own save succeed.
//
// Asserting only the state after a final quiescent save would prove nothing
// about the concurrent phase: that save rewrites the file from the complete
// in-memory list and repairs whatever the writers lost (CodeRabbit,
// PR #1591). It is kept below as a separate, weaker check on the quiescent
// state.
//
// Honest limit: this is a strengthened CONTROL, not a defect gate. Reverting
// SaveRevocations to the pre-fix shape (snapshot taken outside saveMu) did
// not make it fail — 0 failures in 5 runs at n=60 and 6 at n=400 — because
// the inverted write has to land in the window between one writer's save
// returning and its read. TestSaveRevocations_LocksBeforeSnapshotting is the
// gate that actually holds the ordering; this one guards against a
// regression it happens to catch and gives the race detector real work.
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
				return
			}
			// This writer's save has returned, so the file holds either its
			// own snapshot or a later one; both contain this token.
			raw, err := os.ReadFile(path) // #nosec G304 -- temp path created by this test
			if err != nil {
				t.Errorf("read after save %d: %v", i, err)
				return
			}
			var seen []RevocationEntry
			if err := json.Unmarshal(raw, &seen); err != nil {
				t.Errorf("unmarshal after save %d: %v", i, err)
				return
			}
			tok := fmt.Sprintf("tok-%03d", i)
			for j := range seen {
				if seen[j].Token == tok {
					return
				}
			}
			t.Errorf("file lacks %s though its own save already returned: a snapshot "+
				"taken before this token existed was published over a newer one", tok)
		}(i)
	}
	wg.Wait()

	// Weaker, separate check: after a quiescent save the file holds them all.
	// This one cannot witness a lost update — it rewrites from the complete
	// in-memory list — so it is here to pin the steady state, not the race.
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
