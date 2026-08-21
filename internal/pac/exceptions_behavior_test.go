package pac

// exceptions_behavior_test.go — behavioral proofs for the governance state
// machine and the node-local store, beyond the basic round-trip/table tests:
// precedence ordering, boundary instants, the not-applicable short-circuit,
// copy-on-read isolation, and concurrency safety.

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestStatus_PrecedenceOrdering proves the classification order is
// not-applicable > ungoverned > expired > review_due > governed, so a record
// that is simultaneously in several problem states always reports the most
// alarming applicable one (never something safer than reality).
func TestStatus_PrecedenceOrdering(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	past := now.AddDate(0, 0, -1).Format(time.RFC3339)
	oldReview := now.AddDate(0, 0, -400).Format(time.RFC3339)

	// Unowned AND expired AND overdue: owner-check wins → ungoverned.
	r := ExceptionRecord{ExpiresAt: past, ReviewCadenceDays: 30, LastReviewedAt: oldReview}
	if got := r.Status(now, true); got != GovUngoverned {
		t.Errorf("unowned+expired+overdue = %q, want ungoverned (owner check first)", got)
	}
	// Owned+justified but expired AND overdue: expiry wins over review_due.
	r = ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: past, ReviewCadenceDays: 30, LastReviewedAt: oldReview}
	if got := r.Status(now, true); got != GovExpired {
		t.Errorf("expired+overdue = %q, want expired (expiry before cadence)", got)
	}
	// not-applicable short-circuits everything, even with garbage fields.
	r = ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: "garbage", ReviewCadenceDays: -5}
	if got := r.Status(now, false); got != "" {
		t.Errorf("directCapable=false = %q, want empty", got)
	}
}

// TestStatus_ExpiryBoundaryInclusive proves expiry is inclusive: at the exact
// deadline instant the exception is already expired (fail-safe), and one
// instant before it is still valid.
func TestStatus_ExpiryBoundaryInclusive(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	rec := func(exp time.Time) ExceptionRecord {
		return ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: exp.Format(time.RFC3339)}
	}
	if got := rec(now).Status(now, true); got != GovExpired {
		t.Errorf("expiry == now = %q, want expired (inclusive)", got)
	}
	if got := rec(now.Add(time.Second)).Status(now, true); got != GovGoverned {
		t.Errorf("expiry one second in the future = %q, want governed", got)
	}
}

// TestStatus_TimezoneInstantComparison proves comparisons are by absolute
// instant, not wall-clock components: an offset-bearing timestamp equal to the
// same instant as `now` is treated identically.
func TestStatus_TimezoneInstantComparison(t *testing.T) {
	nowUTC := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	// Same instant, expressed with a -05:00 offset, one hour in the future.
	loc := time.FixedZone("X", -5*3600)
	future := nowUTC.Add(time.Hour).In(loc).Format(time.RFC3339)
	r := ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: future}
	if got := r.Status(nowUTC, true); got != GovGoverned {
		t.Errorf("offset future expiry = %q, want governed (instant comparison)", got)
	}
}

// TestStore_AllReturnsCopy proves mutating the map returned by All() cannot
// corrupt the store's internal state.
func TestStore_AllReturnsCopy(t *testing.T) {
	var s ExceptionStore
	if err := s.Put(ExceptionRecord{ProfileID: "a", Owner: "o", Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	out := s.All()
	out["a"] = ExceptionRecord{ProfileID: "a", Owner: "TAMPERED"}
	delete(out, "a")
	if got, ok := s.Get("a"); !ok || got.Owner != "o" {
		t.Errorf("store corrupted via All() copy: %+v ok=%v", got, ok)
	}
}

// TestStore_DeleteMissingIsNoop proves deleting an absent id is a nil-error
// no-op (idempotent cleanup on profile delete).
func TestStore_DeleteMissingIsNoop(t *testing.T) {
	var s ExceptionStore
	if err := s.Delete("nope"); err != nil {
		t.Errorf("delete missing should be nil, got %v", err)
	}
}

// TestStore_ConcurrentAccessRaceFree hammers the store from many goroutines;
// run under -race this proves the RWMutex discipline holds.
func TestStore_ConcurrentAccessRaceFree(t *testing.T) {
	var s ExceptionStore
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			id := fmt.Sprintf("g%d", g)
			for i := 0; i < 200; i++ {
				_ = s.Put(ExceptionRecord{ProfileID: id, Owner: "o", Reason: "r"})
				_, _ = s.Get(id)
				_ = s.All()
				if i%3 == 0 {
					_ = s.Delete(id)
				}
			}
		}(g)
	}
	wg.Wait()
}
