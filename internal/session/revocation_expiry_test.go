package session

// revocation_expiry_test.go — SEC-REVEXP-1.
//
// The defect was a disagreement between two expiry predicates, so the tests
// are written as a DIFFERENTIAL against the verifier (Decode) rather than
// against a hand-copied constant: a future change to either side that
// reintroduces the gap fails here even if the numbers move.
//
// ── GATES vs CONTROLS, and why the difference is worth stating ──────────────
//
// 9 tests here, and they are NOT interchangeable as evidence:
//
//   7 REGRESSION GATES fail against the pre-fix `!now.After(exp)` predicate
//     and pass against the corrected one. They are the reproducible evidence
//     that the defect was real and is closed.
//
//   2 CONTROLS pass under BOTH predicates, by design — that is what makes
//     them controls. They are marked CONTROL below. They are not evidence
//     that anything was broken; they are evidence that the fix did not buy
//     its result by breaking something else (eviction still happens, and a
//     peer still cannot inject a degenerate expiry).
//
// Quoting a control as a confirmed pre-fix failure would make the evidence
// irreproducible for the next person who re-runs it, so don't.
//
// Several tests must observe behaviour INSIDE a particular wall-clock second:
// the defect only appears when the revocation expiry equals the current second
// AND `time.Now()` carries a sub-second remainder, so an observation that
// straddles a second boundary proves nothing (and would pass against the
// pre-fix code).
//
// That makes these tests clock-dependent, which is a flake risk worth removing
// rather than tolerating — a security gate that flakes is a security gate
// somebody switches off. `observeWithinSecond` handles it the only sound way:
// it settles into the comfortable middle of a second, takes the observation,
// and then CHECKS WHETHER THE SECOND ROLLED OVER MID-OBSERVATION. If it did,
// the observation is void and is retried; it is never reported as a failure.
// Only a verdict reached wholly inside one second can fail the test.

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// settleWithinSecond blocks until the current instant is between 200ms and
// 600ms past a second boundary, leaving at least 400ms of headroom for the
// observation that follows.
func settleWithinSecond(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ns := time.Now().Nanosecond()
		if ns >= int(200*time.Millisecond) && ns <= int(600*time.Millisecond) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("could not settle inside a second — clock is not advancing")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// observeWithinSecond settles inside a second, hands `observe` that second,
// and accepts its verdict only if the clock was still in that same second when
// it returned. A rollover voids the attempt and retries. `observe` reports the
// problem it found, or "" when the observation held.
func observeWithinSecond(t *testing.T, observe func(sec int64) string) {
	t.Helper()
	for attempt := 0; attempt < 25; attempt++ {
		settleWithinSecond(t)
		sec := time.Now().Unix()
		problem := observe(sec)
		if time.Now().Unix() != sec {
			continue // straddled a second boundary — proves nothing either way
		}
		if problem != "" {
			t.Error(problem)
		}
		return
	}
	t.Fatal("could not complete an observation inside a single second after 25 attempts")
}

// revokeToken encodes a session, revokes it the way the production logout path
// does (`time.Unix(s.Exp, 0)`) and returns the cookie and its b64 payload.
func revokeToken(t *testing.T, s *Session) (cookie, b64 string) {
	t.Helper()
	cookie, err := Encode(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	b64 = cookie[:strings.LastIndex(cookie, ".")]
	Revoked.Revoke(b64, time.Unix(s.Exp, 0))
	return cookie, b64
}

// ─── The regression gate ─────────────────────────────────────────────────────

// TestRevocationExpiry_EvictionNeverPrecedesDecode is the measurement that
// found the defect, inverted. A session whose Exp is the CURRENT second is
// still accepted by Decode (its test is `now.Unix() > s.Exp`), so its
// revocation must still be honoured. Before the fix this reported
// IsRevoked=false with Decode err=<nil> — the logged-out cookie authenticated.
func TestRevocationExpiry_EvictionNeverPrecedesDecode(t *testing.T) {
	initSecret(t)
	withFreshRevocationList(t)

	observeWithinSecond(t, func(sec int64) string {
		s := &Session{Sub: "victim", Exp: sec}
		cookie, b64 := revokeToken(t, s)
		if _, err := Decode(cookie); err == nil {
			return "logged-out cookie was accepted inside its final second (fail-open)"
		}
		if !Revoked.IsRevoked(b64) {
			return "revocation was evicted while the cookie it revokes is still within its lifetime"
		}
		return ""
	})
}

// TestRevocationExpiry_EntrySurvivesTheFinalSecond pins the retention half
// directly: the entry must still be in the map, not merely reported revoked.
// The pre-fix bug DELETED it, which is what made the hole propagate to disk
// and to peers.
func TestRevocationExpiry_EntrySurvivesTheFinalSecond(t *testing.T) {
	rl := NewRevocationList()

	observeWithinSecond(t, func(sec int64) string {
		rl.Revoke("tok", time.Unix(sec, 0)) // the current second, truncated
		if !rl.IsRevoked("tok") {
			return "IsRevoked = false inside the revocation's own final second"
		}
		rl.mu.Lock()
		_, exists := rl.tokens["tok"]
		rl.mu.Unlock()
		if !exists {
			return "entry was deleted inside its own final second"
		}
		return ""
	})
}

// TestRevocationExpiry_DifferentialAcrossOffsets is the property: across a
// sweep of session expiries either side of now, Decode and the revocation list
// must never disagree in the fail-open direction — "Decode accepts" implies
// "the revocation is still live". The reverse (a retained entry for a session
// Decode already rejects) is harmless and expected.
func TestRevocationExpiry_DifferentialAcrossOffsets(t *testing.T) {
	initSecret(t)
	withFreshRevocationList(t)

	observeWithinSecond(t, func(sec int64) string {
		for _, off := range []int64{-5, -2, -1, 0, 1, 2, 5} {
			s := &Session{Sub: "u", Exp: sec + off}
			cookie, b64 := revokeToken(t, s)

			accepted := func() bool { _, err := Decode(cookie); return err == nil }()
			// Decode consults IsRevoked itself, so ask the list directly for
			// the live/evicted verdict rather than inferring it from Decode.
			live := Revoked.IsRevoked(b64)

			if accepted {
				return fmt.Sprintf("offset %+ds: Decode accepted a revoked cookie", off)
			}
			// A session Decode would accept on expiry grounds alone must have
			// a live revocation.
			if sec <= s.Exp && !live {
				return fmt.Sprintf("offset %+ds: revocation evicted while the session is still within its lifetime", off)
			}
		}
		return ""
	})
}

// ─── Negative controls: the fix must not retain forever ─────────────────────

// TestRevocationExpiry_UnambiguouslyPastEntriesStillEvict is a CONTROL: it
// passes both before and after the fix (see the file header).
//
// A fix in the fail-closed direction is only correct if eviction still happens
// once the expiry second has genuinely passed — otherwise the list grows
// without bound. Had this flipped to FAIL, the fix would have turned a bounded
// list into an unbounded leak, so its PASS is load-bearing even though it is
// not regression evidence.
func TestRevocationExpiry_UnambiguouslyPastEntriesStillEvict(t *testing.T) {
	rl := NewRevocationList()
	for _, age := range []time.Duration{2 * time.Second, time.Minute, 24 * time.Hour} {
		tok := "old-" + age.String()
		rl.Revoke(tok, time.Now().Add(-age))
		if rl.IsRevoked(tok) {
			t.Errorf("entry %s past its expiry still reported revoked", age)
		}
		rl.mu.Lock()
		_, exists := rl.tokens[tok]
		rl.mu.Unlock()
		if exists {
			t.Errorf("entry %s past its expiry was not evicted", age)
		}
	}
}

// TestRevocationExpiry_ExportDropsOnlyWhatDecodeRejects covers the path that
// writes the on-disk file and the cluster gossip export. An entry inside its
// final second must be exported (so it survives a restart and reaches peers);
// one well past must be dropped.
func TestRevocationExpiry_ExportDropsOnlyWhatDecodeRejects(t *testing.T) {
	rl := NewRevocationList()

	observeWithinSecond(t, func(sec int64) string {
		rl.Revoke("final-second", time.Unix(sec, 0))
		rl.Revoke("long-dead", time.Unix(sec-60, 0))

		got := map[string]bool{}
		for _, e := range rl.ExportRevocations() {
			got[e.Token] = true
		}
		if !got["final-second"] {
			return "export dropped an entry still inside its final second — it would vanish from disk and from every peer"
		}
		if got["long-dead"] {
			return "export retained an entry a minute past its expiry"
		}
		return ""
	})
}

// TestRevocationExpiry_MergeAdmitsTheFinalSecond is the inbound half: a peer's
// entry for a session Decode would still accept must be admitted, not refused
// as "already expired".
func TestRevocationExpiry_MergeAdmitsTheFinalSecond(t *testing.T) {
	observeWithinSecond(t, func(sec int64) string {
		// A fresh list per attempt: `added` counts only what THIS merge
		// admitted, so a retried attempt must not see the previous one's entry
		// already present.
		fresh := NewRevocationList()
		added := fresh.MergeRevocations([]RevocationEntry{
			{Token: "from-peer", Expiry: sec},
			{Token: "stale-peer", Expiry: sec - 60},
		})
		if added != 1 {
			return fmt.Sprintf("merged %d entries, want 1 (the final-second entry admitted, the stale one refused)", added)
		}
		if !fresh.IsRevoked("from-peer") {
			return "a peer's revocation for a still-valid session was refused"
		}
		if fresh.IsRevoked("stale-peer") {
			return "a peer's long-expired revocation was admitted"
		}
		return ""
	})
}

// ─── Malformed / boundary input ─────────────────────────────────────────────

// TestRevocationExpiry_MalformedPeerExpiries is a CONTROL: it passes both
// before and after the fix (see the file header).
//
// It checks the degenerate Expiry values a peer or a hand-edited revocations
// file can carry. None may be admitted, and none may panic. Both predicates
// agree on every case, which is the point — widening the retention window by
// under a second must not widen what an untrusted origin can inject.
func TestRevocationExpiry_MalformedPeerExpiries(t *testing.T) {
	rl := NewRevocationList()
	for _, exp := range []int64{0, -1, -(1 << 40), 1} {
		if added := rl.MergeRevocations([]RevocationEntry{{Token: "t", Expiry: exp}}); added != 0 {
			t.Errorf("Expiry=%d was admitted", exp)
		}
	}
	// A far-future expiry is admitted — a peer choosing it is CHAOS-73's
	// concern (bounding), not this one's. Pinned so the two fixes stay
	// distinguishable.
	if added := rl.MergeRevocations([]RevocationEntry{{Token: "far", Expiry: 1 << 40}}); added != 1 {
		t.Errorf("far-future entry: added %d, want 1", added)
	}
}

// TestRevocationExpiry_UserRevocationHonoursTheSameOracle covers the
// username-keyed list, which gates every session of a deleted account.
func TestRevocationExpiry_UserRevocationHonoursTheSameOracle(t *testing.T) {
	rl := NewRevocationList()

	observeWithinSecond(t, func(sec int64) string {
		rl.mu.Lock()
		rl.users["inside"] = time.Unix(sec, 0)
		rl.users["past"] = time.Unix(sec-60, 0)
		rl.mu.Unlock()

		if !rl.IsUserRevoked("inside") {
			return "user revocation evicted inside its final second"
		}
		if rl.IsUserRevoked("past") {
			return "user revocation a minute past its expiry still reported"
		}
		return ""
	})
}

// ─── Concurrency ────────────────────────────────────────────────────────────

// TestRevocationExpiry_ConcurrentReadersAndWriters runs the predicate under
// -race from every path that reaches it. The eviction sites mutate the map
// while holding r.mu; this asserts the fix did not move any read outside it.
//
// The storm and the boundary assertion are deliberately SEPARATE phases. An
// earlier draft ran 2400 operations and only then asserted a condition that
// requires still being inside the starting wall-clock second — which is a
// flake waiting for a loaded CI runner, because the storm's duration is
// exactly the thing that is not bounded here. Phase 1 is therefore
// time-independent (it exists to shake out races and panics across every entry
// point), and phase 2 takes the boundary observation on its own, inside a
// single settled second, while the same concurrent traffic is still running.
//
// "Still running" is proven, not assumed: phase-2 workers loop until stopped
// (a fixed iteration budget would let them finish while the helper is still
// settling), and the assertion waits until more full export sweeps — the one
// worker path that evicts every token — have completed after the boundary
// entry was inserted than there are workers. At most one sweep per worker can
// already be in flight when the count is sampled, so at least one counted
// sweep started after the insert and ran over the entry under test.
func TestRevocationExpiry_ConcurrentReadersAndWriters(t *testing.T) {
	rl := NewRevocationList()
	// A far-future expiry for the storm: phase 1 asserts nothing about the
	// boundary, so it must not depend on the clock.
	stormExp := time.Now().Add(time.Hour).Unix()

	const workers = 8
	const iters = 300

	// exportSweeps counts completed ExportRevocations calls across workers.
	var exportSweeps atomic.Int64

	// ── Phase 1: the storm. Races and panics only. ──────────────────────────
	// limit > 0 bounds each worker to that many iterations; limit == 0 runs
	// each worker until stop is closed.
	hammer := func(stop <-chan struct{}, limit int) func() {
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; limit == 0 || i < limit; i++ {
					select {
					case <-stop:
						return
					default:
					}
					switch (w + i) % 5 {
					case 0:
						rl.Revoke("storm", time.Unix(stormExp, 0))
					case 1:
						rl.IsRevoked("storm")
					case 2:
						rl.ExportRevocations()
						exportSweeps.Add(1)
					case 3:
						rl.MergeRevocations([]RevocationEntry{{Token: "peer", Expiry: stormExp}})
					case 4:
						rl.IsUserRevoked("someone")
					}
				}
			}(w)
		}
		return wg.Wait
	}
	never := make(chan struct{})
	hammer(never, iters)()

	if !rl.IsRevoked("storm") {
		t.Error("a far-future entry did not survive the concurrent storm")
	}

	// ── Phase 2: the boundary, under live concurrent traffic. ───────────────
	// Background traffic keeps the eviction sites running against the entry
	// under test until stop is closed; the observation is voided and retried if
	// it straddles a second boundary.
	stop := make(chan struct{})
	wait := hammer(stop, 0)
	defer func() { close(stop); wait() }()

	observeWithinSecond(t, func(sec int64) string {
		rl.Revoke("final-second", time.Unix(sec, 0))
		// Require workers+1 sweeps completed after the insert (see the test
		// doc): only then is a sweep over "final-second" guaranteed.
		base := exportSweeps.Load()
		for exportSweeps.Load()-base <= workers {
			if time.Now().Unix() != sec {
				if exportSweeps.Load() == base {
					t.Fatal("phase-2 workers completed no export sweep across a whole observation window — the boundary is not being checked under live traffic")
				}
				return "" // second rolled over before enough sweeps; the helper voids this attempt
			}
			runtime.Gosched()
		}
		if !rl.IsRevoked("final-second") {
			return "entry inside its final second was evicted by a concurrent pass"
		}
		return ""
	})
}

// TestRevocationExpiry_CountingNeverEvictsALiveRevocation is SEC-REVEXP-1's
// measurement aimed at the eviction site added AFTER it: pruneExpiredLocked,
// reached by Count and UserCount.
//
// Count/UserCount are called from READ-ONLY surfaces — a /metrics scrape, the
// session_revocation diagnostics row, /api/cluster/revocations — and they
// DELETE. Using a raw now.After(exp) there evicts during the whole wall-clock
// second numbered Exp, while Decode still accepts the cookie, so a scrape
// landing in that second resurrected a logged-out session for the remainder of
// it (Codex P2, PR #1437). Verified failing against `now.After(exp)`.
func TestRevocationExpiry_CountingNeverEvictsALiveRevocation(t *testing.T) {
	initSecret(t)
	withFreshRevocationList(t)

	observeWithinSecond(t, func(sec int64) string {
		s := &Session{Sub: "victim", Exp: sec}
		cookie, b64 := revokeToken(t, s)

		// Control: the cookie is still inside its lifetime, so Decode accepts
		// it and the revocation is what denies the session.
		if _, err := Decode(cookie); err == nil {
			return "logged-out cookie was accepted inside its final second (fail-open)"
		}

		// The read-only surface. This must not be able to destroy the entry
		// that is doing the denying.
		if n := Revoked.Count(); n != 1 {
			return "Count() evicted a revocation whose cookie Decode still honours"
		}
		if !Revoked.IsRevoked(b64) {
			return "revocation gone after a counting read inside the final second"
		}
		return ""
	})
}

// TestRevocationExpiry_UserCountingNeverEvictsALiveRevocation is the same
// property for the account-level map, which has its own accessor and so its
// own chance to diverge.
func TestRevocationExpiry_UserCountingNeverEvictsALiveRevocation(t *testing.T) {
	rl := NewRevocationList()

	observeWithinSecond(t, func(sec int64) string {
		rl.mu.Lock()
		rl.users["alice"] = time.Unix(sec, 0) // the current second, truncated
		rl.mu.Unlock()

		if n := rl.UserCount(); n != 1 {
			return "UserCount() evicted an account revocation inside its final second"
		}
		if !rl.IsUserRevoked("alice") {
			return "account revocation gone after a counting read inside the final second"
		}
		return ""
	})
}

// CONTROL. The prune must still collect a GENUINELY expired entry — the whole
// reason pruneExpiredLocked exists is that expiry is otherwise lazy and an
// entry on a standalone node would sit in the map for the life of the process,
// making the "currently in force" gauges wrong. The cheapest way to pass the
// two gates above is to stop pruning at all.
func TestRevocationExpiry_CountingStillCollectsExpiredEntries(t *testing.T) {
	rl := NewRevocationList()
	past := time.Now().Add(-2 * time.Second)
	rl.Revoke("stale-token", past)
	rl.mu.Lock()
	rl.users["stale-user"] = past
	rl.mu.Unlock()

	if n := rl.Count(); n != 0 {
		t.Errorf("Count() = %d, want 0: an expired token revocation was not collected", n)
	}
	if n := rl.UserCount(); n != 0 {
		t.Errorf("UserCount() = %d, want 0: an expired account revocation was not collected", n)
	}
	rl.mu.Lock()
	nTok, nUsr := len(rl.tokens), len(rl.users)
	rl.mu.Unlock()
	if nTok != 0 || nUsr != 0 {
		t.Errorf("entries left in the maps after counting: tokens=%d users=%d", nTok, nUsr)
	}
}
