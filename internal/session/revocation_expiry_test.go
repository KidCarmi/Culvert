package session

// revocation_expiry_test.go — SEC-REVEXP-1 gates.
//
// The defect was a disagreement between two expiry predicates, so the tests
// are written as a DIFFERENTIAL against the verifier (Decode) rather than
// against a hand-copied constant: a future change to either side that
// reintroduces the gap fails here even if the numbers move.
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
	"strings"
	"sync"
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

// TestRevocationExpiry_UnambiguouslyPastEntriesStillEvict is the negative
// control. A fix in the fail-closed direction is only correct if eviction
// still happens once the expiry second has genuinely passed — otherwise the
// list grows without bound.
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

// TestRevocationExpiry_MalformedPeerExpiries checks the degenerate Expiry
// values a peer or a hand-edited revocations file can carry. None may be
// admitted, and none may panic.
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
func TestRevocationExpiry_ConcurrentReadersAndWriters(t *testing.T) {
	rl := NewRevocationList()
	// A far-future expiry for the storm: phase 1 asserts nothing about the
	// boundary, so it must not depend on the clock.
	stormExp := time.Now().Add(time.Hour).Unix()

	const workers = 8
	const iters = 300

	// ── Phase 1: the storm. Races and panics only. ──────────────────────────
	hammer := func(stop <-chan struct{}) func() {
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; i < iters; i++ {
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
	hammer(never)()

	if !rl.IsRevoked("storm") {
		t.Error("a far-future entry did not survive the concurrent storm")
	}

	// ── Phase 2: the boundary, under live concurrent traffic. ───────────────
	// Background traffic keeps the eviction sites running against the entry
	// under test; the observation itself is microseconds and is voided and
	// retried if it straddles a second boundary.
	stop := make(chan struct{})
	wait := hammer(stop)
	defer func() { close(stop); wait() }()

	observeWithinSecond(t, func(sec int64) string {
		rl.Revoke("final-second", time.Unix(sec, 0))
		if !rl.IsRevoked("final-second") {
			return "entry inside its final second was evicted by a concurrent pass"
		}
		return ""
	})
}
