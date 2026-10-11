package session

// revocation_expiry_test.go — SEC-REVEXP-1 gates.
//
// The defect was a disagreement between two expiry predicates, so the tests
// are written as a DIFFERENTIAL against the verifier (Decode) rather than
// against a hand-copied constant: a future change to either side that
// reintroduces the gap fails here even if the numbers move.
//
// Several tests must observe behaviour INSIDE a particular wall-clock second.
// `settleWithinSecond` parks the goroutine in the comfortable middle of a
// second so the sub-second remainder is unambiguous in both directions; it
// costs at most one second and makes every assertion below deterministic
// rather than probabilistic. Without it, a test that happened to run at
// X.000 would pass against the pre-fix code too.

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// settleWithinSecond blocks until the current instant is between 300ms and
// 800ms past a second boundary.
func settleWithinSecond(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ns := time.Now().Nanosecond()
		if ns >= int(300*time.Millisecond) && ns <= int(800*time.Millisecond) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("could not settle inside a second — clock is not advancing")
		}
		time.Sleep(5 * time.Millisecond)
	}
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
	settleWithinSecond(t)

	s := &Session{Sub: "victim", Exp: time.Now().Unix()}
	cookie, b64 := revokeToken(t, s)

	if _, err := Decode(cookie); err == nil {
		t.Fatal("logged-out cookie was accepted inside its final second (fail-open)")
	}
	if !Revoked.IsRevoked(b64) {
		t.Error("revocation was evicted while the cookie it revokes is still within its lifetime")
	}
}

// TestRevocationExpiry_EntrySurvivesTheFinalSecond pins the retention half
// directly: the entry must still be in the map, not merely reported revoked.
// The pre-fix bug DELETED it, which is what made the hole propagate to disk
// and to peers.
func TestRevocationExpiry_EntrySurvivesTheFinalSecond(t *testing.T) {
	rl := NewRevocationList()
	settleWithinSecond(t)

	exp := time.Unix(time.Now().Unix(), 0) // the current second, truncated
	rl.Revoke("tok", exp)

	if !rl.IsRevoked("tok") {
		t.Error("IsRevoked = false inside the revocation's own final second")
	}
	rl.mu.Lock()
	_, exists := rl.tokens["tok"]
	rl.mu.Unlock()
	if !exists {
		t.Error("entry was deleted inside its own final second")
	}
}

// TestRevocationExpiry_DifferentialAcrossOffsets is the property: across a
// sweep of session expiries either side of now, Decode and the revocation list
// must never disagree in the fail-open direction — "Decode accepts" implies
// "the revocation is still live". The reverse (a retained entry for a session
// Decode already rejects) is harmless and expected.
func TestRevocationExpiry_DifferentialAcrossOffsets(t *testing.T) {
	initSecret(t)
	withFreshRevocationList(t)
	settleWithinSecond(t)

	base := time.Now().Unix()
	for _, off := range []int64{-5, -2, -1, 0, 1, 2, 5} {
		s := &Session{Sub: "u", Exp: base + off}
		cookie, b64 := revokeToken(t, s)

		accepted := func() bool { _, err := Decode(cookie); return err == nil }()
		// Decode consults IsRevoked itself, so ask the list directly for the
		// live/evicted verdict rather than inferring it from Decode.
		live := Revoked.IsRevoked(b64)

		if accepted {
			t.Errorf("offset %+ds: Decode accepted a revoked cookie", off)
		}
		// A session Decode would accept on expiry grounds alone must have a
		// live revocation.
		if time.Now().Unix() <= s.Exp && !live {
			t.Errorf("offset %+ds: revocation evicted while the session is still within its lifetime", off)
		}
	}
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
	settleWithinSecond(t)

	nowSec := time.Now().Unix()
	rl.Revoke("final-second", time.Unix(nowSec, 0))
	rl.Revoke("long-dead", time.Unix(nowSec-60, 0))

	got := map[string]bool{}
	for _, e := range rl.ExportRevocations() {
		got[e.Token] = true
	}
	if !got["final-second"] {
		t.Error("export dropped an entry still inside its final second — it would vanish from disk and from every peer")
	}
	if got["long-dead"] {
		t.Error("export retained an entry a minute past its expiry")
	}
}

// TestRevocationExpiry_MergeAdmitsTheFinalSecond is the inbound half: a peer's
// entry for a session Decode would still accept must be admitted, not refused
// as "already expired".
func TestRevocationExpiry_MergeAdmitsTheFinalSecond(t *testing.T) {
	rl := NewRevocationList()
	settleWithinSecond(t)

	nowSec := time.Now().Unix()
	added := rl.MergeRevocations([]RevocationEntry{
		{Token: "from-peer", Expiry: nowSec},
		{Token: "stale-peer", Expiry: nowSec - 60},
	})
	if added != 1 {
		t.Fatalf("merged %d entries, want 1 (the final-second entry admitted, the stale one refused)", added)
	}
	if !rl.IsRevoked("from-peer") {
		t.Error("a peer's revocation for a still-valid session was refused")
	}
	if rl.IsRevoked("stale-peer") {
		t.Error("a peer's long-expired revocation was admitted")
	}
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
	settleWithinSecond(t)

	rl.mu.Lock()
	rl.users["inside"] = time.Unix(time.Now().Unix(), 0)
	rl.users["past"] = time.Unix(time.Now().Unix()-60, 0)
	rl.mu.Unlock()

	if !rl.IsUserRevoked("inside") {
		t.Error("user revocation evicted inside its final second")
	}
	if rl.IsUserRevoked("past") {
		t.Error("user revocation a minute past its expiry still reported")
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────────

// TestRevocationExpiry_ConcurrentReadersAndWriters runs the predicate under
// -race from every path that reaches it. The eviction sites mutate the map
// while holding r.mu; this asserts the fix did not move any read outside it.
func TestRevocationExpiry_ConcurrentReadersAndWriters(t *testing.T) {
	rl := NewRevocationList()
	settleWithinSecond(t)
	nowSec := time.Now().Unix()

	const workers = 8
	const iters = 300
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				switch (w + i) % 5 {
				case 0:
					rl.Revoke("tok", time.Unix(nowSec, 0))
				case 1:
					rl.IsRevoked("tok")
				case 2:
					rl.ExportRevocations()
				case 3:
					rl.MergeRevocations([]RevocationEntry{{Token: "peer", Expiry: nowSec}})
				case 4:
					rl.IsUserRevoked("someone")
				}
			}
		}(w)
	}
	wg.Wait()

	// The entry revoked inside its final second must have survived every
	// concurrent eviction pass.
	if !rl.IsRevoked("tok") {
		t.Error("entry inside its final second was evicted by a concurrent pass")
	}
}
