package session

// Benchmarks for the revocation READ path — the checks Decode runs on every
// authenticated proxy request.
//
// Both shapes are measured in the SAME run: `StatusFor`, which answers both
// questions under ONE acquisition of the list mutex, and the two-call form it
// replaced (`IsRevoked` then `IsUserRevoked`, both still exported and both
// still the single-question entry points). A slow or differently-tuned runner
// therefore cannot make the comparison lie, which is the differential
// convention session_mac_bench_test.go already uses for the MAC engine.
//
// There is no copy of production logic here: the "legacy" arm calls the real
// public methods, because what changed is the NUMBER OF ACQUISITIONS and not
// the decision under them.
//
// The contract these establish is enforced by
// revocation_readpath_benchgate_test.go.

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// benchRevocationEntries is how many LIVE revocations the list holds while the
// read path is measured. A quiet appliance holds none; one inside a 7-day
// session TTL holds one per real logout. 4096 is a busy-but-ordinary middle,
// and it is deliberately not zero: an empty map would measure the lock protocol
// and not the lookup under it.
const benchRevocationEntries = 4096

// benchMissPayload / benchMissUser are the shapes the hot path actually
// presents: a cookie payload and a subject that are NOT on the list. Every
// request a gateway allows takes this path.
//
// The payload is a realistic LENGTH (a base64url Session of the usual size),
// because the map lookup's cost depends on how many bytes a key comparison
// has to walk, and deliberately not realistic CONTENT: a base64-shaped
// literal in a constant whose name contains "token" is a gosec G101 match,
// which is the inadvertent-secret-name trap the conventions call out. Nothing
// here needs it to decode — these benchmarks never call Decode.
const (
	benchMissPayload = "absent-cookie-payload-of-a-representative-length-00000000"
	benchMissUser    = "alice@example.com"
)

func benchTokenAt(i int) string { return "revoked-token-" + strconv.Itoa(i) }
func benchUserAt(i int) string  { return "user-" + strconv.Itoa(i) + "@example.com" }

// filledRevocationList returns a list holding benchRevocationEntries live token
// and user revocations.
//
// Deliberately NOT the `Revoked` package singleton: the two arms must differ
// only in how many times they take the lock, and a global's allocation locality
// is not something a fresh object shares.
func filledRevocationList(tb testing.TB) *RevocationList {
	tb.Helper()
	r := NewRevocationList()
	exp := time.Now().Add(time.Hour)
	r.mu.Lock()
	for i := 0; i < benchRevocationEntries; i++ {
		r.tokens[benchTokenAt(i)] = exp
		r.users[benchUserAt(i)] = exp
	}
	r.mu.Unlock()
	return r
}

var benchRevokedSink atomic.Bool

// ─── The hot path: a miss on both maps, which is every allowed request ──────

func BenchmarkRevocationStatus_OneLock(b *testing.B) {
	r := filledRevocationList(b)
	b.ReportAllocs()
	for b.Loop() {
		tok, usr := r.StatusFor(benchMissPayload, benchMissUser)
		benchRevokedSink.Store(tok || usr)
	}
}

func BenchmarkRevocationStatus_TwoLocks(b *testing.B) {
	r := filledRevocationList(b)
	b.ReportAllocs()
	for b.Loop() {
		benchRevokedSink.Store(r.IsRevoked(benchMissPayload) || r.IsUserRevoked(benchMissUser))
	}
}

// ─── The same path under the concurrency a gateway actually applies ─────────
//
// This pair is the measurement the change exists for. The serial pair above
// cannot show much: an uncontended acquisition is a CAS, so dropping one saves
// a CAS. Under contention it saves an entire serialisation point, and the
// saving grows with the number of cores asking.

func BenchmarkRevocationStatusParallel_OneLock(b *testing.B) {
	r := filledRevocationList(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tok, usr := r.StatusFor(benchMissPayload, benchMissUser)
			benchRevokedSink.Store(tok || usr)
		}
	})
}

func BenchmarkRevocationStatusParallel_TwoLocks(b *testing.B) {
	r := filledRevocationList(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchRevokedSink.Store(r.IsRevoked(benchMissPayload) || r.IsUserRevoked(benchMissUser))
		}
	})
}

// BenchmarkRevocationStatusParallel_OneLockHit is the enforcement path: a live
// revocation on both maps.
//
// It is measured to be SLOWER than the miss above, and that is the expected
// shape rather than a regression: a miss returns from `!ok` without consulting
// the clock, where a hit pays two successful lookups (full key comparison) and
// two `revocationExpired` calls, each of which reads the clock. The miss is the
// path every allowed request takes, so it is the one that matters; this arm
// exists so a change that made the REFUSAL path disproportionately expensive
// would be visible rather than unmeasured.
func BenchmarkRevocationStatusParallel_OneLockHit(b *testing.B) {
	r := filledRevocationList(b)
	tok := benchTokenAt(benchRevocationEntries / 2)
	usr := benchUserAt(benchRevocationEntries / 2)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			t, u := r.StatusFor(tok, usr)
			benchRevokedSink.Store(t || u)
		}
	})
}

// BenchmarkRevocationStatusParallel_OneLockNoSubject covers the arm that skips
// the user lookup entirely (a cookie with no subject), which is the guard
// Decode's call site used to apply itself.
func BenchmarkRevocationStatusParallel_OneLockNoSubject(b *testing.B) {
	r := filledRevocationList(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tok, usr := r.StatusFor(benchMissPayload, "")
			benchRevokedSink.Store(tok || usr)
		}
	})
}
