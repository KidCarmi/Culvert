//go:build benchgate

package session

// Allocation-regression gate for the session-cookie MAC path (the macState /
// macEngine block in session.go).
//
// Correctness and equivalence contracts live in session_mac_test.go and run in
// the normal suite; this file holds the PERFORMANCE contract only, in the
// repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v ./internal/session/
//
// Keyed on allocations per op, which are deterministic and hardware
// independent, rather than ns/op, which is not. The timing win is real and
// large (see the PR and the benchmarks) but its SIZE depends on how expensive
// the runner's allocator and SHA-256 are relative to each other, so the gate
// asserts the structural property the win comes from: the verify step builds
// no HMAC state, no digest, and no expected-signature string.

import "testing"

// TestBenchGate_MacVerifyAllocFree locks the verify step at zero allocations.
//
// Measured (Go 1.26, linux/amd64): 0 allocs/op for the pooled engine, 9
// allocs/op and 896 B/op for the per-call hmac.New form it replaced — the
// HMAC struct, the ipad and opad blocks, an inner and an outer sha256.Digest,
// the payload conversion for Write, the digest from Sum(nil), two for
// EncodeToString, and the two []byte conversions hmac.Equal needed.
//
// Zero is the right bound rather than a cushion: every one of those nine has a
// named owner in the implementation, so a single reintroduced allocation is a
// regression worth failing on, not runtime churn. The gate also asserts the
// RELATIONSHIP — both shapes are measured in the same run on the same machine,
// so a slow or differently-tuned runner cannot make the comparison lie.
func TestBenchGate_MacVerifyAllocFree(t *testing.T) {
	const maxAllocs int64 = 0

	engine := testing.Benchmark(BenchmarkMacVerify)
	legacy := testing.Benchmark(BenchmarkMacVerifyLegacy)

	engineAllocs, legacyAllocs := engine.AllocsPerOp(), legacy.AllocsPerOp()
	t.Logf("verify engine: %d allocs/op, %d B/op (bound %d)", engineAllocs, engine.AllocedBytesPerOp(), maxAllocs)
	t.Logf("verify legacy: %d allocs/op, %d B/op", legacyAllocs, legacy.AllocedBytesPerOp())

	if engineAllocs > maxAllocs {
		t.Errorf("session MAC verification allocates %d/op, bound %d — per-request HMAC construction (or an equivalent temporary) is back on the proxy authentication hot path",
			engineAllocs, maxAllocs)
	}
	if engineAllocs >= legacyAllocs {
		t.Errorf("the pooled engine (%d allocs/op) is no cheaper than the per-call hmac.New shape (%d allocs/op); the optimization has been undone",
			engineAllocs, legacyAllocs)
	}
}

// TestBenchGate_MacVerifyRejectAllocFree extends the bound to the
// attacker-reachable shape. A tampered signature takes the length check and
// the constant-time compare rather than the accept path, and must be just as
// allocation-free — otherwise an unauthenticated client can drive allocation
// on the proxy by replaying garbage cookies.
func TestBenchGate_MacVerifyRejectAllocFree(t *testing.T) {
	const maxAllocs int64 = 0

	reject := testing.Benchmark(BenchmarkMacVerifyReject)
	t.Logf("verify reject: %d allocs/op, %d B/op (bound %d)", reject.AllocsPerOp(), reject.AllocedBytesPerOp(), maxAllocs)

	if got := reject.AllocsPerOp(); got > maxAllocs {
		t.Errorf("rejecting a tampered signature allocates %d/op, bound %d — an unauthenticated client can drive allocation through the cookie arm",
			got, maxAllocs)
	}
}

// TestBenchGate_DecodeAllocs bounds the whole per-request step, so the win
// cannot be given back one caller up.
//
// Measured (Go 1.26, linux/amd64): 17 allocs/op and 752 B/op, against 26 and
// 1648 for the pre-change shape. What remains is the base64 payload decode and
// encoding/json's unmarshal into Session — a SEPARATE concern, deliberately
// not touched here. The bound sits at 20: above the measured value so stdlib
// churn across Go releases does not flip the gate, and well below the legacy
// 26 so restoring per-request HMAC construction fails here too.
//
// legacyDecode is the current body with the ONE changed line put back, so the
// relationship below is an end-to-end before/after measured in the same run.
func TestBenchGate_DecodeAllocs(t *testing.T) {
	const maxAllocs int64 = 20

	decode := testing.Benchmark(BenchmarkDecode)
	legacy := testing.Benchmark(BenchmarkDecodeLegacyMac)

	t.Logf("decode:        %d allocs/op, %d B/op (bound %d)", decode.AllocsPerOp(), decode.AllocedBytesPerOp(), maxAllocs)
	t.Logf("decode legacy: %d allocs/op, %d B/op", legacy.AllocsPerOp(), legacy.AllocedBytesPerOp())

	if got := decode.AllocsPerOp(); got > maxAllocs {
		t.Errorf("session Decode allocates %d/op, bound %d — the per-request cost of the cookie auth arm has regressed",
			got, maxAllocs)
	}
	if decode.AllocsPerOp() >= legacy.AllocsPerOp() {
		t.Errorf("Decode (%d allocs/op) is no cheaper than the same body with the per-call hmac.New comparison (%d allocs/op); the optimization has been undone",
			decode.AllocsPerOp(), legacy.AllocsPerOp())
	}
	if decode.AllocedBytesPerOp() >= legacy.AllocedBytesPerOp() {
		t.Errorf("Decode allocates %d B/op against %d for the pre-change shape; the HMAC state is back on the per-request path",
			decode.AllocedBytesPerOp(), legacy.AllocedBytesPerOp())
	}
}

// TestBenchGate_UnchangedKeyKeepsPoolWarm pins the retention rule that makes
// the engine worth having on a cluster data plane: applySnapshotSessionSecret
// reinstalls the CP-synced secret on every snapshot apply whether or not it
// moved, and SetSigningKey must recognise that no-op. If it stops doing so,
// steady config sync rebuilds HMAC state continuously and this gate catches it
// as an allocation delta against plain Decode.
func TestBenchGate_UnchangedKeyKeepsPoolWarm(t *testing.T) {
	plain := testing.Benchmark(BenchmarkDecode)
	reinstall := testing.Benchmark(BenchmarkDecodeKeyReinstallPerOp)
	rebind := testing.Benchmark(BenchmarkDecodeKeyRebindPerOp)

	t.Logf("decode plain:     %d allocs/op, %d B/op", plain.AllocsPerOp(), plain.AllocedBytesPerOp())
	t.Logf("decode reinstall: %d allocs/op, %d B/op", reinstall.AllocsPerOp(), reinstall.AllocedBytesPerOp())
	t.Logf("decode rebind:    %d allocs/op, %d B/op", rebind.AllocsPerOp(), rebind.AllocedBytesPerOp())

	if reinstall.AllocsPerOp() > plain.AllocsPerOp() {
		t.Errorf("reinstalling an unchanged signing key costs %d allocs/op against %d for a plain Decode — SetSigningKey is rebinding the engine on a no-op and discarding the warm pool",
			reinstall.AllocsPerOp(), plain.AllocsPerOp())
	}
	// Sanity on the oracle itself: a REAL key change must still cost more, or
	// the comparison above is measuring nothing.
	if rebind.AllocsPerOp() <= plain.AllocsPerOp() {
		t.Errorf("a genuine key rotation costs %d allocs/op against %d for a plain Decode; the rebind benchmark is not exercising a rebind, so the no-op assertion above is vacuous",
			rebind.AllocsPerOp(), plain.AllocsPerOp())
	}
}
