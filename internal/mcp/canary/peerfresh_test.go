package canary

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// The peer-freshness matrix (blocker #11, §16), driven against the pure verdict.
//
// The rows that need a real catalog, a real discovery or a restart live in the root package;
// these are the ones that are pure functions of one capture and one clock sample, so they are
// exhaustive and deterministic rather than rig-dependent.
//
// EVERY NEGATIVE FAMILY HAS A POSITIVE CONTROL. freshBase below is that control, asserted
// directly by TestPeerFresh_ExactAuthenticatedTargetIsMet: a verdict that simply answered "not
// fresh" to everything would satisfy every negative row here while making the First Canary
// permanently impossible — strictly worse than the defect being closed.

var (
	fpF1 = tooltrust.FingerprintDigest{1, 2, 3}
	fpF2 = tooltrust.FingerprintDigest{9, 9, 9}
)

const (
	freshTenant   = "tenant-a"
	freshServer   = "controlled"
	freshTool     = "t"
	freshIdentity = "spki-pin-1"
)

// freshNow is the evaluation instant every case below shares.
var freshNow = time.Unix(1_700_000_000, 0).UTC()

// freshTarget builds the exact target both sides of the binding start from.
func freshTarget() ReviewedTarget {
	return ReviewedTarget{
		Tenant:            freshTenant,
		ServerID:          freshServer,
		ToolName:          freshTool,
		Fingerprint:       fpF1,
		FingerprintFormat: 1,
		ServerIdentity:    freshIdentity,
	}
}

// freshBase is the fully-correct input: an exact reviewed F1 target, backed by an authenticated
// observation ten minutes old under the identity the registry pins now, on a usable server.
func freshBase() PeerFreshnessInput {
	return PeerFreshnessInput{
		Resolved:               true,
		Now:                    freshNow,
		Observed:               PeerObservationFacts{At: freshNow.Add(-10 * time.Minute), Identity: freshIdentity},
		Reviewed:               freshTarget(),
		Current:                freshTarget(),
		ActivationTenant:       freshTenant,
		RegistryPinnedIdentity: freshIdentity,
		ServerUsable:           true,
	}
}

// TestPeerFresh_ExactAuthenticatedTargetIsMet is THE positive control for this whole file.
func TestPeerFresh_ExactAuthenticatedTargetIsMet(t *testing.T) {
	if got := EvaluatePeerObservedFresh(freshBase()); got != PeerFreshOK {
		t.Fatalf("the canonical fresh case must be MET, got %q", got)
	}
}

// TestPeerFresh_Matrix is §16's pure half. Each row names the exact expected bounded reason, not
// merely "not OK": a verdict that returned the wrong class would still refuse activation, but it
// would send an operator to the wrong remedy — "stale" tells them to refresh, and refreshing
// cannot fix a target that moved.
func TestPeerFresh_Matrix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mutil func(*PeerFreshnessInput)
		want  PeerFreshReason
	}{
		// ── the shipped default ────────────────────────────────────────────────────────
		{
			name:  "seed-only F1 carries no observation",
			mutil: func(in *PeerFreshnessInput) { in.Observed = PeerObservationFacts{} },
			want:  PeerFreshMissing,
		},
		{
			name:  "capture unresolved",
			mutil: func(in *PeerFreshnessInput) { in.Resolved = false },
			want:  PeerFreshUnavailable,
		},

		// ── the clock ──────────────────────────────────────────────────────────────────
		{
			name: "exactly at the freshness boundary is still fresh",
			mutil: func(in *PeerFreshnessInput) {
				in.Observed.At = in.Now.Add(-FirstCanaryPeerObservationMaxAge)
			},
			want: PeerFreshOK,
		},
		{
			name: "one nanosecond beyond the boundary is stale",
			mutil: func(in *PeerFreshnessInput) {
				in.Observed.At = in.Now.Add(-FirstCanaryPeerObservationMaxAge - time.Nanosecond)
			},
			want: PeerFreshStale,
		},
		{
			name: "well beyond the bound is stale",
			mutil: func(in *PeerFreshnessInput) {
				in.Observed.At = in.Now.Add(-24 * time.Hour)
			},
			want: PeerFreshStale,
		},
		{
			name:  "zero timestamp",
			mutil: func(in *PeerFreshnessInput) { in.Observed.At = time.Time{} },
			want:  PeerFreshMissing,
		},
		{
			name: "observation stamped in the future (clock rollback)",
			mutil: func(in *PeerFreshnessInput) {
				in.Observed.At = in.Now.Add(time.Minute)
			},
			want: PeerFreshFuture,
		},

		// ── identity ───────────────────────────────────────────────────────────────────
		{
			name:  "no verified identity",
			mutil: func(in *PeerFreshnessInput) { in.Observed.Identity = "" },
			want:  PeerFreshNoIdentity,
		},
		{
			name:  "observed identity is not the registry pin",
			mutil: func(in *PeerFreshnessInput) { in.RegistryPinnedIdentity = "spki-pin-2" },
			want:  PeerFreshIdentityNotCurrent,
		},
		{
			name: "observed identity is not the fingerprint identity",
			mutil: func(in *PeerFreshnessInput) {
				in.Current.ServerIdentity = "spki-pin-2"
				in.Reviewed.ServerIdentity = "spki-pin-2"
			},
			want: PeerFreshIdentityNotCurrent,
		},

		// ── exact target binding ───────────────────────────────────────────────────────
		{
			name: "observation backs F1 but the activation reviewed F2",
			mutil: func(in *PeerFreshnessInput) {
				in.Reviewed.Fingerprint = fpF2
			},
			want: PeerFreshTargetMoved,
		},
		{
			name: "fingerprint matches but the format differs",
			mutil: func(in *PeerFreshnessInput) {
				in.Reviewed.FingerprintFormat = 2
			},
			want: PeerFreshTargetMoved,
		},
		{
			name: "correct fingerprint on the wrong server",
			mutil: func(in *PeerFreshnessInput) {
				in.Reviewed.ServerID = "other-server"
			},
			want: PeerFreshTargetMoved,
		},
		{
			name: "correct server but the wrong tool",
			mutil: func(in *PeerFreshnessInput) {
				in.Reviewed.ToolName = "other-tool"
			},
			want: PeerFreshTargetMoved,
		},
		{
			name: "activation names a tenant the registry does not own",
			mutil: func(in *PeerFreshnessInput) {
				in.ActivationTenant = "tenant-b"
			},
			want: PeerFreshTargetMoved,
		},
		{
			name: "reviewed target belongs to another tenant",
			mutil: func(in *PeerFreshnessInput) {
				in.Reviewed.Tenant = "tenant-b"
			},
			want: PeerFreshTargetMoved,
		},
		{
			name:  "no activation tenant at all",
			mutil: func(in *PeerFreshnessInput) { in.ActivationTenant = "" },
			want:  PeerFreshTargetMoved,
		},
		{
			name:  "nothing was reviewed for this tool",
			mutil: func(in *PeerFreshnessInput) { in.Reviewed = ReviewedTarget{} },
			want:  PeerFreshTargetMoved,
		},

		// ── live server state ──────────────────────────────────────────────────────────
		{
			name:  "server is disabled or identity-mismatched now",
			mutil: func(in *PeerFreshnessInput) { in.ServerUsable = false },
			want:  PeerFreshServerUnusable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := freshBase()
			tc.mutil(&in)
			if got := EvaluatePeerObservedFresh(in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPeerFresh_StaleAndMovedAreNotInterchangeable pins the ORDER the verdict checks in.
//
// A target that both moved AND is stale must report that it moved. The distinction is not
// cosmetic: the two reasons name different remedies, and an operator told "stale" about a target
// that was never theirs would refresh forever without the row ever turning green.
func TestPeerFresh_StaleAndMovedAreNotInterchangeable(t *testing.T) {
	in := freshBase()
	in.Reviewed.Fingerprint = fpF2                                             // moved
	in.Observed.At = in.Now.Add(-FirstCanaryPeerObservationMaxAge - time.Hour) // and stale
	if got := EvaluatePeerObservedFresh(in); got != PeerFreshTargetMoved {
		t.Fatalf("a moved target must report that it moved even when it is also stale, got %q", got)
	}
}

// TestPeerObservationFresh_Predicate pins the pure predicate directly, including the boundary
// decision, because the runtime will re-check this exact function before a physical send and the
// two call sites must never be able to disagree about what "fresh" means.
func TestPeerObservationFresh_Predicate(t *testing.T) {
	now := freshNow
	for _, tc := range []struct {
		name string
		obs  PeerObservationFacts
		want bool
	}{
		{"canonical", PeerObservationFacts{At: now.Add(-time.Minute), Identity: freshIdentity}, true},
		{"exactly at the bound", PeerObservationFacts{At: now.Add(-FirstCanaryPeerObservationMaxAge), Identity: freshIdentity}, true},
		{"one tick past the bound", PeerObservationFacts{At: now.Add(-FirstCanaryPeerObservationMaxAge - time.Nanosecond), Identity: freshIdentity}, false},
		{"stamped now", PeerObservationFacts{At: now, Identity: freshIdentity}, true},
		{"stamped in the future", PeerObservationFacts{At: now.Add(time.Nanosecond), Identity: freshIdentity}, false},
		{"zero timestamp", PeerObservationFacts{Identity: freshIdentity}, false},
		{"no identity", PeerObservationFacts{At: now.Add(-time.Minute)}, false},
		{"nothing at all", PeerObservationFacts{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PeerObservationFresh(now, tc.obs); got != tc.want {
				t.Fatalf("PeerObservationFresh = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPeerFresh_MaxAgeIsItsOwnInterval pins §8's independence claim structurally.
//
// The value may legitimately coincide with another duration, but the CONSTANT must be its own:
// if a future edit expresses it in terms of some other interval, shortening that one silently
// tightens peer freshness, and the two properties stop being able to move independently. There
// is no way to assert "this expression is a literal" from inside the package, so what is pinned
// here is the property an accidental re-definition would break — a stated, reviewed value.
func TestPeerFresh_MaxAgeIsItsOwnInterval(t *testing.T) {
	if FirstCanaryPeerObservationMaxAge != 30*time.Minute {
		t.Fatalf("FirstCanaryPeerObservationMaxAge changed to %v. That is allowed, but it is a "+
			"SECURITY INTERVAL: update the recorded rationale in peerfresh.go (why this value "+
			"suits an attended First Canary, and what it makes the worst-case unobserved drift) "+
			"in the same change, and re-check the runtime's pre-send re-check against it.",
			FirstCanaryPeerObservationMaxAge)
	}
	if FirstCanaryPeerObservationMaxAge <= 0 {
		t.Fatal("a non-positive max age would make every observation stale and the First Canary " +
			"impossible")
	}
}
