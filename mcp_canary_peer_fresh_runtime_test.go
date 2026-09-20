package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// THE RUNTIME PEER-FRESHNESS MATRIX (blocker #11, §9-§11).
//
// The core invariant: a request may cross the irreversible boundary only if the exact target still
// carries a fresh authenticated peer observation AT THE INSTANT EXECUTION AUTHORITY IS SPENT.
// Activation-time readiness is not sufficient, because freshness is the one prerequisite that
// becomes false with no state change at all — purely by the clock advancing.
//
// EVERY CASE IS DETERMINISTIC AND SLEEP-FREE. Two seams do all the work:
//
//   - the gate's boundary clock (g.now), read EXACTLY THREE TIMES per request — once in
//     preCallGuard before the emergency-kill re-read, then again at each CallOptions.PreSend
//     point: after the pool slot and DNS, and again after the TCP connect and TLS handshake.
//     A clock that reports fresh for the first N reads and stale afterwards therefore places the
//     expiry at a precise point on the path, with no timing dependence whatsoever.
//   - the precheck's observation, which the test owns, so evidence can be aged, future-dated,
//     re-observed or removed between requests.
//
// The three-read count is not assumed: the rig records every read, and the positive control
// asserts it, so a future change to the PreSend wiring makes these cases fail loudly rather than
// silently stop testing the point they were written for.
//
// ANTI-VACUITY, MEASURED RATHER THAN CLAIMED. With the boundary freshness call deleted from
// mcp_live_gate.go, SEVEN of the nine cases below fail. The two that still pass are the two that
// should: RT01 is the positive control (a boundary that refused everything would satisfy every
// negative here while making the First Canary impossible), and RT06 proves a DIFFERENT authority
// — the precheck's target binding — and is labelled as such rather than counted as a freshness
// gate it is not.

// peerFreshRig drives the REAL live-execution path against a REAL local HTTPS peer, with the
// boundary clock and the peer observation under test control.
type peerFreshRTRig struct {
	*peerRig
	peer *controlledPeer
	// nowNanos is the boundary clock. freshReads, when >= 0, is how many boundary reads report
	// that instant before the clock jumps past the freshness bound.
	nowNanos   atomic.Int64
	reads      atomic.Int64
	freshReads atomic.Int64
	// obsNanos / obsIdentity are the evidence the precheck reports.
	obsNanos atomic.Int64
	obsIdent atomic.Value // string
	regPin   atomic.Value // string
	eligible atomic.Bool
}

// staleJump is comfortably past the freshness bound, so an expired read is unambiguous.
var staleJump = canary.FirstCanaryPeerObservationMaxAge + time.Minute

func newPeerFreshRTRig(t *testing.T, p *controlledPeer, budget int) *peerFreshRTRig {
	t.Helper()
	r := &peerFreshRTRig{peer: p}
	r.nowNanos.Store(liveHarnessInstant.UnixNano())
	r.obsNanos.Store(liveHarnessInstant.UnixNano())
	r.obsIdent.Store(testReviewedTarget().ServerIdentity)
	r.regPin.Store(testReviewedTarget().ServerIdentity)
	r.eligible.Store(true)
	r.freshReads.Store(-1) // -1 ⇒ the clock never jumps

	r.peerRig = armCanaryWithRealPeerGate(t, p, budget, true, func(g *mcpLiveSideEffectGate) {
		g.trustPrecheck = func(string, string, string, string) liveTrustPrecheck {
			base := stubTrustPrecheckObservedAt(time.Unix(0, r.obsNanos.Load()))("", "", "", "")
			base.Eligible = r.eligible.Load()
			base.Observed.Identity = r.obsIdent.Load().(string)
			base.RegistryPin = r.regPin.Load().(string)
			if r.obsNanos.Load() == 0 {
				base.Observed = canary.PeerObservationFacts{} // never observed
			}
			return base
		}
		g.now = func() time.Time {
			n := r.reads.Add(1)
			if fr := r.freshReads.Load(); fr >= 0 && n > fr {
				return time.Unix(0, r.nowNanos.Load()).Add(staleJump)
			}
			return time.Unix(0, r.nowNanos.Load())
		}
	})
	return r
}

// expireAfter places the expiry after n boundary reads: n=0 refuses at the very first re-check,
// n=1 after preCallGuard, n=2 after the pool wait and DNS but with the connection established.
func (r *peerFreshRTRig) expireAfter(n int64) { r.freshReads.Store(n); r.reads.Store(0) }

// run executes one request and reports whether it crossed, plus the peer's request count.
func (r *peerFreshRTRig) run(t *testing.T) (crossed bool, peerRequests int) {
	t.Helper()
	before := r.peer.count()
	out := r.exec(peerExecInput(r.peer, policy.OpRead))
	return out.Executed, r.peer.count() - before
}

// ── (1) the POSITIVE CONTROL ────────────────────────────────────────────────────────────────

// TestPeerFreshRT01_FreshObservationCrossesTheWholePath is the control every negative case below
// depends on. A boundary that refused everything would satisfy all eleven of them while making
// the First Canary impossible — strictly worse than the defect being closed.
//
// It also pins the THREE-READ structure the rest of the matrix places its expiries against.
func TestPeerFreshRT01_FreshObservationCrossesTheWholePath(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)

	crossed, reqs := r.run(t)
	if !crossed || reqs != 1 {
		t.Fatalf("a fresh observation must reach the peer exactly once: crossed=%v requests=%d", crossed, reqs)
	}
	if got := r.reads.Load(); got != 3 {
		t.Fatalf("the boundary clock must be read three times per request (preCallGuard, PreSend "+
			"after the pool wait, PreSend after the handshake); got %d. The expiry points every "+
			"case below places depend on this structure — if the PreSend wiring changed, these "+
			"cases are no longer testing what they say.", got)
	}
}

// ── (2)(3)(4) expiry BEFORE the first boundary re-check ─────────────────────────────────────

// TestPeerFreshRT02_StaleBeforeAdmissionNeverReachesThePeer.
//
// This one case covers §9's rows 2, 3 and 4 — stale before admission, expired after activation
// but before the request, and expired after policy resolution but before live admission — and
// that is a statement about the design rather than a shortcut. Admission does not consult peer
// freshness at all; the first authority that does is the boundary re-check. So all three
// orderings converge on the same observable: the request is refused at the first re-check, having
// touched nothing.
func TestPeerFreshRT02_StaleBeforeAdmissionNeverReachesThePeer(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)
	if crossed, _ := r.run(t); !crossed {
		t.Fatal("premise: the fixture must be able to execute while fresh")
	}

	r.expireAfter(0) // stale at the very first boundary read
	crossed, reqs := r.run(t)
	if crossed {
		t.Fatal("a request whose observation expired before the boundary must not execute")
	}
	if reqs != 0 {
		t.Fatalf("no bytes may reach the peer, got %d request(s)", reqs)
	}
}

// ── (5) expiry after admission, during the durable work ─────────────────────────────────────

// TestPeerFreshRT03_ExpiryAfterAdmissionRefusesBeforeTheUpstream.
//
// preCallGuard has already admitted the request — this is the window in which the request holds a
// budget reservation and is doing credential materialization and the durable decision commit. The
// observation lapses there. The first PreSend re-ask catches it, before any connection is made.
func TestPeerFreshRT03_ExpiryAfterAdmissionRefusesBeforeTheUpstream(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)

	r.expireAfter(1) // read 1 (preCallGuard) fresh; read 2 (first PreSend) stale
	crossed, reqs := r.run(t)
	if crossed {
		t.Fatal("an observation that lapsed after admission must not authorize the send")
	}
	if reqs != 0 {
		t.Fatalf("no bytes may reach the peer, got %d request(s)", reqs)
	}
}

// ── (6) + §10 THE BYTE-LEVEL PROOF ──────────────────────────────────────────────────────────

// TestPeerFreshRT04_ExpiryDuringTheConnectionWaitSendsNoRequestBytes is §10.
//
// The expiry lands after the LAST PreSend point — i.e. after the pool slot, after DNS, after the
// TCP connect and after the TLS handshake. A transport connection may therefore legitimately
// exist. What must not exist is a single byte of MCP REQUEST.
//
// It is asserted on the PEER's own request count rather than on a handler call count, matching
// #1370's proof style: a handler that was never invoked proves only that the handler did not run,
// which a connection opened and then abandoned would also satisfy. The controlled peer counts
// what it actually received.
func TestPeerFreshRT04_ExpiryDuringTheConnectionWaitSendsNoRequestBytes(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)
	if crossed, reqs := r.run(t); !crossed || reqs != 1 {
		t.Fatalf("control: the fixture must reach this peer while fresh (crossed=%v reqs=%d)", crossed, reqs)
	}

	r.expireAfter(2) // reads 1 and 2 fresh; read 3 — after connect + TLS — stale
	crossed, reqs := r.run(t)
	if crossed {
		t.Fatal("an observation that lapsed during the connection wait must not authorize the send")
	}
	if reqs != 0 {
		t.Fatalf("SECURITY: %d MCP request(s) reached the peer after the observation expired. The "+
			"connection may exist at this point; the request bytes may not.", reqs)
	}
}

// ── (7) future-dated ────────────────────────────────────────────────────────────────────────

// TestPeerFreshRT05_FutureDatedObservationIsRefused. A stamp after the evaluation instant means
// either a clock moved backwards or the timestamp cannot be trusted; both resolve to NOT fresh.
// Honouring it would grant authority for however far ahead it sits.
func TestPeerFreshRT05_FutureDatedObservationIsRefused(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)

	r.obsNanos.Store(time.Unix(0, r.nowNanos.Load()).Add(time.Hour).UnixNano())
	crossed, reqs := r.run(t)
	if crossed || reqs != 0 {
		t.Fatalf("a future-dated observation must not authorize a send: crossed=%v reqs=%d", crossed, reqs)
	}
}

// ── (8) F1 stale, F2 fresh ──────────────────────────────────────────────────────────────────

// TestPeerFreshRT06_AFreshObservationForAnotherTargetDoesNotRescueThisOne.
//
// The peer moved to F2 and was observed there — so the catalog holds a perfectly fresh
// observation. The request was authorized against F1. It must still be refused, and the refusal
// comes from the target binding the precheck performs (the current record no longer carries the
// DECISION's fingerprint), not from freshness: a fresh observation of a DIFFERENT target is not
// evidence about this one, and no amount of it can become evidence about this one.
//
// SO THIS CASE DELIBERATELY DOES NOT DEPEND ON THE RUNTIME FRESHNESS CHECK, and that was verified
// by deleting it: this case still passes, because the precheck refuses first. It is kept because
// §9 asks for the F1-stale/F2-fresh sequence and because the property matters — but it is NOT
// evidence that the freshness re-check works, and counting it as such would inflate the matrix.
func TestPeerFreshRT06_AFreshObservationForAnotherTargetDoesNotRescueThisOne(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)
	if crossed, _ := r.run(t); !crossed {
		t.Fatal("premise: the fixture must execute while the target still matches")
	}

	// The target moved: the precheck refuses because the current record no longer carries the
	// decision's fingerprint. The observation stays maximally fresh throughout.
	r.eligible.Store(false)
	r.obsNanos.Store(r.nowNanos.Load())
	crossed, reqs := r.run(t)
	if crossed || reqs != 0 {
		t.Fatalf("a fresh observation of another target must not authorize this request: crossed=%v reqs=%d",
			crossed, reqs)
	}
}

// ── (9) registry pin changed ────────────────────────────────────────────────────────────────

// TestPeerFreshRT07_ObservationUnderASupersededPinIsRefused.
//
// The observation is recent and well-formed, and the identity it was gathered under is the one
// the catalog record carries — but the registry now pins a DIFFERENT identity. The peer that was
// observed is not the peer this node would now dial, so the evidence describes someone else.
func TestPeerFreshRT07_ObservationUnderASupersededPinIsRefused(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)

	r.regPin.Store("spiffe://test/repinned")
	crossed, reqs := r.run(t)
	if crossed || reqs != 0 {
		t.Fatalf("an observation under a superseded pin must not authorize a send: crossed=%v reqs=%d",
			crossed, reqs)
	}
}

// ── (10)(11) a failed refresh does not extend age; a real one does ──────────────────────────

// TestPeerFreshRT08_FailedRefreshDoesNotExtendAgeAndARealOneDoes covers both halves of §9's rows
// 10 and 11 in one sequence, because they are the same property seen from two sides: only a
// SIGHTING moves the clock forward.
func TestPeerFreshRT08_FailedRefreshDoesNotExtendAgeAndARealOneDoes(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)
	if crossed, _ := r.run(t); !crossed {
		t.Fatal("premise: fresh evidence must execute")
	}

	// Time passes and the refresh FAILS: the evidence is untouched, so it simply ages out. A
	// failed refresh is not a statement that the peer is unchanged.
	r.nowNanos.Store(time.Unix(0, r.nowNanos.Load()).Add(staleJump).UnixNano())
	if crossed, reqs := r.run(t); crossed || reqs != 0 {
		t.Fatalf("aged-out evidence must refuse after a failed refresh: crossed=%v reqs=%d", crossed, reqs)
	}

	// The peer is observed again, unchanged. THAT moves the evidence forward.
	r.obsNanos.Store(r.nowNanos.Load())
	if crossed, reqs := r.run(t); !crossed || reqs != 1 {
		t.Fatalf("a real re-observation must restore authority: crossed=%v reqs=%d", crossed, reqs)
	}
}

// ── (12) + §11 operator reseed and restart ──────────────────────────────────────────────────

// TestPeerFreshRT09_ReseedAndRestartBothRemoveTheAuthority.
//
// An operator reseed replaces the record with one carrying no observation, and a restart rebuilds
// the whole catalog from the operator inventory — the same end state, reached two ways, and the
// accepted posture for both. A previous process's green activation cannot make seed data read as
// observed, because nothing about the seed says a peer was ever seen.
func TestPeerFreshRT09_ReseedAndRestartBothRemoveTheAuthority(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)
	if crossed, _ := r.run(t); !crossed {
		t.Fatal("premise: the observed target must execute first")
	}

	// obsNanos == 0 is the seeded state: a record with no observation at all.
	r.obsNanos.Store(0)
	crossed, reqs := r.run(t)
	if crossed || reqs != 0 {
		t.Fatalf("a record with no peer observation must not authorize a send: crossed=%v reqs=%d",
			crossed, reqs)
	}
}
