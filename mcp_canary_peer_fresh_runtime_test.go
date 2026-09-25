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
// ANTI-VACUITY, MEASURED RATHER THAN CLAIMED. There are TWO freshness sites since round 13 (Codex
// P2, PR #1439): the boundary re-check and an admission-time check that stops an already-stale
// request from spending budget. Deleting each in turn:
//
//   - boundary call only  → RT02, RT03, RT04 fail (lapses DURING the request)
//   - admission call only → RT11 fails (stale on arrival: refused at the boundary, but charged)
//   - both                → those four plus RT05, RT07, RT08, RT09, which either site refuses
//
// RT01, RT06 and RT10 survive every deletion, and should: RT01 is the positive control (a boundary
// that refused everything would satisfy every negative here while making the First Canary
// impossible), and RT06 and RT10 prove a DIFFERENT authority — the precheck's target binding — and
// are labelled as such rather than counted as freshness gates they are not.

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
	// eligibleAfter, when >= 0, is how many precheck calls report eligible before the target stops
	// resolving — so drift can be placed AFTER admission rather than before it.
	eligibleAfter atomic.Int64
	precheckCalls atomic.Int64
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
	r.eligibleAfter.Store(-1)
	r.freshReads.Store(-1) // -1 ⇒ the clock never jumps

	r.peerRig = armCanaryWithRealPeerGate(t, p, budget, true, func(g *mcpLiveSideEffectGate) {
		g.trustPrecheck = func(string, string, string, string) liveTrustPrecheck {
			base := stubTrustPrecheckObservedAt(time.Unix(0, r.obsNanos.Load()))("", "", "", "")
			base.Eligible = r.eligible.Load()
			if ea := r.eligibleAfter.Load(); ea >= 0 && r.precheckCalls.Add(1) > ea {
				base.Eligible = false
			}
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
// depends on. A boundary that refused everything would satisfy all nine of them while making
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

// TestPeerFreshRT02_StaleBeforeAdmissionNeverReachesThePeer covers every ordering in which the
// observation lapses before the first boundary re-check.
//
// It places the lapse on the BOUNDARY clock at its very first read, while the admission instant
// still sees the observation as fresh — so admission reserves and the first re-check refuses,
// having touched nothing. §9's rows 2, 3 and 4 converge on that observable.
//
// The case where the observation is ALREADY stale at the admission instant is RT11, and it
// asserts something this case cannot: that the refusal happens before the budget is charged.
// Admission did not consult freshness when this case was written, which is exactly the gap
// Codex found (P2, PR #1439) — the invariant held, the budget did not.
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

// TestPeerFreshRT03_ExpiryAfterAdmissionRefusesBeforeTheUpstream places the lapse in the window
// where the request already holds a budget reservation.
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

// TestPeerFreshRT06_AFreshObservationForAnotherTargetDoesNotRescueThisOne pins that freshness
// belongs to an exact target and cannot be borrowed from another.
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

// TestPeerFreshRT07_ObservationUnderASupersededPinIsRefused pins that recent, well-formed
// evidence is worthless once it names an identity the registry no longer pins.
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
	//
	// Age is modelled by moving the EVIDENCE back rather than the boundary clock forward. This
	// harness pins the admission instant (the executor's clock) at a fixed value, and admission now
	// judges freshness too (Codex P2, PR #1439); advancing only the boundary clock and then
	// re-observing at it would stamp the observation in the FUTURE relative to admission — two
	// clocks that are one clock in production, disagreeing about an instant that cannot occur.
	// Freshness is a function of (evaluation instant − sighting), so this is the same fact.
	r.obsNanos.Store(time.Unix(0, r.nowNanos.Load()).Add(-staleJump).UnixNano())
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

// TestPeerFreshRT09_ReseedAndRestartBothRemoveTheAuthority pins the accepted posture for a
// record that carries no observation at all.
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

// ── the gap the mutation campaign found (RM5) ───────────────────────────────────────────────

// TestPeerFreshRT10_TargetDriftBetweenAdmissionAndTheBoundaryIsRefused is the case that makes
// the boundary's eligibility check non-redundant.
//
// RT06 drives a target that was already ineligible when the request arrived, and admission
// refuses it — so deleting the boundary's own eligibility check left RT06 green. That made the
// boundary check look redundant when it is not: its whole reason to exist is the window AFTER
// admission, where the request holds a reservation and is doing credential materialization, the
// durable commit and an unbounded wait for a pool slot.
//
// Here the target resolves fine for admission and stops resolving at the first boundary re-ask.
// Nothing may reach the peer.
func TestPeerFreshRT10_TargetDriftBetweenAdmissionAndTheBoundaryIsRefused(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 10)
	if crossed, _ := r.run(t); !crossed {
		t.Fatal("premise: the fixture must execute while the target resolves")
	}

	// Admission's probe resolves; every later precheck call — the boundary re-asks — does not.
	r.precheckCalls.Store(0)
	r.eligibleAfter.Store(1)
	crossed, reqs := r.run(t)
	if crossed {
		t.Fatal("a target that stopped resolving after admission must not reach the upstream")
	}
	if reqs != 0 {
		t.Fatalf("no bytes may reach the peer, got %d request(s)", reqs)
	}
}

// ── (13) an observation already stale at admission spends no budget (Codex P2, PR #1439) ─────

// TestPeerFreshRT11_StaleAtAdmissionSpendsNoBudget is the defect proof for the admission-time
// freshness check.
//
// The boundary re-check makes the INVARIANT hold — nothing crosses on a lapsed observation — but
// it runs after the reservation, and the reservation spends from a MONOTONIC total that Release
// never refunds. So before the fix, a request whose observation was already stale when it arrived
// was admitted, charged a slot, and refused at the boundary having sent nothing. With the First
// Canary's tiny total, a handful of such requests stopped the experiment, and re-observing the
// peer afterwards could not buy the spent generation back.
//
// The budget here is ONE execution, which makes the defect binary: three stale requests arrive
// first, then the peer is re-observed. If any stale request was charged, the fresh one is refused
// for budget and never reaches the peer. It must reach it exactly once.
//
// The observation is aged, not the clock, so it is stale at BOTH the admission instant and the
// boundary — the precondition the admission check exists for. RT02 covers the other ordering.
func TestPeerFreshRT11_StaleAtAdmissionSpendsNoBudget(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	r := newPeerFreshRTRig(t, p, 1)

	r.obsNanos.Store(time.Unix(0, r.nowNanos.Load()).Add(-staleJump).UnixNano())
	before := mcpLiveGateDenialSnapshot()["peer_observation_not_fresh"]
	for i := range 3 {
		if crossed, reqs := r.run(t); crossed || reqs != 0 {
			t.Fatalf("stale request %d must not execute: crossed=%v reqs=%d", i, crossed, reqs)
		}
	}
	if got := mcpLiveGateDenialSnapshot()["peer_observation_not_fresh"] - before; got != 3 {
		t.Fatalf("each stale request must be refused as peer_observation_not_fresh (the boundary's own "+
			"reason, so both sites diagnose one fact identically); got %d of 3", got)
	}
	if got := r.reads.Load(); got != 0 {
		t.Fatalf("a request refused at admission must never reach the boundary re-check, which runs "+
			"only after a reservation; the boundary clock was read %d time(s)", got)
	}

	// The peer is observed again. The single budget slot must still be there to spend.
	r.obsNanos.Store(r.nowNanos.Load())
	crossed, reqs := r.run(t)
	if !crossed || reqs != 1 {
		t.Fatalf("SECURITY/AVAILABILITY: after stale requests, a fresh one must still execute on the "+
			"First Canary's only slot (crossed=%v reqs=%d). A stale request was charged budget it "+
			"could never spend.", crossed, reqs)
	}
}
