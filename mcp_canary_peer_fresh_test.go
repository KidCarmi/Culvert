package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// The peer-freshness matrix rows that need REAL state (blocker #11, §16).
//
// The pure rows — every binding and clock case — live in internal/mcp/canary/peerfresh_test.go.
// These are the ones a pure verdict cannot express, because what is being tested is how the
// catalog, the discovery path and the passage of time actually interact: a rediscovery that
// refreshes, a reseed that does not, a failed refresh that changes nothing, a stalled discovery
// whose evidence is real but already expired, and a restart that returns every record to
// unobserved.
//
// They run against the production resolver (canaryExactRequestFacts), not a hand-built input, so
// what they pin is the path an activation preflight actually takes.

// peerFreshRig is the permit rig plus the scripted peer its refresh dials.
type peerFreshRig struct {
	permitRig
	peer *refreshPeer
	// clock is the OBSERVATION clock, distinct from the rig's evaluation clock so a test can
	// stamp an observation at one instant and evaluate freshness at another without sleeping.
	clock *time.Time
}

// newPeerFreshRig builds the seeded F1 stack and points the refresh engine at a peer that
// advertises exactly the seeded tool, so a refresh produces a real observation of F1 without
// moving the fingerprint.
func newPeerFreshRig(t *testing.T) *peerFreshRig {
	t.Helper()
	r := newCredRig(t, "")
	clock := r.now
	peer := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`}
	useRefreshPeer(t, peer)
	prev := mcpPeerRefreshNow
	mcpPeerRefreshNow = func() time.Time { return clock }
	t.Cleanup(func() { mcpPeerRefreshNow = prev })
	return &peerFreshRig{permitRig: r, peer: peer, clock: &clock}
}

// observe runs one authenticated refresh through the production engine.
func (r *peerFreshRig) observe(t *testing.T) {
	t.Helper()
	if _, reason, err := mcpRefreshPeerObservation(context.Background(), r.serverID); reason != "" || err != nil {
		t.Fatalf("refresh must succeed: reason=%q err=%v", reason, err)
	}
}

// freshnessAt resolves the production freshness fact at an explicit evaluation instant.
func (r *peerFreshRig) freshnessAt(t *testing.T, at time.Time) (bool, canary.PeerFreshReason) {
	t.Helper()
	f := canaryExactRequestFacts(r.scope(), r.reviewedReadOnly(t), at)
	return f.PeerObservedFresh, f.PeerObservedFreshReason
}

// record returns the live catalog record for the rig's exact tool.
func (r *peerFreshRig) record(t *testing.T) catalog.ToolRecord {
	t.Helper()
	_, cat := mcpInventory.sharedInventory()
	if cat == nil {
		t.Fatal("the inventory must be published")
	}
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(r.serverID), Name: r.toolName})
	if !ok {
		t.Fatal("the rig's tool must exist")
	}
	return rec
}

// ── the shipped default, and why ToolFingerprintCurrent cannot stand in for it ──────────────

// TestPeerFreshProd_SeedOnlyIsUnmetEvenThoughTheFingerprintIsCurrent is the row the whole blocker
// turns on.
//
// The seeded record's digest matches the reviewed target EXACTLY — that is what
// ToolFingerprintCurrent asks, and it is true and will stay true forever, because nothing ever
// re-observed the peer. The freshness row is the only one that can tell that state apart from a
// target the upstream actually advertises.
func TestPeerFreshProd_SeedOnlyIsUnmetEvenThoughTheFingerprintIsCurrent(t *testing.T) {
	r := newPeerFreshRig(t)

	rec := r.record(t)
	if rec.Provenance() != catalog.OperatorSeeded {
		t.Fatalf("premise: provisioning must produce a seeded record, got %v", rec.Provenance())
	}
	// The reviewed digest and the current record agree — the "fingerprint current" property.
	reviewed := r.reviewedReadOnly(t)
	if len(reviewed) != 1 {
		t.Fatalf("premise: exactly one reviewed target, got %d", len(reviewed))
	}
	cur := exactPermitCurrentTarget(registry.ServerRecord{}, rec, r.toolName)
	if reviewed[0].Fingerprint != cur.Fingerprint || reviewed[0].FingerprintFormat != cur.FingerprintFormat {
		t.Fatal("premise: the reviewed digest must match the catalog record, or this proves nothing " +
			"about the difference between 'fingerprint current' and 'peer observed'")
	}

	fresh, reason := r.freshnessAt(t, r.now)
	if fresh {
		t.Fatal("an operator-seeded record must NEVER satisfy peer freshness")
	}
	if reason != canary.PeerFreshMissing {
		t.Fatalf("the reason must name the missing observation, got %q", reason)
	}
}

// TestPeerFreshProd_FingerprintCurrentDoesNotImplyFresh states the same thing at the readiness
// table, where an operator reads it: a Facts set that is true everywhere EXCEPT the new row must
// still refuse, and must refuse naming this row.
func TestPeerFreshProd_FingerprintCurrentDoesNotImplyFresh(t *testing.T) {
	f := credAllTrueFacts()
	f.ToolFingerprintCurrent = true
	f.FirstCanaryPeerObservedFresh = false
	v := canary.Evaluate(f)
	if v.Ready {
		t.Fatal("Ready:true must be impossible without peer-observed freshness")
	}
	if len(v.Unmet) != 1 || v.Unmet[0] != canary.ReasonPeerObservationNotFresh {
		t.Fatalf("must be unmet for exactly peer_observation_not_fresh, got %v", v.Unmet)
	}
}

// ── the positive control ────────────────────────────────────────────────────────────────────

// TestPeerFreshProd_AuthenticatedObservationIsMet is the positive control for every negative row
// in this file. Without it, a resolver that answered "not fresh" to everything would satisfy them
// all while making the First Canary impossible.
func TestPeerFreshProd_AuthenticatedObservationIsMet(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)

	rec := r.record(t)
	if rec.Provenance() != catalog.PeerObserved {
		t.Fatalf("premise: the refresh must have produced an observation, got %v", rec.Provenance())
	}
	fresh, reason := r.freshnessAt(t, r.now)
	if !fresh {
		t.Fatalf("an exact authenticated observation must be MET, got %q", reason)
	}
}

// ── rediscovery refreshes, reseed does not ──────────────────────────────────────────────────

// TestPeerFreshProd_RediscoveryRestoresFreshness pins that a peer answering again is a new
// sighting: an observation that has aged past the bound becomes fresh again when the same
// unchanged peer is re-observed.
func TestPeerFreshProd_RediscoveryRestoresFreshness(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)
	first := r.record(t).Observed.At

	// Evaluate well past the bound: stale.
	late := r.now.Add(canary.FirstCanaryPeerObservationMaxAge + time.Minute)
	if fresh, reason := r.freshnessAt(t, late); fresh || reason != canary.PeerFreshStale {
		t.Fatalf("premise: the observation must have aged out, got fresh=%v reason=%q", fresh, reason)
	}

	// The peer answers again, at the later instant.
	*r.clock = late
	mcpPeerRefreshNow = func() time.Time { return late }
	r.observe(t)

	second := r.record(t).Observed.At
	if !second.After(first) {
		t.Fatalf("rediscovery must advance the observation: %v -> %v", first, second)
	}
	if fresh, reason := r.freshnessAt(t, late); !fresh {
		t.Fatalf("after rediscovery the row must be MET again, got %q", reason)
	}
}

// TestPeerFreshProd_ByteIdenticalReseedRemovesFreshness is the anti-renewal rule at the
// production layer, driven through the IN-PLACE seeded entrypoint on the live catalog — the one
// shape where a "nothing changed, keep what we had" implementation would be tempting, because a
// prior record exists and its fingerprint is about to be re-derived identically.
//
// An operator re-running provisioning is not a sighting of the peer. If a byte-identical reseed
// preserved the observation, an operator could keep a long-dead peer's freshness alive forever
// without that peer answering once — the evidence would then be about the operator, not the peer.
func TestPeerFreshProd_ByteIdenticalReseedRemovesFreshness(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)
	if fresh, reason := r.freshnessAt(t, r.now); !fresh {
		t.Fatalf("premise: the observation must be fresh first, got %q", reason)
	}
	before := r.record(t)

	// Re-seed the SAME tool bytes into the SAME live catalog through the OPERATOR entrypoint.
	reg, cat := mcpInventory.sharedInventory()
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: registry.ServerID(r.serverID),
		Identity: before.Observed.Identity,
		Raw:      []byte(`{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`),
	}); err != nil {
		t.Fatalf("operator reseed: %v", err)
	}

	after := r.record(t)
	if !after.Fingerprint.Equal(before.Fingerprint) {
		t.Fatal("premise: the reseed must not move the fingerprint, or this proves something else — " +
			"the whole point is that the RECORD is identical and the PROVENANCE is not")
	}
	if after.Provenance() != catalog.OperatorSeeded {
		t.Fatalf("a reseed must downgrade the record to seeded, got %v", after.Provenance())
	}
	fresh, reason := r.freshnessAt(t, r.now)
	if fresh {
		t.Fatal("a byte-identical operator reseed must NOT preserve peer freshness")
	}
	if reason != canary.PeerFreshMissing {
		t.Fatalf("after a reseed the record carries no observation at all, got %q", reason)
	}
}

// ── failure and stalls ──────────────────────────────────────────────────────────────────────

// TestPeerFreshProd_FailedRefreshLeavesTheObservationAndLetsItAge is §14 seen through the
// freshness row: a failed refresh must not fabricate "unchanged", must not erase what was known,
// and must not stop the clock. The evidence stays exactly as it was and expires on its own.
func TestPeerFreshProd_FailedRefreshLeavesTheObservationAndLetsItAge(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)
	before := r.record(t).Observed

	// The peer stops answering.
	r.peer.mu.Lock()
	r.peer.err = mcperr.New(mcperr.ReasonUpstreamTimeout, "test", "unreachable")
	r.peer.mu.Unlock()
	if _, reason, _ := mcpRefreshPeerObservation(context.Background(), r.serverID); reason == "" {
		t.Fatal("premise: the refresh must have failed")
	}

	after := r.record(t).Observed
	if !after.At.Equal(before.At) || after.Identity != before.Identity {
		t.Fatalf("a failed refresh must leave the observation untouched: %+v -> %+v", before, after)
	}
	// Still fresh right now...
	if fresh, reason := r.freshnessAt(t, r.now); !fresh {
		t.Fatalf("the surviving observation must still be usable, got %q", reason)
	}
	// ...and it ages out on its own clock, because failing to reach a peer is not evidence that
	// the peer is unchanged.
	late := r.now.Add(canary.FirstCanaryPeerObservationMaxAge + time.Nanosecond)
	if fresh, reason := r.freshnessAt(t, late); fresh || reason != canary.PeerFreshStale {
		t.Fatalf("the observation must expire normally, got fresh=%v reason=%q", fresh, reason)
	}
}

// TestPeerFreshProd_StalledDiscoveryCannotManufactureFreshness is §8's sharp test, and it is the
// behavioural catch for "improve accuracy by stamping response completion time".
//
// The timestamp is minted BEFORE the call. Here the call then stalls past the whole freshness
// bound before succeeding. The resulting record carries a REAL, well-formed observation — the
// peer genuinely answered, and genuinely advertised this tool — and it is nevertheless stale the
// instant it lands, because what it attests is when the question was asked.
//
// Stamping on response completion would make this case fresh, which is exactly the property that
// must not exist: a peer that hangs for an hour and then answers would mint a brand-new window of
// authority for a statement about an hour ago. No sleeps — the peer advances the clock itself.
func TestPeerFreshProd_StalledDiscoveryCannotManufactureFreshness(t *testing.T) {
	r := newPeerFreshRig(t)
	start := r.now
	// The stall: the peer advances the observation clock while the call is in flight, so the
	// response completes long after the stamp was taken.
	landed := start.Add(canary.FirstCanaryPeerObservationMaxAge + time.Minute)
	stalling := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`}
	prevUp := mcpPeerRefreshUpstream
	mcpPeerRefreshUpstream = func() (execution.UpstreamCaller, error) {
		return &clockAdvancingPeer{inner: stalling, advance: func() { *r.clock = landed }}, nil
	}
	t.Cleanup(func() { mcpPeerRefreshUpstream = prevUp })

	r.observe(t)

	rec := r.record(t)
	if rec.Provenance() != catalog.PeerObserved {
		t.Fatal("the discovery SUCCEEDED, so a real observation must have been recorded")
	}
	if !rec.Observed.At.Equal(start) {
		t.Fatalf("the observation must be stamped when the question was ASKED (%v), not when the "+
			"answer arrived (%v); got %v", start, landed, rec.Observed.At)
	}
	// Evaluated at the instant the response actually landed, the brand-new record is already
	// stale.
	fresh, reason := r.freshnessAt(t, landed)
	if fresh {
		t.Fatal("a peer that stalls past the freshness bound and then answers must NOT mint a new " +
			"window of authority for a statement about the past")
	}
	if reason != canary.PeerFreshStale {
		t.Fatalf("expected the observation to be stale, got %q", reason)
	}
}

// ── restart ─────────────────────────────────────────────────────────────────────────────────

// TestPeerFreshProd_RestartReturnsEveryRecordToUnobserved pins the accepted restart semantics.
//
// The catalog is not durable, so a restart rebuilds it from the operator inventory and every
// record comes back seeded. That is DESIRABLE, not a gap: the alternative is persisting evidence
// about a third party across a process that was not running to see it, and a restart must never
// be able to move an observation forward. Re-observation is required, and the row says so.
func TestPeerFreshProd_RestartReturnsEveryRecordToUnobserved(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)
	if fresh, reason := r.freshnessAt(t, r.now); !fresh {
		t.Fatalf("premise: the observation must be fresh before the restart, got %q", reason)
	}

	// Restart: the inventory is re-seeded from the operator's file exactly as boot does.
	seedCredentialInventory(t, "")

	rec := r.record(t)
	if rec.Provenance() != catalog.OperatorSeeded || rec.Observed.Present() {
		t.Fatalf("a rebuilt catalog must carry no observation, got %v %+v", rec.Provenance(), rec.Observed)
	}
	fresh, reason := r.freshnessAt(t, r.now)
	if fresh {
		t.Fatal("a restart must not preserve peer freshness")
	}
	if reason != canary.PeerFreshMissing {
		t.Fatalf("after a restart the row must report the missing observation, got %q", reason)
	}
}

// ── F1 -> F2 ────────────────────────────────────────────────────────────────────────────────

// TestPeerFreshProd_FreshF2NeverMakesAnF1ActivationFresh is §11's mandatory sequence, and the
// property it pins is the one a server-scoped implementation would get wrong.
//
// Freshness belongs to an EXACT OBSERVED TARGET, not to a server. After the peer moves to F2 and
// is observed there, the catalog is perfectly fresh — and an activation still reviewed against F1
// must be UNMET, because nothing has observed F1 since it stopped being what the peer offers.
func TestPeerFreshProd_FreshF2NeverMakesAnF1ActivationFresh(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)
	reviewedF1 := r.reviewedReadOnly(t)
	if fresh, reason := r.freshnessAt(t, r.now); !fresh {
		t.Fatalf("premise: F1 must be observed and fresh, got %q", reason)
	}

	// The peer now advertises F2, and is authentically observed there.
	r.peer.mu.Lock()
	r.peer.result = `{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}`
	r.peer.mu.Unlock()
	r.observe(t)

	rec := r.record(t)
	if rec.Provenance() != catalog.PeerObserved || !rec.Observed.Present() {
		t.Fatal("premise: F2 must carry its own observation")
	}

	// The catalog's CURRENT target is fresh. The F1 activation is not.
	f := canaryExactRequestFacts(r.scope(), reviewedF1, r.now)
	if f.PeerObservedFresh {
		t.Fatal("a fresh observation of F2 must NEVER make an activation reviewed against F1 fresh")
	}
	if f.PeerObservedFreshReason != canary.PeerFreshTargetMoved {
		t.Fatalf("the reason must say the target moved, not that it is stale: got %q",
			f.PeerObservedFreshReason)
	}
}

// TestPeerFreshProd_AReviewedSetForAnotherToolIsNotAReviewedTarget closes the case the mutation
// campaign found the matrix could not see (M13).
//
// exactReviewedTargetFor picks the candidate reviewed target for THIS exact (server, tool) out of
// the set the activation would bind, and returns the ZERO target on a miss — which cannot equal
// any real current target, so the verdict reports the target moved. The tempting "simplification"
// is to fall back to whatever the set does contain when there is exactly one entry.
//
// None of the earlier rows exercised a miss at all: every one supplies a reviewed set that
// already contains the right tool. This row drives the miss through the production resolver.
//
// It does NOT by itself kill that mutation, and saying so is the point. The verdict independently
// compares Reviewed against Current on server and tool, so a fallback target still fails there and
// still reports TargetMoved — the fallback is rejected TWICE. The helper's own contract is pinned
// separately by TestExactReviewedTargetFor_MissReturnsTheZeroTarget, which is what actually
// distinguishes the two implementations. Both gates are kept: one says what the resolver does,
// the other says what the helper promises, and the redundancy between them is defence in depth
// rather than duplication.
func TestPeerFreshProd_AReviewedSetForAnotherToolIsNotAReviewedTarget(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)
	if fresh, reason := r.freshnessAt(t, r.now); !fresh {
		t.Fatalf("premise: the exact target must be observed and fresh, got %q", reason)
	}

	// The activation reviewed some OTHER tool. Nothing was reviewed for the tool the scope names.
	elsewhere := r.reviewedReadOnly(t)
	if len(elsewhere) != 1 {
		t.Fatalf("premise: exactly one reviewed target, got %d", len(elsewhere))
	}
	elsewhere[0].ToolName = "some-other-tool"

	f := canaryExactRequestFacts(r.scope(), elsewhere, r.now)
	if f.PeerObservedFresh {
		t.Fatal("an activation that reviewed a DIFFERENT tool has no reviewed target for this " +
			"observation to back; inventing one from the current state would make the binding " +
			"assert only that the catalog agrees with itself")
	}
	if f.PeerObservedFreshReason != canary.PeerFreshTargetMoved {
		t.Fatalf("a missing reviewed target must report that the target moved, got %q",
			f.PeerObservedFreshReason)
	}
}

// ── no authority widening ───────────────────────────────────────────────────────────────────

// TestPeerFreshProd_FreshnessConfersNoAuthority pins that a fresh observation is only truth.
//
// It must not promote, approve, make the record Usable, change rollout mode or arm anything. The
// check is on OBSERVABLE state before and after a refresh, because the claim is about what the
// refresh did, not about what its code mentions — the reach walls already cover that.
func TestPeerFreshProd_FreshnessConfersNoAuthority(t *testing.T) {
	r := newPeerFreshRig(t)
	modeBefore := getMCPRollout().gateway.CurrentConfig().Mode
	eligBefore := r.eligibility(t)

	r.observe(t)

	if fresh, reason := r.freshnessAt(t, r.now); !fresh {
		t.Fatalf("premise: the observation must have landed, got %q", reason)
	}
	if got := getMCPRollout().gateway.CurrentConfig().Mode; got != modeBefore {
		t.Fatalf("a refresh must not change rollout mode: %v -> %v", modeBefore, got)
	}
	if got := r.eligibility(t); got != eligBefore {
		t.Fatalf("a refresh must not change catalog eligibility by itself: %v -> %v", eligBefore, got)
	}
	// And the readiness verdict is still governed by every other prerequisite: freshness alone
	// does not make an activation ready.
	f := credAllTrueFacts()
	f.LiveApprovalValid = false
	f.FirstCanaryPeerObservedFresh = true
	if canary.Evaluate(f).Ready {
		t.Fatal("peer freshness must not substitute for any other prerequisite")
	}
}

// ── one clock sample ────────────────────────────────────────────────────────────────────────

// TestPeerFreshProd_OneClockSamplePerEvaluation pins §10's semantic rule.
//
// The resolver takes `now` as a parameter and must not sample a clock of its own: two facts in
// one readiness evaluation that straddled two instants could each be true about a different
// moment. The First Canary has one exact tool today, so the rule is not yet observable through
// disagreement between tools — which is precisely why it is pinned now, while it is cheap.
func TestPeerFreshProd_OneClockSamplePerEvaluation(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)

	// The same capture, evaluated at two instants either side of the bound, must answer
	// differently — proving the verdict is a function of the instant it is HANDED, not of a
	// clock it reads.
	early := r.now
	late := r.now.Add(canary.FirstCanaryPeerObservationMaxAge + time.Nanosecond)
	if fresh, _ := r.freshnessAt(t, early); !fresh {
		t.Fatal("premise: fresh at the early instant")
	}
	if fresh, reason := r.freshnessAt(t, late); fresh {
		t.Fatalf("the verdict must follow the instant it is handed, got fresh with reason %q", reason)
	}
	// And it is deterministic at a fixed instant: two evaluations at the same `now` agree.
	a, ra := r.freshnessAt(t, early)
	b, rb := r.freshnessAt(t, early)
	if a != b || ra != rb {
		t.Fatalf("the verdict must be a pure function of its inputs: (%v,%q) vs (%v,%q)", a, ra, b, rb)
	}
}

// clockAdvancingPeer expresses a STALL without a sleep: it moves the observation clock forward
// while the inner call is notionally in flight, so the response completes at a strictly later
// instant than the one the stamp was taken at. The delegation is total — the peer still answers
// normally, because the point of the test is a SUCCESSFUL discovery whose evidence is already
// expired, not a failed one.
type clockAdvancingPeer struct {
	inner   execution.UpstreamCaller
	advance func()
}

func (p *clockAdvancingPeer) Call(ctx context.Context, tgt upstreamclient.Target, method string,
	params json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	p.advance()
	return p.inner.Call(ctx, tgt, method, params, opts)
}

// TestExactReviewedTargetFor_MissReturnsTheZeroTarget pins the helper's own contract.
//
// It exists because the mutation campaign showed the verdict is OVER-DETERMINED here: a fallback
// to "whatever the reviewed set contains" is rejected a second time by the Reviewed-vs-Current
// comparison, so no end-to-end row can tell the two apart. That redundancy is deliberate and
// worth keeping — but it also means the helper could be changed to something unsound without a
// single behavioural test moving, until some later change removed the second rejection.
//
// So the contract is asserted where it is made: a miss yields the ZERO target, which cannot equal
// any real current target.
func TestExactReviewedTargetFor_MissReturnsTheZeroTarget(t *testing.T) {
	reviewed := []canary.ReviewedTarget{{
		Tenant: "tenant-a", ServerID: "controlled", ToolName: "other", Fingerprint: fpOne(),
	}}
	if got := exactReviewedTargetFor(reviewed, "controlled", "t"); got != (canary.ReviewedTarget{}) {
		t.Fatalf("a miss must yield the zero target, not a substitute from the set: %+v", got)
	}
	// The positive control: a hit still returns the exact entry, or this gate would be satisfied
	// by a helper that returned the zero target unconditionally — which would make every
	// activation report TargetMoved and the First Canary impossible.
	hit := []canary.ReviewedTarget{
		{Tenant: "tenant-a", ServerID: "controlled", ToolName: "other"},
		{Tenant: "tenant-a", ServerID: "controlled", ToolName: "t", Fingerprint: fpOne()},
	}
	got := exactReviewedTargetFor(hit, "controlled", "t")
	if got.ToolName != "t" || got.Fingerprint != fpOne() {
		t.Fatalf("an exact hit must return that entry, got %+v", got)
	}
}

// fpOne is an arbitrary non-zero digest; only its distinctness matters here.
func fpOne() tooltrust.FingerprintDigest { return tooltrust.FingerprintDigest{7, 7, 7} }

// TestPeerFreshProd_TheProductionPrecheckCarriesTheEvidence closes a gap the runtime mutation
// campaign found (RM13).
//
// Every runtime matrix case replaces g.trustPrecheck with a stub, so none of them exercises
// mcpLiveTrustPrecheck — the production wiring that lifts the peer observation and the registry
// pin out of the ONE loadTarget snapshot and hands them to the boundary. Zeroing that carrying
// left all nine runtime cases green: the check still ran, on evidence that was always empty,
// which would refuse every request in production while the suite reported a working feature.
//
// So the wiring is asserted where it is done, against a REAL observed record.
func TestPeerFreshProd_TheProductionPrecheckCarriesTheEvidence(t *testing.T) {
	r := newPeerFreshRig(t)
	r.observe(t)

	rec := r.record(t)
	if rec.Provenance() != catalog.PeerObserved {
		t.Fatalf("premise: the refresh must have produced an observation, got %v", rec.Provenance())
	}

	live := mcpLiveTrustPrecheck(ttTenant, r.serverID, r.toolName, r.fpHex)
	if !live.Eligible {
		t.Fatalf("premise: the observed target must be eligible, got %+v", live)
	}
	if live.Observed.At.IsZero() || live.Observed.Identity == "" {
		t.Fatalf("the production precheck must carry the catalog record's peer observation to the "+
			"boundary; got %+v. Without it the send-boundary check runs on evidence that is "+
			"always empty — refusing every request in production while every runtime test that "+
			"stubs the precheck stays green.", live.Observed)
	}
	if live.Observed.Identity != string(rec.Observed.Identity) || !live.Observed.At.Equal(rec.Observed.At) {
		t.Fatalf("the carried evidence must be the RECORD's, not a value assembled on the way: "+
			"carried %+v, record %+v", live.Observed, rec.Observed)
	}
	if live.RegistryPin == "" {
		t.Fatal("the registry's current pin must be carried too: the verdict requires the observed " +
			"identity to match BOTH it and the catalog record's identity, and an empty pin would " +
			"make that second comparison vacuous")
	}
}
