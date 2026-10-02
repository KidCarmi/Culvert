package main

import (
	"errors"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcp_canary_read_first_classification_test.go — the §10 deterministic matrix for EXACT
// READ-FIRST TOOL CLASSIFICATION (blocker #4).
//
// The fact under test, in one line:
//
//	a tools/call becomes OpRead if and only if the ACTIVE activation's immutable reviewed record
//	binds THIS exact (tenant, server, tool), at THIS exact fingerprint and fingerprint format,
//	under THIS exact pinned server identity, to a reviewed READ-ONLY class — and every other
//	state, without exception, stays OpWrite.
//
// Why the "if and only if" matters in both directions. The forward direction is the reason the
// blocker existed at all: runtime/policy.go defaults tools/call to OpWrite and the read-first gate
// admits only OpRead/OpDiscovery, so before this work NO exact tool invocation could cross the
// First-Canary boundary however carefully it had been reviewed. The reverse direction is the
// reason it is dangerous to close: every cheap way to make an invocation "read" — the server's own
// readOnlyHint, the tool's name, a permissive default, an inherited classification after the tool
// republished — hands the decision to something with no authority to make it.
//
// So the matrix is written so that the cheapest wrong implementations fail it. A classifier that
// always answered true would fail cases 2-4, 6, 7, 9 and 10; one that always answered false would
// fail case 1 and the positive controls, which is why those are MANDATORY rather than decorative.
//
// The cases, in the order the specification enumerates them:
//
//	 1  exact reviewed F1, reviewed class = read       → OpRead                (positive control)
//	 2  exact reviewed F1, NO reviewed class           → not classified, OpWrite
//	 3  the server says readOnlyHint, Culvert did not  → OpWrite
//	 4  reviewed F1 read, the tool is now F2           → not inherited, OpWrite
//	 5  reviewed F1 read, the APPROVAL has expired     → still bound to F1; authorization is
//	                                                     a separate gate and still refuses
//	 6  a tool nobody reviewed                         → never read
//	 7  the reviewed tool's server became unusable     → classification does not bypass it
//	 8  tools/list                                     → stays OpDiscovery, not "read via #4"
//	 9  a write-reviewed tool                          → stays write
//	10  an empty/unknown reviewed class                → fails closed at activation
//	11  restart                                        → the same classification is restored
//	12  a same-generation update                       → cannot mutate the classification

// readFirstRig is one armed activation over the REAL inventory, the REAL approval store and the
// REAL production classifier seam. Nothing here is a stub: every assertion below runs through
// canaryReadFirstClassifier, which reads the process-global activation and the published
// inventory exactly as a dispatched request would.
type readFirstRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
	sid  string
	tool string
	fp1  string
	gen  uint64
}

// newReadFirstRig seeds the controlled inventory, grants a real four-eyes live approval carrying
// the supplied reviewed determination, and arms an activation whose reviewed snapshot is derived
// from that grant the way production derives it (reviewedTargetsFromBindings).
func newReadFirstRig(t *testing.T, class tooltrust.ReviewedOperationClass) *readFirstRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	// Several cases here admit the reviewed request through the real gate, which now refuses a
	// target no peer has been seen advertising (round 13). Observed at the rig's admission
	// instant, before the grant pins the catalog revision.
	observeSeededToolTrustPeerAt(t, sid, canaryRuntimeTestNow)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	grant := requestLiveClassified(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour, class)
	approveLiveOrFail(t, grant)

	reviewed := observedReviewedTargetClassified(t, sid, tool, fpHex, reviewedClassOrFail(t, grant))
	gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{reviewed},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	return &readFirstRig{rt: rt, capb: capb, sid: sid, tool: tool, fp1: fpHex, gen: gen}
}

// approveLiveOrFail completes the four-eyes live approval for a pending grant.
func approveLiveOrFail(t *testing.T, req *tooltrust.ToolApproval) {
	t.Helper()
	if _, err := mcpToolTrust.ApproveLive(req.ApprovalID, liveApprover, ttTenant); err != nil {
		t.Fatalf("ApproveLive: %v", err)
	}
}

// classify asks the PRODUCTION seam the runtime is handed — not an inner helper — for the class of
// the rig's reviewed tool. Going through the seam is deliberate: it is the only surface the
// runtime can reach, so a test that called the inner resolver directly could pass while the seam
// itself was mis-bound (wrong capability, wrong argument order, not wired at all).
func (r *readFirstRig) classify() (policy.OperationClass, bool) {
	return canaryReadFirstClassifier(rollout.CapabilityGateway.String(), r.sid, r.tool)
}

// readFirst is the single boolean the runtime actually consumes.
func (r *readFirstRig) readFirst() bool {
	class, ok := r.classify()
	return ok && class == policy.OpRead
}

// ── 1 ────────────────────────────────────────────────────────────────────────────────────────
// §10.1 + the MANDATORY positive control. A reviewed target, still at its reviewed fingerprint,
// whose four-eyes review stated read-only, classifies as OpRead — and that class is one the
// read-first gate actually admits.
//
// Without this case every other case in the file would be satisfied by a classifier that returned
// (OpUnset, false) unconditionally, which is to say by deleting the feature. It is the only case
// here that can fail in the "too strict" direction, so it is the one that keeps the rest honest.
func TestReadFirstClass_C01_ExactReviewedReadOnlyToolClassifiesAsRead(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	class, ok := r.classify()
	if !ok {
		t.Fatal("the activation's reviewed record must be able to speak for its own reviewed target")
	}
	if class != policy.OpRead {
		t.Fatalf("a reviewed read-only target must classify as OpRead, got %v", class)
	}
	if !canary.IsReadFirstOperation(class) {
		t.Fatal("the classified class must be one the read-first gate admits, or blocker #4 is not closed")
	}
}

// ── 2 ────────────────────────────────────────────────────────────────────────────────────────
// §10.2. The exact reviewed fingerprint with NO reviewed class is not read. The point is where
// the refusal lands: an activation cannot even ARM carrying an unclassified target, so the
// unclassified state is not something a request can encounter at the gate. It is refused at the
// door, with its own named reason, which is strictly stronger than classifying it OpWrite later.
func TestReadFirstClass_C02_ReviewedTargetWithNoClassCannotArm(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	unclassified := observedReviewedTargetClassified(t, sid, tool, fpHex, policy.OpUnset)
	_, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{unclassified},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err == nil {
		t.Fatal("SECURITY: an activation carrying an unclassified reviewed target must not arm")
	}
	if !errors.Is(err, errCanaryReviewedTargetsInvalid) {
		t.Fatalf("the refusal must name the reviewed-set reason, got %v", err)
	}
	// And with nothing armed, nothing classifies — the fail-closed floor.
	if _, ok := canaryReadFirstClassifier(capb.String(), sid, tool); ok {
		t.Fatal("SECURITY: a refused activation must leave nothing classifiable")
	}
}

// ── 3 ────────────────────────────────────────────────────────────────────────────────────────
// §10.3. The server's own claim is not authority. This is asserted STRUCTURALLY rather than
// behaviourally, and the reason is worth stating: Culvert's MCP ingest carries no readOnlyHint
// field at all today, so there is no value a test could set to watch it be ignored. A behavioural
// test would therefore be vacuous — it would pass for the same reason an empty file passes.
//
// What can be proven, and is, is the shape that makes the hint unusable if it ever arrives: the
// classifier's entire input is (capability, serverID, toolName), so there is no parameter a hint
// could travel through, and the reviewed vocabulary in tooltrust has no hint-derived constructor.
// A future ingest change that wanted to honour a hint would have to widen that seam in a diff a
// reviewer sees, which is the property this case exists to lock down. The complete wall lives in
// TestReadFirstWall_ClassifierTakesNoServerSuppliedInput; this case pins the half that a reader
// of the matrix needs in front of them.
func TestReadFirstClass_C03_ServerHintIsNotAnInputToClassification(t *testing.T) {
	// The reviewed vocabulary is stated by a REVIEWER. Parsing is strict and total: nothing a
	// server could send parses into a determination, because the only accepted spellings are the
	// two Culvert's own review surface emits.
	for _, hint := range []string{"true", "readOnlyHint", "read-only", "readonly", "1", "yes", "READ_ONLY"} {
		if c, ok := tooltrust.ParseReviewedOperationClass(hint); ok {
			t.Fatalf("SECURITY: a server-shaped hint %q must not parse into a reviewed class, got %v", hint, c)
		}
	}
	// And an unstated determination maps to no policy class at all, so a missing review cannot
	// become a permissive one by falling through.
	if c, ok := canary.OperationClassFromReviewed(tooltrust.ReviewedOpUnset); ok || c != policy.OpUnset {
		t.Fatalf("SECURITY: an unstated reviewed class must map to nothing, got (%v, %v)", c, ok)
	}
}

// ── 4 ────────────────────────────────────────────────────────────────────────────────────────
// §10.4. THE HEADLINE CASE. A tool reviewed read-only at F1 republishes as F2. F2 inherits
// nothing: it is not "read-only until someone notices", it is unclassified, and unclassified is
// never read. A classifier keyed on (server, tool) rather than on the fingerprint would pass every
// other case in this file and fail only this one.
func TestReadFirstClass_C04_F2DoesNotInheritF1ReadClassification(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	if !r.readFirst() {
		t.Fatal("premise: the reviewed target must classify read-first before it moves")
	}
	fp2 := republishWithIdentity(t, r.sid, r.tool, "id", `{"type":"object","properties":{"moved":{"type":"string"}}}`)
	if fp2 == r.fp1 {
		t.Fatal("premise: the republished tool must carry a DIFFERENT fingerprint")
	}
	class, ok := r.classify()
	if ok {
		t.Fatalf("SECURITY: a moved fingerprint must carry NO reviewed classification, got %v", class)
	}
	if class == policy.OpRead {
		t.Fatal("SECURITY: F2 inherited F1's read-only classification")
	}
}

// ── 5 ────────────────────────────────────────────────────────────────────────────────────────
// §10.5. Classification and authorization are different questions with different lifetimes, and
// conflating them is what blocker #7 had to unpick. The activation's reviewed record is immutable
// and outlives the 24h approval TTL, so an expired approval does NOT silently un-classify the
// target — the record still says what it was reviewed as.
//
// That is safe only because authorization is enforced separately and still refuses, which this
// case proves in the same breath: the live-trust precheck reports the expired grant, so the
// admission gate denies regardless of how the class reads. A test that asserted only the first
// half would be describing a hole.
func TestReadFirstClass_C05_ExpiredApprovalLeavesClassificationBoundButUnauthorized(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	clk, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	grant := requestLiveClassified(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour, tooltrust.ReviewedOpReadOnly)
	approveLiveOrFail(t, grant)
	reviewed := observedReviewedTargetClassified(t, sid, tool, fpHex, policy.OpRead)
	if _, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget: runtimeTestBudget(20), ReviewedTargets: []canary.ReviewedTarget{reviewed}, StartedAt: canaryRuntimeTestNow,
	}); err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	if !canaryReadFirstClass(t, capb, sid, tool) {
		t.Fatal("premise: the reviewed read-only target must classify read-first while the grant is alive")
	}

	clk.advance(2 * time.Hour) // past the grant's expiry, well inside the activation window

	// The classification is bound to the FINGERPRINT, not to the grant, so it survives.
	if !canaryReadFirstClass(t, capb, sid, tool) {
		t.Fatal("the reviewed classification must outlive the approval it was derived from")
	}
	// Authorization does not. The live-trust probe reports the expired grant, and the gate denies.
	// The peer is seen at this instant so the refusal is the EXPIRED GRANT and nothing else — an
	// unobserved target is refused before the approval is consulted (round 13).
	observeSeededToolTrustPeerAt(t, sid, mcpToolTrust.now())
	g := realAdmissionGate(t, capb)
	d := g.AdmitSideEffect(driftGateInput(sid, tool, fpHex, mcpToolTrust.now()))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("SECURITY: an expired live approval must not admit a side effect, whatever the class says")
	}
}

// canaryReadFirstClass runs the production seam and reports whether it promotes to read-first.
func canaryReadFirstClass(t *testing.T, capb rollout.Capability, sid, tool string) bool {
	t.Helper()
	class, ok := canaryReadFirstClassifier(capb.String(), sid, tool)
	return ok && class == policy.OpRead
}

// ── 6 ────────────────────────────────────────────────────────────────────────────────────────
// §10.6. A tool this activation never reviewed is never read — including a tool that resolves
// perfectly well in the catalog. "Culvert can identify it" and "Culvert reviewed it" are different
// facts, and only the second one classifies.
func TestReadFirstClass_C06_UnreviewedToolIsNeverRead(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	if !r.readFirst() {
		t.Fatal("premise: the reviewed target must classify read-first")
	}
	// A name nothing in the inventory answers to.
	if class, ok := canaryReadFirstClassifier(rollout.CapabilityGateway.String(), r.sid, "never-reviewed"); ok {
		t.Fatalf("SECURITY: an unknown tool must carry no classification, got %v", class)
	}
	// And an unknown SERVER, which is the same fact one level up.
	if class, ok := canaryReadFirstClassifier(rollout.CapabilityGateway.String(), "never-reviewed-server", r.tool); ok {
		t.Fatalf("SECURITY: an unknown server must carry no classification, got %v", class)
	}
	// Empty identity is refused before anything is read, so a blank request cannot probe.
	if _, ok := canaryReadFirstClassifier(rollout.CapabilityGateway.String(), "", ""); ok {
		t.Fatal("SECURITY: an empty target must carry no classification")
	}
}

// ── 7 ────────────────────────────────────────────────────────────────────────────────────────
// §10.7. Classification never bypasses the catalog's own controls. When the reviewed server is
// disabled — the trust anchor the experiment was approved against is no longer in force — the
// target stops being one this node can speak for, so it stops being classified. The classifier
// declines FIRST rather than leaning on the policy engine's quarantine override to catch it
// afterwards, because a promotion that depends on a later gate to undo it is one refactor away
// from being wrong.
func TestReadFirstClass_C07_UnusableServerIsNotClassified(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	if !r.readFirst() {
		t.Fatal("premise: the reviewed target must classify read-first while its server is usable")
	}
	republishServerDisabled(t, r.sid, r.tool)
	if cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool); cur.Usable {
		t.Fatal("premise: the republished server must be unusable")
	}
	if class, ok := r.classify(); ok {
		t.Fatalf("SECURITY: an unusable reviewed server must carry no classification, got %v", class)
	}
}

// ── 8 ────────────────────────────────────────────────────────────────────────────────────────
// §10.8. Discovery stays discovery. tools/list is OpDiscovery and is NOT routed through the
// read-first classifier at all — blocker #4 is not closed by pretending a listing is an
// invocation. The proof is structural (the classification site is unreachable for tools/list) and
// lives in the runtime package; what is pinned here is the vocabulary half: a REVIEW can never
// bind OpDiscovery to a tool, so no reviewed record can make a tool call look like a listing.
func TestReadFirstClass_C08_DiscoveryIsNotAToolClassification(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	for _, class := range []policy.OperationClass{policy.OpDiscovery, policy.OpControl} {
		tgt := observedReviewedTargetClassified(t, sid, tool, fpHex, class)
		if _, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
			Budget: runtimeTestBudget(20), ReviewedTargets: []canary.ReviewedTarget{tgt}, StartedAt: canaryRuntimeTestNow,
		}); err == nil {
			t.Fatalf("SECURITY: a review must not be able to bind %v to a tool — it would pass the read-first gate", class)
		}
	}
	// IsReadFirstOperation admitting discovery is CORRECT for the protocol method and is exactly
	// why the vocabulary above must refuse it for a tool: the two facts meet at this predicate.
	if !canary.IsReadFirstOperation(policy.OpDiscovery) {
		t.Fatal("premise drifted: the read-first gate is expected to admit discovery for tools/list")
	}
}

// ── 9 ────────────────────────────────────────────────────────────────────────────────────────
// §10.9. A tool reviewed as MUTATING stays write, at its own reviewed fingerprint, with a live
// grant and an armed activation — every condition case 1 needs except the determination itself.
// It is the differential that isolates the reviewed class as the deciding input.
func TestReadFirstClass_C09_WriteReviewedToolStaysWrite(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpMutating)
	class, ok := r.classify()
	if !ok {
		t.Fatal("premise: the activation must still be able to speak for its own reviewed target")
	}
	if class != policy.OpWrite {
		t.Fatalf("a mutating-reviewed target must classify as OpWrite, got %v", class)
	}
	if canary.IsReadFirstOperation(class) {
		t.Fatal("SECURITY: a mutating-reviewed tool must not pass the read-first gate")
	}
}

// ── 10 ───────────────────────────────────────────────────────────────────────────────────────
// §10.10. The zero value fails closed at every layer that can see it, and each layer is checked
// separately because a single layer getting this right is how the other layers stop being
// checked. ReviewedOpUnset is not "stated", it maps to no policy class, and a reviewed set
// carrying OpUnset is refused by name.
func TestReadFirstClass_C10_EmptyClassFailsClosedAtEveryLayer(t *testing.T) {
	if tooltrust.ReviewedOpUnset.Stated() {
		t.Fatal("SECURITY: the zero reviewed class must not count as stated")
	}
	if tooltrust.ReviewedOpUnset.ReadOnly() {
		t.Fatal("SECURITY: the zero reviewed class must not read as read-only")
	}
	if _, ok := canary.OperationClassFromReviewed(tooltrust.ReviewedOpUnset); ok {
		t.Fatal("SECURITY: the zero reviewed class must map to no policy class")
	}
	// The zero ReviewedTargetSet — an activation that somehow armed with nothing reviewed —
	// classifies nothing, for any target at all.
	var empty canary.ReviewedTargetSet
	if class, ok := empty.OperationClassFor(canary.ReviewedTarget{Tenant: "t", ServerID: "s", ToolName: "n"}); ok {
		t.Fatalf("SECURITY: an empty reviewed set must classify nothing, got %v", class)
	}
	if empty.ReviewedReadFirst(canary.ReviewedTarget{Tenant: "t", ServerID: "s", ToolName: "n"}) {
		t.Fatal("SECURITY: an empty reviewed set must never report read-first")
	}
}

// ── 11 ───────────────────────────────────────────────────────────────────────────────────────
// §10.11. The classification is part of the DURABLE activation state, so a restart restores it
// rather than re-deriving it — which matters because the approval it came from may be long
// expired by then (case 5) and there would be nothing left to re-derive it from.
//
// The negative half is in the same test and is the more important one: a restart must not turn an
// unclassifiable state into a read one. The durable schema version was bumped for exactly this —
// a record written before the class existed decodes with OpUnset, and rather than arm with a
// target it cannot classify, the restore refuses the whole record.
func TestReadFirstClass_C11_RestartRestoresTheSameClassification(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	if !r.readFirst() {
		t.Fatal("premise: the reviewed target must classify read-first before the restart")
	}
	before, _ := r.classify()

	// Simulate the process restart: a fresh runtime over the SAME dataDir, restored from disk.
	globalCanaryRuntime = &canaryRuntime{}
	globalCanaryRuntime.restore()

	after, ok := canaryReadFirstClassifier(rollout.CapabilityGateway.String(), r.sid, r.tool)
	if !ok {
		t.Fatal("a restored activation must still be able to classify its own reviewed target")
	}
	if after != before {
		t.Fatalf("restart changed the classification: %v → %v", before, after)
	}
	if after != policy.OpRead {
		t.Fatalf("the restored classification must be the reviewed one, got %v", after)
	}
}

// ── 12 ───────────────────────────────────────────────────────────────────────────────────────
// §10.12. A same-generation control-plane update cannot change what generation G was reviewed as.
// The reviewed set is compared by VALUE and the operation class is part of that value, so an
// update that changes only the class — same tenant, same server, same tool, same fingerprint, same
// identity — is a DIFFERENT reviewed set and is refused, with the running generation left exactly
// as armed.
//
// Without this, the control plane could promote a reviewed-mutating tool to read-only without a
// review, which is the whole mechanism defeated by the one actor best placed to defeat it.
func TestReadFirstClass_C12_SameGenerationCannotMutateTheClassification(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	capb := rollout.CapabilityGateway
	budget := runtimeTestBudget(10)

	readTgt := reviewedAt(fpF1) // OpRead, from the shared fixture
	writeTgt := readTgt
	writeTgt.OperationClass = policy.OpWrite // the ONLY difference

	if _, err := globalCanaryRuntime.beginCanaryActivation(capb, canaryActivationSpec{
		Budget: budget, ReviewedTargets: []canary.ReviewedTarget{readTgt}, StartedAt: time.Unix(0, 1),
	}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	r := newTestRollout()
	st := r.gateway
	prevCfg := *gwCanaryCfg(1)
	if err := st.SetConfig(prevCfg, "prev", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("install prev canary: %v", err)
	}
	cfg := gwCanaryCfg(2)
	if err := st.SetConfig(*cfg, "new", time.Unix(0, 2).UnixNano()); err != nil {
		t.Fatalf("install new canary: %v", err)
	}
	tgt := commitTransitionTarget{
		st: st, persist: func(*rollout.State) error { return nil },
		setStatus: func(string) {}, countTransition: func() {}, reconcileRuntime: true,
	}
	err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(),
		canaryActivationSpec{Budget: budget, ReviewedTargets: []canary.ReviewedTarget{writeTgt}, StartedAt: time.Unix(0, 2)},
		"new", time.Unix(0, 2))
	if !errors.Is(err, errRolloutCanaryReviewedTargetsChanged) {
		t.Fatalf("a same-generation update that rebinds the reviewed CLASS must be refused, got %v", err)
	}
	set, ok := globalCanaryRuntime.activeReviewedTargets(capb)
	if !ok {
		t.Fatal("the running activation must still be armed after a refused update")
	}
	if !set.Equal(mustCanonical(t, readTgt)) {
		t.Fatal("SECURITY: the refused update mutated the active reviewed classification")
	}
}

// ── §9 ───────────────────────────────────────────────────────────────────────────────────────
// STALE DECISION. A request decided under F1 as OpRead must not reach upstream once the target has
// become F2 — and the new classifier must not have weakened that boundary.
//
// This is the case where the read-first promotion is most tempting to trust too far: the decision
// tuple says OpRead, the read-first gate admits OpRead, and the whole point of promoting was to let
// such a request through. If the promotion were the LAST word, a tool that republished between the
// decision and the boundary would be invoked under a classification that no longer describes it —
// which is to say, an unreviewed tool executed under a reviewed tool's authority.
//
// It does not, because classification and freshness are different gates and the freshness one is
// downstream. The gate below is driven with the decision's ORIGINAL F1 fingerprint, exactly as a
// request in flight would carry it, after the tool has moved to F2.
func TestReadFirstClass_StaleF1DecisionIsRefusedAfterF2(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	g := realAdmissionGate(t, r.capb)

	// PREMISE, and it has to be asserted or the test proves nothing: while the target is still F1,
	// the reviewed read-only tool classifies read-first AND the gate admits it. A gate that refused
	// everything would satisfy the assertion below for the wrong reason.
	if !r.readFirst() {
		t.Fatal("premise: the reviewed read-only target must classify read-first at F1")
	}
	d := g.AdmitSideEffect(driftGateInput(r.sid, r.tool, r.fp1, mcpToolTrust.now()))
	if d.Release != nil {
		d.Release()
	}
	if !d.Admit {
		t.Fatalf("premise: the exact reviewed request must be admitted at F1, reason=%s", d.Reason.Code())
	}

	// The tool republishes. The in-flight request still carries the F1 fingerprint its decision was
	// computed against.
	fp2 := republishWithIdentity(t, r.sid, r.tool, "id", `{"type":"object","properties":{"moved":{"type":"string"}}}`)
	if fp2 == r.fp1 {
		t.Fatal("premise: the republished tool must carry a DIFFERENT fingerprint")
	}

	stale := g.AdmitSideEffect(driftGateInput(r.sid, r.tool, r.fp1, mcpToolTrust.now()))
	if stale.Release != nil {
		stale.Release()
	}
	if stale.Admit {
		t.Fatal("SECURITY: a decision computed under F1 must not reach upstream once the target is F2 — " +
			"the read-first promotion is not the last word, the freshness boundary is")
	}
	// And the classification itself has already stopped speaking for the target, so even a request
	// re-decided against F2 would be OpWrite rather than inheriting the read-first promotion.
	if r.readFirst() {
		t.Fatal("SECURITY: the read-first classification survived the fingerprint move")
	}
}

// The read-first gate is a NECESSARY condition, not a sufficient one, and the two halves are
// pinned separately because a reader of this file has to be able to see that promoting a call to
// OpRead does not hand it an execution. A mutating-reviewed target — which the read-first gate
// refuses outright — and a read-reviewed target both still pass through trust revalidation,
// activation binding and budget reservation before anything is admitted.
func TestReadFirstClass_PromotionDoesNotBypassTheRemainingGates(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	g := realAdmissionGate(t, r.capb)

	// An admitted request is admitted against the reviewed target only. A DIFFERENT tool on the
	// same server — whatever its class would be — is out of the reviewed set and is refused.
	d := g.AdmitSideEffect(driftGateInput(r.sid, "never-reviewed", r.fp1, mcpToolTrust.now()))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("SECURITY: a read-first classification on one tool must not admit a different tool")
	}
}

// The classification and the gate MEET here, and this is the gate that makes blocker #4's closure
// non-vacuous in the direction that matters for blast radius: the class the classifier produces is
// the class the live side-effect gate consumes, and a write class is refused at it.
//
// Both directions are driven against the SAME armed activation and the SAME reviewed target, so
// the only difference between the two admissions is the operation class — which is what makes this
// a differential rather than two unrelated assertions.
func TestReadFirstClass_LiveGateAdmitsTheReadClassAndRefusesTheWriteClass(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	g := realAdmissionGate(t, r.capb)
	now := mcpToolTrust.now()

	readIn := driftGateInput(r.sid, r.tool, r.fp1, now)
	readIn.Operation = policy.OpRead
	d := g.AdmitSideEffect(readIn)
	if d.Release != nil {
		d.Release()
	}
	if !d.Admit {
		t.Fatalf("a reviewed read-only target carrying OpRead must be admitted, reason=%s", d.Reason.Code())
	}

	writeIn := driftGateInput(r.sid, r.tool, r.fp1, now)
	writeIn.Operation = policy.OpWrite
	w := g.AdmitSideEffect(writeIn)
	if w.Release != nil {
		w.Release()
	}
	if w.Admit {
		t.Fatal("SECURITY: an OpWrite operation must never cross the First-Canary read-first gate")
	}
	if w.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("the refusal must be the read-first gate's own bounded reason, got %s", w.Reason.Code())
	}
}

// ── §10.11 (durable half) ────────────────────────────────────────────────────────────────────
// A persisted ACTIVE record whose reviewed target carries NO operation class does not come back
// armed, and therefore classifies nothing.
//
// This is the restart case the matrix's C11 cannot reach from the arming path, because arming
// refuses an unclassified target outright (C02) — so the only way a process can meet one is by
// reading a record written before the field existed, or one that was tampered with. Both answer
// the same way: a record that cannot say from its own bytes what it was reviewed as does not
// restore execution authority. Fail-closed here costs one operator re-activation.
func TestReadFirstClass_DurableRecordWithoutAClassDoesNotRestoreArmed(t *testing.T) {
	r := newReadFirstRig(t, tooltrust.ReviewedOpReadOnly)
	if !r.readFirst() {
		t.Fatal("premise: the reviewed target must classify read-first before the record is damaged")
	}

	st := durableRecord(t, r.capb)
	if len(st.ReviewedTargets) == 0 {
		t.Fatal("premise: the durable record must carry the reviewed set")
	}
	if st.ReviewedTargets[0].OperationClass != policy.OpRead {
		t.Fatalf("premise: the persisted target must carry the reviewed class, got %v", st.ReviewedTargets[0].OperationClass)
	}
	// Exactly what a pre-field build's record decodes to: every other field intact, the class zero.
	for i := range st.ReviewedTargets {
		st.ReviewedTargets[i].OperationClass = policy.OpUnset
	}
	writeDurableRecord(t, r.capb, st)

	globalCanaryRuntime = &canaryRuntime{}
	globalCanaryRuntime.restore()

	if _, armed := globalCanaryRuntime.activeReviewedTargets(r.capb); armed {
		t.Fatal("SECURITY: a record that cannot state its reviewed class must not restore armed")
	}
	if class, ok := canaryReadFirstClassifier(r.capb.String(), r.sid, r.tool); ok {
		t.Fatalf("SECURITY: a disarmed runtime must classify nothing, got %v", class)
	}
}

// ── §3 (format half) ─────────────────────────────────────────────────────────────────────────
// The binding is to the fingerprint AND its FORMAT VERSION. Two digests are only comparable under
// one interpretation, so a target whose format moved is a target whose fingerprint has no agreed
// meaning — and an unagreed meaning is not a match, whatever the bytes look like.
//
// This is the one shape a digest-only classifier gets wrong while passing every other case here,
// which is why it has its own gate rather than riding on C04's schema change.
func TestReadFirstClass_FingerprintFormatIsPartOfTheBinding(t *testing.T) {
	reviewed := canary.ReviewedTarget{
		Tenant: "t1", ServerID: "srv", ToolName: "echo",
		Fingerprint: fpF1, FingerprintFormat: 1, ServerIdentity: "spiffe://test/srv",
		OperationClass: policy.OpRead,
	}
	set, reason := canary.CanonicalizeReviewedTargets([]canary.ReviewedTarget{reviewed})
	if reason != canary.ReviewedOK {
		t.Fatalf("fixture must canonicalize, got %s", reason)
	}
	// The CONTROL: at the reviewed format, the reviewed class is returned.
	if !set.ReviewedReadFirst(reviewed) {
		t.Fatal("premise: the exact reviewed target must classify read-first")
	}
	// The same digest under a DIFFERENT format version is not the reviewed target.
	moved := reviewed
	moved.FingerprintFormat = 2
	if class, ok := set.OperationClassFor(moved); ok {
		t.Fatalf("SECURITY: a changed fingerprint FORMAT must carry no reviewed class, got %v", class)
	}
	if set.ReviewedReadFirst(moved) {
		t.Fatal("SECURITY: a changed fingerprint format inherited the read-only classification")
	}
	// And a caller cannot supply its own class and have it honoured: the class is an OUTPUT of the
	// comparison, never an input to it.
	asserted := reviewed
	asserted.OperationClass = policy.OpWrite
	if class, ok := set.OperationClassFor(asserted); !ok || class != policy.OpRead {
		t.Fatalf("SECURITY: the caller's asserted class was consulted; got (%v, %v)", class, ok)
	}
}

// ── Codex P1 (PR #1370) ──────────────────────────────────────────────────────────────────────
// THE CLASSIFICATION MUST NOT OUTLIVE THE ACTIVATION THAT MADE IT.
//
// The operation class is decided once, at policy time, under whatever activation is armed at that
// instant — and the request that carries it is charged, at the boundary, to whatever activation is
// armed THEN. Those need not be the same one, and the gap is the whole finding:
//
//	G1 armed, tool X at F1 reviewed READ-ONLY   → a request is decided OpRead
//	the request pauses (credential path, durable commit, scheduler stall)
//	G1 demoted; G2 armed for the SAME tool at the SAME fingerprint, reviewed MUTATING
//	the request resumes → gate 2 reads OpRead off its own decision and lets it through;
//	                      the target identity still matches, so nothing drifts;
//	                      the reservation is charged to G2
//
// Nothing about the TARGET moved, so every drift control stays silent — correctly. What moved is
// the review OF it, which is exactly the case where a correction most needs to take effect: a
// reviewer looked again and said this tool mutates.
//
// The test drives the real gate through the real activations. The "pause" needs no goroutine: the
// class is a value the request carries, so re-admitting the SAME decided class after the swap is
// the identical state, and a deterministic test is worth more than a raced one.
func TestReadFirstClass_StaleReadClassIsRefusedAfterAReviewSaysMutating(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	// The premise admits under G1, so the peer must have been seen (round 13).
	observeSeededToolTrustPeerAt(t, sid, canaryRuntimeTestNow)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLiveClassified(t, sid, tool, fpHex, cat.Current().Revision(), tooltrust.ReviewedOpReadOnly)

	readTarget := observedReviewedTargetClassified(t, sid, tool, fpHex, policy.OpRead)
	g1, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget: runtimeTestBudget(20), ReviewedTargets: []canary.ReviewedTarget{readTarget}, StartedAt: canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("arm G1: %v", err)
	}
	g := realAdmissionGate(t, capb)
	in := driftGateInput(sid, tool, fpHex, mcpToolTrust.now())
	in.Operation = policy.OpRead

	// PREMISE: under G1 the read-first decision is admitted. Without this the refusal below could
	// be anything at all.
	d := g.AdmitSideEffect(in)
	if d.Release != nil {
		d.Release()
	}
	if !d.Admit {
		t.Fatalf("premise: a read-reviewed target must be admitted under G1, reason=%s", d.Reason.Code())
	}

	// The review is corrected: same tenant, same server, same tool, same fingerprint, same pinned
	// identity — only the reviewed class changes. A same-generation rebind is refused (C12), so the
	// correction lands the way it must: demote, then arm a new generation.
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote G1: %v", err)
	}
	writeTarget := readTarget
	writeTarget.OperationClass = policy.OpWrite
	g2, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget: runtimeTestBudget(20), ReviewedTargets: []canary.ReviewedTarget{writeTarget}, StartedAt: canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("arm G2: %v", err)
	}
	if g2 == g1 {
		t.Fatalf("premise: the corrected review must be a NEW generation, still %d", g1)
	}

	// PREMISE, and it is the reason this test is not simply re-proving drift detection: NOTHING
	// about the target moved. The classifier still resolves it, and the only thing that changed is
	// what the activation says about it.
	if class, ok := canaryReadFirstClassifier(capb.String(), sid, tool); !ok || class != policy.OpWrite {
		t.Fatalf("premise: G2 must bind this exact target to OpWrite, got (%v, %v)", class, ok)
	}

	// THE GATE. The stale OpRead decision must not cross, and the refusal must be the read-first
	// gate's own reason rather than a drift or a budget denial — from the caller's side this
	// operation is simply not read-first here.
	stale := g.AdmitSideEffect(in)
	if stale.Release != nil {
		stale.Release()
	}
	if stale.Admit {
		t.Fatal("SECURITY: a read-first classification decided under G1 crossed the boundary under " +
			"G2, whose review states the tool MUTATES — the classification outlived the authority " +
			"that made it")
	}
	if stale.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("the refusal must be the read-first gate's bounded reason, got %s", stale.Reason.Code())
	}
	// And it is REQUEST-SCOPED: the target did not move, so the experiment must not be stopped.
	if rt.abortedNow(capb) {
		t.Fatal("SECURITY: a corrected review is not a breach of the target — nothing may latch")
	}
}
