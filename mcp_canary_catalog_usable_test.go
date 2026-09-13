package main

import (
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// ---------------------------------------------------------------------------
// BLOCKER #13 — governed catalog usability is a First-Canary activation fact.
//
// The defect: the readiness table asserted the server was usable, the fingerprint
// current and a live approval valid, but nothing asserted the exact scoped tool had
// reached catalog.Usable through the governed promotion lifecycle. Usability is
// enforced by the POLICY ENGINE — a Quarantined tool is hard-overridden to
// ActionQuarantine before any operator ALLOW rule is consulted — so a node could
// report Ready:true for an experiment in which every single request dies at that
// override.
//
// These gates drive the REAL catalog and the REAL governed shadow_evaluation
// promotion lifecycle. Nothing here promotes by hand: every Usable state in this
// file was produced by requestAndApprove, which is the production path.
// ---------------------------------------------------------------------------

// usableRig is the one-server/one-tool fixture these gates share.
type usableRig struct {
	cat      *catalog.Catalog
	serverID string
	toolName string
	fpHex    string
	// now is the injected coordinator clock. It is a pointer so a test can advance time
	// across a grant's expiry WITHOUT triggering the periodic reconcile — which is the
	// exact window the expiry gate below exercises.
	now *atomic.Int64
}

func newUsableRig(t *testing.T) usableRig {
	t.Helper()
	// The published inventory is a PROCESS GLOBAL with no owner-scoped teardown, so seeding one
	// leaks a healthy registry+catalog into every later test in the package. That is not
	// hypothetical: TestCanaryMatrix_DormantNodeRejections asserts a dormant node reports
	// registry_unhealthy AND catalog_unhealthy, and it silently loses both when it happens to run
	// after a seeding test — a failure whose appearance depends only on -run filtering and
	// -shuffle ordering. This file restores what it found.
	restoreMCPInventory(t)
	now := &atomic.Int64{}
	now.Store(1_700_000_000)
	composeToolTrust(t, func() time.Time { return time.Unix(now.Load(), 0) })
	_, cat, serverID, toolName, fpHex := seedToolTrustInventory(t)
	return usableRig{cat: cat, serverID: serverID, toolName: toolName, fpHex: fpHex, now: now}
}

// advance moves the injected coordinator clock forward. It deliberately does NOT reconcile:
// the point of the gate that uses it is that a caller must not depend on the periodic tick
// having run.
func (r usableRig) advance(d time.Duration) { r.now.Add(int64(d / time.Second)) }

// restoreMCPInventory snapshots the published inventory and re-publishes it verbatim when the
// test ends, so a seeding test is hermetic with respect to the package's process globals.
func restoreMCPInventory(t *testing.T) {
	t.Helper()
	mcpInventory.mu.RLock()
	state, reason, reg, cat := mcpInventory.state, mcpInventory.reason, mcpInventory.reg, mcpInventory.cat
	mcpInventory.mu.RUnlock()
	t.Cleanup(func() { publishMCPInventory(state, reason, reg, cat) })
}

// scope returns the exact First-Canary scope over this rig's tool, pinned to fpHex
// unless an override pin is supplied.
func (r usableRig) scope(pin ...string) rollout.ScopeSpec {
	fp := r.fpHex
	if len(pin) == 1 {
		fp = pin[0]
	}
	return rollout.ScopeSpec{
		Tenants:    []string{ttTenant},
		Servers:    []string{r.serverID},
		Tools:      []rollout.ToolSel{{Server: r.serverID, Name: r.toolName, Fingerprint: fp}},
		Principals: []string{"agent-1"},
	}
}

func (r usableRig) eligibility(t *testing.T) catalog.Eligibility {
	t.Helper()
	return eligibility(t, r.cat, r.serverID, r.toolName)
}

// republishAsF2 re-ingests the same server with a CHANGED tool schema, so the tool's
// composite fingerprint moves F1 -> F2 through the real ingestion path (which applies
// the sticky Quarantined floor). It returns the new fingerprint hex.
func (r usableRig) republishAsF2(t *testing.T) string {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":{"type":"object","properties":{"extra":{"type":"string"}}}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode F2 inventory: %v", err)
	}
	reg2, cat2, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed F2 inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg2, cat2)
	rec, ok := cat2.Current().Get(catalog.ToolKey{Server: registry.ServerID(r.serverID), Name: r.toolName})
	if !ok {
		t.Fatal("F2 tool must exist")
	}
	sum := rec.Fingerprint.Sum()
	fp2 := hex.EncodeToString(sum[:])
	if fp2 == r.fpHex {
		t.Fatal("premise: the republish must actually move the fingerprint, or case 6 proves nothing")
	}
	return fp2
}

// catalogRev returns the tool's per-record catalog revision (the optimistic-concurrency
// token requestAndApprove needs).
func (r usableRig) catalogRev(t *testing.T) uint64 {
	t.Helper()
	ti := mcpToolTrust.loadTarget(r.serverID, r.toolName)
	if !ti.found {
		t.Fatal("target must resolve")
	}
	return ti.target.CatalogRevision
}

// ── 1. seeded tool → Quarantined ─────────────────────────────────────────────

func TestCatalogUsable_SeededToolIsQuarantinedAndNotUsable(t *testing.T) {
	r := newUsableRig(t)
	if got := r.eligibility(t); got != catalog.Quarantined {
		t.Fatalf("a freshly seeded tool must be Quarantined, got %v", got)
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("a Quarantined tool must not satisfy the catalog-usability activation fact")
	}
}

// ── 2. a live approval ALONE never promotes ──────────────────────────────────
//
// The separation this gate defends is deliberate and load-bearing: catalog.Usable
// means "this exact tool passed the governed trust lifecycle"; a live_execution
// approval means "this reviewed target is authorized for live side effects". Neither
// implies the other, and a live grant must never manufacture the first.

func TestCatalogUsable_LiveApprovalAloneNeverPromotes(t *testing.T) {
	r := newUsableRig(t)
	requestAndApproveLive(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t))
	if got := r.eligibility(t); got != catalog.Quarantined {
		t.Fatalf("SECURITY: a live_execution approval must not promote the catalog, eligibility=%v", got)
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("SECURITY: a live approval alone must not satisfy the catalog-usability fact")
	}
}

// ── 3. the governed shadow approval promotes (MANDATORY POSITIVE CONTROL) ────
//
// Without this, every negative gate here would also pass an implementation that
// refuses everything — which would make the First Canary unreachable rather than
// governed.

func TestCatalogUsable_ExactShadowApprovalPromotes(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("CONTROL: an exact governed shadow approval must promote to Usable, got %v", got)
	}
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: a governed-promoted exact tool must satisfy the catalog-usability fact")
	}
}

// ── 4. shadow + live are two INDEPENDENT true facts ──────────────────────────

func TestCatalogUsable_ShadowAndLiveAreIndependentFacts(t *testing.T) {
	r := newUsableRig(t)
	rev := r.catalogRev(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, rev, time.Hour)
	requestAndApproveLive(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t))

	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("the shadow promotion must still hold with a live approval also present")
	}
	if len(buildLiveApprovalBindings(r.scope())) == 0 {
		t.Fatal("the live approval must still bind with a shadow promotion also present")
	}
}

// ── 5. a shadow approval for the WRONG fingerprint does not promote ──────────

func TestCatalogUsable_WrongFingerprintApprovalDoesNotPromote(t *testing.T) {
	r := newUsableRig(t)
	wrong := strings.Repeat("ab", 32)
	in := toolTrustRequestInput{
		Tenant: ttTenant, ServerID: r.serverID, ToolName: r.toolName,
		ExpectedFingerprint: wrong, ExpectedCatalogRev: r.catalogRev(t),
		Purpose: tooltrust.PurposeShadowEvaluation, RequestedBy: "operator@corp", Reason: "wrong fp",
	}
	if _, err := mcpToolTrust.RequestApproval(in); err == nil {
		t.Fatal("a request pinned to a fingerprint the tool does not carry must be refused")
	}
	if got := r.eligibility(t); got != catalog.Quarantined {
		t.Fatalf("a refused request must leave the tool Quarantined, got %v", got)
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("a wrong-fingerprint approval must not satisfy the usability fact")
	}
}

// ── 6. F2 does NOT inherit F1's usability ────────────────────────────────────

func TestCatalogUsable_F2DoesNotInheritF1Usability(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: F1 must be Usable first, got %v", got)
	}
	fp2 := r.republishAsF2(t)
	r.cat = mustSharedCatalog(t)

	if got := r.eligibility(t); got == catalog.Usable {
		t.Fatal("SECURITY: a republished tool must not stay Usable by inheritance")
	}
	if canaryScopedToolsCatalogUsable(r.scope(fp2)) {
		t.Fatal("SECURITY: F2 must not satisfy the usability fact on F1's promotion")
	}
}

// ── 7. a FRESH governed promotion of F2 makes F2 usable ──────────────────────

func TestCatalogUsable_FreshF2PromotionRestoresUsability(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	fp2 := r.republishAsF2(t)
	r.cat = mustSharedCatalog(t)

	requestAndApprove(t, r.serverID, r.toolName, fp2, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("CONTROL: a fresh governed promotion of F2 must make F2 Usable, got %v", got)
	}
	if !canaryScopedToolsCatalogUsable(r.scope(fp2)) {
		t.Fatal("CONTROL: F2 must satisfy the usability fact after its own governed promotion")
	}
}

// ── 7b. a USABLE record does not satisfy a scope pinned elsewhere ────────────
//
// Case 6 proves F2 does not inherit F1's usability, but it proves it through the
// STICKY QUARANTINED FLOOR: F2's record is not Usable, so the eligibility check alone
// would catch it. This gate isolates the OTHER half — a genuinely Usable record whose
// digest is not the one the activation pinned — so removing the digest comparison from
// the resolver cannot hide behind the eligibility check.

func TestCatalogUsable_UsableRecordDoesNotSatisfyAScopePinnedElsewhere(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: the record must be genuinely Usable, got %v", got)
	}
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: the pin that MATCHES must satisfy the fact, or this gate proves nothing")
	}
	other := strings.Repeat("cd", 32)
	if other == r.fpHex {
		t.Fatal("fixture: the mismatched pin must differ from the record's digest")
	}
	if canaryScopedToolsCatalogUsable(r.scope(other)) {
		t.Fatal("SECURITY: a Usable record must not satisfy a scope pinned to a different fingerprint")
	}
}

// ── 7c. the FORMAT is bound because it is folded into the digest ─────────────
//
// The resolver binds the format without a second comparison, because the digest it
// compares is itself format-bound: Fingerprint.Sum writes FormatVersion before any
// other segment. This gate pins that property directly, so a future change to Sum that
// stopped folding the version in would fail HERE — where the reason is stated — rather
// than silently unbinding format at every call site that relies on it.

func TestCatalogUsable_FingerprintFormatIsFoldedIntoTheBoundDigest(t *testing.T) {
	base := catalog.Fingerprint{
		Server: "controlled", Identity: "id", Name: "t", FormatVersion: 1,
	}
	other := base
	other.FormatVersion = 2
	if base.Sum() == other.Sum() {
		t.Fatal("SECURITY: two capabilities identical except for fingerprint FORMAT must not " +
			"share a digest — the activation's format binding rests entirely on this property")
	}
}

// ── 7d. a tenant that does not own the server never satisfies the fact ───────
//
// Tenant ownership is resolved from the REGISTRY, not from the catalog record, so a
// scope that names some other tenant resolves to no usable target however Usable the
// record is.

func TestCatalogUsable_TenantThatDoesNotOwnTheServerIsNotUsable(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: the owning tenant must satisfy the fact, or this gate proves nothing")
	}
	foreign := r.scope()
	foreign.Tenants = []string{"tenant-that-owns-nothing"}
	if canaryScopedToolsCatalogUsable(foreign) {
		t.Fatal("SECURITY: a tenant that does not own the server must not satisfy the fact")
	}
}

// ── 7e. an EMPTY scope is not vacuously usable ───────────────────────────────
//
// "every tool the scope admits is Usable" is vacuously TRUE for a scope that admits no
// tool. That is the shape in which a fact about an experiment's target is satisfied by
// an experiment with no target, so the resolver refuses an empty scope explicitly
// rather than letting the loop fall through.

func TestCatalogUsable_EmptyScopeIsNotVacuouslyUsable(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: the populated scope must satisfy the fact, or this gate proves nothing")
	}
	noTools := r.scope()
	noTools.Tools = nil
	if canaryScopedToolsCatalogUsable(noTools) {
		t.Fatal("SECURITY: a scope that admits no tool must not satisfy a fact about its tools")
	}
	noTenants := r.scope()
	noTenants.Tenants = nil
	if canaryScopedToolsCatalogUsable(noTenants) {
		t.Fatal("SECURITY: a scope that names no tenant must not satisfy the fact")
	}
}

// ── 7f. an unpublished inventory fails CLOSED ────────────────────────────────
//
// The condition under which nothing whatsoever is known about the tool is exactly the
// condition under which the fact must not be claimed.

func TestCatalogUsable_AbsentInventoryFailsClosed(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: a published inventory must satisfy the fact, or this gate proves nothing")
	}
	scope := r.scope()
	// newUsableRig already restores whatever inventory this test found, so withdrawing here
	// cannot leak past the test.
	publishMCPInventory(mcpInvNotConfigured, "test: inventory withdrawn", nil, nil)
	if canaryScopedToolsCatalogUsable(scope) {
		t.Fatal("SECURITY: with no published inventory the fact must fail closed")
	}
}

// ── 8. a usable, live-approved F2 does NOT revive an F1-reviewed activation ──
//
// Blocker #7's immutable reviewed snapshot is not weakened by anything here: a new
// catalog record and a new approval are LIVE state, and an activation that reviewed
// F1 must still refuse F2. F2 requires a new activation generation.

func TestCatalogUsable_UsableF2StillRefusedByAnF1ReviewedActivation(t *testing.T) {
	r := newUsableRig(t)
	reviewedF1 := canary.ReviewedTarget{
		Tenant: ttTenant, ServerID: r.serverID, ToolName: r.toolName,
		Fingerprint: mustDigest(t, r.fpHex), FingerprintFormat: 1,
		ServerIdentity: "id", OperationClass: policy.OpRead,
	}
	fp2 := r.republishAsF2(t)
	r.cat = mustSharedCatalog(t)
	requestAndApprove(t, r.serverID, r.toolName, fp2, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: F2 must be genuinely Usable for this gate to mean anything, got %v", got)
	}

	currentF2 := canary.ReviewedTarget{
		Tenant: ttTenant, ServerID: r.serverID, ToolName: r.toolName,
		Fingerprint: mustDigest(t, fp2), FingerprintFormat: 1,
		ServerIdentity: "id", OperationClass: policy.OpRead,
	}
	if mustCanonical(t, reviewedF1).Compare(currentF2) == canary.ReviewedMatches {
		t.Fatal("SECURITY: an activation that reviewed F1 must not match a current F2, " +
			"however usable and however freshly approved F2 is")
	}
}

// ── 9. revoking the LAST valid promotion demotes ─────────────────────────────

func TestCatalogUsable_RevokingLastPromotionDemotes(t *testing.T) {
	r := newUsableRig(t)
	a := requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("premise: the tool must be usable before revocation")
	}
	if _, err := mcpToolTrust.Revoke(a.ApprovalID, "admin@corp", ttTenant, "withdrawn"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := r.eligibility(t); got == catalog.Usable {
		t.Fatal("revoking the last valid promotion must demote the tool")
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("a revoked promotion must not keep satisfying the usability fact")
	}
}

// ── 10. revoking ONE of several valid promotions does not demote ─────────────

func TestCatalogUsable_RevokingOneOfTwoPromotionsStaysUsable(t *testing.T) {
	r := newUsableRig(t)
	a1 := requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	// The first promotion advances the record's catalog revision, so the second review
	// must be taken against the CURRENT one — a stale token is refused by design.
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), 2*time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("premise: two valid promotions must leave the tool usable")
	}
	if _, err := mcpToolTrust.Revoke(a1.ApprovalID, "admin@corp", ttTenant, "one of two"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("CONTROL: another valid promotion still qualifies — the tool must stay Usable, got %v", got)
	}
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: the usability fact must survive while any valid promotion remains")
	}
}

// ── 10b. an EXPIRED promotion does not survive to the next reconcile tick ────
//
// Codex P2 on PR #1378, and a real gap in this file's own §7 coverage: case 9 proved a
// REVOKED promotion demotes, but revoke calls into the coordinator and demotes inline,
// whereas EXPIRY is passive. A grant past its `ExpiresAt` leaves the catalog record
// `Usable` until `reconcile()` materializes the expiry, and that runs on a 30-second
// tick. Read the catalog directly in that window and an already-expired promotion
// answers "usable" — the fail-OPEN direction, on trust that has lapsed.
//
// `shadowScopeHasUsableTool` already solved this for the Shadow preflight by reconciling
// before it reads, on the rule ADR-0034 D7 states: reconcile never widens usability, it
// only withdraws expired trust and re-affirms exact-match active trust. This gate holds
// the activation resolver to the same rule, and does it WITHOUT calling reconcile itself
// — so it fails against a resolver that leans on the periodic tick.

func TestCatalogUsable_ExpiredPromotionIsNotUsableBeforeTheReconcileTick(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: an unexpired promotion must satisfy the fact, or this gate proves nothing")
	}

	// Cross the grant's expiry. Nothing reconciles: the periodic tick has not run, which is
	// precisely the window a caller must not be able to read through.
	r.advance(2 * time.Hour)

	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("SECURITY: an EXPIRED promotion must not satisfy the activation fact just " +
			"because the periodic reconcile has not run yet — the resolver must reconcile " +
			"before it reads, exactly as shadowScopeHasUsableTool does")
	}
}

// ── 10c. reconciling to read never WIDENS usability ──────────────────────────
//
// The control for the gate above. Reconciling before the read is only safe because it is
// one-directional: it withdraws lapsed trust and re-affirms exact-match active trust, and
// can never turn a tool that was not usable into one that is. A resolver that reconciled
// itself into a promotion would be a promotion path on the activation read path — the
// thing §8 and the structural wall exist to forbid.

func TestCatalogUsable_ReconcilingToReadNeverPromotes(t *testing.T) {
	r := newUsableRig(t)
	if got := r.eligibility(t); got != catalog.Quarantined {
		t.Fatalf("premise: the seeded tool must be Quarantined, got %v", got)
	}
	for i := 0; i < 3; i++ {
		if canaryScopedToolsCatalogUsable(r.scope()) {
			t.Fatal("SECURITY: reading the fact must never promote — no number of reads may " +
				"turn a Quarantined tool into a Usable one")
		}
	}
	if got := r.eligibility(t); got != catalog.Quarantined {
		t.Fatalf("SECURITY: the tool must still be Quarantined after repeated reads, got %v", got)
	}
}

// ── 11. a restart does not resurrect stale usability ─────────────────────────
//
// Usability is a PROJECTION of the durable tool-trust store, so recovery must
// re-derive it from the authoritative trust state rather than restore a remembered
// catalog verdict. A revoked grant must stay demoted across the reconcile that a
// restart performs.

func TestCatalogUsable_RestartDoesNotResurrectStaleUsability(t *testing.T) {
	r := newUsableRig(t)
	a := requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if _, err := mcpToolTrust.Revoke(a.ApprovalID, "admin@corp", ttTenant, "withdrawn"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// The reconcile a restart runs re-derives every tool's eligibility from the store.
	mcpToolTrust.reconcile()
	if got := r.eligibility(t); got == catalog.Usable {
		t.Fatal("SECURITY: a restart reconcile must not resurrect usability for a revoked promotion")
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("SECURITY: stale usability must not survive the restart reconcile")
	}
}

// ── 12. the data plane cannot promote (STRUCTURAL, anti-vacuous) ─────────────
//
// The wall is by CALLER, not by call shape: it asserts that catalog.Promote is
// reachable from the governed trust coordinator and from nowhere else in the root
// package — and, critically, that the legitimate governed path IS still visible to
// the test. A wall that merely found zero callers would pass just as happily if the
// promotion lifecycle had been deleted, which is the vacuous form this avoids.

func TestCatalogUsable_OnlyTheGovernedCoordinatorPromotes(t *testing.T) {
	owners := catalogPromotionOwners(t)
	// ANTI-VACUITY: the governed lifecycle must still be visible, or this wall proves nothing.
	governed, ok := owners["mcp_tooltrust.go"]
	if !ok || len(governed) == 0 {
		t.Fatal("ANTI-VACUOUS: the governed promotion lifecycle must be visible in mcp_tooltrust.go — " +
			"a wall that finds no promotion at all would pass even if promotion had been deleted")
	}
	// Every promoter must live in the trust coordinator, never in a request/data-plane file.
	for file, fns := range owners {
		if file != "mcp_tooltrust.go" {
			t.Fatalf("SECURITY: catalog promotion/demotion reached from %s (%v) — promotion is "+
				"control-plane governance only; a Gateway request must never make a tool Usable",
				file, fns)
		}
	}
}

// catalogPromotionOwners maps each non-test root-package file to the functions in it that
// call a catalog Promote/Demote, by AST. Split out from the wall above so the wall reads as
// its two assertions — the governed path is visible, and nothing else promotes — rather than
// as a parse loop with a verdict at the bottom.
func catalogPromotionOwners(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob root package: %v (%d files)", err, len(files))
	}
	owners := map[string][]string{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, f, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", f, perr)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "Promote" || sel.Sel.Name == "Demote" {
					owners[f] = append(owners[f], fn.Name.Name)
				}
				return true
			})
		}
	}
	return owners
}

// ── the resolver reads each source exactly once ──────────────────────────────
//
// Codex P2 round 2, PR #1378, and a correction to a claim made earlier in this PR.
//
// The resolver must decide from ONE catalog snapshot and ONE registry snapshot. The
// earlier shape took a catalog snapshot and then resolved tenant ownership through
// mcpToolTrust.loadTarget, which re-reads BOTH current snapshots — so a republish landing
// between the two reads let an old Usable F1 record satisfy eligibility and the F1-pinned
// digest while ownership came from the newer snapshot, and the resolver answered "usable"
// for a target the current catalog had already re-quarantined at F2.
//
// THE CLAIM THIS CORRECTS. An earlier commit deleted a cross-check between those two
// resolutions on the reasoning that "both sides come from the same catalog, so no test
// could ever distinguish the check from its absence." Same catalog, DIFFERENT READS: the
// check was the snapshot-consistency guard, and the reasoning that removed it was wrong.
//
// The fix removes the second read rather than re-adding a guard over it, because a
// cross-check can only DETECT an inconsistency that one read cannot produce. This gate is
// therefore structural — it pins the property the fix rests on. A behavioural test cannot
// reach it without a seam that interposes a republish mid-scan, and adding a production
// seam whose only purpose is to let a test drive a race is a worse trade than asserting
// the shape directly.

func TestCatalogUsable_ResolverReadsEachSnapshotExactlyOnce(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mcp_canary_preflight.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp_canary_preflight.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "canaryScopedToolsCatalogUsable" {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("wall is vacuous: canaryScopedToolsCatalogUsable not found (it was renamed or moved)")
	}

	counts := map[string]int{}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Current":
			if id, ok := sel.X.(*ast.Ident); ok {
				counts[id.Name+".Current"]++
			}
		case "loadTarget":
			// loadTarget re-reads BOTH current snapshots internally, so one call reintroduces
			// the whole defect however the surrounding reads are counted.
			counts["loadTarget"]++
		}
		return true
	})

	if n := counts["loadTarget"]; n != 0 {
		t.Fatalf("SECURITY: the resolver calls loadTarget %d time(s) — loadTarget re-reads "+
			"cat.Current() AND reg.Current(), so the decision would again straddle two "+
			"snapshots and a mid-scan republish could pair an old Usable record with new "+
			"ownership", n)
	}
	if n := counts["cat.Current"]; n != 1 {
		t.Fatalf("SECURITY: the resolver reads cat.Current() %d time(s), want exactly 1 — "+
			"every check must be derived from ONE catalog snapshot", n)
	}
	if n := counts["reg.Current"]; n != 1 {
		t.Fatalf("SECURITY: the resolver reads reg.Current() %d time(s), want exactly 1 — "+
			"every check must be derived from ONE registry snapshot", n)
	}
}

// ── the production preflight itself carries the row ──────────────────────────
//
// Every gate above drives the resolver directly. This one drives the whole production
// path — productionCanaryActivationInputs -> evaluateCanaryActivationPreflight -> the
// readiness table — so a mutation anywhere along it (a probe that stops resolving the
// fact, a wiring step that drops it, a table row that disappears) is caught here rather
// than only in the pure canary package.
//
// It asserts MEMBERSHIP of the reason, never Ready:true: a stock node leaves several
// other rows unmet by design and this PR does not change that.

func TestCatalogUsable_ProductionPreflightCarriesTheRow(t *testing.T) {
	r := newUsableRig(t)
	in := CanaryActivationInput{
		Capability: rollout.CapabilityGateway, Scope: r.scope(), ScopeRev: 1,
		Now: time.Unix(1_700_000_000, 0),
	}
	ai := productionCanaryActivationInputs(in.Capability, in.Scope, in.ScopeRev)
	in.ToolApprovals, in.Budget = ai.ToolApprovals, ai.Budget
	in.ServerUsable, in.FingerprintCurrent = ai.ServerUsable, ai.FingerprintCurrent
	in.ToolCatalogUsable = ai.ToolCatalogUsable

	before := evaluateCanaryActivationPreflight(in)
	if !hasReason(before, canary.ReasonToolNotCatalogUsable) {
		t.Fatalf("a Quarantined scoped tool must make the activation report %s, got %v",
			canary.ReasonToolNotCatalogUsable, before.Unmet)
	}

	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	ai2 := productionCanaryActivationInputs(in.Capability, in.Scope, in.ScopeRev)
	in.ToolCatalogUsable = ai2.ToolCatalogUsable
	after := evaluateCanaryActivationPreflight(in)
	if hasReason(after, canary.ReasonToolNotCatalogUsable) {
		t.Fatalf("CONTROL: after the governed promotion this row must be MET, got %v", after.Unmet)
	}
}

// ── every activation-input field reaches every preflight call site ───────────
//
// The production path resolves activation facts ONCE, into canaryActivationInputs, and
// then spreads them by hand into a CanaryActivationInput at each preflight call site —
// the transition commit and the restart reconcile. A hand-spread struct is exactly the
// shape in which one field is silently dropped at one site, and a behavioural test
// cannot reach either site in this build: the live tier is never armed, so the commit
// refuses at an earlier gate and the mutation stays invisible.
//
// So the gate is STRUCTURAL. Every field of canaryActivationInputs must be forwarded at
// every literal built from a probe result, by AST, and the wall names the sites it found
// so a preflight call site added without a forwarding pass fails here rather than
// shipping an activation that decides on a fact it never received.
//
// It is deliberately wider than blocker #13: dropping ANY activation fact at a commit
// site is the same defect, and a wall scoped to one field would be re-derived — and
// re-missed — the next time a fact is added.

func TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall(t *testing.T) {
	fset := token.NewFileSet()

	// The fields the probe resolves, taken from the type rather than a hand-written list,
	// so a new activation fact is covered the moment it exists.
	want := parseStructFields(t, fset, "mcp_canary_preflight.go", "canaryActivationInputs")
	if len(want) < 2 {
		t.Fatalf("wall is vacuous: canaryActivationInputs must have fields, found %v", want)
	}
	if !slices.Contains(want, "ToolCatalogUsable") {
		t.Fatal("wall is looking at the wrong type: ToolCatalogUsable must be an activation input")
	}

	file, err := parser.ParseFile(fset, "mcp_rollout.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp_rollout.go: %v", err)
	}
	sites := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "CanaryActivationInput" {
			return true
		}
		sites++
		set := map[string]bool{}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok {
				set[k.Name] = true
			}
		}
		for _, f := range want {
			if !set[f] {
				t.Errorf("mcp_rollout.go:%d builds a CanaryActivationInput that never sets %s — "+
					"the probe resolves that activation fact and this call site throws it away, so "+
					"the preflight decides without it", fset.Position(lit.Pos()).Line, f)
			}
		}
		return true
	})
	// Anti-vacuity: the wall must have found the real call sites. Today there are two —
	// the transition commit and the restart reconcile.
	if sites < 2 {
		t.Fatalf("wall is vacuous: expected at least 2 CanaryActivationInput literals in "+
			"mcp_rollout.go, found %d (the selector has drifted)", sites)
	}
}

// parseStructFields returns the exported field names of the named struct in the given
// root-package file.
func parseStructFields(t *testing.T, fset *token.FileSet, filename, typeName string) []string {
	t.Helper()
	file, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != typeName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, f := range st.Fields.List {
			for _, nm := range f.Names {
				if nm.IsExported() {
					out = append(out, nm.Name)
				}
			}
		}
		return false
	})
	return out
}

// ── TOCTOU: usability withdrawn after a Ready preflight ──────────────────────
//
// A preflight verdict is a statement about the instant it was taken. If the governed
// promotion is withdrawn afterwards, the runtime must still refuse — and it does so
// through the EXISTING policy hard-override, not through a second catalog authority
// invented for the purpose. The point of this control is that closing blocker #13 did
// not move enforcement out of the policy engine.

func TestCatalogUsable_WithdrawnAfterPreflightStillHardQuarantines(t *testing.T) {
	r := newUsableRig(t)
	a := requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("premise: the preflight fact must hold before the withdrawal")
	}

	// The withdrawal lands after that verdict was taken.
	if _, err := mcpToolTrust.Revoke(a.ApprovalID, "admin@corp", ttTenant, "withdrawn mid-experiment"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("the fact must be re-observed, never cached from the earlier Ready verdict")
	}

	// The runtime consequence: the policy engine hard-quarantines, so no request can
	// reach an upstream regardless of what the earlier preflight said.
	dec := policyQuarantineDecisionFor(t, catalogDispositionNow(t, r))
	if dec.Action != policy.ActionQuarantine {
		t.Fatalf("SECURITY: a withdrawn promotion must still hard-quarantine at runtime, got %v", dec.Action)
	}
}

// ── policy E2E: quarantine override stops firing after governed promotion ────
//
// This is the proof that blocker #13 MATTERS. Same policy, same rule, same request:
// the only thing that changes is the governed catalog disposition.
//
// It deliberately stops at "ordinary policy evaluation became reachable". Whether an
// operator ALLOW rule then matches is blocker #14 and is NOT closed here.

func TestCatalogUsable_PolicyQuarantineOverrideClearsAfterGovernedPromotion(t *testing.T) {
	r := newUsableRig(t)

	before := policyQuarantineDecisionFor(t, catalogDispositionNow(t, r))
	if before.Action != policy.ActionQuarantine {
		t.Fatalf("premise: a Quarantined tool must be hard-overridden to QUARANTINE, got %v", before.Action)
	}

	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: the governed promotion must have landed, got %v", got)
	}

	after := policyQuarantineDecisionFor(t, catalogDispositionNow(t, r))
	if after.Action == policy.ActionQuarantine && after.Reason == policy.ReasonToolUnknown {
		t.Fatal("after a governed promotion the catalog-quarantine hard override must no longer fire — " +
			"the request must reach ordinary policy evaluation (whether a rule then ALLOWS it is blocker #14)")
	}
}

// policyQuarantineDecisionFor evaluates the REAL policy engine over one fixed Gateway
// tuple whose ONLY variable is the catalog disposition, so the E2E above changes exactly
// one thing between its two evaluations. The rule set deliberately contains an ALLOW that
// would match — the point is not that it fires (that is blocker #14) but that the
// catalog-quarantine HARD OVERRIDE stops pre-empting ordinary evaluation.
func policyQuarantineDecisionFor(t *testing.T, disp policy.Disposition) policy.Decision {
	t.Helper()
	doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY",` +
		`"rules":[{"id":"ALLOW_READ_T","priority":1,"action":"ALLOW",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"t"}],` +
		`"obligations":{"logging":"standard"}}]}`
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	in := policy.DecisionInput{
		Capability: policy.CapGateway, PolicyRevision: 1, CatalogRevision: 7,
		RegistryRevision: 3, RuntimeRevision: 1, EvalTime: time.Unix(1_700_000_000, 0).UTC(),
		Principal: policy.Principal{Kind: policy.SubjectHuman, SubjectID: "agent-1", Tenant: "tenant-a",
			Groups: []string{"developers"}, Assurance: policy.AssuranceHigh, Issuer: "https://idp"},
		Client: policy.Client{ClientID: "client-g", Tenant: "tenant-a",
			Capability: policy.CapGateway, Trust: policy.TrustHigh},
		Server: &policy.Server{ServerID: "srv-1", Owner: "tenant-a", Environment: "prod",
			Enabled: true, Verification: policy.ServerVerified},
		Tool: &policy.Tool{Name: "t", ServerID: "srv-1", FingerprintHash: "abc123",
			Disposition: disp, Drift: policy.DriftNoMaterialChange,
			Destination:     policy.DestinationApproved,
			CredentialPower: policy.PowerReadOnly, Reversibility: policy.Reversible},
		Operation: policy.Operation{Method: "tools/call", Class: policy.OpRead,
			Namespace: policy.NamespaceGatewayTool, Operand: "t", DecisionPoint: "policy_engine"},
	}
	eng := policy.NewEngine(policy.DefaultLimits())
	dec, _, err := eng.Evaluate(snap, &in)
	if err != nil {
		t.Fatalf("policy Evaluate: %v", err)
	}
	return dec
}

// catalogDispositionNow maps the tool's CURRENT catalog eligibility onto the policy
// engine's disposition input, so the E2E above changes exactly one variable.
func catalogDispositionNow(t *testing.T, r usableRig) policy.Disposition {
	t.Helper()
	if r.eligibility(t) == catalog.Usable {
		return policy.DispUsable
	}
	return policy.DispQuarantined
}

func mustSharedCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	_, cat := mcpInventory.sharedInventory()
	if cat == nil {
		t.Fatal("shared catalog must be published")
	}
	return cat
}

// ---------------------------------------------------------------------------
// Codex P2, round 6 (PR #1378): the repin window.
//
// Registry.Repin and the catalog re-ingest that follows it are SEPARATE publications, so
// between them the registry pins I2 while the catalog record describes I1. That is an
// inconsistency in the PUBLISHED STATE, not in the reading of it, so the round-2 fix — one
// snapshot of each source — cannot close it: no reader can read around a window that exists
// in the data. mcpToolTrust.loadTarget answers it by DETECTING the pair, and this row must
// use the same formula or it reports met for a target whose requests the runtime refuses.
// ---------------------------------------------------------------------------

// TestCatalogUsable_RepinWindowIsNotUsable is the defect gate. It drives the real
// Registry.Repin, leaving the catalog untouched, and requires the row to go unmet.
func TestCatalogUsable_RepinWindowIsNotUsable(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("premise: a governed promotion must make the exact scoped tool usable")
	}

	reg, _ := mcpInventory.sharedInventory()
	if reg == nil {
		t.Fatal("premise: a shared registry must be published")
	}
	if _, err := reg.Repin(registry.ServerID(r.serverID), registry.Identity("rotated"), time.Unix(r.now.Load(), 0)); err != nil {
		t.Fatalf("repin: %v", err)
	}

	// The catalog record is untouched and still Usable — that is the whole point. If this
	// premise ever stops holding, the gate is passing for the wrong reason.
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: the catalog record must still read Usable inside the window, got %v", got)
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("SECURITY: the row reported met inside the repin window. The registry now pins an " +
			"identity the catalog record was not built against, so the runtime refuses these requests " +
			"as AnchorLost/RegistryPinDiverged (C18) — the Canary would activate and be unable to execute")
	}
}

// TestCatalogUsable_DisabledServerIsNotUsable pins the BEHAVIOUR that a server disabled in
// the registry cannot satisfy the row. It is deliberately NOT claimed as the defect gate for
// srv.Usable(), because it passes with or without that line — measured, not assumed. Being
// sequential, its disable lands BEFORE the resolver's reconcile, which withdraws trust and
// demotes the record, so the eligibility check rejects it and srv.Usable() is never reached.
//
// An earlier revision of this comment concluded from that measurement that srv.Usable() was
// UNREACHABLE. That was WRONG (Codex P2 round 7). The registry publishes independently of this
// resolver, so a disable — or, sharply, a mismatching VerifyIdentity, whose branch clears
// Enabled WITHOUT touching PinnedIdentity — can instead land AFTER mcpToolTrustReconcile()
// returns and BEFORE reg.Current() is read. In that window the record is still Usable, the
// tenant still owns the server, the digest still matches, the identity pin still matches, and
// srv.Usable() is the ONLY check that rejects it.
//
// The guard is therefore load-bearing, pinned structurally by
// TestCatalogUsable_ServerUsabilityGuardIsPresent and by campaign mutation M18. What this test
// proves is the sequential half only, and it says so rather than implying more.
//
// The lesson worth keeping: reasoning sequentially about state that is PUBLISHED CONCURRENTLY
// is unsound in BOTH directions. On this PR it deleted a guard as vacuous that was not (round
// 2), and then labelled this one unreachable when it is the last line of defence (round 7).
func TestCatalogUsable_DisabledServerIsNotUsable(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("premise: a governed promotion must make the exact scoped tool usable")
	}

	reg, _ := mcpInventory.sharedInventory()
	if reg == nil {
		t.Fatal("premise: a shared registry must be published")
	}
	if _, err := reg.SetEnabled(registry.ServerID(r.serverID), false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: the catalog record must still read Usable before re-ingest, got %v", got)
	}
	if canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("SECURITY: the row reported met for a server the REGISTRY has disabled. " +
			"rec.Eligibility is the catalog's last ingested opinion, not the registry's current one")
	}
}

// TestCatalogUsable_CoherentPairStillUsable is the CONTROL. The cheapest way to pass both
// gates above is to make the resolver refuse everything, which would silently delete the
// capability this row exists to report. A coherent registry/catalog pair must still be met.
func TestCatalogUsable_CoherentPairStillUsable(t *testing.T) {
	r := newUsableRig(t)
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if !canaryScopedToolsCatalogUsable(r.scope()) {
		t.Fatal("CONTROL: a coherent, governed-promoted, same-identity, enabled target must be " +
			"usable — the repin/disabled checks must narrow the row, never empty it")
	}
}

// TestCatalogUsable_ServerUsabilityGuardIsPresent pins `srv.Usable()` STRUCTURALLY, because the
// state it is the sole defence against is reachable only by an interleaving no sequential test can
// construct (Codex P2 round 7, PR #1378).
//
// The registry publishes independently of the resolver, so a mismatching Registry.VerifyIdentity
// can land AFTER mcpToolTrustReconcile() returns and BEFORE reg.Current() is read. Its branch sets
// Enabled=false and Verification=VerifyIdentityMismatch but DOES NOT TOUCH PinnedIdentity — so in
// that window the catalog record is still Usable, the tenant still owns the server, the digest still
// matches, and the identity comparison still passes because the pin never moved. srv.Usable() is
// the only check that rejects it.
//
// Reaching that behaviourally needs a production seam interposing between the reconcile and the
// registry read, purely so a test can drive a race. That is the worse trade — the same call made
// for the snapshot race in round 2 — so the guard is pinned by its presence instead, with campaign
// mutation M18 proving the gate actually rejects its removal.
//
// This test exists because the guard was briefly, and wrongly, documented as unreachable.
func TestCatalogUsable_ServerUsabilityGuardIsPresent(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mcp_canary_preflight.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp_canary_preflight.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "canaryScopedToolsCatalogUsable" {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("wall is vacuous: canaryScopedToolsCatalogUsable not found (it was renamed or moved)")
	}

	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Usable" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("SECURITY: the resolver no longer asks the REGISTRY whether the server is usable. " +
			"rec.Eligibility is the catalog's LAST INGESTED opinion, and a mismatching VerifyIdentity " +
			"landing between the reconcile and the registry read leaves the record Usable, the tenant " +
			"owning, the digest matching and the identity pin UNCHANGED — so every other check passes " +
			"and this was the only one rejecting it")
	}
}
