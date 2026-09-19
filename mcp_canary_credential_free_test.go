package main

import (
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ---------------------------------------------------------------------------
// BLOCKER #9 — the ENGINE-DRIVEN half of the credential-free proof.
//
// Every gate here drives the REAL policy engine over a REAL compiled snapshot against a tool
// promoted through the REAL governed shadow_evaluation lifecycle, and reads the REAL registry
// and catalog. Nothing about the credential question is stubbed: the server's credential
// profile is seeded through the production inventory path (registry.Register), and the catalog
// fingerprint derives from it exactly as ingest does.
//
// The pure verdict's own matrix lives in internal/mcp/canary/credfree_test.go.
// ---------------------------------------------------------------------------

// seedCredentialInventory seeds the one-server/one-tool inventory with an explicit server
// credential profile, through the SAME production decode+seed path newUsableRig uses. An empty
// profile reproduces the canonical credential-free inventory byte for byte.
func seedCredentialInventory(t *testing.T, credProfile string) (reg *registry.Registry, cat *catalog.Catalog, fpHex string) {
	t.Helper()
	cred := ""
	if credProfile != "" {
		cred = `"credential_profile":"` + credProfile + `",`
	}
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,` + cred + `
	   "tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err = seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"})
	if !ok {
		t.Fatal("seeded tool must exist")
	}
	sum := rec.Fingerprint.Sum()
	return reg, cat, hex.EncodeToString(sum[:])
}

// credRig is a permitRig whose server carries an explicit credential profile. Building it
// re-seeds the inventory BEFORE the governed promotion, so the promotion and the live approval
// bind the credential-bearing fingerprint — which is what makes the reviewed target's credential
// statement real rather than a value patched in afterwards.
func newCredRig(t *testing.T, credProfile string) permitRig {
	t.Helper()
	restoreMCPInventory(t)
	now := &atomic.Int64{}
	now.Store(1_700_000_000)
	composeToolTrust(t, func() time.Time { return time.Unix(now.Load(), 0) })
	_, cat, fpHex := seedCredentialInventory(t, credProfile)
	r := usableRig{cat: cat, serverID: "controlled", toolName: "t", fpHex: fpHex, now: now}
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: the governed promotion must have landed, got %v", got)
	}
	requestAndApproveLive(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t))
	publishPermitPolicy(t, plainAllowDoc())
	return permitRig{usableRig: r, now: time.Unix(now.Load(), 0)}
}

// facts runs the production combined resolver for this rig's exact scope.
func (r permitRig) facts(t *testing.T) exactRequestFacts {
	t.Helper()
	return canaryExactRequestFacts(r.scope(), r.reviewedReadOnly(t), r.now)
}

// ── §11 case 1 — the POSITIVE CONTROL ────────────────────────────────────────

// TestCredFreeE2E_CanonicalPathIsCredentialFree is the anti-vacuity control for every negative
// gate in this file (§13 mutation M12). A resolver that answered false to everything would
// satisfy all of them while making the First Canary permanently impossible — strictly worse than
// the defect. It also pins that the credential fact does not accidentally refuse the very shape
// the experiment is built around.
func TestCredFreeE2E_CanonicalPathIsCredentialFree(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	f := r.facts(t)
	if !f.Permit {
		t.Fatalf("premise: the canonical shape must still be a permit, got %q", f.PermitReason)
	}
	if !f.CredentialFree {
		t.Fatalf("the canonical First-Canary shape must be credential-free, got %q", f.CredentialFreeReason)
	}
}

// ── §11 case 2 — policy obligation carries a credential ──────────────────────

// TestCredFreeE2E_PolicyObligationCredentialIsRefused drives the real engine over a rule whose
// ALLOW carries a credential_profile obligation. BOTH facts must refuse — the permit because the
// obligation is not satisfiable here, this row because the policy layer demands a credential —
// and the credential reason must name the POLICY layer, not an inventory layer.
func TestCredFreeE2E_PolicyObligationCredentialIsRefused(t *testing.T) {
	r := newPermitRig(t, permitPolicyDoc("ALLOW", `"logging":"standard","credential_profile":"cred-a"`))
	f := r.facts(t)
	if f.CredentialFree {
		t.Fatal("an ALLOW carrying a credential_profile obligation must never be credential-free")
	}
	if f.CredentialFreeReason != canary.CredFreePolicyObligation {
		t.Fatalf("must name the policy layer, got %q", f.CredentialFreeReason)
	}
	if f.Permit {
		t.Fatal("premise: the permit must also refuse a credential obligation")
	}
}

// ── §11 cases 3 + 4 — the inventory layers ───────────────────────────────────

// TestCredFreeE2E_ServerCredentialProfileIsRefused is THE gate blocker #9 exists for, and the
// one the policy permit alone cannot make.
//
// The server record declares a credential profile; the policy rule carries no obligation. The
// permit is SATISFIED — correctly, on its own terms — because the matched rule is a plain ALLOW
// with satisfiable obligations. Execution would then read only the policy obligation, find it
// empty, take the no-broker branch, and reach a credential-REQUIRED upstream with NO
// Authorization header. Without this row that state is Ready.
//
// Case 4 (the REVIEWED target implies a credential requirement) is the same assertion: the
// governed promotion and the live approval in this rig bound the credential-bearing fingerprint,
// and CredentialProfile is a hashed fingerprint field, so the reviewed target's credential
// statement IS the catalog record's — asserted explicitly below.
func TestCredFreeE2E_ServerCredentialProfileIsRefused(t *testing.T) {
	r := newCredRig(t, "cred-a")
	f := r.facts(t)
	if !f.Permit {
		t.Fatalf("premise: the POLICY permit must still be satisfied here — that is exactly why "+
			"this row is needed and not implied by blocker #14; got %q", f.PermitReason)
	}
	if f.CredentialFree {
		t.Fatal("a server record declaring a credential profile must never be credential-free")
	}
	if f.CredentialFreeReason != canary.CredFreeServerRequires {
		t.Fatalf("must name the server layer, got %q", f.CredentialFreeReason)
	}
	// Case 4: the reviewed target carries the same credential statement, because the four-eyes
	// approval bound a fingerprint that hashes the credential profile.
	_, cat, _ := mcpToolTrustReconcileSnapshot()
	rec, ok := cat.Get(catalog.ToolKey{Server: registry.ServerID(r.serverID), Name: r.toolName})
	if !ok {
		t.Fatal("catalog record must resolve")
	}
	if string(rec.Fingerprint.CredentialProfile) != "cred-a" {
		t.Fatalf("the REVIEWED fingerprint must carry the credential profile, got %q",
			rec.Fingerprint.CredentialProfile)
	}
}

// TestCredFreeE2E_CredentialProfileChangesTheFingerprint is the §10 pin, and the reason no
// separate credential-drift authority is invented.
//
// CredentialProfile is a hashed fingerprint field, so none → profile-X is a DIFFERENT tool
// identity. Everything already bound to the old fingerprint — the scope pin, the governed
// promotion, the four-eyes live approval — therefore stops matching, which is the existing
// reviewed-target drift machinery doing the work. If this ever stops holding, the credential
// requirement could change under an activation without the fingerprint noticing.
func TestCredFreeE2E_CredentialProfileChangesTheFingerprint(t *testing.T) {
	free := newCredRig(t, "")
	freeFP := free.fpHex
	bound := newCredRig(t, "cred-a")
	if bound.fpHex == freeFP {
		t.Fatal("adding a credential profile MUST change the tool fingerprint — it is a hashed " +
			"fingerprint field, and the whole runtime drift guarantee for blocker #9 rests on it")
	}
}

// ── §11 cases 5 + 6 — the mandatory mismatch differential ────────────────────

// TestCredFreeE2E_PolicyNoneServerRequiresIsNotReady is §5 direction A end to end, at the
// readiness verdict rather than at the resolver: policy says no credential, the authoritative
// server metadata says one is required, and the node must NOT be able to report Ready.
func TestCredFreeE2E_PolicyNoneServerRequiresIsNotReady(t *testing.T) {
	r := newCredRig(t, "cred-a")
	ai := productionCanaryActivationInputs(rollout.CapabilityGateway, r.scope(), 1)
	if !ai.ExactPolicyPermit {
		t.Fatalf("premise: the policy half must be satisfied, or this is not the mismatch case")
	}
	if ai.FirstCanaryCredentialFree {
		t.Fatal("policy-none + server-requires must not resolve as credential-free")
	}
	// And the readiness verdict must carry the named reason, not merely be un-ready for some
	// other reason this build happens to have.
	f := credAllTrueFacts()
	f.FirstCanaryCredentialFree = ai.FirstCanaryCredentialFree
	v := canary.Evaluate(f)
	if v.Ready {
		t.Fatal("a credential-required experiment must never reach Ready")
	}
	if len(v.Unmet) != 1 || v.Unmet[0] != canary.ReasonCredentialPathRequired {
		t.Fatalf("must be unmet for exactly credential_path_required, got %v", v.Unmet)
	}
}

// TestCredFreeE2E_PolicyRequiresServerAnonymousIsNotReady is §5 direction B: the policy rule
// demands a credential while the server record declares none — "the upstream happens to allow
// anonymous access" is never a First-Canary path.
func TestCredFreeE2E_PolicyRequiresServerAnonymousIsNotReady(t *testing.T) {
	r := newPermitRig(t, permitPolicyDoc("ALLOW", `"logging":"standard","credential_profile":"cred-a"`))
	// Premise: the SERVER declares no credential profile (the canonical rig).
	_, cat, _ := mcpToolTrustReconcileSnapshot()
	rec, ok := cat.Get(catalog.ToolKey{Server: registry.ServerID(r.serverID), Name: r.toolName})
	if !ok {
		t.Fatal("catalog record must resolve")
	}
	if rec.Fingerprint.CredentialProfile != "" {
		t.Fatalf("premise: the server must declare NO credential profile, got %q", rec.Fingerprint.CredentialProfile)
	}
	f := r.facts(t)
	if f.CredentialFree {
		t.Fatal("a policy rule demanding a credential must not be credential-free even against an anonymous server")
	}
}

// ── the two-publication window ───────────────────────────────────────────────

// TestCredFreeWall_CatalogCredentialDerivesFromTheRegistryRecord pins WHY the registry and the
// catalog cannot disagree about the credential profile, rather than leaving that as an
// assumption the single-capture argument silently depends on.
//
// Two production facts, both asserted here. (1) The catalog fingerprint's CredentialProfile is
// DERIVED from the registry ServerRecord at ingest — it is never independently supplied by the
// upstream's tools/list response, which matters because that response is attacker-influenced
// data. (2) The registry exposes NO mutator for CredentialProfile: Register refuses a duplicate
// id, and Repin/SetEnabled change other fields. So the pair can only change together, by
// republishing the whole inventory — which replaces the catalog in the same publication.
//
// That is what makes canary.CredFreeInventoryDisagrees unreachable today, and it is recorded as
// a wall rather than a comment so that ADDING a credential-profile mutator (a perfectly
// reasonable future feature) fails here and forces the divergence question to be answered
// again, instead of silently opening a window the empty checks were never designed to cover.
func TestCredFreeWall_CatalogCredentialDerivesFromTheRegistryRecord(t *testing.T) {
	// (1) The fingerprint field is assigned from the registry record, in the ingest parser.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "internal", "mcp", "catalog", "ingest_parse.go"))
	if err != nil {
		t.Fatalf("read ingest parser: %v", err)
	}
	if !strings.Contains(string(src), "CredentialProfile: server.CredentialProfile") {
		t.Error("SECURITY: the catalog fingerprint no longer derives its CredentialProfile from " +
			"the registry ServerRecord. If it is now taken from discovery data, the reviewed " +
			"fingerprint records an upstream-supplied claim rather than the operator's inventory, " +
			"and the credential-free proof must be re-derived.")
	}
	// (2) The registry exposes no credential-profile mutator.
	regSrc, err := os.ReadFile(filepath.Join(pkgSourceDir(), "internal", "mcp", "registry", "registry.go"))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "registry.go", regSrc, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	allowed := map[string]bool{"Current": true, "Register": true, "VerifyIdentity": true, "SetEnabled": true, "Repin": true}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !fn.Name.IsExported() {
			continue
		}
		if recvTypeName(fn.Recv) != "Registry" {
			continue // Snapshot and other read-only types cannot mutate a record
		}
		if !allowed[fn.Name.Name] {
			t.Errorf("SECURITY: registry exposes a new exported method %q. If it can change a "+
				"server's CredentialProfile, the registry and the catalog fingerprint can diverge "+
				"and canary.CredFreeInventoryDisagrees stops being unreachable — re-derive the "+
				"credential-free proof and add this method to the allow-list if it cannot.", fn.Name.Name)
		}
	}
	// And the premise the wall protects: a duplicate Register is refused, so an existing
	// server's credential profile cannot be replaced in place.
	r := newPermitRig(t, plainAllowDoc())
	mcpInventory.mu.RLock()
	live := mcpInventory.reg
	mcpInventory.mu.RUnlock()
	if live == nil {
		t.Fatal("the live registry must be published")
	}
	snap, _, ok := mcpToolTrustReconcileSnapshot()
	if !ok {
		t.Fatal("inventory must be composed")
	}
	srv, sok := snap.Get(registry.ServerID(r.serverID))
	if !sok {
		t.Fatal("server record must resolve")
	}
	if _, err := live.Register(registry.Registration{
		ID: srv.ID, Endpoint: srv.Endpoint, PinnedIdentity: srv.PinnedIdentity,
		Capability: protocol.Gateway, CredentialProfile: "cred-a", OwnerScope: srv.OwnerScope,
	}); err == nil {
		t.Fatal("SECURITY: re-registering an existing server with a DIFFERENT credential profile " +
			"succeeded. The catalog fingerprint is not re-ingested by that call, so the registry " +
			"and the reviewed fingerprint would now disagree about whether a credential is required.")
	}
}

// ── coherence ────────────────────────────────────────────────────────────────

// TestCredFreeWall_BothFactsComeFromOneCapture pins the §3 coherence requirement STRUCTURALLY:
// the permit and the credential fact are two questions about ONE request and must be answered
// from ONE observation of node state.
//
// It is a wall rather than a behavioural gate for the reason TestPermitWall_ResolverTakesOne-
// CoherentCapture records: every behavioural gate passes against a two-capture resolver on a
// quiescent fixture, because nothing changes between the captures. And it is AST-based rather
// than hook-based because adding a production seam whose only purpose is to let a test count
// reads is the worse trade — the same call the blocker-#13 round made.
//
// What it forbids is specific: canaryExactRequestFacts must reach the inventory ONLY through one
// buildExactPermitInput call. Calling canaryExactPolicyPermit from it would take a second
// capture, and between the two the registry and catalog publish independently — so the permit
// could be decided against an inventory in which the tool needs no credential while the
// credential fact is decided against one in which it does. Each verdict would be individually
// true and their conjunction would describe no state that ever existed.
func TestCredFreeWall_BothFactsComeFromOneCapture(t *testing.T) {
	fn := parseNamedResolver(t, "canaryExactRequestFacts")
	builds, forbidden := 0, map[string]string{
		"canaryExactPolicyPermit":          "takes a SECOND coherent capture",
		"mcpToolTrustReconcileSnapshotFor": "captures directly instead of sharing the one build",
		"mcpToolTrustReconcileSnapshot":    "captures directly instead of sharing the one build",
		"mcpCurrentAuthoritativeTarget":    "re-reads the live inventory",
		"mcpToolTrustReconcile":            "reconciles without capturing",
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "buildExactPermitInput" {
			builds++
		}
		if why, bad := forbidden[id.Name]; bad {
			t.Errorf("SECURITY: canaryExactRequestFacts calls %s, which %s. Both facts must come "+
				"from the ONE capture buildExactPermitInput takes.", id.Name, why)
		}
		return true
	})
	if builds != 1 {
		t.Fatalf("canaryExactRequestFacts must call buildExactPermitInput exactly once, got %d", builds)
	}
}

// TestCredFreeWall_CredentialFactsComeFromTheCapturedRecords pins that the three credential
// statements are read from the records the ONE capture produced — the same `srv` and `rec` the
// permit was decided on — rather than from a fresh lookup. A fresh lookup would reintroduce the
// two-read inconsistency the capture exists to remove, and no behavioural gate on a quiescent
// fixture could tell the difference.
func TestCredFreeWall_CredentialFactsComeFromTheCapturedRecords(t *testing.T) {
	fn := parsePermitResolver(t)
	want := map[string]bool{
		"dec.Obligations.CredentialProfile": false,
		"srv.CredentialProfile":             false,
		"rec.Fingerprint.CredentialProfile": false,
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "CredentialProfile" {
			return true
		}
		if _, seen := want[selectorPath(sel)]; seen {
			want[selectorPath(sel)] = true
		}
		return true
	})
	for expr, found := range want {
		if !found {
			t.Errorf("SECURITY: buildExactPermitInput does not read %s. Every credential statement "+
				"must come from the records the one coherent capture produced.", expr)
		}
	}
}

// selectorPath renders a dotted selector chain (a.b.c) as text, for the wall above. It is a
// local spelling-free walk rather than the printer-based exprText in the exact-scope wall,
// because it needs no FileSet and only ever sees dotted identifier chains.
func selectorPath(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return selectorPath(v.X) + "." + v.Sel.Name
	default:
		return ""
	}
}

// recvTypeName returns the bare receiver type name (dereferenced) of a method decl.
func recvTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	t := recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// parseNamedResolver returns the named top-level func from the permit resolver file.
func parseNamedResolver(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), "mcp_canary_policy_permit.go"), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse resolver: %v", err)
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s not found — this wall is checking nothing", name)
	return nil
}

// TestCredFreeE2E_UnresolvableTupleIsNotCredentialFree pins the fail-closed direction at the
// production resolver: a scope whose tool does not resolve yields no credential statement at
// all, and that must read as "not established", never as "no credential required".
func TestCredFreeE2E_UnresolvableTupleIsNotCredentialFree(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	missing := r.scope()
	missing.Tools = []rollout.ToolSel{{Server: r.serverID, Name: "does-not-exist", Fingerprint: r.fpHex}}
	f := canaryExactRequestFacts(missing, r.reviewedReadOnly(t), r.now)
	if f.CredentialFree {
		t.Fatal("an unresolvable tuple must never resolve as credential-free")
	}
	if f.CredentialFreeReason != canary.CredFreeUnavailable {
		t.Fatalf("must be %q, got %q", canary.CredFreeUnavailable, f.CredentialFreeReason)
	}
}

// credAllTrueFacts is the all-prerequisites-hold fact set, used ONLY to isolate the readiness
// reason this row contributes. It is a local fixture, never a claim about the node: this build
// cannot satisfy LiveExecutorComposed or the rollback-coordinator rehearsal, which is why the
// production preflight can still never reach Ready.
//
// It is derived by reflection rather than written out, so a prerequisite added later is set true
// here automatically and this gate keeps isolating exactly one reason instead of silently
// starting to report two.
func credAllTrueFacts() canary.Facts {
	var f canary.Facts
	v := reflect.ValueOf(&f).Elem()
	for i := range v.NumField() {
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool(true)
		}
	}
	return f
}

// ── §9 / §10 — runtime drift after the preflight proved credential-free ──────

// TestCredDrift_CredentialChangeBreaksTheReviewedBinding is the §9 TOCTOU case, answered by the
// EXISTING reviewed-target machinery rather than by a new credential-drift authority.
//
// The sequence: an activation is prepared against a tool that needs no credential, the
// authoritative metadata then changes to credential-required, and a stale request resumes. Because
// CredentialProfile is a hashed fingerprint field (pinned by
// TestCredFreeE2E_CredentialProfileChangesTheFingerprint), the change produces a DIFFERENT tool
// identity — so the reviewed set the activation bound no longer describes the current target and
// the permit refuses before anything executes.
//
// This is why §10's answer matters so much: had the credential profile been outside the
// fingerprint, the reviewed binding would have kept matching across the change and the credential
// requirement could have appeared under a live activation unnoticed. Nothing here is a
// request-local check.
func TestCredDrift_CredentialChangeBreaksTheReviewedBinding(t *testing.T) {
	// Phase 1: the credential-free world. Capture the reviewed set an activation would bind.
	free := newCredRig(t, "")
	reviewedBefore := free.reviewedReadOnly(t)
	if f := canaryExactRequestFacts(free.scope(), reviewedBefore, free.now); !f.Permit || !f.CredentialFree {
		t.Fatalf("premise: the credential-free world must satisfy both facts (permit=%q cred=%q)",
			f.PermitReason, f.CredentialFreeReason)
	}

	// Phase 2: the authoritative metadata now says a credential is required.
	bound := newCredRig(t, "cred-a")

	// A stale activation still carrying the OLD reviewed set must not resolve. Both halves refuse,
	// for their own reasons, and BOTH are asserted: the reviewed binding no longer matches the
	// current target, and the credential layer objects on its own terms.
	stale := canaryExactRequestFacts(bound.scope(), reviewedBefore, bound.now)
	if stale.Permit {
		t.Fatal("SECURITY: a reviewed set bound to the pre-change fingerprint must not still permit")
	}
	if stale.CredentialFree {
		t.Fatal("SECURITY: a credential requirement that appeared after the reviewed binding must " +
			"not read as credential-free")
	}
	if stale.CredentialFreeReason != canary.CredFreeServerRequires {
		t.Fatalf("must name the server layer, got %q", stale.CredentialFreeReason)
	}

	// CONTROL: the refusal is caused by the CHANGE, not by newCredRig being unable to produce a
	// working world. A reviewed set taken AFTER the change still refuses on the credential layer
	// while the policy permit is satisfied — the exact state the new row exists to catch.
	fresh := canaryExactRequestFacts(bound.scope(), bound.reviewedReadOnly(t), bound.now)
	if !fresh.Permit {
		t.Fatalf("control: a freshly reviewed credential-required target must still satisfy the "+
			"POLICY permit (that is why this row is not implied by blocker #14), got %q", fresh.PermitReason)
	}
	if fresh.CredentialFree {
		t.Fatal("control: a freshly reviewed credential-required target must still not be credential-free")
	}
}

// TestCredDrift_ReadinessIsReEvaluatedNotFrozen pins that the credential fact is LIVE state.
//
// A credential profile added to the server AFTER activation must be able to make the next FULL
// ACTIVATION PREFLIGHT refuse. If the fact were copied into the activation's immutable reviewed
// snapshot — which is the natural way to implement "the reviewed target needs no credential" — a
// post-activation credential requirement would be invisible for the life of the Canary.
//
// What this pins is that the FACT is live. It says NOTHING about which read surface exposes it,
// and the node status surface does not: EvaluateNode excludes every activation row. Reading more
// than that out of this gate is exactly the round-2 defect (§25d);
// TestCredWall_NoActivationFactPromisesNodeReadiness holds that boundary.
func TestCredDrift_ReadinessIsReEvaluatedNotFrozen(t *testing.T) {
	free := newCredRig(t, "")
	before := productionCanaryActivationInputs(rollout.CapabilityGateway, free.scope(), 1)
	if !before.FirstCanaryCredentialFree {
		t.Fatal("premise: the credential-free world must resolve as credential-free")
	}
	bound := newCredRig(t, "cred-a")
	after := productionCanaryActivationInputs(rollout.CapabilityGateway, bound.scope(), 1)
	if after.FirstCanaryCredentialFree {
		t.Fatal("SECURITY: the credential fact did not re-observe authoritative state. A credential " +
			"requirement that appears after activation must be able to make the next activation " +
			"preflight refuse; a value frozen into the reviewed snapshot could never express that.")
	}
}

// ── §11 case 11 — restart durability ─────────────────────────────────────────

// TestCredFreeE2E_RestartPreservesTheCredentialFreeReviewedState drives a real restart — a fresh
// inventory seed plus a coordinator recomposed against the SAME durable trust store — and
// asserts the credential-free determination survives it, in both directions.
//
// Two things must hold across the restart, and they are different claims. (1) A credential-free
// reviewed target is re-promoted and still resolves as credential-free, so a node does not lose a
// prepared experiment to a reboot. (2) Re-seeding does not launder a credential requirement: when
// the re-seeded inventory declares one, the restored state refuses, because the durable approval
// binds a FINGERPRINT and the credential profile is inside it.
//
// (2) is the one worth having. A restart re-derives eligibility from the durable store against a
// freshly seeded catalog, and that is exactly the moment a stale approval could be re-applied to
// changed metadata.
func TestCredFreeE2E_RestartPreservesTheCredentialFreeReviewedState(t *testing.T) {
	restoreMCPInventory(t)
	dir := t.TempDir()
	setDataDirForTest(t, dir)
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)

	// initMCPToolTrust (NOT composeToolTrust) is what a boot runs, and it is what binds the
	// durable store to dataDir. composeToolTrust points the store at its own temp dir, so a
	// "restart" through it would read an empty store and prove nothing. It also requires the
	// inventory to be published first, exactly as boot ordering does.
	_, cat, fpHex := seedCredentialInventory(t, "")
	initMCPToolTrust(nil)
	now := &atomic.Int64{}
	now.Store(mcpToolTrust.now().Unix())
	r := usableRig{cat: cat, serverID: "controlled", toolName: "t", fpHex: fpHex, now: now}
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	requestAndApproveLive(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t))
	publishPermitPolicy(t, plainAllowDoc())
	rig := permitRig{usableRig: r, now: mcpToolTrust.now()}
	if f := rig.facts(t); !f.Permit || !f.CredentialFree {
		t.Fatalf("premise: both facts must hold before the restart (permit=%q cred=%q)",
			f.PermitReason, f.CredentialFreeReason)
	}

	// (1) RESTART with the SAME credential-free inventory: the durable approval re-promotes and
	// the credential-free determination is intact.
	_, cat2, fp2 := seedCredentialInventory(t, "")
	resetMCPToolTrustForTest()
	initMCPToolTrust(nil)
	rig2 := permitRig{usableRig: usableRig{cat: cat2, serverID: r.serverID, toolName: r.toolName, fpHex: fp2, now: now}, now: rig.now}
	if f := rig2.facts(t); !f.Permit || !f.CredentialFree {
		t.Fatalf("a restart must preserve a credential-free prepared experiment (permit=%q cred=%q)",
			f.PermitReason, f.CredentialFreeReason)
	}

	// (2) RESTART into an inventory that now declares a credential. The durable approval binds a
	// fingerprint that does not describe this tool any more, and the credential layer objects.
	_, cat3, fp3 := seedCredentialInventory(t, "cred-a")
	if fp3 == fp2 {
		t.Fatal("premise: the credential-bearing inventory must carry a different fingerprint")
	}
	resetMCPToolTrustForTest()
	initMCPToolTrust(nil)
	rig3 := permitRig{usableRig: usableRig{cat: cat3, serverID: r.serverID, toolName: r.toolName, fpHex: fp3, now: now}, now: rig.now}
	f3 := rig3.facts(t)
	if f3.CredentialFree {
		t.Fatal("SECURITY: a restart must not launder a credential requirement into a " +
			"credential-free verdict")
	}
	if f3.CredentialFreeReason != canary.CredFreeServerRequires {
		t.Fatalf("must name the server layer after the restart, got %q", f3.CredentialFreeReason)
	}
}
