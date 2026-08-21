package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcpDistributionTrustKeysJSON builds the env trust-keys JSON payload from a signer's
// PUBLIC key (test-only; emits PUBLIC key material only, never a private key).
func mcpDistributionTrustKeysJSON(keyID string, pub ed25519.PublicKey) string {
	b, _ := json.Marshal([]mcpDistributionTrustKey{{
		KeyID: keyID, Alg: cpdp.SigAlgEd25519, PublicKey: base64.StdEncoding.EncodeToString(pub),
	}})
	return string(b)
}

// These tests cover the two P1 findings closed before merge:
//
//   P1-A: the DP applier is now composed by PRODUCTION startup (initMCPDistribution),
//         so a signed rollout envelope reaches the durable rollout commit path. The
//         tests drive the REAL composition (env trust + initMCPDistribution), never a
//         test-only setDPApplier.
//   P1-B: distribution activation and the rollout commit are ONE truthful transaction:
//         an AckApplied is impossible unless BOTH accepted the same revision, a
//         locally-rejected rollout never leaves an applied distribution revision, and a
//         rollout persistence failure reverts the distribution activation.
//
// The pre-fix RED behavior (documented in the PR): before initMCPDistribution existed,
// mcpProdSetup below could not compose an applier (setDPApplier had no production
// caller), so every "reaches rollout commit" assertion failed; and before the
// transaction coordinator, an executing-mode/persist-failure rollout left the
// distribution applied with an AckApplied — the split these tests now forbid.

// ---- production-composition harness (no test-only setDPApplier) ----------------

// mcpResetGlobals swaps the process-wide distribution + rollout singletons for fresh
// ones and restores them on cleanup, so each test composes from a clean slate.
func mcpResetGlobals(t *testing.T) {
	t.Helper()
	prevD := globalMCPDistribution
	globalMCPDistribution = &mcpDistribution{}
	_ = getMCPRollout() // ensure the sync.Once has fired before we swap the pointer
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPDistribution = prevD; globalMCPRollout = prevR })
}

// mcpProdSetup drives the REAL production composition path: it points dataDir at a
// fresh directory, provisions the DP trust from the signer's PUBLIC key via the env
// surface, and runs initMCPDistribution. It returns the signer and the data dir. It
// fails the test if composition did not enable the DP appliers.
func mcpProdSetup(t *testing.T) (signer cpdp.Signer, dir string) {
	t.Helper()
	signer, _ = mcpTestSigner(t)
	dir = t.TempDir()
	setDataDirForTest(t, dir)
	t.Setenv(envMCPDistributionTrustKeys, mcpDistributionTrustKeysJSON("mcp-k1", signer.Public()))
	mcpResetGlobals(t)
	initMCPDistribution(nil)
	if !globalMCPDistribution.enabled.Load() {
		t.Fatalf("production composition did not enable DP appliers: %v", mcpDistributionStatus()["dp_compose_reason"])
	}
	return signer, dir
}

// setDataDirForTest sets the global dataDir and restores it on cleanup, WITHOUT the
// per-call temp dir that withTempDataDir creates (so a restart can reuse a dir).
func setDataDirForTest(t *testing.T, dir string) {
	t.Helper()
	prev := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = prev })
}

// mcpSimulateRestart re-composes the node against the same dataDir with fresh
// singletons, exactly as a process restart would: rollout state is restored (as
// initMCPRollout does) and the DP appliers are recomposed + reconciled (as
// initMCPDistribution does). No test-only wiring.
func mcpSimulateRestart(t *testing.T) {
	t.Helper()
	prevD := globalMCPDistribution
	globalMCPDistribution = &mcpDistribution{}
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPDistribution = prevD; globalMCPRollout = prevR })
	getMCPRollout().restore() // initMCPRollout equivalent
	initMCPDistribution(nil)  // recover appliers + reconcile
}

// ---- signed-envelope builders carrying a rollout config ------------------------

func mcpObserveRollout(capb rollout.Capability) *rollout.SignedConfig {
	cfg := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: capb, Mode: rollout.ModeObserve,
		Scope: rollout.ScopeSpec{Capability: capb},
	}
	if capb == rollout.CapabilityGateway {
		cfg.ConnectorMode = rollout.ConnectorLocalClient
	}
	return cfg
}

func mcpShadowRollout(capb rollout.Capability, scopeRev uint64) *rollout.SignedConfig {
	cfg := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: capb, Mode: rollout.ModeShadow, ScopeRevision: scopeRev,
		Scope: rollout.ScopeSpec{Capability: capb, Servers: []string{"s1"}},
	}
	if capb == rollout.CapabilityGateway {
		cfg.ConnectorMode = rollout.ConnectorLocalClient
	}
	return cfg
}

func mcpProductionRollout(capb rollout.Capability, scopeRev uint64) *rollout.SignedConfig {
	cfg := mcpShadowRollout(capb, scopeRev)
	cfg.Mode = rollout.ModeProduction
	return cfg
}

// mcpSignedGWEnv signs a Gateway envelope at cfgRev carrying rc as its rollout config.
func mcpSignedGWEnv(t *testing.T, s cpdp.Signer, cfgRev uint64, rc *rollout.SignedConfig) *cpdp.Envelope {
	t.Helper()
	m := cpdp.Manifest{
		SchemaVersion: cpdp.SchemaVersion, Capability: cpdp.CapabilityGateway, Epoch: 0,
		Revisions: cpdp.Revisions{Config: cfgRev, Policy: cfgRev, Catalog: 1, Credential: 1}, MinDPVersion: 1,
		PayloadType: "gateway", PayloadVersion: 1, CreatedUnixNano: 1000, Source: cpdp.SourceMeta{Kind: "publish"},
	}
	p := cpdp.Payload{Gateway: &cpdp.GatewayPayload{
		Listener:     cpdp.GatewayListener{Enabled: true, BindAddress: "127.0.0.1", Port: 8091, PolicyDefaultAction: "deny"},
		Servers:      []cpdp.ServerRecord{{ID: "s1", Endpoint: "https://s1", PinnedIdentity: "sha256:aa", Verified: true, Enabled: true}},
		Tools:        []cpdp.ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp"}},
		PolicySource: mcpTestPolicyDoc,
		Rollout:      rc,
	}}
	env, err := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// mcpSignedMGEnv signs a Management envelope at cfgRev carrying rc as its rollout.
func mcpSignedMGEnv(t *testing.T, s cpdp.Signer, cfgRev uint64, rc *rollout.SignedConfig) *cpdp.Envelope {
	t.Helper()
	m := cpdp.Manifest{
		SchemaVersion: cpdp.SchemaVersion, Capability: cpdp.CapabilityManagement, Epoch: 0,
		Revisions: cpdp.Revisions{Config: cfgRev, Policy: cfgRev, Catalog: 1, Credential: 1}, MinDPVersion: 1,
		PayloadType: "management", PayloadVersion: 1, CreatedUnixNano: 1000, Source: cpdp.SourceMeta{Kind: "publish"},
	}
	p := cpdp.Payload{Management: &cpdp.ManagementPayload{
		Listener: cpdp.ManagementListener{
			Enabled: true, BindAddress: "127.0.0.1", Port: 8092, ClientCertMode: "require",
			AuthMode: "oauth-token", DefaultMinRole: "viewer", TenantScopeMode: "strict",
			OutputMaxBytes: 1048576, OutputRedaction: "default",
		},
		Rollout: rc,
	}}
	env, err := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// ---- P1-A: production composition + non-executing successful apply -------------

// TestProd_DisabledDefaultIsInert proves the disabled default (no trust env) composes
// NO applier and a received signed rollout envelope is inert (fail-closed, byte-safe).
// This is also the pre-fix state the RED reproduction demonstrated.
func TestProd_DisabledDefaultIsInert(t *testing.T) {
	s, _ := mcpTestSigner(t)
	dir := t.TempDir()
	setDataDirForTest(t, dir)
	t.Setenv(envMCPDistributionTrustKeys, "") // explicitly unset
	mcpResetGlobals(t)
	initMCPDistribution(nil)
	if globalMCPDistribution.enabled.Load() {
		t.Fatal("distribution must stay disabled with no trust configured")
	}
	if globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway) != nil {
		t.Fatal("no DP applier may be composed in the disabled default")
	}
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))})
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("a signed rollout envelope must be inert while distribution is disabled")
	}
}

// TestProd_ComposesApplierAndReachesRolloutCommit is the P1-A proof: production
// composition wires the DP applier, so a signed Observe envelope activates the
// distribution AND reaches the durable rollout commit, with a truthful AckApplied.
// Before the fix this FAILED because no production applier was ever composed.
func TestProd_ComposesApplierAndReachesRolloutCommit(t *testing.T) {
	s, _ := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	if a == nil {
		t.Fatal("P1-A: production startup did not register a DP applier")
	}
	env := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})

	if a.Active() == nil || a.Active().ContentHash != env.ContentHash {
		t.Fatal("signed envelope did not activate the distribution")
	}
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatalf("rollout commit not reached: mode=%s", getMCPRollout().gateway.CurrentMode())
	}
	if pa := a.PendingAck(); pa == nil || pa.State != cpdp.AckApplied || pa.ContentHash != env.ContentHash {
		t.Fatalf("both halves accepted but no truthful AckApplied: %+v", pa)
	}
}

// TestProd_RestartRecomposesAndRestores is the §9 proof: after a valid non-executing
// apply and a restart, production startup recomposes the applier AUTOMATICALLY,
// restores the exact revision/state, and a re-delivered identical envelope is
// idempotent (no revision inflation, no window restamp).
func TestProd_RestartRecomposesAndRestores(t *testing.T) {
	s, _ := mcpProdSetup(t)
	env := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})

	mcpSimulateRestart(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	if a == nil {
		t.Fatal("restart did not recompose the DP applier")
	}
	if a.Active() == nil || a.Active().ContentHash != env.ContentHash {
		t.Fatal("restart did not restore the exact active distribution revision")
	}
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("restart reconciliation did not restore the rollout mode")
	}
	// Re-deliver the identical envelope: idempotent, no revision inflation.
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	if a.Active().ContentHash != env.ContentHash {
		t.Fatal("idempotent re-delivery changed the active revision")
	}
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("idempotent re-delivery disturbed the rollout mode")
	}
}

// ---- P1-B: transaction (no AckApplied unless both halves accept) ---------------

// TestTxn_ShadowFailsClosedNoAckNoSplit is the §10 proof AND the P1-B RED case: a
// signed Observe→Shadow envelope reaches the production commit path and fails closed
// at the execution-dependency gate — no Shadow mode, no distribution activation, no
// AckApplied, no distribution/rollout split. Before the fix the distribution applied
// (and produced AckApplied) while the rollout was rejected.
func TestTxn_ShadowFailsClosedNoAckNoSplit(t *testing.T) {
	s, _ := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	env := mcpSignedGWEnv(t, s, 2, mcpShadowRollout(rollout.CapabilityGateway, 1))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})

	if getMCPRollout().gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("Shadow must fail closed: rollout mode must not advance")
	}
	if getMCPRollout().gateway.Evidence().ShadowStartUnix != 0 {
		t.Fatal("no Shadow window may be stamped on a fail-closed transition")
	}
	if a.Active() != nil {
		t.Fatal("distribution must NOT activate when the coupled rollout fails closed (no split)")
	}
	if pa := a.PendingAck(); pa != nil && pa.State == cpdp.AckApplied {
		t.Fatal("no AckApplied may exist for a rollout the node rejected (CP must not count convergence)")
	}
}

// TestTxn_ProductionEnvelopeFailsClosed proves a signed envelope carrying mode=
// Production is rejected fail-closed at the same execution-dependency gate — the
// signed distribution path can never bypass the Production lock.
func TestTxn_ProductionEnvelopeFailsClosed(t *testing.T) {
	s, _ := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	env := mcpSignedGWEnv(t, s, 2, mcpProductionRollout(rollout.CapabilityGateway, 1))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("a signed Production envelope must not advance the rollout mode")
	}
	if a.Active() != nil {
		t.Fatal("a signed Production envelope must not activate distribution")
	}
}

// TestTxn_CapabilityMismatchRejected proves the pre-check rejects a Gateway envelope
// whose rollout config claims the Management capability (or vice versa) WHOLE, before
// any distribution activation — capability isolation at the transaction boundary.
func TestTxn_CapabilityMismatchRejected(t *testing.T) {
	s, _ := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	// A Gateway envelope carrying a Management rollout config.
	env := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityManagement))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	if a.Active() != nil {
		t.Fatal("a capability-mismatched rollout must not activate distribution")
	}
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeDisabled ||
		getMCPRollout().management.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("a capability-mismatched rollout must not advance any rollout state")
	}
	if pa := a.PendingAck(); pa != nil && pa.State == cpdp.AckApplied {
		t.Fatal("a capability-mismatched rollout must not produce an AckApplied")
	}
}

// TestTxn_PersistFailureRevertsDistributionNoAck is the §12 proof: with distribution
// persistence healthy but rollout-state persistence forced to fail, the apply fails,
// the distribution activation is reverted to the prior revision, no AckApplied stands,
// and a restart recovers the prior revision.
func TestTxn_PersistFailureRevertsDistributionNoAck(t *testing.T) {
	s, dir := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)

	// Establish a good prior revision (rev2, Observe).
	env2 := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env2})
	if a.Active() == nil || a.Active().ContentHash != env2.ContentHash {
		t.Fatal("prior revision did not activate")
	}

	// Force ONLY the rollout-state write to fail: replace the rollout state file with a
	// directory so its atomic write fails, while the distribution dir stays writable.
	rollFile := filepath.Join(dir, "mcp_rollout_state_gateway.json")
	_ = os.Remove(rollFile)
	if err := os.Mkdir(rollFile, 0o700); err != nil {
		t.Fatalf("arm rollout persist failure: %v", err)
	}

	env3 := mcpSignedGWEnv(t, s, 3, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env3})

	if a.Active() == nil || a.Active().ContentHash != env2.ContentHash {
		t.Fatalf("distribution must be reverted to the prior revision after a rollout persist failure, got %v", a.ActiveHash())
	}
	if pa := a.PendingAck(); pa == nil || pa.State != cpdp.AckRejected {
		t.Fatalf("a persist-failed apply must leave a Rejected ack, not AckApplied: %+v", pa)
	}

	// Un-arm the failure and prove a restart recovers the prior (rev2) revision.
	_ = os.Remove(rollFile)
	mcpSimulateRestart(t)
	a2 := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	if a2.Active() == nil || a2.Active().ContentHash != env2.ContentHash {
		t.Fatal("restart after a persist-failure must recover the prior revision")
	}
}

// TestTxn_CapabilityIsolation is the §13 proof: a rollout persistence failure while
// applying a Management envelope reverts ONLY Management distribution and leaves the
// Gateway distribution + rollout untouched (and vice versa is symmetric by design).
func TestTxn_CapabilityIsolation(t *testing.T) {
	s, dir := mcpProdSetup(t)
	gwA := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	mgA := globalMCPDistribution.dpApplierFor(cpdp.CapabilityManagement)

	// Gateway applies cleanly.
	gwEnv := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: gwEnv})
	if gwA.Active() == nil || getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("gateway did not apply")
	}

	// Force ONLY Management rollout persistence to fail.
	mgFile := filepath.Join(dir, "mcp_rollout_state_management.json")
	_ = os.Remove(mgFile)
	if err := os.Mkdir(mgFile, 0o700); err != nil {
		t.Fatalf("arm mgmt rollout persist failure: %v", err)
	}
	mgEnv := mcpSignedMGEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityManagement))
	applySnapshotMCP(ConfigSnapshot{MCPManagementSnapshot: mgEnv})

	// Management reverted; Gateway untouched.
	if mgA.Active() != nil {
		t.Fatal("management distribution must be reverted after its rollout persist failure")
	}
	if getMCPRollout().management.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("management rollout must stay Disabled after its persist failure")
	}
	if gwA.Active() == nil || gwA.Active().ContentHash != gwEnv.ContentHash {
		t.Fatal("gateway distribution must be UNAFFECTED by a management failure")
	}
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("gateway rollout must be UNAFFECTED by a management failure")
	}
}

// TestTxn_IdempotentReapplyStable is the §7 proof for a non-executing config: a
// byte-identical re-delivery is idempotent — no revision inflation, no error, no
// state corruption, and the ack stays truthful.
func TestTxn_IdempotentReapplyStable(t *testing.T) {
	s, _ := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	env := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	firstHash := a.Active().ContentHash
	// Re-deliver twice more.
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	if a.Active().ContentHash != firstHash {
		t.Fatal("idempotent re-delivery changed the active revision")
	}
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("idempotent re-delivery disturbed the rollout mode")
	}
}

// TestProd_InvalidTrustFailsClosed proves a present-but-invalid trust value composes
// NO applier (fail-closed to disabled), never an applier that trusts nothing.
func TestProd_InvalidTrustFailsClosed(t *testing.T) {
	dir := t.TempDir()
	setDataDirForTest(t, dir)
	t.Setenv(envMCPDistributionTrustKeys, `[{"key_id":"k","alg":"ed25519","public_key":"not-base64!!"}]`)
	mcpResetGlobals(t)
	initMCPDistribution(nil)
	if globalMCPDistribution.enabled.Load() {
		t.Fatal("invalid trust must fail closed to disabled")
	}
	if globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway) != nil {
		t.Fatal("invalid trust must compose no applier")
	}
	if r := mcpDistributionStatus()["dp_compose_reason"]; r != "invalid_trust_key" {
		t.Fatalf("compose reason = %v, want invalid_trust_key", r)
	}
}
