package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Durable Shadow rollout state remediation (B-MECH-1/2/3) tests.
//
// These cover the mechanical defects the Shadow Readiness Decision found: the
// evidence window was never coupled to a transition, rollout state was RAM-only, and
// an executing mode could activate against an unconfigured execution plane. All use
// deterministic injected clocks — no sleeps.

// newTestRollout builds an isolated rollout composition (never the global singleton).
func newTestRollout() *mcpRollout {
	return &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
}

func gwShadowCfg(rev uint64, servers ...string) *rollout.SignedConfig {
	if len(servers) == 0 {
		servers = []string{"s1"}
	}
	return &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		ScopeRevision: rev,
		Scope:         rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: servers},
		ConnectorMode: rollout.ConnectorLocalClient,
	}
}

func gwObserveCfg() *rollout.SignedConfig {
	return &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeObserve,
		Scope: rollout.ScopeSpec{Capability: rollout.CapabilityGateway}, ConnectorMode: rollout.ConnectorLocalClient,
	}
}

// withExecDepsReady flips the Gateway SHADOW-readiness flag for the duration of a test
// so a Shadow transition can be exercised, then restores it. These durable tests
// exercise the Shadow mode, which after the readiness split gates on the shadow tier
// (shadowDepsConfigured), so it uses the real Shadow composition hook
// (markGatewayShadowDepsReady) — NOT the live-execution hook, which stays uncalled.
func withExecDepsReady(t *testing.T) {
	t.Helper()
	prev := globalExecDeps.shadowGateway.Load()
	markGatewayShadowDepsReady()
	t.Cleanup(func() { globalExecDeps.shadowGateway.Store(prev) })
}

// withLiveExecDepsReady arms the LIVE-execution tier for the duration of a test so a
// Canary/Production transition can be exercised end to end (evidence-window mechanics).
// It is deliberately SEPARATE from withExecDepsReady: a test that only needs Shadow must
// not arm the live tier, so the readiness split stays honestly exercised. Nothing in
// production ever calls markGatewayExecDepsReady (pinned by the execution-posture wall);
// this is test-only arming to reach the Canary code path.
func withLiveExecDepsReady(t *testing.T) {
	t.Helper()
	prev := globalExecDeps.gateway.Load()
	markGatewayExecDepsReady()
	t.Cleanup(func() { globalExecDeps.gateway.Store(prev) })
}

// Test 8: Shadow activation is blocked fail-closed when execution deps are missing.
func TestDurable_ShadowBlockedWhenExecDepsMissing(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0))
	if err != errShadowExecDepsNotConfigured {
		t.Fatalf("expected exec-deps rejection, got %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("mode must stay Disabled after fail-closed Shadow reject, got %s", r.gateway.CurrentMode())
	}
	if r.gateway.Evidence().ShadowStartUnix != 0 {
		t.Fatal("no Shadow window may be stamped on a rejected transition")
	}
}

// Test 9: a mechanically complete Shadow transition starts the window exactly once.
func TestDurable_ShadowTransitionStartsWindowOnce(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatalf("shadow transition: %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeShadow {
		t.Fatalf("mode should be Shadow, got %s", r.gateway.CurrentMode())
	}
	ev := r.gateway.Evidence()
	if ev.ShadowStartUnix != 1000 {
		t.Fatalf("ShadowStartUnix should be 1000, got %d", ev.ShadowStartUnix)
	}
	if ev.Origin != rollout.OriginProduction {
		t.Fatalf("origin should be production, got %s", ev.Origin)
	}
}

// Test 10: idempotent re-apply of the same accepted mode does not restamp the window.
func TestDurable_IdempotentReapplyDoesNotRestamp(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	// Re-apply the SAME config (same scope) at a later time — window must be preserved.
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(9999, 0)); err != nil {
		t.Fatal(err)
	}
	if got := r.gateway.Evidence().ShadowStartUnix; got != 1000 {
		t.Fatalf("continuous window must be preserved on idempotent reapply, got %d", got)
	}
}

// Test 11/13: restart preserves the exact Shadow window start (soak too).
func TestDurable_RestartPreservesShadowStart(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	orig := r.gateway.Evidence()
	// Reconstruct as production startup would (fresh states + restore from disk).
	r2 := newTestRollout()
	r2.restore()
	if r2.gateway.CurrentMode() != rollout.ModeShadow {
		t.Fatalf("recovered mode should be Shadow, got %s", r2.gateway.CurrentMode())
	}
	rec := r2.gateway.Evidence()
	if rec.ShadowStartUnix != orig.ShadowStartUnix || rec.ShadowStartUnix != 1000 {
		t.Fatalf("recovered ShadowStartUnix mismatch: got %d want %d", rec.ShadowStartUnix, orig.ShadowStartUnix)
	}
	if rec.SoakStartUnix != orig.SoakStartUnix {
		t.Fatalf("recovered soak start mismatch: got %d want %d", rec.SoakStartUnix, orig.SoakStartUnix)
	}
	// Elapsed continues from the ORIGINAL start, not the restart.
	if el := rec.ShadowElapsed(time.Unix(1000+3600, 0)); el != time.Hour {
		t.Fatalf("elapsed should continue from original start (1h), got %s", el)
	}
}

// Test 14: a material scope change resets/invalidates the continuous window.
func TestDurable_ScopeChangeResetsWindow(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1, "s1"), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if got := r.gateway.Evidence().ShadowStartUnix; got != 1000 {
		t.Fatalf("initial window start should be 1000, got %d", got)
	}
	// Expand the scope (add a server) at rev 2 and later time: window MUST reset.
	if err := r.commitRolloutTransition(gwShadowCfg(2, "s1", "s2"), "admin", time.Unix(5000, 0)); err != nil {
		t.Fatal(err)
	}
	if got := r.gateway.Evidence().ShadowStartUnix; got != 5000 {
		t.Fatalf("expanded scope must NOT inherit old window; want restamp 5000, got %d", got)
	}
}

// Test 15: demotion to Observe breaks Shadow continuity (window reset to 0).
func TestDurable_DemotionBreaksContinuity(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := r.commitRolloutTransition(gwObserveCfg(), "admin", time.Unix(2000, 0)); err != nil {
		t.Fatal(err)
	}
	if r.gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatalf("mode should be Observe after demotion, got %s", r.gateway.CurrentMode())
	}
	if got := r.gateway.Evidence().ShadowStartUnix; got != 0 {
		t.Fatalf("demotion must reset Shadow window to 0, got %d", got)
	}
}

// Test 16: a persistence write failure prevents transition success (fail-closed).
func TestDurable_PersistFailurePreventsTransition(t *testing.T) {
	withExecDepsReady(t)
	// Isolate the global storage-health observer: this test deliberately trips a
	// durable-write failure, which must not pollute the process-global storage
	// counter other tests assert on.
	fileutil.SetWriteFailureObserver(func(string, error) {})
	t.Cleanup(func() { fileutil.SetWriteFailureObserver(noteStorageWriteFailure) })
	// Point dataDir at a path that cannot be written (a nonexistent dir) so
	// AtomicWrite fails deterministically.
	prev := dataDir
	dataDir = "/proc/1/cannot-write-here"
	t.Cleanup(func() { dataDir = prev })
	r := newTestRollout()
	err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0))
	if err == nil {
		t.Fatal("transition must fail when durable persistence fails")
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("mode must roll back to Disabled on persist failure, got %s", r.gateway.CurrentMode())
	}
	if r.gateway.Evidence().ShadowStartUnix != 0 {
		t.Fatal("no window may be stamped when the transition was rejected")
	}
}

// Test 17: corrupt persisted state fails closed (keeps Disabled, never promotes).
func TestDurable_CorruptStateFailsClosed(t *testing.T) {
	withTempDataDir(t)
	// Write garbage to the gateway state file.
	if err := os.WriteFile(rolloutStateFileName(rollout.CapabilityGateway), []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newTestRollout()
	r.restore() // must not panic, must not promote
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("corrupt state must fail closed to Disabled, got %s", r.gateway.CurrentMode())
	}
}

// Test 18: synthetic evidence origin can never be reported as production.
func TestDurable_SyntheticOriginNotProduction(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransitionAt(gwShadowCfg(1), "admin", time.Unix(1000, 0), rollout.OriginSynthetic); err != nil {
		t.Fatal(err)
	}
	if got := r.gateway.Evidence().Origin; got != rollout.OriginSynthetic {
		t.Fatalf("origin must be synthetic, got %s", got)
	}
	if r.gateway.Evidence().Origin == rollout.OriginProduction {
		t.Fatal("synthetic evidence must never be labeled production")
	}
}

// Test 19: Gateway and Management durable state stay isolated across restart.
func TestDurable_CapabilityIsolationAcrossRestart(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	// Observe (non-executing) on Gateway only; Management untouched.
	if err := r.commitRolloutTransition(gwObserveCfg(), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	r2 := newTestRollout()
	r2.restore()
	if r2.gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatalf("gateway should recover Observe, got %s", r2.gateway.CurrentMode())
	}
	if r2.management.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("management must stay Disabled (isolation), got %s", r2.management.CurrentMode())
	}
}

// Test: emergency kill-switch survives restart (durable narrowing).
func TestDurable_KillSwitchSurvivesRestart(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	r.emergencyDisable(rollout.CapabilityGateway, "oncall")
	if !r.gateway.Killed() {
		t.Fatal("kill switch should be engaged")
	}
	r2 := newTestRollout()
	r2.restore()
	if !r2.gateway.Killed() {
		t.Fatal("kill switch must survive restart (a restart cannot silently re-admit)")
	}
	if r2.management.Killed() {
		t.Fatal("management kill switch must not be set (isolation)")
	}
}

// Test 20: the durable-transition machinery cannot weaken Production qualification —
// an executing target (incl. Production) fails closed without execution deps, and the
// status surface always reports production_locked.
func TestDurable_ProductionRemainsLocked(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	// production_locked is always true on the status surface.
	if r.status()["production_locked"] != true {
		t.Fatal("production must always be locked on the status surface")
	}
	// A Production-mode signed config fails closed at the exec-dependency precondition
	// (no partial activation), leaving mode Disabled.
	prodCfg := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeProduction,
		ScopeRevision: 1, Scope: rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{"s1"}},
		ConnectorMode: rollout.ConnectorLocalClient,
	}
	if err := r.commitRolloutTransition(prodCfg, "cp", time.Unix(1000, 0)); err != errShadowExecDepsNotConfigured {
		t.Fatalf("production commit must fail closed on exec deps, got %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("mode must stay Disabled, got %s", r.gateway.CurrentMode())
	}
}

// Test: persistence status is surfaced (fresh/recovered) on the admin status view.
func TestDurable_PersistenceStatusSurfaced(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	r.restore() // no file yet
	gw := r.status()["gateway"].(map[string]any)
	if gw["persistence"] != "fresh" {
		t.Fatalf("expected fresh persistence, got %v", gw["persistence"])
	}
	if err := r.commitRolloutTransition(gwObserveCfg(), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	r2 := newTestRollout()
	r2.restore()
	gw2 := r2.status()["gateway"].(map[string]any)
	if gw2["persistence"] != "recovered" {
		t.Fatalf("expected recovered persistence after restart, got %v", gw2["persistence"])
	}
}

// Test: concurrent durable mutations are serialized (no torn window/persist).
func TestDurable_ConcurrentCommitsSerialized(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Same mode+scope: idempotent; the continuous window must never be torn.
			_ = r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(int64(1000+n), 0))
		}(i)
	}
	wg.Wait()
	if r.gateway.CurrentMode() != rollout.ModeShadow {
		t.Fatalf("mode should be Shadow, got %s", r.gateway.CurrentMode())
	}
	// The window start is one of the injected times and is stable + recoverable.
	start := r.gateway.Evidence().ShadowStartUnix
	if start < 1000 || start > 1007 {
		t.Fatalf("window start out of expected range: %d", start)
	}
	r2 := newTestRollout()
	r2.restore()
	if got := r2.gateway.Evidence().ShadowStartUnix; got != start {
		t.Fatalf("recovered window start %d != persisted %d", got, start)
	}
}

// Test (Finding A): a concurrent kill-switch toggle storm plus restart never loses a
// final emergency-disable. durableMu serializes the whole mutate+persist of every
// durable path, so the last durable write reflects the last-acquiring writer.
func TestDurable_KillSwitchToggleStormThenRestart(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				r.emergencyDisable(rollout.CapabilityGateway, "oncall")
			} else {
				r.clearEmergency(rollout.CapabilityGateway)
			}
		}(i)
	}
	wg.Wait()
	// Drive a definitive final state: engage last, serialized by durableMu.
	r.emergencyDisable(rollout.CapabilityGateway, "oncall")
	if !r.gateway.Killed() {
		t.Fatal("final in-memory state must be killed")
	}
	// The durable file must match the final in-memory state (no stale last-write).
	r2 := newTestRollout()
	r2.restore()
	if !r2.gateway.Killed() {
		t.Fatal("Finding A: restart must recover the final emergency-disable, not a stale clear")
	}
}

// Test (Finding C): a hand-crafted state file claiming an executing mode is clamped
// to Disabled at restore when execution deps are not configured.
func TestDurable_RestoreClampsExecutingModeWithoutDeps(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t) // allow persisting a Shadow state first
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	// Now simulate the shipped build (no shadow deps) and restart: the persisted Shadow
	// mode must be clamped to Disabled (fail-closed), not surfaced as executing.
	globalExecDeps.shadowGateway.Store(false)
	r2 := newTestRollout()
	r2.restore()
	if r2.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("restored executing mode must be clamped to Disabled without exec deps, got %s", r2.gateway.CurrentMode())
	}
	gw := r2.status()["gateway"].(map[string]any)
	if gw["persistence"] != "degraded" {
		t.Fatalf("clamped restore should report degraded persistence, got %v", gw["persistence"])
	}
}

// Test: the Management capability exec-deps gate works via its real production hook.
func TestDurable_ManagementExecDepsGate(t *testing.T) {
	withTempDataDir(t)
	r := newTestRollout()
	mgShadow := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityManagement, Mode: rollout.ModeShadow,
		ScopeRevision: 1, Scope: rollout.ScopeSpec{Capability: rollout.CapabilityManagement, Servers: []string{"m1"}},
	}
	// Without management exec deps: fail closed.
	if err := r.commitRolloutTransition(mgShadow, "cp", time.Unix(1000, 0)); err != errShadowExecDepsNotConfigured {
		t.Fatalf("management shadow must fail closed without deps, got %v", err)
	}
	// With management shadow deps (real hook): the transition proceeds.
	prev := globalExecDeps.shadowManagement.Load()
	markManagementShadowDepsReady()
	t.Cleanup(func() { globalExecDeps.shadowManagement.Store(prev) })
	if err := r.commitRolloutTransition(mgShadow, "cp", time.Unix(2000, 0)); err != nil {
		t.Fatalf("management shadow with deps: %v", err)
	}
	if r.management.CurrentMode() != rollout.ModeShadow {
		t.Fatalf("management mode should be Shadow, got %s", r.management.CurrentMode())
	}
	// Gateway stays Disabled (isolation).
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("gateway must stay Disabled (isolation), got %s", r.gateway.CurrentMode())
	}
}

func gwCanaryCfg(rev uint64, servers ...string) *rollout.SignedConfig {
	if len(servers) == 0 {
		servers = []string{"s1"}
	}
	return &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeCanary,
		ScopeRevision: rev,
		Scope:         rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: servers},
		ConnectorMode: rollout.ConnectorLocalClient,
	}
}

// Test (Codex P1 #1): re-entering Shadow from Canary starts a FRESH Shadow window;
// two disjoint Shadow periods are never treated as one continuous window.
func TestDurable_ShadowWindowRestartsAfterCanaryDemotion(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)     // shadow tier — for the Shadow legs
	withLiveExecDepsReady(t) // live tier — this test also exercises the Canary leg
	r := newTestRollout()
	// Shadow at t=1000.
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	// Promote to Canary at t=2000: Shadow evidence preserved for the promotion gate.
	if err := r.commitRolloutTransition(gwCanaryCfg(2), "admin", time.Unix(2000, 0)); err != nil {
		t.Fatal(err)
	}
	if r.gateway.Evidence().ShadowStartUnix != 1000 {
		t.Fatalf("Shadow evidence must be preserved across Shadow->Canary, got %d", r.gateway.Evidence().ShadowStartUnix)
	}
	// Demote back to Shadow at t=9000: the Shadow window MUST restart (not inherit 1000).
	if err := r.commitRolloutTransition(gwShadowCfg(3), "admin", time.Unix(9000, 0)); err != nil {
		t.Fatal(err)
	}
	if got := r.gateway.Evidence().ShadowStartUnix; got != 9000 {
		t.Fatalf("re-entering Shadow from Canary must start a fresh window (9000), got %d", got)
	}
	if got := r.gateway.Evidence().CanaryStartUnix; got != 0 {
		t.Fatalf("Canary window must clear when demoting to Shadow, got %d", got)
	}
}

// Test (Codex P2 #3): an idempotent same-mode same-scope re-apply preserves the soak
// timer (repeated ConfigSnapshot delivery must not reset the 24h soak).
func TestDurable_SoakPreservedOnIdempotentReapply(t *testing.T) {
	withTempDataDir(t)
	withExecDepsReady(t)
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	soak0 := r.gateway.Evidence().SoakStartUnix
	if soak0 != 1000 {
		t.Fatalf("soak start should be 1000, got %d", soak0)
	}
	// Repeated idempotent delivery at much later times must NOT reset the soak.
	for _, ts := range []int64{2000, 50000, 90000} {
		if err := r.commitRolloutTransition(gwShadowCfg(1), "admin", time.Unix(ts, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.gateway.Evidence().SoakStartUnix; got != soak0 {
		t.Fatalf("idempotent re-apply must preserve soak start %d, got %d", soak0, got)
	}
	if got := r.gateway.Evidence().ShadowStartUnix; got != 1000 {
		t.Fatalf("idempotent re-apply must preserve shadow window, got %d", got)
	}
}

// Test (Codex P1 #2): an emergency-disable persist failure is reported, not silently
// treated as durable success; the in-memory disable stays engaged.
func TestDurable_EmergencyDisablePersistFailureReported(t *testing.T) {
	fileutil.SetWriteFailureObserver(func(string, error) {})
	t.Cleanup(func() { fileutil.SetWriteFailureObserver(noteStorageWriteFailure) })
	prev := dataDir
	dataDir = "/proc/1/cannot-write-here"
	t.Cleanup(func() { dataDir = prev })
	r := newTestRollout()
	err := r.emergencyDisable(rollout.CapabilityGateway, "oncall")
	if err == nil {
		t.Fatal("emergency-disable with failed persistence must return an error (not silent success)")
	}
	if !r.gateway.Killed() {
		t.Fatal("the in-memory disable must remain engaged even when persistence fails (fail-safe)")
	}
}
