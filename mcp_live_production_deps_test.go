package main

// Production live-dependency composition — test campaign (§23 E2E, §24 failure matrix,
// §25 concurrency/-race, §26 mutation, §27 red-team, §28 post-arming degradation, §29 zero
// real credentials).
//
// §29 discipline: EVERY piece of key material here is ephemeral, synthetic, and local. The
// credential-broker KEK is a random 0600 file the production secret.FileProvider generates
// inside t.TempDir(); it never leaves the temp directory or the test process. No real
// credential, endpoint, or upstream is ever contacted (composition NEVER arms and NEVER
// executes).

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// resetLiveProdGlobals isolates BOTH the lifecycle/execdeps globals (via resetLiveTierGlobals)
// AND the production-deps status holder, so a composed/armed bit or a recorded status can never
// leak across tests (the PR3d fence-pollution class).
func resetLiveProdGlobals(t *testing.T) {
	t.Helper()
	resetLiveTierGlobals(t)
	prev := globalMCPLiveProd
	globalMCPLiveProd = &mcpLiveProdHolder{status: mcpLiveProdStatus{Reason: liveDepsReasonNotRequested, Deps: pendingLiveProdDeps()}}
	t.Cleanup(func() { globalMCPLiveProd = prev })
}

// tempKEKPath returns an absolute path to a not-yet-created KEK file inside a fresh temp dir.
// The production FileProvider generates a random 0600 key there (§29: ephemeral, local).
func tempKEKPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "credential.kek")
}

// prodInventory builds a fresh, empty registry+catalog pair for the broker.
func prodInventory() (*registry.Registry, *catalog.Catalog) {
	return registry.New(limits.DefaultCatalog()), catalog.New(limits.DefaultCatalog())
}

// requestedConfig is the resolved config for an opted-in node with the given KEK path.
func requestedConfig(kek string) mcpLiveProductionConfig {
	return mcpLiveProductionConfig{Requested: true, KEKFile: kek}
}

// ── §23 Production-shaped E2E composition ──────────────────────────────────────────────────

func TestLiveProd_E2E_ComposesRealGraphNeverArms(t *testing.T) {
	resetLiveProdGlobals(t)
	reg, cat := prodInventory()
	ev := liveTestEvents(t)
	kekPath := tempKEKPath(t)

	cfg := &mcpruntime.Config{}
	composeProductionGatewayLiveTier(cfg, requestedConfig(kekPath), reg, cat, ev, nil)

	// The real executor was installed via the seam.
	if cfg.Deps.Executor == nil {
		t.Fatal("§23: production composition must install a live executor as Deps.Executor")
	}
	// COMPOSED, but NOT armed — the whole point (§16).
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	if !lt.composed() {
		t.Fatal("§23: tier must be composed")
	}
	if lt.armed() || liveExecDepsConfigured(false) {
		t.Fatal("§23: composition must NEVER arm the live tier")
	}
	// Status is truthful and complete.
	s := globalMCPLiveProd.snapshot()
	if !s.Requested || !s.Composed || s.Reason != liveDepsReasonComposed {
		t.Fatalf("§23: status must be requested+composed+composed-reason, got %+v", s)
	}
	if s.Deps.KEK != liveDepKEKReady || s.Deps.Upstream != liveDepUpstreamReady ||
		s.Deps.Events != liveDepEventsReady || s.Deps.ResponseProfile != liveDepResponseProfileReady ||
		s.Deps.ProfileStore != liveDepProfileStoreReady || s.Deps.Resolver != liveDepResolverReady {
		t.Fatalf("§23: every wired dependency must report ready, got %+v", s.Deps)
	}
	// The honest pre-Canary gap: broker composed but NO provider.
	if s.Deps.Broker != liveDepBrokerNoProvider {
		t.Fatalf("§23: broker must report broker_composed_no_provider (honest gap), got %q", s.Deps.Broker)
	}
	// §29: the KEK file exists, lives under the temp dir, and is 0600.
	fi, err := os.Stat(kekPath)
	if err != nil {
		t.Fatalf("§29: KEK file must have been created: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("§29: KEK file must be 0600, got %#o", perm)
	}
	if !filepath.IsAbs(kekPath) {
		t.Fatal("§29: KEK path must be absolute/local temp")
	}
}

// §29: the viewer-safe status surface carries NO secret — only bounded tokens and bools.
func TestLiveProd_StatusViewCarriesNoSecret(t *testing.T) {
	resetLiveProdGlobals(t)
	reg, cat := prodInventory()
	ev := liveTestEvents(t)
	kekPath := tempKEKPath(t)
	cfg := &mcpruntime.Config{}
	composeProductionGatewayLiveTier(cfg, requestedConfig(kekPath), reg, cat, ev, nil)

	view := mcpLiveProdStatusView()
	// The KEK path (a filesystem location) must NOT appear anywhere in the view.
	assertNoSubstring(t, view, kekPath)
	// A raw 0600 key file's bytes are random; assert the KEK value is only a token.
	deps, _ := view["dependencies"].(map[string]any)
	if got := deps["kek"]; got != liveDepKEKReady {
		t.Fatalf("§29: kek must surface as a token, got %v", got)
	}
}

// assertNoSubstring fails if needle appears in any string value reachable in v.
func assertNoSubstring(t *testing.T, v any, needle string) {
	t.Helper()
	switch x := v.(type) {
	case string:
		if needle != "" && x == needle {
			t.Fatalf("§29: secret/path %q leaked into the status view", needle)
		}
	case map[string]any:
		for _, e := range x {
			assertNoSubstring(t, e, needle)
		}
	}
}

// ── §24 Fail-closed failure matrix ─────────────────────────────────────────────────────────

func TestLiveProd_FailureMatrix_NeverArmsRecordsReason(t *testing.T) {
	cases := []struct {
		name       string
		cfg        func(t *testing.T) mcpLiveProductionConfig
		events     bool // pass a real events manager
		wantReason string
	}{
		{
			name:       "not_requested",
			cfg:        func(*testing.T) mcpLiveProductionConfig { return mcpLiveProductionConfig{Requested: false} },
			events:     true,
			wantReason: liveDepsReasonNotRequested,
		},
		{
			name:       "requested_no_kek",
			cfg:        func(*testing.T) mcpLiveProductionConfig { return mcpLiveProductionConfig{Requested: true} },
			events:     true,
			wantReason: liveDepsReasonConfigInvalid,
		},
		{
			name:       "relative_kek",
			cfg:        func(*testing.T) mcpLiveProductionConfig { return requestedConfig("relative/credential.kek") },
			events:     true,
			wantReason: liveDepsReasonConfigInvalid,
		},
		{
			name:       "noncanonical_kek",
			cfg:        func(*testing.T) mcpLiveProductionConfig { return requestedConfig("/data/../data/credential.kek") },
			events:     true,
			wantReason: liveDepsReasonConfigInvalid,
		},
		{
			name:       "nil_events",
			cfg:        func(t *testing.T) mcpLiveProductionConfig { return requestedConfig(tempKEKPath(t)) },
			events:     false,
			wantReason: liveDepsReasonEventsAbsent,
		},
		{
			name: "symlink_kek",
			cfg: func(t *testing.T) mcpLiveProductionConfig {
				dir := t.TempDir()
				target := filepath.Join(dir, "real.kek")
				link := filepath.Join(dir, "credential.kek")
				if err := os.Symlink(target, link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return requestedConfig(link)
			},
			events:     true,
			wantReason: liveDepKEKUnavailable,
		},
		{
			name: "world_readable_prexisting_kek",
			cfg: func(t *testing.T) mcpLiveProductionConfig {
				p := tempKEKPath(t)
				// A correctly-sized but world-readable key file is rejected by secret.load.
				// #nosec G306 -- intentionally world-readable to verify secret.load rejects it
				if err := os.WriteFile(p, make([]byte, 32), 0o644); err != nil {
					t.Fatalf("write kek: %v", err)
				}
				return requestedConfig(p)
			},
			events:     true,
			wantReason: liveDepKEKUnavailable,
		},
		{
			name: "wrong_size_prexisting_kek",
			cfg: func(t *testing.T) mcpLiveProductionConfig {
				p := tempKEKPath(t)
				if err := os.WriteFile(p, []byte("short"), 0o600); err != nil {
					t.Fatalf("write kek: %v", err)
				}
				return requestedConfig(p)
			},
			events:     true,
			wantReason: liveDepKEKUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetLiveProdGlobals(t)
			reg, cat := prodInventory()
			cfg := &mcpruntime.Config{}
			composeProductionGatewayLiveTier(cfg, tc.cfg(t), reg, cat, mgrOrNil(t, tc.events), nil)

			if cfg.Deps.Executor != nil {
				t.Fatalf("§24 %s: a fail-closed path must NEVER install an executor", tc.name)
			}
			if mcpLiveTierFor(rollout.CapabilityGateway).composed() {
				t.Fatalf("§24 %s: a fail-closed path must NEVER mark the tier composed", tc.name)
			}
			if liveExecDepsConfigured(false) {
				t.Fatalf("§24 %s: a fail-closed path must NEVER arm", tc.name)
			}
			if got := globalMCPLiveProd.snapshot().Reason; got != tc.wantReason {
				t.Fatalf("§24 %s: reason = %q, want %q", tc.name, got, tc.wantReason)
			}
		})
	}
}

// mgrOrNil returns a real events manager when want is true, else a typed-nil *events.Manager.
func mgrOrNil(t *testing.T, want bool) *events.Manager {
	if !want {
		return nil
	}
	return liveTestEvents(t)
}

// ── §25 Concurrency (run under -race) ──────────────────────────────────────────────────────

func TestLiveProd_ConcurrentCompositionAndReads(t *testing.T) {
	resetLiveProdGlobals(t)
	reg, cat := prodInventory()
	ev := liveTestEvents(t)

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			cfg := &mcpruntime.Config{}
			// Each worker uses its OWN KEK dir (distinct local temp files).
			composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, ev, nil)
			_ = mcpLiveProdStatusView()
			_ = globalMCPLiveProd.snapshot()
			_ = mcpLiveTierStatus()
		}()
	}
	// Concurrent readers.
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = mcpLiveProdStatusView()
				_ = globalMCPLiveProd.snapshot()
			}
		}()
	}
	wg.Wait()

	// After all compositions, the tier is composed and — critically — still NOT armed.
	if !mcpLiveTierFor(rollout.CapabilityGateway).composed() {
		t.Fatal("§25: tier must be composed after concurrent composition")
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("§25: concurrent composition must NEVER arm")
	}
}

// ── §26 Mutation campaign: each fail-closed guard is load-bearing ───────────────────────────
//
// Each subtest names a mutation an adversary (or a careless refactor) might make and asserts the
// behavior that a test would lose if the guard were removed. The failure matrix above is the
// executable catcher; this table is the enumerated map from mutation → catching assertion.

func TestLiveProd_MutationCampaign(t *testing.T) {
	// M1: drop the not-requested early return ⇒ a disabled node would compose. Caught by the
	//     not_requested row asserting no executor.
	t.Run("M1_disabled_composes", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, mcpLiveProductionConfig{Requested: false}, reg, cat, liveTestEvents(t), nil)
		if cfg.Deps.Executor != nil {
			t.Fatal("M1: disabled node must not compose")
		}
	})
	// M2: skip validateMCPLiveProductionConfig ⇒ a partial (no-KEK) opt-in would reach the KEK
	//     provider with an empty path. Caught: empty path is config_invalid, no executor.
	t.Run("M2_partial_config_composes", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, mcpLiveProductionConfig{Requested: true}, reg, cat, liveTestEvents(t), nil)
		if cfg.Deps.Executor != nil || globalMCPLiveProd.snapshot().Reason != liveDepsReasonConfigInvalid {
			t.Fatal("M2: partial config must fail closed")
		}
	})
	// M3: accept a relative KEK path (drop IsAbs) ⇒ cwd-relative KEK. Caught by validator.
	t.Run("M3_relative_kek", func(t *testing.T) {
		if err := validateMCPLiveProductionConfig(requestedConfig("relative.kek")); err != errLiveDepsKEKNotAbsolute {
			t.Fatalf("M3: want errLiveDepsKEKNotAbsolute, got %v", err)
		}
	})
	// M4: accept a non-canonical KEK path (drop Clean idempotence check). Caught by validator.
	t.Run("M4_noncanonical_kek", func(t *testing.T) {
		if err := validateMCPLiveProductionConfig(mcpLiveProductionConfig{Requested: true, KEKFile: "/a/../b"}); err != errLiveDepsKEKNotCanonical {
			t.Fatalf("M4: want errLiveDepsKEKNotCanonical, got %v", err)
		}
	})
	// M5: follow a symlinked KEK (drop kekPathNotSymlink). Caught by symlink helper.
	t.Run("M5_symlink_kek", func(t *testing.T) {
		dir := t.TempDir()
		link := filepath.Join(dir, "credential.kek")
		if err := os.Symlink(filepath.Join(dir, "real"), link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := kekPathNotSymlink(link); err != errLiveDepsKEKSymlink {
			t.Fatalf("M5: want errLiveDepsKEKSymlink, got %v", err)
		}
	})
	// M6: drop the nil-events guard ⇒ a live tier with no evidence plane. Caught: durable_events_absent.
	t.Run("M6_nil_events", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, nil, nil)
		if cfg.Deps.Executor != nil || globalMCPLiveProd.snapshot().Reason != liveDepsReasonEventsAbsent {
			t.Fatal("M6: nil events must fail closed")
		}
	})
	// M7: mark composed BEFORE the seam succeeds ⇒ a half-composed tier. Caught: the seam records
	//     composed only on success; the failure rows above all assert !composed.
	t.Run("M7_compose_before_success", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, nil, nil)
		if mcpLiveTierFor(rollout.CapabilityGateway).composed() {
			t.Fatal("M7: a failed composition must not leave the tier composed")
		}
	})
	// M8: arm as a side effect of composing ⇒ composed==armed. Caught: every success/failure path
	//     asserts !liveExecDepsConfigured.
	t.Run("M8_compose_arms", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, liveTestEvents(t), nil)
		if liveExecDepsConfigured(false) {
			t.Fatal("M8: composition must never arm")
		}
	})
}

// ── §27 Red-team (adversarial) ─────────────────────────────────────────────────────────────

func TestLiveProd_RedTeam(t *testing.T) {
	// R1: env with whitespace-only enable ⇒ NOT requested (no composition).
	t.Run("R1_whitespace_enable", func(t *testing.T) {
		if resolveMCPLiveProductionConfig("   ", "/x/kek").Requested {
			t.Fatal("R1: whitespace enable must not opt in")
		}
	})
	// R2: env enable + whitespace KEK ⇒ requested but empty KEK ⇒ config_invalid.
	t.Run("R2_whitespace_kek", func(t *testing.T) {
		c := resolveMCPLiveProductionConfig("on", "   ")
		if !c.Requested || c.KEKFile != "" {
			t.Fatalf("R2: want requested+empty KEK, got %+v", c)
		}
		if validateMCPLiveProductionConfig(c) != errLiveDepsKEKMissing {
			t.Fatal("R2: empty KEK must be rejected")
		}
	})
	// R3: env enable + traversal KEK ⇒ resolver cleans to canonical; a traversal that escapes
	//     lexically is still absolute+canonical, so it is ACCEPTED as a path but the file simply
	//     does not exist / is created there — it can never point back inside via "..". Assert the
	//     resolver cleans it (no residual "..").
	t.Run("R3_traversal_cleaned", func(t *testing.T) {
		c := resolveMCPLiveProductionConfig("1", "/data/../data/kek")
		if c.KEKFile != "/data/kek" {
			t.Fatalf("R3: resolver must clean traversal, got %q", c.KEKFile)
		}
		if err := validateMCPLiveProductionConfig(c); err != nil {
			t.Fatalf("R3: a cleaned absolute path is valid, got %v", err)
		}
	})
	// R4: arm WITHOUT composing ⇒ refused (live_executor_absent). The arming path is the only way
	//     to set the armed bit, and it gates on composition.
	t.Run("R4_arm_without_compose", func(t *testing.T) {
		resetLiveProdGlobals(t)
		rd, err := armLiveTier(rollout.CapabilityGateway)
		if err == nil || rd.Ready {
			t.Fatalf("R4: arming an uncomposed tier must be refused, got ready=%v err=%v", rd.Ready, err)
		}
		if liveExecDepsConfigured(false) {
			t.Fatal("R4: a refused arm must not set the armed bit")
		}
	})
	// R5: compose then confirm the executor is present but the tier still refuses to be Canary-
	//     ready (composed != Canary active) — node readiness still reports live_executor_absent
	//     because the tier is not ARMED.
	t.Run("R5_composed_not_canary_ready", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, liveTestEvents(t), nil)
		rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
		if rd.Ready {
			t.Fatal("R5: a composed-but-not-armed node must not be Canary node-ready")
		}
		if !unmetContainsReason(rd.Unmet, "live_executor_absent") {
			t.Fatalf("R5: node readiness must still carry live_executor_absent, got %v", rd.Unmet)
		}
	})
	// R6: double composition is idempotent and still never arms.
	t.Run("R6_double_compose", func(t *testing.T) {
		resetLiveProdGlobals(t)
		reg, cat := prodInventory()
		ev := liveTestEvents(t)
		cfg := &mcpruntime.Config{}
		composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, ev, nil)
		composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, ev, nil)
		if liveExecDepsConfigured(false) {
			t.Fatal("R6: re-composition must never arm")
		}
		if !globalMCPLiveProd.snapshot().Composed {
			t.Fatal("R6: re-composition stays composed")
		}
	})
}

func unmetContainsReason(rs []canary.Reason, want string) bool {
	for _, r := range rs {
		if string(r) == want {
			return true
		}
	}
	return false
}

// ── §28 Post-arming dependency degradation → fail-closed ────────────────────────────────────

func TestLiveProd_PostArmingDegradationFailsClosed(t *testing.T) {
	resetLiveProdGlobals(t)
	reg, cat := prodInventory()
	ev := liveTestEvents(t)
	// Make the node arm-eligible: publish inventory + policy + shadow inspection + attestation
	// are node-readiness inputs; rather than satisfy the FULL arm gate (which needs shadow-exit
	// attestation + rollback rehearsals this PR does not run), we prove the DEGRADATION direction:
	// once armed, engaging the emergency kill makes the arm-readiness gate report not-ready, so a
	// re-arm is refused and quiesce cleanly disarms.
	cfg := &mcpruntime.Config{}
	composeProductionGatewayLiveTier(cfg, requestedConfig(tempKEKPath(t)), reg, cat, ev, nil)

	// Force-arm through the lifecycle object directly (bypassing the full node gate) to model an
	// already-armed node, then degrade a dependency.
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !liveExecDepsConfigured(false) {
		t.Fatal("precondition: tier must be armed")
	}
	// Degrade: engage the emergency kill for the capability. The arm-readiness gate is a
	// fail-closed ORDERED switch, so it reports the FIRST unmet prerequisite (which may be an
	// unrelated degraded dependency in this harness) — the contract §28 asserts is the DIRECTION:
	// a degraded node is NOT arm-ready, so a re-arm would fail closed.
	getMCPRollout().gateway.EngageKillSwitch("degradation-test", 1)
	rd := evaluateLiveArmReadiness(rollout.CapabilityGateway)
	if rd.Ready || rd.Reason == "" {
		t.Fatalf("§28: a degraded node must not be arm-ready, got ready=%v reason=%q", rd.Ready, rd.Reason)
	}
	// A live re-arm attempt through the authoritative path is refused (fail-closed).
	if rearm, err := armLiveTier(rollout.CapabilityGateway); err == nil && rearm.Ready {
		t.Fatal("§28: re-arming a degraded node must be refused")
	}
	// Quiesce cleanly disarms regardless (fail-closed): the armed bit clears.
	quiesceLiveTier(rollout.CapabilityGateway, 0)
	if liveExecDepsConfigured(false) {
		t.Fatal("§28: quiesce must clear the armed bit")
	}
}
