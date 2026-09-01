package main

import (
	"math"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// The readiness split (docs/design/mcp/SHADOW-ACTIVATION.md §3). After Layer B (#1226)
// Shadow readiness and live-execution readiness are SEPARATE tiers with a strict,
// load-bearing invariant:
//
//	Shadow readiness MUST NOT imply live-execution readiness.
//	Live-execution readiness MUST NOT become true merely because Shadow is available.
//
// These are the security boundary that lets Shadow be activated on a controlled node
// while every Canary/Production transition stays fail-closed. Each assertion below is
// verified by a mutation that COMPILES and CHANGES BEHAVIOUR (see the mutation notes).

// resetExecDeps clears both tiers for both capabilities and restores them after the
// test, so an ordering/shuffle never leaks a set flag into another test.
func resetExecDeps(t *testing.T) {
	t.Helper()
	sg := globalExecDeps.shadowGateway.Load()
	sm := globalExecDeps.shadowManagement.Load()
	lg := globalExecDeps.gateway.Load()
	lm := globalExecDeps.management.Load()
	globalExecDeps.shadowGateway.Store(false)
	globalExecDeps.shadowManagement.Store(false)
	globalExecDeps.gateway.Store(false)
	globalExecDeps.management.Store(false)
	t.Cleanup(func() {
		globalExecDeps.shadowGateway.Store(sg)
		globalExecDeps.shadowManagement.Store(sm)
		globalExecDeps.gateway.Store(lg)
		globalExecDeps.management.Store(lm)
	})
}

// TestReadinessSplit_ShadowDoesNotImplyLive is the core invariant: arming the shadow
// tier must NOT arm the live tier. Mutation: making markGatewayShadowDepsReady also
// set globalExecDeps.gateway fails this test.
func TestReadinessSplit_ShadowDoesNotImplyLive(t *testing.T) {
	resetExecDeps(t)
	markGatewayShadowDepsReady()
	if !shadowDepsConfigured(false) {
		t.Fatal("shadow tier should be armed")
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: arming shadow readiness must NOT arm live-execution readiness")
	}
	// Shadow may now transition; Canary/Production must still fail closed.
	if !modeExecReady(rollout.ModeShadow, false) {
		t.Fatal("Shadow must be admissible once shadow deps are ready")
	}
	if modeExecReady(rollout.ModeCanary, false) || modeExecReady(rollout.ModeProduction, false) {
		t.Fatal("SECURITY: Canary/Production must stay fail-closed with only shadow deps armed")
	}
}

// TestReadinessSplit_LiveDoesNotImplyShadowAndViceVersa pins the reverse and the
// capability isolation. Mutation: collapsing the two tiers into one flag fails here.
func TestReadinessSplit_LiveDoesNotImplyShadowAndViceVersa(t *testing.T) {
	resetExecDeps(t)
	// Arming the live tier alone (the future live composition) does not read the shadow
	// flag; both predicates answer only their own tier.
	markGatewayExecDepsReady()
	if !liveExecDepsConfigured(false) {
		t.Fatal("live tier should be armed")
	}
	// Live composition would arm shadow too in reality, but the FLAGS are independent:
	// the live hook must not set the shadow flag as a side effect.
	if shadowDepsConfigured(false) {
		t.Fatal("live-exec hook must not set the shadow flag as a side effect")
	}
}

// TestReadinessSplit_CapabilityIsolation pins that Gateway readiness never satisfies a
// Management gate and vice versa. Mutation: making shadowDepsConfigured ignore its
// capability argument fails here.
func TestReadinessSplit_CapabilityIsolation(t *testing.T) {
	resetExecDeps(t)
	markGatewayShadowDepsReady()
	if !shadowDepsConfigured(false) {
		t.Fatal("gateway shadow tier should be armed")
	}
	if shadowDepsConfigured(true) {
		t.Fatal("SECURITY: gateway shadow readiness must not satisfy a Management gate")
	}
	if modeExecReady(rollout.ModeShadow, true) {
		t.Fatal("SECURITY: Management Shadow must fail closed when only Gateway is armed")
	}
}

// TestReadinessSplit_ManagementLiveHookIsCapabilityLocal pins the Management symmetry of
// the split: the LIVE Management arming hook arms ONLY the live Management tier — it does
// not arm the shadow tier, the Gateway tier, or make a Management Shadow transition
// succeed. Mutation: making markManagementExecDepsReady also set shadowManagement (or
// gateway) fails here.
func TestReadinessSplit_ManagementLiveHookIsCapabilityLocal(t *testing.T) {
	resetExecDeps(t)
	markManagementExecDepsReady()
	if !liveExecDepsConfigured(true) {
		t.Fatal("management live tier should be armed")
	}
	if shadowDepsConfigured(true) {
		t.Fatal("the live Management hook must not arm the Management shadow tier")
	}
	if liveExecDepsConfigured(false) || shadowDepsConfigured(false) {
		t.Fatal("the Management hook must not arm any Gateway tier")
	}
	// A Management Shadow transition still fails closed (it needs the shadow tier).
	if modeExecReady(rollout.ModeShadow, true) {
		t.Fatal("SECURITY: Management Shadow must fail closed with only the live tier armed")
	}
}

// TestReadinessSplit_ModeExecReadyDefaults pins that Disabled/Observe need no readiness
// tier (they never touch the execution plane) while an executing mode does.
func TestReadinessSplit_ModeExecReadyDefaults(t *testing.T) {
	resetExecDeps(t)
	// Nothing armed.
	if !modeExecReady(rollout.ModeDisabled, false) || !modeExecReady(rollout.ModeObserve, false) {
		t.Fatal("Disabled/Observe must be ready with no execution deps")
	}
	if modeExecReady(rollout.ModeShadow, false) {
		t.Fatal("Shadow must fail closed with nothing armed")
	}
	if modeExecReady(rollout.ModeCanary, false) {
		t.Fatal("Canary must fail closed with nothing armed")
	}
}

// TestReadinessSplit_UnknownModeFailsClosed pins that modeExecReady never hands the
// "no readiness tier needed" answer to a mode it does not recognise.
//
// The gate used to answer with a bare `default: return true`, so ANY Mode value that was
// neither Canary/Production nor Shadow — including one outside the five-token taxonomy —
// was admitted without proving a readiness tier. Nothing exploited it (every caller
// re-validates the mode downstream: SignedConfig.Validate rejects !Mode.Valid(),
// rollout.Resolve blocks an unknown mode, and the admin surface parses through
// ParseMode), but a readiness GATE whose default arm is "admit" is exactly the shape a
// later refactor turns into a real hole, and a newly-added rollout.Mode would have been
// silently admitted rather than failing closed until it was explicitly classified.
//
// Mutation: restoring `default: return true` fails this test.
func TestReadinessSplit_UnknownModeFailsClosed(t *testing.T) {
	resetExecDeps(t)
	// Every mode value the taxonomy does NOT claim must fail closed. rollout.Mode is a
	// uint8, so the 256 candidates are exhaustively enumerable and Mode.Valid() — which
	// answers from the package's own modeToken registry — is the authority on which of
	// them are real. Deriving the unknown set this way (rather than hardcoding a magic
	// value) keeps the test correct if the taxonomy ever grows into the value it used to
	// pick. With nothing armed...
	unknown := invalidModes(t)
	assertUnknownModesFailClosed(t, unknown)
	// ...and still not once BOTH readiness tiers are armed, for both capabilities: an
	// unknown mode has no tier to satisfy, so no amount of composition admits it.
	markGatewayShadowDepsReady()
	markManagementShadowDepsReady()
	markGatewayExecDepsReady()
	markManagementExecDepsReady()
	assertUnknownModesFailClosed(t, unknown)
	// Every VALID mode keeps its prior answer with everything armed, so the hardening is
	// behaviour-preserving for the whole real taxonomy, whatever that taxonomy contains.
	for _, m := range validModes(t) {
		if !modeExecReady(m, false) {
			t.Fatalf("mode %s must be ready with every tier armed", m.String())
		}
	}
}

// eachMode calls fn once for every value in rollout.Mode's domain.
//
// The counter is a uint8, not an int: rollout.Mode's underlying type is uint8, so
// rollout.Mode(v) here converts between two uint8-width types and narrows nothing,
// whereas the int form is an int -> uint8 conversion the lint gate rejects as a
// potential integer overflow (gosec G115) even though 0..255 provably fits. Removing
// the conversion is preferred over a #nosec suppression — the same direction
// rollout.bucketHasSurvivingKey takes when it widens to int to avoid the mirror-image
// narrowing. It cannot be written `for v := uint8(0); v <= 255; v++`, which wraps and
// never terminates, so the exit test is on the last value instead.
func eachMode(fn func(rollout.Mode)) {
	for v := uint8(0); ; v++ {
		fn(rollout.Mode(v))
		if v == math.MaxUint8 {
			return
		}
	}
}

// validModes returns every rollout.Mode the package's own taxonomy claims, derived by
// exhausting the uint8 domain and asking Mode.Valid(). It is the authoritative list: a
// mode added to rollout's modeToken registry appears here with no edit to this file,
// which is what makes the completeness gate below a real signal rather than a
// self-fulfilling loop over a hand-copied table (Codex P2, PR #1240).
func validModes(t *testing.T) []rollout.Mode {
	t.Helper()
	var out []rollout.Mode
	eachMode(func(m rollout.Mode) {
		if m.Valid() {
			out = append(out, m)
		}
	})
	if len(out) == 0 {
		t.Fatal("test premise broken: the rollout taxonomy claims no modes at all")
	}
	return out
}

// invalidModes returns every value in the domain the taxonomy does NOT claim.
func invalidModes(t *testing.T) []rollout.Mode {
	t.Helper()
	var out []rollout.Mode
	eachMode(func(m rollout.Mode) {
		if !m.Valid() {
			out = append(out, m)
		}
	})
	if len(out) == 0 {
		t.Fatal("test premise broken: every uint8 is a valid mode, so there is no unknown to test")
	}
	return out
}

// assertUnknownModesFailClosed requires modeExecReady to refuse every unrecognised mode
// for both capabilities, whatever readiness tiers are armed.
func assertUnknownModesFailClosed(t *testing.T, unknown []rollout.Mode) {
	t.Helper()
	for _, m := range unknown {
		if modeExecReady(m, false) || modeExecReady(m, true) {
			t.Fatalf("SECURITY: unrecognised rollout mode %d must fail closed", m)
		}
	}
}

// TestReadinessSplit_EveryValidModeIsExplicitlyClassified pins the completeness half:
// every mode in the real taxonomy must reach one of the three NAMED arms in
// modeExecReady, never the fail-closed default. Without it, adding a rollout.Mode and
// forgetting to classify it would fail closed SILENTLY — safe, but surfacing as an
// unexplained rollout-transition rejection in production rather than a red build.
//
// The expectation table is checked AGAINST the authoritative taxonomy first (Codex P2,
// PR #1240). Iterating the hand-written table alone would have made this gate
// self-fulfilling: a sixth mode added to rollout's modeToken registry but omitted from
// modeExecReady would keep the test green, since the table it walks would not know the
// mode exists. Driving the loop from validModes() — derived by exhausting the uint8
// domain against Mode.Valid() — means a new mode fails HERE until it is deliberately
// classified in both places, which is the build-time signal this test claims to be.
//
// With nothing armed the answer separates the arms exactly: Disabled/Observe need no
// tier (ready), every executing mode needs one (not ready).
func TestReadinessSplit_EveryValidModeIsExplicitlyClassified(t *testing.T) {
	resetExecDeps(t)
	needsTier := map[rollout.Mode]bool{
		rollout.ModeDisabled:   false,
		rollout.ModeObserve:    false,
		rollout.ModeShadow:     true,
		rollout.ModeCanary:     true,
		rollout.ModeProduction: true,
	}
	for _, m := range validModes(t) {
		wantTier, classified := needsTier[m]
		if !classified {
			t.Fatalf("rollout mode %q is in the taxonomy but this test does not classify it: "+
				"classify it in modeExecReady (a named arm, never the fail-closed default) and add it here",
				m.String())
		}
		if got := modeExecReady(m, false); got == wantTier {
			t.Fatalf("mode %s: with nothing armed modeExecReady=%v; a mode that needs a tier must be false and one that does not must be true",
				m.String(), got)
		}
	}
	// The reverse direction: the table must not claim a mode the taxonomy dropped, or a
	// removed mode would keep a stale expectation alive.
	if len(needsTier) != len(validModes(t)) {
		t.Fatalf("expectation table has %d modes but the taxonomy claims %d; a mode was added or removed",
			len(needsTier), len(validModes(t)))
	}
}
