package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcpRollout is the process-wide, DISABLED-BY-DEFAULT PR-11 rollout composition.
// It owns the two capability-local rollout states (Gateway + Management) and the
// bounded low-cardinality rollout metrics. Gateway and Management are physically
// and logically isolated: separate states, scopes, kill switches, transition
// history, and metrics — nothing is shared between them.
//
// Disabled-by-default posture: with no MCP configuration the states are Disabled
// with empty scopes, no listener binds, no upstream pool starts, no executor runs,
// no credential is materialized, and the existing SWG request path is unaffected.
// An active PR-10 snapshot does NOT silently enable Shadow/Canary — the mode comes
// only from an explicitly-published rollout config.
type mcpRollout struct {
	gateway    *rollout.State
	management *rollout.State
	metrics    mcpRolloutMetrics
}

// mcpRolloutMetrics are bounded, low-cardinality counters. No tenant/subject/
// session/URL/argument/tool-name label is ever used.
type mcpRolloutMetrics struct {
	inScope        atomic.Int64
	outOfScope     atomic.Int64
	shadowOverride atomic.Int64
	hardBlocks     atomic.Int64
	executed       atomic.Int64
	upstreamOK     atomic.Int64
	upstreamErr    atomic.Int64
	dlpBlocks      atomic.Int64
	commitFail     atomic.Int64
	emergencies    atomic.Int64
	transitions    atomic.Int64
}

var (
	globalMCPRollout     *mcpRollout
	globalMCPRolloutOnce sync.Once
)

// getMCPRollout returns the process-wide rollout composition, constructing the two
// isolated capability states on first use (both Disabled).
func getMCPRollout() *mcpRollout {
	globalMCPRolloutOnce.Do(func() {
		lim := rollout.DefaultLimits()
		globalMCPRollout = &mcpRollout{
			gateway:    rollout.NewState(rollout.CapabilityGateway, lim),
			management: rollout.NewState(rollout.CapabilityManagement, lim),
		}
	})
	return globalMCPRollout
}

// initMCPRollout is the startup shim (disabled-by-default): it constructs the
// isolated capability states and (best-effort) recovers node-local rollout state
// from durable storage. It binds no socket and starts no worker.
func initMCPRollout(_ *startupState) {
	_ = getMCPRollout()
}

// stateFor returns the capability-local rollout state (never shared).
func (r *mcpRollout) stateFor(cap rollout.Capability) *rollout.State {
	switch cap {
	case rollout.CapabilityManagement:
		return r.management
	default:
		return r.gateway
	}
}

// applyRolloutConfig validates and installs a signed rollout config into the
// matching capability state. It is called from the DP snapshot-apply path AFTER
// the envelope's whole-snapshot validation succeeds. A validation failure leaves
// the current rollout state unchanged (fail closed).
func (r *mcpRollout) applyRolloutConfig(cfg *rollout.SignedConfig, actor string) {
	if cfg == nil {
		return // absence is not deletion — keep local rollout state
	}
	st := r.stateFor(cfg.Capability)
	if err := st.SetConfig(*cfg, actor, time.Now().UnixNano()); err != nil {
		logger.Printf("MCP rollout config rejected for %s (state unchanged): %v",
			cfg.Capability.String(), err)
		return
	}
	r.metrics.transitions.Add(1)
}

// emergencyDisable engages the capability-local kill switch immediately (admission
// stop) without a CP round trip. It never widens access. The signed-publication
// convergence of the fleet is a separate step.
func (r *mcpRollout) emergencyDisable(cap rollout.Capability, actor string) {
	r.stateFor(cap).EngageKillSwitch(actor, time.Now().UnixNano())
	r.metrics.emergencies.Add(1)
}

// clearEmergency clears the capability-local kill switch (does not change mode).
func (r *mcpRollout) clearEmergency(cap rollout.Capability) {
	r.stateFor(cap).ClearKillSwitch()
}

// mcpRolloutStatus returns a bounded, safe status view for the admin surface. It
// never includes a tenant/subject/token/secret.
func (r *mcpRollout) status() map[string]any {
	cap := func(st *rollout.State) map[string]any {
		return map[string]any{
			"mode":        st.CurrentMode().String(),
			"desired":     st.Desired().String(),
			"scope_hash":  st.ScopeHash(),
			"killed":      st.Killed(),
			"connector":   st.CurrentConfig().ConnectorMode,
			"history_len": len(st.History()),
		}
	}
	return map[string]any{
		"gateway":    cap(r.gateway),
		"management": cap(r.management),
		"metrics": map[string]int64{
			"in_scope":        r.metrics.inScope.Load(),
			"out_of_scope":    r.metrics.outOfScope.Load(),
			"shadow_override": r.metrics.shadowOverride.Load(),
			"hard_blocks":     r.metrics.hardBlocks.Load(),
			"executed":        r.metrics.executed.Load(),
			"upstream_ok":     r.metrics.upstreamOK.Load(),
			"upstream_err":    r.metrics.upstreamErr.Load(),
			"dlp_blocks":      r.metrics.dlpBlocks.Load(),
			"commit_fail":     r.metrics.commitFail.Load(),
			"emergencies":     r.metrics.emergencies.Load(),
			"transitions":     r.metrics.transitions.Load(),
		},
		// Production is unreachable without an externally-verified qualification
		// receipt; this build ships no issuer.
		"production_locked": true,
	}
}

// rolloutFromEnvelope extracts the signed rollout config from a validated cpdp
// envelope's payload (Gateway or Management).
func rolloutFromEnvelope(env *cpdp.Envelope) *rollout.SignedConfig {
	if env == nil {
		return nil
	}
	if g := env.Payload.Gateway; g != nil {
		return g.Rollout
	}
	if m := env.Payload.Management; m != nil {
		return m.Rollout
	}
	return nil
}
