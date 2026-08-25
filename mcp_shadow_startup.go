package main

// Controlled Shadow activation — production composition of the NON-EXECUTING Shadow
// evaluator (docs/design/mcp/SHADOW-ACTIVATION.md §4).
//
// This is the ONLY production file that imports internal/mcp/execution. It composes a
// *execution.ShadowEvaluator — the capability-reduced object from Layer B (#1226) that
// structurally holds NO UpstreamCaller and NO materialize-capable broker — and injects
// it as runtime.Deps.Executor so an in-scope Shadow request is EVALUATED (formal
// Model-1 ShadowDecision + durable evidence) while remaining incapable of an upstream
// side effect or credential materialization.
//
// It deliberately composes NO live *execution.Executor, NO upstream client, and NO
// materialize-capable broker, and it NEVER calls markGatewayExecDepsReady (the
// live-execution arming hook stays uncalled, pinned by the execution-posture wall). It
// arms ONLY the shadow readiness tier via markGatewayShadowDepsReady.
//
// Disabled by default (fail-closed): composition happens ONLY when the operator
// explicitly opts in via CULVERT_MCP_SHADOW_READY. Unset/false ⇒ nil executor ⇒ the
// runtime keeps its byte-identical Observe/SWG path. A missing required dependency
// (durable events) also fails closed to a nil executor.

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpShadowReadyEnvVar is the explicit, operator-controlled opt-in for composing the
// non-executing Shadow evaluator on this node. Startup-scoped, read once. Default OFF.
const mcpShadowReadyEnvVar = "CULVERT_MCP_SHADOW_READY"

// mcpShadowActor labels the durable evidence the Shadow evaluator emits.
const mcpShadowActor = "mcp-gateway-shadow"

// mcpShadowComposition records, for the read-only health/status surface, whether the
// Shadow evaluator was composed this boot and why not when it was requested. It is
// node-local, set once at startup, and never a secret.
type mcpShadowComposition struct {
	// composed is true once the ShadowEvaluator is injected as Deps.Executor.
	composed atomic.Bool
	// requested is true when CULVERT_MCP_SHADOW_READY opted in (even if composition
	// then failed closed), so the health surface can distinguish "not asked for" from
	// "asked for but a dependency was missing".
	requested atomic.Bool
	// reason is a bounded, fixed classification code (never a secret/path/raw error).
	reasonMu sync.Mutex
	reason   string
}

var globalMCPShadow = &mcpShadowComposition{}

func (c *mcpShadowComposition) setReason(s string) {
	c.reasonMu.Lock()
	c.reason = s
	c.reasonMu.Unlock()
}

// Reason returns the bounded classification of the last composition outcome.
func (c *mcpShadowComposition) Reason() string {
	c.reasonMu.Lock()
	defer c.reasonMu.Unlock()
	if c.reason == "" {
		return "not_requested"
	}
	return c.reason
}

// mcpShadowStatus builds the bounded, read-only Shadow status for the admin surface. It
// distinguishes the three postures an operator must be able to tell apart (§13): the
// Gateway listener, the non-executing Shadow capability, and LIVE execution — which is
// ALWAYS unarmed in this build. It carries no secret, tenant, subject, or raw error;
// only fixed classification codes, booleans, and the bounded metric snapshot.
func mcpShadowStatus() map[string]any {
	m := map[string]any{
		// The non-executing Shadow evaluation capability.
		"evaluator_composed": globalMCPShadow.composed.Load(),
		"requested":          globalMCPShadow.requested.Load(),
		"reason":             globalMCPShadow.Reason(),
		"shadow_deps_ready":  shadowDepsConfigured(false),
		// LIVE execution readiness — Canary/Production only, never composed in this build.
		// Surfaced so an operator can confirm the shadow-vs-live split holds on the node.
		"live_execution_ready": liveExecDepsConfigured(false),
		// The §14 operator dry-run: is this node ready to activate Shadow right now?
		"preflight": evaluateShadowActivationPreflight(rollout.CapabilityGateway),
	}
	if snap := mcpShadowMetricsSnapshotOrNil(); snap != nil {
		m["metrics"] = snap.snapshot()
	}
	return m
}

// mcpShadowReadyEnabled reports whether the operator explicitly opted this node into
// Shadow readiness. Fail-safe default-OFF: only an explicit true-ish value enables it
// (same convention as CULVERT_EXPERIMENTAL_UI / CULVERT_CLUSTER_GRPC_COMPRESSION).
func mcpShadowReadyEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(mcpShadowReadyEnvVar))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// composeGatewayShadowIntoConfig composes the non-executing Shadow evaluator and, on
// success, installs it as cfg.Deps.Executor. It is fail-closed at every branch: when
// Shadow readiness is disabled or a required dependency is missing it leaves
// cfg.Deps.Executor untouched (nil ⇒ the byte-identical Observe posture) and records the
// bounded reason for the health surface. Installing the executor HERE keeps this file
// the single production assignment site of Deps.Executor and the single importer of the
// execution package, which the evolved execution-posture wall pins.
//
// The evaluator receives ONLY non-side-effect dependencies: the Gateway rollout State,
// the durable Events manager, bounded Shadow metrics, and a clock/actor. It receives NO
// UpstreamCaller and NO materialize-capable broker (the ShadowConfig type cannot carry
// either — Layer B), and NO CredentialPlanner in this build (no broker is composed, so
// credential readiness is honestly reported as not-evaluated). On success it arms ONLY
// the shadow readiness tier — never the live-execution tier.
func composeGatewayShadowIntoConfig(cfg *mcpruntime.Config, shadowReady bool, evMgr *events.Manager) {
	if cfg == nil || !shadowReady {
		globalMCPShadow.requested.Store(false)
		globalMCPShadow.setReason("not_requested")
		return
	}
	globalMCPShadow.requested.Store(true)
	// Shadow requires durable events (evidence-before-report is mandatory). Without the
	// telemetry manager composed, fail closed (leave the executor nil) rather than
	// compose a Shadow path that cannot record what it evaluated.
	if evMgr == nil {
		globalMCPShadow.setReason("durable_events_unavailable")
		logger.Printf("MCP gateway shadow not composed: durable telemetry (events) is not configured; shadow requires it (fail-closed to Observe)")
		return
	}
	ev, err := execution.NewShadowEvaluator(execution.ShadowConfig{
		State:  getMCPRollout().gateway,
		Events: evMgr,
		// The bounded Shadow metrics singleton is constructed HERE (only when actually
		// composing), so a node that never armed Shadow exposes no shadow series.
		Metrics: newMCPShadowMetrics(),
		Actor:   mcpShadowActor,
		// Clock: nil ⇒ time.Now. Planner: nil ⇒ no credential planning capability is
		// composed (no broker in this build), so credential readiness reports
		// not-evaluated. NO Upstream, NO materialize-capable broker — the ShadowConfig
		// type structurally cannot carry either (Layer B).
	})
	if err != nil {
		globalMCPShadow.setReason("evaluator_construct_failed")
		logger.Printf("MCP gateway shadow not composed: evaluator construction failed (fail-closed to Observe): %v", sanitizeLog(err.Error()))
		return
	}
	// Install the evaluator as the runtime executor. It is a non-nil concrete pointer, so
	// the runtime's `deps.Executor != nil` guard reads it correctly (no nil-interface trap).
	cfg.Deps.Executor = ev
	// Arm ONLY the shadow readiness tier — never the live-execution tier. This is what
	// lets a Shadow transition be admitted while every Canary/Production transition
	// stays fail-closed (mcp_rollout_execdeps.go).
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	globalMCPShadow.setReason("composed")
	logger.Printf("MCP gateway shadow evaluator composed (non-executing; no upstream client, no credential materialization). Shadow may be activated for a bounded scope.")
}
