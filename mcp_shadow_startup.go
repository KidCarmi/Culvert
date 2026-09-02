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
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// staticGatewayInspection serves one immutable Gateway inspection profile as the runtime
// InspectionProvider. It is read-only and capability-scoped: it answers only for the
// Gateway capability (Management never runs tools/call inspection).
type staticGatewayInspection struct{ prof inspection.Profile }

func (s staticGatewayInspection) InspectionProfile(capNS protocol.Capability) (inspection.Profile, bool) {
	if capNS != protocol.Gateway {
		return inspection.Profile{}, false
	}
	return s.prof, true
}

// mcpShadowReadyEnvVar is the explicit, operator-controlled opt-in for composing the
// non-executing Shadow evaluator on this node. Startup-scoped, read once. Default OFF.
const mcpShadowReadyEnvVar = "CULVERT_MCP_SHADOW_READY"

// mcpShadowActor labels the durable evidence the Shadow evaluator emits.
const mcpShadowActor = "mcp-gateway-shadow"

// shadowCredentialPlannerSeam is the OPTIONAL, disabled-by-default composition seam for the
// Shadow evaluator's metadata-only CredentialPlanner (same startup-scoped seam pattern as
// gatewayListenerReadyProbe / shadowScopeUsableToolProbe). Default nil ⇒ no planner is
// composed, so a shipped build is byte-identical to "no credential planning" and credential
// readiness reports not-evaluated. It is deliberately typed as the Plan-only
// execution.CredentialPlanner interface (which exposes NO Materialize), so installing a
// planner cannot widen the Shadow type graph toward a materializing capability, and the
// evaluator additionally drops the interface after binding its Plan method
// (TestShadow_DoesNotRetainConcretePlanner). Set only by the controlled credential-planning
// evidence run to exercise the real Shadow credential-readiness path.
//
// SCOPE (read before "wiring a real planner here"): unlike the two sibling seams above, which
// carry LIVE production defaults, this one has NO production caller by design — a shipped
// build installs no planner and reports credential readiness not-evaluated. That is
// deliberate: Shadow Exit criterion 8 ("readiness derivable without materialization") is a
// property of the Shadow EVALUATOR — proven, and exercised through THIS production
// composition path, by the controlled evidence run — NOT a requirement that a production
// binary ship credential planning. Composing a deployable production planner is a distinct,
// larger change (real credential-broker composition surface, materialization-adjacent) that
// belongs to the executing-mode / Canary track, not this disabled-by-default Shadow-evidence
// phase, and is intentionally deferred. Installing a planner here in production is a
// deliberate feature decision, never a test convenience.
var shadowCredentialPlannerSeam execution.CredentialPlanner

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
	// inspectionComposed is true once the shadow composition has wired the request
	// inspection provider (Deps.Inspection) into the runtime, so the preflight can require
	// it — Shadow must evaluate against inspection, not classify inspection-rejectable
	// inputs as would_execute.
	inspectionComposed atomic.Bool
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
		// The §14 operator dry-run: is this NODE ready to activate Shadow right now? This is
		// deliberately the SCOPE-INDEPENDENT node readiness — before the first Observe→Shadow
		// activation the active scope is the empty Observe/Disabled scope, so folding the
		// scope-dependent usable-tool check in here would make the dry-run always report
		// no_usable_shadow_tools regardless of node health. The apply/commit paths, which know
		// the candidate scope, layer the usable-tool precondition on via
		// evaluateShadowActivationPreflight (Codex P2, PR #1234).
		"preflight": evaluateShadowNodeReadiness(rollout.CapabilityGateway),
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
	return mcpEnvTruthy(os.Getenv(mcpShadowReadyEnvVar))
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
		// Planner: the OPTIONAL metadata-only credential planner (Plan-only). Default nil ⇒
		// no credential planning capability is composed, so credential readiness reports
		// not-evaluated — byte-identical to the shipped build. When a real deployment or a
		// controlled evidence run installs one via shadowCredentialPlannerSeam, the evaluator
		// extracts ONLY its bound Plan method and drops the interface (TestShadow_
		// DoesNotRetainConcretePlanner), so a materialize-capable broker can never enter the
		// Shadow type graph — the CredentialPlanner interface exposes no Materialize. NO
		// Upstream, NO materialize-capable broker: the ShadowConfig type structurally cannot
		// carry either (Layer B). Clock: nil ⇒ time.Now.
		Planner: shadowCredentialPlannerSeam,
	})
	if err != nil {
		globalMCPShadow.setReason("evaluator_construct_failed")
		logger.Printf("MCP gateway shadow not composed: evaluator construction failed (fail-closed to Observe): %v", sanitizeLog(err.Error()))
		return
	}
	// Install the evaluator as the runtime executor. It is a non-nil concrete pointer, so
	// the runtime's `deps.Executor != nil` guard reads it correctly (no nil-interface trap).
	cfg.Deps.Executor = ev
	// Wire request inspection so a Shadow evaluation actually runs against schema/DLP/
	// destination inspection (Codex P1, PR #1234). Without it, a tools/call is recorded
	// with request_inspection=not_evaluated and an inspection-rejectable input could be
	// classified WOULD_EXECUTE, corrupting the soak the runbook promises. Only wired on a
	// shadow-ready node (gated by this whole function), so a plain Observe node is
	// unaffected. A hard inspection failure still BLOCKS in the runtime before the executor
	// (§10 "degrade toward Block"; the would_fail_inspection evidence shape is the tracked
	// SHADOW-EVIDENCE-ROUTING-1 deferral) — never a would_execute for a rejected input.
	if cfg.Deps.Inspection == nil {
		cfg.Deps.Inspection = staticGatewayInspection{prof: inspection.DefaultGatewayProfile(1)}
	}
	globalMCPShadow.inspectionComposed.Store(true)
	// Arm ONLY the shadow readiness tier — never the live-execution tier. This is what
	// lets a Shadow transition be admitted while every Canary/Production transition
	// stays fail-closed (mcp_rollout_execdeps.go).
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	globalMCPShadow.setReason("composed")
	logger.Printf("MCP gateway shadow evaluator composed (non-executing; no upstream client, no credential materialization). Shadow may be activated for a bounded scope.")
}

// setMCPDiscoveryReconcileHook and setMCPDiscoveryIngestGuard are the package-main indirection
// the tool-trust coordinator (mcp_tooltrust.go) uses to wire the execution.Discovery seams —
// the post-ingest reconcile hook and the ingest-serialization guard — WITHOUT importing the
// execution package itself. The execution-posture wall (mcp_execution_posture_test.go) pins
// THIS file as the single production importer of internal/mcp/execution, so these thin wrappers
// keep that bright line intact. Neither touches a live-execution symbol: SetReconcileHook and
// SetIngestGuard only install trust-reconciliation callbacks that can withdraw-or-re-affirm a
// tool's usability, never widen it, and constructing a live executor stays impossible.
func setMCPDiscoveryReconcileHook(fn func()) { execution.SetReconcileHook(fn) }

func setMCPDiscoveryIngestGuard(fn func(ingest func() error) error) { execution.SetIngestGuard(fn) }
