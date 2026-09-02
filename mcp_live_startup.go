package main

// MCP live-execution tier COMPOSITION (Live Tier Composition, Arming & Quiesce, §3/§11/§12).
//
// This is a SECOND production file permitted to import internal/mcp/execution and assign
// runtime.Deps.Executor (the evolved execution-posture wall pins the exact set). It composes the
// REAL live *execution.Executor — the guarded object that possesses the UpstreamCaller and the
// materialize-capable *broker.Broker — using execution.New, NOT a Canary-specific fork, so there
// remains exactly ONE irreversible MCP upstream boundary (execution's Upstream.Call) and one
// commit-before-side-effect discipline.
//
// COMPOSED != ARMED. Composing installs the executor as Deps.Executor and wires the
// composition-layer LiveGate (budget / live-trust / read-first), but it does NOT arm: the LIVE
// readiness tier stays off (liveExecDepsConfigured==false), so the executor resolves record-only
// for every Observe/Shadow request and modeExecReady refuses every Canary/Production transition.
// Arming is a separate, explicit, node-readiness-gated act (mcp_live_arming.go).
//
// DEFERRED PRODUCTION DEPENDENCY WIRING. There is deliberately NO production caller of
// composeGatewayLiveTierInto in this build: the collaborators the live executor needs — a bounded
// upstreamclient.Client (destination resolver + SSRF policy + root-CA pool) and a materialize-
// capable broker.Broker (KEK secret.Provider + profile store) — are a documented, separately-
// reviewed prerequisite that lands with the actual arming DEPLOYMENT (the real-infra composition).
// A stock build therefore composes NOTHING and the tier is absent (§24 "live tier currently armed
// by default: NO"). The controlled live-armed rehearsal and the mutation/red-team campaigns inject
// SYNTHETIC collaborators (a recording upstream, a synthetic-provider broker) through this exact
// production composition path, so the wiring is real-typed and exercised end to end (§19).

import (
	"errors"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpLiveActor labels the durable evidence the live executor emits (distinct from the Shadow
// actor, so evidence can tell a live execution apart from a Shadow evaluation).
const mcpLiveActor = "mcp-gateway-live"

// Composition errors (bounded, fail-closed). Composition leaves Deps.Executor untouched on any.
var (
	errLiveComposeNilConfig      = errors.New("mcp live tier: nil runtime config")
	errLiveComposeUpstreamAbsent = errors.New("mcp live tier: upstream client absent (required)")
	errLiveComposeEventsAbsent   = errors.New("mcp live tier: durable events absent (required)")
)

// liveTierComposition carries the collaborators the live Executor needs. In this PR there is NO
// production caller that supplies a real Upstream/Broker (deferred); tests inject synthetic ones.
type liveTierComposition struct {
	// Upstream is the bounded upstream MCP client — the single irreversible side-effect boundary.
	// REQUIRED (execution.New fails closed on nil).
	Upstream execution.UpstreamCaller
	// Broker is the materialize-capable credential broker. Optional: nil ⇒ the upstream call
	// carries no Authorization (a tool that needs no credential). Never handed to the embedded
	// Shadow evaluator as anything but the plan-only method value (execution.New enforces this).
	Broker *broker.Broker
	// Events is the durable-event manager. REQUIRED for commit-before-side-effect.
	Events *events.Manager
	// ResponseProfile is the response DLP/inspection profile applied before egress.
	ResponseProfile inspection.Profile
	// Clock is injected for deterministic tests; nil ⇒ time.Now.
	Clock func() time.Time
}

// composeGatewayLiveTierInto composes the live Executor and installs it as cfg.Deps.Executor,
// wiring the composition-layer LiveGate. On success it records the tier COMPOSED (never armed).
// It is fail-closed: a nil cfg, a missing required collaborator, or a construction failure leaves
// cfg.Deps.Executor untouched and records the bounded reason. This is the ONE production assignment
// site of Deps.Executor for the LIVE tier (the Shadow composition owns the shadow-only site).
//
// The composed live Executor embeds its own capability-reduced ShadowEvaluator (execution.New)
// for the out-of-scope Canary → Shadow disposition, so installing it does NOT lose Shadow
// evaluation — and that embedded evaluator still structurally cannot reach Upstream.Call or
// Materialize (Layer B), which the strengthened wall + the execution package's shadow_capability
// tests pin.
func composeGatewayLiveTierInto(cfg *mcpruntime.Config, comp liveTierComposition) error {
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	if cfg == nil {
		lt.setComposeReason("nil_runtime_config")
		return errLiveComposeNilConfig
	}
	if comp.Upstream == nil {
		lt.setComposeReason("upstream_absent")
		return errLiveComposeUpstreamAbsent
	}
	if comp.Events == nil {
		lt.setComposeReason("durable_events_unavailable")
		return errLiveComposeEventsAbsent
	}
	ex, err := execution.New(execution.Config{
		State:           getMCPRollout().gateway,
		Broker:          comp.Broker,
		Events:          comp.Events,
		Upstream:        comp.Upstream,
		ResponseProfile: comp.ResponseProfile,
		// Metrics nil ⇒ noop; the composition-layer gate carries the live-specific counters.
		Clock: comp.Clock,
		Actor: mcpLiveActor,
		// The composition-layer side-effect gate: budget reservation + runtime live-trust
		// revalidation + read-first, consulted at the boundary BEFORE the executor's kill re-check.
		LiveGate: newMCPLiveSideEffectGate(rollout.CapabilityGateway),
	})
	if err != nil {
		lt.setComposeReason("executor_construct_failed")
		return err
	}
	// Install the live executor as the runtime executor. It is a non-nil concrete pointer, so the
	// runtime's deps.Executor != nil guard reads it correctly. This assignment is permitted ONLY
	// here and in the Shadow composition (the wall pins both).
	cfg.Deps.Executor = ex
	// Wire response inspection if not already present, so the ResponseInspectionReady node fact is
	// true (the live tier requires response DLP). The default Gateway profile is used unless the
	// Shadow composition already installed one.
	if cfg.Deps.Inspection == nil {
		cfg.Deps.Inspection = staticGatewayInspection{prof: inspection.DefaultGatewayProfile(1)}
	}
	globalMCPShadow.inspectionComposed.Store(true)
	// Record the tier COMPOSED. This NEVER arms: markComposed moves absent→composed and leaves the
	// armed bit false, so modeExecReady still refuses every live-execution transition.
	lt.markComposed("composed")
	logger.Printf("MCP gateway LIVE execution tier composed (executor + upstream + broker present; NOT armed). Arming is a separate, node-readiness-gated act.")
	return nil
}
