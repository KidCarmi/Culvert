package main

import "sync/atomic"

// Execution-dependency precondition for MCP rollout (Shadow execution safety gate).
//
// An "executing" rollout mode (Shadow / Canary / Production) may drive the guarded
// execution pipeline: the executor, bounded upstream client, credential broker,
// event manager, and inspection/DLP components. The current shipped Gateway
// composition (mcp_observe_startup.go) is Observe-only and composes NONE of those.
//
// Activating an executing mode against that composition would create a partial,
// unsafe Shadow state that claims ModeShadow but cannot satisfy its execution
// contract. That is forbidden. Instead, a transition to an executing mode is
// REJECTED, fail-closed, unless every required execution-plane dependency has been
// registered here by the (separate, later) guarded-execution composition task.
//
// Until that task lands, gatewayExecDepsReady stays false and every Shadow/Canary/
// Production activation fails closed with shadow_execution_dependencies_not_configured.
// This is the deliberate, safe boundary described in the remediation task §12: the
// rollout transport, persistence, and evidence-window mechanics are fully wired,
// while an actual Shadow transition still fails safely until execution is configured.

// execDepsRegistry tracks, per capability, whether the guarded-execution plane is
// composed. Both default to false (Observe-only shipped posture). The values are
// process-global and set once at startup by the execution composition (none today).
type execDepsRegistry struct {
	gateway    atomic.Bool
	management atomic.Bool
}

var globalExecDeps = &execDepsRegistry{}

// markGatewayExecDepsReady is the registration hook the future guarded-execution
// composition calls once it has composed the executor, upstream client, credential
// broker, event manager, and inspection/DLP plane for the Gateway capability. It is
// intentionally UNCALLED in the current build, so the precondition stays fail-closed.
func markGatewayExecDepsReady() { globalExecDeps.gateway.Store(true) }

// markManagementExecDepsReady mirrors the Gateway hook for the Management capability.
func markManagementExecDepsReady() { globalExecDeps.management.Store(true) }

// execDepsConfigured reports whether the guarded-execution plane for a capability is
// composed. False (fail-closed) is the shipped default for both capabilities.
func execDepsConfigured(capbManagement bool) bool {
	if capbManagement {
		return globalExecDeps.management.Load()
	}
	return globalExecDeps.gateway.Load()
}
