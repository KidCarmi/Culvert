// Package canary is the MCP Canary readiness + activation-prerequisite engine
// (ADR-0035): a pure, I/O-free, deterministically-testable model of exactly what must
// become true before Culvert may perform its FIRST controlled real MCP upstream
// execution. It defines the machine-verifiable readiness contract, the bounded
// first-Canary scope constraints, the live-execution trust-consumption predicate, the
// blast-radius budget, and the automatic-abort taxonomy.
//
// # What this package is NOT
//
// Nothing here executes a business operation, calls an upstream MCP server, materializes
// a credential, contacts a provider, composes a live executor, or activates a rollout
// mode. It CANNOT: the package deliberately does not import internal/mcp/execution,
// internal/mcp/upstreamclient, or internal/mcp/credentials/broker, so it holds no path to
// Upstream.Call or credential Materialize (a compile-time firewall, pinned by
// canary_import_wall_test.go). It reads no files and touches no globals — every fact it
// reasons about is supplied by the caller, so the decision is a pure function and the
// clock is injected. The root composition layer (mcp_canary_preflight.go) populates the
// facts from live state and surfaces the result read-only; this package only decides.
//
// # Distinct from Shadow readiness (§2)
//
// Canary readiness is a STRICTLY STRONGER, separate contract from Shadow readiness
// (mcp_shadow_preflight.go). Shadow requires the non-executing evaluation plane and
// REFUSES a live-execution tier; Canary requires the LIVE-execution plane PLUS a bounded
// enumerable read-first scope, an exact live_execution trust approval, a configured
// blast-radius budget, and the emergency-stop invariants — every one an individually
// observable fact with a stable classified reason. There is no boolean blob: Ready is
// true only when the Unmet reason set is empty, and each absent fact names itself.
//
// # Dormant by construction
//
// In the shipped build the live-execution tier is never armed (liveExecDepsConfigured is
// false; the execution-posture wall pins that no live executor is composed and
// markGatewayExecDepsReady is uncalled). So CanaryReadiness.Evaluate always returns
// NOT-READY with at least ReasonLiveExecutorAbsent, and the Canary preflight always fails
// closed. That is the point of this phase: the architecture is reviewable and testable
// without Canary ever being activatable. Arming Canary is a separately-reviewed activation
// that must satisfy every prerequisite this package enumerates.
package canary
