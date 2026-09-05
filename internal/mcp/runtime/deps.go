package runtime

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// Deps are the shared IMMUTABLE libraries the listeners read. They are read-only
// from the listeners' perspective (snapshots / pure validators); the listeners never
// mutate them and never share mutable per-capability state through them. The replay
// cache is per-capability partitioned internally, so one instance is safe for both.
type Deps struct {
	Registry     *registry.Registry
	Catalog      *catalog.Catalog
	Keys         authn.KeyResolver
	Introspector authn.Introspector
	Replay       *senderconstraint.ReplayCache
	// Sink receives sanitized observe records. A nil sink drops records (still
	// bounded). Sink failure NEVER permits a denied request or a decision-point
	// operation, and must not block shutdown.
	Sink Sink
	// Policy is the OPTIONAL capability-local policy provider (PR-6). When nil, the
	// listener keeps the PR-5 observe-only disposition for decision-point methods.
	// When set, decision-point methods are evaluated against the capability-local
	// policy snapshot (decision-only — never an upstream/credential/broker call); a
	// missing snapshot fails closed with MCP.POLICY.SNAPSHOT_UNAVAILABLE, never a
	// permissive fall-back.
	Policy PolicyProvider
	// Inspection is the OPTIONAL capability-local inspection provider (PR-7). When
	// nil, decision-point methods keep the pre-inspection path (byte-identical). When
	// set, a Gateway tools/call is semantically inspected (schema/DLP/destination)
	// BEFORE policy evaluation; a hard security failure blocks regardless of the
	// policy action, and an ALLOW_WITH_REDACTION obligation is satisfied by a
	// re-validated transform — still decision-only (no upstream/credential/broker
	// call, execution_state stays not_implemented).
	Inspection InspectionProvider
	// Events is the OPTIONAL capability-scoped PR-8 durable decision-event provider.
	// When nil, the pipeline keeps the PR-7 decision-only path byte-identically (no
	// event committed, no denial routed). When set, an ALLOW-class decision-point
	// outcome durably commits a sanitized decision event before the (still
	// not-implemented) response — a critical operation whose event cannot commit
	// fails closed — and auth/authorization denials are routed into the isolated
	// denial lane. It never causes an upstream/credential/broker call.
	Events EventProvider
	// Executor is the OPTIONAL capability-local guarded-execution provider (PR-11).
	// When nil, the pipeline keeps the PR-8 decision-only path byte-identically
	// (execution_state stays not_implemented). When set — only for the Gateway
	// capability, and only after rollout distribution arms it — a decision-point
	// outcome is handed to the rollout-mode executor AFTER inspection + policy have
	// run, which resolves the effective mode disposition (record-only / execute /
	// block) and, for an in-scope executing mode, performs the real guarded upstream
	// tools/call (credential broker + PR-8 commit-before-materialization + upstream
	// client + response DLP). A nil executor is the disabled-by-default posture.
	Executor ExecutionProvider
	// CanaryBreach is the OPTIONAL narrow seam for reporting an authoritative WHOLE-CANARY breach
	// that this pipeline detects BEFORE the executor is reached. Nil ⇒ nothing composed and nothing
	// reported, which is the disabled-by-default posture.
	//
	// It exists because tool drift is detectable at three points and only one of them used to route
	// anywhere: the composition-layer admission gate. This pipeline refuses a drifted decision
	// BEFORE the executor (refuseOnToolDrift), so a rug-pull landing in that window failed the
	// request and left the Canary running — every later request against the new fingerprint then
	// merely failed approval validation, which looks like ordinary denial rather than proof the
	// experiment's premise no longer holds (Codex round 14).
	//
	// The signature carries no activation generation ON PURPOSE. This package cannot import the
	// composition layer (the dependency runs the other way), and at this point no reservation has
	// been made, so there is no generation this request was admitted under. The adapter resolves
	// "the activation admitting right now", exactly as the admission gate's own drift path does.
	CanaryBreach func(capability, code string)
	// Clock is injected for deterministic tests; nil ⇒ time.Now.
	Clock func() time.Time
}

// reportCanaryBreach forwards an authoritative whole-Canary breach when a reporter is composed.
// Nil-safe so call sites stay free of branching.
func (d Deps) reportCanaryBreach(capability, code string) {
	if d.CanaryBreach != nil {
		d.CanaryBreach(capability, code)
	}
}

func (d Deps) now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}

// authDeps builds the PR-3 authn.Deps from the shared libraries.
func (d Deps) authDeps() authn.Deps {
	return authn.Deps{
		Keys:         d.Keys,
		Introspector: d.Introspector,
		Registry:     d.Registry,
		Catalog:      d.Catalog,
		Replay:       d.Replay,
	}
}
