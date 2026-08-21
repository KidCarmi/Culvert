// Package rollout is the capability-local rollout state model for the MCP
// Security Gateway and Culvert Management MCP Server (PR-11). It owns the mode
// ladder (Disabled → Observe → Shadow → Canary → Production), the immutable
// revisioned rollout scope, the single central hard-failure classifier, and the
// Production-Qualification lockout.
//
// It is a pure leaf: it imports only the standard library and internal/mcp/mcperr
// (plus a stable hash for percentage bucketing). It performs NO I/O, reads NO
// wall clock of its own (callers pass an explicit time), and holds no policy,
// token, credential, or raw request/response. The signed, distributable subset
// (mode + scope) is carried inside the PR-10 cpdp signed snapshot payload, so
// cpdp imports rollout — never the reverse.
//
// Doctrine (ROLLOUT-AND-ROLLBACK.md): the two capabilities keep SEPARATE modes,
// scopes, transition history, kill switches, evidence, and rollback state. A
// Gateway transition never alters Management mode and vice versa. Management
// stays read-only/draft/validate/simulate in every mode. Production is a real
// mode semantic but is UNREACHABLE without a machine-verifiable
// ProductionQualificationVerifier receipt; this package contains no issuer that
// can mint one.
package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// Capability identifies which MCP capability a rollout state belongs to. It is a
// small local enum (rollout is a leaf and must not import the runtime/cpdp
// capability types); mapping to those types happens at the wiring layer.
type Capability uint8

const (
	// CapabilityUnknown is the zero value; it fails closed (never a valid rollout).
	CapabilityUnknown Capability = iota
	// CapabilityGateway is the MCP Security Gateway (the only capability that ever
	// executes upstream).
	CapabilityGateway
	// CapabilityManagement is the Culvert Management MCP Server (read-only/draft/
	// validate/simulate in every mode — it never executes an upstream tools/call).
	CapabilityManagement
)

// Valid reports whether the capability is one of the two real capabilities.
func (c Capability) Valid() bool {
	return c == CapabilityGateway || c == CapabilityManagement
}

// String returns the stable wire token for the capability.
func (c Capability) String() string {
	switch c {
	case CapabilityGateway:
		return "gateway"
	case CapabilityManagement:
		return "management"
	default:
		return "unknown"
	}
}

// ParseCapability parses a stable capability token, failing closed on anything
// other than the two admitted values.
func ParseCapability(s string) (Capability, error) {
	switch s {
	case "gateway":
		return CapabilityGateway, nil
	case "management":
		return CapabilityManagement, nil
	default:
		return CapabilityUnknown, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "rollout", "unknown capability")
	}
}

// Mode is one rung of the rollout ladder. The zero value (ModeDisabled) is the
// safe default: no listener, no execution, no request-path cost.
type Mode uint8

const (
	// ModeDisabled — the capability is absent: no listener bound, no MCP traffic
	// accepted, no upstream pool, no credential materialization, no worker loop, no
	// request-path overhead on the existing SWG. Signed snapshots may be retained but
	// are not active for execution. "Disabled" means absent, not a DENY-returning
	// listener.
	ModeDisabled Mode = iota
	// ModeObserve — a bounded listener may run; requests pass protocol/auth/identity/
	// registry/inspection/policy and are recorded, but NOTHING is executed upstream,
	// no credential is materialized, and no provider is contacted. The decision-only
	// posture (execution_state = not_implemented / observe) is preserved.
	ModeObserve
	// ModeShadow — for an explicit bounded Shadow scope only (default empty), real
	// Gateway traffic reaches the approved upstream server for allow-class decisions;
	// the exact PR-6 evaluator computes the would-be enforcement decision, which is
	// recorded unchanged (a non-hard DENY is allow-and-record). The fixed hard-failure
	// set still BLOCKS, and DLP stays enforcing. Outside the scope: Observe behavior.
	ModeShadow
	// ModeCanary — full enforcement (all nine policy actions) for an explicit,
	// enumerated, read-first scope. Outside scope: Shadow (if enabled) else Observe.
	ModeCanary
	// ModeProduction — full enforcement for an approved scope. Implemented as a mode
	// semantic but UNREACHABLE without a valid Production Qualification receipt; a
	// transition into it fails closed otherwise.
	ModeProduction
)

// modeToken maps each mode to its stable machine string (part of the wire/config
// contract — MUST NOT change).
var modeToken = map[Mode]string{
	ModeDisabled:   "disabled",
	ModeObserve:    "observe",
	ModeShadow:     "shadow",
	ModeCanary:     "canary",
	ModeProduction: "production",
}

// Valid reports whether m is one of the five defined modes.
func (m Mode) Valid() bool {
	_, ok := modeToken[m]
	return ok
}

// String returns the stable token, or "invalid" for an unknown mode.
func (m Mode) String() string {
	if s, ok := modeToken[m]; ok {
		return s
	}
	return "invalid"
}

// Rank returns the ladder position (Disabled=0 … Production=4). Higher rank means
// more enforcement/execution surface; promotion increases rank by exactly one and
// demotion decreases it by one or more.
func (m Mode) Rank() int { return int(m) }

// Executes reports whether the mode permits any real upstream execution at all
// (Shadow, Canary, Production do; Disabled and Observe never do). Whether a
// SPECIFIC request executes further depends on scope + hard failures + policy.
func (m Mode) Executes() bool { return m == ModeShadow || m == ModeCanary || m == ModeProduction }

// FullyEnforces reports whether the mode blocks on a non-hard policy DENY inside
// scope (Canary and Production). Shadow records-and-allows a non-hard DENY;
// Observe/Disabled never enforce policy at all.
func (m Mode) FullyEnforces() bool { return m == ModeCanary || m == ModeProduction }

// ParseMode parses a stable mode token, failing closed on anything unknown.
func ParseMode(s string) (Mode, error) {
	for m, tok := range modeToken {
		if tok == s {
			return m, nil
		}
	}
	return ModeDisabled, mcperr.New(mcperr.ReasonRolloutModeInvalid, "rollout", "unknown mode")
}
