// Package livetier is the lifecycle state machine of the MCP live-execution
// tier (IM-025, ADR-0057; lifecycle defined by ADR-0035).
//
// THE RULE. Three states must never collapse into one:
//
//	Live tier COMPOSED  !=  Live tier ARMED  !=  Canary ACTIVE
//
//	absent      — nothing is composed. No live executor exists. The shipped default.
//	  ↓ compose (opt-in, fail-closed)
//	composed    — the real executor, upstream caller and broker exist and are
//	              installed, but the LIVE readiness tier is NOT armed. The mode gate
//	              still refuses every Canary/Production transition, so the executor
//	              resolves record-only and can never cross the side-effect boundary.
//	              Composition creates CAPABILITY, never permission.
//	  ↓ arm (explicit, authoritative, node-readiness gated)
//	armed       — the LIVE readiness tier is armed, so a Canary MODE transition can
//	              now be authorized by the full activation preflight. Arming grants
//	              READINESS, never activation: it composes no executor, begins no
//	              Canary generation, issues no approval, and reaches no upstream.
//	  ↓ quiesce (explicit)
//	quiescing   — disarm in progress: the tier is un-armed (so no new Canary
//	              transition can be authorized and no new live execution can be
//	              admitted), in-flight executions are bounded/drained, and evidence
//	              and trust records are preserved. Emergency kill remains
//	              authoritative regardless.
//	  ↓ (drain complete)
//	composed    — back to composed/unarmed. Re-arming is a fresh explicit act.
//
// SEPARATION IS THE WHOLE POINT. A Tier never begins a Canary activation and
// never reaches an upstream; arming only flips the readiness bit the rollout
// commit gate and the Canary preflight consult.
//
// Ownership. A Tier owns its lifecycle state, the admission bit, the in-flight
// count, the bounded drain wait, and the ORDER in which the armed bit, the
// admission bit and the state change. Package main owns everything the tier is
// handed through Options: the readiness registry the mode gate reads (the tier
// is its only writer for the live tier, through Options.SetArmed), and the lock
// rollout commits hold (Options.CommitLock). Main also owns the two process
// tiers, the node-readiness evaluation that decides the `ready` argument of
// Arm, the live side-effect gate that calls AdmitExecution, and the log lines.
//
// Lifecycle, in one sentence: main builds one Tier per capability at package
// initialization and holds it for the life of the process; the Tier starts no
// goroutine and owns no context, file or connection — its only timer is the
// one a DrainWait arms for the deadline its caller chose and stops before it
// returns.
//
// The package holds no mutable package-level state (its two variables are
// sentinel errors), has no init, does no I/O or logging and imports no other
// Culvert package.
package livetier
