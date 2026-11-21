package main

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/livetier"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// MCP live-execution tier LIFECYCLE (Live Tier Composition, Arming & Quiesce).
//
// The state machine itself — the composed/armed/quiescing states, the in-flight accounting,
// the admission bit and the bounded drain — is internal/mcp/livetier (IM-025, ADR-0057).
// This file is its composition: the two process-global tiers, and the three collaborators
// each one is built with.
//
//	Live tier COMPOSED  !=  Live tier ARMED  !=  Canary ACTIVE
//
// The armed bit is derived by the tier and mirrored into the execdeps registry
// (mcp_rollout_execdeps.go), the single place modeExecReady reads, through the SetArmed
// binding below. That binding is the ONLY production call of setLiveExecDepsArmed (pinned by
// the execution-posture wall, which names this file), and the tier invokes it only from Arm
// and from its three revocations, so exactly one authoritative arming path toggles
// liveExecDepsConfigured.
//
// ARMED BY DEFAULT: NO. absent by default; composition is a disabled-by-default opt-in and
// arming is a separate explicit act. A stock build composes nothing and arms nothing.

// Bindings to the lifecycle owner. The callers in this package and its tests keep these names.
type mcpLiveTier = livetier.Tier

const (
	liveTierAbsent    = livetier.Absent
	liveTierComposed  = livetier.Composed
	liveTierArmed     = livetier.Armed
	liveTierQuiescing = livetier.Quiescing
)

// Lifecycle transition errors (bounded, fail-closed); see livetier.
var (
	errLiveTierNotComposed = livetier.ErrNotComposed
	errLiveTierNotReady    = livetier.ErrNotReady
)

// globalMCPLiveTier is the process-global Gateway live-tier lifecycle. Management never
// executes an upstream tools/call, so only the Gateway tier is composed/armed; a Management
// object exists for symmetry and stays absent.
var (
	globalMCPLiveTier     = newMCPLiveTier(rollout.CapabilityGateway)
	globalMCPLiveTierMgmt = newMCPLiveTier(rollout.CapabilityManagement)
)

// newMCPLiveTier builds one capability's lifecycle, absent, wired to this process's readiness
// registry and rollout owner:
//
//   - SetArmed is the arm/disarm dispatcher for this capability.
//   - DepsReady reads the same bit back for the status row.
//   - CommitLock is mcpRollout.durableMu, which every rollout commit holds across its armed
//     read and its install; the tier's Quiesce takes it around the revocation (lock order
//     durableMu → tier lock). It is resolved per Quiesce because getMCPRollout's owner can be
//     replaced.
func newMCPLiveTier(capb rollout.Capability) *mcpLiveTier {
	management := capb == rollout.CapabilityManagement
	return livetier.New(livetier.Options{
		SetArmed:   func(armed bool) { setLiveExecDepsArmed(capb, armed) },
		DepsReady:  func() bool { return liveExecDepsConfigured(management) },
		CommitLock: func() sync.Locker { return &getMCPRollout().durableMu },
	})
}

// mcpLiveTierFor returns the lifecycle object for a capability.
func mcpLiveTierFor(capb rollout.Capability) *mcpLiveTier {
	if capb == rollout.CapabilityManagement {
		return globalMCPLiveTierMgmt
	}
	return globalMCPLiveTier
}

// drainWaitFn returns the tier's bounded drain wait for a quiesce that must finish by deadline.
func drainWaitFn(lt *mcpLiveTier, deadline time.Time) func(inFlight func() int) int {
	return lt.DrainWait(deadline)
}
