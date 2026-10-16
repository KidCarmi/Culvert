package main

// cp_grpc_activation.go — CHAOS-71: the ONE post-bind activation step of the
// Control Plane gRPC listener supervisor (commitActivation).
//
// Why a separate step with its own ordering. Activation used to run inline and
// synchronously inside enableControlPlane, at boot or on an admin request, so
// nothing could change between "the socket is real" and "claim the role". The
// supervisor made activation ASYNCHRONOUS — a retried bind can succeed minutes
// after boot — so it now races everything that changed since boot. Codex's
// review of #1556 found five faces of that one root cause:
//
//   - shutdown began after the bind was adopted, and onActivated (the HA
//     leadership resume) still ran after globalHA.Stop had been joined,
//     re-acquiring the fencing lease during teardown;
//   - a delayed CP bind overwrote an established data-plane role while the DP
//     client kept running, flipping isManagedDataPlane false;
//   - the CP-address republish was built from a snapshot captured before a
//     concurrent admin publish, rolling that publish back at a higher version;
//   - the republish error was discarded, so a promotion reported success while
//     Data Planes kept only the dead leader's address;
//   - a refused runtime activation left the health plane CONFIGURED, so every
//     surface described a Control Plane the 409 had just said does not exist.
//
// commitActivation answers all five with one ordering:
//
//  1. Under clusterRoleMu, abort if Stop or process shutdown has begun, and
//     refuse to replace any role other than none/standalone (or this
//     supervisor's own earlier claim, on a rebind). A refused role is terminal
//     for the supervisor and raised as the listener-down alert.
//  2. Commit the role, release the lock.
//  3. Publish the CP address list by merging onto the LATEST COMMITTED snapshot
//     inside the config store's own commit serialization
//     (ConfigStore.UpdateCPAddresses), only if it changed.
//  4. A rejected publish is RETURNED: the role is rolled back, the attempt is a
//     failure in the listener's episode (so the alert stays raised once it
//     has fired), and the supervisor retries with backoff. Activation never
//     reports success without the address list it owes the fleet.
//  5. onActivated runs only after 1–4, behind the shutdown gate, re-checked
//     immediately before the call.
//
// (The refused-runtime-activation health reset is noteCPGRPCActivationRejected,
// called by startControlPlaneListener.)

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// cpActivationShutdown is set — under cpActivationGateMu — by the shutdown
// sequence BEFORE globalHA.Stop (the ha-stop hook, order 10), i.e. before the
// supervisor itself is stopped (order 20). Read lock-free inside clusterRoleMu
// so the role check never nests the gate inside the role lock.
var cpActivationShutdown atomic.Bool

// cpActivationGateMu is held across the stop re-check AND the onActivated call,
// and by beginCPActivationShutdown while it sets the flag. So once the flag is
// set no onActivated can START, and one already running finishes before the
// shutdown sequence goes on to globalHA.Stop — which then joins whatever it
// started. A check without the lock would leave the check-then-call window
// Codex's P1 describes.
var cpActivationGateMu sync.Mutex

// beginCPActivationShutdown closes the activation gate for the rest of the
// process. Called first in the ha-stop shutdown hook.
func beginCPActivationShutdown() {
	cpActivationGateMu.Lock()
	cpActivationShutdown.Store(true)
	cpActivationGateMu.Unlock()
}

// resetCPActivationShutdownForTest reopens the gate (tests only).
func resetCPActivationShutdownForTest() {
	cpActivationGateMu.Lock()
	cpActivationShutdown.Store(false)
	cpActivationGateMu.Unlock()
}

// cpCommitOutcome is commitActivation's verdict.
type cpCommitOutcome int

const (
	cpCommitted           cpCommitOutcome = iota // role claimed, addresses published, onActivated run
	cpCommitStopped                              // Stop or process shutdown won: tear down, exit quietly
	cpCommitRoleConflict                         // another role is established: never replace it
	cpCommitPublishFailed                        // the address publish was rejected: roll back, retry
)

// cpRoleFields is the clusterRole state a rollback restores.
type cpRoleFields struct {
	role, grpcAddr, certFile, keyFile, caFile string
}

// errCPGRPCAddressPublish tags a rejected CP-address publish so the classifier
// can name it `address_publish_rejected` (and give it its own remedy).
var errCPGRPCAddressPublish = fmt.Errorf("control plane address list publish rejected")

// cpPublishCPAddresses publishes the committed CP address list. Package-level
// seam so a gate can inject a commit-time rejection deterministically.
var cpPublishCPAddresses = func() (changed bool, err error) {
	return globalConfigStore.UpdateCPAddressesFrom(buildCPAddressList)
}

// cpActivationAfterClaim, when non-nil, runs between the role claim and the
// gated publish/onActivated step. Test seam only (nil in production): it opens
// the "shutdown began after the claim" window deterministically.
var cpActivationAfterClaim func()

// commitActivation is the ONE post-bind activation step (see the file header
// for the ordering and why each step is where it is). conflictRole names the
// established role on cpCommitRoleConflict; err carries the publish rejection
// on cpCommitPublishFailed.
func (s *cpListenerSupervisor) commitActivation() (outcome cpCommitOutcome, conflictRole string, err error) {
	prev, outcome, conflictRole := s.claimRole()
	if outcome != cpCommitted {
		return outcome, conflictRole, nil
	}
	if hook := cpActivationAfterClaim; hook != nil {
		hook()
	}

	// (3)–(4) behind the shutdown gate, so the address publish cannot start
	// once shutdown has begun.
	if outcome, err = s.publishAndActivate(); outcome != cpCommitted {
		s.rollbackRole(prev)
		return outcome, "", err
	}
	// (5) onActivated runs OUTSIDE the gate (Codex review of #1556): the boot
	// callback is the HA leadership resume, whose lease acquisition can wait
	// up to haResumeGhostWait (45 s) — longer than the shutdown watchdog gives
	// the ha-stop hook, which takes the gate. The gate records activation; the
	// resume's own shutdown safety is the HA shutdown latch (HAState.BeginShutdown,
	// set by ha-stop before Stop): its waits abort on it, and it is re-checked
	// under HAState.mu before any role is taken.
	// TestChaos71_Wall_NoHALeaseAcquisitionUnderTheActivationGate.
	if !s.stopRequested() && !cpActivationShutdown.Load() {
		s.runOnActivated()
	}

	if prev.role != "control-plane" {
		// First activation only: a rebind after a serve-death must NOT start a
		// second monitor. resolveLifecycleCtx, not appLifecycleCtx directly:
		// the context is nil in every one-shot command path and in the test
		// binary, and on the SUPERVISOR goroutine a nil deref is a panic that
		// kills the listener permanently (found by this sweep's self-heal gate).
		globalClusterStore.StartHeartbeatMonitor(resolveLifecycleCtx().Done())
	}
	return cpCommitted, "", nil
}

// claimRole is steps (1) and (2): under clusterRoleMu, decide whether this
// supervisor may claim the Control Plane role, and claim it.
//
// The invariant is the one enableControlPlane stated in a comment — "Only set
// role after gRPC is successfully started" — preserved rather than traded for
// availability: while the bind is failing the node reports what it is.
//
// It never REPLACES an established role. A node whose CP bind failed at boot
// goes on to Data-Plane wiring, and a later successful retry that overwrote
// `data-plane` would leave the DP client running under a node that every
// role gate (isManagedDataPlane, the PAC writer gate, feed authority) now
// treats as a Control Plane. The only role it re-asserts is its OWN, on a
// rebind after a serve-death (s.committed).
//
// The decision and the write are the cluster-role ARBITER's
// (cluster_role_arbiter.go): an already-claimed role wins and the second
// claimant is refused and latched as a conflict — the same rule the Data
// Plane's claim obeys in the other order.
//
// Locking: clusterRoleMu only (inside the arbiter), never cpActivationMu (the
// starter may hold it while waiting on this goroutine). The shutdown flag is
// read lock-free so the gate mutex is never nested inside the role lock.
// s.committed is touched only by the supervisor's own goroutine.
func (s *cpListenerSupervisor) claimRole() (prev cpRoleFields, outcome cpCommitOutcome, conflictRole string) {
	prev, outcome, conflictRole = claimControlPlaneRole(s.cfg,
		func(cur string) bool { return cur == "control-plane" && s.committed },
		func() bool { return s.stopRequested() || cpActivationShutdown.Load() })
	if outcome == cpCommitted {
		if prev.role != "control-plane" {
			// First claim of a fresh role: what a terminal exit restores.
			s.original, s.haveOriginal = prev, true
		}
		s.committed = true
	}
	return prev, outcome, conflictRole
}

// rollbackRole restores the role fields claimRole replaced, unless something
// else has changed the role since (it then owns it).
func (s *cpListenerSupervisor) rollbackRole(prev cpRoleFields) {
	if restoreControlPlaneRole(prev, s.cfg.addr) {
		s.committed = prev.role == "control-plane"
	}
}

// publishAndActivate is steps (3)–(4), behind the shutdown gate
// (cpActivationGateMu, re-checked first): publish the CP address list. Keeping
// the PUBLISH inside the gate means a node whose shutdown has begun never tells
// the fleet it is a Control Plane (CodeRabbit review of #1556). Nothing that
// can wait on the fencing backend runs under the gate — onActivated is step
// (5), run by commitActivation after the gate is released.
//
// The publish runs outside clusterRoleMu: buildCPAddressList reads it, and
// RWMutex is not reentrant (the CHAOS-71 promote-deadlock rider).
//
// This publish reflects the HA topology AS OF NOW. An HA transition after it —
// onActivated's leadership resume included (Codex review of #1556) — is
// republished by the HA topology writer itself (setTopologyLocked,
// ha_topology.go), so no caller here has to order anything after the resume.
// Lock order: cpActivationGateMu → HAState.mu (read, via Status) → clusterRoleMu
// → ConfigStore.mu.
func (s *cpListenerSupervisor) publishAndActivate() (cpCommitOutcome, error) {
	cpActivationGateMu.Lock()
	defer cpActivationGateMu.Unlock()
	if s.stopRequested() || cpActivationShutdown.Load() {
		return cpCommitStopped, nil
	}
	changed, perr := cpPublishCPAddresses()
	if perr != nil {
		// (4) Never report success without the address list the fleet needs.
		return cpCommitPublishFailed, fmt.Errorf("%w: %w", errCPGRPCAddressPublish, perr)
	}
	if changed {
		s.everPublished = true
		// Operator- and peer-supplied addresses: format, sanitize (CWE-117), %q.
		logger.Printf("ControlPlane: published the committed CP address list %q",
			sanitizeLog(fmt.Sprint(globalConfigStore.Get().CPAddresses)))
	}
	return cpCommitted, nil
}

// commitAfterAdopt runs commitActivation for an adopted server and turns the
// verdict into the loop's next move: serve it, retry with backoff, or exit.
// Every non-serve path tears the built server down; nothing it bound outlives
// the decision.
func (s *cpListenerSupervisor) commitAfterAdopt(mode string, backoff time.Duration) (serve, exit bool) {
	outcome, conflictRole, err := s.commitActivation()
	if outcome == cpCommitted {
		// The success line is emitted AFTER the bind AND the commit, never
		// before — §33's rule, learned from an admin UI that announced a
		// listener that did not exist. Recording "bound" only now also keeps an
		// open failure episode (and its alert) raised across a rejected commit.
		suppressed, rebound := noteCPGRPCBound()
		if !s.firstResolved() {
			s.noteFirstBound()
		}
		logControlPlaneTransport(s.cfg.addr, mode)
		if rebound {
			logger.Printf("ControlPlane: gRPC listener bound and serving again on %s — stabilizing: the outage episode stays open until it has served for %s (%d suppressed bind-failure log line(s))",
				sanitizeLog(s.cfg.addr), cpGRPCServeStableAfter, suppressed)
		}
		return true, false
	}

	s.releaseAttempt()
	switch outcome {
	case cpCommitStopped:
		noteCPGRPCListenerStopped()
		return false, true
	case cpCommitRoleConflict:
		logErrorf("ControlPlane gRPC listener bound on %s, but this node already holds the %q cluster role — "+
			"refusing to replace it; the Control Plane listener is STOPPED and will not rebind (fix the "+
			"Control Plane / Data Plane configuration and restart this node)", s.cfg.addr, conflictRole)
		s.exitTerminal(cpGRPCRoleConflictReason)
		return false, true
	default: // cpCommitPublishFailed: a failure in this episode, retried with backoff
		if !s.handleBindFailure(err, backoff) {
			noteCPGRPCListenerStopped()
			return false, true
		}
		return false, false
	}
}
