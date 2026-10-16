package main

// cluster_role_arbiter.go — CHAOS-71: the ONE writer of this node's cluster
// role and advertised gRPC address.
//
// Why it exists. Before the CP listener supervisor, every role transition ran
// synchronously on the boot path in a fixed order, so "who writes
// clusterRole.role" never had to be arbitrated: the CP path set it, then (if
// Data-Plane wiring was also present) startDataPlane overwrote it with
// UNLOCKED writes. The supervisor made the CP claim asynchronous — a retried
// bind can land before or after Data-Plane wiring — and Codex's review of
// #1556 found both orderings: a delayed CP claim replacing an established
// data-plane role, and startDataPlane replacing a CP role the supervisor had
// already claimed while the CP listener, heartbeat monitor and HA leadership
// stayed live.
//
// THE RULE (one deterministic winner): an ALREADY-CLAIMED role wins, and the
// second claimant is REFUSED loudly. Silently switching an established role is
// the dangerous outcome — a node that is simultaneously serving config as a
// Control Plane and consuming config as a Data Plane, with every role gate
// (isManagedDataPlane, the PAC writer gate, feed authority) answering for only
// one of them. A refusal is latched as a cluster-role conflict, which the
// `cluster_posture` diagnostics row reports as FAIL with the operator action;
// a refused CP claim additionally stops its listener supervisor and raises
// `cp_grpc_listener_down` (reason `role_conflict`). Which role SHOULD win when
// both are configured is an owner decision recorded in the PR; refusing the
// second is the conservative choice until it is made.
//
// Every write of clusterRole.role / .grpcAddr (and the identity fields that
// travel with them) lives in this file; TestChaos71_Wall_ClusterRoleIsWrittenOnlyByTheArbiter
// pins it.

import (
	"fmt"
	"time"
)

// clusterRoleConflict is the latched record of a refused role claim. Guarded
// by clusterRoleMu, like the role it describes.
var clusterRoleConflict struct {
	set           bool
	held, refused string
	at            time.Time
}

// initStandaloneClusterRole is the boot-time reset: standalone until a CP/DP/HA
// path claims a role.
func initStandaloneClusterRole(nodeID string) {
	clusterRoleMu.Lock()
	defer clusterRoleMu.Unlock()
	clusterRole.role = "standalone"
	if nodeID != "" {
		clusterRole.nodeID = nodeID
	}
}

// recordClusterRoleConflictLocked latches a refused claim. Caller holds
// clusterRoleMu (write).
func recordClusterRoleConflictLocked(held, refused string) {
	clusterRoleConflict.set = true
	clusterRoleConflict.held = held
	clusterRoleConflict.refused = refused
	clusterRoleConflict.at = time.Now().UTC()
}

// clusterRoleConflictState reports the latched conflict, if any.
func clusterRoleConflictState() (set bool, held, refused string) {
	clusterRoleMu.RLock()
	defer clusterRoleMu.RUnlock()
	return clusterRoleConflict.set, clusterRoleConflict.held, clusterRoleConflict.refused
}

// resetClusterRoleConflictForTest clears the latch (tests only).
func resetClusterRoleConflictForTest() {
	clusterRoleMu.Lock()
	clusterRoleConflict.set = false
	clusterRoleConflict.held, clusterRoleConflict.refused = "", ""
	clusterRoleConflict.at = time.Time{}
	clusterRoleMu.Unlock()
}

// errClusterRoleConflict is returned when a claim is refused because another
// role is already established.
var errClusterRoleConflict = fmt.Errorf("cluster role conflict")

// claimDataPlaneRole claims the Data Plane role for addr. It REFUSES — leaving
// the role untouched — when a Control Plane role is already claimed. Returns
// the effective node ID (the caller's, or the boot-time hostname).
func claimDataPlaneRole(addr, nodeID string) (string, error) {
	clusterRoleMu.Lock()
	defer clusterRoleMu.Unlock()
	if cur := clusterRole.role; cur == "control-plane" {
		recordClusterRoleConflictLocked(cur, "data-plane")
		return "", fmt.Errorf("%w: this node already holds the %q role", errClusterRoleConflict, cur)
	}
	clusterRole.role = "data-plane"
	clusterRole.grpcAddr = addr
	if nodeID == "" {
		nodeID = clusterRole.nodeID
	}
	clusterRole.nodeID = nodeID
	return nodeID, nil
}

// claimControlPlaneRole claims the Control Plane role for cfg. abort is checked
// under the lock first (Stop / shutdown). ours reports whether the current
// control-plane role is the caller's own earlier claim (a rebind may re-assert
// it). Any other established role is refused and latched.
func claimControlPlaneRole(cfg cpListenerConfig, ours func(cur string) bool, abort func() bool) (prev cpRoleFields, outcome cpCommitOutcome, conflictRole string) {
	clusterRoleMu.Lock()
	defer clusterRoleMu.Unlock()
	if abort() {
		return prev, cpCommitStopped, ""
	}
	cur := clusterRole.role
	if cur != "" && cur != "standalone" && !ours(cur) {
		recordClusterRoleConflictLocked(cur, "control-plane")
		return prev, cpCommitRoleConflict, cur
	}
	prev = cpRoleFields{role: cur, grpcAddr: clusterRole.grpcAddr, certFile: clusterRole.certFile,
		keyFile: clusterRole.keyFile, caFile: clusterRole.caFile}
	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = cfg.addr
	clusterRole.certFile = cfg.certFile
	clusterRole.keyFile = cfg.keyFile
	clusterRole.caFile = cfg.caFile
	return prev, cpCommitted, ""
}

// restoreControlPlaneRole rolls back a claimControlPlaneRole, unless the role
// has changed since (whoever changed it now owns it). Reports whether it
// restored.
func restoreControlPlaneRole(prev cpRoleFields, addr string) bool {
	clusterRoleMu.Lock()
	defer clusterRoleMu.Unlock()
	if clusterRole.role != "control-plane" || clusterRole.grpcAddr != addr {
		return false
	}
	clusterRole.role = prev.role
	clusterRole.grpcAddr = prev.grpcAddr
	clusterRole.certFile = prev.certFile
	clusterRole.keyFile = prev.keyFile
	clusterRole.caFile = prev.caFile
	return true
}
