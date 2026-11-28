package main

// ha_legacy_authority.go — ADR-0064 part C: in LEGACY mode (no fencing lease)
// a restarting leader revalidates its authority before it resumes.
//
// The persisted role says what this node WAS. While it was down its standby
// may have promoted; resuming on the file alone gives two leaders. There is no
// lease to ask, and a standby that has not promoted runs no Control Plane
// listener, so an unanswered dial is equally a healthy standby, a dead peer or
// a partition — peer reachability proves nothing in either direction. The
// evidence that does exist, and the only evidence used:
//
//  1. No standby has ever synced from this node (standby_addr is empty): no
//     other node holds this cluster's state, and CLU-004 forbids promoting such
//     a node automatically. Authority is established.
//  2. The peer POLLS this node: an authenticated HASync that says role=standby
//     (or carries no role: an older standby build, which has no other reason to
//     call it), received after this restart. Only a standby polls; a node that
//     promoted stops. It is the peer's own statement that it does not lead. The
//     resume completes inside that RPC and the same RPC is then answered, so
//     the proving poll is not a failed round for the standby.
//  3. The peer ANSWERS this node's HASync with a term above ours: it promoted.
//     This node joins it as standby (enterStandbyResync) — automatic,
//     idempotent, no operator act.
//  4. An operator asserts leadership (the promote endpoint), audited.
//
// Otherwise authority is NOT established and the node stays in the HA-gated
// state ha_intent.go already defines: no HA role, leader-gated RPCs and CA
// issuance refused, /healthz 503, distributed-configuration mutations refused
// (ha_write_gate.go); the proxy, the admin UI and diagnostics keep working.
// The attempt is retried by the existing loop and paged once per episode.
//
// Lease mode never reaches this file's decision: the lease is the authority.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errLegacyAuthorityNotEstablished gates a legacy leader resume that has no
// evidence of exclusive authority yet.
var errLegacyAuthorityNotEstablished = errors.New("exclusive HA leadership could not be established after the restart: " +
	"the standby has neither polled this node nor answered as leader (no fencing lease is configured)")

// errLegacyPeerAlsoLeads: the peer serves as leader at a term that is not
// above ours — two leaders of the same or an older term. Neither may yield
// automatically; an operator decides.
var errLegacyPeerAlsoLeads = errors.New("the HA peer is serving as leader at a term that is not above this node's: " +
	"two leaders exist and neither can be shown to be the later one")

// haRoleRevalidating is the role a restarting legacy leader states in its
// probe, so the probe is never mistaken for a standby's poll (two restarting
// leaders probing each other must not each take the other for a standby).
const haRoleRevalidating = "leader-revalidating"

// legacyAuthorityState is the evidence gathered since this process started.
// Guarded by mu; leaf lock.
var legacyAuthority struct {
	mu             sync.Mutex
	standbyPollAt  time.Time // an authenticated standby poll arrived
	operatorAssert bool      // an operator asserted leadership
}

// resumeAttemptMu serializes resumeLeadershipAttempt: the retry loop, the
// standby poll that proves authority and an operator assertion all run it.
var resumeAttemptMu sync.Mutex

func resetLegacyAuthorityEvidence() {
	legacyAuthority.mu.Lock()
	legacyAuthority.standbyPollAt = time.Time{}
	legacyAuthority.operatorAssert = false
	legacyAuthority.mu.Unlock()
}

type legacyVerdict int

const (
	legacyProceed    legacyVerdict = iota // resume as leader
	legacyJoined                          // joined the peer as standby: decided, not leader
	legacyUndecided                       // gated; retry
	legacyNotStandby                      // peer leads but this node could not enter standby: gated
)

// haProbePeerLeader asks the recorded standby address whether it leads, and at
// which term. answered is false when it did not answer as a leader (no
// listener, unreachable, refused, or not the leader). Test seam.
var haProbePeerLeader = func(cfg *haConfig) (term uint64, answered bool) {
	rc := globalHA.resyncMaterial()
	if !rc.set {
		return 0, false
	}
	client, err := NewDataPlaneClient("ha-revalidate", cfg.StandbyAddr, rc.certFile, rc.keyFile, rc.caFile)
	if err != nil {
		return 0, false
	}
	defer func() {
		client.mu.Lock()
		if client.conn != nil {
			_ = client.conn.Close()
		}
		client.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), dpTightCallDeadline)
	defer cancel()
	req, _ := json.Marshal(map[string]any{"token": cfg.Token, "role": haRoleRevalidating, "term": cfg.Term})
	raw, err := client.call(ctx, methodHASync, json.RawMessage(req))
	if err != nil {
		return 0, false
	}
	var reply struct {
		LeaderTerm uint64 `json:"leader_term"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return 0, false
	}
	return reply.LeaderTerm, true
}

func (h *HAState) resyncMaterial() haResyncContext {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.resync
}

// legacyRestartAuthority decides one resume attempt of a persisted LEADER.
func legacyRestartAuthority(cfg *haConfig) legacyVerdict {
	if globalHA.leaseConfigured() {
		return legacyProceed // the lease is the authority (ADR-0005)
	}
	if cfg.StandbyAddr == "" {
		return legacyProceed // evidence 1: no standby ever synced from this node
	}
	legacyAuthority.mu.Lock()
	polled, asserted := !legacyAuthority.standbyPollAt.IsZero(), legacyAuthority.operatorAssert
	legacyAuthority.mu.Unlock()
	if asserted {
		logger.Printf("HA: an operator asserted leadership — resuming as leader without evidence from the standby")
		return legacyProceed
	}
	if polled {
		logger.Printf("HA: the standby polled this node after the restart — it has not promoted; resuming as leader")
		return legacyProceed // evidence 2
	}
	term, answered := haProbePeerLeader(cfg)
	if !answered {
		haIntentStillUnknown(errLegacyAuthorityNotEstablished)
		return legacyUndecided
	}
	if term <= cfg.Term {
		haIntentStillUnknown(fmt.Errorf("%w (peer term %d, this node's term %d)", errLegacyPeerAlsoLeads, term, cfg.Term))
		return legacyUndecided
	}
	return joinPromotedPeer(cfg, term)
}

// joinPromotedPeer makes this node a standby of the peer that promoted while
// it was down (evidence 3).
func joinPromotedPeer(cfg *haConfig, peerTerm uint64) legacyVerdict {
	logger.Printf("HA: the standby promoted while this node was down (its term %d is above ours, %d) — "+
		"joining it as standby instead of resuming leadership", peerTerm, cfg.Term)
	globalHA.adoptPersistedForStandby(cfg)
	if !globalHA.enterStandbyResync("peer leads a later term after this node's restart") {
		haIntentStillUnknown(fmt.Errorf("the HA peer leads term %d but this node has no resync material to join it as standby", peerTerm))
		return legacyNotStandby
	}
	globalHAFailoverRing.Load().record("leader", "standby", "restart: peer leads a later term", 0, time.Now())
	return legacyJoined
}

// adoptPersistedForStandby loads what enterStandbyResync reads from the
// persisted leader config.
func (h *HAState) adoptPersistedForStandby(cfg *haConfig) {
	h.mu.Lock()
	h.token = cfg.Token
	h.standbyAddr = cfg.StandbyAddr
	h.autoFailover = cfg.AutoFailover
	h.mu.Unlock()
}

// legacyRevalidationPending reports whether this node is a restarted legacy
// leader still waiting for evidence.
func (h *HAState) legacyRevalidationPending() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.intent.reason != "" && h.intent.legacy && h.role == ""
}

// markIntentLegacy tags the open intent episode as a legacy revalidation.
func (h *HAState) markIntentLegacy() {
	h.mu.Lock()
	if h.intent.reason != "" {
		h.intent.legacy = true
	}
	h.mu.Unlock()
}

// haStandbyPollRequest is the part of an HASync request the revalidation reads.
type haStandbyPollRequest struct {
	Token string `json:"token"`
	Role  string `json:"role"`
	Term  uint64 `json:"term"`
}

// noteStandbyPollWhileRevalidating is called for every inbound HASync BEFORE
// the leader gate. While this node is revalidating, an authenticated poll from
// a standby is the evidence that establishes authority: it is recorded and the
// resume is run at once, so the gate that follows sees a leader and this very
// poll is answered.
func noteStandbyPollWhileRevalidating(raw json.RawMessage) {
	if !globalHA.legacyRevalidationPending() {
		return
	}
	var req haStandbyPollRequest
	if json.Unmarshal(raw, &req) != nil || (req.Role != "" && req.Role != "standby") {
		return
	}
	cfg, err := loadHAConfig()
	if action, aerr := haPersistedAction(cfg, err); aerr != nil || action != "leader" || cfg.Token == "" ||
		subtle.ConstantTimeCompare([]byte(req.Token), []byte(cfg.Token)) != 1 {
		return
	}
	if req.Term > cfg.Term {
		return // a standby of a LATER term than ours is not our standby
	}
	legacyAuthority.mu.Lock()
	legacyAuthority.standbyPollAt = time.Now()
	legacyAuthority.mu.Unlock()
	resumeLeadershipAttempt()
}

// assertLegacyLeadership is the operator break-glass for a revalidating node
// whose standby is gone for good. Reports whether the node now leads.
func assertLegacyLeadership() bool {
	if !globalHA.legacyRevalidationPending() {
		return false
	}
	legacyAuthority.mu.Lock()
	legacyAuthority.operatorAssert = true
	legacyAuthority.mu.Unlock()
	resumeLeadershipAttempt()
	return globalHA.IsLeader()
}

// haAuthorityStatus is the HA status surface's view of leadership authority:
// "" when there is nothing to say.
func haAuthorityStatus() (state, reason string) {
	if globalHA.legacyRevalidationPending() {
		r, _ := globalHA.intentGate()
		return "revalidating", r
	}
	return "", ""
}

// haLeadershipHeld reports whether this node holds HA leadership for
// leadership-dependent operations: the leader role, and in lease mode the
// fence. A standalone (HA off) control plane holds it trivially. It is one of
// the two predicates the node-lifecycle surface reads (ADR-0064); the other is
// haPublishAuthorized.
func haLeadershipHeld() bool {
	if _, gated := globalHA.intentGate(); gated {
		return false
	}
	st := globalHA.Status()
	if !st.Enabled {
		return true
	}
	return st.Role == "leader" && globalHA.WriteAllowed()
}

// haNodeStartingMarker is the text a Control Plane listener that is up before
// the node is ready puts in the gRPC status it refuses requests with (code
// Unavailable). A standby treats such a refusal as an ANSWERED round: a
// restarting leader with a live standby must never trigger that standby's
// promotion. The early-listener work emits it; this is the agreed constant.
const haNodeStartingMarker = "culvert-node-starting"

// haLeaderStartingError reports whether err is a leader's "starting, not
// ready" refusal.
func haLeaderStartingError(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.Unavailable && strings.Contains(st.Message(), haNodeStartingMarker)
}
