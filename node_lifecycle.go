package main

// node_lifecycle.go — the node's start-up lifecycle, owned in ONE place.
//
// Nothing infers "may I serve / publish / lead" from a side effect such as "the
// listener is bound". The start-up sequence (main.go runStartupSequence)
// advances one phase, and every consumer asks an accessor:
//
//	nodeLive()            the process is up and running its sequence
//	nodeReady()           every store is loaded and the cluster role is active:
//	                      the node may answer cluster RPCs with real data
//	haLeadershipHeld()    this node holds leadership           (ha_authority.go)
//	haPublishAuthorized() this node may distribute a snapshot  (ha_authority.go)
//
// The four are ORTHOGONAL. A node is live long before it is ready; a ready
// node may be a standby (no leadership); a leader may be refused publication
// by the publication safety gate. Leadership acquisition and publishing
// authorization are separate questions with separate answers.
//
//	phase            entered by                    cluster listener answers
//	unmanaged        (zero value)                  real handlers — see below
//	identity         enterStartupIdentityPhase     CULVERT_NODE_STARTING
//	loading-stores   enterStartupStoresPhase       CULVERT_NODE_STARTING
//	activating       enterStartupActivationPhase   CULVERT_NODE_STARTING
//	ready            markNodeReady                 real handlers
//
// "unmanaged" is a process whose lifecycle nothing drives: a one-shot command,
// or a test that calls a handler or an activation directly. It reads as ready
// (and may publish) so that code which never entered the sequence behaves as
// it always did; the production sequence leaves it in its first statement.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type nodePhase int32

const (
	nodePhaseUnmanaged     nodePhase = iota // not driven by the start-up sequence
	nodePhaseIdentity                       // node services, cluster identity and trust
	nodePhaseLoadingStores                  // configuration stores and their reconciliation
	nodePhaseActivating                     // the cluster role is starting to act
	nodePhaseReady                          // stores loaded, role active, about to open traffic gates
)

func (p nodePhase) String() string {
	switch p {
	case nodePhaseUnmanaged:
		return "unmanaged"
	case nodePhaseIdentity:
		return "identity"
	case nodePhaseLoadingStores:
		return "loading-stores"
	case nodePhaseActivating:
		return "activating"
	case nodePhaseReady:
		return "ready"
	default:
		return fmt.Sprintf("unknown(%d)", int32(p))
	}
}

// nodeLifecyclePhase is the one piece of lifecycle state. Written only by the
// enter*/mark* functions below, in runStartupSequence's order.
var nodeLifecyclePhase atomic.Int32

func currentNodePhase() nodePhase { return nodePhase(nodeLifecyclePhase.Load()) }

// advanceNodePhase moves the lifecycle FORWARD to p; it never goes back.
func advanceNodePhase(p nodePhase) {
	for {
		cur := nodeLifecyclePhase.Load()
		if int32(p) <= cur || nodeLifecyclePhase.CompareAndSwap(cur, int32(p)) {
			return
		}
	}
}

// enterStartupIdentityPhase is the first statement of the start-up sequence:
// from here until markNodeReady the node is live and NOT ready.
func enterStartupIdentityPhase() { advanceNodePhase(nodePhaseIdentity) }

// enterStartupStoresPhase: identity is established; the stores load next.
func enterStartupStoresPhase() { advanceNodePhase(nodePhaseLoadingStores) }

// enterStartupActivationPhase: every store is loaded; the cluster role may
// start acting, and a publish is no longer premature.
func enterStartupActivationPhase() { advanceNodePhase(nodePhaseActivating) }

// markNodeReady: the role is active (a control plane has published). The
// traffic gates and listeners open after this.
func markNodeReady() {
	advanceNodePhase(nodePhaseReady)
	logger.Printf("Startup: node READY %s after process start (stores loaded, cluster role activated)",
		nodeStartupElapsed().Round(time.Millisecond))
}

// nodeLive reports that the process is running: true from the first statement
// of the sequence (and for an unmanaged process). It says nothing about
// whether the node can serve.
func nodeLive() bool { return true }

// nodeReady reports that the node may answer cluster RPCs with real data.
func nodeReady() bool {
	p := currentNodePhase()
	return p == nodePhaseUnmanaged || p == nodePhaseReady
}

// nodePublishPhaseReached reports that start-up has reached the point where a
// snapshot publish is not premature: every store has loaded. It is the
// LIFECYCLE half of "may this node publish"; leadership and the publication
// safety gate are the other, separate halves (ha_authority.go).
func nodePublishPhaseReached() bool {
	p := currentNodePhase()
	return p == nodePhaseUnmanaged || p >= nodePhaseActivating
}

// nodeStartupElapsed is the time since the process started.
func nodeStartupElapsed() time.Duration { return time.Since(startTime) }

// nodeLifecycleStatus is the lifecycle as the health surfaces report it.
type nodeLifecycleStatus struct {
	Phase             string `json:"phase" redact:"public"`
	Live              bool   `json:"live" redact:"public"`
	Ready             bool   `json:"ready" redact:"public"`
	LeadershipHeld    bool   `json:"leadership_held" redact:"public"`
	PublishAuthorized bool   `json:"publish_authorized" redact:"public"`
}

func currentNodeLifecycleStatus() nodeLifecycleStatus {
	pub, _ := nodePublishAuthorized()
	return nodeLifecycleStatus{
		Phase: currentNodePhase().String(), Live: nodeLive(), Ready: nodeReady(),
		LeadershipHeld: nodeLeadershipHeld(), PublishAuthorized: pub,
	}
}

// ── the wire statuses ───────────────────────────────────────────────────────
//
// Both are gRPC code Unavailable — the code every released data plane and
// standby already treats as "this control plane cannot serve me now, retry or
// fail over" — with a fixed token leading the message, so a current peer can
// tell them apart from a transport failure and from each other.

const (
	// cpStartingStatusMarker marks "the node is alive and still starting".
	cpStartingStatusMarker = "CULVERT_NODE_STARTING"
	// cpPublishRefusedMarker marks "the node is ready but may not
	// distribute a snapshot" (leadership / publication safety gate).
	cpPublishRefusedMarker = "CULVERT_PUBLISH_NOT_AUTHORIZED"
)

// cpStartingStatus is the answer to method until start-up has completed. It
// carries the phase and the seconds since process start, so a standby can log
// both and bound how long it treats a starting leader as alive.
func cpStartingStatus(method string) error {
	return status.Errorf(codes.Unavailable, "%s: control plane is starting (phase=%s elapsed_seconds=%d); %s is not served until the node is ready",
		cpStartingStatusMarker, currentNodePhase(), int64(nodeStartupElapsed().Seconds()), method)
}

func cpPublishNotAuthorizedStatus(method, reason string) error {
	return status.Errorf(codes.Unavailable, "%s: %s; %s is not served", cpPublishRefusedMarker, reason, method)
}

func cpStatusHasMarker(err error, token string) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.Unavailable && strings.HasPrefix(st.Message(), token+":")
}

// isCPStartingStatus reports whether err is a control plane's "alive, still
// starting" answer: an ANSWERED round, not an unreachable peer.
func isCPStartingStatus(err error) bool { return cpStatusHasMarker(err, cpStartingStatusMarker) }

// isCPPublishNotAuthorizedStatus reports whether err is a ready control
// plane's refusal to distribute a snapshot.
func isCPPublishNotAuthorizedStatus(err error) bool {
	return cpStatusHasMarker(err, cpPublishRefusedMarker)
}

// cpStartingStatusFields extracts the phase and elapsed seconds a starting
// answer carries. ok is false when err is not one.
func cpStartingStatusFields(err error) (phase string, elapsedSeconds int64, ok bool) {
	if !isCPStartingStatus(err) {
		return "", 0, false
	}
	msg := status.Convert(err).Message()
	at := strings.Index(msg, "(phase=")
	if at < 0 {
		return "", 0, true // a starting answer whose fields this build cannot read
	}
	if _, scanErr := fmt.Sscanf(msg[at:], "(phase=%s elapsed_seconds=%d)", &phase, &elapsedSeconds); scanErr != nil {
		return "", 0, true
	}
	return phase, elapsedSeconds, true
}

// nodeLeadershipHeld and nodePublishAuthorized are the two authority answers
// as this file's gates consume them: haLeadershipHeld and haPublishAuthorized
// (ha_authority.go), through variables so a test can exercise each refusal
// without the HA machinery. Production never reassigns them.
var (
	nodeLeadershipHeld    = haLeadershipHeld
	nodePublishAuthorized = haPublishAuthorized
	// nodeDistributionRefused decides the BLANKET refusal of the
	// snapshot-serving RPCs. It is narrower than "not publish-authorized": during
	// a publication hold (ADR-0064) the gate answers each data plane itself —
	// consistent ones are served, ahead ones keep their state — and HASync stays
	// served so the standby stays eligible and inherits the hold. Refusing
	// everything on haPublishAuthorized would freeze consistent data planes.
	nodeDistributionRefused = haDistributionRefused
)

// cpSnapshotServingMethods are the RPCs that hand a peer a configuration
// snapshot. Beyond readiness they require publication authorization.
var cpSnapshotServingMethods = map[string]bool{"GetConfig": true, "GetConfigDelta": true, "HASync": true}

// nodeServingRefusal is the lifecycle gate in front of EVERY ConfigService
// handler (gatedUnary): nil to serve, otherwise the status to return.
func nodeServingRefusal(method string) error {
	if !nodeReady() {
		return cpStartingStatus(method)
	}
	if cpSnapshotServingMethods[method] {
		if reason, refused := nodeDistributionRefused(); refused {
			return cpPublishNotAuthorizedStatus(method, reason)
		}
	}
	return nil
}

// ── health surfaces ─────────────────────────────────────────────────────────
//
// The lifecycle is reported on the surfaces that already exist — the proxy
// port's /health (liveness) and /ready (readiness), the admin /healthz and
// /api/cluster/status — and, while the node is starting and none of those
// listeners is up yet, by the cluster listener's own CULVERT_NODE_STARTING
// answer, which carries the phase. No endpoint is added.

// startupHealthFieldValue is /health's `startup` field: the phase, or "" for
// an unmanaged process (the field is then omitted).
func startupHealthFieldValue() string {
	if p := currentNodePhase(); p != nodePhaseUnmanaged {
		return p.String()
	}
	return ""
}

// appendStartupReadinessCheck adds /ready's gating `startup` row and reports
// whether it passes. No row for an unmanaged process.
func appendStartupReadinessCheck(checks map[string]*readinessCheck) (ok bool) {
	p := currentNodePhase()
	switch p {
	case nodePhaseUnmanaged:
		return true
	case nodePhaseReady:
		checks["startup"] = &readinessCheck{Status: "ok"}
		return true
	default:
		checks["startup"] = &readinessCheck{Status: "fail", Detail: "starting: " + p.String()}
		return false
	}
}

// addLifecycleHealth adds the lifecycle to an admin health/status response:
// the phase, readiness, and — reported separately, because they are separate
// — whether leadership is held and whether publication is authorized.
func addLifecycleHealth(resp map[string]any) {
	st := currentNodeLifecycleStatus()
	resp["startup_phase"] = st.Phase
	resp["ready"] = st.Ready
	resp["leadership_held"] = st.LeadershipHeld
	resp["publish_authorized"] = st.PublishAuthorized
}
