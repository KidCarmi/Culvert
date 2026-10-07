package main

// cp_grpc_health.go — CHAOS-71: the Control Plane gRPC listener's health plane.
//
// This is the observability half of the finding; the lifecycle half is in
// cp_grpc_supervisor.go and the finding itself is recorded in
// roadmap/CHAOS-ENGINEERING-REVIEW.md §41. Read that header first — it explains
// why the two halves had to ship together, which is the load-bearing part of
// this change.
//
// What was missing, in one sentence: nothing in the process ever asked whether
// the Control Plane's gRPC listener was alive. `clusterRole.grpcSrv` is written
// once by StartControlPlaneGRPC and read in exactly one other place —
// StopControlPlaneGRPC — so a listener that never bound, or that bound and then
// died, was indistinguishable on every surface from a healthy one:
//
//   - `/healthz` answered `{"status":"ok","role":"leader","write_authority":true}`.
//   - `/health` carried `cluster_ca` but no field for the listener in front of it.
//   - `/metrics` carried `culvert_cluster_ratelimit_*` — the DP-side view — and
//     nothing about the CP's own listener.
//   - `/api/diagnostics` had rows for the admin UI listener and the SOCKS5
//     listener, and none for the listener the whole fleet depends on.
//
// And the fencing lease kept renewing throughout, because leaseKeepaliveLoop
// renews on a ticker against etcd and has no knowledge of the gRPC server. So a
// leader whose control plane was dark held the fence against its own standby,
// which is the inverse of CHAOS-55: that sweep handled a leader that CANNOT
// WRITE (unfenced), this one a leader that holds the fence and CANNOT BE
// REACHED.
//
// Surfaces, all reusing the vocabulary CHAOS-54/57/66 already established so an
// operator who can read one listener runbook can read this one:
//
//   - `/api/diagnostics` — the `control_plane_listener` operator-contract row.
//   - `/health` (PROXY port) — the `control_plane` posture field, a fixed enum.
//     On the proxy port deliberately: it is the surface that survives, exactly
//     as CHAOS-57 put the `admin_ui` field there. A CP whose gRPC listener is
//     down is still proxying, so the proxy port answers while the thing being
//     measured does not.
//   - `/ready` (proxy port) — a report-only `control_plane` row. REPORT-ONLY is
//     load-bearing for CHAOS-57's reason: a CP node whose gRPC listener cannot
//     bind is serving its own traffic perfectly, and failing readiness would
//     eject a healthy gateway from the load balancer over a cluster-control
//     fault. Strict callers opt in via ?strict=1.
//   - `/healthz` (admin port) — the `control_plane` + `control_plane_unavailable`
//     fields on the leader response. See the note on cpGRPCHealthzFields for
//     why the HTTP status and the `status` string are deliberately UNCHANGED.
//   - `/metrics` — culvert_cp_grpc_{up,unavailable,bind_failures_total,
//     binds_total,bind_backoff_seconds,serve_exits_total}.
//   - alerts — `control_plane_unavailable`.
//
// Every series is emitted ONLY when a Control Plane listener was configured.
// That is the socks5/cluster_ca/dns rule and it matters here as much as
// anywhere: `culvert_cp_grpc_up 0` on a standalone appliance that never asked
// for a control plane is indistinguishable from a CP whose listener is dead,
// and the documented paging rule is `== 0`.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// cpGRPCBindBackoffInitial / cpGRPCBindBackoffMax bound the RATE of rebind
	// attempts, never their COUNT.
	//
	// Never bounding the count is the CHAOS-55 argument, and it is stronger
	// here than for either listener that established it: the terminal state of
	// "give up" is a fleet whose Control Plane is gone until someone restarts
	// it, with every Data Plane frozen on its last snapshot. "Avoid infinite
	// retries" is satisfied the CHAOS-54/55/57 way — the retry is never
	// SILENT. The first failure logs immediately, then at most one line per
	// cpGRPCBindLogInterval, then one recovery line naming the suppressed
	// count, with the magnitude carried by a counter and the state by a gauge,
	// a contract row and an alert.
	//
	// The values mirror adminUIListenBackoff* and socks5BindBackoff* exactly,
	// because it is the same fault class on the same kind of socket and a third
	// cadence would be a third thing for an operator to learn.
	cpGRPCBindBackoffInitial = 1 * time.Second
	cpGRPCBindBackoffMax     = 30 * time.Second

	// cpGRPCBindJitter spreads the backoff by ±20%. A fleet restarts together,
	// and in an HA pair the two CPs are the LAST pair of processes that should
	// retry a bind in lockstep. Matches adminUIListenJitter, socks5BindJitter
	// and haLeaseRecoveryJitter.
	cpGRPCBindJitter = 0.20

	// cpGRPCBindLogInterval rate-limits the bind-failure log line. Same
	// discipline as every other listener in the tree: the log carries the
	// SIGNAL, the counter carries the MAGNITUDE, and a mitigation for a crash
	// loop must not itself become a log flood.
	cpGRPCBindLogInterval = 60 * time.Second

	// cpGRPCUnavailableAfter is how long the listener must be continuously
	// unbindable before it is reported UNAVAILABLE (fail row, alert, gauge at
	// zero) rather than merely retrying.
	//
	// Unavailability is a DURATION, not a count — the CHAOS-54/57/66 rule. In
	// an HA pair a planned handoff hands the CP port from one process to
	// another and a predecessor still draining clears in a few seconds; paging
	// on that would page on every ordinary failover.
	cpGRPCUnavailableAfter = 30 * time.Second
)

// cpGRPCListenerHealth is the process-wide record of the Control Plane gRPC
// listener's state.
//
// Mutex-guarded rather than atomic-per-field because every reader (the
// diagnostics row, the readiness row, the two health fields, the metrics block)
// needs a view that is consistent across all of it — a row that said "serving"
// while the gauge said 0 would be worse than either alone.
type cpGRPCListenerHealth struct {
	mu sync.Mutex

	// configured is set before the FIRST bind attempt, not after a successful
	// one. That ordering is load-bearing and is CHAOS-66's rule: it gates every
	// surface in this file, so recording it after the bind would report a
	// Control Plane that has NEVER come up as "no control plane configured" —
	// indistinguishable from the ordinary standalone appliance, on exactly the
	// node where an operator is trying to find out why the fleet is not
	// syncing.
	configured bool
	addr       string

	// serving is true between an observed successful bind and the serve call
	// returning. everServed separates the two operator situations that look
	// identical in a gauge and need different responses: a CP that has NEVER
	// come up (a misconfiguration — wrong address, occupied port, a deployment
	// that was never a working CP) versus one that was up and fell over (an
	// environmental fault, or the serve-exit case this file exists to catch).
	serving    bool
	everServed bool

	// stopped records the loop exiting for SHUTDOWN rather than for a fault, so
	// a node in the middle of a clean teardown never reports a CP failure on
	// its way out.
	stopped bool

	// firstFailure is the start of the current run of consecutive failures;
	// zero while serving. Unavailability is measured from here, so a listener
	// that fails, binds, and fails again never accumulates toward the threshold
	// across healthy periods.
	firstFailure time.Time
	lastFailure  time.Time
	lastReason   string
	backoff      time.Duration

	// consecutive resets on an observed successful BIND; total never does.
	// Recovery is established by EVIDENCE (a listener that actually bound),
	// never by elapsed time — the house rule from storage_health.go, ca_health.go
	// and every listener plane since.
	consecutive int64
	total       int64
	binds       int64

	// serveExits counts the times a BOUND listener's Serve returned without a
	// shutdown having been requested. This is the counter the pre-CHAOS-71 code
	// had no equivalent of: `srv.Serve(ln)` logged one line and its goroutine
	// exited, leaving a dark control plane that every surface reported as
	// healthy. It is kept separate from bind failures because the two point at
	// different questions — a bind failure says the socket could not be taken,
	// a serve exit says a working socket went away.
	serveExits int64

	// logAt / suppressed implement the rate-limited log line.
	logAt      time.Time
	suppressed int64

	// alerted is the fire-once-per-episode latch for `control_plane_unavailable`.
	// Cleared only by an observed bind, never by elapsed time.
	alerted bool
}

var cpGRPCListener cpGRPCListenerHealth

// cpGRPCEverFailed is read by the metrics block to decide whether to emit the
// counters at all on a node that has had a perfectly healthy CP since boot. An
// atomic rather than a field read so /metrics does not take the record's mutex
// on every scrape just to answer "is there anything to say".
var cpGRPCEverFailed atomic.Bool

// cpGRPCListenerSnapshot is a consistent point-in-time view of the record.
type cpGRPCListenerSnapshot struct {
	Configured  bool
	Addr        string
	Serving     bool
	EverServed  bool
	Stopped     bool
	Failing     bool
	Unavailable bool
	LastReason  string
	Backoff     time.Duration
	Consecutive int64
	Total       int64
	Binds       int64
	ServeExits  int64
	FailingFor  time.Duration
}

// cpGRPCListenerState returns a consistent snapshot of the record.
//
// FailingFor is derived from the two stored stamps, which means it FREEZES
// between attempts — the CHAOS-66 round-3 defect, where an episode's duration
// stopped advancing the instant an attempt returned and a node sat below the
// unavailability threshold for up to a full backoff ceiling AFTER the
// documented window had elapsed. The clamp in cpGRPCSupervisor.run is the other
// half of the answer: it shortens the one sleep that would straddle the
// threshold, so an attempt always lands to observe the transition. The read
// path here is deliberately clock-free so a snapshot stays a pure function of
// recorded state — the determinism property CHAOS-66 had to retrofit.
func cpGRPCListenerState() cpGRPCListenerSnapshot {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	return cpGRPCListenerStateLocked()
}

func cpGRPCListenerStateLocked() cpGRPCListenerSnapshot {
	snap := cpGRPCListenerSnapshot{
		Configured:  cpGRPCListener.configured,
		Addr:        cpGRPCListener.addr,
		Serving:     cpGRPCListener.serving,
		EverServed:  cpGRPCListener.everServed,
		Stopped:     cpGRPCListener.stopped,
		LastReason:  cpGRPCListener.lastReason,
		Backoff:     cpGRPCListener.backoff,
		Consecutive: cpGRPCListener.consecutive,
		Total:       cpGRPCListener.total,
		Binds:       cpGRPCListener.binds,
		ServeExits:  cpGRPCListener.serveExits,
	}
	if !cpGRPCListener.firstFailure.IsZero() {
		snap.Failing = true
		snap.FailingFor = cpGRPCListener.lastFailure.Sub(cpGRPCListener.firstFailure)
		snap.Unavailable = snap.FailingFor >= cpGRPCUnavailableAfter
	}
	return snap
}

// errCPGRPCTLSMaterial tags a failure to assemble the Control Plane's TLS
// material (missing or unreadable cert/key/CA, or the refusal to run without
// TLS and without -cluster-insecure), so the classifier can name it without
// matching on error text.
//
// It is the CP's ONE plane-specific fault class, the exact counterpart of
// errAdminUITLSMaterial, and it is checked BEFORE the shared table for the same
// reason: it has its own remedy and must not appear in another listener's
// vocabulary.
var errCPGRPCTLSMaterial = errors.New("control plane grpc tls material")

// classifyCPGRPCListenError maps a bind/serve error to a BOUNDED reason class.
//
// Never a raw error string: the listen error text embeds the bind address, the
// TLS error can quote an operator-configured path, and the operator-contract
// row is a VIEWER-role surface. More importantly an unbounded reason gives the
// alert dedup key one distinct value per failure (the WK-12/RS-5 defect). The
// full error reaches the rate-limited log line and nowhere else.
func classifyCPGRPCListenError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, errCPGRPCTLSMaterial) {
		return "tls_material"
	}
	// CHAOS-71: the errno/timeout/fallback mapping is SHARED with the admin UI
	// and SOCKS5 listeners (listener_fault_class.go). Writing a third copy here
	// is precisely what that file exists to prevent — the two existing copies
	// already shared one defect that had to be fixed in both.
	return classifyListenerFault(err)
}

// fireCPGRPCListenerAlert delivers the `control_plane_unavailable` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
//
// This is a NEW event name, which the repository's own rule treats as a cost: a
// new name is silently unsubscribed on every webhook already configured in the
// field. It is minted anyway because there is no existing event for "this
// node's cluster control plane is unreachable" — the closest candidates name a
// different plane with a different remedy (`admin_ui_unavailable` is the
// management UI, `cert_expiry` with Host `culvert-cluster-ca` is the cluster
// CA), and reusing one of those would send an operator to the wrong runbook.
// That is the same judgement CHAOS-54 made when it minted
// `socks5_listener_down` for a genuinely new plane, as against CHAOS-66, which
// extended that existing plane and deliberately minted nothing. The
// subscription caveat is carried in the runbook.
var fireCPGRPCListenerAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("control_plane_unavailable") {
		return
	}
	go fireAlert("control_plane_unavailable", AlertPayload{
		Detail: detail,
		Source: "control_plane",
	})
}

// noteCPGRPCConfigured records that a Control Plane listener was requested.
// Called before the first bind attempt — see the `configured` field comment for
// why that ordering is load-bearing.
func noteCPGRPCConfigured(addr string) {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.configured = true
	cpGRPCListener.addr = addr
	cpGRPCListener.stopped = false
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCBindFailure records one failed bind attempt. It returns whether the
// caller should emit a log line, and how long the current episode has been
// running so the caller can keep its retry cadence inside the unavailability
// threshold (see clampCPGRPCBindSleep).
func noteCPGRPCBindFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool, failingFor time.Duration) {
	cpGRPCEverFailed.Store(true)

	cpGRPCListener.mu.Lock()

	cpGRPCListener.serving = false
	cpGRPCListener.total++
	cpGRPCListener.consecutive++
	cpGRPCListener.lastFailure = now
	cpGRPCListener.lastReason = reason
	cpGRPCListener.backoff = backoff
	cpGRPCListener.stopped = false
	if cpGRPCListener.firstFailure.IsZero() {
		cpGRPCListener.firstFailure = now
	}

	if cpGRPCListener.logAt.IsZero() || now.Sub(cpGRPCListener.logAt) >= cpGRPCBindLogInterval {
		cpGRPCListener.logAt = now
		shouldLog = true
	} else {
		cpGRPCListener.suppressed++
	}

	failingFor = now.Sub(cpGRPCListener.firstFailure)
	unavailable := failingFor >= cpGRPCUnavailableAfter
	fireNow := unavailable && !cpGRPCListener.alerted
	if fireNow {
		cpGRPCListener.alerted = true
	}
	cpGRPCListener.mu.Unlock()

	if fireNow {
		// Detail is BOUNDED — it is the dedup key. The reason CLASS and the
		// episode duration only; never the error text, never the bind address
		// (which would give the key one value per deployment and put the
		// cluster topology on a webhook).
		fireCPGRPCListenerAlert(fmt.Sprintf(
			"Control Plane gRPC listener unavailable for %s (%s); the listener keeps retrying. "+
				"Data Plane nodes cannot sync configuration, enroll, or renew certificates while it is down. "+
				"This node's own HTTP/HTTPS proxy and admin UI are unaffected.",
			failingFor.Round(time.Second), reason))
	}
	return shouldLog, failingFor
}

// noteCPGRPCBound records an OBSERVED successful bind. This is the ONLY thing
// that clears the failing state — never elapsed time, because a loop that
// stopped failing because it stopped attempting looks identical to a bound one.
//
// It returns the suppressed-log count so the caller can emit one recovery line
// naming the magnitude the rate limiter withheld.
func noteCPGRPCBound() (wasFailing bool, suppressed int64, failures int64) {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()

	wasFailing = !cpGRPCListener.firstFailure.IsZero()
	suppressed = cpGRPCListener.suppressed
	failures = cpGRPCListener.consecutive

	cpGRPCListener.serving = true
	cpGRPCListener.everServed = true
	cpGRPCListener.stopped = false
	cpGRPCListener.binds++
	cpGRPCListener.consecutive = 0
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.lastFailure = time.Time{}
	cpGRPCListener.lastReason = ""
	cpGRPCListener.backoff = 0
	cpGRPCListener.logAt = time.Time{}
	cpGRPCListener.suppressed = 0
	cpGRPCListener.alerted = false
	return wasFailing, suppressed, failures
}

// noteCPGRPCServeExit records that a BOUND listener's Serve returned while the
// node was still supposed to be serving.
//
// This is the counter for the half of CHAOS-71 that had no surface at all. The
// pre-change code was:
//
//	go func() {
//	        if err := srv.Serve(ln); err != nil {
//	                logger.Printf("ControlPlane gRPC error: %v", err)
//	        }
//	}()
//
// — one log line, then the goroutine exits and the Control Plane is dark with
// `clusterRole.grpcSrv` still set, the HA role still "leader", the fencing
// lease still being renewed by a keepalive that knows nothing about this, and
// `/healthz` still answering `status: ok`.
func noteCPGRPCServeExit(reason string, now time.Time) {
	cpGRPCEverFailed.Store(true)
	cpGRPCListener.mu.Lock()
	cpGRPCListener.serving = false
	cpGRPCListener.serveExits++
	cpGRPCListener.lastReason = reason
	cpGRPCListener.lastFailure = now
	if cpGRPCListener.firstFailure.IsZero() {
		cpGRPCListener.firstFailure = now
	}
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCStopped records the supervisor exiting for shutdown.
func noteCPGRPCStopped() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.serving = false
	cpGRPCListener.stopped = true
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.lastFailure = time.Time{}
	cpGRPCListener.backoff = 0
	cpGRPCListener.mu.Unlock()
}

// nextCPGRPCBindBackoff doubles the backoff up to the ceiling.
func nextCPGRPCBindBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return cpGRPCBindBackoffInitial
	}
	next := cur * 2
	if next > cpGRPCBindBackoffMax {
		return cpGRPCBindBackoffMax
	}
	return next
}

// clampCPGRPCBindSleep shortens a sleep that would carry the loop PAST the
// unavailability threshold without an attempt landing to observe it.
//
// This is CHAOS-66's round-3 correctness bound, not a tuning knob. The alert is
// produced by an ATTEMPT (noteCPGRPCBindFailure holds the fire-once latch and
// nothing else wakes this loop), and FailingFor is derived from two stored
// stamps, so it freezes between attempts. Without the clamp, a failure landing
// at 29 s with a 30 s backoff leaves the contract row saying "retrying", the
// gauge at 1 and the page unfired for up to 36 s after the documented threshold
// elapsed.
//
// Clamping this ONE sleep is deliberately preferred over lowering the ceiling,
// which would pay permanently for a property that matters on a single sleep. At
// most one extra attempt per episode.
func clampCPGRPCBindSleep(wait, failingFor time.Duration) time.Duration {
	if failingFor >= cpGRPCUnavailableAfter {
		return wait
	}
	remaining := cpGRPCUnavailableAfter - failingFor
	if wait <= remaining {
		return wait
	}
	if remaining < cpGRPCBindClampFloor {
		return cpGRPCBindClampFloor
	}
	return remaining
}

// cpGRPCBindClampFloor is the shortest sleep clampCPGRPCBindSleep will produce,
// so the one attempt it schedules to observe the threshold cannot degenerate
// into a near-zero spin when the threshold is all but reached.
const cpGRPCBindClampFloor = 100 * time.Millisecond

// cpGRPCListenerStatus is the /health posture string for the Control Plane
// gRPC listener, served on the PROXY port — the surface that survives the fault
// the field describes.
//
// A fixed five-value enum, deliberately, because handleHealth serves this
// UNAUTHENTICATED on the proxy port. The posture is public; the RESOLUTION (the
// attempt count, the reason class — which would name, for instance, descriptor
// exhaustion) lives only on the role-gated /api/diagnostics row, the alert and
// the logs. Same discipline as the socks5 and admin_ui fields.
//
// "disabled" on the ordinary standalone appliance, so this field never reads as
// a fault on a node that never asked for a control plane.
func cpGRPCListenerStatus() string {
	snap := cpGRPCListenerState()
	switch {
	case !snap.Configured:
		return "disabled"
	case snap.Serving:
		return "ready"
	case snap.Stopped:
		return "stopped"
	case snap.Unavailable:
		return "unavailable"
	default:
		return "degraded"
	}
}

// cpGRPCUnavailableNow reports whether the Control Plane listener is
// configured and has been continuously unusable past the threshold.
//
// This is the predicate the /healthz leader response and the metrics gauge
// share, so the two can never disagree about whether this node's control plane
// is reachable — the "two answers to one question is the defect" rule from
// CHAOS-61.
func cpGRPCUnavailableNow() bool {
	snap := cpGRPCListenerState()
	return snap.Configured && !snap.Serving && !snap.Stopped && snap.Unavailable
}

// cpGRPCHealthzFields adds the Control Plane listener posture to a /healthz
// response body.
//
// WHAT THIS DELIBERATELY DOES NOT DO, and why that is a recorded posture
// decision rather than an oversight: it does not change the HTTP status code,
// and it does not change the `status` string. A leader whose control plane is
// dark still answers 200 with `"status":"ok"`.
//
// The argument for changing them is real. /healthz is explicitly an HA-role
// surface — a standby already answers 503, and ADR-0004's own comment says the
// fields exist so "an external monitor scraping BOTH CPs can DETECT
// split-brain" — so a dark leader arguably ought to answer 503 and let an
// orchestrator fail over.
//
// The argument against is the one CHAOS-57 settled for the report-only /ready
// row, and it decides this: flipping the code is a POSTURE change with an
// availability cost that belongs to the owner, not to a sweep. An orchestrator
// keying on the code may demote, restart, or fail over on a condition that
// clears by itself in seconds (a planned CP handoff hands this very port
// between two processes), and a flapping leader is a worse failure than a
// visible one. Surrendering the FENCE on a dark listener has the same shape and
// the same answer.
//
// So this change makes the state VISIBLE and leaves the decision expressible:
// an operator can page on `culvert_cp_grpc_unavailable == 1`, and the pair
// `cp_grpc_unavailable == 1 AND write_authority == 1` is exactly "I hold the
// fence and cannot be reached". Recorded as register row CP-4 for an owner.
func cpGRPCHealthzFields(resp map[string]any) {
	snap := cpGRPCListenerState()
	if !snap.Configured {
		return
	}
	resp["control_plane"] = cpGRPCListenerStatus()
	resp["control_plane_unavailable"] = cpGRPCUnavailableNow()
}

// checkCPGRPCListener is the `control_plane_listener` operator-contract row.
//
// Severity policy, mirroring checkAdminUIListener's so the two rows read the
// same way:
//   - not configured → ok. No control plane was requested (the ordinary
//     standalone appliance, and every one-shot command path).
//   - stopped → ok. The loop exited because the node is shutting down.
//   - unavailable (persistently unusable) → FAIL. A Control Plane that has been
//     unreachable for longer than the threshold is a real, operator-actionable
//     fleet fault: no Data Plane can sync configuration, enroll, or renew a
//     certificate against it, and in lease mode this node is holding the
//     fencing lease that would otherwise let its standby take over.
//   - failing but under the threshold → warn. Still retrying, and a
//     predecessor draining the port during a planned handoff clears on its own
//     within seconds; failing here would report a self-healing failover as
//     broken.
//   - serving → ok, carrying the cumulative failure and serve-exit counts so a
//     HISTORY of transient faults stays visible after recovery.
func checkCPGRPCListener() OperatorContractCheck {
	snap := cpGRPCListenerState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "control_plane_listener",
			Status:  diagOK,
			Message: "Control Plane gRPC not configured",
		}
	}
	if snap.Stopped {
		return OperatorContractCheck{
			Code:    "control_plane_listener",
			Status:  diagOK,
			Message: "Control Plane gRPC listener stopped (shutting down)",
		}
	}
	if snap.Serving {
		msg := "Control Plane gRPC listener serving"
		if snap.Total > 0 || snap.ServeExits > 0 {
			msg = fmt.Sprintf("Control Plane gRPC listener serving (%d bind failure(s), %d serve exit(s) since start)",
				snap.Total, snap.ServeExits)
		}
		return OperatorContractCheck{
			Code:    "control_plane_listener",
			Status:  diagOK,
			Message: msg,
		}
	}
	if snap.Unavailable {
		return OperatorContractCheck{
			Code:   "control_plane_listener",
			Status: diagFail,
			Message: fmt.Sprintf("Control Plane gRPC listener unavailable for %s (%s)",
				snap.FailingFor.Round(time.Second), snap.LastReason),
			OperatorAction: cpGRPCBindRemedy(snap.LastReason),
		}
	}
	return OperatorContractCheck{
		Code:   "control_plane_listener",
		Status: diagWarn,
		Message: fmt.Sprintf("Control Plane gRPC listener retrying (%s, %d consecutive failure(s))",
			snap.LastReason, snap.Consecutive),
		OperatorAction: cpGRPCBindRemedy(snap.LastReason),
	}
}

// cpGRPCBindRemedy selects the operator action for a bind-failure reason class.
//
// Per-class rather than one string for every class: that is CHAOS-66's round-3
// finding, where a node out of descriptors or with an interface not yet up was
// sent to hunt the owner of a port nobody holds. A bounded classifier is worth
// nothing if one remedy is printed for every class.
//
// Two clauses are invariant in every branch and must stay that way: the
// listener rebinds by itself (so nobody restarts a CP to achieve what is
// already in progress — the CHAOS-66 "unavailable until restart" correction),
// and this node's own proxy and admin UI are unaffected (so nobody treats a
// fleet-control fault as a traffic outage).
func cpGRPCBindRemedy(reason string) string {
	const tail = " The listener keeps retrying and rebinds by itself once the fault clears; " +
		"this node's HTTP/HTTPS proxy and admin UI are unaffected. Data Plane nodes keep serving " +
		"on their last synced configuration meanwhile."
	switch reason {
	case "port_in_use":
		return "Another process holds the Control Plane gRPC port. Check for a predecessor container still " +
			"draining, a second Culvert instance, or a host service on the same port (ss -ltnp)." + tail
	case "permission_denied":
		return "The process may not bind this port. Grant CAP_NET_BIND_SERVICE, run as a user that may bind " +
			"it, or move -cp-grpc-addr to an unprivileged port." + tail
	case "address_unavailable":
		return "The address in -cp-grpc-addr does not exist on this host yet — commonly a floating/VIP " +
			"address or an interface that is not up. Verify the address is present (ip addr)." + tail
	case "descriptors_exhausted":
		return "The process is out of file descriptors, so no socket can be opened. Raise the nofile limit " +
			"and look for a descriptor leak." + tail
	case "tls_material":
		return "The Control Plane TLS material could not be loaded. Verify -cp-grpc-cert/-cp-grpc-key/" +
			"-cp-grpc-ca exist and are readable, or set -cluster-insecure for development only." + tail
	default:
		return "See the rate-limited CPGRPC log line for the underlying error." + tail
	}
}

// resetCPGRPCHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `cpGRPCListener = cpGRPCListenerHealth{}`
// under the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex" (the CHAOS-54 note).
func resetCPGRPCHealthForTest() {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	cpGRPCListener.configured = false
	cpGRPCListener.addr = ""
	cpGRPCListener.serving = false
	cpGRPCListener.everServed = false
	cpGRPCListener.stopped = false
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.lastFailure = time.Time{}
	cpGRPCListener.lastReason = ""
	cpGRPCListener.backoff = 0
	cpGRPCListener.consecutive = 0
	cpGRPCListener.total = 0
	cpGRPCListener.binds = 0
	cpGRPCListener.serveExits = 0
	cpGRPCListener.logAt = time.Time{}
	cpGRPCListener.suppressed = 0
	cpGRPCListener.alerted = false
	cpGRPCEverFailed.Store(false)
}

// cpGRPCHealthFieldValue is the /health `control_plane` field, or "" on a node
// that never configured a control plane so the field is omitted entirely.
//
// Omitted rather than "disabled" because this field is `omitempty`: an
// always-present field would make every standalone appliance look like it has a
// cluster, which is the same emission rule the cluster_ca and socks5 gauges
// follow for the same reason.
func cpGRPCHealthFieldValue() string {
	if !cpGRPCListenerState().Configured {
		return ""
	}
	return cpGRPCListenerStatus()
}

// appendCPGRPCReadinessCheck adds the report-only `control_plane` row to
// /ready. Absent entirely when no Control Plane listener was configured, and
// while the loop is stopping — the same shape as
// appendAdminUIReadinessCheck/appendSOCKS5ReadinessCheck.
//
// REPORT-ONLY is load-bearing and is CHAOS-57's reasoning transposed: a CP node
// whose gRPC listener cannot bind is proxying its own traffic perfectly, so
// gating the default readiness verdict would eject a healthy gateway from the
// load balancer over a cluster-control fault — converting a fleet-management
// outage into the traffic outage this row exists to make visible. Strict
// callers opt in via ?strict=1.
//
// The detail strings are FIXED. /ready is unauthenticated on the proxy port, so
// a reason class (which would name, for instance, descriptor exhaustion) or an
// attempt count would fingerprint the node's state to anyone who can reach it —
// the CHAOS-54 rule for this surface. The resolution lives on the role-gated
// diagnostics row, the alert and the logs.
func appendCPGRPCReadinessCheck(checks map[string]*readinessCheck) {
	snap := cpGRPCListenerState()
	if !snap.Configured || snap.Stopped {
		return
	}
	switch {
	case snap.Serving:
		checks["control_plane"] = &readinessCheck{Status: "ok"}
	case snap.Unavailable:
		checks["control_plane"] = &readinessCheck{
			Status: "fail",
			Detail: "control plane listener is not accepting connections — see server logs",
		}
	default:
		checks["control_plane"] = &readinessCheck{
			Status: "fail",
			Detail: "control plane listener is rebinding — see server logs",
		}
	}
}
