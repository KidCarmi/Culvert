package main

// cluster_grpc_health.go — CHAOS-71: the Control Plane gRPC listener's health
// plane. The finding and the four rules live in cluster_grpc_bind.go's header;
// this file is the observability half.
//
// Every surface rides the PROXY port, and that is the same reasoning §33 gave
// for the admin UI: a probe that dies with the plane it measures reports
// nothing at all. The Control Plane's own gRPC endpoint cannot tell anyone
// that the Control Plane's gRPC endpoint is unreachable, so the posture is
// published where it survives the fault.
//
// The clock discipline is the SOCKS5 dialect (`socks5ElapsedSince` plus a
// read-path clock seam), deliberately NOT the admin UI's. §36 round 3 found
// that deriving an episode duration from two stored stamps FREEZES it between
// attempts: at a 30 s ceiling a failure landing at 29 s left the row saying
// "retrying", the gauge at 1 and the page unfired for up to 36 s after the
// documented threshold had passed. `admin_ui_health.go` still computes
// `lastFailure.Sub(firstFailure)` and carries that defect; this plane does not
// inherit it.
//
// Surfaces:
//   - `/api/diagnostics` — the `control_plane_grpc` operator-contract row.
//   - `/ready` (proxy port) — a report-only `control_plane_grpc` row.
//     REPORT-ONLY is load-bearing and is pinned as a control test: a node
//     whose CP listener cannot bind is proxying perfectly, so gating the
//     default verdict would eject a healthy gateway from the load balancer
//     over its cluster-configuration plane — converting a management outage
//     into the traffic outage this change exists to prevent. Strict callers
//     opt in via `?strict=1`.
//   - `/health` (proxy port) — the `control_plane_grpc` posture field.
//   - `/metrics` — `culvert_cp_grpc_{up,unavailable,bind_failures_total,binds_total,bind_backoff_seconds}`,
//     emitted ONLY when a CP gRPC address is configured (the
//     socks5/cluster_ca/dns rule: `up 0` on a standalone proxy that never
//     asked to be a Control Plane is indistinguishable from a broken one, and
//     the documented paging rule is `== 0`).
//   - alerts — `controlplane_grpc_unavailable`.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// cpGRPCHealth is the process-wide record for the Control Plane gRPC
// listener's bind lifecycle.
type cpGRPCHealth struct {
	mu sync.Mutex

	// configured is set BEFORE the first bind attempt, so a Control Plane
	// whose listener has never come up is distinguishable from a node that was
	// never asked to be one. See the comment on noteCPGRPCConfigured.
	configured bool
	addr       string

	// serving is true between an observed bind and an observed serve exit.
	serving    bool
	everServed bool
	// stopped records a clean teardown, so shutdown is never read as a fault.
	stopped bool

	// terminal marks a state nothing will retry out of: the supervisor
	// panicked, or the configuration can never bind (empty address).
	terminal       bool
	terminalReason string

	firstFailure time.Time
	lastFailure  time.Time
	lastReason   string
	backoff      time.Duration

	consecutive int64
	total       int64
	binds       int64

	logAt      time.Time
	suppressed int64

	// alerted is the fire-once-per-episode latch for the unavailability page.
	alerted bool
}

var cpGRPC cpGRPCHealth

// cpGRPCEverFailed is an atomic short-circuit so the read surfaces
// (/health, /ready, /metrics, the contract row) cost nothing on the
// overwhelming majority of appliances, which never have a CP listener fault.
var cpGRPCEverFailed atomic.Bool

// cpGRPCHealthNow is the READ-path clock seam. A health snapshot must be a
// pure function of recorded state and an INJECTED clock — §36 round 3's
// determinism lesson: giving the read path the real clock while gates drive
// the write path with synthetic stamps MIXES two clocks, and a gate recording
// failures 19 s apart synthetically then asserting "not yet degraded" is
// invisibly also asserting that under 30 s of WALL time passed between two of
// its own statements (true locally, false on a loaded runner under -count=2).
var cpGRPCHealthNow = time.Now

// cpGRPCSnapshot is the immutable read view every surface consumes.
type cpGRPCSnapshot struct {
	Configured  bool
	Addr        string
	Serving     bool
	EverServed  bool
	Stopped     bool
	Terminal    bool
	TermReason  string
	Unavailable bool
	FailingFor  time.Duration
	LastReason  string
	Backoff     time.Duration
	Consecutive int64
	Total       int64
	Binds       int64
}

// cpGRPCState returns the current snapshot, ageing any live failure episode
// against the clock rather than against the last stored stamp.
func cpGRPCState() cpGRPCSnapshot {
	cpGRPC.mu.Lock()
	defer cpGRPC.mu.Unlock()

	snap := cpGRPCSnapshot{
		Configured:  cpGRPC.configured,
		Addr:        cpGRPC.addr,
		Serving:     cpGRPC.serving,
		EverServed:  cpGRPC.everServed,
		Stopped:     cpGRPC.stopped,
		Terminal:    cpGRPC.terminal,
		TermReason:  cpGRPC.terminalReason,
		LastReason:  cpGRPC.lastReason,
		Backoff:     cpGRPC.backoff,
		Consecutive: cpGRPC.consecutive,
		Total:       cpGRPC.total,
		Binds:       cpGRPC.binds,
	}
	if !cpGRPC.firstFailure.IsZero() {
		snap.FailingFor = cpGRPCElapsedSince(cpGRPC.firstFailure, cpGRPC.lastFailure, cpGRPCHealthNow())
		snap.Unavailable = snap.FailingFor >= cpGRPCBindUnavailableAfter
	}
	// A terminal state is unavailable regardless of elapsed time: nothing is
	// retrying, so waiting for the duration threshold would never report it.
	if snap.Terminal {
		snap.Unavailable = true
	}
	return snap
}

// cpGRPCElapsedSince returns how long a failure episode that began at `first`
// has been running, given the last attempt at `last` and the clock.
//
// It takes the LATER of the clock-derived and stored ends so a clock rollback
// cannot SHRINK an outage already observed. That is deliberately the opposite
// of CHAOS-61's rollback verdict, for the reason §36 records: there the
// fail-safe answer is distrusting a remote value, here it is the longer
// duration.
func cpGRPCElapsedSince(first, last, now time.Time) time.Duration {
	if first.IsZero() {
		return 0
	}
	byClock := now.Sub(first)
	byStamp := last.Sub(first)
	if byStamp > byClock {
		return byStamp
	}
	if byClock < 0 {
		return 0
	}
	return byClock
}

// cpGRPCFailingFor reports the live episode duration, for the supervisor's
// sleep clamp.
func cpGRPCFailingFor(now time.Time) time.Duration {
	cpGRPC.mu.Lock()
	defer cpGRPC.mu.Unlock()
	return cpGRPCElapsedSince(cpGRPC.firstFailure, cpGRPC.lastFailure, now)
}

// noteCPGRPCConfigured records that this node was ASKED to be a Control Plane,
// before the first bind attempt.
//
// The ordering is load-bearing, for exactly the reason §36 moved
// `noteSOCKS5Configured` ahead of its first bind. `clusterRole.role` is set to
// "control-plane" only on an OBSERVED successful bind — correctly, that is
// evidence-based — so without this separate record a Control Plane whose
// listener has NEVER come up reports role "standalone", indistinguishable from
// a node that was never configured as one, on precisely the node where an
// operator is trying to find out why the fleet has stopped syncing.
func noteCPGRPCConfigured(addr string) {
	cpGRPC.mu.Lock()
	cpGRPC.configured = true
	cpGRPC.addr = addr
	cpGRPC.mu.Unlock()
}

// noteCPGRPCBindFailure records one failed bind attempt and reports whether the
// caller should log, plus how long the episode has been running (for the sleep
// clamp).
func noteCPGRPCBindFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool, failingFor time.Duration) {
	cpGRPCEverFailed.Store(true)

	cpGRPC.mu.Lock()

	cpGRPC.serving = false
	cpGRPC.stopped = false
	cpGRPC.total++
	cpGRPC.consecutive++
	cpGRPC.lastFailure = now
	cpGRPC.lastReason = reason
	cpGRPC.backoff = backoff
	if cpGRPC.firstFailure.IsZero() {
		cpGRPC.firstFailure = now
	}

	if cpGRPC.logAt.IsZero() || now.Sub(cpGRPC.logAt) >= cpGRPCBindLogInterval {
		cpGRPC.logAt = now
		shouldLog = true
	} else {
		cpGRPC.suppressed++
	}

	failingFor = cpGRPCElapsedSince(cpGRPC.firstFailure, cpGRPC.lastFailure, now)
	unavailable := failingFor >= cpGRPCBindUnavailableAfter
	alertNow := unavailable && !cpGRPC.alerted
	if alertNow {
		cpGRPC.alerted = true
	}
	failures := cpGRPC.consecutive
	addr := cpGRPC.addr
	everServed := cpGRPC.everServed
	cpGRPC.mu.Unlock()

	if alertNow {
		// The Detail states explicitly that the rest of the appliance is
		// serving. That is the single most important fact for whoever this
		// pages: before CHAOS-71 this condition meant the whole gateway was
		// gone, so an operator who remembers the old behaviour must not go
		// looking for a dead data plane. It is also BOUNDED — Dispatch dedups
		// on `event + ":" + Detail`, and the raw error embeds the listen
		// address (the WK-12/RS-5 defect).
		history := "has never bound"
		if everServed {
			history = "lost its socket and cannot rebind"
		}
		fireCPGRPCListenerAlert(fmt.Sprintf(
			"Control Plane gRPC listener %s after %s of retrying (%d consecutive failures, reason: %s); "+
				"enrolled Data Planes cannot fetch config and continue on their last-good policy, and node "+
				"enrollment is unavailable. This node's HTTP/HTTPS proxy and admin UI are unaffected",
			history, cpGRPCBindUnavailableAfter, failures, reason))
		_ = addr
	}
	return shouldLog, failingFor
}

// noteCPGRPCBound records an OBSERVED successful bind and returns the number of
// bind-failure log lines the rate gate suppressed during the episode that just
// ended, plus whether an episode was in fact ended (so the caller logs a
// recovery line only when there was something to recover from).
//
// This is the ONLY thing that clears the failure state. Elapsed time never
// does: a supervisor that has stopped failing because it has stopped
// attempting looks identical to a bound one — the mistake ca_health.go and
// storage_health.go both call out by name.
func noteCPGRPCBound() (suppressed int64, recovered bool) {
	cpGRPC.mu.Lock()
	defer cpGRPC.mu.Unlock()

	cpGRPC.binds++
	cpGRPC.serving = true
	cpGRPC.everServed = true
	cpGRPC.stopped = false
	// A bind proves the socket exists, so a terminal verdict no longer
	// describes reality.
	cpGRPC.terminal = false
	cpGRPC.terminalReason = ""

	if cpGRPC.consecutive == 0 && cpGRPC.firstFailure.IsZero() {
		return 0, false
	}
	suppressed = cpGRPC.suppressed
	cpGRPC.consecutive = 0
	cpGRPC.suppressed = 0
	cpGRPC.firstFailure = time.Time{}
	cpGRPC.lastFailure = time.Time{}
	cpGRPC.backoff = 0
	cpGRPC.alerted = false
	cpGRPC.logAt = time.Time{}
	return suppressed, true
}

// noteCPGRPCServeEnded records that a bound listener's Serve returned with an
// error — the socket is gone and, per the cluster_grpc_bind.go header, nothing
// rebinds it (register row CL-21). Recording it is what stops every surface
// reporting a healthy Control Plane with no listener.
func noteCPGRPCServeEnded(reason string) {
	noteCPGRPCTerminal("serve ended: " + reason)
}

// noteCPGRPCSupervisorDown records the rebind supervisor dying, which is
// terminal: nothing else retries the bind, so the operator action really is a
// restart. Kept DISTINCT from the retrying state for §36's round-2 reason —
// one wording for both would either send an operator to restart a gateway to
// achieve what is already in progress, or promise an automatic rebind that is
// not coming.
func noteCPGRPCSupervisorDown(reason string) {
	noteCPGRPCTerminal(reason)
}

// noteCPGRPCBindTerminal records a configuration that can never bind.
func noteCPGRPCBindTerminal(reason string) {
	noteCPGRPCTerminal("not retryable: " + reason)
}

func noteCPGRPCTerminal(reason string) {
	cpGRPCEverFailed.Store(true)

	cpGRPC.mu.Lock()
	cpGRPC.serving = false
	cpGRPC.terminal = true
	cpGRPC.terminalReason = reason
	alertNow := !cpGRPC.alerted
	if alertNow {
		cpGRPC.alerted = true
	}
	everServed := cpGRPC.everServed
	cpGRPC.mu.Unlock()

	if alertNow {
		history := "never bound"
		if everServed {
			history = "has stopped serving"
		}
		fireCPGRPCListenerAlert(fmt.Sprintf(
			"Control Plane gRPC listener %s and will NOT recover on its own (%s); enrolled Data Planes "+
				"cannot fetch config and continue on their last-good policy. Restart this node. Its "+
				"HTTP/HTTPS proxy and admin UI are unaffected", history, reason))
	}
}

// noteCPGRPCStopped records the listener going away because shutdown asked it
// to, so a clean teardown is never reported as a fault. It deliberately does
// NOT clear the failure history: an operator reading the last diagnostics of a
// node that is shutting down should still see that the CP listener had been
// unable to bind.
func noteCPGRPCStopped() {
	cpGRPC.mu.Lock()
	cpGRPC.stopped = true
	cpGRPC.serving = false
	cpGRPC.mu.Unlock()
}

// fireCPGRPCListenerAlert is a package-level var so tests can capture it. It is
// HasSubscriber-gated so the default posture (no webhooks configured) spawns no
// goroutine and builds no payload.
var fireCPGRPCListenerAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("controlplane_grpc_unavailable") {
		return
	}
	go fireAlert("controlplane_grpc_unavailable", AlertPayload{
		Detail: detail,
		Source: "control_plane",
	})
}

// cpGRPCListenerStatus is the /health posture field — a FIXED five-value enum.
// /health is unauthenticated on the proxy port, so the posture is public while
// the RESOLUTION (attempt counts, reason classes, the listen address) is not.
func cpGRPCListenerStatus() string {
	if !cpGRPCEverFailed.Load() {
		snap := cpGRPCState()
		switch {
		case !snap.Configured:
			return "disabled"
		case snap.Stopped:
			return "stopped"
		case snap.Serving:
			return "ready"
		}
		return "ready"
	}
	snap := cpGRPCState()
	switch {
	case !snap.Configured:
		return "disabled"
	case snap.Stopped:
		return "stopped"
	case snap.Serving:
		return "ready"
	case snap.Unavailable:
		return "unavailable"
	}
	return "degraded"
}

// checkControlPlaneGRPC is the operator-contract row.
//
// Severity policy, mirroring checkAdminUIListener and checkSOCKS5Listener:
// not configured ⇒ ok (nothing is wrong with a standalone proxy); shutting
// down ⇒ ok; sustained-unavailable or terminal ⇒ fail with a per-class
// remedy; still retrying under the threshold ⇒ warn with an explicit "no
// action yet"; healthy-with-history ⇒ ok carrying the cumulative count.
func checkControlPlaneGRPC() OperatorContractCheck {
	snap := cpGRPCState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "control_plane_grpc",
			Status:  diagOK,
			Message: "Control Plane gRPC listener not configured on this node",
		}
	}
	if snap.Stopped && !snap.Terminal {
		return OperatorContractCheck{
			Code:    "control_plane_grpc",
			Status:  diagOK,
			Message: "Control Plane gRPC listener stopped (shutting down)",
		}
	}
	if snap.Terminal {
		return OperatorContractCheck{
			Code:           "control_plane_grpc",
			Status:         diagFail,
			Message:        fmt.Sprintf("Control Plane gRPC listener is down and nothing is retrying it (%s)", snap.TermReason),
			OperatorAction: "Restart this node. Until then, enrolled Data Planes keep enforcing their last-good policy and node enrollment is unavailable. This node's HTTP/HTTPS proxy and admin UI are unaffected.",
		}
	}
	if snap.Unavailable {
		return OperatorContractCheck{
			Code:   "control_plane_grpc",
			Status: diagFail,
			Message: fmt.Sprintf("Control Plane gRPC listener has been unable to bind for %s (%d consecutive failures, reason: %s)",
				snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason),
			OperatorAction: cpGRPCBindRemedy(snap.LastReason, snap.Addr),
		}
	}
	if snap.Consecutive > 0 {
		return OperatorContractCheck{
			Code:   "control_plane_grpc",
			Status: diagWarn,
			Message: fmt.Sprintf("Control Plane gRPC listener is retrying its bind (%d consecutive failures, reason: %s)",
				snap.Consecutive, snap.LastReason),
			OperatorAction: fmt.Sprintf("No action yet — the listener rebinds automatically and is reported as unavailable only after %s of continuous failure. This node's HTTP/HTTPS proxy and admin UI are unaffected.", cpGRPCBindUnavailableAfter),
		}
	}
	msg := "Control Plane gRPC listener is serving"
	if snap.Total > 0 {
		msg = fmt.Sprintf("Control Plane gRPC listener is serving (%d earlier bind failure(s) recovered)", snap.Total)
	}
	return OperatorContractCheck{Code: "control_plane_grpc", Status: diagOK, Message: msg}
}

// cpGRPCBindRemedy maps a bounded bind-failure reason class to the step that
// actually resolves it.
//
// The classifier exists to tell these apart, so handing every class the same
// port-ownership advice throws the classification away at the one surface an
// operator reads — §36 round 3's finding, which is why this is per-class from
// the start rather than after someone reports it.
//
// Two clauses are invariant across every branch and must stay: that the
// listener rebinds by itself (so nobody restarts a gateway to achieve what is
// already happening) and that the proxy and admin UI are unaffected (so nobody
// goes looking for a dead data plane — this row used to mean the whole
// appliance was gone). The strings carry no raw error: the row is viewer-role
// and the bounded class is the contract.
func cpGRPCBindRemedy(reason, addr string) string {
	const rebinds = " The listener rebinds automatically once this is resolved — no restart required. Enrolled Data Planes keep enforcing their last-good policy meanwhile, and this node's HTTP/HTTPS proxy and admin UI are unaffected."

	switch reason {
	case "port_in_use":
		return fmt.Sprintf("Find and stop whatever already holds the Control Plane gRPC port on this host (`ss -ltnp`): commonly a predecessor container still draining, a second Culvert, or another service on %s.", sanitizeLog(addr)) + rebinds
	case "permission_denied":
		return "This process may not bind the configured Control Plane gRPC port. Grant it CAP_NET_BIND_SERVICE, run it as a user that may bind the port, or move the listener to a port above 1023." + rebinds
	case "address_unavailable":
		return "The bind address is not available on this host yet — usually an interface that has not come up, or an address that is not local to this machine. Check the interface and the configured -cp-grpc-addr." + rebinds
	case "descriptors_exhausted":
		return "This process is out of file descriptors, so no listener can be opened at all. Raise its limit (systemd `LimitNOFILE`, or `ulimit -n`) and look for a descriptor leak — other subsystems are degrading too, whatever their own health rows say." + rebinds
	case "tls_certificate":
		return "The Control Plane mTLS certificate/key pair could not be loaded. If a rotation is in flight this clears by itself on the next attempt and needs no action; otherwise check that -cp-grpc-cert/-cp-grpc-key exist, are readable by this process, and are a matching PEM pair." + rebinds
	default:
		// network_error and listen_failed are the UNRECOGNISED classes, so the
		// honest next step is the log line, which is the only place the raw
		// error is written.
		return "Check the server logs for the underlying bind error, and what else is bound to the configured Control Plane gRPC port on this host." + rebinds
	}
}

// appendCPGRPCReadinessCheck adds the REPORT-ONLY readiness row.
//
// It never touches the caller's `allOK`, and that is the whole mechanism: a
// node whose Control Plane listener cannot bind is proxying perfectly, so
// failing the default readiness verdict would pull a healthy gateway out of
// the load balancer over its cluster-configuration plane. Pinned as a control
// test. Strict callers opt in via `?strict=1`.
//
// The row is ABSENT on a node with no CP listener configured, and its Detail
// strings are FIXED: /ready is unauthenticated on the proxy port, so an
// attempt count or a reason class would fingerprint a node's state to anyone
// who can reach the port.
func appendCPGRPCReadinessCheck(checks map[string]*readinessCheck) {
	snap := cpGRPCState()
	if !snap.Configured || snap.Stopped {
		return
	}
	switch {
	case snap.Terminal:
		checks["control_plane_grpc"] = &readinessCheck{Status: "fail", Detail: "listener down, not retrying"}
	case snap.Unavailable:
		checks["control_plane_grpc"] = &readinessCheck{Status: "fail", Detail: "listener unavailable"}
	case snap.Consecutive > 0:
		checks["control_plane_grpc"] = &readinessCheck{Status: "fail", Detail: "listener rebinding"}
	default:
		checks["control_plane_grpc"] = &readinessCheck{Status: "ok"}
	}
}

// resetCPGRPCHealthForTest zeroes the process-global record between tests.
//
// Fields are cleared INDIVIDUALLY rather than by assigning a zero struct: the
// mutex is a FIELD of the record, so `cpGRPC = cpGRPCHealth{}` under the lock
// would replace the held mutex with an unlocked zero value and the following
// Unlock would be a fatal "unlock of unlocked mutex".
func resetCPGRPCHealthForTest() {
	cpGRPC.mu.Lock()
	cpGRPC.configured = false
	cpGRPC.addr = ""
	cpGRPC.serving = false
	cpGRPC.everServed = false
	cpGRPC.stopped = false
	cpGRPC.terminal = false
	cpGRPC.terminalReason = ""
	cpGRPC.firstFailure = time.Time{}
	cpGRPC.lastFailure = time.Time{}
	cpGRPC.lastReason = ""
	cpGRPC.backoff = 0
	cpGRPC.consecutive = 0
	cpGRPC.total = 0
	cpGRPC.binds = 0
	cpGRPC.logAt = time.Time{}
	cpGRPC.suppressed = 0
	cpGRPC.alerted = false
	cpGRPC.mu.Unlock()
	cpGRPCEverFailed.Store(false)
	cpGRPCHealthNow = time.Now
}
