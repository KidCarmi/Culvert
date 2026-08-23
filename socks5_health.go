package main

// socks5_health.go — CHAOS-54: the SOCKS5 accept loop under listener faults.
//
// Why this file exists.
//
// `socks5Server.serve` was the ONE hand-rolled accept loop in the data plane.
// Every other listener in the process is served by `net/http.Server.Serve`
// (proxy port, admin UI, PAC, MCP gateway) or by gRPC, both of which apply an
// exponential accept backoff and stop on an unrecoverable error. The SOCKS5
// loop did neither: any `Accept` error that was not `net.ErrClosed` was logged
// and retried IMMEDIATELY, forever.
//
// The reachable fault is file-descriptor exhaustion. `accept(2)` returns
// EMFILE/ENFILE when the process or the system runs out of descriptors, and Go
// surfaces that straight out of `FD.Accept` — it is not retried in the runtime
// and it does NOT block. Measured on the pre-fix loop with a listener returning
// EMFILE: **173,834 accept attempts in 200 ms** (~870k/s), one `logger.Printf`
// each. The consequences compound outward from a subsystem that is OFF by
// default (`-socks5-port 0`) into the primary data path:
//
//   1. One CPU core pinned at 100% for as long as the fault lasts.
//   2. ~40 MB/s of accept-error lines into the process log. The log is a
//      `fileutil.RotatingFile` capped at 50 MB with ONE archive, so the entire
//      retained history — including whatever caused the FD exhaustion — is
//      overwritten in a couple of seconds. The flood destroys the evidence.
//   3. `internal/logsink` is a shock absorber, not a load shedder: a full queue
//      BLOCKS the caller. `handleRequest` writes one POLICY_* line per proxied
//      request through that same sink, so the flood adds latency to every HTTP
//      request on a node whose SOCKS5 listener nobody is using.
//
// And FD exhaustion is the terminal state of several already-registered
// failures (WK-11's leaked alert sockets, PX-6's absent global connection cap),
// so this loop turns a recoverable resource incident into a self-amplifying one.
//
// The second half of the finding is that the SOCKS5 listener had NO health
// surface at all — not `/healthz`, not `/readyz`, not `/api/diagnostics`, not
// `/metrics`. A listener wedged in a hot retry loop, and a listener that had
// stopped accepting entirely, were both reported by every probe as a completely
// healthy node.
//
// What this file provides is the observability half; the loop itself is in
// socks5.go. Surfaces, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the `socks5_listener` operator-contract row.
//   - `/readyz` — a report-only `socks5` row, present only when SOCKS5 is
//     configured (so it never appears on the ordinary appliance).
//   - `/healthz` — the `socks5` posture field.
//   - `/metrics` — culvert_socks5_listener_up / _accept_errors_total /
//     _accept_degraded / _accept_backoff_seconds.
//   - alerts — `socks5_listener_down`.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// socks5AcceptBackoffInitial / socks5AcceptBackoffMax mirror
	// net/http.Server.Serve's accept backoff (5 ms doubling to a 1 s ceiling).
	// The shape is deliberately copied rather than invented: it is the schedule
	// every other listener in this process already follows, it recovers from a
	// transient EMFILE within milliseconds, and it caps a sustained one at one
	// syscall per second instead of ~870,000.
	//
	// The ceiling is bounded by the shutdown budget as well as by taste: the
	// accept loop sleeps between attempts, and `socks5-listener-stop` gets 2 s
	// in the shutdown sequence. The sleep is interruptible (see serve), so the
	// ceiling never actually delays shutdown — but keeping it below the budget
	// means shutdown stays correct even if that interruption were ever lost.
	socks5AcceptBackoffInitial = 5 * time.Millisecond
	socks5AcceptBackoffMax     = 1 * time.Second

	// socks5AcceptLogInterval rate-limits the accept-error log line. The FIRST
	// error in an episode is always logged immediately (an operator must see the
	// onset), then at most one line per interval, then one line on recovery
	// carrying the suppressed count. That is the same discipline
	// storage_health.go applies to a failing disk, and for the same reason: the
	// fault repeats at machine speed, so the log must carry the SIGNAL and the
	// counter must carry the MAGNITUDE.
	socks5AcceptLogInterval = 30 * time.Second

	// socks5AcceptDegradedAfter is how long a run of consecutive accept
	// failures must persist before the listener is reported DEGRADED (warn row,
	// alert, gauge). Backoff reaches its 1 s ceiling after ~1.3 s, which is far
	// too eager to page on: a burst of EMFILE during a connection spike is
	// exactly the transient this backoff exists to absorb. Thirty seconds of
	// uninterrupted failure is no longer a transient.
	socks5AcceptDegradedAfter = 30 * time.Second
)

// socks5ListenerHealth is the process-wide record of the SOCKS5 accept loop's
// state. Mutex-guarded rather than atomic-per-field because every reader
// (diagnostics row, readiness row, metrics block) needs a consistent view
// across all of it.
type socks5ListenerHealth struct {
	mu sync.Mutex

	// configured is false when no -socks5-port is set. Every other field is
	// meaningless then, and every surface reports "not configured" rather than
	// a zero that would be indistinguishable from a fault.
	configured bool
	port       int

	// down is set when the accept loop STOPPED — an unrecoverable listener
	// error or a contained panic. It is terminal for the process: nothing
	// re-opens the socket, so this is the state that must be loudest.
	down       bool
	downReason string

	// firstFailure is the start of the current run of consecutive failures;
	// zero when the last accept succeeded. Degradation is measured from here,
	// so a listener that fails, recovers, and fails again never accumulates
	// toward the threshold across healthy periods.
	firstFailure time.Time
	lastFailure  time.Time
	lastReason   string
	backoff      time.Duration

	// consecutive resets on an observed successful Accept; total never does.
	// Recovery is established by EVIDENCE (an accept that returned a
	// connection), never by elapsed time — the house rule from
	// storage_health.go / ca_health.go. A listener that stops failing because
	// nobody is dialling it has not recovered.
	consecutive int64
	total       int64

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line, so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per DEGRADATION episode: one page when the
	// listener starts failing persistently, not one per retry. Cleared by an
	// observed successful accept, so a second incident pages again.
	alerted bool

	// downAlerted is a SEPARATE latch for the listener-stopped page, and the
	// separation is load-bearing. Degraded ("retrying, self-heals when
	// descriptors free up") and down ("socket gone, restart required") are
	// different operator states with different actions, and the second can
	// follow the first. Sharing one latch would swallow the page for a dead
	// listener whenever it had already been degraded — silencing the more
	// urgent of the two, which is the storage_health.go "two failures must not
	// share a rate gate" rule (Codex P2) in a different costume.
	downAlerted bool
}

var socks5Listener socks5ListenerHealth

// socks5EverFailed short-circuits the success observer until the first accept
// failure, so a healthy accept costs one atomic load rather than a mutex
// acquire (the storageEverFailed pattern from storage_health.go). Accepts are
// per-TCP-connection rather than per-request, so this is not a hot path in the
// benchgate sense — but the whole point of this file is that the fault plane
// must not tax the healthy plane.
var socks5EverFailed atomic.Bool

// socks5ListenerSnapshot is the lock-free view handed to the reporting
// surfaces.
type socks5ListenerSnapshot struct {
	Configured  bool
	Port        int
	Down        bool
	DownReason  string
	Degraded    bool
	Failing     bool
	LastReason  string
	Backoff     time.Duration
	Consecutive int64
	Total       int64
	FailingFor  time.Duration
}

// fireSOCKS5ListenerAlert delivers the `socks5_listener_down` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches). HasSubscriber-gated for the reason documented on
// fireStorageWriteAlert: with no webhook configured — the default posture, and
// the state of every test binary — this must not spawn a goroutine at all.
var fireSOCKS5ListenerAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("socks5_listener_down") {
		return
	}
	go fireAlert("socks5_listener_down", AlertPayload{
		Detail: detail,
		Source: "socks5",
	})
}

// noteSOCKS5Configured records that a SOCKS5 listener was bound. Called from
// startSOCKS5 after a successful bind; until then every surface reports the
// feature as absent.
func noteSOCKS5Configured(port int) {
	socks5Listener.mu.Lock()
	socks5Listener.configured = true
	socks5Listener.port = port
	socks5Listener.mu.Unlock()
}

// noteSOCKS5AcceptFailure records one retryable accept failure and returns
// whether the caller should emit a log line for it.
//
// reason is a BOUNDED classification, never a raw error string. The accept
// error text embeds the listener address, and the operator-contract row is a
// VIEWER-role surface with a standing no-sensitive-values guardrail; more
// importantly, an unbounded reason would give the alert dedup key one distinct
// value per failure, which is the WK-12/RS-5 defect. The full error goes to the
// (rate-limited) log line and nowhere else.
func noteSOCKS5AcceptFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool) {
	socks5EverFailed.Store(true)

	socks5Listener.mu.Lock()

	socks5Listener.total++
	socks5Listener.consecutive++
	socks5Listener.lastFailure = now
	socks5Listener.lastReason = reason
	socks5Listener.backoff = backoff
	if socks5Listener.firstFailure.IsZero() {
		socks5Listener.firstFailure = now
	}

	if socks5Listener.logAt.IsZero() || now.Sub(socks5Listener.logAt) >= socks5AcceptLogInterval {
		socks5Listener.logAt = now
		shouldLog = true
	} else {
		socks5Listener.suppressed++
	}

	// Degradation is a DURATION, not a count: the backoff ceiling is reached in
	// about a second, and paging on that would page on every transient burst.
	degraded := now.Sub(socks5Listener.firstFailure) >= socks5AcceptDegradedAfter
	alertNow := degraded && !socks5Listener.alerted
	if alertNow {
		socks5Listener.alerted = true
	}
	failures := socks5Listener.consecutive
	port := socks5Listener.port
	socks5Listener.mu.Unlock()

	if alertNow {
		fireSOCKS5ListenerAlert(fmt.Sprintf(
			"SOCKS5 listener on port %d has failed to accept connections for over %s (%d consecutive failures, reason: %s); SOCKS5 clients cannot connect",
			port, socks5AcceptDegradedAfter, failures, reason))
	}
	return shouldLog
}

// noteSOCKS5AcceptSuccess records an OBSERVED successful accept and returns the
// number of log lines the rate gate suppressed during the episode that just
// ended (zero when nothing was failing).
//
// This is the only thing that clears the degraded state. Elapsed time never
// does: an accept loop that has stopped failing because no client is dialling
// looks identical to a healthy one, and reporting recovery on silence is the
// mistake ca_health.go and storage_health.go both call out by name.
func noteSOCKS5AcceptSuccess() (suppressed int64) {
	if !socks5EverFailed.Load() {
		return 0
	}
	socks5Listener.mu.Lock()
	defer socks5Listener.mu.Unlock()
	if socks5Listener.consecutive == 0 {
		return 0
	}
	suppressed = socks5Listener.suppressed
	socks5Listener.consecutive = 0
	socks5Listener.suppressed = 0
	socks5Listener.firstFailure = time.Time{}
	socks5Listener.backoff = 0
	socks5Listener.alerted = false
	socks5Listener.logAt = time.Time{}
	return suppressed
}

// noteSOCKS5ListenerDown records that the accept loop STOPPED and will not
// resume. reason is a bounded classification for the same cardinality and
// disclosure reasons as noteSOCKS5AcceptFailure's.
//
// This always alerts (subject to the fire-once latch), never rate-limits: it
// happens at most once per process and it means a configured service is gone.
func noteSOCKS5ListenerDown(reason string) {
	socks5Listener.mu.Lock()
	socks5Listener.down = true
	socks5Listener.downReason = reason
	alertNow := !socks5Listener.downAlerted
	socks5Listener.downAlerted = true
	port := socks5Listener.port
	socks5Listener.mu.Unlock()

	if alertNow {
		fireSOCKS5ListenerAlert(fmt.Sprintf(
			"SOCKS5 listener on port %d has STOPPED accepting connections (%s); the port is closed and SOCKS5 is unavailable until this node restarts",
			port, reason))
	}
}

// socks5ListenerState returns a consistent copy of the accept loop's state.
func socks5ListenerState() socks5ListenerSnapshot {
	socks5Listener.mu.Lock()
	defer socks5Listener.mu.Unlock()
	snap := socks5ListenerSnapshot{
		Configured:  socks5Listener.configured,
		Port:        socks5Listener.port,
		Down:        socks5Listener.down,
		DownReason:  socks5Listener.downReason,
		LastReason:  socks5Listener.lastReason,
		Backoff:     socks5Listener.backoff,
		Consecutive: socks5Listener.consecutive,
		Total:       socks5Listener.total,
	}
	if !socks5Listener.firstFailure.IsZero() {
		snap.Failing = true
		snap.FailingFor = socks5Listener.lastFailure.Sub(socks5Listener.firstFailure)
		snap.Degraded = snap.FailingFor >= socks5AcceptDegradedAfter
	}
	return snap
}

// resetSOCKS5HealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `socks5Listener = socks5ListenerHealth{}`
// under the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex".
func resetSOCKS5HealthForTest() {
	socks5Listener.mu.Lock()
	defer socks5Listener.mu.Unlock()
	socks5Listener.configured = false
	socks5Listener.port = 0
	socks5Listener.down = false
	socks5Listener.downReason = ""
	socks5Listener.firstFailure = time.Time{}
	socks5Listener.lastFailure = time.Time{}
	socks5Listener.lastReason = ""
	socks5Listener.backoff = 0
	socks5Listener.consecutive = 0
	socks5Listener.total = 0
	socks5Listener.logAt = time.Time{}
	socks5Listener.suppressed = 0
	socks5Listener.alerted = false
	socks5Listener.downAlerted = false
	socks5EverFailed.Store(false)
}

// socks5ListenerStatus is the /healthz posture string for the SOCKS5 listener.
//
// "disabled" when no -socks5-port is set (the ordinary appliance), so the field
// never reads as a fault on a node that never had the feature.
func socks5ListenerStatus() string {
	snap := socks5ListenerState()
	switch {
	case !snap.Configured:
		return "disabled"
	case snap.Down:
		return "down"
	case snap.Degraded:
		return "degraded"
	default:
		return "ready"
	}
}

// checkSOCKS5Listener is the `socks5_listener` operator-contract row.
//
// Severity policy:
//   - not configured → ok. The feature is off; a permanent row would be noise.
//   - down → FAIL. Unlike the CA rows, this is not a fleet-wide condition that
//     would eject every node at once: the SOCKS5 listener is per-node, opt-in,
//     and the loop stops only on an error that means the socket itself is gone.
//     A configured service that is permanently unavailable is exactly what a
//     fail row is for.
//   - degraded (sustained accept failures) → warn. The listener is still
//     retrying and recovers on its own the moment descriptors free up, so
//     failing here would report a self-healing condition as broken.
//   - healthy → ok, carrying the cumulative error count so a HISTORY of
//     transient failures stays visible after recovery.
func checkSOCKS5Listener() OperatorContractCheck {
	snap := socks5ListenerState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "socks5_listener",
			Status:  diagOK,
			Message: "SOCKS5 listener not configured",
		}
	}
	if snap.Down {
		return OperatorContractCheck{
			Code:   "socks5_listener",
			Status: diagFail,
			Message: fmt.Sprintf("SOCKS5 listener stopped accepting connections (%s) after %d accept errors; the port is closed",
				snap.DownReason, snap.Total),
			OperatorAction: "Restart this node to rebind the SOCKS5 listener, then check the server logs for the underlying socket fault.",
		}
	}
	if snap.Degraded {
		return OperatorContractCheck{
			Code:   "socks5_listener",
			Status: diagWarn,
			Message: fmt.Sprintf("SOCKS5 listener has been unable to accept connections for %s (%d consecutive errors, reason: %s); retrying with backoff",
				snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason),
			OperatorAction: "Check the process file-descriptor limit and system-wide descriptor usage; the listener recovers automatically once descriptors free up.",
		}
	}
	if snap.Total > 0 {
		return OperatorContractCheck{
			Code:   "socks5_listener",
			Status: diagOK,
			Message: fmt.Sprintf("SOCKS5 listener accepting connections (%d transient accept errors since startup)",
				snap.Total),
		}
	}
	return OperatorContractCheck{
		Code:    "socks5_listener",
		Status:  diagOK,
		Message: "SOCKS5 listener accepting connections",
	}
}

// appendSOCKS5ReadinessCheck adds the report-only `socks5` row.
//
// Absent entirely when SOCKS5 is not configured: a permanently-absent feature
// must not add a permanently-green row to every appliance's probe.
//
// REPORT-ONLY by default, like `ca` and `cluster_ca`. A node whose SOCKS5
// listener is dead still proxies HTTP, HTTPS and PAC perfectly, and gating the
// default verdict would eject it from the load balancer over an optional
// subsystem. An operator who wants such nodes ejected opts in via
// /ready?strict=1.
//
// The detail is a FIXED string per branch. /readyz is served UNAUTHENTICATED on
// the proxy port, so anything written here is readable by every client on the
// network; the consecutive-error count and the accept reason would fingerprint
// a resource-exhausted node (and, in the FD-exhaustion case, announce the exact
// window in which the gateway is least able to serve). Both stay on the
// role-gated /api/diagnostics row, the alert and the logs.
func appendSOCKS5ReadinessCheck(checks map[string]*readinessCheck) {
	snap := socks5ListenerState()
	if !snap.Configured {
		return
	}
	switch {
	case snap.Down:
		checks["socks5"] = &readinessCheck{
			Status: "fail",
			Detail: "SOCKS5 listener has stopped accepting connections — see server logs",
		}
	case snap.Degraded:
		checks["socks5"] = &readinessCheck{
			Status: "fail",
			Detail: "SOCKS5 listener is not accepting connections — see server logs",
		}
	default:
		checks["socks5"] = &readinessCheck{Status: "ok"}
	}
}
