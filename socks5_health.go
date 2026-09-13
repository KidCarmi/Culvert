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
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
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

	// down is set when the listener STOPPED — an unrecoverable accept error or
	// a contained panic. Before CHAOS-66 this was terminal for the process;
	// the supervisor now rebinds, so `downRecoveryPending` below says whether
	// this particular `down` is recoverable, and every operator-facing surface
	// branches on it. Still the loudest state the subsystem can produce.
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

	// downRecoveryPending distinguishes the two ways the listener can be down,
	// which point at OPPOSITE operator actions: the accept loop stopping is
	// recoverable (the supervisor rebinds), the supervisor's own contained
	// panic is not (nothing rebinds). Before CHAOS-66 every `down` was
	// terminal, so one message served both.
	downRecoveryPending bool

	// ── The BIND plane (CHAOS-66) ────────────────────────────────────────────
	//
	// Everything above describes a listener that is BOUND and whose accept loop
	// is misbehaving. These fields describe the step before it: a listener that
	// cannot get a socket at all. They are a separate episode with their own
	// rate gate and their own fire-once latch, for the same reason `alerted`
	// and `downAlerted` are separate — "cannot bind the port" and "bound, but
	// accepts are failing" point the operator at completely different things.

	// everBound distinguishes the two situations that read identically in a
	// gauge but need opposite responses: a listener that has NEVER come up (a
	// misconfiguration — wrong port, a port permanently owned by something
	// else, a deployment that has never had SOCKS5) versus one that was serving
	// and lost its socket (an environmental fault).
	everBound bool

	// stopped records the supervisor loop exiting for SHUTDOWN rather than for
	// a fault, so a node in the middle of a clean teardown never reports a
	// SOCKS5 failure on its way out.
	stopped bool

	// bindFirstFailure is the start of the current run of consecutive bind
	// failures; zero once a bind succeeds. Unavailability is measured from
	// here, so a listener that fails, binds, and fails again never accumulates
	// toward the threshold across healthy periods.
	bindFirstFailure time.Time
	bindLastFailure  time.Time
	bindLastReason   string
	bindBackoff      time.Duration

	// bindConsecutive resets on an observed successful BIND; bindTotal never
	// does. Recovery is established by EVIDENCE (a listener that actually
	// bound), never by elapsed time — the house rule from storage_health.go and
	// ca_health.go. A retry loop that stops failing because it stopped trying
	// has not recovered. binds counts successful binds, so a flapping listener
	// is distinguishable from a stable one.
	bindConsecutive int64
	bindTotal       int64
	binds           int64

	// bindLogAt gates the bind-failure log line; bindSuppressed counts what the
	// gate swallowed since the last emitted line so the recovery line can state
	// it.
	bindLogAt      time.Time
	bindSuppressed int64

	// bindAlerted is a fire-once latch per UNAVAILABILITY episode: one page
	// when the listener goes persistently unbindable, not one per retry.
	// Cleared by an observed bind, so a second incident pages again.
	bindAlerted bool
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
	Configured bool
	Port       int
	Down       bool
	DownReason string
	// DownRecoveryPending: a rebind is pending (accept-plane fault) rather than
	// terminal (the supervisor itself stopped).
	DownRecoveryPending bool
	Degraded            bool
	Failing             bool
	LastReason          string
	Backoff             time.Duration
	Consecutive         int64
	Total               int64
	FailingFor          time.Duration

	// The bind plane (CHAOS-66). BindFailing is "cannot get a socket right now,
	// retrying"; BindUnavailable is the same condition sustained past
	// socks5BindUnavailableAfter, which is the state that pages.
	EverBound       bool
	Stopped         bool
	BindFailing     bool
	BindUnavailable bool
	BindLastReason  string
	BindBackoff     time.Duration
	BindConsecutive int64
	BindTotal       int64
	Binds           int64
	BindFailingFor  time.Duration
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

// noteSOCKS5ListenerDown records that the ACCEPT LOOP stopped: the socket is
// gone, but the supervisor owns the lifecycle and a rebind is pending. reason is
// a bounded classification for the same cardinality and disclosure reasons as
// noteSOCKS5AcceptFailure's.
func noteSOCKS5ListenerDown(reason string) {
	noteSOCKS5DownWithRecovery(reason, true)
}

// noteSOCKS5SupervisorDown records that the SUPERVISOR ITSELF stopped — today
// only its contained panic — so nothing will rebind and the listener is gone
// until the node restarts.
//
// The split from noteSOCKS5ListenerDown exists because CHAOS-66 made the
// accept-plane `down` RECOVERABLE while this one stayed terminal, and every
// operator-facing surface has to tell those two apart. Codex review on PR #1376
// caught the first half of this: the contract row's operator action had been
// updated to "no restart required" while the alert Detail and both accept-loop
// log lines still said "unavailable until restart" — and a blanket reword of
// all three would have gone wrong in the other direction, promising an
// automatic rebind on the one path that does not have one. Two named functions
// rather than a bool parameter, so the call site says which it means.
func noteSOCKS5SupervisorDown(reason string) {
	noteSOCKS5DownWithRecovery(reason, false)
}

// noteSOCKS5DownWithRecovery is the shared core.
//
// It always alerts (subject to the fire-once latch) and never rate-limits: it
// happens at most once per episode and it means a configured service is gone.
// The Detail stays BOUNDED — port plus reason class plus a fixed sentence —
// because it is the `event + ":" + Detail` dedup key.
func noteSOCKS5DownWithRecovery(reason string, recoveryPending bool) {
	socks5Listener.mu.Lock()
	socks5Listener.down = true
	socks5Listener.downReason = reason
	socks5Listener.downRecoveryPending = recoveryPending
	alertNow := !socks5Listener.downAlerted
	socks5Listener.downAlerted = true
	port := socks5Listener.port
	socks5Listener.mu.Unlock()

	if !alertNow {
		return
	}
	outlook := "the supervisor is rebinding automatically — no restart required"
	if !recoveryPending {
		outlook = "SOCKS5 is unavailable until this node restarts"
	}
	fireSOCKS5ListenerAlert(fmt.Sprintf(
		"SOCKS5 listener on port %d has STOPPED accepting connections (%s); the port is closed and %s. The HTTP/HTTPS proxy and the admin UI are unaffected",
		port, reason, outlook))
}

// classifySOCKS5BindError maps a bind failure to a BOUNDED reason class
// (CHAOS-66).
//
// Bounded for the same two reasons socks5AcceptReason is: the class reaches the
// alert Detail, which alerts.Store.Dispatch dedups on `event + ":" + Detail`
// (a raw error embeds the listener address and would mint one dedup key per
// failure — the WK-12/RS-5 defect), and it reaches the viewer-role
// /api/diagnostics row, which must not carry internal addresses. The full error
// goes to the rate-limited log line and nowhere else.
//
// Matched with errors.As on syscall.Errno, never by string: net wraps bind
// errors as *net.OpError{Err: *os.SyscallError{Err: syscall.Errno}} and the
// text is platform-specific. The class set deliberately mirrors
// classifyAdminUIListenError's — it is the same fault on the same kind of
// socket, and one vocabulary across both listeners is what lets an operator
// read either runbook.
func classifySOCKS5BindError(err error) string {
	if err == nil {
		return "none"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EADDRINUSE:
			return "port_in_use"
		case syscall.EACCES, syscall.EPERM:
			return "permission_denied"
		case syscall.EADDRNOTAVAIL:
			return "address_unavailable"
		case syscall.EMFILE, syscall.ENFILE:
			return "descriptors_exhausted"
		}
	}
	// `network_error` requires an actual TIMEOUT, not merely an error the net
	// package wrapped. Every bind failure arrives as *net.OpError, which
	// satisfies net.Error unconditionally (verified: Timeout() is false for a
	// bind EINVAL), so an unqualified errors.As(&ne) branch swallows every
	// unrecognised errno into a class that names the wrong subsystem and sends
	// the operator down a network-troubleshooting path for a socket or
	// permission fault — while making `listen_failed` unreachable for any real
	// listen error. classifyAdminUIListenError had exactly this shape and was
	// narrowed in the same change; its test only ever passed a bare
	// errors.New, which is why the branch looked correct.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}

// noteSOCKS5BindFailure records one failed bind attempt and returns whether the
// caller should emit a log line for it.
func noteSOCKS5BindFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool) {
	socks5Listener.mu.Lock()

	socks5Listener.bindTotal++
	socks5Listener.bindConsecutive++
	socks5Listener.bindLastFailure = now
	socks5Listener.bindLastReason = reason
	socks5Listener.bindBackoff = backoff
	socks5Listener.stopped = false
	if socks5Listener.bindFirstFailure.IsZero() {
		socks5Listener.bindFirstFailure = now
	}

	if socks5Listener.bindLogAt.IsZero() || now.Sub(socks5Listener.bindLogAt) >= socks5BindLogInterval {
		socks5Listener.bindLogAt = now
		shouldLog = true
	} else {
		socks5Listener.bindSuppressed++
	}

	// Unavailability is a DURATION, not a count: an ordinary redeploy in which
	// a predecessor still holds the port clears in seconds, and paging on that
	// would page on every restart.
	unavailable := now.Sub(socks5Listener.bindFirstFailure) >= socks5BindUnavailableAfter
	alertNow := unavailable && !socks5Listener.bindAlerted
	if alertNow {
		socks5Listener.bindAlerted = true
	}
	failures := socks5Listener.bindConsecutive
	port := socks5Listener.port
	everBound := socks5Listener.everBound
	socks5Listener.mu.Unlock()

	if alertNow {
		// The Detail states explicitly that the rest of the appliance is
		// serving. That is the single most important fact for whoever this
		// pages: before CHAOS-66 this condition meant the whole gateway was
		// gone, so an operator who remembers the old behaviour must not go
		// looking for a dead data plane.
		history := "has never bound"
		if everBound {
			history = "lost its socket and cannot rebind"
		}
		fireSOCKS5ListenerAlert(fmt.Sprintf(
			"SOCKS5 listener on port %d %s after %s of retrying (%d consecutive failures, reason: %s); SOCKS5 clients cannot connect. The HTTP/HTTPS proxy and the admin UI are unaffected",
			port, history, socks5BindUnavailableAfter, failures, reason))
	}
	return shouldLog
}

// noteSOCKS5Bound records an OBSERVED successful bind and returns the number of
// bind-failure log lines the rate gate suppressed during the episode that just
// ended, plus whether an episode was in fact ended (so the caller only logs a
// recovery line when there was something to recover from).
//
// This is the only thing that clears the bind-failure state — and, because a
// fresh socket is exactly the recovery for an unrecoverable one, the only thing
// that clears `down` as well. Elapsed time never does: a supervisor that has
// stopped failing because it has stopped attempting looks identical to a bound
// one, which is the mistake ca_health.go and storage_health.go both call out by
// name.
func noteSOCKS5Bound() (suppressed int64, recovered bool) {
	socks5Listener.mu.Lock()
	defer socks5Listener.mu.Unlock()

	socks5Listener.binds++
	socks5Listener.everBound = true
	socks5Listener.stopped = false

	// A bind proves the socket exists again, so the accept loop's terminal
	// `down` no longer describes reality. Clearing it here is what makes the
	// CHAOS-54 down state recoverable without a restart now that something
	// rebinds.
	socks5Listener.down = false
	socks5Listener.downReason = ""
	socks5Listener.downRecoveryPending = false
	socks5Listener.downAlerted = false

	if socks5Listener.bindConsecutive == 0 && socks5Listener.bindFirstFailure.IsZero() {
		return 0, false
	}
	suppressed = socks5Listener.bindSuppressed
	socks5Listener.bindConsecutive = 0
	socks5Listener.bindSuppressed = 0
	socks5Listener.bindFirstFailure = time.Time{}
	socks5Listener.bindBackoff = 0
	socks5Listener.bindAlerted = false
	socks5Listener.bindLogAt = time.Time{}
	return suppressed, true
}

// noteSOCKS5ListenerStopped records the supervisor exiting because Stop was
// called, so a clean teardown is never reported as a fault. It deliberately
// does NOT clear the failure history: an operator reading the last diagnostics
// of a node that is shutting down should still see that SOCKS5 had been unable
// to bind.
func noteSOCKS5ListenerStopped() {
	socks5Listener.mu.Lock()
	socks5Listener.stopped = true
	socks5Listener.mu.Unlock()
}

// socks5ListenerState returns a consistent copy of the accept loop's state.
func socks5ListenerState() socks5ListenerSnapshot {
	socks5Listener.mu.Lock()
	defer socks5Listener.mu.Unlock()
	snap := socks5ListenerSnapshot{
		Configured: socks5Listener.configured,
		Port:       socks5Listener.port,
		Down:       socks5Listener.down,
		DownReason: socks5Listener.downReason,

		DownRecoveryPending: socks5Listener.downRecoveryPending,
		LastReason:          socks5Listener.lastReason,
		Backoff:             socks5Listener.backoff,
		Consecutive:         socks5Listener.consecutive,
		Total:               socks5Listener.total,

		EverBound:       socks5Listener.everBound,
		Stopped:         socks5Listener.stopped,
		BindLastReason:  socks5Listener.bindLastReason,
		BindBackoff:     socks5Listener.bindBackoff,
		BindConsecutive: socks5Listener.bindConsecutive,
		BindTotal:       socks5Listener.bindTotal,
		Binds:           socks5Listener.binds,
	}
	if !socks5Listener.firstFailure.IsZero() {
		snap.Failing = true
		snap.FailingFor = socks5Listener.lastFailure.Sub(socks5Listener.firstFailure)
		snap.Degraded = snap.FailingFor >= socks5AcceptDegradedAfter
	}
	if !socks5Listener.bindFirstFailure.IsZero() {
		snap.BindFailing = true
		snap.BindFailingFor = socks5Listener.bindLastFailure.Sub(socks5Listener.bindFirstFailure)
		snap.BindUnavailable = snap.BindFailingFor >= socks5BindUnavailableAfter
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
	socks5Listener.downRecoveryPending = false
	socks5Listener.everBound = false
	socks5Listener.stopped = false
	socks5Listener.bindFirstFailure = time.Time{}
	socks5Listener.bindLastFailure = time.Time{}
	socks5Listener.bindLastReason = ""
	socks5Listener.bindBackoff = 0
	socks5Listener.bindConsecutive = 0
	socks5Listener.bindTotal = 0
	socks5Listener.binds = 0
	socks5Listener.bindLogAt = time.Time{}
	socks5Listener.bindSuppressed = 0
	socks5Listener.bindAlerted = false
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
	case snap.Down, snap.BindUnavailable:
		return "down"
	case snap.Degraded, snap.BindFailing:
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
	// The BIND branches come first: a listener with no socket at all is a more
	// fundamental state than one whose accepts are failing, and while the
	// supervisor is unbound the accept-plane fields describe the PREVIOUS
	// socket. CHAOS-66.
	if snap.BindUnavailable {
		msg := fmt.Sprintf("SOCKS5 listener has never bound port %d (%s) after %s of retrying (%d attempts)",
			snap.Port, snap.BindLastReason, snap.BindFailingFor.Round(time.Second), snap.BindConsecutive)
		action := fmt.Sprintf("Check what else is bound to port %d on this host, and that the process may bind it; the listener rebinds automatically once the port is free — no restart required. The HTTP/HTTPS proxy and the admin UI are unaffected.", snap.Port)
		if snap.EverBound {
			msg = fmt.Sprintf("SOCKS5 listener lost port %d and has been unable to rebind for %s (%s, %d attempts)",
				snap.Port, snap.BindFailingFor.Round(time.Second), snap.BindLastReason, snap.BindConsecutive)
		}
		return OperatorContractCheck{
			Code:           "socks5_listener",
			Status:         diagFail,
			Message:        msg,
			OperatorAction: action,
		}
	}
	if snap.Down {
		// CHAOS-66 changed this action, and then had to SPLIT it. It used to
		// read "Restart this node to rebind the SOCKS5 listener", correct while
		// nothing re-opened the socket; the supervisor now does, so that advice
		// would cost a production outage to achieve what already happens. But
		// the supervisor's own contained panic is still terminal, so promising
		// an automatic rebind there would be the same error inverted.
		msg := fmt.Sprintf("SOCKS5 listener stopped accepting connections (%s) after %d accept errors; the port is closed and a rebind is pending",
			snap.DownReason, snap.Total)
		action := "Check the server logs for the underlying socket fault; the listener rebinds automatically — no restart required."
		if !snap.DownRecoveryPending {
			msg = fmt.Sprintf("SOCKS5 listener supervisor stopped (%s); nothing will rebind the port",
				snap.DownReason)
			action = "Restart this node to rebind the SOCKS5 listener, then check the server logs for the fault that stopped the supervisor. The HTTP/HTTPS proxy and the admin UI are unaffected."
		}
		return OperatorContractCheck{
			Code:           "socks5_listener",
			Status:         diagFail,
			Message:        msg,
			OperatorAction: action,
		}
	}
	if snap.BindFailing {
		return OperatorContractCheck{
			Code:   "socks5_listener",
			Status: diagWarn,
			Message: fmt.Sprintf("SOCKS5 listener has been unable to bind port %d for %s (%d attempts, reason: %s); retrying with backoff",
				snap.Port, snap.BindFailingFor.Round(time.Second), snap.BindConsecutive, snap.BindLastReason),
			OperatorAction: fmt.Sprintf("Usually a predecessor process still holding port %d; it clears on its own. The HTTP/HTTPS proxy and the admin UI are unaffected.", snap.Port),
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
	if snap.Total > 0 || snap.BindTotal > 0 {
		return OperatorContractCheck{
			Code:   "socks5_listener",
			Status: diagOK,
			Message: fmt.Sprintf("SOCKS5 listener accepting connections (%d transient accept errors, %d transient bind failures since startup)",
				snap.Total, snap.BindTotal),
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
	case snap.BindUnavailable:
		checks["socks5"] = &readinessCheck{
			Status: "fail",
			Detail: "SOCKS5 listener could not bind its port — see server logs",
		}
	case snap.Down:
		checks["socks5"] = &readinessCheck{
			Status: "fail",
			Detail: "SOCKS5 listener has stopped accepting connections — see server logs",
		}
	case snap.BindFailing, snap.Degraded:
		checks["socks5"] = &readinessCheck{
			Status: "fail",
			Detail: "SOCKS5 listener is not accepting connections — see server logs",
		}
	default:
		checks["socks5"] = &readinessCheck{Status: "ok"}
	}
}
