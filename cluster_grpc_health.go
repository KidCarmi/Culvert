package main

// cluster_grpc_health.go — CHAOS-71: the observability plane for the Control
// Plane's gRPC listener lifecycle.
//
// Companion to cluster_grpc_bind.go, which owns bind → serve → rebind. This
// file owns only the RECORD and the surfaces that read it, and it deliberately
// speaks the vocabulary CHAOS-54/57/66 already established for the other three
// listeners rather than inventing a fourth dialect:
//
//   - a `cluster_grpc` operator-contract row (role-gated /api/diagnostics)
//   - a REPORT-ONLY `cluster_grpc` row on /ready
//   - a fixed-enum `cluster_grpc` posture on /health
//   - culvert_cluster_grpc_{up,unavailable,bind_failures_total,binds_total,
//     bind_backoff_seconds}, emitted ONLY on a node configured as a Control
//     Plane
//   - one fire-once-per-episode alert
//
// Three rules carried over verbatim, each because a previous sweep paid for it:
//
//  1. Every surface is emitted only when CP mode is CONFIGURED. A
//     `culvert_cluster_grpc_up 0` on the ordinary single-node appliance that
//     never asked for a cluster is indistinguishable from a Control Plane whose
//     listener is dead, and the documented paging rule is `== 0` (the
//     socks5 / cluster_ca / dns emission rule).
//
//  2. Freshness is EVALUATED against an INJECTED clock, never latched. An
//     episode duration derived from two stored stamps FREEZES between
//     attempts, which is CHAOS-66's round-3 finding: at the 30 s ceiling with
//     ±20% jitter a failure landing at 29 s left every read surface reporting
//     "retrying" for up to 36 s past the documented threshold. `cpGRPCElapsed`
//     ages an episode against the clock and takes the LATER of the stored and
//     clock-derived ends, so a clock rollback cannot shrink an outage already
//     observed.
//
//  3. Recovery is declared on OBSERVED evidence only — a listener that
//     actually bound. Elapsed time never clears a failure, because a loop that
//     stopped failing because it stopped attempting looks identical to a bound
//     one (the storage_health.go / ca_health.go house rule).

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
	// cpGRPCBindBackoffInitial / cpGRPCBindBackoffMax bound the RATE of rebind
	// attempts, never their COUNT.
	//
	// Identical to adminUIListenBackoff* and socks5BindBackoff* because it is
	// the same fault class on the same kind of socket: a port frees when a
	// predecessor finishes draining, a certificate reappears when a rotation
	// completes, an interface comes up when the host finishes booting — all
	// measured in seconds, none at machine speed.
	cpGRPCBindBackoffInitial = 1 * time.Second
	cpGRPCBindBackoffMax     = 30 * time.Second

	// cpGRPCBindJitter spreads the backoff by ±20%. A cluster restarts
	// together — a compose `up`, a rolling reboot, a host bringing every
	// container back at once — and an unjittered cadence would aim a
	// synchronised herd of rebind attempts at one instant (the WK-13 shape).
	cpGRPCBindJitter = 0.20

	// cpGRPCBindLogInterval rate-limits the bind-failure log line: the FIRST
	// failure of an episode is always logged, then one line per interval, then
	// one recovery line naming the suppressed count. The log carries the
	// SIGNAL, the counter the MAGNITUDE — a mitigation for a crash loop must
	// not itself be a log flood.
	cpGRPCBindLogInterval = 60 * time.Second

	// cpGRPCUnavailableAfter is how long the listener must be continuously
	// unbindable before it is reported UNAVAILABLE (fail row, alert, gauge at
	// zero) rather than merely retrying.
	//
	// Unavailability is a DURATION, not a count. A restart in which a
	// predecessor still holds the port clears in a few seconds, and paging on
	// that would page on every ordinary redeploy of a CP container.
	cpGRPCUnavailableAfter = 30 * time.Second

	// cpGRPCBindClampFloor is the shortest sleep clampCPGRPCBindSleep will
	// produce, so the one attempt it schedules to observe the unavailability
	// threshold cannot degenerate into a near-zero spin when the threshold is
	// all but reached.
	cpGRPCBindClampFloor = 100 * time.Millisecond
)

// cpGRPCHealthNow is the clock seam. Tests FREEZE it (see rule 2 in the file
// header and CHAOS-66's round-3 determinism finding): giving the read path a
// clock while gates drive the write path with synthetic stamps mixes two
// clocks, and `cpGRPCElapsed`'s max() lets the real one dominate — so a gate
// recording failures 19 s apart synthetically and asserting "not yet
// unavailable" would invisibly also be asserting that under 30 s of WALL time
// passed between two of its own statements. True in milliseconds locally,
// false on a loaded shared runner under -count=2.
var cpGRPCHealthNow = time.Now

// cpGRPCListenerHealth is the process-wide record of the Control Plane gRPC
// listener's state. Mutex-guarded rather than atomic-per-field because every
// reader (the diagnostics row, the readiness row, the health field, the metrics
// block) needs a consistent view across all of it.
type cpGRPCListenerHealth struct {
	mu sync.Mutex

	// configured is set by noteCPGRPCConfigured BEFORE the first bind attempt,
	// not after a successful one. That ordering is load-bearing and is
	// CHAOS-66's finding restated: it gates every surface in this file, so
	// recording it after the bind would report a Control Plane whose listener
	// has NEVER come up as "not a Control Plane" — indistinguishable from the
	// ordinary standalone appliance, on exactly the node where an operator is
	// trying to find out why the fleet stopped syncing.
	configured bool
	addr       string

	// serving is true between an observed successful bind and the serve call
	// returning. everBound distinguishes the two operator situations that look
	// identical in a gauge but need different responses: a Control Plane that
	// has NEVER come up (a misconfiguration, or a port something else owns)
	// versus one that was up and fell over (an environmental fault).
	serving   bool
	everBound bool

	// roleAsserted records whether this node has actually taken the
	// control-plane role. It is DISTINCT from `serving` on purpose: the whole
	// point of CHAOS-71's rule 3 is that role and leadership are asserted only
	// on an observed bind, so an operator must be able to see "configured as a
	// CP, not yet acting as one" as its own state rather than inferring it.
	roleAsserted bool

	// stopped records a deliberate teardown rather than a fault, so a node in
	// the middle of a clean shutdown never reports a cluster fault on its way
	// out. Set by the supervisor's Stop, which is reached on EVERY shutdown —
	// including the happy path, where the supervisor loop has already exited
	// because activation succeeded and there was nothing left to retry.
	stopped bool

	// serveEnded records grpc-go's Serve returning on a listener that WAS
	// bound, without a shutdown having been requested — i.e. the socket died
	// under a serving Control Plane.
	//
	// It exists because this sweep introduced `culvert_cluster_grpc_up`, and
	// `serving` is otherwise only ever cleared by a bind failure or a teardown.
	// `StartControlPlaneGRPC`'s serve goroutine has always just logged the
	// error, which was harmless while nothing claimed the listener was up —
	// and becomes a LIE the moment a gauge does. A surface reading 1 on a dead
	// listener is the exact defect class this sweep exists to remove, so
	// shipping the gauge without this would have reintroduced it inside its own
	// fix (CHAOS-66's PX-18-in-miniature note).
	//
	// It is TERMINAL: the supervisor does not rebind an established listener
	// that died, so every surface must say so rather than promise a recovery
	// that will not happen. Making it rebind is a larger design (a full
	// serve/rebind loop with its own shutdown interaction) and is recorded as
	// an open residual rather than folded in here.
	serveEnded bool

	// firstFailure is the start of the current run of consecutive failures;
	// zero while serving. Unavailability is measured from here, so a listener
	// that fails, binds, and fails again never accumulates toward the threshold
	// across healthy periods.
	firstFailure time.Time
	lastFailure  time.Time
	lastReason   string
	backoff      time.Duration

	// consecutive resets on an observed successful BIND; total never does.
	consecutive int64
	total       int64
	binds       int64

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per UNAVAILABILITY episode: one page when
	// the cluster control plane goes persistently unbindable, not one per
	// retry. Cleared by an observed bind, so a second incident pages again.
	alerted bool
}

var cpGRPCListener cpGRPCListenerHealth

// cpGRPCEverFailed short-circuits the success observer until the first bind
// failure, so a healthy bind costs one atomic load rather than a mutex acquire
// (the storageEverFailed / adminUIEverFailed pattern). A bind happens once per
// process in the healthy case, so this is not a hot path — but the fault plane
// must not tax the healthy plane.
var cpGRPCEverFailed atomic.Bool

// cpGRPCListenerSnapshot is a consistent read of the record.
type cpGRPCListenerSnapshot struct {
	Configured   bool
	Addr         string
	Serving      bool
	EverBound    bool
	RoleAsserted bool
	Stopped      bool
	ServeEnded   bool

	Failing     bool
	Unavailable bool
	FailingFor  time.Duration
	LastReason  string
	Backoff     time.Duration
	Consecutive int64
	Total       int64
	Binds       int64
}

// fireCPGRPCUnavailableAlert delivers the `cluster_grpc_unavailable` alert.
//
// A NEW event name, which this file owes an explanation for: CHAOS-59's rule is
// that a new name is silently unsubscribed on every already-configured webhook,
// so reusing an existing one is the default. There is no existing event that
// means "this node's cluster control-plane listener is not serving" — the
// CP-link alerting that exists fires on the DATA PLANE side, about reaching a
// CP, and cannot be produced by the CP about itself. `admin_ui_unavailable`
// (CHAOS-57) is the direct precedent for adding one: the same plane-level
// finding, the same shape, and a different remedy from anything already named.
// The contract row, the readiness row and the metrics are the signal for
// operators whose webhook subscriptions predate this build.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink. HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
var fireCPGRPCUnavailableAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("cluster_grpc_unavailable") {
		return
	}
	go fireAlert("cluster_grpc_unavailable", AlertPayload{
		Detail: detail,
		Source: "cluster",
	})
}

// noteCPGRPCConfigured records that this node was configured as a Control
// Plane. Called BEFORE the first bind attempt — see the `configured` field.
func noteCPGRPCConfigured(addr string) {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.configured = true
	cpGRPCListener.addr = addr
	cpGRPCListener.mu.Unlock()
}

// classifyCPGRPCBindError maps a listen/TLS failure onto a BOUNDED reason
// class.
//
// Bounded because the class reaches the alert Detail, and `Dispatch` dedups on
// `event + ":" + Detail`: a raw bind error embeds the listener address, so an
// unbounded reason gives the dedup key one value per failure (the WK-12/RS-5
// defect) and puts the listener address on a viewer-role surface. The raw error
// reaches the rate-limited log and nowhere else.
//
// Matched with errors.As on syscall.Errno, never by string — net wraps as
// *net.OpError{*os.SyscallError{syscall.Errno}} and the text is
// platform-specific.
//
// `network_error` requires an actual TIMEOUT, not merely an error the net
// package wrapped: every bind failure arrives as *net.OpError, which satisfies
// net.Error UNCONDITIONALLY (Timeout() is false for a bind EINVAL), so an
// unqualified errors.As(&ne) branch swallows every unrecognised errno into a
// class that names the wrong subsystem — and makes `listen_failed` unreachable.
// Both classifyAdminUIListenError and classifySOCKS5BindError had exactly that
// shape and were narrowed; this one starts narrow.
func classifyCPGRPCBindError(err error) string {
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
	// The mTLS pair is loaded by cpServerOption BEFORE the socket is bound
	// (CHAOS-57 rule 5 — ServeTLS returns a certificate error WITHOUT closing
	// the listener it was handed, so a bind-first loop leaks one socket per
	// attempt against a persistently bad cert). A certbot / cert-manager /
	// Docker-secret rotation that momentarily truncates or re-permissions the
	// pair therefore lands here, and it is the trigger that made this fault
	// reachable without anybody touching a port.
	if isCPGRPCTLSMaterialError(err) {
		return "tls_certificate"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}

// isCPGRPCTLSMaterialError reports whether err came from loading the Control
// Plane's mTLS material rather than from the socket.
//
// It keys on the ERROR PATH, not on the message: cpServerOption wraps every
// credential failure as "gRPC TLS: %w" and StartControlPlaneGRPC wraps every
// socket failure as "gRPC listen: %w", so the two are structurally
// distinguishable by the sentinels below without matching any string the
// crypto/tls package chose. A tls.LoadX509KeyPair failure is reported as an
// opaque error by the stdlib (no wrapped sentinel), which is exactly why the
// distinction is carried by OUR wrapper rather than inferred from theirs.
func isCPGRPCTLSMaterialError(err error) bool {
	return errors.Is(err, errCPGRPCTLSMaterial)
}

// errCPGRPCTLSMaterial marks a credential-loading failure so
// classifyCPGRPCBindError can tell it apart from a socket failure without
// string matching. Wrapped in by cpServerOption.
var errCPGRPCTLSMaterial = errors.New("control-plane gRPC TLS material")

// noteCPGRPCBindFailure records one failed bind attempt and returns whether the
// caller should emit a log line, plus how long the current episode has been
// running so the caller can keep its retry cadence inside the unavailability
// threshold (see clampCPGRPCBindSleep).
func noteCPGRPCBindFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool, failingFor time.Duration) {
	cpGRPCEverFailed.Store(true)

	cpGRPCListener.mu.Lock()
	if cpGRPCListener.firstFailure.IsZero() {
		cpGRPCListener.firstFailure = now
	}
	cpGRPCListener.lastFailure = now
	cpGRPCListener.lastReason = reason
	cpGRPCListener.backoff = backoff
	cpGRPCListener.serving = false
	cpGRPCListener.consecutive++
	cpGRPCListener.total++

	failingFor = cpGRPCElapsed(cpGRPCListener.firstFailure, cpGRPCListener.lastFailure, now)
	unavailable := failingFor >= cpGRPCUnavailableAfter

	if cpGRPCListener.logAt.IsZero() || now.Sub(cpGRPCListener.logAt) >= cpGRPCBindLogInterval {
		shouldLog = true
		cpGRPCListener.logAt = now
		cpGRPCListener.suppressed = 0
	} else {
		cpGRPCListener.suppressed++
	}

	// Fire-once per episode, and the latch is taken INSIDE the lock so two
	// attempts crossing the threshold concurrently cannot both page.
	fireAlertNow := unavailable && !cpGRPCListener.alerted
	if fireAlertNow {
		cpGRPCListener.alerted = true
	}
	everBound := cpGRPCListener.everBound
	cpGRPCListener.mu.Unlock()

	if fireAlertNow {
		posture := "has never bound since this node started"
		if everBound {
			posture = "stopped serving"
		}
		// The Detail is the DEDUP KEY, so it carries the bounded reason class
		// and a bounded posture — never the address and never the raw error.
		// It also states the blast radius in both directions, because the
		// single most expensive operator mistake here would be to treat a
		// cluster-plane fault as a traffic outage and start restarting nodes.
		fireCPGRPCUnavailableAlert(fmt.Sprintf(
			"control-plane gRPC listener %s (reason: %s); this node is not distributing config to the fleet and new nodes cannot enrol. "+
				"It rebinds automatically — no restart is required. This node's proxy data plane and admin UI are unaffected, "+
				"and Data Planes keep enforcing their last-known config.",
			posture, reason))
	}
	return shouldLog, failingFor
}

// noteCPGRPCBound records an OBSERVED successful bind: the only thing that
// clears a failure episode. Returns the suppressed log count and whether this
// bind ended an episode (so the caller can emit the one recovery line).
func noteCPGRPCBound() (suppressed int64, recovered bool) {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()

	recovered = !cpGRPCListener.firstFailure.IsZero()
	suppressed = cpGRPCListener.suppressed

	cpGRPCListener.serving = true
	cpGRPCListener.everBound = true
	cpGRPCListener.stopped = false
	// An observed bind IS the recovery, so a previous serve-ended state must
	// not stay latched — CHAOS-66's rule, where leaving `down` latched reported
	// a fail row and a page after the outage was over.
	cpGRPCListener.serveEnded = false
	cpGRPCListener.binds++
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.lastFailure = time.Time{}
	cpGRPCListener.backoff = 0
	cpGRPCListener.consecutive = 0
	cpGRPCListener.logAt = time.Time{}
	cpGRPCListener.suppressed = 0
	cpGRPCListener.alerted = false
	return suppressed, recovered
}

// noteCPGRPCRoleAsserted records that the control-plane role (and, where
// applicable, leadership) has been taken. Separate from noteCPGRPCBound
// because a bind is the EVIDENCE and the role transition is the CONSEQUENCE,
// and CHAOS-71's rule 3 is precisely that the second may not happen without
// the first.
func noteCPGRPCRoleAsserted() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.roleAsserted = true
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCSupervisorPanic records a contained panic in the supervisor loop.
//
// A contained panic IS terminal for the loop — nothing rebinds — so the state
// recorded must not promise an automatic recovery. That is CHAOS-66's round-2
// lesson: a blanket "retrying" message sends an operator away from the one
// restart that IS actually needed.
//
// But THE CLAIM MUST MATCH THE EVIDENCE, which is why this is a function rather
// than an unconditional `noteCPGRPCBindFailure` at the call site. The loop can
// panic either BEFORE a bind (the listener really is down) or AFTER one, in the
// leadership-resolution step that follows a successful activation (the listener
// is bound and serving the fleet). Reporting the second case as a dead listener
// would send an operator to hunt a bind fault that does not exist, and would
// drop `culvert_cluster_grpc_up` to 0 on a node whose gRPC is answering — a
// surface saying the opposite of the truth, which is the whole class of defect
// this sweep exists to remove.
//
// So: a panic with no listener is recorded as a failure; a panic with one is
// recorded only in the log, loudly, naming what is and is not affected. Both
// are terminal for the SUPERVISOR, and neither is silent.
func noteCPGRPCSupervisorPanic() {
	if cpGRPCListenerState().Serving {
		logErrorf("ControlPlane: gRPC listener supervisor panicked AFTER the listener bound — the listener is " +
			"still serving the fleet, but this node will not rebind if it ever stops, and leadership resolution " +
			"may be incomplete. Verify the HA role via /healthz or the HA panel and restart this node at a " +
			"convenient time. The proxy data plane and the admin UI are unaffected.")
		return
	}
	noteCPGRPCBindFailure("supervisor_panicked", 0, cpGRPCHealthNow())
	logErrorf("ControlPlane: gRPC listener supervisor panicked — the cluster control plane is " +
		"unavailable until this node is restarted. This node's proxy data plane and admin UI are unaffected, " +
		"and Data Planes keep enforcing their last-known config.")
}

// noteCPGRPCStopped records the supervisor exiting for shutdown.
func noteCPGRPCStopped() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.stopped = true
	cpGRPCListener.serving = false
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCServeEnded records grpc-go's Serve returning on a listener that was
// bound, with no shutdown requested. Called from StartControlPlaneGRPC's serve
// goroutine.
//
// It is a NO-OP during a deliberate teardown, and that check is why the
// supervisor's Stop records `stopped`: GracefulStop makes Serve return NIL, so
// without it every clean shutdown of a healthy Control Plane would report its
// listener as having died.
//
// It is also a no-op when no bind was ever observed — there is nothing to
// contradict, and a bind failure already owns that state.
func noteCPGRPCServeEnded() {
	cpGRPCListener.mu.Lock()
	if cpGRPCListener.stopped || !cpGRPCListener.everBound {
		cpGRPCListener.mu.Unlock()
		return
	}
	cpGRPCListener.serving = false
	already := cpGRPCListener.serveEnded
	cpGRPCListener.serveEnded = true
	addr := cpGRPCListener.addr
	cpGRPCListener.mu.Unlock()

	if already {
		return
	}
	logErrorf("ControlPlane: gRPC listener on %s stopped serving and will NOT rebind — the cluster control "+
		"plane is unavailable until this node is restarted. This node's proxy data plane and admin UI are "+
		"unaffected, and Data Planes keep enforcing their last-known config.", addr)
	fireCPGRPCUnavailableAlert("control-plane gRPC listener stopped serving (reason: serve_ended); " +
		"this node is not distributing config to the fleet and new nodes cannot enrol, and it will NOT rebind " +
		"on its own — restart this node. Its proxy data plane and admin UI are unaffected, and Data Planes keep " +
		"enforcing their last-known config.")
}

// cpGRPCElapsed ages an episode against the clock instead of deriving it from
// two stored stamps.
//
// It takes the LATER of the stored end and the clock-derived end, so a clock
// ROLLBACK cannot shrink an outage that has already been observed. That is
// deliberately the OPPOSITE of CHAOS-61's rollback verdict: there the fail-safe
// answer is distrusting a remote value, here it is the longer duration.
func cpGRPCElapsed(first, last, now time.Time) time.Duration {
	if first.IsZero() {
		return 0
	}
	stored := last.Sub(first)
	if stored < 0 {
		stored = 0
	}
	live := now.Sub(first)
	if live > stored {
		return live
	}
	return stored
}

// clampCPGRPCBindSleep shortens the ONE sleep that would otherwise straddle the
// unavailability threshold.
//
// CHAOS-55's recoveryPollCeiling rule, and a CORRECTNESS bound rather than
// tuning: the alert is produced by an ATTEMPT (noteCPGRPCBindFailure holds the
// fire-once latch and nothing else wakes the loop), so a sleep that crosses the
// threshold defers the page by up to a whole ceiling. Capping the CEILING
// instead was rejected: that pays permanently for a property that matters on
// one sleep. At most one extra attempt per episode.
func clampCPGRPCBindSleep(wait, failingFor time.Duration) time.Duration {
	remaining := cpGRPCUnavailableAfter - failingFor
	if remaining <= 0 || wait <= remaining {
		return wait
	}
	if remaining < cpGRPCBindClampFloor {
		return cpGRPCBindClampFloor
	}
	return remaining
}

// nextCPGRPCBindBackoff advances the rebind backoff: 1 s on the first failure,
// doubling, capped at 30 s.
func nextCPGRPCBindBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return cpGRPCBindBackoffInitial
	}
	cur *= 2
	if cur > cpGRPCBindBackoffMax {
		return cpGRPCBindBackoffMax
	}
	return cur
}

// cpGRPCListenerState returns a consistent snapshot of the record.
func cpGRPCListenerState() cpGRPCListenerSnapshot {
	// Clock read BEFORE the lock: nothing here needs it consistent with the
	// fields, and a syscall under a mutex every health surface takes is a habit
	// worth not forming.
	now := cpGRPCHealthNow()

	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	snap := cpGRPCListenerSnapshot{
		Configured:   cpGRPCListener.configured,
		Addr:         cpGRPCListener.addr,
		Serving:      cpGRPCListener.serving,
		EverBound:    cpGRPCListener.everBound,
		RoleAsserted: cpGRPCListener.roleAsserted,
		Stopped:      cpGRPCListener.stopped,
		ServeEnded:   cpGRPCListener.serveEnded,
		LastReason:   cpGRPCListener.lastReason,
		Backoff:      cpGRPCListener.backoff,
		Consecutive:  cpGRPCListener.consecutive,
		Total:        cpGRPCListener.total,
		Binds:        cpGRPCListener.binds,
	}
	if !cpGRPCListener.firstFailure.IsZero() {
		snap.Failing = true
		snap.FailingFor = cpGRPCElapsed(cpGRPCListener.firstFailure, cpGRPCListener.lastFailure, now)
		snap.Unavailable = snap.FailingFor >= cpGRPCUnavailableAfter
	}
	// A listener whose Serve returned is unavailable IMMEDIATELY and with no
	// episode to age: there is no retry in flight, so the duration threshold —
	// which exists to avoid paging on an ordinary redeploy's few seconds of
	// rebinding — has nothing to measure and nothing to wait for.
	if snap.ServeEnded {
		snap.Unavailable = true
	}
	return snap
}

// cpGRPCListenerStatus is the fixed-enum /health posture.
//
// A FIXED five-value enum, deliberately, because handleHealth serves this
// UNAUTHENTICATED on the proxy port. The posture is public — a readiness row
// already makes the existence of the degradation public, that is what a
// readiness row is — while the RESOLUTION (attempt count, reason class, which
// would name descriptor exhaustion specifically) stays on the role-gated
// /api/diagnostics row, the alert and the logs.
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

// cpGRPCBindRemedy selects the operator action per BOUNDED reason class.
//
// Per class rather than one string for every class, which is CHAOS-66's
// round-3 finding: a bounded classifier is worth nothing if one remedy is
// printed for every class, and a node out of descriptors or with an interface
// not yet up was being sent to hunt the owner of a port nobody holds.
//
// Two clauses are invariant in every branch, because they are the two things an
// operator most needs to know before reaching for a restart: the listener
// rebinds by itself, and this node's proxy and admin UI are unaffected.
func cpGRPCBindRemedy(reason, addr string) string {
	const tail = " The listener rebinds automatically once the fault clears — no restart is required, and a restart would cost this node's egress for nothing. " +
		"This node's proxy data plane and admin UI are unaffected, and Data Planes keep enforcing their last-known config while the Control Plane is unreachable."
	switch reason {
	case "port_in_use":
		return fmt.Sprintf("Another process already holds %s. Identify it (ss -ltnp / lsof -i) — commonly a predecessor container still draining, a host-network service, or a second Culvert instance — and free the address or move the Control Plane to another one.%s", addr, tail)
	case "permission_denied":
		return fmt.Sprintf("This process may not bind %s. A privileged port needs CAP_NET_BIND_SERVICE (or a non-privileged address); check whether the deployment stopped running as root or dropped the capability.%s", addr, tail)
	case "address_unavailable":
		return fmt.Sprintf("The address in %s does not exist on this host yet — usually a bind racing an interface that is still coming up, or an address that moved. Confirm the interface is up and the address is local.%s", addr, tail)
	case "descriptors_exhausted":
		return fmt.Sprintf("This process is out of file descriptors, so no socket can be opened at all. Raise the limit (LimitNOFILE / ulimit -n) and look for a descriptor leak — the cluster listener is a symptom here, not the cause.%s", tail)
	case "tls_certificate":
		return fmt.Sprintf("The Control Plane mTLS material could not be loaded. This is most often a certificate rotation caught mid-write: the pair is re-read on EVERY attempt, so a rotation that completes needs no intervention. If it persists, check that -cp-grpc-cert/-cp-grpc-key are readable by this process and are a valid matching pair.%s", tail)
	default:
		return fmt.Sprintf("The cause is not one this build classifies; the full error is in the process log on the `ControlPlane: gRPC listener` line.%s", tail)
	}
}

// checkCPGRPCListener is the `cluster_grpc` operator-contract row.
//
// Severity policy:
//   - not configured → ok. This node is not a Control Plane.
//   - stopped → ok. The supervisor exited because the node is shutting down.
//   - unavailable → FAIL. A Control Plane that has been unable to serve for
//     longer than the threshold is a real, operator-actionable fault: no node
//     in the fleet is receiving config, no new node can enrol, and no DP
//     certificate can be renewed.
//   - failing but under the threshold → warn. Still retrying, and a
//     predecessor draining the port clears on its own within seconds; failing
//     here would report a self-healing handover as broken.
//   - serving → ok, carrying the cumulative failure count so a HISTORY of
//     transient failures stays visible after recovery.
func checkCPGRPCListener() OperatorContractCheck {
	snap := cpGRPCListenerState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "cluster_grpc",
			Status:  diagOK,
			Message: "Not a Control Plane (no cluster gRPC listener configured)",
		}
	}
	if snap.Stopped {
		return OperatorContractCheck{
			Code:    "cluster_grpc",
			Status:  diagOK,
			Message: "Control Plane gRPC listener stopped (node shutting down)",
		}
	}
	if snap.ServeEnded {
		return OperatorContractCheck{
			Code:   "cluster_grpc",
			Status: diagFail,
			Message: fmt.Sprintf("Control Plane gRPC on %s stopped serving after having bound; no node in the fleet is receiving config and new nodes cannot enrol",
				snap.Addr),
			OperatorAction: "Restart this node. Unlike a bind failure this does NOT recover on its own — the listener socket is gone and the supervisor does not re-establish a listener that was already serving. The full error is on the `ControlPlane gRPC error` line in the process log. This node's proxy data plane and admin UI are unaffected, and Data Planes keep enforcing their last-known config, so the restart can be scheduled.",
		}
	}
	if snap.Unavailable {
		posture := "has never bound since this node started"
		if snap.EverBound {
			posture = "stopped serving"
		}
		// The role clause is the half an operator cannot get anywhere else, and
		// it is the whole reason `roleAsserted` is a separate field: a node that
		// never bound has deliberately NOT taken the control-plane role, which
		// is what keeps a standby's auto-failover unambiguous.
		role := "this node has deliberately NOT asserted the control-plane role, so a standby is free to lead"
		if snap.RoleAsserted {
			role = "this node holds the control-plane role"
		}
		return OperatorContractCheck{
			Code:   "cluster_grpc",
			Status: diagFail,
			Message: fmt.Sprintf("Control Plane gRPC on %s %s and has been unbindable for %s (%d consecutive attempts, reason: %s); %s",
				snap.Addr, posture, snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason, role),
			OperatorAction: cpGRPCBindRemedy(snap.LastReason, snap.Addr),
		}
	}
	if snap.Failing {
		return OperatorContractCheck{
			Code:   "cluster_grpc",
			Status: diagWarn,
			Message: fmt.Sprintf("Control Plane gRPC on %s is not currently serving (%d consecutive attempts, reason: %s); retrying with backoff",
				snap.Addr, snap.Consecutive, snap.LastReason),
			OperatorAction: "No action yet — the listener retries automatically and this usually clears within seconds of a restart. If it persists it is raised to a failure. Data Planes keep enforcing their last-known config meanwhile.",
		}
	}
	if snap.Total > 0 {
		return OperatorContractCheck{
			Code:    "cluster_grpc",
			Status:  diagOK,
			Message: fmt.Sprintf("Control Plane gRPC serving on %s (%d transient bind failures since startup)", snap.Addr, snap.Total),
		}
	}
	return OperatorContractCheck{
		Code:    "cluster_grpc",
		Status:  diagOK,
		Message: fmt.Sprintf("Control Plane gRPC serving on %s", snap.Addr),
	}
}

// appendCPGRPCReadinessCheck adds the report-only `cluster_grpc` row to /ready
// on the PROXY port.
//
// REPORT-ONLY, like `ca`, `cluster_ca`, `socks5` and `admin_ui`, and the
// reasoning is the same one CHAOS-57 recorded for the admin UI: a node whose
// cluster gRPC cannot bind is proxying traffic perfectly. Gating the default
// readiness verdict on it would pull a fully-functional gateway out of the load
// balancer because of a fault in a plane that has nothing to do with serving
// traffic — converting a control-plane outage into the traffic outage this
// change exists to prevent. An operator who does want such nodes ejected opts
// in via /ready?strict=1.
//
// Absent entirely when this node is not a Control Plane, so an ordinary
// standalone appliance never grows a permanently-green row.
//
// The detail is a FIXED string per branch. /ready is served UNAUTHENTICATED on
// the proxy port, so the attempt count and reason class — which would tell an
// unauthenticated caller that this node's control plane is down and why — stay
// on the role-gated row, the alert and the logs.
func appendCPGRPCReadinessCheck(checks map[string]*readinessCheck) {
	snap := cpGRPCListenerState()
	if !snap.Configured || snap.Stopped {
		return
	}
	switch {
	case snap.Serving:
		checks["cluster_grpc"] = &readinessCheck{Status: "ok"}
	case snap.Unavailable:
		checks["cluster_grpc"] = &readinessCheck{
			Status: "fail",
			Detail: "control-plane gRPC listener is not serving — see server logs",
		}
	default:
		checks["cluster_grpc"] = &readinessCheck{
			Status: "fail",
			Detail: "control-plane gRPC listener is rebinding — see server logs",
		}
	}
}

// resetCPGRPCHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `cpGRPCListener = cpGRPCListenerHealth{}`
// under the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex".
func resetCPGRPCHealthForTest() {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	cpGRPCListener.configured = false
	cpGRPCListener.addr = ""
	cpGRPCListener.serving = false
	cpGRPCListener.everBound = false
	cpGRPCListener.roleAsserted = false
	cpGRPCListener.stopped = false
	cpGRPCListener.serveEnded = false
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.lastFailure = time.Time{}
	cpGRPCListener.lastReason = ""
	cpGRPCListener.backoff = 0
	cpGRPCListener.consecutive = 0
	cpGRPCListener.total = 0
	cpGRPCListener.binds = 0
	cpGRPCListener.logAt = time.Time{}
	cpGRPCListener.suppressed = 0
	cpGRPCListener.alerted = false
	cpGRPCEverFailed.Store(false)
}
