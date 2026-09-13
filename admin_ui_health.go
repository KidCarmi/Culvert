package main

// admin_ui_health.go — CHAOS-57: the admin UI listener under bind and serve faults.
//
// Why this file exists.
//
// `startUI` spawned a detached goroutine whose ONLY error branch was
// `logFatalf` — which `os.Exit(1)`s the process. So every way the ADMIN UI's
// listener could fail terminated the PROXY DATA PLANE with it:
//
//	go func() {
//	    if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
//	        logFatalf("UI server error: %v", err)   // ← kills the whole appliance
//	    }
//	}()
//
// That inverts the dependency this product is built on. Culvert is an IN-LINE
// secure web gateway: its reason to exist is enforcing policy on live traffic,
// and the admin UI is the plane you manage that enforcement FROM. A management
// plane may degrade without the enforcement plane going with it — never the
// reverse. `startUI` is called from the init block BEFORE the proxy listener
// starts, and returns as soon as the goroutine is spawned, so the failure lands
// asynchronously against a process that is already announcing itself as up.
//
// Both triggers were reproduced against the real binary:
//
//  1. **The admin port is occupied.** `-ui-port` already bound — a predecessor
//     container still draining, a host-network service on 9090, an operator
//     collision. `validatePortCollisions` (main.go) only checks Culvert's own
//     three ports against EACH OTHER; it cannot see anything else on the host.
//     Observed log, verbatim, in that order:
//
//     UIHTTP: http://localhost:19090          ← claims the UI is listening
//     Proxy:  http://localhost:18080          ← the data plane announces itself
//     UI server error: listen tcp :19090: bind: address already in use   → exit 1
//
//  2. **The custom UI certificate cannot be loaded.** `ListenAndServeTLS`
//     reads `-tls-cert`/`-tls-key` at call time, so a rotation that briefly
//     truncates, replaces or re-permissions those files — certbot, cert-manager,
//     a Docker secret whose mount is not ready yet — is a boot that ends in
//     `UI TLS error: tls: failed to find any PEM data in certificate input`
//     and exit 1.
//
// Both are ROUTINE operational events, and under `restart: unless-stopped`
// (docker-compose.yml) each becomes an unattended crash loop: no proxy, no
// admin UI, no health endpoint, recoverable only with shell access — which is
// precisely the outcome §19 (CHAOS-50) closed for the category store, arrived
// at from the other direction. Note also which way the failure actually falls:
// process death is NOT "fail closed". An explicit-proxy fleet loses all egress
// (total outage); a PAC/WPAD fleet with a DIRECT fallback, or a transparent
// deployment that bypasses a dead next hop, sends traffic straight out
// UNFILTERED. Killing the process picks neither posture deliberately — it
// delegates the choice to the network topology.
//
// The codebase already knew the right shape here and applied it to exactly one
// of the failure modes in this same function: a `selfSignedTLS()` failure does
// NOT exit, it degrades to plain HTTP and records `uiTLSFallbackActive` for the
// operator. This change extends that instinct to the rest of the function, and
// borrows the mechanism wholesale from CHAOS-54 (the SOCKS5 accept loop) and
// CHAOS-55 (the fencing-lease re-acquire loop) rather than inventing a second
// dialect: a rate-bounded, jittered, interruptible retry; recovery declared
// only on OBSERVED evidence; bounded reason classes on the public surfaces; and
// separate fire-once latches for states that point at different actions.
//
// Surfaces, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the `admin_ui_listener` operator-contract row.
//   - `/ready` (proxy port) — a report-only `admin_ui` row. REPORT-ONLY is
//     load-bearing: a node whose admin UI is down still proxies perfectly, and
//     gating the default verdict would eject a healthy gateway from the load
//     balancer over its management plane. Strict callers opt in via ?strict=1.
//   - `/health` (proxy port) — the `admin_ui` posture field. This is the
//     surface that SURVIVES the fault, which is the whole point: the admin
//     port's own `/healthz` cannot report that the admin port is unreachable.
//   - `/metrics` — culvert_admin_ui_up / _listen_failures_total /
//     _unavailable / _listen_backoff_seconds / _binds_total.
//   - alerts — `admin_ui_unavailable`.

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
	// adminUIListenBackoffInitial / adminUIListenBackoffMax bound the RATE of
	// rebind attempts, never their COUNT.
	//
	// Never bounding the count is deliberate and is the CHAOS-55 argument: the
	// terminal state of "give up" is an appliance nobody can manage and that
	// will not recover without a restart — which is the very outcome this
	// change exists to remove. "Avoid infinite retries" is satisfied the way
	// CHAOS-54/55 satisfy it: the retry is never SILENT. The first failure logs
	// immediately, then at most one line per adminUIListenLogInterval, then one
	// recovery line naming the suppressed count, with the magnitude carried by
	// a counter and the state by a gauge, a contract row and an alert.
	//
	// The floor is 1 s rather than SOCKS5's 5 ms because the faults here are
	// not machine-speed: a port frees when a predecessor finishes draining and
	// a certificate reappears when a rotation completes, both measured in
	// seconds. The ceiling is 30 s so a self-healed fault is picked up within
	// half a minute without hammering the bind.
	adminUIListenBackoffInitial = 1 * time.Second
	adminUIListenBackoffMax     = 30 * time.Second

	// adminUIListenJitter spreads the backoff by ±20%. A fleet restarts
	// together — a compose `up`, a rolling node reboot, a host that brings
	// every container back at once — and an unjittered cadence would aim a
	// synchronised herd of rebind attempts at the same instant (the WK-13
	// shape). Matches haLeaseRecoveryJitter.
	adminUIListenJitter = 0.20

	// adminUIListenLogInterval rate-limits the listen-failure log line: the
	// FIRST failure of an episode is always logged (the operator must see the
	// onset), then one line per interval, then one recovery line carrying the
	// suppressed count. Same discipline as socks5AcceptLogInterval and
	// storage_health.go, for the same reason — the log carries the SIGNAL, the
	// counter carries the MAGNITUDE.
	adminUIListenLogInterval = 60 * time.Second

	// adminUIUnavailableAfter is how long the admin UI must be continuously
	// unbindable before it is reported UNAVAILABLE (fail row, alert, gauge)
	// rather than merely retrying.
	//
	// A restart in which a predecessor is still holding the port clears in a
	// few seconds and paging on that would page on every ordinary redeploy.
	// Thirty seconds of an admin plane that cannot bind is no longer a
	// handover artifact.
	adminUIUnavailableAfter = 30 * time.Second
)

// adminUIListenerHealth is the process-wide record of the admin UI listener's
// state. Mutex-guarded rather than atomic-per-field because every reader (the
// diagnostics row, the readiness row, the health field, the metrics block)
// needs a consistent view across all of it.
type adminUIListenerHealth struct {
	mu sync.Mutex

	// configured is set once startUI runs. Unlike SOCKS5 the admin UI is always
	// configured on a normal appliance (the port defaults to 9090), but the
	// flag keeps every surface honest in the one-shot command paths that never
	// start a UI at all — a zero there must not read as a fault.
	configured bool
	port       int

	// serving is true between an observed successful bind and the serve call
	// returning. everServed distinguishes the two operator situations that
	// look identical in a gauge but need different responses: an admin UI that
	// has NEVER come up (a misconfiguration — wrong port, bad certificate, a
	// deployment that has never been manageable) versus one that was up and
	// fell over (an environmental fault).
	serving    bool
	everServed bool

	// stopped records the loop exiting for shutdown rather than for a fault, so
	// a node in the middle of a clean teardown never reports an admin-UI
	// failure on its way out.
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
	// never by elapsed time — the house rule from storage_health.go and
	// ca_health.go. A retry loop that stops failing because it stopped trying
	// has not recovered.
	consecutive int64
	total       int64
	binds       int64

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per UNAVAILABILITY episode: one page when
	// the admin plane goes persistently unbindable, not one per retry. Cleared
	// by an observed bind, so a second incident pages again.
	alerted bool
}

var adminUIListener adminUIListenerHealth

// adminUIEverFailed short-circuits the success observer until the first listen
// failure, so a healthy bind costs one atomic load rather than a mutex acquire
// (the storageEverFailed pattern). A bind happens once per process in the
// healthy case, so this is not a hot path — but the fault plane must not tax
// the healthy plane.
var adminUIEverFailed atomic.Bool

// adminUIListenerSnapshot is the lock-free view handed to the reporting
// surfaces.
type adminUIListenerSnapshot struct {
	Configured  bool
	Port        int
	Serving     bool
	EverServed  bool
	Stopped     bool
	Unavailable bool
	Failing     bool
	LastReason  string
	Backoff     time.Duration
	Consecutive int64
	Total       int64
	Binds       int64
	FailingFor  time.Duration
}

// fireAdminUIListenerAlert delivers the `admin_ui_unavailable` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
var fireAdminUIListenerAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("admin_ui_unavailable") {
		return
	}
	go fireAlert("admin_ui_unavailable", AlertPayload{
		Detail: detail,
		Source: "admin_ui",
	})
}

// noteAdminUIConfigured records that an admin UI was requested. Called from
// startUI before the first bind attempt, so a listener that fails on its very
// first attempt is reported against a CONFIGURED service rather than as "no
// admin UI" — the CHAOS-54 ordering rule.
func noteAdminUIConfigured(port int) {
	adminUIListener.mu.Lock()
	adminUIListener.configured = true
	adminUIListener.port = port
	adminUIListener.stopped = false
	adminUIListener.mu.Unlock()
}

// classifyAdminUIListenError maps a bind/serve error to a BOUNDED reason class.
//
// Never a raw error string. The listen error text embeds the bind address, the
// certificate error can quote an operator-configured path, and the
// operator-contract row is a VIEWER-role surface with a standing
// no-sensitive-values guardrail. More importantly an unbounded reason gives the
// alert dedup key one distinct value per failure, which is the WK-12/RS-5
// defect. The full error goes to the (rate-limited) log line and nowhere else.
//
// Matched via errors.As on syscall.Errno rather than by string, because net
// wraps as *net.OpError{*os.SyscallError{syscall.Errno}} and the text is
// platform-specific (the CHAOS-54 rule).
func classifyAdminUIListenError(err error) string {
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
	if errors.Is(err, errAdminUITLSMaterial) {
		return "tls_certificate"
	}
	// CHAOS-66 narrowed this branch. `network_error` requires an actual
	// TIMEOUT, not merely an error the net package wrapped: a bind failure
	// arrives as *net.OpError, which satisfies net.Error unconditionally
	// (Timeout() false for, say, EINVAL), so the unqualified form reported
	// every unrecognised errno as `network_error` — pointing the operator at
	// network troubleshooting for a socket or permission fault — and made
	// `listen_failed` unreachable for any error the net package produced. The
	// original gate passed only a bare errors.New, which is the one shape that
	// does reach `listen_failed`, so the branch looked correct.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}

// errAdminUITLSMaterial tags a failure to load the operator-supplied admin UI
// certificate/key pair, so the classifier can name it without matching on the
// crypto/tls error text.
var errAdminUITLSMaterial = errors.New("admin ui tls material")

// noteAdminUIListenFailure records one failed bind/serve attempt and returns
// whether the caller should emit a log line for it.
func noteAdminUIListenFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool) {
	adminUIEverFailed.Store(true)

	adminUIListener.mu.Lock()

	adminUIListener.serving = false
	adminUIListener.total++
	adminUIListener.consecutive++
	adminUIListener.lastFailure = now
	adminUIListener.lastReason = reason
	adminUIListener.backoff = backoff
	if adminUIListener.firstFailure.IsZero() {
		adminUIListener.firstFailure = now
	}

	if adminUIListener.logAt.IsZero() || now.Sub(adminUIListener.logAt) >= adminUIListenLogInterval {
		adminUIListener.logAt = now
		shouldLog = true
	} else {
		adminUIListener.suppressed++
	}

	// Unavailability is a DURATION, not a count: the backoff ceiling is reached
	// in under a minute and paging on the attempt count would page on every
	// redeploy in which a predecessor was still draining the port.
	unavailable := now.Sub(adminUIListener.firstFailure) >= adminUIUnavailableAfter
	alertNow := unavailable && !adminUIListener.alerted
	if alertNow {
		adminUIListener.alerted = true
	}
	failures := adminUIListener.consecutive
	port := adminUIListener.port
	everServed := adminUIListener.everServed
	adminUIListener.mu.Unlock()

	if alertNow {
		posture := "has never bound since this node started"
		if everServed {
			posture = "has stopped accepting connections"
		}
		fireAdminUIListenerAlert(fmt.Sprintf(
			"Admin UI on port %d %s for over %s (%d consecutive attempts, reason: %s); the proxy data plane is UNAFFECTED and still enforcing policy, but this node cannot be managed or configured until the admin listener recovers",
			port, posture, adminUIUnavailableAfter, failures, reason))
	}
	return shouldLog
}

// noteAdminUIServing records an OBSERVED successful bind and returns the number
// of log lines the rate gate suppressed during the episode that just ended
// (zero when nothing was failing).
//
// This is the only thing that clears the unavailable state. Elapsed time never
// does: a retry loop that has stopped failing because it has stopped attempting
// looks identical to a bound listener, and reporting recovery on silence is the
// mistake ca_health.go and storage_health.go both call out by name.
func noteAdminUIServing() (suppressed int64) {
	adminUIListener.mu.Lock()
	defer adminUIListener.mu.Unlock()

	adminUIListener.serving = true
	adminUIListener.everServed = true
	adminUIListener.stopped = false
	adminUIListener.binds++

	if !adminUIEverFailed.Load() || adminUIListener.consecutive == 0 {
		return 0
	}
	suppressed = adminUIListener.suppressed
	adminUIListener.consecutive = 0
	adminUIListener.suppressed = 0
	adminUIListener.firstFailure = time.Time{}
	adminUIListener.backoff = 0
	adminUIListener.alerted = false
	adminUIListener.logAt = time.Time{}
	return suppressed
}

// noteAdminUIStopped records the serve loop exiting for SHUTDOWN. It is not a
// fault: a node being torn down must not report its admin plane as failed on
// the way out, and must not alert.
func noteAdminUIStopped() {
	adminUIListener.mu.Lock()
	adminUIListener.serving = false
	adminUIListener.stopped = true
	adminUIListener.firstFailure = time.Time{}
	adminUIListener.consecutive = 0
	adminUIListener.backoff = 0
	adminUIListener.alerted = false
	adminUIListener.mu.Unlock()
}

// adminUIListenerState returns a consistent copy of the listener's state.
func adminUIListenerState() adminUIListenerSnapshot {
	adminUIListener.mu.Lock()
	defer adminUIListener.mu.Unlock()
	snap := adminUIListenerSnapshot{
		Configured:  adminUIListener.configured,
		Port:        adminUIListener.port,
		Serving:     adminUIListener.serving,
		EverServed:  adminUIListener.everServed,
		Stopped:     adminUIListener.stopped,
		LastReason:  adminUIListener.lastReason,
		Backoff:     adminUIListener.backoff,
		Consecutive: adminUIListener.consecutive,
		Total:       adminUIListener.total,
		Binds:       adminUIListener.binds,
	}
	if !adminUIListener.firstFailure.IsZero() {
		snap.Failing = true
		snap.FailingFor = adminUIListener.lastFailure.Sub(adminUIListener.firstFailure)
		snap.Unavailable = snap.FailingFor >= adminUIUnavailableAfter
	}
	return snap
}

// resetAdminUIHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `adminUIListener = adminUIListenerHealth{}`
// under the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex" (the CHAOS-54 note).
func resetAdminUIHealthForTest() {
	// Re-armed BEFORE the health lock is taken: the stop machinery carries its
	// own lock (ui.go), and taking a second lock from under this one would
	// establish an ordering that nothing else in the file needs.
	resetAdminUIStopForTest()

	adminUIListener.mu.Lock()
	defer adminUIListener.mu.Unlock()
	adminUIListener.configured = false
	adminUIListener.port = 0
	adminUIListener.serving = false
	adminUIListener.everServed = false
	adminUIListener.stopped = false
	adminUIListener.firstFailure = time.Time{}
	adminUIListener.lastFailure = time.Time{}
	adminUIListener.lastReason = ""
	adminUIListener.backoff = 0
	adminUIListener.consecutive = 0
	adminUIListener.total = 0
	adminUIListener.binds = 0
	adminUIListener.logAt = time.Time{}
	adminUIListener.suppressed = 0
	adminUIListener.alerted = false
	adminUIEverFailed.Store(false)
}

// adminUIListenerStatus is the /health posture string for the admin UI
// listener, served on the PROXY port — the surface that survives the fault the
// field describes.
//
// A fixed four-value enum, deliberately, because handleHealth serves this
// UNAUTHENTICATED. It is the same granularity the socks5 field publishes. What
// stays off the public surface is the RESOLUTION: the attempt count and the
// reason class (which would name, for instance, descriptor exhaustion) live
// only on the role-gated /api/diagnostics row, the alert and the logs.
func adminUIListenerStatus() string {
	snap := adminUIListenerState()
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

// checkAdminUIListener is the `admin_ui_listener` operator-contract row.
//
// Severity policy:
//   - not configured → ok. No UI was requested (one-shot command paths).
//   - stopped → ok. The loop exited because the node is shutting down.
//   - unavailable (persistently unbindable) → FAIL. A management plane that has
//     been unreachable for longer than the threshold is a real, operator-
//     actionable fault: the node cannot be configured, its sessions cannot be
//     revoked, and an incident cannot be responded to on this node.
//   - failing but under the threshold → warn. Still retrying, and a predecessor
//     draining the port clears on its own within seconds; failing here would
//     report a self-healing handover as broken.
//   - serving → ok, carrying the cumulative failure count so a HISTORY of
//     transient failures stays visible after recovery.
func checkAdminUIListener() OperatorContractCheck {
	snap := adminUIListenerState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "admin_ui_listener",
			Status:  diagOK,
			Message: "Admin UI not configured",
		}
	}
	if snap.Stopped {
		return OperatorContractCheck{
			Code:    "admin_ui_listener",
			Status:  diagOK,
			Message: "Admin UI listener stopped (node shutting down)",
		}
	}
	if snap.Unavailable {
		posture := "has never bound since this node started"
		action := "Check that no other process holds the admin UI port and that the configured -tls-cert/-tls-key pair is readable and valid; the listener rebinds automatically once the fault clears — no restart is required. The proxy data plane is unaffected and is still enforcing policy."
		if snap.EverServed {
			posture = "stopped accepting connections"
		}
		return OperatorContractCheck{
			Code:   "admin_ui_listener",
			Status: diagFail,
			Message: fmt.Sprintf("Admin UI on port %d %s and has been unbindable for %s (%d consecutive attempts, reason: %s); this node cannot be managed until it recovers",
				snap.Port, posture, snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason),
			OperatorAction: action,
		}
	}
	if snap.Failing {
		return OperatorContractCheck{
			Code:   "admin_ui_listener",
			Status: diagWarn,
			Message: fmt.Sprintf("Admin UI on port %d is not currently accepting connections (%d consecutive attempts, reason: %s); retrying with backoff",
				snap.Port, snap.Consecutive, snap.LastReason),
			OperatorAction: "No action yet — the listener retries automatically and this usually clears within seconds of a restart. If it persists it is raised to a failure.",
		}
	}
	if snap.Total > 0 {
		return OperatorContractCheck{
			Code:   "admin_ui_listener",
			Status: diagOK,
			Message: fmt.Sprintf("Admin UI listener accepting connections on port %d (%d transient listen failures since startup)",
				snap.Port, snap.Total),
		}
	}
	return OperatorContractCheck{
		Code:    "admin_ui_listener",
		Status:  diagOK,
		Message: fmt.Sprintf("Admin UI listener accepting connections on port %d", snap.Port),
	}
}

// appendAdminUIReadinessCheck adds the report-only `admin_ui` row to /ready on
// the PROXY port.
//
// REPORT-ONLY, like `ca`, `cluster_ca` and `socks5`, and here the reasoning is
// the sharpest in the file: a node whose admin UI cannot bind is proxying
// traffic perfectly. Gating the default readiness verdict on it would pull a
// fully-functional gateway out of the load balancer because of a fault in the
// plane that has nothing to do with serving traffic — converting a management
// outage into the traffic outage this whole change exists to prevent. An
// operator who does want such nodes ejected opts in via /ready?strict=1.
//
// Absent entirely when no admin UI was configured, so a one-shot command path
// never grows a permanently-green row.
//
// The detail is a FIXED string per branch. /ready is served UNAUTHENTICATED on
// the proxy port, so the attempt count and reason class — which would tell an
// unauthenticated caller on the network that this node's management plane is
// down and why — stay on the role-gated row, the alert and the logs.
func appendAdminUIReadinessCheck(checks map[string]*readinessCheck) {
	snap := adminUIListenerState()
	if !snap.Configured || snap.Stopped {
		return
	}
	switch {
	case snap.Serving:
		checks["admin_ui"] = &readinessCheck{Status: "ok"}
	case snap.Unavailable:
		checks["admin_ui"] = &readinessCheck{
			Status: "fail",
			Detail: "admin UI listener is not accepting connections — see server logs",
		}
	default:
		checks["admin_ui"] = &readinessCheck{
			Status: "fail",
			Detail: "admin UI listener is rebinding — see server logs",
		}
	}
}
