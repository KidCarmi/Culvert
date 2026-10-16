package main

// cp_grpc_health.go — CHAOS-71: the Control Plane gRPC listener's health plane.
//
// This file is the observability half of the finding written up in
// cp_grpc_bind.go. It deliberately reuses the vocabulary the two earlier
// listener sweeps established — §33 (CHAOS-57, `admin_ui_health.go`) and §36
// (CHAOS-66, `socks5_health.go`) — because a third dialect for the third
// listener in the same process is how an operator ends up unable to answer one
// question ("is this node's listener up?") the same way twice.
//
// What did NOT exist before this file, and is the reason it does:
//
//	$ ls *_health.go
//	admin_ui_health.go   socks5_health.go   readyz_dp_health.go   ...
//
// Every other listener in the appliance has a health plane. The Control Plane
// gRPC listener — the socket the ENTIRE FLEET's config distribution, node
// enrollment and certificate renewal arrive on — had none: no metric, no
// `/health` field, no `/ready` row, no operator-contract row, no alert. The
// only two surfaces that said anything about it, `GET /api/cluster/status` and
// `/api/diagnostics`, both read `clusterRole.role` and `clusterRole.grpcAddr`,
// which are set once after a successful bind and NEVER cleared — so a listener
// that died after binding reported `role: "control-plane"` with its address,
// indistinguishable from a healthy one. That is PX-18 in miniature: probes
// green on a dead listener.
//
// Surfaces, all additive:
//
//   - `/api/diagnostics` — the `cp_grpc_listener` operator-contract row.
//   - `/ready` (proxy port) — a report-only `cp_grpc` row. REPORT-ONLY for the
//     §33 reason, which is if anything stronger here: a Control Plane node
//     whose gRPC listener cannot bind is still proxying traffic perfectly, and
//     gating the default readiness verdict would eject a healthy gateway from
//     the load balancer over the plane that distributes config to OTHER nodes.
//     Strict callers opt in via `?strict=1`.
//   - `/health` (proxy port) — the `cp_grpc` posture field, a FIXED 5-value
//     enum.
//   - `/metrics` — culvert_cp_grpc_{up,unavailable,bind_failures_total,
//     binds_total,bind_backoff_seconds}, emitted ONLY on a node that asked to
//     be a Control Plane (the CHAOS-54 emission rule: a flat `up 0` from every
//     standalone proxy and every Data Plane in the fleet is indistinguishable
//     from a broken CP, and the documented paging rule is `== 0`).
//   - alerts — `cp_grpc_listener_down`.
//
// On the new alert NAME. The house rule is that a new event name is silently
// unsubscribed on every webhook an operator has already configured, so an
// existing name is preferred (§36 reused `socks5_listener_down` rather than
// mint a second SOCKS5 event). There is no existing event for this plane:
// `admin_ui_unavailable` and `socks5_listener_down` are both specific to their
// own listener, and folding the CP into either would page for one subsystem
// under another subsystem's name with the wrong operator action attached. §33
// minted `admin_ui_unavailable` for exactly this reason. The name follows the
// `<contract-row>_down` convention (`socks5_listener_down`, `mcp_gateway_down`,
// `upstream_pool_down`): row `cp_grpc_listener` → event `cp_grpc_listener_down`.
// The admin UI's webhook editor offers it as a checkbox (GUI parity). The cost
// is recorded in docs/operator/cp-grpc-listener-recovery.md: an existing
// deployment must add the event to its webhook subscriptions, and until it
// does the contract row and the gauge are the surfaces that carry the state.

import (
	"errors"
	"fmt"
	"io"
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
	// Never bounding the count is the CHAOS-55 argument: the terminal state of
	// "give up" is a Control Plane that is gone until somebody restarts the
	// appliance — which is the outcome this change exists to remove. "Avoid
	// infinite retries" is satisfied the CHAOS-54/55/57 way, by the retry never
	// being SILENT: the first failure logs immediately, then at most one line
	// per cpGRPCBindLogInterval, then one recovery line naming the suppressed
	// count, with the magnitude in a counter and the state in a gauge, a
	// contract row and an alert.
	//
	// The values match adminUIListenBackoff* and socks5BindBackoff* exactly,
	// because it is the same fault class on the same kind of socket: a port
	// frees when a predecessor finishes draining, a certificate reappears when
	// a rotation completes, an interface comes up when the host finishes
	// booting — all measured in seconds, none machine-speed.
	cpGRPCBindBackoffInitial = 1 * time.Second
	cpGRPCBindBackoffMax     = 30 * time.Second

	// cpGRPCServeStableAfter is how long a serve must stay up before it counts
	// as SUCCESSFUL: it resets the rebind backoff to its floor AND ends the
	// failure episode (cpGRPCEndEpisodeIfStableLocked) — one definition of
	// "recovered" for both. Twice the backoff ceiling, so a socket that dies
	// within one ceiling period of every bind — the pathological flap — can
	// never earn a reset, and it outlasts cpGRPCUnavailableAfter, so a flap
	// always crosses the unavailability threshold inside one episode.
	cpGRPCServeStableAfter = 2 * cpGRPCBindBackoffMax

	// cpGRPCBindJitter spreads the backoff by ±20%. A fleet restarts together —
	// a compose `up`, a rolling reboot, a host bringing every container back at
	// once — and an unjittered cadence would aim a synchronised herd of rebind
	// attempts at the same instant (the WK-13 shape). Matches
	// adminUIListenJitter, socks5BindJitter and haLeaseRecoveryJitter.
	cpGRPCBindJitter = 0.20

	// cpGRPCBindLogInterval rate-limits the bind-failure log line. The log
	// carries the SIGNAL, the counter carries the MAGNITUDE — a mitigation for
	// a crash loop must not itself be a log flood (storage_health.go's rule).
	cpGRPCBindLogInterval = 60 * time.Second

	// cpGRPCUnavailableAfter is how long the listener must be continuously
	// unbindable before it is reported UNAVAILABLE (fail row, alert, gauge at
	// zero) rather than merely retrying.
	//
	// Unavailability is a DURATION, not a count — the CHAOS-54/57 rule. A
	// redeploy in which a predecessor CP is still holding the port clears in a
	// few seconds, and paging on that would page on every ordinary rollout of
	// the one node in the cluster that gets rolled most carefully.
	cpGRPCUnavailableAfter = 30 * time.Second

	// cpGRPCBindClampFloor is the shortest sleep clampCPGRPCBindSleep will
	// produce, so the one attempt it schedules to observe the unavailability
	// threshold cannot degenerate into a near-zero spin when the threshold is
	// all but reached. Mirrors socks5BindClampFloor.
	cpGRPCBindClampFloor = 100 * time.Millisecond
)

// cpGRPCHealthNow is the clock the READ path ages an in-progress failure
// episode against.
//
// It exists because of CHAOS-66's round-3 finding, applied here from the start
// rather than discovered again: a duration derived from two STORED stamps
// freezes the instant an attempt returns, so at the 30 s ceiling a failure
// landing at 29 s would leave `/health` degraded, the gauge at 1 and the
// contract row saying "retrying" for up to 36 s after the documented threshold
// had elapsed. Freshness is EVALUATED, never latched.
//
// A test seam as well as a clock: cpGRPCChaosSetup freezes it, so a gate that
// records failures with synthetic stamps is not also, invisibly, asserting
// something about how much WALL time passed between two of its own statements
// (the determinism failure CHAOS-66 §36 diagnosed the expensive way).
//
// The supervisor also measures how long a serve stayed up against it
// (cpGRPCBackoffAfterServe), so the backoff-reset policy shares the one seam.
var cpGRPCHealthNow = time.Now

// cpGRPCListenerHealth is the process-wide record of the CP gRPC listener's
// state. Mutex-guarded rather than atomic-per-field because every reader (the
// contract row, the readiness row, the health field, the metrics block) needs a
// consistent view across all of it.
type cpGRPCListenerHealth struct {
	mu sync.Mutex

	// configured is set once a Control Plane listener has been REQUESTED, before
	// the first bind attempt. The ordering is load-bearing and is CHAOS-66's
	// lesson: recording it after a successful bind would report a CP that has
	// NEVER come up as "not a Control Plane" — indistinguishable from the
	// ordinary standalone proxy or Data Plane, on exactly the node where an
	// operator is trying to find out why the fleet is not getting config.
	configured bool
	addr       string

	// serving is true between an observed successful bind and the gRPC Serve
	// call returning. everServed separates the two operator situations that
	// look identical in a gauge but need different responses: a CP that has
	// NEVER bound (a misconfiguration — occupied port, unreadable mTLS pair, a
	// deployment that was never a working Control Plane) from one that was up
	// and fell over (an environmental fault).
	serving    bool
	everServed bool

	// boundAt is when the current serve began (the last observed bind). A
	// bind does NOT end a failure episode (flap damping, Codex review of
	// #1556): the episode ends only once the listener has been serving for
	// cpGRPCServeStableAfter, so a socket whose Serve dies right after every
	// bind accumulates ONE episode toward the 30 s threshold, the page and the
	// lease withholding instead of starting a fresh one each cycle.
	boundAt time.Time

	// stopped records the supervisor exiting for shutdown rather than for a
	// fault, so a node in the middle of a clean teardown never reports a CP
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
	// Recovery is established by EVIDENCE — a listener that actually bound —
	// never by elapsed time (the storage_health.go / ca_health.go house rule).
	// A retry loop that stopped failing because it stopped trying has not
	// recovered.
	consecutive int64
	total       int64
	binds       int64

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// episode numbers failure episodes: incremented when one BEGINS
	// (firstFailure goes from zero to set); an observed bind ends it. A
	// listener-down page queued before the webhooks load carries its episode,
	// and the startup flush drops it if that episode has since ended
	// (cpGRPCEpisodeOpen) — no late "down" page for a listener that is up.
	episode uint64

	// alerted is a fire-once latch per UNAVAILABILITY episode: one page when the
	// control plane goes persistently unbindable, not one per retry. Cleared by
	// an observed bind, so a second incident pages again.
	alerted bool

	// supervisorDown latches the one state no rebind will clear: the supervisor
	// goroutine itself panicked, so nothing is attempting to bind any more.
	//
	// It is SEPARATE from the ordinary unavailable state for CHAOS-66's round-2
	// reason: the two point at OPPOSITE operator actions. An unbindable
	// listener is rebinding on its own and a restart costs an outage to achieve
	// what is already in progress; a dead supervisor is terminal and the
	// restart is the only remedy. One field for both would send the operator
	// the wrong way half the time.
	supervisorDown bool

	// terminalAlerted is the TERMINAL state's own fire-once latch, separate
	// from `alerted`: a recoverable episode that already paged ("the listener
	// keeps retrying") and then ESCALATES to terminal must page again, because
	// the one alert subscribers hold carries the opposite operator action —
	// the sibling SOCKS5 plane's escalation rule (noteSOCKS5DownWithRecovery).
	terminalAlerted bool
}

var cpGRPCListener cpGRPCListenerHealth

// cpGRPCEverFailed short-circuits the success observer until the first bind
// failure, so the healthy path costs one atomic load rather than a mutex
// acquire (the storageEverFailed pattern). A bind happens once per process in
// the healthy case, so this is not a hot path — but the fault plane must not
// tax the healthy plane.
var cpGRPCEverFailed atomic.Bool

// cpGRPCListenerSnapshot is the lock-free view handed to the reporting surfaces.
type cpGRPCListenerSnapshot struct {
	Configured     bool
	Addr           string
	Serving        bool
	EverServed     bool
	Stopped        bool
	Unavailable    bool
	Failing        bool
	SupervisorDown bool
	// Stabilizing: serving again, but the serve has not yet lasted
	// cpGRPCServeStableAfter, so the failure episode is still open.
	Stabilizing bool
	LastReason  string
	Backoff     time.Duration
	Consecutive int64
	Total       int64
	Binds       int64
	FailingFor  time.Duration
}

// fireCPGRPCListenerAlert delivers the `cp_grpc_listener_down` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
//
// STARTUP ORDERING (Codex review of #1556): the supervisor starts in
// initCluster, BEFORE initPersistentAdminState loads the webhooks, and its
// latches are fire-once — a threshold or terminal page raised before the load
// would latch and be lost. Until the startup flush it queues through
// deferStartupAlert, like every other startup-capable producer.
//
// A queued page is delivered at the flush only while its episode is still
// open (deferStartupAlertWhile + cpGRPCEpisodeOpen): a listener that recovered
// before the webhooks loaded is not paged as down (Codex review of #1556).
var fireCPGRPCListenerAlert = func(detail string, episode uint64) {
	payload := AlertPayload{Detail: detail, Source: "control_plane"}
	if !startupAlertsFlushed() {
		deferStartupAlertWhile("cp_grpc_listener_down", payload, func() bool { return cpGRPCEpisodeOpen(episode) })
		return
	}
	if !globalAlertStore.HasSubscriber("cp_grpc_listener_down") {
		return
	}
	go fireAlert("cp_grpc_listener_down", payload)
}

// cpGRPCBeginEpisodeLocked starts a failure episode if none is open. Caller
// holds cpGRPCListener.mu.
func cpGRPCBeginEpisodeLocked(now time.Time) {
	if cpGRPCListener.firstFailure.IsZero() {
		cpGRPCListener.firstFailure = now
		cpGRPCListener.episode++
	}
}

// cpGRPCEpisodeOpen reports whether failure episode ep is still the current,
// unrecovered one on a node that is still a configured, running Control
// Plane — the validity test for a queued listener-down page.
func cpGRPCEpisodeOpen(ep uint64) bool {
	now := cpGRPCHealthNow()
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	cpGRPCEndEpisodeIfStableLocked(now)
	l := &cpGRPCListener
	return l.configured && !l.stopped && l.episode == ep && !l.firstFailure.IsZero()
}

// noteCPGRPCConfigured records that a Control Plane listener was requested.
// Called BEFORE the first bind attempt — see the `configured` field comment.
func noteCPGRPCConfigured(addr string) {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.configured = true
	cpGRPCListener.addr = addr
	cpGRPCListener.stopped = false
	cpGRPCListener.supervisorDown = false
	cpGRPCListener.terminalAlerted = false
	cpGRPCListener.mu.Unlock()
}

// cpGRPCConfigured reports whether this node asked to be a Control Plane. The
// gate for every metric in this plane (the CHAOS-54 emission rule).
func cpGRPCConfigured() bool {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	return cpGRPCListener.configured
}

// errCPGRPCTLSMaterial tags a failure to load the operator-supplied Control
// Plane mTLS cert/key/CA material, so the classifier can name it without
// matching on the crypto/tls error text.
var errCPGRPCTLSMaterial = errors.New("control plane grpc tls material")

// classifyCPGRPCBindError maps a bind/serve/TLS error to a BOUNDED reason class.
//
// Never a raw error string. The listen error embeds the bind address, the TLS
// error can quote an operator-configured path, the operator-contract row is a
// VIEWER-role surface, and — most importantly — an unbounded reason gives the
// alert dedup key one distinct value per failure, which is the WK-12/RS-5
// defect. The full error goes to the rate-limited log line and nowhere else.
//
// The classes are ONE ordered table, cpGRPCReasonRules, and the first match
// wins. Its order is the contract: EXPLICIT sentinel tags first, generic
// errnos after (Codex review of #1556). A tagged error routinely WRAPS an
// errno — an unreadable cert/key/CA file is tls.LoadX509KeyPair's wrapped
// EACCES under errCPGRPCTLSMaterial — and the tag is what names the failing
// stage; checking the errno first sent a TLS-permission outage to the
// bind-port/CAP_NET_BIND_SERVICE remedy. TestChaos71_CPGRPCReasonTable pins
// every class with a wrapped errno inside each tag.
//
// Errnos are matched via errors.As on syscall.Errno, never by string: net
// wraps as *net.OpError{*os.SyscallError{syscall.Errno}} and the text is
// platform-specific (the CHAOS-54 rule).
//
// The `network_error` rule requires an actual TIMEOUT, carrying forward
// CHAOS-66's correction to the two sibling classifiers: *net.OpError satisfies
// net.Error UNCONDITIONALLY (Timeout() false for a bind EINVAL), so the
// unqualified form reports every unrecognised errno as a network fault — and
// makes `listen_failed` reachable only by an error the net package did not
// produce.
func classifyCPGRPCBindError(err error) string {
	if err == nil {
		return "none"
	}
	for _, r := range cpGRPCReasonRules {
		if r.match(err) {
			return r.reason
		}
	}
	return "listen_failed"
}

// cpGRPCReasonRule is one row of the classifier table.
type cpGRPCReasonRule struct {
	reason string
	match  func(error) bool
}

// cpGRPCReasonRules is the ordered classifier table (first match wins):
// sentinel tags, then errnos, then the timeout test. A new tag goes in the
// first block, never after an errno rule.
var cpGRPCReasonRules = []cpGRPCReasonRule{
	// 1. Explicit stage tags.
	{"tls_certificate", cpGRPCTagged(errCPGRPCTLSMaterial)},
	{"address_publish_rejected", cpGRPCTagged(errCPGRPCAddressPublish)},
	// 2. Generic errnos.
	{"port_in_use", cpGRPCErrno(syscall.EADDRINUSE)},
	{"permission_denied", cpGRPCErrno(syscall.EACCES, syscall.EPERM)},
	{"address_unavailable", cpGRPCErrno(syscall.EADDRNOTAVAIL)},
	{"descriptors_exhausted", cpGRPCErrno(syscall.EMFILE, syscall.ENFILE)},
	// 3. Network timeout.
	{"network_error", func(err error) bool {
		var ne net.Error
		return errors.As(err, &ne) && ne.Timeout()
	}},
}

func cpGRPCTagged(tag error) func(error) bool {
	return func(err error) bool { return errors.Is(err, tag) }
}

func cpGRPCErrno(want ...syscall.Errno) func(error) bool {
	return func(err error) bool {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return false
		}
		for _, w := range want {
			if errno == w {
				return true
			}
		}
		return false
	}
}

// cpGRPCBindRemedy returns the operator action for a bounded reason class.
//
// Per-class rather than one string for every branch — CHAOS-66's round-3
// finding: a bounded classifier is worth nothing if one remedy is printed for
// every class, and a node out of descriptors was being sent to hunt the owner
// of a port nobody holds.
//
// Two clauses are invariant in every branch and must stay that way, because
// they are the two things an operator most needs to know and most often
// assumes the opposite of: the listener rebinds BY ITSELF (so a restart costs
// an outage to achieve what is already happening), and this node's proxy data
// plane and admin UI are UNAFFECTED (so this is not a traffic incident).
func cpGRPCBindRemedy(reason string) string {
	const tail = " The listener rebinds automatically once the fault clears — no restart is required. This node's proxy data plane and admin UI are unaffected and are still enforcing policy; enrolled Data Planes keep serving their last-good config while the Control Plane is unreachable."
	switch reason {
	case "port_in_use":
		return "Another process holds the Control Plane gRPC address. Check for a predecessor container still draining, a second Culvert instance, or a host service on that port." + tail
	case "permission_denied":
		return "The process may not bind that address. A privileged port needs CAP_NET_BIND_SERVICE (or a port above 1024)." + tail
	case "address_unavailable":
		return "The configured address does not exist on this host yet — usually an interface that is not up, or a literal IP this node does not own." + tail
	case "descriptors_exhausted":
		return "This node is out of file descriptors, which affects far more than the Control Plane. Raise the process/container descriptor limit and look for a descriptor leak." + tail
	case "tls_certificate":
		return "The Control Plane mTLS material could not be loaded. Check that -cp-grpc-cert/-cp-grpc-key/-cp-grpc-ca are readable and valid — a cert-manager or certbot rotation that briefly truncates the pair lands here and clears on its own." + tail
	case "address_publish_rejected":
		return "The listener bound, but publishing the Control Plane address list to the fleet was rejected at commit (see LastPublishError / the config_snapshot_rejected alert — usually a config at its sync size cap). Activation is refused rather than leaving Data Planes on a stale address list; reduce the oversized collection." + tail
	default:
		return "See the rate-limited CONTROL-PLANE gRPC log line on this node for the underlying error." + tail
	}
}

// cpGRPCElapsedSince reports how long a failure episode that began at `first`
// has been running.
//
// It takes the LATER of the stored end and the clock-derived one, so a clock
// ROLLBACK cannot shrink an outage that has already been observed. That is
// deliberately the OPPOSITE of CHAOS-61's rollback verdict for a remote
// broadcast, and for the opposite reason: there the fail-safe answer is to
// distrust the value, here it is to keep the longer duration, because
// under-reporting an outage is what loses the page.
func cpGRPCElapsedSince(first, last, now time.Time) time.Duration {
	if first.IsZero() {
		return 0
	}
	end := last
	if now.After(end) {
		end = now
	}
	if d := end.Sub(first); d > 0 {
		return d
	}
	return 0
}

// clampCPGRPCBindSleep shortens a sleep that would straddle the unavailability
// threshold.
//
// The alert is produced by an ATTEMPT (noteCPGRPCBindFailure holds the
// fire-once latch and nothing else wakes the supervisor), so a sleep that
// crosses the threshold would delay the page by up to the full ceiling plus
// jitter. CHAOS-55's recoveryPollCeiling rule: an interval that can straddle a
// state transition is capped below it. This is a CORRECTNESS bound, not tuning,
// and it costs at most one extra attempt per episode — capping the CEILING
// instead was rejected as paying permanently for a property that matters on one
// sleep.
func clampCPGRPCBindSleep(d, failingFor time.Duration) time.Duration {
	remaining := cpGRPCUnavailableAfter - failingFor
	if remaining <= 0 || d <= remaining {
		return d
	}
	if remaining < cpGRPCBindClampFloor {
		return cpGRPCBindClampFloor
	}
	return remaining
}

// noteCPGRPCBindFailure records one failed bind (or TLS-material, or rejected
// commit) attempt. See noteCPGRPCListenFailure.
func noteCPGRPCBindFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool, failingFor time.Duration) {
	return noteCPGRPCListenFailure(reason, backoff, now)
}

// noteCPGRPCListenFailure is the ONE failure recorder for this plane: a failed
// bind and a serve that ended both go through it, so the counters, the shared
// log gate, the unavailability episode and the fire-once alert latch can never
// drift between the two paths. (They did: the serve-end path once skipped the
// alert latch, so a listener dark past the threshold after a serve death could
// go unpaged — Codex review of #1556.) Reports whether the caller should log,
// plus how long the episode has been running so the caller can clamp its sleep.
func noteCPGRPCListenFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool, failingFor time.Duration) {
	cpGRPCEverFailed.Store(true)

	cpGRPCListener.mu.Lock()
	// A serve that outlived the stability window ended its episode; this
	// failure starts a new one. A shorter serve continues the SAME episode.
	cpGRPCEndEpisodeIfStableLocked(now)

	cpGRPCListener.serving = false
	cpGRPCListener.total++
	cpGRPCListener.consecutive++
	cpGRPCListener.lastFailure = now
	cpGRPCListener.lastReason = reason
	cpGRPCListener.backoff = backoff
	cpGRPCBeginEpisodeLocked(now)

	if cpGRPCListener.logAt.IsZero() || now.Sub(cpGRPCListener.logAt) >= cpGRPCBindLogInterval {
		cpGRPCListener.logAt = now
		shouldLog = true
	} else {
		cpGRPCListener.suppressed++
	}

	failingFor = cpGRPCElapsedSince(cpGRPCListener.firstFailure, now, now)
	unavailable := failingFor >= cpGRPCUnavailableAfter
	alertNow := unavailable && !cpGRPCListener.alerted
	if alertNow {
		cpGRPCListener.alerted = true
	}
	failures := cpGRPCListener.consecutive
	everServed := cpGRPCListener.everServed
	episode := cpGRPCListener.episode
	cpGRPCListener.mu.Unlock()

	if alertNow {
		posture := "has never bound since this node started"
		if everServed {
			posture = "stopped serving"
		}
		// BOUNDED detail: Dispatch dedups on event + ":" + Detail, so the raw
		// error — which embeds the bind address — would mint one key per
		// failure and defeat the dedup window by construction (WK-12/RS-5).
		fireCPGRPCListenerAlert(fmt.Sprintf(
			"Control Plane gRPC listener %s and has been unbindable for over %s (%d consecutive attempts, reason: %s). "+
				"Config distribution, node enrollment and certificate renewal are unavailable fleet-wide. "+
				"Enrolled Data Planes continue serving their last-good config. "+
				"This node's own proxy data plane and admin UI are unaffected. The listener keeps retrying.",
			posture, cpGRPCUnavailableAfter, failures, reason), episode)
	}
	return shouldLog, failingFor
}

// noteCPGRPCBound records an OBSERVED successful bind and reports the number of
// suppressed log lines plus whether the bind came INSIDE an open failure
// episode (so the caller logs a rebind line instead of an ordinary start).
//
// A bind does NOT end the episode — flap damping (Codex review of #1556). It
// marks the listener serving and stamps boundAt; the episode ends only once
// that serve has lasted cpGRPCServeStableAfter (cpGRPCEndEpisodeIfStableLocked),
// so a Serve that fails at once keeps firstFailure, the alert latch and the
// consecutive count of the SAME episode. Recovery is still established by
// evidence — a serve that stayed up — never by elapsed time alone.
func noteCPGRPCBound() (suppressed int64, rebound bool) {
	now := cpGRPCHealthNow()
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	cpGRPCListener.serving = true
	cpGRPCListener.everServed = true
	cpGRPCListener.binds++
	cpGRPCListener.boundAt = now
	if !cpGRPCEverFailed.Load() {
		return 0, false
	}
	return cpGRPCListener.suppressed, !cpGRPCListener.firstFailure.IsZero()
}

// cpGRPCEndEpisodeIfStableLocked ends the open failure episode once the
// current serve has lasted cpGRPCServeStableAfter. Every recorder and reader
// calls it first (under cpGRPCListener.mu), so the episode's end is evaluated
// on the injected clock — no timer, no extra goroutine. Caller holds
// cpGRPCListener.mu.
func cpGRPCEndEpisodeIfStableLocked(now time.Time) {
	l := &cpGRPCListener
	if !l.serving || l.firstFailure.IsZero() || now.Sub(l.boundAt) < cpGRPCServeStableAfter {
		return
	}
	l.consecutive = 0
	l.suppressed = 0
	l.firstFailure = time.Time{}
	l.lastFailure = time.Time{}
	l.backoff = 0
	l.logAt = time.Time{}
	l.alerted = false
	l.supervisorDown = false
	l.terminalAlerted = false
}

// noteCPGRPCServeEnded records that the gRPC Serve call returned while the node
// is still running — the listener is gone and a rebind is pending.
//
// Distinct from noteCPGRPCSupervisorDown: a rebind IS in progress here, so the
// operator action must not be "restart this node". A serve that ended is a
// FAILURE of the listener and is counted as one — `culvert_cp_grpc_bind_failures_total`
// says "bind/TLS/serve" — through the same recorder, log gate and alert latch
// as a failed bind (noteCPGRPCListenFailure).
func noteCPGRPCServeEnded(reason string, backoff time.Duration) (shouldLog bool, failingFor time.Duration) {
	return noteCPGRPCListenFailure(reason, backoff, cpGRPCHealthNow())
}

// noteCPGRPCSupervisorDown records the TERMINAL state: the supervisor goroutine
// itself is gone (it panicked), so nothing is attempting to bind any more.
//
// A separate recorder from noteCPGRPCServeEnded / noteCPGRPCBindFailure rather
// than a boolean argument, so the CALL SITE states which it means — CHAOS-66's
// round-2 conclusion, where a mutation swapping the two recorders left every
// behavioural subtest green.
func noteCPGRPCSupervisorDown(reason string) {
	cpGRPCEverFailed.Store(true)
	cpGRPCListener.mu.Lock()
	cpGRPCEndEpisodeIfStableLocked(cpGRPCHealthNow())
	cpGRPCListener.serving = false
	cpGRPCListener.supervisorDown = true
	cpGRPCListener.lastReason = reason
	cpGRPCBeginEpisodeLocked(cpGRPCHealthNow())
	// Terminal escalation BYPASSES the recoverable latch (see terminalAlerted).
	alertNow := !cpGRPCListener.terminalAlerted
	cpGRPCListener.terminalAlerted = true
	cpGRPCListener.alerted = true
	episode := cpGRPCListener.episode
	cpGRPCListener.mu.Unlock()

	if alertNow {
		fireCPGRPCListenerAlert(fmt.Sprintf(
			"Control Plane gRPC listener supervisor stopped (reason: %s) and will NOT rebind on its own. "+
				"Config distribution, node enrollment and certificate renewal are unavailable fleet-wide until this node is restarted. "+
				"Enrolled Data Planes continue serving their last-good config. "+
				"This node's own proxy data plane and admin UI are unaffected.", reason), episode)
	}
}

// noteCPGRPCActivationRejected restores the UNCONFIGURED state after a
// runtime (admin/promote) activation was refused with an error.
//
// The request answered 409 and the node is still a live standalone gateway, so
// every surface must read as it did before the attempt: leaving `configured`
// set made /health say `stopped`, dropped the readiness row, emitted `up 0`
// with no unavailability, and had diagnostics claim the node was shutting down
// (Codex review of #1556). The lifetime COUNTERS are kept — a Prometheus
// counter must never go backwards — and are simply not emitted while the
// plane is unconfigured.
func noteCPGRPCActivationRejected() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.configured = false
	cpGRPCListener.addr = ""
	cpGRPCListener.serving = false
	cpGRPCListener.boundAt = time.Time{}
	cpGRPCListener.stopped = false
	cpGRPCListener.supervisorDown = false
	cpGRPCListener.terminalAlerted = false
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.lastFailure = time.Time{}
	cpGRPCListener.lastReason = ""
	cpGRPCListener.backoff = 0
	cpGRPCListener.consecutive = 0
	cpGRPCListener.suppressed = 0
	cpGRPCListener.logAt = time.Time{}
	cpGRPCListener.alerted = false
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCListenerStopped records a clean shutdown exit.
func noteCPGRPCListenerStopped() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.serving = false
	cpGRPCListener.stopped = true
	cpGRPCListener.mu.Unlock()
}

// cpGRPCListenerState is the snapshot accessor every reporting surface uses.
func cpGRPCListenerState() cpGRPCListenerSnapshot {
	now := cpGRPCHealthNow()
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	cpGRPCEndEpisodeIfStableLocked(now)

	snap := cpGRPCListenerSnapshot{
		Configured:     cpGRPCListener.configured,
		Addr:           cpGRPCListener.addr,
		Serving:        cpGRPCListener.serving,
		EverServed:     cpGRPCListener.everServed,
		Stopped:        cpGRPCListener.stopped,
		SupervisorDown: cpGRPCListener.supervisorDown,
		LastReason:     cpGRPCListener.lastReason,
		Backoff:        cpGRPCListener.backoff,
		Consecutive:    cpGRPCListener.consecutive,
		Total:          cpGRPCListener.total,
		Binds:          cpGRPCListener.binds,
	}
	if !cpGRPCListener.firstFailure.IsZero() {
		snap.FailingFor = cpGRPCElapsedSince(cpGRPCListener.firstFailure, cpGRPCListener.lastFailure, now)
	}
	snap.Failing = !snap.Serving && !snap.Stopped && snap.Configured
	snap.Stabilizing = snap.Serving && !cpGRPCListener.firstFailure.IsZero()
	if snap.Serving {
		// The reported backoff is the CURRENT rebind wait: none while serving,
		// stabilizing included (the metric's documented "0 while serving").
		// The internal value is kept for the episode's flap policy.
		snap.Backoff = 0
	}
	snap.Unavailable = snap.Failing && (snap.SupervisorDown || snap.FailingFor >= cpGRPCUnavailableAfter)
	return snap
}

// cpGRPCLeaseRenewWithheld reports whether an HA leader holding the fencing
// lease must stop renewing it because this node's Control Plane gRPC listener
// is dark, plus a BOUNDED reason for the log/self-fence line.
//
// "Dark" is exactly the state every other surface already calls unavailable —
// configured, not serving, not stopped for shutdown, and either failing for at
// least cpGRPCUnavailableAfter or with the supervisor itself gone. Reusing that
// one predicate keeps the fence, the alert, the contract row and the gauge from
// ever disagreeing about whether the listener is down. A node that never asked
// to be a Control Plane, or whose listener is merely rebinding inside the
// threshold (an ordinary rollout), keeps renewing.
func cpGRPCLeaseRenewWithheld() (reason string, withhold bool) {
	snap := cpGRPCListenerState()
	if !snap.Unavailable {
		return "", false
	}
	if snap.SupervisorDown {
		return fmt.Sprintf("Control Plane gRPC listener supervisor stopped (reason: %s)", snap.LastReason), true
	}
	return fmt.Sprintf("Control Plane gRPC listener unavailable for %s (%d consecutive attempts, reason: %s)",
		snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason), true
}

// cpGRPCHealthPosture is the FIXED enum on the proxy port's /health.
//
// Five values, and the set is a monitoring contract: not_configured, ready,
// rebinding, unavailable, stopped.
func cpGRPCHealthPosture() string {
	snap := cpGRPCListenerState()
	switch {
	case !snap.Configured:
		return "not_configured"
	case snap.Stopped:
		return "stopped"
	case snap.Serving:
		return "ready"
	case snap.Unavailable:
		return "unavailable"
	default:
		return "rebinding"
	}
}

// checkCPGRPCListener is the `cp_grpc_listener` operator-contract row.
//
// Severity policy, mirroring checkAdminUIListener:
//   - not configured → ok. This node is not a Control Plane.
//   - stopped → ok. The supervisor exited because the node is shutting down.
//   - supervisor down → FAIL, and the ONLY branch whose remedy is a restart.
//   - unavailable (persistently unbindable) → FAIL. The fleet's config
//     distribution plane has been unreachable for longer than the threshold.
//   - failing but under the threshold → warn. Still retrying; a predecessor
//     draining the port clears on its own within seconds, and failing here
//     would report a self-healing rollout as broken.
//   - serving → ok, carrying the cumulative failure count so a HISTORY of
//     transient failures stays visible after recovery.
func checkCPGRPCListener() OperatorContractCheck {
	snap := cpGRPCListenerState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "cp_grpc_listener",
			Status:  diagOK,
			Message: "Not a Control Plane (no gRPC listener requested)",
		}
	}
	if snap.Stopped {
		return OperatorContractCheck{
			Code:    "cp_grpc_listener",
			Status:  diagOK,
			Message: "Control Plane gRPC listener stopped (node shutting down)",
		}
	}
	if snap.SupervisorDown {
		return OperatorContractCheck{
			Code:   "cp_grpc_listener",
			Status: diagFail,
			Message: fmt.Sprintf("Control Plane gRPC listener supervisor stopped (reason: %s) and will NOT rebind; config distribution, enrollment and certificate renewal are unavailable fleet-wide",
				snap.LastReason),
			OperatorAction: "Restart this node — unlike an ordinary bind failure this state does not recover on its own. Enrolled Data Planes keep serving their last-good config meanwhile, and this node's proxy data plane and admin UI are unaffected.",
		}
	}
	if snap.Unavailable {
		posture := "has never bound since this node started"
		if snap.EverServed {
			posture = "stopped serving"
		}
		return OperatorContractCheck{
			Code:   "cp_grpc_listener",
			Status: diagFail,
			Message: fmt.Sprintf("Control Plane gRPC listener %s and has been unbindable for %s (%d consecutive attempts, reason: %s); config distribution, node enrollment and certificate renewal are unavailable fleet-wide",
				posture, snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason),
			OperatorAction: cpGRPCBindRemedy(snap.LastReason),
		}
	}
	if snap.Failing {
		return OperatorContractCheck{
			Code:   "cp_grpc_listener",
			Status: diagWarn,
			Message: fmt.Sprintf("Control Plane gRPC listener is not currently serving (%d consecutive attempts, reason: %s); retrying with backoff",
				snap.Consecutive, snap.LastReason),
			OperatorAction: "No action yet — the listener retries automatically and this usually clears within seconds of a restart or a certificate rotation. If it persists it is raised to a failure.",
		}
	}
	if snap.Stabilizing {
		// OK, like any serving listener: an ordinary rollout that failed a
		// bind or two must not read as degraded for the window. A real flap
		// is not hidden by this — it spends its time NOT serving and is raised
		// through the unavailable branch above.
		return OperatorContractCheck{
			Code:   "cp_grpc_listener",
			Status: diagOK,
			Message: fmt.Sprintf("Control Plane gRPC listener bound and serving again, stabilizing (%d consecutive failures in this episode, last: %s); the episode closes once it has served for %s",
				snap.Consecutive, snap.LastReason, cpGRPCServeStableAfter),
		}
	}
	if snap.Total > 0 {
		return OperatorContractCheck{
			Code:    "cp_grpc_listener",
			Status:  diagOK,
			Message: fmt.Sprintf("Control Plane gRPC listener serving (%d transient bind failures since startup)", snap.Total),
		}
	}
	return OperatorContractCheck{
		Code:    "cp_grpc_listener",
		Status:  diagOK,
		Message: "Control Plane gRPC listener serving",
	}
}

// appendCPGRPCReadinessCheck adds the report-only `cp_grpc` row to /ready on the
// PROXY port.
//
// REPORT-ONLY, like `ca`, `cluster_ca`, `socks5` and `admin_ui`, and the
// reasoning here is the strongest of the set: a Control Plane node whose gRPC
// listener cannot bind is proxying its own traffic perfectly. Gating the
// default readiness verdict on it would pull a fully-functional gateway out of
// the load balancer because the plane that serves config to OTHER nodes is
// down — converting a fleet-management outage into a traffic outage, which is
// the exact inversion this whole change exists to prevent. Operators who do
// want such nodes ejected opt in via /ready?strict=1.
//
// Absent entirely on a node that is not a Control Plane, so a standalone proxy
// or a Data Plane never grows a permanently-green row.
//
// The detail is a FIXED string per branch. /ready is served UNAUTHENTICATED on
// the proxy port, so the attempt count and reason class — which would tell an
// unauthenticated caller that this node is a Control Plane whose management
// plane is down, and why — stay on the role-gated row, the alert and the logs.
func appendCPGRPCReadinessCheck(checks map[string]*readinessCheck) {
	snap := cpGRPCListenerState()
	if !snap.Configured || snap.Stopped {
		return
	}
	switch {
	case snap.Serving:
		checks["cp_grpc"] = &readinessCheck{Status: "ok"}
	case snap.Unavailable:
		checks["cp_grpc"] = &readinessCheck{
			Status: "fail",
			Detail: "control plane gRPC listener is not serving — see server logs",
		}
	default:
		checks["cp_grpc"] = &readinessCheck{
			Status: "fail",
			Detail: "control plane gRPC listener is rebinding — see server logs",
		}
	}
}

// resetCPGRPCListenerHealthForTest restores the process-global record. Folded
// into the shared diagnostic reset so no test inherits another's episode.
func resetCPGRPCListenerHealthForTest() {
	cpGRPCEverFailed.Store(false)
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	// Fields are zeroed individually rather than by assigning a fresh struct:
	// `cpGRPCListener = cpGRPCListenerHealth{}` while holding `mu` overwrites
	// the mutex itself with an unlocked one, and the deferred Unlock then
	// fatals with "unlock of unlocked mutex". Caught by the first run of these
	// gates.
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
	cpGRPCListener.logAt = time.Time{}
	cpGRPCListener.suppressed = 0
	cpGRPCListener.alerted = false
	cpGRPCListener.supervisorDown = false
	cpGRPCListener.terminalAlerted = false
}

// cpGRPCListenerStatus is the /health posture value. Empty on a node that is
// not a Control Plane so the field is omitted entirely — see the CPGRPC field
// comment in healthcheck.go.
func cpGRPCListenerStatus() string {
	if !cpGRPCConfigured() {
		return ""
	}
	return cpGRPCHealthPosture()
}

// writeCPGRPCMetrics emits the culvert_cp_grpc_* series for /metrics. Lives
// with the plane it describes so handleMetrics carries one call, not the block.
func writeCPGRPCMetrics(w io.Writer) {
	// Emitted only on a node that asked to be a Control Plane (the CHAOS-54
	// emission rule the other listener blocks in handleMetrics follow): a
	// flat `up 0` from every standalone proxy and every Data Plane in the fleet
	// is indistinguishable from a broken CP, and the documented paging rule is
	// `== 0`.
	//
	// `up` is 0 whenever the listener is not currently serving — including
	// while it is rebinding — because the loop rebinds for as long as the
	// process lives. The alertable pair is `culvert_cp_grpc_unavailable 1`,
	// latched only once the fault has persisted past the threshold, so it does
	// not fire on the few seconds of rebinding that follow an ordinary rollout
	// of the Control Plane.
	//
	// Served by the PROXY port's /metrics, which is what makes it reachable
	// while the cluster plane is down.
	cp := cpGRPCListenerState()
	if !cp.Configured {
		return
	}
	up, unavailable := 0, 0
	if cp.Serving {
		up = 1
	}
	if cp.Unavailable {
		unavailable = 1
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_cp_grpc_up 1 while the Control Plane gRPC listener is serving; 0 while it is not
# TYPE culvert_cp_grpc_up gauge
culvert_cp_grpc_up %d

# HELP culvert_cp_grpc_unavailable 1 while the Control Plane gRPC listener has been unable to serve for longer than the unavailability threshold
# TYPE culvert_cp_grpc_unavailable gauge
culvert_cp_grpc_unavailable %d

# HELP culvert_cp_grpc_bind_failures_total Control Plane gRPC bind/TLS/serve failures since startup
# TYPE culvert_cp_grpc_bind_failures_total counter
culvert_cp_grpc_bind_failures_total %d

# HELP culvert_cp_grpc_binds_total Successful Control Plane gRPC listener binds since startup
# TYPE culvert_cp_grpc_binds_total counter
culvert_cp_grpc_binds_total %d

# HELP culvert_cp_grpc_bind_backoff_seconds Current Control Plane gRPC rebind backoff; 0 while the listener is serving
# TYPE culvert_cp_grpc_bind_backoff_seconds gauge
culvert_cp_grpc_bind_backoff_seconds %g
`,
		up,
		unavailable,
		cp.Total,
		cp.Binds,
		cp.Backoff.Seconds(),
	)
}
