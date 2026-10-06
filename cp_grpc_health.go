package main

// cp_grpc_health.go — CHAOS-73: the Control Plane's own gRPC listener, under
// bind and serve faults.
//
// Why this file exists.
//
// §36's closing paragraph named this path as the last unexamined member of the
// listener-fatality family: *"the CP gRPC bind (`cluster_startup.go`) is the
// closest unexamined analogue."* It is, and it lands harder than the sentence
// suggests, in two directions at once.
//
// THE BIND WAS FATAL. `startControlPlaneWithHAResume` had exactly one error
// branch — `logFatalf("ControlPlane gRPC: %v", err)`, which `os.Exit(1)`s the
// process — and `initCluster` runs in main.go's init block at line 228, BEFORE
// `startAdminUI` (269) and `buildAndStartProxyServer` (271). So every way the
// CLUSTER CONTROL plane's listener could fail to come up terminated the
// HTTP/HTTPS proxy, SOCKS5, the admin UI and every health endpoint before any
// of them existed. Both triggers were reproduced against the real binary.
//
//  1. **The gRPC port is occupied.** With 127.0.0.1:50551 held by a squatter:
//
//     ControlPlane: config v1791324754 published
//     ClusterCA: generated new cluster CA (expires 2036-10-03)
//     ControlPlane gRPC: gRPC listen: listen tcp 127.0.0.1:50551: bind: address already in use
//     → exit 1, proxy http_code=000, adminui http_code=000, health http_code=000
//
//     `validatePortCollisions` (main.go) compares Culvert's own three ports to
//     EACH OTHER only — the CP gRPC port is not among them, and nothing on the
//     host is visible to it. A draining predecessor container, a second
//     Culvert, or anything else on :50051 reaches this.
//
//  2. **The gRPC certificate pair cannot be loaded.** `cpServerOption` reads
//     `-cp-grpc-cert`/`-cp-grpc-key` at call time, so a rotation that briefly
//     truncates or re-permissions the pair — certbot, cert-manager, a Docker
//     secret whose mount is not ready — is a boot that ends in
//     `ControlPlane gRPC: gRPC TLS: tls: failed to find any PEM data in key
//     input` and exit 1. Reproduced with a zero-byte key: same three 000s.
//
// Under `restart: unless-stopped` each is an unattended CRASH LOOP recoverable
// only with shell access. And **"it exits, so it fails closed" is wrong and
// must not be re-argued** — §33's rule, which §36 restates: process death picks
// NO posture, it delegates the choice to the topology. An explicit-proxy fleet
// loses all egress; a PAC/WPAD fleet with a `DIRECT` fallback, or a transparent
// deployment, goes UNFILTERED.
//
// THE ASYMMETRY IS THE FINDING. `enableControlPlane` has THREE callers and the
// identical error produced three different postures:
//
//	ui_cluster.go:98        → HTTP 500 to the admin, node keeps serving
//	ha.go promote()         → contained, stays standby, retryable (CHAOS-25)
//	cluster_startup.go:95   → os.Exit(1), takes the data plane with it
//
// The two non-fatal callers are the proof that the fault is survivable: one of
// them is a live admin API that has always returned an error for it, and the
// other deliberately treats it as "the node did not become a leader" and
// retries. The boot path is the outlier. This is CHAOS-58's shape exactly —
// *"the ADMIN directory-test endpoint already called conn.SetTimeout; the
// per-request production path did not"* — the bounded path being the one
// clicked occasionally and the unbounded one the one every boot takes.
//
// THE SERVE LOOP WAS SILENT, which is the second half and the one no restart
// fixes. `StartControlPlaneGRPC` ends with:
//
//	go func() {
//	    if err := srv.Serve(ln); err != nil {
//	        logger.Printf("ControlPlane gRPC error: %v", err)   // ← and nothing else
//	    }
//	}()
//
// grpc-go backs off on a TEMPORARY accept error (unlike the hand-rolled SOCKS5
// loop §22 had to fix) and returns nil after Stop/GracefulStop, so the error
// branch is reached only by a genuinely non-temporary accept fault — EBADF,
// ENOTSOCK, EINVAL, the same classes `socks5AcceptFatal` enumerates. When it
// is, the goroutine logs ONE line and exits, and:
//
//   - `clusterRole.role` stays `"control-plane"` — it is set after a successful
//     bind and never cleared;
//   - `clusterRole.grpcSrv` stays non-nil, pointing at a server serving nothing;
//   - `GET /api/cluster/status` keeps reporting `role: "control-plane"` with its
//     `grpcAddr`, plus `nodes`, `enrolledNodes` and `activeTokens`;
//   - the heartbeat monitor keeps running and `globalConfigStore.Update` keeps
//     publishing config;
//   - and no Data Plane can `GetConfig`, `Enroll`, `RenewCert` or
//     `PushAuditEvents`.
//
// That is PX-18 in the control plane: *"returning silently would leave every
// probe green on a dead listener."* It is also an observability asymmetry with
// a precise operational cost. The DP side of this link HAS a health surface —
// the `cp_poll` `/ready` row and contract row say "I cannot reach my Control
// Plane". The CP side had nothing that says "my listener is dead". So on a
// fleet in this state every DP reports a failure and the CP reports perfect
// health, and the evidence points an operator at the network rather than at
// the one process that needs restarting. §33's rule, one link over: the
// surfaces must ride a port that SURVIVES the fault they describe, because the
// CP's own gRPC port cannot report that it is unreachable.
//
// What this plane does NOT change: `enableControlPlane` keeps its one-shot
// contract, byte-for-byte, because `promote()` DEPENDS on the error. A
// promotion whose listener silently "succeeded and will retry later" would
// assert leadership, take the fencing lease and publish config no Data Plane
// can fetch — a leader nobody can reach, which is strictly worse than the
// standby it replaced. The recovery loop therefore wraps the BOOT caller only.
//
// Surfaces, all on the PROXY port and all reusing existing vocabulary:
//
//   - `/api/diagnostics` — the `cp_grpc_listener` operator-contract row.
//   - `/ready` — a report-only `cp_grpc` row. REPORT-ONLY is load-bearing for
//     the §33 reason: a CP whose gRPC listener is down is still proxying
//     traffic perfectly, and failing readiness would eject a healthy gateway
//     from the load balancer over its cluster plane. Strict callers opt in via
//     `?strict=1`.
//   - `/health` — the `cp_grpc` posture field (fixed enum, unauthenticated).
//   - `/metrics` — `culvert_cp_grpc_{up,unavailable,listen_failures_total,
//     binds_total,listen_backoff_seconds,serve_exits_total}`, emitted ONLY on a
//     node that asked to be a Control Plane (the socks5/admin_ui rule: a `0`
//     from a standalone proxy is indistinguishable from a dead CP and the
//     documented paging rule is `== 0`).
//   - alerts — `cp_grpc_listener_down`. A NEW event name is correct here and
//     not a §36 violation: §36 reused `socks5_listener_down` because CHAOS-54
//     had already created a row for that listener, whereas no existing event
//     covers the CP's gRPC plane. The GUI checkbox is added in the same change
//     (GUI-parity), so the name is subscribable rather than silently unused.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// cpGRPCListenBackoffInitial / cpGRPCListenBackoffMax bound the RATE of
	// rebind attempts, never their COUNT.
	//
	// Never bounding the count is the CHAOS-55 argument, and it is stronger
	// here than for any listener examined so far: the terminal state of "give
	// up" is a fleet whose Control Plane will never return without a human,
	// while every Data Plane runs on last-known-good config that ages for as
	// long as the outage lasts. "Avoid infinite retries" is satisfied the
	// CHAOS-54/55/57 way — the retry is never SILENT: the first failure logs
	// immediately, then one line per cpGRPCListenLogInterval, then one recovery
	// line naming the suppressed count, with the magnitude in a counter and the
	// state in a gauge, a contract row and an alert.
	//
	// The floor and ceiling are copied from the admin UI plane deliberately,
	// not re-derived: the faults are the same (a port frees when a predecessor
	// finishes draining, a certificate reappears when a rotation completes,
	// both measured in seconds) and two cadences for one fault class is the
	// second-dialect trap this register keeps naming.
	cpGRPCListenBackoffInitial = 1 * time.Second
	cpGRPCListenBackoffMax     = 30 * time.Second

	// cpGRPCListenJitter spreads the backoff by ±20%. A fleet restarts together
	// — a compose `up`, a rolling reboot, a host bringing every container back
	// at once — and an unjittered cadence aims a synchronised herd of rebind
	// attempts at the same instant (the WK-13 shape). Matches
	// adminUIListenJitter and haLeaseRecoveryJitter.
	cpGRPCListenJitter = 0.20

	// cpGRPCListenLogInterval rate-limits the failure log line. The FIRST
	// failure of an episode is always logged — the operator must see the onset
	// — then one line per interval, then one recovery line carrying the
	// suppressed count. The log carries the SIGNAL, the counter the MAGNITUDE.
	cpGRPCListenLogInterval = 60 * time.Second

	// cpGRPCUnavailableAfter is how long the listener must be continuously
	// unusable before it is reported UNAVAILABLE (fail row, alert, gauge)
	// rather than merely retrying.
	//
	// A DURATION, not a count: the backoff ceiling is reached in under a
	// minute, so paging on attempts would page on every ordinary redeploy in
	// which a predecessor is still draining the port. Thirty seconds of a
	// control plane no Data Plane can reach is no longer a handover artifact.
	cpGRPCUnavailableAfter = 30 * time.Second
)

// cpGRPCListenerHealth is the process-wide record of the CP gRPC listener's
// state. Mutex-guarded rather than atomic-per-field because every reader (the
// diagnostics row, the readiness row, the health field, the metrics block, the
// cluster status API) needs a consistent view across all of it.
type cpGRPCListenerHealth struct {
	mu sync.Mutex

	// configured is set when a Control Plane role was REQUESTED, before the
	// first bind attempt — the CHAOS-54/66 ordering rule. Recording it only
	// after a successful bind would report a listener that has NEVER come up as
	// "not a Control Plane", which is indistinguishable from a standalone proxy
	// on exactly the node where an operator is debugging a cluster outage.
	configured bool
	addr       string

	// serving spans an observed successful bind to the serve call returning.
	// everServed separates the two operator situations a single gauge cannot:
	// a Control Plane that has NEVER come up (a misconfiguration — wrong port,
	// bad certificate, a deployment that was never a working CP) from one that
	// was up and fell over (an environmental fault).
	serving    bool
	everServed bool

	// stopped records the loop exiting for SHUTDOWN rather than for a fault, so
	// a node being torn down never reports a cluster failure on its way out.
	stopped bool

	// serveExits counts serve-loop deaths that were NOT a shutdown — the
	// silent-failure case this plane exists to make loud. Tracked separately
	// from bind failures because they point at different causes (a dead accept
	// loop versus a port that will not bind) even though the remedy is the
	// same rebind.
	serveExits int64

	// firstFailure starts the current run of consecutive failures; zero while
	// serving. Unavailability is measured from here, so a listener that fails,
	// binds, and fails again never accumulates toward the threshold across
	// healthy periods.
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
	// the last emitted line, so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per UNAVAILABILITY episode: one page when
	// the control plane goes persistently unreachable, not one per retry.
	// Cleared by an observed bind, so a second incident pages again.
	alerted bool
}

var cpGRPCListener cpGRPCListenerHealth

// cpGRPCEverFailed short-circuits the success observer until the first failure,
// so a healthy bind costs one atomic load rather than a mutex acquire (the
// storageEverFailed / adminUIEverFailed pattern). A bind happens once per
// process in the healthy case, so this is not a hot path — but the fault plane
// must not tax the healthy one.
var cpGRPCEverFailed atomic.Bool

// cpGRPCListenerSnapshot is the lock-free view handed to the reporting surfaces.
type cpGRPCListenerSnapshot struct {
	Configured  bool
	Addr        string
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
	ServeExits  int64
	FailingFor  time.Duration
}

// fireCPGRPCListenerAlert delivers the `cp_grpc_listener_down` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// fireStorageWriteAlert documents: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
var fireCPGRPCListenerAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("cp_grpc_listener_down") {
		return
	}
	go fireAlert("cp_grpc_listener_down", AlertPayload{
		Detail: detail,
		Source: "control_plane",
	})
}

// errCPGRPCCredentials tags a failure to build the operator-supplied gRPC
// credentials, so the classifier can name it without matching on the crypto/tls
// error text.
var errCPGRPCCredentials = errors.New("control plane grpc credentials")

// classifyCPGRPCListenError maps a bind/serve failure to a BOUNDED reason
// class.
//
// The socket half is classifyListenerSocketError — the ONE shared copy
// (listener_error_class.go). Only the two branches genuinely specific to this
// plane stay here: the credentials failure, and the policy refusal
// `cpServerOption` returns when neither a TLS pair nor --cluster-insecure was
// supplied. That last one is NOT an environmental fault and must not be
// retried as if a port were busy, so it gets its own class — an operator who
// forgot the certificates needs to be told that, not told the listener is
// rebinding.
func classifyCPGRPCListenError(err error) string {
	if class, ok := classifyListenerSocketError(err); ok {
		return class
	}
	switch {
	case errors.Is(err, errCPGRPCCredentials):
		return "tls_certificate"
	case errors.Is(err, errCPGRPCTLSRequired):
		return "tls_required"
	}
	if classifyListenerNetworkError(err) {
		return "network_error"
	}
	return "listen_failed"
}

// noteCPGRPCConfigured records that a Control Plane role was REQUESTED. Called
// before the first bind attempt, so a listener that fails on its very first
// try is reported against a CONFIGURED Control Plane rather than as "no
// cluster" — the CHAOS-54/66 ordering rule, which §36 had to apply a second
// time after recording it as a lesson the first.
func noteCPGRPCConfigured(addr string) {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.configured = true
	cpGRPCListener.addr = addr
	cpGRPCListener.stopped = false
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCListenFailure records one failed bind/serve attempt and returns
// whether the caller should emit a log line for it.
func noteCPGRPCListenFailure(reason string, backoff time.Duration, now time.Time) (shouldLog bool) {
	cpGRPCEverFailed.Store(true)

	cpGRPCListener.mu.Lock()

	cpGRPCListener.serving = false
	cpGRPCListener.total++
	cpGRPCListener.consecutive++
	cpGRPCListener.lastFailure = now
	cpGRPCListener.lastReason = reason
	cpGRPCListener.backoff = backoff
	if cpGRPCListener.firstFailure.IsZero() {
		cpGRPCListener.firstFailure = now
	}

	if cpGRPCListener.logAt.IsZero() || now.Sub(cpGRPCListener.logAt) >= cpGRPCListenLogInterval {
		cpGRPCListener.logAt = now
		shouldLog = true
	} else {
		cpGRPCListener.suppressed++
	}

	unavailable := now.Sub(cpGRPCListener.firstFailure) >= cpGRPCUnavailableAfter
	alertNow := unavailable && !cpGRPCListener.alerted
	if alertNow {
		cpGRPCListener.alerted = true
	}
	failures := cpGRPCListener.consecutive
	addr := cpGRPCListener.addr
	everServed := cpGRPCListener.everServed
	cpGRPCListener.mu.Unlock()

	if alertNow {
		posture := "has never bound since this node started"
		if everServed {
			posture = "has stopped serving"
		}
		// The Detail is BOUNDED (addr + duration + count + reason class) and
		// carries the one sentence an operator needs to not go looking in the
		// wrong place: the proxy is fine, the DATA PLANES are the casualty.
		fireCPGRPCListenerAlert(fmt.Sprintf(
			"Control Plane gRPC listener on %s %s for over %s (%d consecutive attempts, reason: %s); this node's PROXY data plane is UNAFFECTED and still enforcing policy, but no Data Plane can fetch config, enroll, renew a certificate or push audit events — DP nodes are running on last-known-good config and ageing. The listener rebinds automatically; no restart is required",
			addr, posture, cpGRPCUnavailableAfter, failures, reason))
	}
	return shouldLog
}

// noteCPGRPCServing records an OBSERVED successful bind and returns the number
// of log lines the rate gate suppressed during the episode that just ended
// (zero when nothing was failing).
//
// This is the only thing that clears the unavailable state. Elapsed time never
// does: a retry loop that has stopped failing because it has stopped attempting
// looks identical to a bound listener, and reporting recovery on silence is the
// mistake ca_health.go and storage_health.go both call out by name.
func noteCPGRPCServing() (suppressed int64) {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()

	cpGRPCListener.serving = true
	cpGRPCListener.everServed = true
	cpGRPCListener.stopped = false
	cpGRPCListener.binds++

	if !cpGRPCEverFailed.Load() || cpGRPCListener.consecutive == 0 {
		return 0
	}
	suppressed = cpGRPCListener.suppressed
	cpGRPCListener.consecutive = 0
	cpGRPCListener.suppressed = 0
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.backoff = 0
	cpGRPCListener.alerted = false
	cpGRPCListener.logAt = time.Time{}
	return suppressed
}

// noteCPGRPCServeExit records the serve loop returning for a reason that is NOT
// a shutdown — the silent case. It marks the listener not-serving and charges
// the dedicated counter; the caller then goes on to record a failure and rebind
// through the ordinary path, so a dead accept loop and an unbindable port reach
// the same surfaces with the same remedy.
func noteCPGRPCServeExit() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.serving = false
	cpGRPCListener.serveExits++
	cpGRPCListener.mu.Unlock()
}

// noteCPGRPCStopped records the loop exiting for SHUTDOWN. It is not a fault: a
// node being torn down must not report its control plane as failed on the way
// out, and must not alert.
func noteCPGRPCStopped() {
	cpGRPCListener.mu.Lock()
	cpGRPCListener.serving = false
	cpGRPCListener.stopped = true
	cpGRPCListener.firstFailure = time.Time{}
	cpGRPCListener.consecutive = 0
	cpGRPCListener.backoff = 0
	cpGRPCListener.alerted = false
	cpGRPCListener.mu.Unlock()
}

// cpGRPCListenerState returns a consistent copy of the listener's state.
func cpGRPCListenerState() cpGRPCListenerSnapshot {
	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
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

// resetCPGRPCHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `cpGRPCListener = cpGRPCListenerHealth{}`
// under the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex" (the CHAOS-54 note).
func resetCPGRPCHealthForTest() {
	resetCPGRPCRecoveryForTest()

	cpGRPCListener.mu.Lock()
	defer cpGRPCListener.mu.Unlock()
	cpGRPCListener.configured = false
	cpGRPCListener.addr = ""
	cpGRPCListener.serving = false
	cpGRPCListener.everServed = false
	cpGRPCListener.stopped = false
	cpGRPCListener.serveExits = 0
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

// cpGRPCListenerStatus is the /health posture string for the CP gRPC listener,
// served on the PROXY port — the surface that survives the fault the field
// describes, because the gRPC port cannot report that it is unreachable.
//
// A FIXED five-value enum, deliberately, because handleHealth serves this
// UNAUTHENTICATED. It is the same granularity the socks5 and admin_ui fields
// publish. What stays off the public surface is the RESOLUTION: the attempt
// count and the reason class (which would name, for instance, descriptor
// exhaustion) live only on the role-gated /api/diagnostics row, the alert and
// the logs.
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

// checkCPGRPCListener is the `cp_grpc_listener` operator-contract row.
//
// Severity policy, mirroring checkAdminUIListener's:
//   - not configured → ok. No Control Plane was requested (a standalone proxy
//     or a Data Plane node).
//   - stopped → ok. The loop exited because the node is shutting down.
//   - unavailable → FAIL. A control plane no Data Plane has been able to reach
//     for longer than the threshold is a real, operator-actionable fault: the
//     fleet is running on ageing last-known-good config, enrollments and
//     certificate renewals cannot complete, and the centralized audit trail is
//     accumulating a gap.
//   - failing but under the threshold → warn. Still retrying, and a draining
//     predecessor clears on its own within seconds; failing here would report a
//     self-healing handover as broken.
//   - serving → ok, carrying the cumulative failure and serve-exit counts so a
//     HISTORY of transient faults stays visible after recovery. A non-zero
//     serve-exit count on an otherwise healthy row is exactly the evidence
//     that was missing before this plane existed.
func checkCPGRPCListener() OperatorContractCheck {
	snap := cpGRPCListenerState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "cp_grpc_listener",
			Status:  diagOK,
			Message: "Control Plane gRPC not configured (not a Control Plane node)",
		}
	}
	if snap.Stopped {
		return OperatorContractCheck{
			Code:    "cp_grpc_listener",
			Status:  diagOK,
			Message: "Control Plane gRPC listener stopped (node shutting down)",
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
			Message: fmt.Sprintf("Control Plane gRPC on %s %s and has been unusable for %s (%d consecutive attempts, reason: %s); no Data Plane can fetch config, enroll, renew a certificate or push audit events",
				snap.Addr, posture, snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason),
			OperatorAction: cpGRPCListenRemedy(snap.LastReason),
		}
	}
	if snap.Failing {
		return OperatorContractCheck{
			Code:   "cp_grpc_listener",
			Status: diagWarn,
			Message: fmt.Sprintf("Control Plane gRPC on %s is not currently serving (%d consecutive attempts, reason: %s); retrying with backoff",
				snap.Addr, snap.Consecutive, snap.LastReason),
			OperatorAction: "No action yet — the listener retries automatically and this usually clears within seconds of a restart. Data Planes continue on last-known-good config meanwhile. If it persists it is raised to a failure.",
		}
	}
	if snap.Total > 0 || snap.ServeExits > 0 {
		return OperatorContractCheck{
			Code:   "cp_grpc_listener",
			Status: diagOK,
			Message: fmt.Sprintf("Control Plane gRPC serving on %s (%d transient listen failures, %d serve-loop exits since startup)",
				snap.Addr, snap.Total, snap.ServeExits),
		}
	}
	return OperatorContractCheck{
		Code:    "cp_grpc_listener",
		Status:  diagOK,
		Message: fmt.Sprintf("Control Plane gRPC serving on %s", snap.Addr),
	}
}

// cpGRPCListenRemedy selects the operator action for a reason CLASS.
//
// §36's third review round found the inverse of this defect and the lesson
// transfers directly: *"a bounded classifier is worth nothing if one remedy is
// printed for every class"* — a node out of descriptors or with an interface
// not yet up was sent to hunt the owner of a port nobody holds. Two clauses are
// invariant in every branch, because both are true in every branch and both are
// what stops an operator reaching for the wrong lever: the listener rebinds by
// itself, and the proxy data plane is unaffected.
//
// `tls_required` is the one class whose remedy is NOT environmental: nothing
// will change on its own, because the configuration never asked for a usable
// listener. Saying "it rebinds automatically" there would be true and useless.
func cpGRPCListenRemedy(reason string) string {
	const tail = " The listener rebinds automatically once the fault clears — no restart is required, and the proxy data plane is unaffected and still enforcing policy."
	switch reason {
	case "port_in_use":
		return "Another process holds the Control Plane gRPC port. Find it (ss -lptn / lsof -i) and stop it, or move Culvert's listener with -cp-grpc-addr. A predecessor container still draining clears on its own." + tail
	case "permission_denied":
		return "The process may not bind this port — typically a privileged port (<1024) on a deployment that is not root and does not hold CAP_NET_BIND_SERVICE. Grant the capability or choose a port above 1024 with -cp-grpc-addr." + tail
	case "address_unavailable":
		return "The configured address does not exist on this host yet — an interface that is not up, or an IP this node does not own. Check -cp-grpc-addr against the host's actual addresses; binding :PORT (all interfaces) avoids it." + tail
	case "descriptors_exhausted":
		return "This process is out of file descriptors, so it cannot create the listening socket. Raise the limit (LimitNOFILE / ulimit -n) and look for a descriptor leak — the process log records what exhausted them." + tail
	case "tls_certificate":
		return "The -cp-grpc-cert/-cp-grpc-key pair could not be loaded. Check that both files exist, are readable by this process and contain valid PEM; a certificate rotation that briefly truncates them self-heals, because the pair is re-read on every attempt." + tail
	case "tls_required":
		return "No Control Plane TLS material was configured and --cluster-insecure was not set, so the listener has nothing to serve and will NOT recover on its own. Supply -cp-grpc-cert/-cp-grpc-key (production), or set --cluster-insecure for development only. The proxy data plane is unaffected and still enforcing policy."
	default:
		return "The full error is in the process log, on the line naming this reason class." + tail
	}
}

// appendCPGRPCReadinessCheck adds the report-only `cp_grpc` row to /ready on
// the PROXY port.
//
// REPORT-ONLY, like `ca`, `cluster_ca`, `socks5` and `admin_ui`, and the
// reasoning is §33's verbatim: a node whose CP gRPC listener cannot bind is
// proxying traffic perfectly. Gating the default readiness verdict on it would
// pull a fully-functional gateway out of the load balancer because of a fault
// in a plane that has nothing to do with serving traffic — converting a
// cluster-control outage into the traffic outage this change exists to prevent.
// An operator who does want such nodes ejected opts in via /ready?strict=1.
//
// Absent entirely on a node that is not a Control Plane, so a standalone proxy
// never grows a permanently-green row.
//
// The detail is a FIXED string per branch. /ready is served UNAUTHENTICATED on
// the proxy port, so the attempt count and reason class — which would tell an
// unauthenticated caller on the network that this node's control plane is down
// and why — stay on the role-gated row, the alert and the logs.
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
