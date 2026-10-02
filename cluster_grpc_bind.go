package main

// cluster_grpc_bind.go — CHAOS-71: the Control Plane's gRPC BIND, and which
// plane is allowed to kill which.
//
// Why this file exists.
//
// `startControlPlaneWithHAResume` (cluster_startup.go) activated the cluster
// control plane with exactly one error branch:
//
//	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err != nil {
//	        logFatalf("ControlPlane gRPC: %v", err)   // ← os.Exit(1)
//	}
//
// So EVERY way the cluster gRPC listener could fail to come up terminated the
// whole appliance — and it did so from `initCluster`, which main.go runs at
// line 228 of the init block, BEFORE `initRootCA`, `initPolicy`,
// `initURLCategories`, `initScanning`, `initSOCKS5`, `startAdminUI` and
// `buildAndStartProxyServer`. The HTTP/HTTPS proxy, the admin UI, the SOCKS5
// listener and every health endpoint therefore never start at all.
//
// This is §33 (CHAOS-57, the admin UI listener) and §36 (CHAOS-66, the SOCKS5
// bind) a third time, on the plane §36 named as "the closest unexamined
// analogue" when it closed the second one. It is the sharpest instance of the
// family so far for one reason that has nothing to do with blast radius:
//
//	THE RULE ALREADY EXISTED ON TWO OF THE THREE CALL SITES OF THE SAME
//	FUNCTION, AND THE ONE THAT LACKED IT IS THE ONE THAT RUNS UNATTENDED.
//
// `enableControlPlane` has exactly three callers. The admin API
// (`ui_cluster.go` — `POST /api/cluster/mode`) RETURNS the error to
// the operator. The HA promote callback (`cluster_startup.go` → `ha.go`'s
// `promote`) is panic-contained under CHAOS-25 and resets its idempotency guard
// on failure *"so a later attempt can retry"*. Only the BOOT path exited the
// process. That asymmetry — not the individual handler — is the finding, and it
// is the same shape §30 (CHAOS-61) recorded for the cluster rate limiter, where
// the CP pruned stale peer counts and the DP did not: the rule was written on
// one side of the link and not the other, and the side that lacked it is the
// one that decides live behaviour.
//
// Reproduced against the real binary, not reasoned about.
//
//	# (1) an occupied gRPC port — the ordinary redeploy / host-service case
//	$ ./culvert -port 18080 -ui-port 19090 -cp-grpc-addr 127.0.0.1:50051 -cluster-insecure
//	ControlPlane gRPC: gRPC listen: listen tcp 127.0.0.1:50051: bind: address already in use
//	EXIT=1
//	proxy http_code=000          ← the HTTP proxy port never listened
//	admin UI log lines: 0        ← startAdminUI never ran
//
//	# (2) an mTLS pair caught mid-rotation — needs no port collision at all
//	$ ./culvert -port 18081 -ui-port 19091 -cp-grpc-addr 127.0.0.1:50052 \
//	      -cp-grpc-cert cp.crt -cp-grpc-key cp.key      # momentarily empty
//	ControlPlane gRPC: gRPC TLS: tls: failed to find any PEM data in certificate input
//	EXIT=1
//	ui http_code=000
//
// None of the triggers is exotic, and none is visible to the one check that
// looks like it should catch them: `validatePortCollisions` (main.go) compares
// Culvert's own proxy / UI / SOCKS5 ports to EACH OTHER only — the cluster gRPC
// port is not even in its list, so it cannot see a host service, a predecessor
// container still draining, a second Culvert, or a collision with Culvert's own
// proxy port.
//
//   - EADDRINUSE: a predecessor container draining, a host-network service, an
//     operator collision, a second instance.
//   - EACCES/EPERM: a privileged gRPC port on a deployment that dropped
//     CAP_NET_BIND_SERVICE or stopped running as root.
//   - EADDRNOTAVAIL: binding before the interface the address lives on is up —
//     an ordinary host-boot race, and a CP is usually bound to a specific
//     address rather than the wildcard, which makes this MORE likely here than
//     for the other three listeners.
//   - the mTLS pair unreadable or momentarily truncated: certbot / cert-manager
//     / a Docker secret mid-rotation. `cpServerOption` loads the pair at bind
//     time, so a rotation window is a boot that ends in exit 1.
//
// Under `restart: unless-stopped` each is an unattended CRASH LOOP: no proxy,
// no admin UI, no `/health`, no `/ready`, recoverable only with shell access.
//
// And "it exits, so it fails closed" is wrong here for the reason §33 states
// and this file must not re-argue: process death picks NO posture, it delegates
// the choice to the topology. An explicit-proxy fleet loses all egress; a
// PAC/WPAD fleet with a `DIRECT` fallback, or a transparent deployment that
// bypasses a dead next hop, goes UNFILTERED.
//
// There is a second argument specific to this plane, and it is the stronger
// one. A Control Plane whose gRPC is not serving is, from the fleet's point of
// view, EXACTLY a Control Plane that is unreachable — and that is a state the
// Data Plane side is already built to survive: `pollConfig` fails and backs
// off, the `cp_poll` readiness row reports it, the CP-link alert fires, and
// every DP keeps enforcing its last-known config (HA-1's documented
// config-staleness posture). Killing the process converts a degradation the
// fleet already tolerates into a TOTAL EGRESS OUTAGE for this node's own
// clients, plus the loss of the only surface on which an operator could see or
// fix it.
//
// ─────────────────────────────────────────────────────────────────────────────
//
// Seven rules. Six are borrowed wholesale from CHAOS-54/55/57/66 rather than
// invented as a fourth dialect. Rule 3 is this sweep's own, and it is the one
// that keeps the fix from being worse than the defect.
//
//  1. No bind path is fatal. `startControlPlaneSupervised` always returns.
//
//  2. Retry is RATE-bounded, never COUNT-bounded. The terminal state of "give
//     up" is a fleet that never gets config again until someone restarts the
//     appliance — the outcome this change exists to remove. "Avoid infinite
//     retries" is satisfied the CHAOS-54/55 way: the retry is never SILENT
//     (onset logged immediately, then ≤1 line per 60 s, then a recovery line
//     naming the suppressed count; magnitude in a counter).
//
//  3. ROLE AND LEADERSHIP ARE ASSERTED ONLY ON AN OBSERVED BIND.
//
//     This is the rule the naive fix gets wrong, and getting it wrong would
//     introduce a SPLIT BRAIN inside the change that removes an outage. If a
//     node that cannot bind were allowed to continue to `clusterRole.role =
//     "control-plane"` and `globalHA.ResumeAsLeader`, it would hold the leader
//     role, report `role: leader` on /healthz and in the HA panel, and serve no
//     gRPC at all — a black hole for config distribution. Its standby cannot
//     reach it, so in legacy ADR-0004 mode (no etcd fence) auto-failover
//     promotes the standby too, and BOTH nodes claim leadership. Today the
//     fatal happens to prevent that, so the exit is load-bearing for a reason
//     that has nothing to do with why it was written.
//
//     Staying `standalone` until a listener actually binds gives the CLUSTER
//     byte-identical semantics to the current fatal — the standby promotes
//     exactly as it does when the leader is dead — while this node keeps
//     proxying and keeps its admin UI. The cost is that leadership is taken
//     late rather than never; in lease mode the etcd fence arbitrates that,
//     and in legacy mode it is the ordinary restarted-leader path the code
//     already prints an ADR-0004/RISK-001 warning for on every boot.
//
//  4. The FIRST attempt is resolved SYNCHRONOUSLY before `loadCluster`
//     continues. Without it `configured` is true while the supervisor
//     goroutine has not run yet, and in that window every surface describes a
//     Control Plane that does not exist. That is the same class of lie this
//     change exists to remove, so reporting the window accurately (a "pending"
//     state) would be the weaker fix: better not to have the window. The wait
//     is bounded by ONE `bind(2)`, which does not block, and it is the
//     pre-CHAOS-71 behaviour — only the fatal is gone.
//
//  5. THE DEFERRED COMPLETION RE-READS THE HA DECISION instead of using the
//     boot snapshot. Non-obvious, and load-bearing precisely BECAUSE of this
//     fix: making the admin UI reachable during the retry window is the whole
//     point, so an operator can now change this node's HA posture while it is
//     still retrying. Completing against a stale boot snapshot would assert a
//     leadership the operator has since revoked — the fix handing back a
//     different version of the hazard rule 3 closes.
//
//  6. Reason classes are BOUNDED and matched with `errors.As` on
//     `syscall.Errno`, never by string. The raw error reaches the rate-limited
//     log and nowhere else: an unbounded reason gives the alert dedup key one
//     value per failure (the WK-12/RS-5 defect) and would put the listener
//     address on a viewer-role surface.
//
//  7. The one-time PRE-BIND work runs ONCE, not per attempt. `enableControlPlane`
//     arms the durable config-version floor, publishes an initial config
//     snapshot and initialises the cluster CA before it binds; re-running that
//     per retry would emit a `config vN published` line and a `ClusterCA:
//     loaded` line on EVERY attempt — exactly the log flood rule 2's rate
//     limiting exists to prevent — and would write the version floor once per
//     attempt for no benefit.
//
// Deliberately NOT changed: `runProxyUntilShutdown`'s `logFatalf("Proxy error")`
// stays correct for §33's reason — the proxy IS the product, and a gateway that
// cannot serve must exit loudly rather than linger as a black hole. The
// asymmetry is the whole point of this family of changes: an auxiliary plane
// degrades, the primary one does not.

import (
	"context"
	"errors"
	"sync"
	"time"
)

// errCPGRPCRoleTaken is returned when the node's cluster role moved to
// something other than standalone or control-plane while the supervisor was
// retrying — today only a completed Data Plane enrollment. It is a retryable
// error rather than a terminal one because the role can move back.
var errCPGRPCRoleTaken = errors.New("cluster role already taken by another plane")

// errCPGRPCNoAddress guards the one precondition that can never clear by
// retrying. It is still non-fatal: the supervisor is only armed when cpMode()
// was true, so an empty address here means a config shape the resolver should
// have refused, and reporting it on every surface beats exiting.
var errCPGRPCNoAddress = errors.New("control-plane gRPC listen address is empty")

// cpPrepareFn is the prepare seam. Package-level so a gate can COUNT the
// one-time pre-bind work across retries instead of reading the supervisor's
// private flag — which is written only by the supervisor goroutine and would be
// a data race to observe from a test. It is also what lets a gate assert the
// prepare runs with clusterRoleMu NOT held, which is the invariant that stops
// prepareControlPlane deadlocking (see attempt's header).
var cpPrepareFn = prepareControlPlane

// cpGRPCSupervisor owns the Control Plane gRPC listener's whole lifecycle:
// attempt the bind, assert the role and leadership on success, and retry on
// failure.
//
// It is deliberately a SEPARATE type rather than a retry loop bolted inside
// `enableControlPlane`: that function is also the admin API's and the HA
// promote path's entry point, and both already have correct non-fatal
// behaviour (see the file header). Keeping it byte-identical in those two
// directions is what lets this change add a lifecycle without disturbing the
// semantics their tests pin.
type cpGRPCSupervisor struct {
	cfg clusterStartupConfig
	ctx context.Context

	// stopping is closed by Stop BEFORE anything else, so a backoff sleep is
	// interruptible and an attempt in flight is not completed. stopOnce keeps
	// Stop idempotent: closing a closed channel panics.
	stopping chan struct{}
	stopOnce sync.Once

	// done is closed when the supervisor loop exits.
	done chan struct{}

	// firstAttempt is closed once the loop has RESOLVED its first bind attempt,
	// one way or the other (rule 4).
	firstAttempt chan struct{}
	firstOnce    sync.Once

	// prepared records that the one-time pre-bind work has run, so a retry
	// attempts only the part that can fail transiently (rule 7).
	//
	// Needs no lock: it is written and read ONLY by the single supervisor
	// goroutine (`run` → `attempt`). It is deliberately NOT guarded by
	// clusterRoleMu, because the work it gates must run with that lock RELEASED
	// — see attempt's header.
	prepared bool
}

// startControlPlaneSupervised is the boot path's entry point for Control Plane
// activation. It NEVER exits the process: see the file header for the finding
// this replaces.
//
// Returns the supervisor so the shutdown sequence can interrupt it. A nil
// return is impossible; the handle is always live.
func startControlPlaneSupervised(cfg clusterStartupConfig, ctx context.Context) *cpGRPCSupervisor {
	s := &cpGRPCSupervisor{
		cfg:          cfg,
		ctx:          ctx,
		stopping:     make(chan struct{}),
		done:         make(chan struct{}),
		firstAttempt: make(chan struct{}),
	}

	// Recorded as configured BEFORE the first attempt, not after a successful
	// one. `noteCPGRPCConfigured` gates every surface in cluster_grpc_health.go,
	// so recording it after the bind would report a Control Plane whose
	// listener has NEVER come up as "not a Control Plane" — indistinguishable
	// from the ordinary standalone appliance, on exactly the node where an
	// operator is trying to find out why the fleet stopped syncing. CHAOS-66
	// moved the equivalent SOCKS5 call for the same reason.
	noteCPGRPCConfigured(cfg.CPAddr)

	go s.run()

	// Rule 4: do not return while every surface still describes a listener that
	// does not exist. `run` closes the channel from a DEFERRED call as well as
	// after each attempt, so a panic before the first attempt cannot hang
	// startup.
	<-s.firstAttempt
	return s
}

// markFirstAttempt releases startControlPlaneSupervised once the first attempt
// has resolved. Idempotent; safe from both the loop and its deferred guard.
func (s *cpGRPCSupervisor) markFirstAttempt() {
	s.firstOnce.Do(func() { close(s.firstAttempt) })
}

// Stop interrupts the supervisor and waits for its loop to exit, bounded by
// ctx. Nil-safe and idempotent.
//
// It does NOT stop the gRPC server itself — `StopControlPlaneGRPC` owns that,
// and runs immediately after this in the same shutdown hook so the drain's
// CHAOS-56 budget is unchanged. The split is deliberate: this call only
// guarantees that no NEW listener will be bound while the node is shutting
// down, which is the one thing the drain cannot do for itself.
func (s *cpGRPCSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stopping) })
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopRequested reports whether Stop has been called.
func (s *cpGRPCSupervisor) stopRequested() bool {
	select {
	case <-s.stopping:
		return true
	default:
		return false
	}
}

// run is the attempt/backoff/retry loop.
//
// The panic guard mirrors the other listener supervisors' rather than using the
// bare recoverGoroutine: a panic here would otherwise leave the cluster control
// plane permanently gone with every surface still green, which is the CHAOS-24
// objection to recovering at the top of a worker goroutine. Reporting the
// listener unavailable — fail row, alert, gauge at zero — is the loudest state
// this subsystem can produce, so recovering is safe in the direction that
// matters.
func (s *cpGRPCSupervisor) run() {
	defer close(s.done)
	// Runs AFTER the recover below (defers are LIFO), so
	// startControlPlaneSupervised is released on every exit path including a
	// panic.
	defer s.markFirstAttempt()
	defer func() {
		if v := recover(); v != nil {
			recordCrash("control-plane-grpc-bind", "", v)
			// A contained panic here IS terminal — nothing rebinds — so the
			// state recorded must not promise an automatic recovery. This is
			// CHAOS-66's round-2 lesson: a blanket "retrying" message sends an
			// operator away from the one restart that IS needed.
			noteCPGRPCBindFailure("supervisor_panicked", 0, cpGRPCHealthNow())
			logErrorf("ControlPlane: gRPC listener supervisor panicked — the cluster control plane is " +
				"unavailable until this node is restarted. This node's proxy data plane and admin UI are unaffected.")
		}
	}()

	// The backoff is deliberately NEVER reset inside the loop, exactly as
	// serveAdminUIWithRetry and the SOCKS5 supervisor do it. Resetting on every
	// successful bind would let a socket that dies immediately after each bind
	// settle into a steady one-bind-per-floor cadence forever; letting it
	// escalate monotonically to the ceiling bounds that pathological case at
	// one attempt per 30 s.
	backoff := cpGRPCBindBackoffInitial

	for {
		if s.stopRequested() {
			noteCPGRPCStopped()
			return
		}

		err := s.attempt()
		if err == nil {
			// Bound, role asserted, leadership resolved. The listener's own
			// serve loop is owned by grpc-go from here; there is no serve-ended
			// signal to wait on, and a transport-level failure surfaces to the
			// DP side as an unreachable CP, which it already handles. Nothing
			// left for this loop to do.
			s.markFirstAttempt()
			return
		}

		reason := classifyCPGRPCBindError(err)
		shouldLog, failingFor := noteCPGRPCBindFailure(reason, backoff, cpGRPCHealthNow())
		// Released only AFTER the failure is recorded:
		// startControlPlaneSupervised may return the moment this fires, and it
		// must never return to a state that has not been written yet — that is
		// the rule-4 window in miniature.
		s.markFirstAttempt()

		// Clamped so this sleep cannot carry us past the unavailability
		// threshold without an attempt to observe it — the alert is
		// attempt-driven and nothing else wakes this loop.
		wait := clampCPGRPCBindSleep(jitterDuration(backoff, cpGRPCBindJitter), failingFor)
		if shouldLog {
			// The FULL error goes here and nowhere else: the contract row, the
			// alert and the readiness detail all carry the bounded class only.
			// logErrorf applies sanitizeLog (CWE-117) to the whole line.
			logErrorf("ControlPlane: gRPC listener on %s could not start (%s): %v — retrying in %s. "+
				"This node is NOT acting as a Control Plane until it binds, so a standby is free to lead. "+
				"The proxy data plane and the admin UI are unaffected, and Data Planes keep enforcing their last-known config.",
				s.cfg.CPAddr, reason, err, wait.Round(time.Millisecond))
		}
		if !haSleepInterruptible(s.stopping, wait) {
			noteCPGRPCStopped()
			return
		}
		backoff = nextCPGRPCBindBackoff(backoff)
	}
}

// attempt runs one activation attempt.
//
// ████ THE LOCK DISCIPLINE HERE IS NOT INCIDENTAL. ████
//
// The first version of this function held `clusterRoleMu` across the WHOLE
// attempt, on the reasoning that the role transition, the gRPC handle and the
// leadership assertion must not interleave with the admin API's own enable or
// with DP enrollment. That shape DEADLOCKS, and it deadlocks on code this sweep
// did not write: the pre-bind work calls `CurrentConfigSnapshot()`, which reads
// the cluster role BACK through `buildCPAddressList`'s `clusterRoleMu.RLock()`,
// and `sync.RWMutex` is not reentrant. See prepareControlPlane (main.go) for
// the full account — including that the same defect was already latent in
// `enableControlPlane` and CERTAIN on the HA promote path, which this sweep's
// own gate is what found.
//
// So the attempt is three phases, and only the middle one holds the write lock:
//
//  1. a cheap precondition READ (short RLock),
//  2. the one-time prepare with NO lock held,
//  3. bind + role commit under the write lock, re-checking the preconditions
//     so the check-then-act gap phase 1 opens is closed.
//
// Leadership is resolved AFTER the lock is released, which is also required
// rather than tidy: `ResumeAsLeader` can perform an etcd lease acquisition with
// network round trips (ADR-0005), and holding the cluster-role write lock
// across that would block every reader of the role for the resume budget. It is
// also exactly what the pre-CHAOS-71 boot path did — `enableControlPlane`
// returned, releasing the lock, and leadership followed — so this preserves the
// original ordering rather than inventing one.
func (s *cpGRPCSupervisor) attempt() error {
	// Phase 1 — preconditions, and the role check that is this supervisor's own.
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()

	// Someone else got there first — the admin API's enable endpoint is
	// reachable during the retry window, which is precisely the point of this
	// change. Treat it as success and stop retrying.
	if role == "control-plane" {
		noteCPGRPCBound()
		noteCPGRPCRoleAsserted()
		return nil
	}
	// The role moved to something that is not ours to overwrite (a DP
	// enrollment completed while we were retrying). Refuse rather than stomping
	// it: a node silently switching from data-plane back to control-plane is a
	// worse surprise than a cluster listener that stays down and says so.
	if role != "standalone" {
		return errCPGRPCRoleTaken
	}
	if s.cfg.CPAddr == "" {
		return errCPGRPCNoAddress
	}

	// Phase 2 — rule 7: the one-time pre-bind work, once, with NO lock held.
	// A failed attempt still counts as prepared: the work is idempotent and its
	// failure modes are logged in place, so re-running it per retry is the log
	// flood rule 7 exists to prevent.
	if !s.prepared {
		s.prepared = true
		cpPrepareFn(s.cfg.ClusterDBPath)
	}

	// Phase 3 — bind and commit the role, re-checking under the write lock.
	if err := func() error {
		clusterRoleMu.Lock()
		defer clusterRoleMu.Unlock()
		if clusterRole.role != "standalone" && clusterRole.role != "control-plane" {
			return errCPGRPCRoleTaken
		}
		return activateControlPlaneLocked(s.cfg.CPAddr, s.cfg.CPCert, s.cfg.CPKey, s.cfg.CPCA, "startup")
	}(); err != nil {
		return err
	}

	suppressed, recovered := noteCPGRPCBound()
	noteCPGRPCRoleAsserted()
	if recovered {
		logger.Printf("ControlPlane: gRPC listener on %s is serving again (%d suppressed bind-failure log line(s))",
			s.cfg.CPAddr, suppressed)
	}

	// Rule 3 + rule 5: leadership is resolved only now, against the CURRENT
	// persisted HA state rather than a boot snapshot, and with the role lock
	// released (see the header).
	completeCPLeadership(s.cfg, s.ctx, recovered)
	return nil
}
