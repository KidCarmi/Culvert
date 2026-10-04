package main

// cluster_grpc_bind.go — CHAOS-71: the Control Plane's gRPC listener BIND, and
// which plane is allowed to kill which.
//
// Why this file exists.
//
// `startControlPlaneWithHAResume` (cluster_startup.go) bound the Control Plane
// gRPC listener with exactly one error branch:
//
//	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err != nil {
//	        logFatalf("ControlPlane gRPC: %v", err)   // ← os.Exit(1)
//	}
//
// So EVERY way the Control Plane's gRPC listener could fail to come up
// terminated the whole appliance. It did so from `initCluster`, which main.go
// runs at line 228 — **before `startAdminUI` (269) and
// `buildAndStartProxyServer` (271)** — so the HTTP/HTTPS proxy, the admin UI
// and the health endpoints never started at all.
//
// This is §33 (CHAOS-57, the admin UI listener) and §36 (CHAOS-66, the SOCKS5
// bind) a third time, and CHAOS-66's own closing note names this path as the
// remaining unexamined analogue. It lands with the same force as §33: a
// MANAGEMENT plane killing the DATA plane. The Control Plane is the fleet's
// configuration-distribution service — it is the plane an operator manages
// enforcement FROM — and its listener failing took down the enforcement plane
// this node was serving, plus the admin UI, plus every health surface.
//
// Three triggers, all reproduced against the real binary, none of them exotic:
//
//  1. **The gRPC port is occupied.** `-cp-grpc-addr :19443` already bound — a
//     predecessor container still draining, a host-network service, a second
//     Culvert. Observed, verbatim:
//
//     WARN ControlPlane: gRPC :19443 (insecure — all cluster data unencrypted!)
//     ControlPlane gRPC: gRPC listen: listen tcp :19443: bind: address already in use
//     → exit 1,  proxy http_code=000,  admin UI http_code=000
//
//     Note the ORDER: the listener was announced before it existed. That is
//     §33's rule (6) — the success log must sit strictly downstream of the
//     evidence — broken here in the same way, and fixed in the same commit.
//
//  2. **The mTLS material cannot be loaded.** `cpServerOption` →
//     `buildServerTLS` calls `tls.LoadX509KeyPair` at call time, so a
//     certbot / cert-manager / Docker-secret rotation that briefly truncates
//     or re-permissions the pair is a boot that ends in exit 1. Observed:
//
//     ControlPlane gRPC: gRPC TLS: tls: failed to find any PEM data in key input
//     → exit 1,  proxy http_code=000
//
//  3. **A privileged port, or an interface that is not up yet** —
//     `permission_denied` on a deployment that dropped CAP_NET_BIND_SERVICE or
//     stopped running as root, `address_unavailable` when the bind races the
//     host finishing its boot.
//
// Under `restart: unless-stopped` (docker-compose.yml) each is an unattended
// CRASH LOOP recoverable only with shell access.
//
// **"It exits, so it fails closed" is wrong and must not be re-argued.** This
// is §33's rule: process death picks NO posture, it delegates the choice to
// the topology. An explicit-proxy fleet loses all egress; a PAC/WPAD fleet
// with a `DIRECT` fallback, or a transparent deployment, goes UNFILTERED. And
// the DP consequence of degrading is the one the register ALREADY documents as
// deliberate (HA-1: a partitioned DP enforces last-good policy) — which is
// also exactly what process death produces, minus this node's own proxy, minus
// the admin UI, and minus any way to see or fix it.
//
// **The decisive evidence is that the codebase had already made this call for
// this very function, from two other callers.** `enableControlPlane` has three
// callers and they disagreed:
//
//   - `apiClusterEnableCP` (ui_cluster.go:98) — returns `409 Conflict`.
//   - `HAState.promote` (ha.go:923) — logs "staying as standby", resets the
//     once-guard, stays retryable. CHAOS-25 even CONTAINS a panic there, with
//     the reasoning spelled out: "a panic in it is operationally identical to
//     the error it already handles: the node did not become a leader. Treat it
//     that way ... rather than letting it kill an in-line gateway."
//   - the BOOT path (cluster_startup.go:95) — `logFatalf`.
//
// One fault, three callers, two postures. The argument for the right one was
// already written, twenty lines away, for the same failure of the same
// function — the asymmetry is the finding, the same way §40 (CHAOS-70) found
// `apiSetupComplete`'s durability rule applied to one path and not its
// siblings.
//
// Four rules now hold, borrowing the mechanism wholesale from §33/§36 rather
// than inventing a second dialect:
//
//  1. **No bind path is fatal.** The first attempt stays SYNCHRONOUS — one
//     non-blocking `bind(2)` plus a file read, exactly the pre-change boot
//     cost — so there is no window in which the surfaces describe a listener
//     that has not been attempted yet (§36's conclusion: REMOVE the window,
//     do not report it). Only on failure is a background supervisor armed, and
//     it never blocks boot: `initCluster` runs ahead of the proxy listener, so
//     time spent here is time the DATA plane is not serving — CHAOS-55's
//     `haResumeUnreachableWait` reasoning.
//
//  2. **Retry is RATE-bounded, never COUNT-bounded.** "Avoid infinite retries"
//     is satisfied the CHAOS-54/55/57 way: the retry is never SILENT. The
//     terminal state of "give up" is a Control Plane that will not return
//     without a restart, which is the outcome being removed.
//
//  3. **Recovery is declared on OBSERVED evidence only** — a listener that
//     actually bound. Elapsed time never clears the state: a supervisor that
//     stopped failing because it stopped attempting looks identical to a bound
//     one (the `ca_health.go` / `storage_health.go` rule).
//
//  4. **The one-time CP prelude must not run per attempt.** This is the half
//     that is specific to THIS listener and is where a careless fix does real
//     damage. `enableControlPlane`'s prelude calls
//     `globalConfigStore.Update(CurrentConfigSnapshot())`, and `Update`
//     INCREMENTS and PERSISTS the durable config-version floor
//     (`persistVersionLocked`) and runs an O(N) blocklist delta over up to 2 M
//     hosts. That was harmless while a bind failure was fatal — it ran once —
//     and is NOT harmless now the bind is retried: a 10-minute rotation
//     outage would ratchet the floor by one per attempt, rebuild the whole
//     snapshot per attempt, and emit a "config vN published" line per attempt,
//     for a listener no DP can reach. A mitigation for a crash loop must not
//     itself be a churn loop (the CHAOS-63/69 rule). `main.go` guards the
//     prelude with `cpPreludeDone`.
//
// Surfaces, all reusing existing operator vocabulary — see
// cluster_grpc_health.go.
//
// DELIBERATELY NOT CHANGED, and recorded rather than silently inherited:
//
//   - **HA role semantics are byte-identical.** A node whose listener is down
//     still runs the ADR-0004 resume exactly as before. In lease mode the
//     fence arbitrates, so nothing is weakened; in legacy auto-failover mode a
//     reachable-but-unservable leader is the partition case RISK-001 already
//     documents and the resume path already warns about. Changing it would be
//     a posture decision inside a resilience fix.
//   - **`StartControlPlaneGRPC`'s `srv.Serve(ln)` ending is NOT rebound** —
//     only recorded (`noteCPGRPCServeEnded`), so the surfaces stop reporting a
//     healthy CP with no listener. Owning the full bind→serve→rebind lifecycle
//     the way socks5_bind.go does would restructure `clusterRole.grpcSrv` and
//     `StopControlPlaneGRPC`, which CHAOS-56's 17 shutdown gates pin. Register
//     row CL-21.
//   - **`runProxyUntilShutdown`'s `logFatalf("Proxy error")` stays correct** —
//     the proxy IS the product, and a gateway that cannot serve must exit
//     loudly rather than linger as a black hole. That asymmetry is the whole
//     finding.

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	// cpGRPCBindBackoffInitial / cpGRPCBindBackoffMax bound the RATE of rebind
	// attempts, never their COUNT (rule 2 in the header).
	//
	// Both mirror adminUIListenBackoff* and socks5BindBackoff* because it is
	// the same fault class on the same kind of socket: a port frees when a
	// predecessor finishes draining and a certificate reappears when a
	// rotation completes, both measured in seconds, so the floor is 1 s rather
	// than an accept loop's milliseconds. The ceiling is 30 s so a self-healed
	// fault is picked up within half a minute without hammering the bind.
	cpGRPCBindBackoffInitial = 1 * time.Second
	cpGRPCBindBackoffMax     = 30 * time.Second

	// cpGRPCBindJitter spreads the backoff by ±20%. A fleet restarts together
	// — a compose `up`, a rolling reboot — and an unjittered cadence would aim
	// a synchronised herd of rebind attempts at the same instant (the WK-13
	// shape). Matches adminUIListenJitter / socks5BindJitter.
	cpGRPCBindJitter = 0.20

	// cpGRPCBindLogInterval rate-limits the bind-failure log line: the FIRST
	// failure of an episode is always logged (the operator must see the onset),
	// then one line per interval, then one recovery line carrying the
	// suppressed count. The log carries the SIGNAL, the counter the MAGNITUDE.
	cpGRPCBindLogInterval = 60 * time.Second

	// cpGRPCBindUnavailableAfter is how long the listener must be continuously
	// unbindable before it is reported UNAVAILABLE (fail row, alert, gauge at
	// zero) rather than merely retrying.
	//
	// Unavailability is a DURATION, not a count — the CHAOS-54/57/66 rule. An
	// ordinary redeploy in which a predecessor still holds the port clears in
	// a few seconds, and paging on that would page on every deploy.
	cpGRPCBindUnavailableAfter = 30 * time.Second

	// cpGRPCBindClampFloor is the shortest sleep clampCPGRPCBindSleep will
	// produce, so the one attempt it schedules to observe the unavailability
	// threshold cannot degenerate into a near-zero spin.
	cpGRPCBindClampFloor = 100 * time.Millisecond
)

// cpGRPCSupervisor retries the Control Plane gRPC bind after the boot path's
// first attempt failed. It owns ONLY the bind: once a bind succeeds the
// existing `StartControlPlaneGRPC` goroutine owns the serve, and
// `StopControlPlaneGRPC` (shutdown hook order 20) owns the teardown, exactly
// as before.
type cpGRPCSupervisor struct {
	cfg clusterStartupConfig

	// stopping is closed by Stop BEFORE anything else, so a backoff sleep is
	// interruptible. stopOnce keeps Stop idempotent: closing a closed channel
	// panics.
	stopping chan struct{}
	stopOnce sync.Once

	// done is closed when the supervisor loop exits.
	done chan struct{}

	// mu guards `stopped`, which closes the bind/Stop race: Stop sets it
	// BEFORE the CP gRPC stop hook runs, and the loop re-checks it under the
	// same lock immediately after a successful bind, tearing the new listener
	// down rather than leaving a socket serving with nobody to stop it. This
	// is socks5_bind.go's `adopt` invariant; the listener here is published
	// into `clusterRole.grpcSrv` by StartControlPlaneGRPC rather than into a
	// field we own, so the compensation is a StopControlPlaneGRPC call instead
	// of a refusal to publish.
	mu      sync.Mutex
	stopped bool
}

// startControlPlaneWithBindRetry makes ONE synchronous bind attempt and, if it
// fails, arms a background supervisor that keeps retrying. It never exits the
// process: see the file header for the finding this replaces.
//
// Returns the supervisor when one was armed (nil when the first attempt
// succeeded, so the caller registers no shutdown hook it does not need).
func startControlPlaneWithBindRetry(cfg clusterStartupConfig, _ context.Context) *cpGRPCSupervisor {
	// CP mode is recorded as CONFIGURED before the first attempt, not after a
	// successful one. That ordering is the observability half of the fix and it
	// is load-bearing, for exactly the reason §36 moved `noteSOCKS5Configured`
	// ahead of its first bind: `clusterRole.role` is only ever set to
	// "control-plane" on an OBSERVED bind (correctly — that is evidence-based),
	// so without a separate record a CP whose listener has NEVER come up
	// reports role "standalone" — indistinguishable from a node that was never
	// asked to be a Control Plane, on precisely the node where an operator is
	// trying to find out why the fleet is not syncing.
	noteCPGRPCConfigured(cfg.CPAddr)

	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err == nil {
		noteCPGRPCBound()
		return nil
	} else if cpGRPCBindTerminal(err) {
		// An empty listen address never becomes non-empty and "already running
		// as control-plane" is success reported as an error. Retrying either
		// is a loop that cannot converge, so it is recorded and left alone —
		// neither is the crash-loop fault this change exists to remove.
		noteCPGRPCBindTerminal(classifyCPGRPCBindError(err))
		logErrorf("ControlPlane gRPC: %v — Control Plane mode is NOT active on this node; "+
			"the HTTP/HTTPS proxy data plane and the admin UI are unaffected", err)
		return nil
	} else {
		reason := classifyCPGRPCBindError(err)
		noteCPGRPCBindFailure(reason, cpGRPCBindBackoffInitial, time.Now())
		// The FULL error goes here and nowhere else: the contract row, the
		// alert and the readiness detail carry the bounded class only.
		// logErrorf applies sanitizeLog (CWE-117) to the whole line.
		logErrorf("ControlPlane gRPC listener could not bind (%s): %v — retrying in the background; "+
			"this node keeps proxying and its admin UI stays reachable, and enrolled Data Planes "+
			"continue on their last-good config until it binds", reason, err)
	}

	s := &cpGRPCSupervisor{
		cfg:      cfg,
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
	go s.run()
	return s
}

// cpGRPCBindTerminal reports whether err is one of enableControlPlane's two
// NON-retryable guard errors rather than a listener fault.
func cpGRPCBindTerminal(err error) bool {
	return errors.Is(err, errCPAlreadyControlPlane) || errors.Is(err, errCPAddrRequired)
}

// Stop interrupts the supervisor and waits for its loop to exit, bounded by
// ctx. Nil-safe and idempotent.
//
// It MUST run before the `control-plane-grpc-stop` hook (order 20), which is
// why its own hook is registered at order 15: otherwise a bind completing
// concurrently with StopControlPlaneGRPC would leave a listener serving with
// nothing left to stop it (the PX-18 class). `stopped` closes the remaining
// microsecond window from the other side.
func (s *cpGRPCSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stopping) })

	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()

	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *cpGRPCSupervisor) stopRequested() bool {
	select {
	case <-s.stopping:
		return true
	default:
		return false
	}
}

// run is the rebind loop.
//
// The panic guard mirrors socks5_bind.go's rather than using the bare
// recoverGoroutine: a panic here would otherwise leave the Control Plane
// permanently absent with every surface still green, which is the CHAOS-24
// objection to recovering at the top of a worker goroutine. Reporting the
// listener terminally DOWN — fail row, alert, gauge at zero — is the loudest
// state this subsystem can produce, so recovering is safe in the direction
// that matters.
func (s *cpGRPCSupervisor) run() {
	defer close(s.done)
	defer func() {
		if v := recover(); v != nil {
			recordCrash("control-plane-grpc-bind", "", v)
			noteCPGRPCSupervisorDown("bind loop panicked")
		}
	}()

	// The backoff is deliberately NEVER reset inside the loop, exactly as
	// serveAdminUIWithRetry and socks5Supervisor.run do it. Resetting it on
	// every successful bind would let a socket that dies immediately after
	// each bind settle into a steady one-bind-per-floor cadence forever;
	// letting it escalate monotonically to the ceiling bounds that
	// pathological case at one attempt per 30 s.
	backoff := cpGRPCBindBackoffInitial

	for {
		if s.stopRequested() {
			noteCPGRPCStopped()
			return
		}

		// Clamped so this sleep cannot carry us past the unavailability
		// threshold without an attempt to observe it — the alert is
		// attempt-driven and nothing else wakes this loop.
		failingFor := cpGRPCFailingFor(time.Now())
		wait := clampCPGRPCBindSleep(jitterDuration(backoff, cpGRPCBindJitter), failingFor)
		if !haSleepInterruptible(s.stopping, wait) {
			noteCPGRPCStopped()
			return
		}
		backoff = nextCPGRPCBindBackoff(backoff)

		if s.stopRequested() {
			noteCPGRPCStopped()
			return
		}

		// The TLS material is re-read on EVERY attempt (buildServerTLS calls
		// tls.LoadX509KeyPair at call time), so a rotation that momentarily
		// broke the pair self-heals with no restart. That is §33's rule (4),
		// and it is the whole remedy for trigger 2.
		err := enableControlPlane(s.cfg.CPAddr, s.cfg.CPCert, s.cfg.CPKey, s.cfg.CPCA, s.cfg.ClusterDBPath)
		if err == nil {
			// Re-check under the SAME lock Stop takes. If Stop won the race the
			// listener we just published into clusterRole.grpcSrv is serving
			// with nobody left to stop it, so tear it down here.
			s.mu.Lock()
			stopped := s.stopped
			s.mu.Unlock()
			if stopped {
				StopControlPlaneGRPC()
				noteCPGRPCStopped()
				return
			}

			suppressed, recovered := noteCPGRPCBound()
			if recovered {
				logger.Printf("ControlPlane: gRPC listener bound and serving again on %s "+
					"(%d suppressed bind-failure log line(s)) — Data Planes can sync config",
					sanitizeLog(s.cfg.CPAddr), suppressed)
			}
			return
		}

		if cpGRPCBindTerminal(err) {
			// Reached when something else (an admin API call, an HA promotion)
			// brought the Control Plane up while this loop was sleeping:
			// "already running as control-plane" means the job is done.
			noteCPGRPCBound()
			return
		}

		reason := classifyCPGRPCBindError(err)
		shouldLog := noteCPGRPCBindFailure(reason, backoff, time.Now())
		if shouldLog {
			logErrorf("ControlPlane gRPC listener still cannot bind (%s): %v — this node keeps proxying "+
				"and its admin UI stays reachable; enrolled Data Planes continue on their last-good config",
				reason, err)
		}
	}
}

// nextCPGRPCBindBackoff doubles cur up to the ceiling.
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

// clampCPGRPCBindSleep shortens a backoff that would carry the supervisor past
// the unavailability threshold without ever observing it.
//
// The read surfaces age an episode against the clock, so they are correct
// continuously — but the ALERT is produced by an ATTEMPT
// (noteCPGRPCBindFailure holds the fire-once latch) and nothing else wakes
// this loop. So a sleep longer than the time remaining to the threshold leaves
// the documented outage UNPAGED for the difference. This is CHAOS-55's
// `recoveryPollCeiling` rule and §36's `clampSOCKS5BindSleep` verbatim: an
// interval that can straddle a state transition is capped below it, which is a
// CORRECTNESS bound rather than tuning, at a cost of at most one extra attempt
// per episode. Capping the CEILING instead would slow every long outage's
// cadence permanently to buy a property that matters on one sleep.
func clampCPGRPCBindSleep(wait, failingFor time.Duration) time.Duration {
	remaining := cpGRPCBindUnavailableAfter - failingFor
	if remaining <= 0 || wait <= remaining {
		return wait
	}
	if remaining < cpGRPCBindClampFloor {
		return cpGRPCBindClampFloor
	}
	return remaining
}

// classifyCPGRPCBindError maps a bind or TLS-material failure to a BOUNDED
// reason class.
//
// Bounded is load-bearing in two directions. `Dispatch` dedups alerts on
// `event + ":" + Detail`, so a raw error — which embeds the listen address —
// would mint one dedup key per failure and defeat the window by construction
// (the WK-12/RS-5 defect). And the contract row is viewer-role, so the raw
// error must not reach it. Matching is via `errors.As` on `syscall.Errno`,
// never on the error text, because net wraps as
// `*net.OpError{*os.SyscallError{syscall.Errno}}` and the text is
// platform-specific.
func classifyCPGRPCBindError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, errCPAddrRequired) {
		return "not_configured"
	}
	if errors.Is(err, errCPAlreadyControlPlane) {
		return "already_active"
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
	if errors.Is(err, errCPGRPCTLSMaterial) {
		return "tls_certificate"
	}
	// §36 narrowed this branch in classifyAdminUIListenError and the same
	// narrowing applies here: `*net.OpError` satisfies `net.Error`
	// UNCONDITIONALLY (Timeout() false for a bind EINVAL), so the unqualified
	// form would report every unrecognised errno as `network_error` — sending
	// an operator down a network-troubleshooting path for a socket or
	// permission fault — and would make `listen_failed` reachable only by an
	// error the net package never produced.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}

// cpGRPCBindSupervisorHandle holds the armed supervisor so the shutdown hook
// can stop it. A plain global rather than a field on startupState because the
// supervisor is armed from inside the cluster startup slice, which does not
// have that struct — matching how clusterDBPathGlobal is carried.
var (
	cpGRPCBindSupervisorMu sync.Mutex
	cpGRPCBindSupervisor   *cpGRPCSupervisor
)

// registerCPGRPCBindSupervisor publishes the armed supervisor (nil when the
// first bind succeeded and none was needed).
func registerCPGRPCBindSupervisor(s *cpGRPCSupervisor) {
	cpGRPCBindSupervisorMu.Lock()
	cpGRPCBindSupervisor = s
	cpGRPCBindSupervisorMu.Unlock()
}

// stopCPGRPCBindSupervisor is the shutdown hook body (order 15). Nil-safe, so
// the overwhelmingly common case — a Control Plane that bound first time, or a
// node that is not a Control Plane at all — is a no-op.
func stopCPGRPCBindSupervisor(ctx context.Context) error {
	cpGRPCBindSupervisorMu.Lock()
	s := cpGRPCBindSupervisor
	cpGRPCBindSupervisorMu.Unlock()
	return s.Stop(ctx)
}
