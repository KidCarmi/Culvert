package main

// cp_grpc_bind.go — CHAOS-73: the Control Plane's gRPC listener, and the third
// instance of "which plane is allowed to kill which".
//
// Why this file exists.
//
// The Control Plane's gRPC listener was started with exactly one error branch
// on the boot path:
//
//	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err != nil {
//	        logFatalf("ControlPlane gRPC: %v", err)   // ← os.Exit(1)
//	}
//
// So EVERY way the Control Plane's listener could fail to come up terminated
// the whole appliance — and it did so from `initCluster`, which main.go runs at
// line 228, BEFORE `initSOCKS5` (254), `startAdminUI` (269) and
// `buildAndStartProxyServer` (271). The HTTP/HTTPS proxy, the SOCKS5 listener,
// the admin UI and the health endpoints therefore never start at all.
//
// This is the same finding as §33 (CHAOS-57, the admin UI listener) and §36
// (CHAOS-66, the SOCKS5 bind), on the plane both of those sweeps named as the
// remaining one. `CLAUDE.md`'s CHAOS-66 note records it verbatim as still open:
// *"the CP gRPC bind (`cluster_startup.go`) is the closest unexamined
// analogue"*. It completes a progression:
//
//	§33  the MANAGEMENT plane killed the DATA plane.
//	§36  a SECONDARY, opt-in data plane killed the PRIMARY data plane.
//	§41  the CLUSTER plane — whose job is serving config to OTHER nodes —
//	     kills this node's own data plane, management plane and health
//	     endpoints, before any of them exist.
//
// Reproduced against the real binary (not reasoned about), both triggers.
//
//  1. **The gRPC address is already bound.** A predecessor container still
//     draining, a second Culvert, a host service. Verbatim:
//
//     ControlPlane: config v1791151952 published
//     ClusterCA: generated new cluster CA (expires 2036-10-01)
//     ControlPlane gRPC: gRPC listen: listen tcp 127.0.0.1:19443: bind: address already in use
//     EXIT CODE: 1
//     proxy http_code=000          ← the HTTP proxy port never listened
//     adminui http_code=000        ← the admin UI port never listened
//
//  2. **The mTLS material cannot be loaded.** `cpServerOption` reads
//     `-cp-grpc-cert`/`-cp-grpc-key`/`-cp-grpc-ca` at call time, so a rotation
//     that briefly truncates, replaces or re-permissions them — cert-manager,
//     certbot, a Docker secret whose mount is not ready — is a boot that ends:
//
//     ControlPlane gRPC: gRPC TLS: tls: failed to find any PEM data in key input
//     EXIT CODE: 1
//
// Neither trigger is visible to the one check that looks like it should catch
// them, and here that is sharper than in §33/§36: `validatePortCollisions`
// (main.go) compares the proxy, UI and SOCKS5 ports to EACH OTHER — the
// Control Plane gRPC address is not even among the three it knows about, so it
// is unchecked in both directions.
//
// Under `restart: unless-stopped` (docker-compose.yml) each is an unattended
// CRASH LOOP: no proxy, no admin UI, no `/health`, no `/ready`, recoverable
// only with shell access. And "it exits, so it fails closed" is wrong for the
// reason §33 states and this file must not re-argue: process death picks NO
// posture, it delegates the choice to the topology. An explicit-proxy fleet
// loses all egress; a PAC/WPAD fleet with a `DIRECT` fallback, or a transparent
// deployment that bypasses a dead next hop, goes UNFILTERED.
//
// THE ASYMMETRY IS THE FINDING, and it is this sweep's governance point. The
// SAME function, `enableControlPlane`, with the SAME error, already has a
// non-fatal caller: `apiClusterMode` (ui_cluster.go) hands it to the live admin
// API, where a bind failure is returned as `409 Conflict` and the appliance
// keeps running. Its own doc comment says so — *"Safe to call at runtime from
// the admin API"*. One caller treats an unbindable socket as a recoverable
// error with an HTTP status; the other treats it as grounds to terminate an
// in-line security gateway. That is the shape CHAOS-62 found for
// `enableLogStore` (fatal on the boot path, an API error on the live one) and
// §40 found for `apiSetupComplete` (the durability rule applied to the
// one-time path and not its sibling). The rule to carry forward: **when one
// caller of a function can report a fault and another can only exit, the exit
// is the one that needs the argument — and "it is the boot path" is not that
// argument.**
//
// A THIRD defect, independent of the bind, and the one with no fatal to blame:
// the listener's death was SILENT AND TERMINAL. `StartControlPlaneGRPC` spawned
//
//	go func() {
//	        if err := srv.Serve(ln); err != nil {
//	                logger.Printf("ControlPlane gRPC error: %v", err)
//	        }
//	}()
//
// so when `Serve` returned, ONE log line was emitted and nothing rebound —
// while `clusterRole.role` stayed `"control-plane"` and `clusterRole.grpcAddr`
// kept its address, because both are set after a successful bind and never
// cleared. `GET /api/cluster/status` therefore reported a healthy Control Plane
// with its listening address, forever, on a node with no listener. There was no
// metric, no `/health` field, no `/ready` row, no operator-contract row and no
// alert for this plane at all — the only listener in the appliance without a
// health plane (compare `admin_ui_health.go`, `socks5_health.go`). That is
// PX-18 in miniature: probes green on a dead listener.
//
// What this file provides is the listener's whole lifecycle — bind → serve →
// rebind — so a cluster-plane fault degrades the cluster plane alone. Five
// rules, all borrowed wholesale from CHAOS-54/55/57/66 rather than invented as
// a fourth dialect:
//
//  1. No bind path is fatal ON THE BOOT PATH. The runtime admin path keeps its
//     synchronous 409 — see startControlPlaneListener's `tolerateFirstFailure`.
//  2. Retry is RATE-bounded, never COUNT-bounded. The terminal state of "give
//     up" is a fleet whose config plane is gone until someone restarts it.
//     "Avoid infinite retries" is satisfied the CHAOS-54/55 way: never SILENT.
//  3. Recovery is declared on OBSERVED evidence only — a listener that actually
//     bound. Elapsed time never clears the state, because a loop that stopped
//     failing because it stopped attempting looks identical to a bound one.
//  4. The sleep is INTERRUPTIBLE, so `control-plane-grpc-stop` (order 20 in the
//     shutdown sequence) never waits out a 30 s backoff.
//  5. Reason classes are BOUNDED and matched with `errors.As` on
//     `syscall.Errno`, never by string (cp_grpc_health.go).
//
// AND ONE RULE THIS PLANE NEEDS THAT THE OTHER TWO DID NOT — the CP role is a
// CLAIM, and it is only true while the socket is real.
//
// `enableControlPlane` carried the comment *"Only set role after gRPC is
// successfully started"*, and that invariant is PRESERVED here rather than
// traded away for availability: while the bind is failing this node stays
// `standalone`, so `GET /api/cluster/status`, `/api/diagnostics` and every
// `clusterRole.role == "control-plane"` gate report what is true. A supervisor
// that asserted the role optimistically would have fixed the crash loop by
// replacing it with an operational lie, which is the weaker fix and is exactly
// what §36 refused when it declined to add a "pending" state.
//
// The HA leadership assertion rides the same rule. `startControlPlaneWithHAResume`
// ran `globalHA.ResumeAsLeader` immediately after `enableControlPlane`
// returned; it is now deferred to the OBSERVED bind, via the `onActivated`
// callback, so this node never asserts leadership it cannot exercise. On the
// happy path (the bind succeeds on the first attempt, which is every healthy
// boot) the ordering is byte-identical — the callback runs synchronously inside
// startControlPlaneListener before it returns. On the failure path it is
// strictly safer than both the old behaviour and today's restart path: a
// "leader" no Data Plane can reach cannot serve HASync, so claiming the term
// while unbindable adds a self-asserted leader to a cluster whose standby is
// correctly concluding the leader is gone. Deferring does not CLOSE the
// split-brain window (RISK-001 / ADR-0004 own that, and the fence closes it
// properly) — it declines to open a second one.
//
// Deliberately NOT done, each recorded rather than silently skipped:
//
//   - `logFatalf("Proxy error")` (main.go) is untouched and stays correct for
//     §33's reason: the proxy IS the product, and a gateway that cannot serve
//     must exit loudly rather than linger as a black hole. The asymmetry is the
//     whole point of all three sweeps.
//   - `armHALease`'s fatal (cluster_startup.go) is untouched and is CORRECT.
//     Its own comment carries the argument: a malformed fence config that fell
//     back to legacy would be "an invisible safety downgrade" — the operator
//     asked for fencing and would not get it. That is a fault whose only safe
//     resolution is refusing to run, which is precisely the test this file
//     applies to the bind and the bind fails.
//   - The Data Plane's two fatals (`dp_enrollment.go`) are the same class one
//     plane over and are NOT touched here: one concern per change, and the DP
//     posture question ("may a node that cannot reach its CP serve traffic?")
//     is a different decision from this one. Recorded as register row CL-23.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// cpListenerConfig is the material one bind attempt needs. Captured once so a
// rebind re-reads the TLS files from disk at the SAME paths — which is what
// makes a certificate rotation self-heal with no restart (§33 rule 4).
type cpListenerConfig struct {
	addr, certFile, keyFile, caFile string
}

// cpListenerSupervisor owns the Control Plane gRPC listener's whole lifecycle:
// bind, serve, and rebind when the serve ends.
//
// It is the single owner of the `*grpc.Server` handle. Before this change
// `StartControlPlaneGRPC` wrote `clusterRole.grpcSrv` and `StopControlPlaneGRPC`
// read it with NO lock — latent while the handle was written exactly once per
// process, a REAL data race the moment anything rebinds. The handle now lives
// here under `mu`, and the shutdown hook goes through the supervisor.
type cpListenerSupervisor struct {
	cfg cpListenerConfig

	// onActivated runs ONCE, on the first observed successful bind, after the
	// CP role has been activated. It carries whatever must not happen until the
	// listener is real — on the boot path, the HA leadership resume.
	onActivated     func()
	onActivatedOnce sync.Once

	// stopping is closed by Stop BEFORE anything else, so a backoff sleep is
	// interruptible and a bind in flight is not adopted. stopOnce keeps Stop
	// idempotent: closing a closed channel panics.
	stopping chan struct{}
	stopOnce sync.Once

	// done is closed when the supervisor loop exits.
	done chan struct{}

	// firstAttempt is closed once the loop has RESOLVED its first bind attempt,
	// one way or the other. startControlPlaneListener waits on it so it cannot
	// return while every CP surface still describes a listener that does not
	// exist yet — the window §36 removed rather than reported.
	firstAttempt chan struct{}
	firstOnce    sync.Once

	// mu guards the handoff between the loop and Stop. stopped is the flag that
	// closes the adopt/Stop race: Stop sets it BEFORE reading srv, and adopt
	// refuses under the same lock, so a server created concurrently with Stop is
	// either stopped by Stop or torn down by the loop — never left serving with
	// nobody waiting on it.
	mu       sync.Mutex
	srv      *grpc.Server
	stopped  bool
	bound    bool // whether the FIRST attempt bound; read by the starter only
	resolved bool // whether the first attempt has been released
}

// cpSupervisor is the process-wide handle. Guarded by cpActivationMu.
var cpSupervisor *cpListenerSupervisor

// cpActivationMu serialises every path that ACTIVATES or REBINDS the Control
// Plane listener: the boot path, the runtime admin API, the HA promote
// callback, and the supervisor's own rebind.
//
// It is an OUTER lock — take it BEFORE clusterRoleMu, never from anything
// reachable underneath one. The pattern and the reason are `caMutationMu`'s
// (§18): activating a listener is prepare → bind → publish-handle → set-role,
// four individually-atomic steps that are jointly not, so un-serialised a
// rebind could publish a stale server over a freshly-activated one and leave
// the role pointing at a socket nobody is serving.
var cpActivationMu sync.Mutex

// startControlPlaneListener starts the supervisor and resolves its FIRST bind
// attempt synchronously.
//
// tolerateFirstFailure is the whole difference between the two callers, and it
// is a deliberate asymmetry rather than an inconsistency:
//
//   - BOOT path (true): a failure is non-fatal. The supervisor keeps retrying,
//     the node serves traffic as a standalone gateway with its local config,
//     and the CP role is claimed if and when the listener actually binds.
//     Nobody is at the keyboard, so the only alternatives are "retry" and
//     "terminate an in-line gateway".
//   - RUNTIME admin path (false): a failure is returned to the caller and the
//     supervisor is torn down, so `POST /api/cluster/mode` keeps its exact
//     pre-change semantics — an admin who typed a bad address or an occupied
//     port gets an immediate 409 and can retype it. A background retry loop
//     there would answer 200 for a Control Plane that may never exist, which
//     is the operational lie this sweep exists to remove, in the one place the
//     operator can be told the truth immediately.
//
// The wait is bounded by ONE non-blocking `bind(2)` plus reading the TLS files,
// which is exactly what the pre-change code did synchronously; only the fatal
// on failure is gone.
func startControlPlaneListener(cfg cpListenerConfig, tolerateFirstFailure bool, onActivated func()) (*cpListenerSupervisor, error) {
	s := &cpListenerSupervisor{
		cfg:          cfg,
		onActivated:  onActivated,
		stopping:     make(chan struct{}),
		done:         make(chan struct{}),
		firstAttempt: make(chan struct{}),
	}
	noteCPGRPCConfigured(cfg.addr)
	go s.run()
	<-s.firstAttempt

	s.mu.Lock()
	bound := s.bound
	s.mu.Unlock()

	if bound {
		return s, nil
	}
	if tolerateFirstFailure {
		return s, nil
	}
	// Runtime path: tear the supervisor down so no background loop is left
	// retrying an address the admin is about to correct, and report the fault.
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Stop(stopCtx)
	return nil, fmt.Errorf("control plane gRPC listener could not start on %s (%s)",
		cfg.addr, cpGRPCListenerState().LastReason)
}

// markFirstAttempt releases startControlPlaneListener once the first bind
// attempt has resolved. Idempotent; safe to call from both the loop and its
// deferred guard.
func (s *cpListenerSupervisor) markFirstAttempt() {
	s.firstOnce.Do(func() {
		s.mu.Lock()
		s.resolved = true
		s.mu.Unlock()
		close(s.firstAttempt)
	})
}

// Stop interrupts the supervisor, stops the currently bound server if there is
// one, and waits for the loop to exit — bounded by ctx. Nil-safe and
// idempotent.
func (s *cpListenerSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stopping) })

	// Set stopped and read srv under ONE lock. adopt takes the same lock, so
	// either it has already published a server (and we stop it here) or it will
	// refuse and tear it down itself.
	s.mu.Lock()
	s.stopped = true
	srv := s.srv
	s.mu.Unlock()

	if srv != nil {
		// The graceful/force split and its two grpc-go hazards are
		// gracefulStopBounded's (CHAOS-56); this call site must not hold a lock
		// across it, which is why srv was read above and released.
		stopControlPlaneServer(srv)
	}

	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// currentServer reports the server currently being served, or nil while the
// listener is unbound (before the first successful bind, or between a serve
// ending and the next rebind).
func (s *cpListenerSupervisor) currentServer() *grpc.Server {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv
}

// adopt publishes srv as the current server, or reports false when Stop has
// already run — in which case the caller owns tearing it down.
func (s *cpListenerSupervisor) adopt(srv *grpc.Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.srv = srv
	return true
}

// release clears the current server once its serve has ended.
func (s *cpListenerSupervisor) release(srv *grpc.Server) {
	s.mu.Lock()
	if s.srv == srv {
		s.srv = nil
	}
	s.mu.Unlock()
}

// noteFirstBound records that the first attempt bound, for the starter to read.
func (s *cpListenerSupervisor) noteFirstBound() {
	s.mu.Lock()
	if !s.resolved {
		s.bound = true
	}
	s.mu.Unlock()
}

// stopRequested reports whether Stop has been called.
func (s *cpListenerSupervisor) stopRequested() bool {
	select {
	case <-s.stopping:
		return true
	default:
		return false
	}
}

// run is the bind/serve/rebind loop.
//
// The panic guard mirrors the SOCKS5 supervisor's rather than using the bare
// recoverGoroutine: a panic here would otherwise leave the Control Plane
// permanently gone with every surface still green, which is the CHAOS-24
// objection to recovering at the top of a worker goroutine. Reporting the
// listener DOWN — fail row, alert, gauge at zero, and the ONE remedy that says
// "restart this node" — is the loudest state this subsystem can produce, so
// recovering is safe in the direction that matters.
func (s *cpListenerSupervisor) run() {
	defer close(s.done)
	// Runs AFTER the recover below (defers are LIFO), so the starter is
	// released on every exit path including a panic.
	defer s.markFirstAttempt()
	defer func() {
		if v := recover(); v != nil {
			recordCrash("control-plane-grpc-bind", "", v)
			noteCPGRPCSupervisorDown("bind loop panicked")
		}
	}()

	// The backoff is deliberately NEVER reset inside the loop, exactly as
	// serveAdminUIWithRetry and the SOCKS5 supervisor do it. Resetting it on
	// every successful bind would let a socket that dies immediately after each
	// bind settle into a steady one-bind-per-floor cadence forever; letting it
	// escalate monotonically to the ceiling bounds that pathological case at
	// one attempt per 30 s.
	backoff := cpGRPCBindBackoffInitial

	for {
		if s.stopRequested() {
			noteCPGRPCListenerStopped()
			return
		}

		srv, ln, mode, err := buildControlPlaneServer(s.cfg)
		if err != nil {
			reason := classifyCPGRPCBindError(err)
			shouldLog, failingFor := noteCPGRPCBindFailure(reason, backoff, cpGRPCHealthNow())
			// Released only AFTER the failure is recorded: the starter may
			// return the moment this fires, and it must never return to a state
			// that has not been written yet — the same window in miniature.
			s.markFirstAttempt()
			// Clamped so this sleep cannot carry us past the unavailability
			// threshold without an attempt to observe it — the alert is
			// attempt-driven and nothing else wakes this loop.
			wait := clampCPGRPCBindSleep(jitterDuration(backoff, cpGRPCBindJitter), failingFor)
			if shouldLog {
				// The FULL error goes here and nowhere else: the contract row,
				// the alert and the readiness detail all carry the bounded
				// class only. logErrorf applies sanitizeLog (CWE-117) to the
				// whole line.
				logErrorf("ControlPlane gRPC listener could not start on %s (%s): %v — retrying in %s; "+
					"this node's proxy data plane and admin UI are unaffected, and enrolled Data Planes "+
					"keep serving their last-good config",
					s.cfg.addr, reason, err, wait.Round(time.Millisecond))
			}
			if !haSleepInterruptible(s.stopping, wait) {
				noteCPGRPCListenerStopped()
				return
			}
			backoff = nextCPGRPCBindBackoff(backoff)
			continue
		}

		if !s.adopt(srv) {
			// Stop won the race: tear down what we just built rather than
			// serving on a socket nobody will ever stop.
			srv.Stop()
			_ = ln.Close()
			noteCPGRPCListenerStopped()
			return
		}

		// The success line is emitted AFTER the bind, never before it — §33's
		// rule, learned from an admin UI that announced a listener that did not
		// exist.
		suppressed, recovered := noteCPGRPCBound()
		if !s.firstResolved() {
			s.noteFirstBound()
		}
		logControlPlaneTransport(s.cfg.addr, mode)
		if recovered {
			logger.Printf("ControlPlane: gRPC listener bound and serving again on %s (%d suppressed bind-failure log line(s))",
				sanitizeLog(s.cfg.addr), suppressed)
		}

		// Claim the CP role now that the socket is real, and run the one-time
		// post-activation work (the HA leadership resume on the boot path).
		//
		// This is the ONE activation path, for every attempt including the
		// first, and that is deliberate. The first draft split it — the
		// starter's caller activated a first-attempt bind and the supervisor
		// activated any later one — which meant two code paths for one
		// transition, differing only in which of them held the activation lock.
		// Its own control gate caught it: a bind driven through
		// startControlPlaneListener claimed no role at all, because the half
		// that would have done so lived in a caller the gate was not going
		// through. Two writers for one state is the trap; there is now one.
		activateControlPlaneAfterBind(s.cfg, srv)
		s.runOnActivated()

		// Released only NOW, with the role claimed and onActivated done, and
		// that ORDER is a correctness argument rather than tidiness.
		//
		// It used to sit immediately after noteCPGRPCBound, which was a WINDOW:
		// `startControlPlaneListener` returns the moment this fires, so
		// `activateControlPlane` could log "ControlPlane: enabled" and hand
		// control back to main.go — which goes straight on to Data-Plane
		// wiring, the admin UI and the proxy — while `clusterRole.role` was
		// still "standalone" and the HA leadership resume had not run.
		// Microseconds wide, and the same class of lie this whole change exists
		// to remove, so the fix is to REMOVE the window rather than report it
		// (§36's rule, which refused to add a "pending" state for the same
		// reason).
		//
		// Found by this sweep's own control gate
		// (TestChaos73_ControlHealthyBindIsSilent) under `-race`, which slows
		// the scheduler enough to make the window observable — it passed
		// without `-race`, which is why the gate runs under it.
		//
		// Blocking here is bounded by exactly the work the pre-change code did
		// synchronously on this path (a role assignment under a mutex, a
		// goroutine start, and `globalHA.ResumeAsLeader`), so nothing new can
		// delay the boot. The deferred markFirstAttempt in the panic guard
		// still releases the starter on every abnormal exit.
		s.markFirstAttempt()

		serveErr := srv.Serve(ln)
		s.release(srv)

		if s.stopRequested() {
			noteCPGRPCListenerStopped()
			return
		}

		// Serve returned on its own. Before this change that was terminal and
		// SILENT: one log line, `clusterRole.role` still "control-plane", and
		// no rebind ever. A fresh socket is exactly its recovery.
		reason := "serve_ended"
		if serveErr != nil {
			reason = classifyCPGRPCBindError(serveErr)
		}
		if noteCPGRPCServeEnded(reason) {
			logErrorf("ControlPlane gRPC serve on %s ended (%s): %v — rebinding; this node's proxy data "+
				"plane and admin UI are unaffected",
				s.cfg.addr, reason, serveErr)
		}

		wait := jitterDuration(backoff, cpGRPCBindJitter)
		if !haSleepInterruptible(s.stopping, wait) {
			noteCPGRPCListenerStopped()
			return
		}
		backoff = nextCPGRPCBindBackoff(backoff)
	}
}

// firstResolved reports whether the first bind attempt has already been
// released to the starter.
func (s *cpListenerSupervisor) firstResolved() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolved
}

// runOnActivated runs the one-time post-activation callback.
func (s *cpListenerSupervisor) runOnActivated() {
	if s.onActivated == nil {
		return
	}
	s.onActivatedOnce.Do(s.onActivated)
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

// buildControlPlaneServer performs ONE bind attempt: load the TLS material,
// construct the gRPC server, register the service, and listen.
//
// It is the pure, global-free half of the old StartControlPlaneGRPC — no
// clusterRole write, no goroutine — so the supervisor can call it on every
// attempt and a test can drive it directly. The TLS material is re-read HERE on
// every attempt, which is what makes a rotation self-heal (§33 rule 4).
//
// On any error nothing is left behind: a server built before a failed Listen is
// stopped rather than leaked. §33 rule 5's defect in the other direction —
// `ServeTLS` returning a certificate error WITHOUT closing the listener it was
// handed, leaking one socket per attempt — cannot occur here because the TLS
// material is loaded BEFORE the listener is bound.
func buildControlPlaneServer(cfg cpListenerConfig) (*grpc.Server, net.Listener, string, error) {
	serverOpt, mode, err := cpServerOptionMode(cfg.addr, cfg.certFile, cfg.keyFile, cfg.caFile)
	if err != nil {
		// Tag it so the classifier can name `tls_certificate` without matching
		// on the crypto/tls error text.
		return nil, nil, "", fmt.Errorf("%w: %w", errCPGRPCTLSMaterial, err)
	}

	srv := newControlPlaneGRPCServer(serverOpt)
	registerConfigService(srv)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", cfg.addr)
	if err != nil {
		srv.Stop()
		return nil, nil, "", fmt.Errorf("gRPC listen: %w", err)
	}
	return srv, ln, mode, nil
}

// stopControlPlaneListener stops the supervisor (and with it the current
// server), bounded by ctx. The shutdown hook's entry point: stopping the
// SERVER alone would leave the supervisor to rebind on its way out.
func stopControlPlaneListener(ctx context.Context) error {
	cpActivationMu.Lock()
	sup := cpSupervisor
	cpSupervisor = nil
	cpActivationMu.Unlock()
	if sup == nil {
		// No supervisor was ever armed (not a Control Plane node). Nothing to
		// stop — and nothing to report, so a standalone proxy's shutdown stays
		// silent on this plane.
		return nil
	}
	return sup.Stop(ctx)
}

// activateControlPlaneAfterBind claims the Control Plane role now that a socket
// is real.
//
// This is the second half of what `enableControlPlane` used to do inline, and
// the invariant it carries is the one that function stated in a comment —
// "Only set role after gRPC is successfully started". CHAOS-73 preserves it
// rather than trading it for availability: while the bind is failing the node
// reports `standalone`, so every `clusterRole.role == "control-plane"` gate,
// `GET /api/cluster/status` and `/api/diagnostics` say what is true.
//
// Locking: takes clusterRoleMu only, never cpActivationMu. Two callers reach
// it — the starter (which already holds cpActivationMu) and the supervisor
// goroutine on a later successful attempt (which does not). The supervisor
// deliberately does NOT take the outer lock: it is not racing another
// activation, because `activateControlPlane` refuses while `cpSupervisor != nil`
// and only `stopControlPlaneListener` clears that, so there is exactly one
// activator for the life of a supervisor. Taking it here would also mean
// holding it across a `Serve` that runs for the life of the process.
//
// Idempotent: a rebind after a serve-death re-runs it, which re-publishes the
// handle and must NOT re-start the heartbeat monitor — hence the alreadyCP
// check.
func activateControlPlaneAfterBind(cfg cpListenerConfig, srv *grpc.Server) {
	clusterRoleMu.Lock()
	alreadyCP := clusterRole.role == "control-plane"
	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = cfg.addr
	clusterRole.certFile = cfg.certFile
	clusterRole.keyFile = cfg.keyFile
	clusterRole.caFile = cfg.caFile
	// Kept in sync for any reader that still consults it; the supervisor is the
	// authoritative owner (see currentControlPlaneServer).
	clusterRole.grpcSrv = srv
	clusterRoleMu.Unlock()

	if !alreadyCP {
		// resolveLifecycleCtx, not appLifecycleCtx directly: the context is
		// wired in main() and is nil in every one-shot command path and in the
		// test binary, so `appLifecycleCtx.Done()` is a nil-pointer deref. The
		// pre-change code had the same expression and was unreachable from any
		// test; the moment this ran on the SUPERVISOR goroutine it became a
		// panic that killed the listener permanently, found by this sweep's own
		// self-heal gate.
		globalClusterStore.StartHeartbeatMonitor(resolveLifecycleCtx().Done())
	}
}
