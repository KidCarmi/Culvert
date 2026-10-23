package main

// cp_grpc_bind.go — CHAOS-71: the Control Plane's gRPC listener, and the third
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
//	§44  the CLUSTER plane — whose job is serving config to OTHER nodes —
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
	"errors"
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
	//
	// srv is also the TEARDOWN CLAIM. A published server has exactly one
	// teardown owner, decided under mu: whoever takes srv out of this field
	// (Stop, or the loop's claimTeardown) stops it, and the other side never
	// calls Stop or GracefulStop on it. Two concurrent stops are not merely
	// redundant: grpc-go's stop() holds the server mutex across
	// handlersWG.Wait(), so a GracefulStop parked behind a wedged handler
	// blocks a concurrent Stop() forever — and when that Stop() was the loop's
	// retirement, done never closed and shutdown ran to its deadline (Codex
	// review of #1556).
	mu       sync.Mutex
	srv      *grpc.Server
	stopped  bool
	bound    bool // whether the FIRST attempt bound; read by the starter only
	resolved bool // whether the first attempt has been released

	// committed is true once this supervisor has claimed the CP role (and not
	// rolled it back), so a rebind after a serve-death may re-assert its OWN
	// claim while a role somebody else established is never replaced. Touched
	// only by the supervisor goroutine.
	committed bool

	// cur is what the in-flight attempt holds; original is the role tuple this
	// supervisor replaced on its FIRST claim. Together they let EVERY exit edge
	// — including a panic at any stage — release exactly what was acquired
	// (see the exit-edge table on run). Supervisor goroutine only.
	//
	// Whether the fleet was told this node is a Control Plane is deliberately
	// NOT a field here: an HA transition (EnableAsLeader, a resume) publishes
	// this node through republishTopology, which no supervisor flag observes.
	// The terminal exit reads it from the committed snapshot instead (Codex
	// review of #1556).
	cur          *cpAttempt
	original     cpRoleFields
	haveOriginal bool
}

// cpAttempt is everything ONE bind attempt holds.
type cpAttempt struct {
	srv       *grpc.Server
	ln        net.Listener
	published bool // adopt published srv: from then on its teardown is CLAIMED (claimTeardown)
	serving   bool // Serve was entered: from then on Serve owns closing ln
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
	// The first attempt did not bind, so normally there is no drain; the bound
	// still covers one (cpListenerStopWait) in case a retry bound meanwhile.
	stopCtx, cancel := context.WithTimeout(context.Background(), cpListenerStopWait())
	defer cancel()
	_ = s.Stop(stopCtx)
	reason := cpGRPCListenerState().LastReason
	// The 409 says no Control Plane exists; the health plane must agree.
	noteCPGRPCActivationRejected()
	return nil, fmt.Errorf("control plane gRPC listener could not start on %s (%s)", cfg.addr, reason)
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
// idempotent: only the call that claims the server (takes it out of s.srv)
// drains it, so a later one (the shutdown hook joining a deactivation still
// draining) finds nothing to claim and waits on the same exit instead of
// starting a second GracefulStop.
func (s *cpListenerSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stopping) })

	// Set stopped and CLAIM srv under ONE lock. adopt takes the same lock, so
	// either it has already published a server (and we claim it here) or it
	// will refuse and tear it down itself. Taking srv out of the field is the
	// claim: a server the loop already claimed for retirement is not here, and
	// Stop only waits on done — it never enters a second, concurrent stop of
	// the same server (see the mu comment).
	s.mu.Lock()
	s.stopped = true
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()

	if srv != nil {
		// The graceful/force split and its two grpc-go hazards are
		// gracefulStopBounded's (CHAOS-56); this call site must not hold a lock
		// across it, which is why srv was claimed above and the lock released.
		teardownCPGRPCServer(srv, true)
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

// adopt publishes the attempt's server as the current server, or reports
// false when Stop has already run — in which case the caller owns tearing it
// down.
func (s *cpListenerSupervisor) adopt(a *cpAttempt) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.srv = a.srv
	a.published = true
	return true
}

// claimTeardown decides, atomically under mu, whether the loop owns tearing
// down the attempt's server. A server adopt never published is the loop's
// alone. A published one is the loop's only if it is still in s.srv, and
// taking it out is the claim; if Stop already took it, Stop owns its teardown
// (the graceful drain) and the loop must not touch it.
func (s *cpListenerSupervisor) claimTeardown(a *cpAttempt) bool {
	if !a.published {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != a.srv {
		return false
	}
	s.srv = nil
	return true
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

// exitTerminal is the ONE way the supervisor ends terminally
// (TestChaos71_Wall_TerminalExitsGoThroughExitTerminal). A terminal exit
// leaves no Control Plane behind, so it gives up CP address-list ownership —
// a Data Plane that won a role conflict, or a node whose loop panicked, must
// not keep reporting and reconciling a CP list (Codex review of #1556). It
// records the terminal state (fail row, alert) first, then withdraws this
// node and gives up ownership.
//
// If the committed CP address list names this node — whichever owned path
// published it: this supervisor's activation, or an HA transition's
// republishTopology after it (a supervisor-local "published" flag missed the
// latter: Codex review of #1556) — ownership is released only AFTER the list
// without this node commits: the withdrawal is an owned
// publish, so a rejection or a lost commit race is pending, paged once per
// episode and retried, and the retry loop releases ownership when it commits
// (withdrawCPAddress). Releasing first — the previous order — discarded a
// failed withdrawal: with no source the retry loop exits clean, and Data
// Planes kept a dead CP address that nothing ever reconciled, in a process
// that survived the panic (Codex review of #1556).
//
// On the panic edge this runs inside the deferred recover, so the withdrawal
// is contained: a panic in it leaves the withdrawal unrecorded, and the
// ownership step then latches it pending so a retry still owns it.
//
// The terminal state is recorded FIRST (Codex P2 4314031070 on #1556): by
// now nothing is serving (abandonAfterPanic stopped the server, or the role
// was refused), and the withdrawal can clone, marshal and delta a snapshot
// near the wire budget. Recorded after it, that whole window reported
// Serving=true on diagnostics and kept cpGRPCLeaseRenewWithheld renewing a
// lease for a leader whose listener and supervisor were already gone,
// delaying failover. The order touches only health: withdrawal ownership and
// its retry path are unchanged
// (TestChaos71_TerminalStateIsRecordedBeforeTheWithdrawal).
func (s *cpListenerSupervisor) exitTerminal(reason string) {
	noteCPGRPCSupervisorDown(reason)
	func() {
		defer func() { _ = recover() }()
		// A no-op unless the committed list names this node. The outcome is
		// recorded (and a failure retried) by the store; the ownership step
		// below decides from the committed list again.
		_, _ = cpWithdrawCPAddress(s.cfg.addr)
	}()
	globalConfigStore.releaseCPAddressSourceAfterWithdrawal(s.cfg.addr)
}

// run is the bind/serve/rebind loop.
//
// THE STATE MACHINE. Stages: bind → adopt → claim → publish → onActivated →
// serve. Every exit edge releases exactly what its stage acquired (via
// releaseAttempt / commitActivation's rollback / abandonAfterPanic) and emits
// exactly one signal. TestChaos71_SupervisorExitEdgeTable drives every row.
//
//	edge                         | released                                   | signal
//	-----------------------------+--------------------------------------------+-----------------------------
//	bind / TLS-reload failure    | nothing held (build cleans up)             | recoverable failure, backoff
//	Stop during a backoff sleep  | nothing held                               | stopped
//	Stop wins the adopt race     | server + listener                          | stopped
//	Stop / shutdown at the claim | server + listener + handle                 | stopped
//	role_conflict                | server + listener + handle (role is not ours) + address ownership, after any withdrawal commits | TERMINAL + alert (bypasses latch)
//	shutdown after the claim     | server + listener + handle + role rollback, no publish | stopped
//	address publish rejected     | server + listener + handle + role rollback | recoverable failure, backoff
//	panic after the claim        | server + listener + handle + role restored + address ownership | TERMINAL + alert (bypasses latch)
//	panic in onActivated         | as above, ownership released after the withdrawal commits | TERMINAL + alert (bypasses latch)
//	panic, withdrawal rejected   | as above; ownership KEPT (withdrawal pending, retried) until it commits | TERMINAL + alert + config_snapshot_rejected
//	Stop while serving           | handle (Stop owns the graceful drain)      | stopped
//	serve ends on its own        | server RETIRED (DP transports) + handle    | recoverable failure, backoff
//	shutdown races a serve end   | server stopped by ONE owner (claimTeardown): | stopped
//	                             | Stop's drain, or the loop's retire/drain   |
//	panic after a serve ended    | role restored + address ownership after the withdrawal commits | TERMINAL + alert (bypasses latch)
//
// Address ownership: every TERMINAL exit releases it (exitTerminal) — at once
// when the committed list does not name this node, otherwise only after the
// list without it commits (a failed withdrawal keeps ownership, pending and
// retried, until then); every recoverable and stopped exit keeps it (a retry,
// or shutdown, follows).
//
// Two more rows are the ENTRY's (activateControlPlane), not the loop's, and
// the same table test drives them:
//
//	sync activation refused      | CP address-list ownership released         | rejected: plane unconfigured (409)
//	(admin activate / promote)   | (releaseCPAddressSource)                   |
//	boot bind failure (resilient)| nothing; address ownership KEPT for retries | recoverable failure, backoff
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
			// Release everything the interrupted stage held BEFORE reporting
			// the terminal state: a panic between adopt and Serve otherwise
			// left the server, the bound socket and the CP role claimed with
			// nothing serving (Codex review of #1556).
			s.abandonAfterPanic()
			s.exitTerminal("bind loop panicked") // records the terminal state, withdraws this node from the list, then releases ownership
		}
	}()

	// The backoff is NOT reset on a bind — only after a SUCCESSFUL SERVE, one
	// that stayed up for at least cpGRPCServeStableAfter (cpGRPCBackoffAfterServe).
	// Resetting on every bind would let a socket that dies immediately after
	// each bind settle into a steady one-bind-per-floor cadence forever, so that
	// pathological case still escalates to the 30 s ceiling. But NEVER resetting
	// (the first draft) charged a listener that served for days and then lost
	// its socket once with the ceiling it reached during an outage last month:
	// an ordinary one-off fault after a long healthy run must rebind on the 1 s
	// floor, not wait out 30 s with the fleet's config plane dark.
	backoff := cpGRPCBindBackoffInitial

	for {
		if s.stopRequested() {
			noteCPGRPCListenerStopped()
			return
		}

		srv, ln, mode, err := buildControlPlaneServer(s.cfg)
		if err != nil {
			if !s.handleBindFailure(err, backoff) {
				noteCPGRPCListenerStopped()
				return
			}
			backoff = nextCPGRPCBindBackoff(backoff)
			continue
		}

		s.cur = &cpAttempt{srv: srv, ln: ln}
		if !s.adopt(s.cur) {
			// Stop won the race: tear down what we just built rather than
			// serving on a socket nobody will ever stop.
			s.releaseAttempt()
			noteCPGRPCListenerStopped()
			return
		}

		// Claim the CP role now that the socket is real, publish the address
		// list it owes the fleet, and run the one-time post-activation work
		// (the HA leadership resume on the boot path) — commitActivation, the
		// ONE activation path, for every attempt including the first. The first
		// draft split it between the starter's caller and the supervisor (two
		// writers for one state transition) and its own control gate caught it.
		// Activation is ASYNCHRONOUS relative to boot, so commitActivation
		// re-decides against everything that may have changed since: Stop,
		// process shutdown, another established role, a rejected publish.
		serve, exit := s.commitAfterAdopt(mode, backoff)
		if exit {
			return
		}
		if !serve {
			backoff = nextCPGRPCBindBackoff(backoff)
			continue
		}

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
		// (TestChaos71_ControlHealthyBindIsSilent) under `-race`, which slows
		// the scheduler enough to make the window observable — it passed
		// without `-race`, which is why the gate runs under it.
		//
		// Blocking here is bounded by exactly the work the pre-change code did
		// synchronously on this path (a role assignment under a mutex, a
		// goroutine start, and `globalHA.ResumeAsLeader`), so nothing new can
		// delay the boot. The deferred markFirstAttempt in the panic guard
		// still releases the starter on every abnormal exit.
		s.markFirstAttempt()

		servedFrom := cpGRPCHealthNow()
		s.cur.serving = true
		serveErr := srv.Serve(ln)
		backoff = cpGRPCBackoffAfterServe(backoff, cpGRPCHealthNow().Sub(servedFrom))

		if s.stopRequested() {
			// Stop owns this server's teardown (graceful drain, then force) if
			// it claimed it; otherwise releaseAttempt drains it under the same
			// bound. Never both (claimTeardown).
			s.releaseAttempt()
			noteCPGRPCListenerStopped()
			return
		}

		// Serve returned on its own. Before this change that was terminal and
		// SILENT: one log line, `clusterRole.role` still "control-plane", and
		// no rebind ever. A fresh socket is exactly its recovery — after the
		// retired server is STOPPED: on a fatal Accept error grpc-go closes
		// the listener but not the transports Data Planes already hold, and
		// only Server.Stop closes those. Dropping the handle without it would
		// leave an orphaned server generation per listener fault, unreachable
		// by stopControlPlaneListener (Codex review of #1556). Shutdown can
		// still arrive between the check above and the retirement; the
		// teardown claim in releaseAttempt decides which side stops the
		// server, so the retirement never races Stop's GracefulStop.
		s.releaseAttempt() // retires the server: see releaseAttempt
		if !s.handleServeEnded(serveErr, backoff) {
			noteCPGRPCListenerStopped()
			return
		}
		backoff = nextCPGRPCBindBackoff(backoff)
	}
}

// releaseAttempt releases what the in-flight attempt holds. Who stops the
// server is decided FIRST, atomically (claimTeardown): exactly one of Stop and
// this loop tears down a given server, and neither ever enters a stop while
// the other can be in one. Then, by stage:
//
//   - not yet serving: close the bound listener (Serve never took it over)
//     and, if claimed, stop the server;
//   - serving, claimed, no Stop requested: RETIRE the server — on a fatal
//     Accept error grpc-go closes the listener but not the transports Data
//     Planes hold, and only Server.Stop closes those;
//   - serving, claimed, Stop requested (shutdown arrived after Serve ended but
//     before Stop could claim): the loop owns the graceful drain, bounded by
//     the same cpGRPCGracefulStopBudget Stop would have used;
//   - not claimed: Stop owns the teardown (graceful drain, then force) and
//     this loop only exits — stopping here would race Stop's GracefulStop.
//
// Always clears the published handle (the claim does). Idempotent;
// supervisor goroutine only.
func (s *cpListenerSupervisor) releaseAttempt() {
	a := s.cur
	s.cur = nil
	if a == nil || a.srv == nil {
		return
	}
	owned := s.claimTeardown(a)
	if !a.serving {
		_ = a.ln.Close()
	}
	switch {
	case !owned:
	case !a.serving:
		teardownCPGRPCServer(a.srv, false)
	case !s.stopRequested():
		retireCPGRPCServer(a.srv)
	default:
		teardownCPGRPCServer(a.srv, true)
	}
}

// abandonAfterPanic is the panic edge's release: whatever the interrupted
// stage held (releaseAttempt), then the CP role — a claim that is only true
// while a socket is real, and nothing will rebind now — restored to what this
// supervisor first replaced. Withdrawing this node from the fleet's address
// list is exitTerminal's, which follows (it applies to every terminal edge).
// Each step is contained: the panic being handled may have come from the very
// code a step reuses.
func (s *cpListenerSupervisor) abandonAfterPanic() {
	contained := func(f func()) {
		defer func() { _ = recover() }()
		f()
	}
	contained(s.releaseAttempt)
	if s.committed && s.haveOriginal {
		contained(func() {
			if restoreControlPlaneRole(s.original, s.cfg.addr) {
				s.committed = false
			}
		})
	}
}

// retireCPGRPCServer stops a server whose Serve already returned on its own,
// closing the client transports grpc-go leaves open after a fatal Accept
// error. Called only with the teardown claimed (releaseAttempt). A
// package-level seam so a gate can observe it — and interleave shutdown with
// it (TestChaos71_RetirementAndShutdownNeverStopTheSameServer).
var retireCPGRPCServer = func(srv *grpc.Server) { teardownCPGRPCServer(srv, false) }

// teardownCPGRPCServer is the ONE place a supervised *grpc.Server is stopped
// (TestChaos71_Wall_SupervisedGRPCServersHaveOneTeardownOwner). Its callers hold
// the teardown claim for srv (Stop, or releaseAttempt after claimTeardown), so
// no two stops of one server ever run concurrently. drain selects the bounded
// graceful drain (stopControlPlaneServer, cpGRPCGracefulStopBudget); otherwise
// it is an immediate Stop, which closes every transport and does not wait for
// handlers (the server is built without WaitForHandlers), so a wedged handler
// cannot hold it.
func teardownCPGRPCServer(srv *grpc.Server, drain bool) {
	if drain {
		stopControlPlaneServer(srv)
		return
	}
	srv.Stop()
}

// handleServeEnded records a serve that ended on its own and sleeps out the
// backoff through the SAME failure path as a failed bind (failAndWait), so the
// threshold clamp and the alert latch apply to both. Reports false when Stop
// interrupted the sleep.
func (s *cpListenerSupervisor) handleServeEnded(serveErr error, backoff time.Duration) (keepGoing bool) {
	reason := "serve_ended"
	if serveErr != nil {
		reason = classifyCPGRPCBindError(serveErr)
	}
	return s.failAndWait(func() (bool, time.Duration) { return noteCPGRPCServeEnded(reason, backoff) }, backoff,
		func(wait time.Duration) {
			logErrorf("ControlPlane gRPC serve on %s ended (%s): %v — rebinding in %s; this node's proxy data "+
				"plane and admin UI are unaffected", s.cfg.addr, reason, serveErr, wait.Round(time.Millisecond))
		})
}

// cpGRPCSleep is the supervisor's interruptible sleep. A package-level seam so
// a gate can observe the wait failAndWait chose without sleeping.
var cpGRPCSleep = haSleepInterruptible

// failAndWait is the ONE failure-and-backoff path for a failed bind, a
// rejected commit and a serve that ended: record through the shared recorder,
// release the starter, clamp the sleep at the unavailability threshold, log
// through the shared rate gate, sleep interruptibly.
//
// The clamp is load-bearing for BOTH callers: at the 30 s ceiling a jittered
// sleep can reach 36 s, and the alert is attempt-driven — nothing else wakes
// this loop — so an unclamped sleep would carry a dark listener past the
// threshold (where HA starts withholding its lease) with no page.
func (s *cpListenerSupervisor) failAndWait(record func() (shouldLog bool, failingFor time.Duration), backoff time.Duration, logLine func(wait time.Duration)) (keepGoing bool) {
	shouldLog, failingFor := record()
	// Released only AFTER the failure is recorded: the starter may return the
	// moment this fires, and it must never return to a state that has not been
	// written yet — the same window the success path closes, in miniature.
	s.markFirstAttempt()
	wait := clampCPGRPCBindSleep(jitterDuration(backoff, cpGRPCBindJitter), failingFor)
	if shouldLog {
		logLine(wait)
	}
	return cpGRPCSleep(s.stopping, wait)
}

// handleBindFailure records one failed bind attempt, logs it if the rate gate
// allows, and sleeps out the backoff. Reports false when Stop interrupted the
// sleep, in which case the caller must exit the loop.
//
// Extracted from run() purely to keep it inside funlen's 50-statement budget
// (reported by golangci-lint on this PR); the sequence and every comment below
// are unchanged from where they sat inline, because each step's ORDER is
// load-bearing.
func (s *cpListenerSupervisor) handleBindFailure(err error, backoff time.Duration) (keepGoing bool) {
	reason := classifyCPGRPCBindError(err)
	return s.failAndWait(func() (bool, time.Duration) { return noteCPGRPCBindFailure(reason, backoff, cpGRPCHealthNow()) }, backoff,
		func(wait time.Duration) {
			// The FULL error goes here and nowhere else: the contract row, the
			// alert and the readiness detail all carry the bounded class only.
			// logErrorf applies sanitizeLog (CWE-117) to the whole line.
			logErrorf("ControlPlane gRPC listener could not start on %s (%s): %v — retrying in %s; "+
				"this node's proxy data plane and admin UI are unaffected, and enrolled Data Planes "+
				"keep serving their last-good config",
				s.cfg.addr, reason, err, wait.Round(time.Millisecond))
		})
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

// cpGRPCBackoffAfterServe resets the rebind backoff to its floor once a serve
// has proven stable — it ran for at least cpGRPCServeStableAfter — and leaves
// it untouched otherwise, so a listener that dies right after every bind still
// escalates to the ceiling. Pure, so the policy is pinned without a clock.
func cpGRPCBackoffAfterServe(cur, served time.Duration) time.Duration {
	if served >= cpGRPCServeStableAfter {
		return cpGRPCBindBackoffInitial
	}
	return cur
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
	serverOpt, mode, err := cpServerOptionMode(cfg.certFile, cfg.keyFile, cfg.caFile)
	if err != nil {
		// Tag it so the classifier can name `tls_certificate` without matching
		// on the crypto/tls error text.
		return nil, nil, "", fmt.Errorf("%w: %w", errCPGRPCTLSMaterial, err)
	}

	srv := newControlPlaneGRPCServer(serverOpt)
	cpRegisterGRPCServices(srv)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", cfg.addr)
	if err != nil {
		srv.Stop()
		return nil, nil, "", fmt.Errorf("gRPC listen: %w", err)
	}
	return srv, cpWrapListener(ln), mode, nil
}

// cpRegisterGRPCServices registers the services one attempt's server serves:
// ConfigService in production. A seam so a gate can add a handler that wedges
// (TestChaos71_RetirementAndShutdownNeverStopTheSameServer).
var cpRegisterGRPCServices = func(srv *grpc.Server) { registerConfigService(srv) }

// cpWrapListener lets a gate observe (and fault) the bound listener. Identity
// in production.
var cpWrapListener = func(ln net.Listener) net.Listener { return ln }

// cpListenerStopWait bounds a caller's wait for a supervisor stop: the gRPC
// drain budget (cpGRPCStopBudget) plus half again for the forced close and
// the loop's exit. Derived, never hard-coded: a wait shorter than the drain
// expires while an in-flight Data Plane RPC still holds it (Codex P1
// 4303232156 on #1645, where a 5 s undo wait sat under the 8 s drain). No
// caller's correctness rests on it — an undo's release runs from the
// supervisor's exit (deactivate), whenever that comes.
func cpListenerStopWait() time.Duration {
	return cpGRPCStopBudget + cpGRPCStopBudget/2
}

// cpDeactivation is the undo in progress (deactivateControlPlane): non-nil
// from the moment it stops the supervisor until the supervisor's loop has
// exited and its activation has been released, then closed. Guarded by
// cpActivationMu. While it is set cpSupervisor still names the draining
// supervisor and the Control Plane role is still claimed, so an activation
// must not read either as "already running": it waits for this, or reports
// errCPDeactivating so the caller retries.
var cpDeactivation chan struct{}

// errCPDeactivating is the retryable refusal of an activation that arrives
// while an undo is still draining.
var errCPDeactivating = errors.New("a control-plane listener is still draining from a deactivation")

// undoPromoteControlPlane is the HA promote's undo (StartAsStandbyWithUndo):
// a promote whose activation completed but which then failed leaves no
// Control Plane behind (deactivateControlPlane). A package-level seam so a
// gate can observe it. Its wait covers the drain; if it still expires, the
// release completes on its own and a promote retry waits for it.
var undoPromoteControlPlane = func() {
	ctx, cancel := context.WithTimeout(context.Background(), cpListenerStopWait())
	defer cancel()
	if err := deactivateControlPlane(ctx); err != nil {
		logErrorf("ControlPlane: undoing a failed promote's activation is still in progress: %v", err)
	}
}

// deactivateControlPlane undoes a synchronous activation (activateControlPlane)
// that a failed HA promote completed: the supervisor stops (its server with
// it), and once its loop has exited the role it claimed is restored and
// address-list ownership released (releaseActivation). The node is then what
// it was before the activation, so the activation can run again. Nothing
// armed: a no-op.
//
// The release runs from the supervisor's exit, on the deactivation's own
// goroutine (deactivate), never from this waiter: ctx bounds only how long the
// caller waits. A wait that expires while an in-flight RPC holds the drain
// returns an error, and the release still completes when the drain does
// (Codex P1 4303232156 on #1645: the waiter cleared the handle, returned on
// its timeout and never released, so every later promote failed "already
// running as control-plane"). A second call while one is in progress joins it.
func deactivateControlPlane(ctx context.Context) error {
	done := beginCPDeactivation()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("the control plane listener is still draining; its release completes when the drain does: %w", ctx.Err())
	}
}

// beginCPDeactivation starts the undo of the armed supervisor, or joins the
// one in progress, and returns the channel its completion closes; nil when
// nothing is armed. The supervisor handle is KEPT until the release completes.
func beginCPDeactivation() <-chan struct{} {
	cpActivationMu.Lock()
	defer cpActivationMu.Unlock()
	if cpDeactivation != nil {
		return cpDeactivation
	}
	sup := cpSupervisor
	if sup == nil {
		return nil
	}
	done := make(chan struct{})
	cpDeactivation = done
	go sup.deactivate(done)
	return done
}

// deactivate stops the supervisor, waits for its loop to exit however long
// the drain takes, releases its activation, and only then drops the handle and
// ends the deactivation. The release is contained: a panic in it is recorded,
// and the deactivation still ends so a later activation is not refused
// forever. If grpc-go never lets the loop exit (gracefulStopBounded's
// hazards), the deactivation stays in progress and activations keep getting
// the retryable errCPDeactivating: the old server may still hold transports.
func (s *cpListenerSupervisor) deactivate(done chan struct{}) {
	defer func() {
		cpActivationMu.Lock()
		if cpSupervisor == s {
			cpSupervisor = nil
		}
		if cpDeactivation == done {
			cpDeactivation = nil
		}
		cpActivationMu.Unlock()
		close(done)
	}()
	defer func() {
		if v := recover(); v != nil {
			recordCrash("control-plane-deactivate", "", v)
		}
	}()
	_ = s.Stop(context.Background()) // unbounded on purpose: the release follows the exit
	s.releaseActivation()
}

// awaitCPDeactivation waits up to wait for an undo in progress to complete.
// It reports errCPDeactivating when it is still draining. The caller must not
// hold cpActivationMu: the deactivation takes it to end.
func awaitCPDeactivation(wait time.Duration) error {
	cpActivationMu.Lock()
	done := cpDeactivation
	cpActivationMu.Unlock()
	if done == nil {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("%w — retry once it completes", errCPDeactivating)
	}
}

// releaseActivation gives back what the supervisor's activation claimed: the
// Control Plane role (restored to what it first replaced, unless another
// writer has changed it since) and CP address-list ownership — after any
// withdrawal of this node from the committed list commits, as a terminal exit
// does (exitTerminal), but without its terminal report: an undo is not a
// listener failure. Health already reads not-serving here, as exitTerminal
// records it before its withdrawal: the loop's noteCPGRPCListenerStopped ran
// before Stop returned. Only after the loop exited (Stop returned), so s.committed
// and s.original are no longer the loop's. Its one caller is deactivate.
func (s *cpListenerSupervisor) releaseActivation() {
	if s.committed && s.haveOriginal && restoreControlPlaneRole(s.original, s.cfg.addr) {
		s.committed = false
	}
	_, _ = cpWithdrawCPAddress(s.cfg.addr)
	globalConfigStore.releaseCPAddressSourceAfterWithdrawal(s.cfg.addr)
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
