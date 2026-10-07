package main

// cp_grpc_supervisor.go — CHAOS-71: the Control Plane gRPC listener's
// lifecycle, and which plane is allowed to kill which.
//
// Why this file exists.
//
// TWO coupled defects, and the coupling is the reason they ship together.
//
// (1) THE BOOT PATH WAS FATAL. `startControlPlaneWithHAResume` had exactly one
// error branch for the Control Plane listener:
//
//	if err := enableControlPlane(cfg.CPAddr, cfg.CPCert, cfg.CPKey, cfg.CPCA, cfg.ClusterDBPath); err != nil {
//	        logFatalf("ControlPlane gRPC: %v", err)      // ← os.Exit(1)
//	}
//
// and it is reached from `initCluster`, which main.go runs at line 228 — BEFORE
// `startAdminUI` (line 269) and before `buildAndStartProxyServer` (line 271).
// So every way the CLUSTER CONTROL plane's listener could fail to bind
// terminated the whole appliance, and the HTTP/HTTPS proxy, the admin UI and
// the health endpoints never started at all.
//
// This is CHAOS-57's finding (§33, the admin UI listener) and CHAOS-66's (§36,
// the SOCKS5 bind) a third time, on the plane CHAOS-66's own note named as "the
// closest unexamined analogue". It lands differently from both: CHAOS-57 was a
// management plane killing the data plane on one node, CHAOS-66 an OPTIONAL
// data plane killing the primary one. Here the FLEET's control plane kills the
// node's primary data plane — and the node in question is a gateway carrying
// production traffic, because a Culvert CP is also a proxy.
//
// Reproduced against the real binary (not reasoned about). Port 19443 held by
// an unrelated listener, then:
//
//	./culvert -port 18080 -ui-port 19090 -ui-no-tls -cp-grpc-addr 127.0.0.1:19443 -cluster-insecure
//	...
//	ControlPlane gRPC: gRPC listen: listen tcp 127.0.0.1:19443: bind: address already in use
//	EXIT CODE: 1
//	proxy http_code=000          ← the HTTP proxy port never listened
//	adminui http_code=000        ← the admin UI port never listened
//	0 proxy/admin-UI/SOCKS5 startup lines in the log
//
// The triggers are ROUTINE, and none is visible to `validatePortCollisions`,
// which compares Culvert's own three ports to EACH OTHER only:
//
//   - The port is already bound: a predecessor container still draining, a
//     second Culvert, a host service, an HA planned handoff that hands this
//     very port between two processes.
//   - EACCES/EPERM: a privileged CP port on a deployment that dropped
//     CAP_NET_BIND_SERVICE or stopped running as root.
//   - EADDRNOTAVAIL: `-cp-grpc-addr` names an address that is not up yet. This
//     one is the common case for a CP specifically, because an HA pair is
//     routinely fronted by a floating/VIP address — binding before the
//     interface carries it is an ordinary host-boot race.
//
// Under `restart: unless-stopped` each is an unattended CRASH LOOP: no proxy,
// no admin UI, no `/health`, no `/ready`, recoverable only with shell access.
// And "it exits, so it fails closed" is wrong for the reason §33 and §36 both
// state and this file must not re-argue: process death picks NO posture, it
// delegates the choice to the topology.
//
// (2) A LISTENER THAT DIED WAS INVISIBLE — and this is why (1) could not be
// fixed alone. The serve half was:
//
//	go func() {
//	        if err := srv.Serve(ln); err != nil {
//	                logger.Printf("ControlPlane gRPC error: %v", err)
//	        }
//	}()
//
// One log line, then the goroutine exits. Nothing rebinds, and nothing reports
// it: `clusterRole.grpcSrv` was written once and read in exactly one other
// place (StopControlPlaneGRPC), so no surface in the process ever asked whether
// the listener was alive. `/healthz` kept answering
// `{"status":"ok","role":"leader","write_authority":true}`, there was no
// `/health` field, no `/metrics` series and no `/api/diagnostics` row for it —
// while the admin UI listener and the SOCKS5 listener each had all four.
//
// Worse, the FENCE kept vouching for it. `leaseKeepaliveLoop` (ha_lease.go)
// renews against etcd on a pure ticker and has no knowledge of the gRPC server,
// so a leader whose control plane was dark went on holding the fencing lease
// against its own standby — which is the exact INVERSE of CHAOS-55: that sweep
// handled a leader that cannot WRITE (unfenced), this one a leader that holds
// the fence and cannot be REACHED. Every Data Plane is then frozen on its last
// snapshot, no node can enroll or renew a certificate, and the two mechanisms
// an operator would trust to notice — the leader's own health endpoint and the
// HA fence — both report a healthy leader.
//
// So making the bind non-fatal WITHOUT (2) would have been a REGRESSION: it
// converts a loud crash loop into a silent dark control plane that reports
// `status: ok` and holds the fence. CHAOS-57 and CHAOS-66 both shipped their
// health plane in the same change for this reason; here the stakes are higher
// because of the fence, which is why the two halves are one change.
//
// The five rules, borrowed wholesale from CHAOS-54/55/57/66 rather than
// invented as a fourth dialect:
//
//  1. No bind path is fatal on the BOOT path. (The two runtime callers keep
//     their error returns — see the contract note on startCPGRPCSupervisor.)
//  2. Retry is RATE-bounded, never COUNT-bounded. "Avoid infinite retries" is
//     satisfied the CHAOS-54/55 way: the retry is never SILENT.
//  3. Recovery is declared on OBSERVED evidence only — a listener that
//     actually bound. Elapsed time never clears the state.
//  4. The sleep is INTERRUPTIBLE, so the shutdown sequence never waits out a
//     30 s backoff.
//  5. Reason classes are BOUNDED and matched with `errors.As` on
//     `syscall.Errno`, never by string — and via the SHARED classifier
//     (listener_fault_class.go), not a third copy.
//
// Deliberately NOT done, and recorded in the register rather than decided here:
// the /healthz HTTP status and `status` string are unchanged for a dark leader,
// and a dark leader does not surrender the fencing lease. Both are POSTURE
// decisions with an availability cost (a planned CP handoff moves this port
// between two processes, so a hair-trigger would flap a healthy pair) and both
// belong to the owner. See cpGRPCHealthzFields and register row CP-4.

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// cpGRPCSupervisor owns the Control Plane gRPC listener's whole lifecycle:
// bind, serve, and — when a bound listener's Serve returns without a shutdown
// having been asked for — rebind.
//
// It owns the *grpc.Server handle itself rather than publishing it to
// `clusterRole.grpcSrv`, and that move is MANDATORY rather than tidy. The old
// assignment took no lock at all (a pre-existing unguarded write that was
// harmless only because it happened exactly once, at startup, before anything
// read it). A rebind loop writes that handle repeatedly from a background
// goroutine while StopControlPlaneGRPC reads it, which makes it a genuine data
// race the detector would flag. It cannot be fixed by taking `clusterRoleMu`:
// `enableControlPlane` holds that lock across its whole body INCLUDING the
// first bind, so acquiring it from the bind path would deadlock on the very
// first attempt. The handle therefore gets its own mutex, which is also the
// honest ownership — a server handle is supervisor state, not role metadata.
type cpGRPCSupervisor struct {
	addr     string
	certFile string
	keyFile  string
	caFile   string

	// stopping is closed by Stop BEFORE anything else, so a backoff sleep is
	// interruptible and a bind in flight is not adopted. stopOnce keeps Stop
	// idempotent: closing a closed channel panics.
	stopping chan struct{}
	stopOnce sync.Once

	// done is closed when the supervisor loop exits.
	done chan struct{}

	// firstAttempt is closed once the loop has RESOLVED its first bind attempt,
	// one way or the other, and firstErr carries that attempt's outcome.
	// startCPGRPCSupervisor waits on it so it never returns while every CP
	// surface still describes a listener that does not exist yet — CHAOS-66's
	// Codex-round rule, and the reason this is a wait rather than a "pending"
	// state: better to not have the window than to report it.
	firstAttempt chan struct{}
	firstOnce    sync.Once
	firstErr     error

	// mu guards the handoff between the loop and Stop. stopped is the flag that
	// closes the adopt/Stop race: Stop sets it BEFORE reading srv, and adopt
	// refuses under the same lock, so a server bound concurrently with Stop is
	// either stopped by Stop or stopped by the loop — never left serving with
	// nobody waiting on it.
	mu      sync.Mutex
	srv     *grpc.Server
	stopped bool
}

// errCPGRPCSupervisorStopped is the first-attempt outcome reported when the
// supervisor loop exits without having resolved a bind attempt — today only a
// contained panic before the first attempt. It is deliberately an ERROR rather
// than nil so every caller fails closed; see the fallback marker in run().
var errCPGRPCSupervisorStopped = errors.New("control plane grpc supervisor stopped before its first bind attempt")

// globalCPGRPC is the process's Control Plane listener supervisor, or nil on a
// node that never started one. Guarded by globalCPGRPCMu.
var (
	globalCPGRPCMu sync.Mutex
	globalCPGRPC   *cpGRPCSupervisor
)

// startCPGRPCSupervisor starts the supervisor and waits for its FIRST bind
// attempt to resolve, returning that attempt's error.
//
// THE CONTRACT, which the three callers rely on differently and which must not
// be collapsed:
//
//   - It returns the first attempt's error, so a caller that needs a
//     synchronous verdict still gets one. That is what preserves
//     `enableControlPlane`'s existing semantics for the two RUNTIME callers.
//
//   - It does NOT stop itself on a failed first attempt. The caller decides,
//     because the right answer differs per caller and getting it wrong is a
//     correctness bug rather than a style choice:
//
//     BOOT (`startControlPlaneWithHAResume`) — keep retrying. This node is
//     configured and persisted as a Control Plane; it is SUPPOSED to hold this
//     port, so a transient fault must self-heal. This is the caller whose
//     `logFatalf` is being removed.
//
//     ADMIN API (`apiClusterCP` → `enableControlPlane`) — stop and report.
//     An admin asking to enable a CP must get the error, and leaving a
//     supervisor retrying behind a 409 would bind the port later, out of band,
//     with no role transition to match it.
//
//     HA PROMOTION (`onPromote` → `enableControlPlane`) — stop and report, and
//     this one is load-bearing for cluster safety. `promote()` treats an
//     `onPromote` error as "stay standby" and resets its once-guard; a
//     supervisor left retrying would then bind the CP port on a node that is
//     NOT the leader, which is a second listener for a role this node does not
//     hold. A STANDBY MUST NEVER HOLD THE CP PORT.
//
// The wait is bounded by one non-blocking bind(2) plus TLS material assembly —
// it is the pre-CHAOS-71 behaviour, where the bind was synchronous. Only the
// fatal is gone.
func startCPGRPCSupervisor(addr, certFile, keyFile, caFile string) (*cpGRPCSupervisor, error) {
	s := &cpGRPCSupervisor{
		addr:         addr,
		certFile:     certFile,
		keyFile:      keyFile,
		caFile:       caFile,
		stopping:     make(chan struct{}),
		done:         make(chan struct{}),
		firstAttempt: make(chan struct{}),
	}

	// Recorded as configured BEFORE the first attempt — see the `configured`
	// field comment in cp_grpc_health.go. A CP that never binds must report as
	// a BROKEN control plane, not as "no control plane configured".
	noteCPGRPCConfigured(addr)

	go s.run()
	<-s.firstAttempt
	return s, s.firstErr
}

// markFirstAttempt releases startCPGRPCSupervisor once the first bind attempt
// has resolved. Idempotent; safe to call from both the loop and its deferred
// guard, so a panic before the first attempt cannot hang startup.
func (s *cpGRPCSupervisor) markFirstAttempt(err error) {
	s.firstOnce.Do(func() {
		s.firstErr = err
		close(s.firstAttempt)
	})
}

// Stop interrupts the supervisor and stops the currently bound server, bounded
// by the existing gracefulStopBounded budget. Nil-safe and idempotent.
func (s *cpGRPCSupervisor) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopping) })

	// Set stopped and read srv under ONE lock. adopt takes the same lock, so
	// either it has already published a server (and we stop it here) or it
	// will refuse and stop it itself.
	s.mu.Lock()
	s.stopped = true
	srv := s.srv
	s.mu.Unlock()

	if srv != nil {
		// CHAOS-56's bound, unchanged: GracefulStop on its own goroutine under
		// a budget, then Stop() to force-close. See gracefulStopBounded for why
		// neither half may be simplified.
		if gracefulStopBounded(srv, cpGRPCGracefulStopBudget) {
			logger.Printf("ControlPlane: gRPC stopped")
		} else {
			logger.Printf("ControlPlane: gRPC drain exceeded %s — force-closed connections", cpGRPCGracefulStopBudget)
		}
	}

	<-s.done
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

// adopt publishes srv as the current server, or reports false when Stop has
// already run — in which case the caller owns stopping it.
func (s *cpGRPCSupervisor) adopt(srv *grpc.Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.srv = srv
	return true
}

// release clears the current server once its Serve has returned.
func (s *cpGRPCSupervisor) release(srv *grpc.Server) {
	s.mu.Lock()
	if s.srv == srv {
		s.srv = nil
	}
	s.mu.Unlock()
}

// server returns the currently bound server, or nil while unbound.
func (s *cpGRPCSupervisor) server() *grpc.Server {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv
}

// run is the bind/serve/rebind loop.
//
// The panic guard mirrors the SOCKS5 supervisor's rather than using the bare
// recoverGoroutine: a panic here would otherwise leave the Control Plane
// permanently gone with every surface still green, which is the CHAOS-24
// objection to recovering at the top of a worker goroutine. Reporting the
// listener unavailable — fail row, alert, gauge at zero — is the loudest state
// this subsystem can produce, so recovering is safe in the direction that
// matters.
func (s *cpGRPCSupervisor) run() {
	defer close(s.done)
	// The FALLBACK marker. It runs AFTER the recover below (defers are LIFO),
	// so startCPGRPCSupervisor is released on every exit path including a
	// panic. It reports a FAILURE, never nil, and that direction is
	// load-bearing. This defer exists for the paths that reach it without the
	// loop having resolved an attempt — a panic before the first bind, or any
	// future early return — and markFirstAttempt is idempotent, so a resolved
	// attempt has already won and this call is a no-op.
	//
	// The first version of this file passed nil here, which was a defect of
	// exactly the class this sweep exists to close: a panic before the first
	// bind would report SUCCESS to startCPGRPCSupervisor, so
	// StartControlPlaneGRPC would return nil, enableControlPlane would set
	// role=control-plane, and HA PROMOTION WOULD PROMOTE THIS NODE TO LEADER
	// WITH NO LISTENER AND NO SUPERVISOR — the dark-leader state §41 was
	// written to eliminate, reintroduced through its own fix. Fail closed: an
	// unresolved attempt is not a successful one.
	defer func() { s.markFirstAttempt(errCPGRPCSupervisorStopped) }()
	defer func() {
		if v := recover(); v != nil {
			recordCrash("cp-grpc-listener-bind", "", v)
			noteCPGRPCServeExit("supervisor_panicked", time.Now())
		}
	}()

	// The backoff is deliberately NEVER reset inside the loop, exactly as
	// serveAdminUIWithRetry and the SOCKS5 supervisor do it. Resetting it on
	// every successful bind would let a socket that dies immediately after each
	// bind settle into a steady one-bind-per-floor cadence forever; letting it
	// escalate monotonically to the ceiling bounds that pathological case at
	// one attempt per 30 s. The cost is that a listener which recovers after a
	// long outage and only later loses its socket rebinds at the escalated rate
	// rather than the floor — bounded by the ceiling, and strictly better than
	// the pre-change behaviour, which never rebound at all.
	backoff := cpGRPCBindBackoffInitial

	for {
		if s.stopRequested() {
			noteCPGRPCStopped()
			return
		}

		srv, ln, err := bindCPGRPC(s.addr, s.certFile, s.keyFile, s.caFile)
		if err != nil {
			reason := classifyCPGRPCListenError(err)
			shouldLog, failingFor := noteCPGRPCBindFailure(reason, backoff, time.Now())
			// Released only AFTER the failure is recorded: the caller may
			// return the moment this fires, and it must never return to a
			// state that has not been written yet.
			s.markFirstAttempt(err)
			// Clamped so this sleep cannot carry us past the unavailability
			// threshold without an attempt to observe it — the alert is
			// attempt-driven and nothing else wakes this loop.
			wait := clampCPGRPCBindSleep(jitterDuration(backoff, cpGRPCBindJitter), failingFor)
			if shouldLog {
				// The FULL error goes here and nowhere else: the contract row,
				// the alert and the readiness detail all carry the bounded
				// class only. logErrorf applies sanitizeLog (CWE-117).
				logErrorf("ControlPlane gRPC listener on %s could not bind (%s): %v — retrying in %s; "+
					"this node's HTTP/HTTPS proxy and admin UI are unaffected, and Data Plane nodes keep "+
					"serving on their last synced configuration",
					s.addr, reason, err, wait.Round(time.Millisecond))
			}
			if !haSleepInterruptible(s.stopping, wait) {
				noteCPGRPCStopped()
				return
			}
			backoff = nextCPGRPCBindBackoff(backoff)
			continue
		}

		if !s.adopt(srv) {
			// Stop ran between the bind and the publish. We own the cleanup.
			_ = ln.Close()
			srv.Stop()
			noteCPGRPCStopped()
			return
		}

		// Recorded AFTER the bind, never before it, so the success line and
		// every surface describe a socket that provably exists.
		wasFailing, suppressed, failures := noteCPGRPCBound()
		if wasFailing {
			logger.Printf("ControlPlane: gRPC listener on %s recovered after %d failed attempt(s) "+
				"(%d further log line(s) suppressed)", s.addr, failures, suppressed)
		} else {
			// The ONE transport line, emitted AFTER an observed bind and only
			// for a FIRST bind. cpServerOption used to emit it itself, which
			// was correct while it ran once per boot and became a per-retry
			// flood the moment this loop existed — see the note there. A
			// recovery (wasFailing) gets the recovery line above instead, so a
			// flapping socket cannot produce one of each per cycle.
			logger.Printf("ControlPlane: gRPC %s (%s)",
				strings.ReplaceAll(s.addr, "\n", ""), cpTransportPosture(s.certFile, s.keyFile))
		}
		s.markFirstAttempt(nil)

		// Serve blocks until the listener is closed or an unrecoverable accept
		// error occurs. grpc-go backs off internally on temporary accept
		// errors and returns only when the listener is genuinely gone, so a
		// return here means the socket needs rebinding.
		serveErr := srv.Serve(ln)
		s.release(srv)

		if s.stopRequested() {
			noteCPGRPCStopped()
			return
		}

		// A BOUND listener's Serve returned and nobody asked for a shutdown.
		// This is the half that used to be one log line and a dead goroutine.
		reason := classifyCPGRPCListenError(serveErr)
		noteCPGRPCServeExit(reason, time.Now())
		// Deliberately NOT behind the bind-failure rate gate, and the bound is
		// STRUCTURAL rather than a timer: this line costs a full bind + serve
		// + backoff cycle to emit, and the backoff escalates monotonically to
		// the 30 s ceiling and is never reset, so the rate can only ever FALL
		// — at worst two lines per 30 s against the rate gate's one per 60 s.
		// Each occurrence is also a distinct state TRANSITION (a working
		// socket went away) rather than a repeated poll of an unchanged
		// condition, which is the CHAOS-61 "one line per transition" case
		// rather than the CHAOS-63 amplification case. If a future change ever
		// resets the backoff on a successful bind, this line needs the gate.
		logErrorf("ControlPlane gRPC listener on %s stopped serving unexpectedly (%s): %v — rebinding; "+
			"Data Plane nodes cannot sync configuration until it is back",
			s.addr, reason, serveErr)

		wait := jitterDuration(backoff, cpGRPCBindJitter)
		if !haSleepInterruptible(s.stopping, wait) {
			noteCPGRPCStopped()
			return
		}
		backoff = nextCPGRPCBindBackoff(backoff)
	}
}

// bindCPGRPC assembles the TLS material, constructs a FRESH *grpc.Server, and
// binds the listener.
//
// A fresh server per attempt is required, not preferred: a *grpc.Server cannot
// be reused after Stop or after Serve returns, so a rebind loop that reused one
// would serve nothing on every attempt after the first.
//
// The server options and the registration are byte-identical to the
// pre-CHAOS-71 StartControlPlaneGRPC — the frame budgets, the gzip codec
// posture and the nil-impl registration all carry their original reasoning and
// are not re-derived here.
func bindCPGRPC(addr, certFile, keyFile, caFile string) (*grpc.Server, net.Listener, error) {
	serverOpt, err := cpServerOption(addr, certFile, keyFile, caFile)
	if err != nil {
		// Tagged so the classifier can name it without matching on text. The
		// wrap keeps the original error readable in the rate-limited log line.
		return nil, nil, wrapCPGRPCTLSMaterial(err)
	}

	srv := grpc.NewServer(
		serverOpt,
		grpc.MaxRecvMsgSize(maxClusterInboundMsgSize),
		grpc.MaxSendMsgSize(maxClusterGRPCMsgSize),
	)
	registerConfigService(srv)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		srv.Stop()
		return nil, nil, err
	}
	return srv, ln, nil
}
