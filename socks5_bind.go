package main

// socks5_bind.go — CHAOS-66: the SOCKS5 listener's BIND, and which optional
// plane is allowed to kill the primary one.
//
// Why this file exists.
//
// `startSOCKS5` bound its listener with exactly one error branch:
//
//	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", port))
//	if err != nil {
//	        logFatalf("SOCKS5 listen error: %v", err)   // ← os.Exit(1)
//	}
//
// So EVERY way the OPTIONAL SOCKS5 listener could fail to bind terminated the
// whole appliance — and it did so from `initSOCKS5`, which main.go runs at
// line 239, BEFORE `startAdminUI` and before `buildAndStartProxyServer`. The
// HTTP/HTTPS proxy and the admin UI therefore never start at all.
//
// This is CHAOS-57's finding (§33, the admin UI listener) one plane over, and
// it lands strictly harder. There the management plane killed the data plane.
// Here a SECONDARY, opt-in data plane — SOCKS5 is off by default
// (`-socks5-port 0`) — kills the PRIMARY data plane *and* the management plane
// *and* the health endpoints, before any of them exist. CHAOS-57 recorded it as
// still open ("`startSOCKS5`'s BIND failure is still fatal — an occupied SOCKS5
// port takes down HTTP proxying"); this closes it.
//
// Reproduced against the real binary (not reasoned about). Port 11080 occupied
// by an unrelated process, then:
//
//	./culvert -port 18080 -ui-port 19090 -socks5-port 11080
//	...
//	SOCKS5 listen error: listen tcp :11080: bind: address already in use
//	EXIT CODE: 1
//	proxy http_code=000          ← the HTTP proxy port never listened
//	admin UI never announced     ← zero UI log lines: startAdminUI never ran
//
// The triggers are ROUTINE operational events, and none of them is visible to
// the one check that looks like it should catch them: `validatePortCollisions`
// (main.go) compares Culvert's own three ports to EACH OTHER only — nothing
// else on the host is in its field of view.
//
//   - The port is already bound: a predecessor container still draining, a
//     host-network service, an operator collision, a second Culvert instance.
//   - EACCES/EPERM: a privileged SOCKS5 port on a deployment that dropped
//     CAP_NET_BIND_SERVICE, or a container that stopped running as root.
//   - EADDRNOTAVAIL: binding before the interface the address lives on is up —
//     an ordinary host-boot race.
//
// Under `restart: unless-stopped` (docker-compose.yml, three services) each is
// an unattended CRASH LOOP: no proxy, no admin UI, no `/health`, no `/ready`,
// recoverable only with shell access. That is the same terminal state §19
// (CHAOS-50) closed for the category store and §33 closed for the admin UI,
// reached this time from an optional subsystem nobody may even be using.
//
// And "it exits, so it fails closed" is wrong here for the reason §33 states
// and this file must not re-argue: process death picks NO posture, it delegates
// the choice to the topology. An explicit-proxy fleet loses all egress; a
// PAC/WPAD fleet with a `DIRECT` fallback, or a transparent deployment that
// bypasses a dead next hop, goes UNFILTERED.
//
// What this file provides is the bind half of the listener's lifecycle: a
// supervisor that owns bind → serve → rebind, so a bind fault degrades the
// SOCKS5 service alone. The accept half (CHAOS-54) is unchanged and still lives
// in socks5.go; the observability for both is in socks5_health.go.
//
// Five rules, all borrowed wholesale from CHAOS-54/55/57 rather than invented
// as a second dialect:
//
//  1. No bind path is fatal. `startSOCKS5` always returns a live handle.
//  2. Retry is RATE-bounded, never COUNT-bounded. The terminal state of "give
//     up" is a configured service that is gone until someone restarts the
//     appliance — the outcome this change exists to remove. "Avoid infinite
//     retries" is satisfied the CHAOS-54/55 way: the retry is never SILENT.
//  3. Recovery is declared on OBSERVED evidence only — a listener that
//     actually bound. Elapsed time never clears the state, because a loop that
//     stopped failing because it stopped attempting looks identical to a bound
//     one.
//  4. The sleep is INTERRUPTIBLE, so `socks5-listener-stop` (2 s in the
//     shutdown sequence) never waits out a 30 s backoff.
//  5. Reason classes are BOUNDED and matched with `errors.As` on
//     `syscall.Errno`, never by string. The raw error reaches the rate-limited
//     log and nowhere else: an unbounded reason gives the alert dedup key one
//     value per failure (the WK-12/RS-5 defect) and would put the listener
//     address on a viewer-role surface.
//
// Deliberately NOT done: the proxy data plane's own
// `logFatalf("Proxy error")` is untouched and stays correct for §33's reason —
// the proxy IS the product, and a gateway that cannot serve must exit loudly
// rather than linger as a black hole. The asymmetry is the whole point of this
// change: an optional listener degrades, the primary one does not.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// socks5BindBackoffInitial / socks5BindBackoffMax bound the RATE of rebind
	// attempts, never their COUNT (rule 2 above).
	//
	// The floor is 1 s rather than the accept loop's 5 ms because these faults
	// are not machine-speed: a port frees when a predecessor finishes draining,
	// an interface comes up when the host finishes booting — both measured in
	// seconds. The ceiling is 30 s so a self-healed fault is picked up within
	// half a minute without hammering the bind. Both mirror
	// adminUIListenBackoff*, because it is the same fault class on the same
	// kind of socket.
	socks5BindBackoffInitial = 1 * time.Second
	socks5BindBackoffMax     = 30 * time.Second

	// socks5BindJitter spreads the backoff by ±20%. A fleet restarts together —
	// a compose `up`, a rolling reboot, a host bringing every container back at
	// once — and an unjittered cadence would aim a synchronised herd of rebind
	// attempts at the same instant (the WK-13 shape). Matches
	// adminUIListenJitter and haLeaseRecoveryJitter.
	socks5BindJitter = 0.20

	// socks5BindLogInterval rate-limits the bind-failure log line: the FIRST
	// failure of an episode is always logged (the operator must see the onset),
	// then one line per interval, then one recovery line carrying the
	// suppressed count. Same discipline as socks5AcceptLogInterval and
	// storage_health.go — the log carries the SIGNAL, the counter the
	// MAGNITUDE. A mitigation for a crash loop must not itself be a log flood.
	socks5BindLogInterval = 60 * time.Second

	// socks5BindUnavailableAfter is how long the listener must be continuously
	// unbindable before it is reported UNAVAILABLE (fail row, alert, gauge at
	// zero) rather than merely retrying.
	//
	// Unavailability is a DURATION, not a count — the CHAOS-54/57 rule. A
	// restart in which a predecessor still holds the port clears in a few
	// seconds, and paging on that would page on every ordinary redeploy.
	socks5BindUnavailableAfter = 30 * time.Second
)

// socks5Supervisor owns the SOCKS5 listener's whole lifecycle: bind, hand the
// bound listener to a socks5Server, wait for that server's accept loop to end,
// and rebind.
//
// It is deliberately a SEPARATE type wrapping an unmodified socks5Server rather
// than a rebind loop bolted inside it. socks5Server is the unit CHAOS-54's 18
// accept-loop gates construct directly from a pre-bound listener; keeping it
// byte-identical is what lets this change add a lifecycle without touching the
// semantics those gates pin.
type socks5Supervisor struct {
	port int

	// stopping is closed by Stop BEFORE anything else, so a backoff sleep is
	// interruptible and a bind that is in flight is not adopted. stopOnce keeps
	// Stop idempotent: closing a closed channel panics.
	stopping chan struct{}
	stopOnce sync.Once

	// done is closed when the supervisor loop exits.
	done chan struct{}

	// firstAttempt is closed once the loop has RESOLVED its first bind attempt,
	// one way or the other. startSOCKS5 waits on it so it cannot return while
	// every SOCKS5 surface still describes a listener that does not exist yet —
	// see the comment there.
	firstAttempt chan struct{}
	firstOnce    sync.Once

	// mu guards the handoff between the loop and Stop. stopped is the flag that
	// closes the adopt/Stop race: Stop sets it BEFORE reading cur, and adopt
	// refuses under the same lock, so a listener bound concurrently with Stop is
	// either stopped by Stop or closed by the loop — never left serving with
	// nobody waiting on it.
	mu      sync.Mutex
	cur     *socks5Server
	stopped bool
}

// startSOCKS5 starts the SOCKS5 listener supervisor and returns its shutdown
// handle. It never blocks on the bind and NEVER exits the process: see the file
// header for the finding this replaces.
//
// The feature is recorded as configured BEFORE the first bind attempt, not
// after a successful one. That ordering is the observability half of the fix
// and it is load-bearing: `noteSOCKS5Configured` gates every SOCKS5 surface,
// so recording it after the bind would report a listener that has NEVER come up
// as "SOCKS5 not configured" — indistinguishable from the ordinary appliance
// that never asked for SOCKS5, on exactly the node where an operator is trying
// to find out why SOCKS5 is unreachable. It is the same reasoning CHAOS-54
// applied one step later, when it moved this call ahead of the accept loop so a
// listener failing on its first Accept was reported against a configured
// service.
func startSOCKS5(port int) *socks5Supervisor {
	s := &socks5Supervisor{
		port:         port,
		stopping:     make(chan struct{}),
		done:         make(chan struct{}),
		firstAttempt: make(chan struct{}),
	}
	noteSOCKS5Configured(port)
	go s.run()

	// Wait for the FIRST bind attempt to resolve before returning.
	//
	// Without this, `configured` is true while the supervisor goroutine has not
	// run yet, and in that window every surface describes a listener that does
	// not exist: /healthz says `ready`, the report-only /readyz row says `ok`,
	// the contract row says "accepting connections", and
	// culvert_socks5_listener_up reads 1 — with no socket bound. That is the
	// same class of lie this whole change exists to remove, so reporting the
	// window accurately (a "pending" state) would be the weaker fix: better to
	// not have the window. Reported by Codex review on PR #1376.
	//
	// The wait is bounded by ONE bind(2), which does not block — and it is the
	// pre-CHAOS-66 behaviour, where startSOCKS5 bound synchronously before
	// returning. Only the fatal on failure is gone. `run` closes the channel
	// from a deferred call as well as after each attempt, so a panic before the
	// first attempt cannot hang startup.
	<-s.firstAttempt
	return s
}

// markFirstAttempt releases startSOCKS5 once the first bind attempt has
// resolved. Idempotent; safe to call from both the loop and its deferred guard.
func (s *socks5Supervisor) markFirstAttempt() {
	s.firstOnce.Do(func() { close(s.firstAttempt) })
}

// Stop interrupts the supervisor, stops the currently bound listener if there
// is one, and waits for the loop to exit — bounded by ctx. Nil-safe and
// idempotent, matching the socks5Server.Stop contract the shutdown hook was
// written against.
func (s *socks5Supervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stopping) })

	// Set stopped and read cur under ONE lock. adopt takes the same lock, so
	// either it has already published a listener (and we stop it here) or it
	// will refuse and close the listener itself.
	s.mu.Lock()
	s.stopped = true
	cur := s.cur
	s.mu.Unlock()

	var stopErr error
	if cur != nil {
		stopErr = cur.Stop(ctx)
	}

	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return stopErr
}

// Addr reports the address of the currently bound listener, or nil while the
// listener is unbound (before the first successful bind, or between a serve
// ending and the next rebind).
func (s *socks5Supervisor) Addr() net.Addr {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	return cur.Addr()
}

// adopt publishes srv as the current server, or reports false when Stop has
// already run — in which case the caller owns closing the listener.
func (s *socks5Supervisor) adopt(srv *socks5Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.cur = srv
	return true
}

// release clears the current server once its accept loop has ended.
func (s *socks5Supervisor) release(srv *socks5Server) {
	s.mu.Lock()
	if s.cur == srv {
		s.cur = nil
	}
	s.mu.Unlock()
}

// run is the bind/serve/rebind loop.
//
// The panic guard mirrors the accept loop's rather than using the bare
// recoverGoroutine: a panic here would otherwise leave the SOCKS5 service
// permanently gone with every surface still green, which is the CHAOS-24
// objection to recovering at the top of a worker goroutine. Reporting the
// listener DOWN — fail row, alert, gauge at zero — is the loudest state this
// subsystem can produce, so recovering is safe in the direction that matters.
func (s *socks5Supervisor) run() {
	defer close(s.done)
	// Runs AFTER the recover below (defers are LIFO), so startSOCKS5 is
	// released on every exit path including a panic.
	defer s.markFirstAttempt()
	defer func() {
		if v := recover(); v != nil {
			recordCrash("socks5-listener-bind", "", v)
			noteSOCKS5SupervisorDown("bind loop panicked")
		}
	}()

	addr := fmt.Sprintf(":%d", s.port)

	// The backoff is deliberately NEVER reset inside the loop, exactly as
	// serveAdminUIWithRetry does it. Resetting it on every successful bind
	// would let a socket that dies immediately after each bind settle into a
	// steady one-bind-per-floor cadence forever; letting it escalate
	// monotonically to the ceiling bounds that pathological case at one attempt
	// per 30 s. The cost is that a listener which recovers after a long
	// outage and only later loses its socket rebinds at the escalated rate
	// rather than the floor — bounded by the ceiling, and strictly better than
	// the pre-change behaviour, which never rebound at all.
	backoff := socks5BindBackoffInitial

	for {
		if s.stopRequested() {
			noteSOCKS5ListenerStopped()
			return
		}

		lc := &net.ListenConfig{}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			reason := classifySOCKS5BindError(err)
			wait := jitterDuration(backoff, socks5BindJitter)
			shouldLog := noteSOCKS5BindFailure(reason, backoff, time.Now())
			// Released only AFTER the failure is recorded: startSOCKS5 may
			// return the moment this fires, and it must never return to a
			// state that has not been written yet — that is the same window
			// in miniature.
			s.markFirstAttempt()
			if shouldLog {
				// The FULL error goes here and nowhere else: the contract row,
				// the alert and the readiness detail all carry the bounded
				// class only. logErrorf applies sanitizeLog (CWE-117) to the
				// whole line.
				logErrorf("SOCKS5 listener on port %d could not bind (%s): %v — retrying in %s; "+
					"the HTTP/HTTPS proxy data plane and the admin UI are unaffected",
					s.port, reason, err, wait.Round(time.Millisecond))
			}
			if !haSleepInterruptible(s.stopping, wait) {
				noteSOCKS5ListenerStopped()
				return
			}
			backoff = nextSOCKS5BindBackoff(backoff)
			continue
		}

		// The success line is emitted AFTER the bind, never before it. The
		// pre-CHAOS-66 code announced `SOCKS5: socks5://localhost:%d` from a
		// path that could only be reached by a successful bind, but the admin
		// UI's equivalent announced a listener that did not exist yet (§33);
		// keeping the announcement strictly downstream of the evidence is the
		// rule, not the accident of where it happened to sit.
		suppressed, recovered := noteSOCKS5Bound()
		s.markFirstAttempt() // after the bind is recorded, for the reason above
		if recovered {
			logger.Printf("SOCKS5: listener on port %d bound and accepting again (%d suppressed bind-failure log line(s))",
				s.port, suppressed)
		} else {
			logger.Printf("SOCKS5: socks5://localhost:%d", s.port)
		}

		srv := newSOCKS5Server(ln)
		if !s.adopt(srv) {
			// Stop won the race: close the listener we just bound rather than
			// serving on a socket nobody will ever stop.
			_ = ln.Close()
			noteSOCKS5ListenerStopped()
			return
		}
		srv.Start()
		<-srv.done
		s.release(srv)

		if s.stopRequested() {
			noteSOCKS5ListenerStopped()
			return
		}

		// The accept loop ended on its own. CHAOS-54 stops it only when the
		// listening socket is unrecoverable (EBADF/ENOTSOCK/EINVAL/...) or it
		// panicked, and both paths have already recorded the listener DOWN —
		// so there is nothing to classify here, only to pace. Before this
		// change that state was terminal for the process; a fresh socket is
		// exactly its recovery, and the pacing sleep is what keeps a socket
		// that dies immediately after every bind from becoming a hot loop.
		wait := jitterDuration(backoff, socks5BindJitter)
		if !haSleepInterruptible(s.stopping, wait) {
			noteSOCKS5ListenerStopped()
			return
		}
		backoff = nextSOCKS5BindBackoff(backoff)
	}
}

// stopRequested reports whether Stop has been called.
func (s *socks5Supervisor) stopRequested() bool {
	select {
	case <-s.stopping:
		return true
	default:
		return false
	}
}

// nextSOCKS5BindBackoff advances the rebind backoff: 1 s on the first failure,
// doubling, capped at 30 s.
func nextSOCKS5BindBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return socks5BindBackoffInitial
	}
	cur *= 2
	if cur > socks5BindBackoffMax {
		return socks5BindBackoffMax
	}
	return cur
}
