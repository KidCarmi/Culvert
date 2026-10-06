package main

// cp_grpc_recovery.go — CHAOS-73: the Control Plane gRPC listener's way back.
//
// The shape, and why it is this shape rather than a supervisor owning the
// listener outright (as §36's socks5Supervisor does).
//
// `enableControlPlane` has three callers and only ONE of them was fatal (see
// cp_grpc_health.go for the full asymmetry). The other two are not merely
// tolerable, they are LOAD-BEARING:
//
//	ha.go promote() — "On an onPromote failure the guard is reset so a later
//	attempt can retry" (CHAOS-25). promote() uses the returned error to decide
//	it is NOT a leader. If `enableControlPlane` were made to swallow a bind
//	failure and retry in the background, a promotion would read as SUCCESS: the
//	node would assert leadership, keep the fencing lease it just acquired, bump
//	its term, persist role=leader — and publish config no Data Plane can fetch.
//	A leader nobody can reach, while the standby it replaced has stood down. In
//	a fencing-lease deployment it holds the lease that stops anyone else leading.
//	That is strictly WORSE than the fault being fixed.
//
// So the primitive is left EXACTLY as it is — one shot, returns an error — and
// the recovery loop wraps the BOOT caller only. This is CHAOS-55's
// `ha_lease_recovery.go` shape (a bounded-rate background loop over an
// unchanged one-shot acquire) rather than CHAOS-66's supervisor shape, chosen
// because here the one-shot's error is part of another subsystem's contract.
//
// **Do not "unify" this by moving the retry inside enableControlPlane.**
//
// Two further decisions worth keeping.
//
// THE RETRY DOES NOT RE-PUBLISH. `enableControlPlane` does its durable,
// fleet-visible work — `armVersionPersistence`, `Update(CurrentConfigSnapshot())`,
// `initClusterCA` — BEFORE the bind, so on a bind failure all of it has already
// happened and only the role transition has not. A loop that re-ran the whole
// function would advance the persisted config-version floor on every attempt
// (register row CP-6), so the loop calls `retryControlPlaneGRPC`, which
// re-attempts the LISTENER and, on success, completes exactly the part that was
// skipped: the role fields and the heartbeat monitor. One consequence worth
// noting as a side benefit: removing the crash loop removes the per-restart
// floor ratchet that CP-6 describes, without touching CHAOS-01's seeding order.
//
// THE CERTIFICATE IS RE-READ ON EVERY ATTEMPT. `cpServerOption` reads
// `-cp-grpc-cert`/`-cp-grpc-key` at call time, and the loop calls it again each
// time, so a rotation that momentarily truncates or re-permissions the pair
// self-heals with no restart. This is CHAOS-57's rule 4 applied here; the
// pre-change path read the pair exactly once, at boot, which is why a
// three-second rotation window was a permanent crash loop.

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// errCPGRPCTLSRequired is the policy refusal `cpServerOption` returns when
// neither a TLS pair nor --cluster-insecure was supplied. It is tagged as its
// own sentinel because it is NOT an environmental fault: nothing on the host
// will change to make it succeed, so it must be classified (and remedied)
// differently from a busy port. The loop still retries it — at the 30 s ceiling,
// and never silently — because the operator's fix is a restart with the right
// flags anyway, and a loop that gave up would leave the surfaces frozen at
// whatever they said when it stopped.
var errCPGRPCTLSRequired = errors.New("control plane grpc tls required")

// cpGRPCRecovery owns the stop channel for the recovery loop. Mirrors the admin
// UI's adminUIStop machinery rather than inventing a second idiom.
var cpGRPCRecovery struct {
	mu     sync.Mutex
	stopCh chan struct{}
	closed bool
	// running guards against two loops for one listener. The loop is armed from
	// the boot path AND from the serve-exit observer, which can both be live on
	// a node that bound, fell over, and is now rebinding.
	running bool
	// onRecovered is the run-once continuation described on cpGRPCOnRecovered.
	onRecovered func()
}

// armCPGRPCRecovery starts the recovery loop if one is not already running.
// Returns false when a loop was already live (the caller has nothing to do).
func armCPGRPCRecovery() bool {
	cpGRPCRecovery.mu.Lock()
	if cpGRPCRecovery.running {
		cpGRPCRecovery.mu.Unlock()
		return false
	}
	cpGRPCRecovery.running = true
	if cpGRPCRecovery.stopCh == nil {
		cpGRPCRecovery.stopCh = make(chan struct{})
		cpGRPCRecovery.closed = false
	}
	stop := cpGRPCRecovery.stopCh
	cpGRPCRecovery.mu.Unlock()

	go runCPGRPCRecoveryLoop(stop)
	return true
}

// stopCPGRPCRecovery closes the stop channel so the loop exits promptly. Called
// from the shutdown path, BEFORE the gRPC server is stopped, so the loop can
// never observe the shutdown's own listener teardown as a fault and rebind on
// the way out.
func stopCPGRPCRecovery() {
	cpGRPCRecovery.mu.Lock()
	defer cpGRPCRecovery.mu.Unlock()
	if cpGRPCRecovery.stopCh != nil && !cpGRPCRecovery.closed {
		close(cpGRPCRecovery.stopCh)
		cpGRPCRecovery.closed = true
	}
}

// resetCPGRPCRecoveryForTest re-arms the stop machinery between tests. A leaked
// closed channel makes every later test's loop exit on its first iteration, and
// a leaked `running` flag makes armCPGRPCRecovery a no-op for the rest of the
// binary — both silent, both the pollution class the determinism gate catches.
func resetCPGRPCRecoveryForTest() {
	cpGRPCRecovery.mu.Lock()
	defer cpGRPCRecovery.mu.Unlock()
	cpGRPCRecovery.stopCh = nil
	cpGRPCRecovery.closed = false
	cpGRPCRecovery.running = false
	cpGRPCRecovery.onRecovered = nil
}

// cpGRPCOnRecovered registers a continuation to run ONCE, on the recovery
// loop's successful bind. The boot path uses it to defer the ADR-0004
// leadership resume behind the listener: leadership follows the listener, so a
// restarted leader whose port was briefly occupied resumes leadership when the
// listener comes up rather than never (dropped) or immediately (asserting
// leadership nobody can reach). See cluster_startup.go for the two rejected
// alternatives.
//
// Stored rather than passed as an argument because the loop is armed from two
// places — the boot path, which has a continuation, and the serve-exit
// observer, which does not (a node whose listener fell over has already
// resumed leadership, and running the resume a second time would re-assert a
// role it already holds).
func cpGRPCOnRecovered(fn func()) {
	cpGRPCRecovery.mu.Lock()
	cpGRPCRecovery.onRecovered = fn
	cpGRPCRecovery.mu.Unlock()
}

// takeCPGRPCOnRecovered removes and returns the continuation, so it can only
// run once however many times the loop is armed.
func takeCPGRPCOnRecovered() func() {
	cpGRPCRecovery.mu.Lock()
	defer cpGRPCRecovery.mu.Unlock()
	fn := cpGRPCRecovery.onRecovered
	cpGRPCRecovery.onRecovered = nil
	return fn
}

// cpGRPCRecoveryAttempt is the seam the loop calls once per iteration. Swapped
// in tests so the cadence, the classification, the rate gate and the recovery
// accounting can be driven without binding a real port.
//
// nil-defaulted rather than initialised to retryControlPlaneGRPC because the
// real chain is cyclic at package-initialisation time (the attempt calls
// StartControlPlaneGRPC, whose serve goroutine arms this loop); cpGRPCAttempt
// resolves it at CALL time, which is also when a test's override must take
// effect.
var cpGRPCRecoveryAttempt func() error

func cpGRPCAttempt() error {
	if cpGRPCRecoveryAttempt != nil {
		return cpGRPCRecoveryAttempt()
	}
	return retryControlPlaneGRPC()
}

// cpGRPCStopRequested reports whether a shutdown has been requested, so the
// serve goroutine can tell a clean teardown from a dead accept loop without
// resting that distinction on grpc-go returning nil (the CHAOS-56 rule).
func cpGRPCStopRequested() bool {
	cpGRPCRecovery.mu.Lock()
	defer cpGRPCRecovery.mu.Unlock()
	return cpGRPCRecovery.closed
}

// runCPGRPCRecoveryLoop re-attempts the CP gRPC listener until it binds, the
// node shuts down, or the process ends.
//
// Rate-bounded, never count-bounded; jittered; interruptible. The three
// properties are not independent: unbounded in count is what makes the loop a
// recovery path rather than a delayed crash, rate-bounded is what stops it
// being an amplifier, and interruptible is what keeps the shutdown budget
// honest (the loop must never be found sitting out a 30 s backoff while a hook
// waits on it).
func runCPGRPCRecoveryLoop(stop <-chan struct{}) {
	defer recoverGoroutine("cp-grpc-recovery")
	defer func() {
		cpGRPCRecovery.mu.Lock()
		cpGRPCRecovery.running = false
		cpGRPCRecovery.mu.Unlock()
	}()

	backoff := cpGRPCListenBackoffInitial
	for {
		select {
		case <-stop:
			noteCPGRPCStopped()
			return
		default:
		}

		err := cpGRPCAttempt()
		if err == nil {
			// Recovery is declared on OBSERVED evidence — a listener that
			// actually bound — never on elapsed time.
			suppressed := noteCPGRPCServing()
			logger.Printf("ControlPlane gRPC: listener recovered on %s and is serving again%s",
				sanitizeLog(cpGRPCListenerState().Addr), suppressedSuffix(suppressed))
			// Taken (not merely called) so it runs at most once, and run
			// AFTER the listener is recorded as serving: the continuation
			// asserts leadership, and every surface it touches must already
			// agree that this node can be reached.
			if fn := takeCPGRPCOnRecovered(); fn != nil {
				fn()
			}
			return
		}

		reason := classifyCPGRPCListenError(err)
		wait := jitterDuration(backoff, cpGRPCListenJitter)
		if noteCPGRPCListenFailure(reason, backoff, time.Now()) {
			// The FULL error goes here and nowhere else: the contract row, the
			// alert and the readiness detail carry the bounded class only.
			// logErrorf applies sanitizeLog (CWE-117) to the whole line.
			logErrorf("ControlPlane gRPC listener on %s unavailable (%s): %v — retrying in %s; "+
				"the proxy data plane is unaffected and is still enforcing policy, but Data Plane nodes "+
				"cannot fetch config, enroll or renew certificates until it recovers",
				cpGRPCListenerState().Addr, reason, err, wait.Round(time.Millisecond))
		}

		if !haSleepInterruptible(stop, wait) {
			noteCPGRPCStopped()
			return
		}
		if backoff *= 2; backoff > cpGRPCListenBackoffMax {
			backoff = cpGRPCListenBackoffMax
		}
	}
}

// suppressedSuffix renders the suppressed-log-line count for the recovery line,
// so the operator can tell a single blip from a long episode whose intermediate
// lines the rate gate swallowed (the storage_health.go/CHAOS-54 discipline: the
// log carries the signal, the counter the magnitude, and the recovery line
// states what was hidden).
func suppressedSuffix(suppressed int64) string {
	if suppressed <= 0 {
		return ""
	}
	return fmt.Sprintf(" (%d further failure log line(s) were suppressed during the outage)", suppressed)
}

// retryControlPlaneGRPC re-attempts ONLY the listener, then completes the role
// transition `enableControlPlane` skipped when its bind failed.
//
// Deliberately NOT a re-run of `enableControlPlane`:
//
//   - that function's publish + cluster-CA work already ran before the failed
//     bind, so re-running it would re-publish on every attempt and ratchet the
//     durable config-version floor once per retry (register row CP-6);
//   - and it refuses outright once the role is set ("already running as
//     control-plane"), which is exactly the state the serve-exit rebind path is
//     in.
//
// Reads the TLS material and the address from `clusterRole`, which
// `enableControlPlane` populated for us — the cert paths are re-read from disk
// by `cpServerOption` on every call, which is what makes a rotation window
// self-healing (CHAOS-57 rule 4).
func retryControlPlaneGRPC() error {
	clusterRoleMu.Lock()
	addr, certFile, keyFile, caFile := cpRetryMaterialLocked()
	if addr == "" {
		clusterRoleMu.Unlock()
		return errors.New("control plane gRPC address is no longer configured")
	}
	// A previous generation's server may still exist — after a serve-loop exit
	// the *grpc.Server is alive but serving nothing, and StartControlPlaneGRPC
	// overwrites clusterRole.grpcSrv. Stop the stale one first or it leaks for
	// the life of the process.
	stale := clusterRole.grpcSrv
	err := StartControlPlaneGRPC(addr, certFile, keyFile, caFile)
	if err == nil {
		clusterRole.role = "control-plane"
		clusterRole.grpcAddr = addr
		clusterRole.certFile = certFile
		clusterRole.keyFile = keyFile
		clusterRole.caFile = caFile
	}
	clusterRoleMu.Unlock()

	if err == nil && stale != nil && stale != clusterRole.grpcSrv {
		go stale.Stop()
	}
	if err != nil {
		return err
	}
	// The heartbeat monitor is idempotent-by-intent here: on the boot path it
	// never started, and on the rebind path it has been running all along (it
	// watches enrolled-node liveness, which is independent of this listener).
	globalClusterStore.StartHeartbeatMonitor(appLifecycleCtx.Done())
	return nil
}

// cpRetryMaterialLocked reads the retry inputs. Caller holds clusterRoleMu.
//
// Prefers the recorded cluster-role fields and falls back to the health
// record's address, so a retry armed before the role fields were populated (a
// first-attempt bind failure, where `enableControlPlane` returns before setting
// them) still knows where to bind.
func cpRetryMaterialLocked() (addr, certFile, keyFile, caFile string) {
	addr, certFile, keyFile, caFile = clusterRole.grpcAddr, clusterRole.certFile, clusterRole.keyFile, clusterRole.caFile
	if addr == "" {
		addr = cpGRPCPendingAddr()
	}
	if certFile == "" && keyFile == "" {
		certFile, keyFile, caFile = cpGRPCPendingTLS()
	}
	return addr, certFile, keyFile, caFile
}

// cpGRPCPending holds the material the BOOT path asked for, captured before the
// first bind attempt so a retry has it even when the first attempt failed
// before `enableControlPlane` recorded anything on clusterRole.
var cpGRPCPending struct {
	mu                  sync.Mutex
	addr, cert, key, ca string
}

// noteCPGRPCRequested records the requested listener material. Called from the
// boot path alongside noteCPGRPCConfigured, before the first attempt.
func noteCPGRPCRequested(addr, certFile, keyFile, caFile string) {
	cpGRPCPending.mu.Lock()
	cpGRPCPending.addr, cpGRPCPending.cert, cpGRPCPending.key, cpGRPCPending.ca = addr, certFile, keyFile, caFile
	cpGRPCPending.mu.Unlock()
}

func cpGRPCPendingAddr() string {
	cpGRPCPending.mu.Lock()
	defer cpGRPCPending.mu.Unlock()
	return cpGRPCPending.addr
}

func cpGRPCPendingTLS() (certFile, keyFile, caFile string) {
	cpGRPCPending.mu.Lock()
	defer cpGRPCPending.mu.Unlock()
	return cpGRPCPending.cert, cpGRPCPending.key, cpGRPCPending.ca
}
