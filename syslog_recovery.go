package main

// syslog_recovery.go — CHAOS-66: the way BACK for a SIEM feed that could not
// connect at startup.
//
// The asymmetry this closes.
//
// `internal/syslog`'s delivery state machine already recovers from a collector
// that goes away MID-LIFE: `deliverLine` notices the failed write, drops the
// connection, and redials on its own 5 s backoff for as long as the process
// lives. A collector that is down at BOOT recovered from nothing, because
// `NewWriter` refuses to construct a Writer whose first dial fails — so
// `InitSyslog` returned an error, both startup loaders logged one line and
// carried on, and the active writer stayed nil for the life of the process.
// Nothing retried. Nothing ever would.
//
// That is the CHAOS-57 shape one plane over: an identical fault is transient
// when it happens at runtime and permanent when it happens at startup, decided
// only by which code path observed it. And the boot case is the LIKELIER one —
// a gateway and its SIEM restart together on a host reboot, a collector is in a
// maintenance window during a rolling upgrade, DNS is not up yet when the
// container starts. The cost is a compliance feed that is dark until a human
// notices and re-saves the target, on a node that reports itself healthy in
// every other respect.
//
// It only bites TCP. A UDP "connect" is a local operation that essentially
// cannot fail, so the operator who chose the transport with delivery semantics
// is the one who paid for it.
//
// Five rules hold.
//
//  1. Retry is bounded in RATE, never in COUNT (1 s doubling to 60 s, ±20%
//     jitter). Bounding the count is the wrong bound here for CHAOS-55's
//     reason: the terminal state of "give up" is exactly the permanent silence
//     this file exists to remove. "Avoid infinite retries" is satisfied the way
//     CHAOS-54/55/57 satisfy it — the retry is never SILENT: the first failure
//     is already logged by the caller, then at most one line per
//     syslogReconnectLogInterval, then one line on success, with the state on
//     the contract row, the `/health` field and the metrics.
//
//  2. The sleep is INTERRUPTIBLE, so shutdown never waits out a backoff.
//
//  3. The campaign is GENERATION-FENCED. An operator who changes or disables
//     the collector while a campaign is running must win: every publication
//     bumps `syslogGeneration`, the campaign captures it at arm time, and a
//     round that finds it moved exits without publishing. Without the fence a
//     retry that finally connected could install itself over a target the
//     operator had since switched off — resurrecting forwarding to a collector
//     they deliberately stopped using.
//
//  4. Only ONE campaign runs at a time. Both startup loaders can fail in the
//     same boot (YAML target, then the persisted admin target), and two
//     campaigns would double the dial rate at a collector that is by hypothesis
//     already unavailable.
//
//  5. The campaign NEVER re-validates or rewrites operator intent. It carries
//     the exact target and format it was armed with; it does not fall back to a
//     different collector, and it does not touch `syslogConfigured` until a
//     writer is actually published.

import (
	"sync"
	"time"
)

const (
	// syslogReconnectInitial / syslogReconnectMax bound the RATE of reconnect
	// attempts. The floor is 1 s because these faults are not machine-speed (a
	// collector finishes booting, a firewall rule lands, DNS starts answering —
	// all measured in seconds); the ceiling is 60 s so a self-healed fault is
	// picked up within a minute without dialling a down collector hard. The
	// ceiling is deliberately ABOVE the engine's own 5 s in-writer backoff:
	// this path has no connection at all to protect, so its only cost is a dial
	// at a host that is not answering.
	syslogReconnectInitial = 1 * time.Second
	syslogReconnectMax     = 60 * time.Second

	// syslogReconnectJitter spreads the backoff by ±20%. A fleet restarts
	// together — a compose `up`, a rolling reboot — and an unjittered cadence
	// would aim a synchronised herd of dials at the one collector that is
	// already struggling (the WK-13 shape). Matches adminUIListenJitter.
	syslogReconnectJitter = 0.20

	// syslogReconnectLogInterval rate-limits the retry log line. The caller
	// logs the first failure; this gate then allows at most one line per
	// interval, and success always logs. The magnitude lives in
	// `culvert_syslog_reconnect_attempts_total`.
	syslogReconnectLogInterval = 5 * time.Minute
)

// syslogReconnectState guards the single-campaign invariant and carries the
// state the reporting surfaces read.
var syslogReconnectState struct {
	mu       sync.Mutex
	running  bool
	attempts int64
	stop     chan struct{}
}

// armSyslogReconnect starts the reconnect campaign for target/format unless one
// is already running. Safe to call from either startup loader.
func armSyslogReconnect(addr, format string) {
	if addr == "" {
		return
	}
	gen := syslogGeneration.Load()

	syslogReconnectState.mu.Lock()
	if syslogReconnectState.running {
		syslogReconnectState.mu.Unlock()
		return // rule 4: one campaign
	}
	syslogReconnectState.running = true
	syslogReconnectState.stop = make(chan struct{})
	stop := syslogReconnectState.stop
	syslogReconnectState.mu.Unlock()

	go runSyslogReconnect(addr, format, gen, stop)
}

// stopSyslogReconnect ends a running campaign. Called by the shutdown sequence
// and by any path that takes ownership of the target (a successful manual
// re-save, a disable).
func stopSyslogReconnect() {
	syslogReconnectState.mu.Lock()
	if syslogReconnectState.running && syslogReconnectState.stop != nil {
		close(syslogReconnectState.stop)
		syslogReconnectState.stop = nil
		syslogReconnectState.running = false
	}
	syslogReconnectState.mu.Unlock()
}

// syslogReconnectActive reports whether a campaign is running, and how many
// attempts it has made.
func syslogReconnectActive() (running bool, attempts int64) {
	syslogReconnectState.mu.Lock()
	defer syslogReconnectState.mu.Unlock()
	return syslogReconnectState.running, syslogReconnectState.attempts
}

// markSyslogReconnectFinished clears the running flag when the loop exits for
// any reason. Idempotent with stopSyslogReconnect.
func markSyslogReconnectFinished() {
	syslogReconnectState.mu.Lock()
	syslogReconnectState.running = false
	syslogReconnectState.stop = nil
	syslogReconnectState.mu.Unlock()
}

// runSyslogReconnect is the campaign loop. It exits on success, on shutdown, or
// when the generation it was armed under has moved (rule 3).
func runSyslogReconnect(addr, format string, gen uint64, stop <-chan struct{}) {
	defer markSyslogReconnectFinished()

	backoff := syslogReconnectInitial
	var lastLog time.Time
	var suppressed int64

	for {
		if !haSleepInterruptible(stop, jitterDuration(backoff, syslogReconnectJitter)) {
			return // shutdown: never wait out a backoff
		}
		// Rule 3, checked BEFORE the dial as well as before the publish: an
		// operator who has already moved on should not even cost the old
		// collector a connection attempt.
		if syslogGeneration.Load() != gen {
			return
		}

		syslogReconnectState.mu.Lock()
		syslogReconnectState.attempts++
		attempts := syslogReconnectState.attempts
		syslogReconnectState.mu.Unlock()

		network, target := parseSyslogTarget(addr)
		sw, err := newSyslogWriter(network, target, format)
		if err == nil {
			// Re-check the fence with the writer in hand: an operator may have
			// reconfigured while this dial was in flight. Publishing then would
			// overwrite their choice with a stale one.
			if syslogGeneration.Load() != gen {
				_ = sw.Close()
				return
			}
			publishSyslogWriter(sw)
			noteSyslogConnected()
			syslogConfigured = addr
			logger.Printf("Syslog: reconnected to %q after %d attempt(s) (format=%s) — SIEM forwarding restored",
				sanitizeLog(addr), attempts, sanitizeLog(sw.Format()))
			return
		}

		now := time.Now()
		if lastLog.IsZero() || now.Sub(lastLog) >= syslogReconnectLogInterval {
			logger.Printf("Syslog: still cannot reach the collector after %d attempt(s) (%v) — retrying with backoff; %d log lines suppressed",
				attempts, err, suppressed)
			lastLog = now
			suppressed = 0
		} else {
			suppressed++
		}

		backoff *= 2
		if backoff > syslogReconnectMax {
			backoff = syslogReconnectMax
		}
	}
}
