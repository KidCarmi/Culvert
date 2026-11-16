package main

// syslog_intent_retry.go — automatic retry of a SIEM/syslog collector that
// could not be connected at STARTUP.
//
// Both boot paths (the YAML/flag slice and the persisted admin settings)
// tolerate a failed connect: the node logs it, records the operator's intent
// and keeps proxying. Until this file, that was the end of it. Nothing dialled
// again, so a collector that was merely late — a site power-cycle where the
// SIEM comes up a minute after the gateway, or a hostname that does not
// resolve until DNS is up — left audit and request forwarding dark for the
// life of the process, with every event lost, until an operator noticed the
// `syslog_feed` row and re-saved the target (POST /api/syslog) or restarted.
// The engine's own reconnect state machine does not cover it: that machine
// belongs to a Writer, and a failed boot dial produces no Writer.
//
// What the retry does is exactly what that re-save does, minus the human: dial
// the SAME recorded target with the SAME format, and publish the Writer
// through the SAME transition InitSyslog uses. It chooses nothing.
//
// What it deliberately does NOT do:
//
//   - act on anything but a boot dial that failed. The live admin re-point
//     refuses a failed dial with a 400 and leaves the previous target in
//     force; that is an operator decision in progress, not a pending intent.
//   - outlive the intent. A disable, a successful re-point, or a different
//     configured target each clear or supersede the pending record under
//     syslogPublishMu, and an attempt re-reads it under that lock AFTER its
//     dial returns — so a dial that was in flight when the operator changed
//     their mind is discarded, never published.
//   - touch persistence. No settings save and no configuration version: the
//     configured target is unchanged; only the live state catches up with it.
//   - move the health plane on a FAILED attempt. The feed stays reported down
//     from the moment the boot dial failed; an attempt neither re-opens the
//     pending-dial grace nor re-anchors the outage's age, so `culvert_syslog_up`
//     does not flap once per attempt.
//   - replay. Events lost while the collector was unreachable stay lost and
//     stay counted, exactly as before.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"
)

// syslogRetryIntent is a boot dial that failed and is still what the operator
// has configured. The zero value means nothing is pending.
type syslogRetryIntent struct {
	addr   string
	format string
}

// syslogRetryPending is the boot dial awaiting an automatic retry. Guarded by
// syslogPublishMu, and cleared inside the same critical sections that publish
// a Writer or disable forwarding, so "is this still wanted" is answered by the
// transition that would make it unwanted.
var syslogRetryPending syslogRetryIntent

// syslogRetryWake nudges the retry loop when a boot dial is armed. Buffered by
// one: an arm that lands before the loop starts (loadObservability runs before
// the background services) is not lost, and a burst collapses to one wake.
var syslogRetryWake = make(chan struct{}, 1)

const (
	// syslogRetryInitialDelay is the wait before the first automatic retry.
	// Short, because the common case is a collector that is seconds behind
	// the gateway at boot.
	syslogRetryInitialDelay = 10 * time.Second
	// syslogRetryMaxDelay caps the backoff. There is no attempt limit — the
	// engine's own reconnect machine never gives up on an installed Writer
	// either — so the cap is the cadence bound: one bounded dial
	// (syslog.DialTimeout) every two minutes at most, for as long as the
	// target stays configured and unreachable.
	syslogRetryMaxDelay = 2 * time.Minute
	// syslogRetryJitterFrac spreads the retries of nodes that booted together
	// against one collector.
	syslogRetryJitterFrac = 0.25
	// syslogRetryLogEvery rate-limits the failed-attempt log line: the first
	// failure, then every Nth. The degraded feed is already reported by the
	// health plane; this line only confirms the retry is alive.
	syslogRetryLogEvery = 10
)

// crashComponentSyslogRetry names the boot-dial retry in the crash plane.
const crashComponentSyslogRetry = "syslog_intent_retry"

// syslogRetryDelay is the production backoff: 10s doubling to a 2-minute cap,
// plus up to 25% jitter. attempt is the number of failed retries so far.
func syslogRetryDelay(attempt int) time.Duration {
	d := syslogRetryMaxDelay
	if attempt >= 0 && attempt < 8 {
		if scaled := syslogRetryInitialDelay << attempt; scaled < syslogRetryMaxDelay {
			d = scaled
		}
	}
	return d + time.Duration(rand.Float64()*syslogRetryJitterFrac*float64(d)) // #nosec G404 -- jitter, not crypto
}

// armSyslogIntentRetry hands a failed BOOT dial to the background retry.
//
// It re-checks, under the publication lock, that addr is still the operator's
// intent and still unserved: by the time a boot path reports its failure a
// later slice may already have installed a Writer for the same target, and
// retrying then would only replace a working Writer with an identical one.
func armSyslogIntentRetry(addr, format string) {
	if addr == "" {
		return
	}
	syslogPublishMu.Lock()
	armed := syslogIntentUnservedLocked(addr)
	if armed {
		syslogRetryPending = syslogRetryIntent{addr: addr, format: format}
	}
	syslogPublishMu.Unlock()
	if !armed {
		return
	}
	select {
	case syslogRetryWake <- struct{}{}:
	default:
	}
}

// syslogRetryPendingSnapshot reads the pending boot dial, or the zero value
// when the operator's current intent is no longer that dial.
func syslogRetryPendingSnapshot() syslogRetryIntent {
	syslogPublishMu.Lock()
	defer syslogPublishMu.Unlock()
	return syslogRetryPendingLocked()
}

// syslogRetryPendingLocked is the ONE definition of "a boot dial is still
// worth retrying": it is recorded, and it is still the configured target.
// Caller holds syslogPublishMu.
func syslogRetryPendingLocked() syslogRetryIntent {
	if !syslogIntentIsLocked(syslogRetryPending.addr) {
		return syslogRetryIntent{}
	}
	return syslogRetryPending
}

// startSyslogIntentRetry runs the boot-dial retry until ctx is cancelled.
// Started from the background-services slice, parented to the lifecycle ctx.
func startSyslogIntentRetry(ctx context.Context) {
	runSyslogIntentRetry(ctx, syslogRetryDelay)
}

// runSyslogIntentRetry is the loop, with the backoff injected so tests drive
// it without wall-clock waits. Single goroutine by construction: attempts are
// serialized, so two retries can never race each other to publish.
func runSyslogIntentRetry(ctx context.Context, delay func(attempt int) time.Duration) {
	var tracked syslogRetryIntent
	failed := 0
	for {
		want := syslogRetryPendingSnapshot()
		if want != tracked {
			// A different target (or none) is a different question: its
			// backoff starts over.
			tracked, failed = want, 0
		}
		if !waitSyslogRetryTurn(ctx, want, delay(failed)) {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		// Per-ROUND guard (CHAOS-118): this loop is `go`-detached, so an
		// unrecovered panic in one attempt would take the gateway down over
		// a SIEM reconnect. The round holds no lock across the dial and the
		// publish section releases by defer, so keep-going is safe.
		var outcome syslogRetryOutcome
		if runGuarded(crashComponentSyslogRetry, func() {
			outcome = attemptSyslogIntentRetry(ctx, want, failed+1)
		}) {
			outcome = syslogRetryFailed
		}
		if outcome == syslogRetryFailed {
			failed++
		}
	}
}

// waitSyslogRetryTurn blocks until it is time to attempt want. It reports
// false when the wait ended for any other reason — shutdown, or a wake that
// means the pending record must be re-read — and never arms a timer while
// nothing is pending, so an idle node pays nothing.
func waitSyslogRetryTurn(ctx context.Context, want syslogRetryIntent, wait time.Duration) bool {
	if want.addr == "" {
		select {
		case <-ctx.Done():
		case <-syslogRetryWake:
		}
		return false
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-syslogRetryWake:
		return false
	case <-t.C:
		return true
	}
}

// syslogRetryOutcome is what one attempt decided.
type syslogRetryOutcome int

const (
	// syslogRetryFailed: the collector is still unreachable; back off.
	syslogRetryFailed syslogRetryOutcome = iota
	// syslogRetryInstalled: a Writer for the configured target is live.
	syslogRetryInstalled
	// syslogRetrySuperseded: the intent moved (disable, re-point, a different
	// configured target, shutdown) before or during the dial. Nothing was
	// published and nothing is retried on this record's behalf.
	syslogRetrySuperseded
)

// attemptSyslogIntentRetry makes one bounded dial for want and publishes the
// Writer only if want is STILL the pending intent once the dial has returned.
// attempt is 1-based and used for diagnostics only.
func attemptSyslogIntentRetry(ctx context.Context, want syslogRetryIntent, attempt int) syslogRetryOutcome {
	// Revalidate before spending a dial: the operator may have acted while
	// the backoff timer ran.
	if want.addr == "" || syslogRetryPendingSnapshot() != want {
		return syslogRetrySuperseded
	}
	network, target := splitSyslogAddr(want.addr)
	sw, err := newSyslogWriter(network, target, want.format)
	if err != nil {
		if attempt == 1 || attempt%syslogRetryLogEvery == 0 {
			logger.Printf("Syslog: automatic reconnect attempt %d to the configured collector failed (%q) — still retrying; events are NOT reaching the SIEM",
				attempt, sanitizeLog(err.Error()))
		}
		return syslogRetryFailed
	}
	if !publishRetriedSyslogWriter(ctx, sw, want) {
		// The dial succeeded for a target nobody wants any more. The Writer
		// was never published and has carried no event; release its socket
		// and drain goroutine. Asynchronous for the reason
		// releaseReplacedSyslogWriter records.
		go func() { _ = sw.Close() }()
		return syslogRetrySuperseded
	}
	logger.Printf("Syslog: the configured collector %s://%q became reachable — forwarding established automatically on reconnect attempt %d (format=%s); events lost while it was unreachable are NOT replayed",
		network, sanitizeLog(target), attempt, sanitizeLog(sw.Format()))
	// Attributed to "system", never to an admin: no human asked for this
	// connect at this moment. It is also the first event the collector
	// receives, which marks where the gap in its record ends.
	auditSystem("settings.syslog.auto_connect", want.addr,
		fmt.Sprintf("syslog forwarding established automatically: the collector configured at startup was unreachable and accepted a connection on reconnect attempt %d (format=%s); events before this one were not forwarded", attempt, sw.Format()))
	return syslogRetryInstalled
}

// publishRetriedSyslogWriter installs sw for want iff want is still the
// pending intent and the node is not shutting down. The check and the publish
// share one critical section with every other transition that can change the
// answer (InitSyslog, disableActiveSyslog), which is what makes a manual
// action racing the retry safe in both orders:
//
//   - the operator acts first: the pending record is gone, and this returns
//     false without publishing.
//   - the retry publishes first: the operator's transition then displaces or
//     disables this Writer exactly as it would any other.
//
// The shutdown check sits inside the same section so a Writer cannot be
// published after the lifecycle cancel, where the `syslog-close` hook (which
// runs later and closes whatever is published) might already have looked.
func publishRetriedSyslogWriter(ctx context.Context, sw *syslogWriter, want syslogRetryIntent) bool {
	syslogPublishMu.Lock()
	defer syslogPublishMu.Unlock()
	if ctx.Err() != nil || syslogRetryPendingLocked() != want {
		return false
	}
	publishSyslogWriterLocked(sw, want.addr)
	return true
}

// resetSyslogIntentRetryForTest clears the pending boot dial and any buffered
// wake. Test isolation only; called from resetSyslogHealthForTest.
func resetSyslogIntentRetryForTest() {
	syslogPublishMu.Lock()
	syslogRetryPending = syslogRetryIntent{}
	syslogPublishMu.Unlock()
	select {
	case <-syslogRetryWake:
	default:
	}
}
