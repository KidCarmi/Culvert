package main

// ha_intent.go — "could not read the persisted HA intent" is never "HA
// disabled" (Codex review of #1556, P1 4303122583).
//
// The boot path re-reads ha_config.json when the Control Plane listener first
// binds (resumeLeadershipIfStillPersisted), which with the retrying supervisor
// can be minutes after boot. haRestartAction maps a read or decode failure to
// "none", so a transient failure of THAT read returned for good: the one-shot
// activation callback was spent, and the listener served with globalHA
// disabled — haServingAllowed and haIssuanceAllowed then allowed every
// leader-gated RPC and CA issuance with no fencing lease, even after the
// standby had taken leadership. Fail-open on a security sink.
//
// Now a read that cannot be decided (haPersistedAction returns an error) sets
// this gate: while it is set and this process holds no HA role, the node is
// HA-gated exactly as a node that is not the leader is — leader-gated RPCs,
// issuance and cluster-state writes refuse, and /healthz reports 503. The
// resume is retried with capped backoff (retryLeadershipResume), interruptible
// by the HA shutdown latch, and paged once per episode if it keeps failing.
// Only a decided read — no file, HA disabled, a standby or a leader — clears
// it. Any HA role taken meanwhile (an admin enable, a standby join) supersedes
// it, because role gating then applies.

import (
	"fmt"
	"time"
)

// haIntentGateState is HAState.intent. Guarded by HAState.mu.
type haIntentGateState struct {
	reason   string // non-empty while the persisted intent is unknown
	attempts int    // failed reads in this episode
	paged    bool   // this episode has been paged
}

// haIntentPageAfter is how many failed reads in one episode page: one
// transient failure that the first retry clears is logged, not paged.
const haIntentPageAfter = 2

// noteIntentUnreadable records a failed read of the persisted HA intent and
// reports whether this episode should page now (once per episode).
func (h *HAState) noteIntentUnreadable(err error) (page bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g := &h.intent
	g.reason = err.Error()
	g.attempts++
	if g.attempts >= haIntentPageAfter && !g.paged {
		g.paged = true
		return true
	}
	return false
}

// clearIntentUnknown ends the episode: a read decided the intent.
func (h *HAState) clearIntentUnknown() {
	h.mu.Lock()
	h.intent = haIntentGateState{}
	h.mu.Unlock()
}

// intentUnknown reports whether the gate is set (whatever the role).
func (h *HAState) intentUnknown() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.intent.reason != ""
}

// intentGate reports whether the node is HA-gated because its persisted
// intent is unknown: the gate is set and no HA role is held (a held role is
// gated by the role itself).
func (h *HAState) intentGate() (reason string, gated bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.intent.reason == "" || h.role != "" {
		return "", false
	}
	return fmt.Sprintf("the persisted HA config (%s) could not be read (%s) — this node cannot tell whether it leads, so it serves no leader-gated request until a read succeeds", haConfigFile, h.intent.reason), true
}

// haIntentRetryMin and haIntentRetryMax bound the resume retry's backoff.
const (
	haIntentRetryMin = time.Second
	haIntentRetryMax = 30 * time.Second
)

// haIntentRetrySleep waits d, or returns false once HA shutdown begins. Test
// seam.
var haIntentRetrySleep = func(d time.Duration) bool { return globalHA.sleepUnlessShutdown(d) }

// haIntentRetrySpawn starts the resume retry loop. Test seam.
var haIntentRetrySpawn = func(loop func()) { go loop() }

// pageHAIntentUnreadable pages a persisted-intent episode that keeps failing.
// The event is the existing ha_resume_unfenced: the leadership resume could
// not complete and the node serves without write authority.
func pageHAIntentUnreadable(err error) {
	fireAlert("ha_resume_unfenced", AlertPayload{
		Event:  "ha_resume_unfenced",
		Source: "ha",
		Detail: "the persisted HA config could not be read during the leadership resume (" + err.Error() +
			"); leader-gated RPCs and CA issuance stay refused (no write authority) and the read is retried",
	})
}
