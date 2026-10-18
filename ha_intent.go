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
	paged    bool   // this episode's page has been queued or dispatched
	// episode numbers the episodes. It survives clearIntentUnknown, so a page
	// queued before the startup flush is delivered only while ITS episode is
	// still the open one (haIntentEpisodeOpen).
	episode uint64
}

// haIntentPageAfter is how many failed reads in one episode page: one
// transient failure that the first retry clears is logged, not paged.
const haIntentPageAfter = 2

// noteHAIntentUnreadable records a failed read of the persisted HA intent on
// globalHA and pages the episode once it keeps failing. It is the ONLY caller
// of noteIntentUnreadable (TestChaos71_Wall_HAIntentLatchArmsOnlyWithItsPage):
// the once-per-episode latch is armed only here, in the same call that hands
// the page to pageHAIntentUnreadable — which queues it until the webhooks load
// or dispatches it — so the latch never silences an episode whose one page
// went nowhere (Codex review of #1556, P2 4303320660).
func noteHAIntentUnreadable(err error) {
	if page, episode := globalHA.noteIntentUnreadable(err); page {
		pageHAIntentUnreadable(err, episode)
	}
}

// noteIntentUnreadable records a failed read of the persisted HA intent and
// reports whether this episode should page now (once per episode), and which
// episode it is. Call it through noteHAIntentUnreadable.
func (h *HAState) noteIntentUnreadable(err error) (page bool, episode uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g := &h.intent
	if g.reason == "" {
		g.episode++ // a new episode
	}
	g.reason = err.Error()
	g.attempts++
	if g.attempts >= haIntentPageAfter && !g.paged {
		g.paged = true
		return true, g.episode
	}
	return false, g.episode
}

// clearIntentUnknown ends the episode: a read decided the intent. The episode
// number is kept, so the next episode gets a new one.
func (h *HAState) clearIntentUnknown() {
	h.mu.Lock()
	h.intent = haIntentGateState{episode: h.intent.episode}
	h.mu.Unlock()
}

// haIntentEpisodeOpen reports whether episode is still the open one and still
// gates the node (no HA role taken meanwhile) — the condition its page reports.
func (h *HAState) haIntentEpisodeOpen(episode uint64) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.intent.reason != "" && h.intent.episode == episode && h.role == ""
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
//
// STARTUP ORDERING (Codex review of #1556, P2 4303320660): the boot read and
// the activation callback's first re-read both run inside initCluster, before
// initPersistentAdminState loads the persisted webhooks, so a page fired then
// fanned out to an empty store while the latch silenced every retry. Before
// the startup flush it queues, delivered only while its episode is still open
// (a read that decided the intent before the webhooks loaded drops it); after
// the flush it fires at once.
func pageHAIntentUnreadable(err error, episode uint64) {
	payload := AlertPayload{
		Event:  "ha_resume_unfenced",
		Source: "ha",
		Detail: "the persisted HA config could not be read during the leadership resume (" + err.Error() +
			"); leader-gated RPCs and CA issuance stay refused (no write authority) and the read is retried",
	}
	if !startupAlertsFlushed() {
		deferStartupAlertWhile("ha_resume_unfenced", payload, func() bool { return globalHA.haIntentEpisodeOpen(episode) })
		return
	}
	fireAlert("ha_resume_unfenced", payload)
}

// pageUnfencedLeader is the read-only resume page: an ha_resume_unfenced page
// about a leader that resumed the role WITHOUT the fencing lease
// (resumeAsLeader). This PR moved the boot resume into the Control Plane
// listener's activation callback, which on a healthy boot runs inside
// initCluster, before the webhooks load. Before the startup flush the page
// queues, delivered only while this node is still an unfenced leader; after
// the flush it is delivered asynchronously, as before: the resume is an HA
// transition path that must not wait on a webhook dispatch.
func (h *HAState) pageUnfencedLeader(detail string) {
	payload := AlertPayload{Event: "ha_resume_unfenced", Detail: detail, Source: "ha"}
	if !startupAlertsFlushed() {
		deferStartupAlertWhile("ha_resume_unfenced", payload, h.unfencedLeader)
		return
	}
	go fireAlert("ha_resume_unfenced", payload)
}

// unfencedLeader reports whether this node holds the leader role without a
// fencing-lease grant: the read-only state an unfenced page reports.
func (h *HAState) unfencedLeader() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.role == "leader" && h.lease != nil && h.leaseEpoch == 0
}
