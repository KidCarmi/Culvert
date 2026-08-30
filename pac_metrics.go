package main

// pac_metrics.go — PAC serving observability (Palo fleet review, ops finding
// 4: the feature shipped with zero counters/alerts and discarded the
// compiler's own degradation warnings at serve time). Lightweight atomics
// exposed via handleMetrics; a degraded compile (dropped rule, unresolvable
// pool, secure-mode conflict) is logged and, once per profile, alerted.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
)

var (
	pacServesTotal      atomic.Int64 // successful PAC bodies served (200)
	pacNotModifiedTotal atomic.Int64 // 304 revalidations
	pacCompileWarnTotal atomic.Int64 // total compile warnings surfaced at serve time

	// Lifecycle observability (Palo review, ops finding: publish/rollback and
	// guardrail blocks shipped with no counters).
	pacPublishesTotal              atomic.Int64 // successful publishes
	pacRollbacksTotal              atomic.Int64 // successful rollbacks
	pacPublishBlockedTotal         atomic.Int64 // publishes/rollbacks refused by a guardrail
	pacPublishConfirmRequiredTotal atomic.Int64 // publishes/rollbacks that returned "confirmation required"
)

// pacMaxReasonLen bounds the operator-supplied change-reason recorded on a
// published revision.
const pacMaxReasonLen = 500

// pacMaxAnalyzeSample bounds the number of destinations replayed by the
// viewer-reachable /api/pac/analyze impact route (DoS guard).
const pacMaxAnalyzeSample = 1000

// pacProfileAlertOnce latches "degraded compile" alerts per profile ID so a
// steady-state degraded profile alerts once, not on every fetch. Reset on
// restart (documented, matches the release-alert latch precedent).
var pacProfileAlertOnce = struct {
	mu   sync.Mutex
	seen map[string]bool
}{seen: map[string]bool{}}

// pacDegradedProfile is the last-observed serve-time compile-warning state
// for one PAC profile.
type pacDegradedProfile struct {
	Warnings []pac.ValidationIssue `json:"warnings"`
	At       time.Time             `json:"at"`
}

// pacDegraded tracks, per profile ID ("default" for the legacy PAC config),
// the most recent serve-time compile warnings (dropped rule, unresolvable
// pool reference, secure-mode conflict).
//
// Enterprise Product Experience finding: pacObserveServe already computes
// this fact on every serve and turns it into a log line, a counter, and a
// once-per-profile alert — but nothing kept the CURRENT state around for a
// later read. An admin who missed the alert (or never configured a webhook)
// had no way to ask "is my PAC currently degraded" without SSHing in to read
// server logs or standing up Prometheus. Cleared the next time a profile
// serves with zero warnings — recovery on OBSERVED evidence only, the same
// convention storage_health.go/ca_health.go use, never on elapsed time.
var pacDegraded = struct {
	mu    sync.Mutex
	state map[string]pacDegradedProfile
}{state: map[string]pacDegradedProfile{}}

// pacUpdateDegraded records or clears profileID's degraded state.
func pacUpdateDegraded(profileID string, warnings []pac.ValidationIssue) {
	pacDegraded.mu.Lock()
	defer pacDegraded.mu.Unlock()
	if len(warnings) == 0 {
		delete(pacDegraded.state, profileID)
		return
	}
	pacDegraded.state[profileID] = pacDegradedProfile{Warnings: warnings, At: time.Now().UTC()}
}

// pacDegradedSnapshot returns a copy of the currently-degraded profiles,
// safe to encode directly into an API response.
func pacDegradedSnapshot() map[string]pacDegradedProfile {
	pacDegraded.mu.Lock()
	defer pacDegraded.mu.Unlock()
	out := make(map[string]pacDegradedProfile, len(pacDegraded.state))
	for k, v := range pacDegraded.state {
		out[k] = v
	}
	return out
}

// pacObserveServe records a served PAC and surfaces any compile warnings.
// profileID is "default" for the legacy surface. notModified reports whether
// the response was a 304 (still counted as a serve of that profile).
func pacObserveServe(profileID string, art pac.Artifact, notModified bool) {
	if notModified {
		pacNotModifiedTotal.Add(1)
	} else {
		pacServesTotal.Add(1)
	}
	pacUpdateDegraded(profileID, art.Warnings)
	if len(art.Warnings) == 0 {
		return
	}
	pacCompileWarnTotal.Add(int64(len(art.Warnings)))
	var b strings.Builder
	for i, wn := range art.Warnings {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s: %s", wn.Code, wn.Message)
	}
	detail := b.String()
	logger.Printf("PAC: profile %q served with %d compile warning(s): %s",
		sanitizeLog(profileID), len(art.Warnings), sanitizeLog(detail))

	pacProfileAlertOnce.mu.Lock()
	first := !pacProfileAlertOnce.seen[profileID]
	if first {
		pacProfileAlertOnce.seen[profileID] = true
	}
	pacProfileAlertOnce.mu.Unlock()
	if first {
		// A degraded compile can flip a profile's whole fleet to fail-closed
		// (secure) or re-steer it — an operator-visible event.
		fireAlert("pac_profile_degraded", AlertPayload{
			Event:  "pac_profile_degraded",
			Actor:  "culvert",
			Host:   profileID,
			Detail: detail,
			Source: "pac",
		})
	}
}

// pacResetProfileAlert clears the once-latch for a profile after a mutation,
// so a fixed-then-rebroken profile can alert again.
func pacResetProfileAlert(profileID string) {
	pacProfileAlertOnce.mu.Lock()
	delete(pacProfileAlertOnce.seen, profileID)
	pacProfileAlertOnce.mu.Unlock()
}

// pacForgetDegraded drops a deleted profile's degraded-state entry so it
// cannot linger in pacDegradedSnapshot() forever (it will never be served
// again to naturally clear itself). Update/create deliberately do NOT clear
// this — the badge must keep reflecting the true last-served reality until a
// clean serve is actually observed, not the admin's hope that an edit fixed
// it.
func pacForgetDegraded(profileID string) {
	pacDegraded.mu.Lock()
	delete(pacDegraded.state, profileID)
	pacDegraded.mu.Unlock()
}

// pacWritePrometheus appends PAC metrics to the exposition buffer.
func pacWritePrometheus(b *strings.Builder) {
	cfg := pacProfiles.Get()
	enabled := 0
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Enabled {
			enabled++
		}
	}
	fmt.Fprintf(b, "\n# HELP culvert_pac_serves_total PAC bodies served (200)\n# TYPE culvert_pac_serves_total counter\nculvert_pac_serves_total %d\n", pacServesTotal.Load())
	fmt.Fprintf(b, "# HELP culvert_pac_not_modified_total PAC conditional revalidations answered 304\n# TYPE culvert_pac_not_modified_total counter\nculvert_pac_not_modified_total %d\n", pacNotModifiedTotal.Load())
	fmt.Fprintf(b, "# HELP culvert_pac_compile_warnings_total PAC compile warnings surfaced at serve time (degraded compiles)\n# TYPE culvert_pac_compile_warnings_total counter\nculvert_pac_compile_warnings_total %d\n", pacCompileWarnTotal.Load())
	fmt.Fprintf(b, "# HELP culvert_pac_profiles Custom PAC steering profiles configured\n# TYPE culvert_pac_profiles gauge\nculvert_pac_profiles %d\n", len(cfg.Profiles))
	fmt.Fprintf(b, "# HELP culvert_pac_profiles_enabled Enabled custom PAC steering profiles\n# TYPE culvert_pac_profiles_enabled gauge\nculvert_pac_profiles_enabled %d\n", enabled)
	fmt.Fprintf(b, "# HELP culvert_pac_pools PAC proxy pools configured\n# TYPE culvert_pac_pools gauge\nculvert_pac_pools %d\n", len(cfg.Pools))
	fmt.Fprintf(b, "# HELP culvert_pac_publishes_total PAC profile publishes committed\n# TYPE culvert_pac_publishes_total counter\nculvert_pac_publishes_total %d\n", pacPublishesTotal.Load())
	fmt.Fprintf(b, "# HELP culvert_pac_rollbacks_total PAC profile rollbacks committed\n# TYPE culvert_pac_rollbacks_total counter\nculvert_pac_rollbacks_total %d\n", pacRollbacksTotal.Load())
	fmt.Fprintf(b, "# HELP culvert_pac_publish_blocked_total PAC publishes/rollbacks refused by a safe-publish guardrail\n# TYPE culvert_pac_publish_blocked_total counter\nculvert_pac_publish_blocked_total %d\n", pacPublishBlockedTotal.Load())
	fmt.Fprintf(b, "# HELP culvert_pac_publish_confirm_required_total PAC publishes/rollbacks that returned new-DIRECT confirmation-required\n# TYPE culvert_pac_publish_confirm_required_total counter\nculvert_pac_publish_confirm_required_total %d\n", pacPublishConfirmRequiredTotal.Load())
}
