package main

// idp_metadata_health.go — CHAOS-71: the interactive IdP compile path.
//
// Why this file exists.
//
// Compiling an enabled SAML or OIDC profile performs a synchronous outbound
// fetch against the customer's identity provider — `fetchSAMLMetadata` for a
// `metadata_url`, `fetchOIDCDiscovery` for an issuer. Before CHAOS-71 that
// fetch had no cache, no fallback and no fallback posture, and its failure was
// reported by exactly one `logger.Printf`. Five consequences, each reproduced
// against the pre-fix tree (`idp_metadata_chaos_test.go`):
//
//  1. **No last-known-good.** A provider that compiled successfully seconds
//     ago could not be compiled at all once its metadata endpoint stopped
//     answering, although nothing about the IdP's published document had
//     changed.
//
//  2. **A boot failure was PERMANENT.** `IdPRegistry.Load` logs a compile
//     error and moves on, leaving the profile Enabled in `r.profiles` and
//     absent from `r.live`. Every accessor keys on `r.live`, so the profile is
//     invisible: `HasEnabledInteractiveProvider()` is false, the captive
//     portal offers nothing, and a scoped `SSORequired` rule fails closed with
//     403 for every browser user. Nothing in the process ever retried, so the
//     IdP coming back changed nothing until a restart or an admin re-save.
//
//  3. **It was INVISIBLE.** No metric, no contract row, no alert, no `/health`
//     or `/ready` field distinguished "no IdP configured" from "an IdP is
//     configured, enabled and dead". That is the register's §1 silent-failure
//     theme reached through the identity plane.
//
//  4. **A third party could veto the operator's config push.** `ReplaceAll`
//     compiles every enabled profile and is all-or-nothing, and
//     `syncSnapshotIdPProfiles` returns its error into `fetchAndApply`, which
//     abandons the snapshot without advancing `lastVersion`. So an IdP
//     maintenance window stopped POLICY, blocklist and threat-feed
//     distribution to every data plane in the fleet — a failure in the
//     identity plane taking out the config plane.
//
//  5. **It amplified into the IdP.** Because the version never advanced, every
//     DP retried the whole apply — including the fetch — on its next 30 s
//     poll, indefinitely. Measured 1:1: ten applies, ten outbound connections.
//     A 200-node fleet with two remote IdPs aims ~800 requests/minute at the
//     metadata endpoint for the duration of the outage, starting the moment an
//     operator pushes a config change. The WK-13 herd, pointed at the
//     customer's identity provider at the moment it is least able to answer.
//
// The rule established in response: **a third party's availability decides
// whether an IdP's metadata is FRESH, never whether the IdP EXISTS.**
// `internal/idpmeta` keeps the last successfully fetched document and the
// compile degrades to it, bounded by `idpmeta.StaleMaxAge`. That closes (1),
// and with it the compile failure that drives (4) and (5) for any node that
// has ever compiled the profile — which is every node in steady state. The
// bounded-rate recompile loop in `idp_recovery.go` closes (2). This file
// closes (3).
//
// Surfaces, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the `idp_metadata` operator-contract row.
//   - `/metrics` — culvert_idp_metadata_* and culvert_idp_enabled_not_live
//     (see metrics.go), emitted ONLY on a node that actually has an enabled
//     interactive IdP profile. A flat `0` from every appliance that never
//     configured SSO is indistinguishable from one whose IdP is dead, and the
//     documented paging rule is `> 0` — the socks5/cluster_ca/dns emission
//     rule.
//   - alerts — the EXISTING `identity_backend_unreachable` event. A new event
//     name would be silently unsubscribed on every already-configured webhook
//     (the cluster-CA `cert_expiry` precedent), and "the IdP cannot be
//     reached" is one operator action whether the unreachable thing is the
//     LDAP bind endpoint (CHAOS-47/58), the OIDC introspection endpoint
//     (CHAOS-49) or the metadata document this file watches.
//
// Deliberately NOT on `/readyz`. An IdP outage is fleet-wide by construction —
// every node talks to the same IdP — so failing readiness would eject the
// entire fleet from the load balancer simultaneously over a dependency none of
// them can fix by restarting, converting an SSO degradation into a total
// traffic outage. That is the rule the `ca`, `cluster_ca` and `dns_resolution`
// rows already follow.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// idpMetadataLogInterval rate-limits the fetch-failure log line. The FIRST
	// failure of an episode is always logged, then at most one line per
	// interval, then one recovery line carrying the suppressed count. Same
	// discipline as storage_health.go, socks5_health.go and dns_health.go: the
	// log carries the SIGNAL, the counter carries the MAGNITUDE.
	//
	// It matters here because the failure repeats at CONFIG-SYNC rate on every
	// DP in the fleet (30 s), not once — an ungated line would fill the
	// rotating process log with one node's IdP outage.
	idpMetadataLogInterval = 5 * time.Minute

	// idpMetadataDegradedAfter is how long an uninterrupted run of fetch
	// failures must persist before the metadata plane is reported DEGRADED.
	//
	// A DURATION, not a count, for the socks5_health.go reason, and a generous
	// one: a compile runs on boot, on admin write and on every config-version
	// change, so the ATTEMPT rate is bursty and unrelated to how bad the
	// outage is. Ten minutes in which not one fetch succeeded is a statement
	// about the IdP; three failures in ten seconds is a statement about how
	// many times an operator saved a profile.
	idpMetadataDegradedAfter = 10 * time.Minute
)

// idpMetadataOutcome names, in a BOUNDED set, what happened to one compile's
// document acquisition. Bounded because it reaches the alert Detail, and
// `Store.Dispatch` dedups on `event + ":" + Detail` — an unbounded reason
// yields one dedup key per failure, which the 30 s window cannot suppress by
// construction and which evicts real threat alerts from the 500-entry retry
// queue (the WK-12/RS-5 defect). It is additionally a viewer-role surface, and
// the raw error embeds the configured IdP URL. The full error goes to the
// rate-limited log line and nowhere else.
type idpMetadataOutcome string

const (
	idpMetaFresh       idpMetadataOutcome = "fresh"        // fetched from the IdP
	idpMetaStale       idpMetadataOutcome = "stale_cached" // fetch failed, served last-known-good
	idpMetaUnavailable idpMetadataOutcome = "unavailable"  // fetch failed, no usable cache
	idpMetaInline      idpMetadataOutcome = "inline"       // admin-pasted metadata_xml, no network
)

// idpMetadataHealth is the process-wide record of IdP document acquisition.
// Mutex-guarded rather than atomic-per-field because every reader needs a
// consistent view across all of it.
type idpMetadataHealth struct {
	mu sync.Mutex

	// Cumulative totals. `remoteAttempts` counts document acquisitions that
	// required the network at all — an inline `metadata_xml` profile is
	// deliberately excluded from every one of these, because it cannot fail
	// this way and counting it would make a node with no remote IdP look
	// healthy for a reason that says nothing.
	remoteAttempts int64
	fetchFailures  int64
	staleServed    int64
	unavailable    int64

	lastReason  idpMetadataOutcome
	lastSuccess time.Time

	// episodes holds the CURRENT failure episode of each profile that is
	// failing, keyed by profile id. Episode state is PER PROFILE on purpose:
	// with it process-global, a successful fetch for one healthy profile
	// cleared the episode another, dead profile had opened — so on a node with
	// two remote IdPs the dead one never reached the degradation threshold,
	// never paged, and repeated compiles emitted false recovery lines (Codex
	// review). Only a success for the SAME profile clears its episode.
	// Bounded by the admin-configured profile count.
	episodes map[string]*idpMetadataEpisode
}

// idpMetadataEpisode is one profile's uninterrupted run of fetch failures.
type idpMetadataEpisode struct {
	// firstFailure is the start of the run. Degradation is measured from
	// here, so an IdP that fails, answers, and fails again never accumulates
	// toward the threshold across healthy periods.
	firstFailure time.Time
	lastFailure  time.Time

	// consecutive is cleared (with the whole episode) on an OBSERVED
	// successful fetch for this profile; the totals never are. Recovery is
	// established by EVIDENCE — a document actually retrieved from the IdP —
	// never by elapsed time. A node whose fetch failures stop because nothing
	// is compiling any more has not recovered, and reporting that as recovery
	// is the mistake ca_health.go and storage_health.go both call out by name.
	consecutive int64

	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per DEGRADATION episode: one page when
	// this profile's document acquisition starts failing persistently, not
	// one per compile. Cleared with the episode, so a second incident pages
	// again.
	alerted bool
}

var idpMetadata idpMetadataHealth

// idpMetadataEverUsed gates every emission surface. A node that has never
// compiled a REMOTE interactive IdP profile emits no idp_metadata series and
// reports an `ok` contract row with no claim in it — the socks5/cluster_ca
// rule: `degraded 0` on an appliance that never configured SSO is
// indistinguishable from a healthy one and would make the `> 0` paging rule
// meaningless.
var idpMetadataEverUsed atomic.Bool

type idpMetadataSnapshot struct {
	RemoteAttempts int64
	FetchFailures  int64
	StaleServed    int64
	Unavailable    int64
	Consecutive    int64
	LastReason     idpMetadataOutcome
	LastSuccess    time.Time
	Failing        bool
	Degraded       bool
	FailingFor     time.Duration
	Used           bool
}

// fireIdPMetadataAlert delivers the degradation page on the EXISTING
// `identity_backend_unreachable` event.
//
// Package-level seam so tests observe the transition SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches). HasSubscriber-gated for the reason documented on
// fireStorageWriteAlert: with no webhook configured — the default posture, and
// the state of every test binary — this must not spawn a goroutine at all.
var fireIdPMetadataAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("identity_backend_unreachable") {
		return
	}
	go fireAlert("identity_backend_unreachable", AlertPayload{
		Detail: detail,
		Source: "idp_metadata",
	})
}

// noteIdPMetadataOutcome records one document acquisition.
//
// profileID and cause reach the rate-limited LOG line only. `outcome` is the
// bounded class that reaches metrics, the contract row and the alert.
func noteIdPMetadataOutcome(profileID string, outcome idpMetadataOutcome, cause error) {
	if outcome == idpMetaInline {
		return // no network was involved; this plane has nothing to say about it
	}
	idpMetadataEverUsed.Store(true)

	now := time.Now()
	idpMetadata.mu.Lock()
	idpMetadata.remoteAttempts++
	idpMetadata.lastReason = outcome

	switch outcome {
	case idpMetaFresh:
		// Recovery on OBSERVED evidence: a document actually came back — for
		// THIS profile. Another profile's success says nothing about it.
		ep := idpMetadata.episodes[profileID]
		wasFailing := ep != nil
		var suppressed int64
		if ep != nil {
			suppressed = ep.suppressed
			delete(idpMetadata.episodes, profileID)
		}
		idpMetadata.lastSuccess = now
		idpMetadata.mu.Unlock()
		if wasFailing {
			logger.Printf("IDP_METADATA_RECOVERED idp=%q (document fetched successfully; %d failure log line(s) suppressed during the episode)",
				sanitizeLog(profileID), suppressed)
		}
		return
	case idpMetaStale:
		idpMetadata.staleServed++
	case idpMetaUnavailable:
		idpMetadata.unavailable++
	}
	idpMetadata.fetchFailures++
	ep := idpMetadataEpisodeLocked(profileID)
	ep.consecutive++
	ep.lastFailure = now
	if ep.firstFailure.IsZero() {
		ep.firstFailure = now
	}
	failingFor := now.Sub(ep.firstFailure)
	degraded := failingFor >= idpMetadataDegradedAfter

	shouldLog := ep.logAt.IsZero() || now.Sub(ep.logAt) >= idpMetadataLogInterval
	suppressed := ep.suppressed
	if shouldLog {
		ep.logAt = now
		ep.suppressed = 0
	} else {
		ep.suppressed++
	}
	shouldAlert := degraded && !ep.alerted
	if shouldAlert {
		ep.alerted = true
	}
	consecutive := ep.consecutive
	idpMetadata.mu.Unlock()

	if shouldLog {
		// The cause is the only place the configured IdP URL may appear, and
		// this line is rate-limited. sanitizeLog + %q per the CWE-117 convention.
		logger.Printf("IDP_METADATA_FETCH_FAILED idp=%q outcome=%q consecutive=%d suppressed=%d cause=%q",
			sanitizeLog(profileID), string(outcome), consecutive, suppressed, sanitizeLog(fmt.Sprint(cause)))
	}
	if shouldAlert {
		// BOUNDED detail: the outcome class only. Never the URL, never the error.
		fireIdPMetadataAlert(fmt.Sprintf("IdP metadata/discovery document unreachable for over %s (outcome: %s)",
			idpMetadataDegradedAfter, outcome))
	}
}

// idpMetadataEpisodeLocked returns profileID's current failure episode,
// opening one if the profile is not failing. Caller holds idpMetadata.mu.
func idpMetadataEpisodeLocked(profileID string) *idpMetadataEpisode {
	if idpMetadata.episodes == nil {
		idpMetadata.episodes = make(map[string]*idpMetadataEpisode)
	}
	ep := idpMetadata.episodes[profileID]
	if ep == nil {
		ep = &idpMetadataEpisode{}
		idpMetadata.episodes[profileID] = ep
	}
	return ep
}

// idpMetadataState aggregates the per-profile episodes: the plane is failing
// while ANY profile is, FailingFor is the OLDEST open episode (degradation is
// a statement about the worst provider, not the average), and Consecutive is
// the longest run.
func idpMetadataState() idpMetadataSnapshot {
	if !idpMetadataEverUsed.Load() {
		return idpMetadataSnapshot{}
	}
	idpMetadata.mu.Lock()
	defer idpMetadata.mu.Unlock()
	snap := idpMetadataSnapshot{
		RemoteAttempts: idpMetadata.remoteAttempts,
		FetchFailures:  idpMetadata.fetchFailures,
		StaleServed:    idpMetadata.staleServed,
		Unavailable:    idpMetadata.unavailable,
		LastReason:     idpMetadata.lastReason,
		LastSuccess:    idpMetadata.lastSuccess,
		Failing:        len(idpMetadata.episodes) > 0,
		Used:           true,
	}
	var oldest time.Time
	for _, ep := range idpMetadata.episodes {
		if ep.consecutive > snap.Consecutive {
			snap.Consecutive = ep.consecutive
		}
		if oldest.IsZero() || ep.firstFailure.Before(oldest) {
			oldest = ep.firstFailure
		}
	}
	if !oldest.IsZero() {
		snap.FailingFor = time.Since(oldest)
		snap.Degraded = snap.FailingFor >= idpMetadataDegradedAfter
	}
	return snap
}

// resetIdPMetadataHealthForTest isolates the process-global record.
func resetIdPMetadataHealthForTest() {
	idpMetadata.mu.Lock()
	defer idpMetadata.mu.Unlock()
	// Fields are cleared INDIVIDUALLY rather than by assigning a zero struct:
	// `idpMetadata = idpMetadataHealth{}` while holding idpMetadata.mu
	// replaces the mutex itself, so the deferred Unlock releases a fresh,
	// never-locked mutex and the runtime kills the process with
	// "sync: unlock of unlocked mutex".
	idpMetadata.remoteAttempts = 0
	idpMetadata.fetchFailures = 0
	idpMetadata.staleServed = 0
	idpMetadata.unavailable = 0
	idpMetadata.lastReason = ""
	idpMetadata.lastSuccess = time.Time{}
	idpMetadata.episodes = nil
	idpMetadataEverUsed.Store(false)
}

// checkIdPMetadata is the `idp_metadata` operator-contract row.
//
// Severity policy:
//   - never used → ok, with no claim. A node with no remote interactive IdP
//     has nothing to report and a permanent row would be noise.
//   - an enabled profile has no live provider → WARN, and this is the row that
//     matters most: before CHAOS-71 this state had no surface at all. Browser
//     SSO is not working for those profiles.
//   - degraded (sustained fetch failures, still serving cached documents) →
//     warn, NOT fail. Authentication is still working from the last-known-good
//     document; what has stopped is picking up an IdP-side change. A fail row
//     would be read as "this node is broken" and, on a strict-readiness
//     deployment, would eject a fleet that is authenticating fine.
//   - healthy → ok, carrying cumulative counts so a HISTORY of transient
//     outages stays visible after recovery.
func checkIdPMetadata() OperatorContractCheck {
	snap := idpMetadataState()
	enabled, live := idpEnabledInteractiveCounts()
	dark := enabled - live

	if !snap.Used && dark == 0 {
		return OperatorContractCheck{
			Code:    "idp_metadata",
			Status:  diagOK,
			Message: "No remote IdP metadata/discovery documents in use",
		}
	}
	if dark > 0 {
		return OperatorContractCheck{
			Code:   "idp_metadata",
			Status: diagWarn,
			Message: fmt.Sprintf("%d of %d enabled interactive IdP profile(s) have NO live provider — browser SSO is not available for them (last outcome: %s)",
				dark, enabled, snap.LastReason),
			OperatorAction: "The profile is enabled and stored but could not be compiled, almost always because its metadata_url / issuer could not be reached and no cached document is available. Check this node's egress to the IdP. Recovery is automatic: the appliance retries at a bounded rate and the provider goes live on the first successful fetch — no restart is required.",
		}
	}
	if snap.Degraded {
		return OperatorContractCheck{
			Code:   "idp_metadata",
			Status: diagWarn,
			Message: fmt.Sprintf("IdP metadata/discovery fetches have been failing for %s (%d consecutive); providers are running from cached documents",
				snap.FailingFor.Round(time.Second), snap.Consecutive),
			OperatorAction: fmt.Sprintf("Authentication still works from the last-known-good document, so this is not yet user-visible — but an IdP-side signing-key rotation will NOT be picked up while it lasts, and a cached document is refused once it is older than %s, after which browser SSO stops. Check egress to the IdP metadata/discovery endpoint.", idpmetaStaleMaxAgeString()),
		}
	}
	if snap.FetchFailures > 0 {
		return OperatorContractCheck{
			Code:   "idp_metadata",
			Status: diagOK,
			Message: fmt.Sprintf("IdP metadata/discovery healthy (%d acquisitions, %d failures, %d served from cache since startup)",
				snap.RemoteAttempts, snap.FetchFailures, snap.StaleServed),
		}
	}
	return OperatorContractCheck{
		Code:    "idp_metadata",
		Status:  diagOK,
		Message: fmt.Sprintf("IdP metadata/discovery healthy (%d document acquisitions since startup)", snap.RemoteAttempts),
	}
}
