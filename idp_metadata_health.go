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
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/idpmeta"
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

	// episodes holds the CURRENT failure episode of each (profile, SOURCE)
	// that is failing — see idpEpisodeKey. Episode state is PER PROFILE on
	// purpose:
	// with it process-global, a successful fetch for one healthy profile
	// cleared the episode another, dead profile had opened — so on a node with
	// two remote IdPs the dead one never reached the degradation threshold,
	// never paged, and repeated compiles emitted false recovery lines (Codex
	// review). Only a success for the SAME profile clears its episode.
	//
	// It is keyed by profile AND SOURCE, not by profile alone, and that is a
	// CORRECTNESS requirement rather than precision for its own sake (Codex
	// review round 6). An `Upsert` that reuses a profile id while repointing it
	// at a different remote source compiles the CANDIDATE speculatively, and
	// with one entry per profile that compile mutated the LIVE profile's
	// episode: a candidate that then failed made the refusal path delete a
	// genuine, ongoing outage episode for the source still in service — losing
	// its fire-once latch and restarting its degradation clock — while a
	// candidate that stale-compiled and then failed to PERSIST left its own
	// episode attached to a profile whose configuration had not changed,
	// reporting an outage for a rejected edit. What an episode describes is a
	// failed fetch against a SOURCE, which is what the key now says.
	//
	// Bounded by (profiles x sources they have been pointed at while failing),
	// i.e. by the admin-configured profile count in the steady state.
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

	// lastOutcome is the BOUNDED class of the most recent failure, kept so the
	// degradation sweep below can name it in the alert Detail without holding a
	// cause string (Dispatch dedups on event+Detail — see fireIdPMetadataAlert).
	lastOutcome idpMetadataOutcome

	// profileID / source identify who this episode belongs to, so a sweep can
	// act on the provider rather than only report a count. The key is
	// length-framed and therefore parseable, but re-deriving an identity from a
	// key is how two layers disagree about what a value means (round 6), so it
	// is carried rather than recovered.
	profileID string
	source    string

	// servedFetchedAt is when the CACHED document this provider is currently
	// serving was fetched from the IdP — zero unless the last acquisition fell
	// back to cache. It is what makes idpmeta.StaleMaxAge enforceable on a LIVE
	// provider (Codex review round 8): the ceiling lives inside Store.Get, which
	// is reached only from a compile, and on a steady-state node nothing
	// recompiles — an unchanged CP snapshot skips ReplaceAll, and the recovery
	// loop considers only DARK profiles. So a provider compiled from cache
	// stayed live indefinitely on a document the documentation promises is
	// refused after seven days, which for SAML means continuing to trust a
	// signing certificate the IdP has withdrawn.
	servedFetchedAt time.Time
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

// forgetIdPMetadataEpisode drops a profile's failure episode because the
// profile is no longer an authoritative, enabled, remote-metadata provider —
// it was deleted, disabled, switched away from a remote URL, or its candidate
// mutation was REJECTED and never entered the registry at all.
//
// The last case is the one that motivated this (CHAOS-71 round 3). Compilation
// records an episode before the transactional Upsert/ReplaceAll decides
// whether to publish, so a refused candidate could leave an episode behind for
// a profile that does not exist. Degradation is derived from ELAPSED TIME
// against the episode's first failure (deliberately — CHAOS-61's "freshness is
// evaluated, never latched"), and only a fresh fetch or an inline transition
// cleared one, so nothing would ever clear this one: the degraded gauge, the
// contract row and eventually an alert would report an indefinite outage for a
// dependency nobody configured.
//
// This is the same rule noteIdPMetadataInline states, generalised: the
// observed-evidence discipline forbids clearing on elapsed TIME, never on
// evidence that the dependency is GONE — and "this profile is not in the
// registry" is exactly that evidence. It clears one profile's episode and
// counts nothing.
// forgetIdPMetadataEpisodeForSource drops the episode a REFUSED candidate's own
// speculative compile opened, and nothing else.
//
// It exists because `Upsert`/`ReplaceAll` compile a candidate BEFORE deciding
// whether to publish it, so a refused edit can leave behind an episode for a
// source no live profile uses — an outage reported against a configuration that
// was rejected. The caller must NOT call this when the candidate's source is
// the one already in service: those are the same key by construction, and the
// episode then belongs to the live profile's ongoing outage (Codex review
// rounds 3, 5 and 6 are all this one distinction, which is why it is now
// carried by the KEY rather than by a predicate over two profiles).
func forgetIdPMetadataEpisodeForSource(profileID, source string) {
	if profileID == "" || source == "" {
		return
	}
	key := idpEpisodeKey(profileID, source)
	idpMetadata.mu.Lock()
	_, had := idpMetadata.episodes[key]
	delete(idpMetadata.episodes, key)
	idpMetadata.mu.Unlock()
	if had {
		logger.Printf("IDP_METADATA_EPISODE_DISCARDED idp=%q — the edit that opened this remote-fetch "+
			"failure episode was refused, so it describes a configuration that is not in service",
			sanitizeLog(profileID))
	}
}

// idpAuthzEndpointUnverified counts OIDC authorization endpoints admitted
// WITHOUT a public-address verdict, because the address could not be
// determined (resolver outage, or the check's own budget spent).
//
// This is register row IDP-9. The endpoint is handed to the user's BROWSER, so
// no dialer of ours re-checks it and isSafeCaptiveRedirect checks only shape;
// a host unresolvable at compile time that later resolves private is a browser
// redirect into the internal network. Refusing on an unknown verdict instead
// would let a resolver outage reject a cached document — this sweep's headline
// defect — so the posture is an owner decision. What this counter removes is
// the SILENCE: non-zero means at least one live provider is issuing redirects
// to an endpoint this appliance never verified.
var idpAuthzEndpointUnverified atomic.Int64

// idpAuthzUnverifiedLogLast rate-limits the line to one per
// idpMetadataLogInterval. The compile path is reachable from every CP->DP
// snapshot apply, so an unrate-limited line would be one per sync per profile
// for the length of a resolver outage.
var idpAuthzUnverifiedLogLast atomic.Int64

func noteIdPAuthzEndpointUnverified(profileID string) {
	if profileID == "" {
		return // admin diagnostic; no live provider results from it
	}
	n := idpAuthzEndpointUnverified.Add(1)
	now := time.Now()
	for {
		last := idpAuthzUnverifiedLogLast.Load()
		// A NEGATIVE age re-arms rather than suppressing: a clock that went
		// backwards must not silence this for however far back it went
		// (the CHAOS-61 rule; see noteTracingBoundsLog).
		if last != 0 {
			if d := now.UnixNano() - last; d >= 0 && d < int64(idpMetadataLogInterval) {
				return
			}
		}
		if idpAuthzUnverifiedLogLast.CompareAndSwap(last, now.UnixNano()) {
			break
		}
	}
	logger.Printf("IDP_AUTHZ_ENDPOINT_UNVERIFIED idp=%q — the authorization endpoint's address could not be "+
		"determined, so it was admitted WITHOUT a public-address verdict and is being handed to browsers "+
		"unverified (%d since boot). Check this node's resolver.", sanitizeLog(profileID), n)
}

// forgetIdPMetadataEpisode drops EVERY episode this profile holds, across all
// sources. It is the "this profile no longer fetches anything" case — stored
// disabled, switched to inline metadata, or removed from the registry — where
// nothing is left that could ever clear an episode by evidence.
func forgetIdPMetadataEpisode(profileID string) {
	if profileID == "" {
		return
	}
	prefix := idpEpisodeProfilePrefix(profileID)
	idpMetadata.mu.Lock()
	had := false
	for k := range idpMetadata.episodes {
		if strings.HasPrefix(k, prefix) {
			delete(idpMetadata.episodes, k)
			had = true
		}
	}
	idpMetadata.mu.Unlock()
	if had {
		logger.Printf("IDP_METADATA_RECOVERED idp=%q (profile is no longer an enabled remote-metadata provider; its failure episode no longer applies)",
			sanitizeLog(profileID))
	}
}

// noteIdPStaleDocumentServed records WHEN the cached document a provider is now
// serving was fetched. It is called only on the stale-fallback path, right after
// noteIdPMetadataOutcome has opened (or extended) that profile's episode.
//
// It exists because idpmeta.StaleMaxAge lives inside Store.Get, which is reached
// only from a compile — so on a steady-state node, where nothing recompiles, the
// ceiling was never re-evaluated and a provider stayed live forever on a
// document the runbook promises stops being usable after seven days (Codex
// review round 8). Carrying the fetch time in memory lets the watchdog enforce
// the ceiling with no disk read and no second copy of the rule: the store still
// owns the value, this is only where the provider's CURRENT document sits in it.
func noteIdPStaleDocumentServed(profileID, source string, fetchedAt time.Time) {
	if profileID == "" || fetchedAt.IsZero() {
		return
	}
	idpMetadata.mu.Lock()
	defer idpMetadata.mu.Unlock()
	if ep := idpMetadata.episodes[idpEpisodeKey(profileID, source)]; ep != nil {
		ep.servedFetchedAt = fetchedAt
	}
}

func noteIdPMetadataOutcome(profileID, source string, outcome idpMetadataOutcome, cause error) {
	idpMetadataEverUsed.Store(true)

	now := time.Now()
	idpMetadata.mu.Lock()
	idpMetadata.remoteAttempts++
	idpMetadata.lastReason = outcome

	switch outcome {
	case idpMetaFresh:
		// Recovery on OBSERVED evidence: a document actually came back — for
		// THIS profile AND THIS SOURCE. Another profile's success says nothing
		// about it, and neither does a success against a different source.
		key := idpEpisodeKey(profileID, source)
		ep := idpMetadata.episodes[key]
		wasFailing := ep != nil
		var suppressed int64
		if ep != nil {
			suppressed = ep.suppressed
			delete(idpMetadata.episodes, key)
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
	ep := idpMetadataEpisodeLocked(idpEpisodeKey(profileID, source))
	ep.consecutive++
	ep.lastFailure = now
	ep.lastOutcome = outcome
	ep.profileID = profileID
	ep.source = source
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
// idpEpisodeKey identifies one profile's failure episode against ONE remote
// source. It is LENGTH-FRAMED so it is injective: unframed, a (profile, source)
// pair could collide with a different pair that concatenates to the same bytes,
// and a collision here merges two profiles' outage state — the failure mode
// per-profile keying was introduced to fix. The framing also makes
// idpEpisodeProfilePrefix a safe prefix.
func idpEpisodeKey(profileID, source string) string {
	return fmt.Sprintf("%d:%s:%s", len(profileID), profileID, source)
}

// idpEpisodeProfilePrefix is the prefix every key for this profile shares.
func idpEpisodeProfilePrefix(profileID string) string {
	return fmt.Sprintf("%d:%s:", len(profileID), profileID)
}

func idpMetadataEpisodeLocked(key string) *idpMetadataEpisode {
	if idpMetadata.episodes == nil {
		idpMetadata.episodes = make(map[string]*idpMetadataEpisode)
	}
	ep := idpMetadata.episodes[key]
	if ep == nil {
		ep = &idpMetadataEpisode{}
		idpMetadata.episodes[key] = ep
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

// idpMetadataDegradationSweep promotes every OPEN episode that has crossed
// idpMetadataDegradedAfter to alerted, and returns the bounded outcome classes
// to page on. It takes `now` so it is a pure function of recorded state plus an
// injected clock (the CHAOS-66 round-3 rule: a health decision must not mix two
// clocks).
//
// WHY THIS EXISTS. `noteIdPMetadataOutcome` evaluates the fire-once latch only
// while RECORDING A FAILURE, so the page required another failed fetch after
// the threshold elapsed. Degradation is derived from elapsed time — deliberately,
// per CHAOS-61's *freshness is EVALUATED, never latched* — so a provider that
// fell back to cache once and whose configuration then never changed again
// crossed the threshold with NOTHING left to evaluate it: no compile, and no
// recovery loop either, because that loop covers DARK profiles and a
// cache-serving provider is live. The documented webhook alert could therefore
// stay silent through exactly the sustained outage it exists for (Codex review
// round 4).
//
// This is the CHAOS-66 round-3 finding one subsystem over, and this sweep had
// already written the rule down: the READ path was given the clock and the
// ALERT was left keyed on an attempt. There the fix clamped the one sleep that
// could straddle the threshold; here there is no loop to clamp, so detection
// gets its own bounded watchdog — the CHAOS-23 `runCatalogStaleWatchdogLoop`
// precedent, where a detection-only ticker keeps a staleness alert live when
// the thing that would have produced it has stopped happening.
func idpMetadataDegradationSweep(now time.Time) []idpMetadataOutcome {
	idpMetadata.mu.Lock()
	var fire []idpMetadataOutcome
	for _, ep := range idpMetadata.episodes {
		if ep == nil || ep.alerted || ep.firstFailure.IsZero() {
			continue
		}
		if now.Sub(ep.firstFailure) < idpMetadataDegradedAfter {
			continue
		}
		ep.alerted = true
		fire = append(fire, ep.lastOutcome)
	}
	idpMetadata.mu.Unlock()
	return fire
}

// idpMetadataWatchdogInterval is capped BELOW idpMetadataDegradedAfter, which is
// a CORRECTNESS bound rather than tuning: an interval that can straddle a state
// transition delays the page past its documented threshold (CHAOS-55's
// recoveryPollCeiling rule, and CHAOS-66's clamped sleep).
const idpMetadataWatchdogInterval = idpMetadataDegradedAfter / 4

// runIdPMetadataDegradationWatchdog fires the degradation page for an episode
// that crossed the threshold with no further fetch to notice it. It is
// detection-only: it never fetches, never compiles, and never clears an episode
// — recovery stays on OBSERVED evidence.
// idpStaleCeilingVictim names a LIVE provider whose cached document has passed
// idpmeta.StaleMaxAge and must therefore stop being served.
type idpStaleCeilingVictim struct {
	profileID string
	source    string
	age       time.Duration
}

// idpStaleCeilingSweep returns the providers whose currently-served cached
// document is older than idpmeta.StaleMaxAge, and clears the recorded fetch time
// so one document is reported once.
//
// It reads the fetch time recorded by noteIdPStaleDocumentServed rather than
// calling Store.Get: the ceiling's VALUE stays the store's (idpmeta.StaleMaxAge
// is imported, never re-stated), and this avoids a disk read per profile per tick
// inside the health plane. The returned list is acted on with idpMetadata.mu
// RELEASED — retiring takes the registry's write lock, and holding one
// subsystem's lock across another's call is the CHAOS-50 cluster-CA rule.
func idpStaleCeilingSweep(now time.Time) []idpStaleCeilingVictim {
	var out []idpStaleCeilingVictim
	idpMetadata.mu.Lock()
	for _, ep := range idpMetadata.episodes {
		if ep == nil || ep.servedFetchedAt.IsZero() {
			continue
		}
		age := now.Sub(ep.servedFetchedAt)
		if age < idpmeta.StaleMaxAge {
			continue
		}
		out = append(out, idpStaleCeilingVictim{profileID: ep.profileID, source: ep.source, age: age})
		// One document, one retirement. A provider that is re-compiled and falls
		// back to cache again records a fresh fetch time and can be swept again.
		ep.servedFetchedAt = time.Time{}
	}
	idpMetadata.mu.Unlock()
	// Deterministic order so a multi-profile sweep logs and retires the same way
	// every run — the test-determinism class the repo's shuffle gate catches.
	sort.Slice(out, func(i, j int) bool { return out[i].profileID < out[j].profileID })
	return out
}

// idpRetireStaleProvider is the seam the watchdog uses to stop serving a
// provider whose cached document has expired. Package-level so tests observe the
// decision without a live registry, matching fireIdPMetadataAlert.
var idpRetireStaleProvider = func(profileID, source string) bool {
	return idpRegistry.retireStaleProvider(profileID, source)
}

// idpArmRecovery is the seam for re-arming the recovery loop after a retirement.
var idpArmRecovery = func(ctx context.Context) { armIdPRecoveryLoop(ctx) }

// idpAnyProfileDark is the seam for "is there anything to recover".
var idpAnyProfileDark = func() bool { return idpRegistry.hasDarkEnabledProfile() }

func runIdPMetadataDegradationWatchdog(ctx context.Context) {
	t := time.NewTicker(idpMetadataWatchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			for _, outcome := range idpMetadataDegradationSweep(now) {
				fireIdPMetadataAlert(fmt.Sprintf(
					"IdP metadata/discovery document unreachable for over %s (outcome: %s)",
					idpMetadataDegradedAfter, outcome))
			}
			// ENFORCE THE CEILING, do not merely report it. Store.Get refuses a
			// document past idpmeta.StaleMaxAge, but it is reached only from a
			// compile, and a steady-state node never recompiles — so without
			// this a provider stayed live forever on an expired document while
			// the runbook promised it would stop being usable (Codex round 8).
			// Retiring makes it DARK, which is exactly the state a fresh boot
			// past the ceiling would produce, and hands it to the recovery loop.
			for _, v := range idpStaleCeilingSweep(now) {
				if !idpRetireStaleProvider(v.profileID, v.source) {
					continue
				}
				logger.Printf("IDP_METADATA_EXPIRED idp=%q — the cached document it was serving is %s old, past the %s ceiling; the provider is no longer live and browser SSO is unavailable for it until a document is fetched successfully",
					sanitizeLog(v.profileID), v.age.Round(time.Minute), idpmeta.StaleMaxAge)
				fireIdPMetadataAlert(fmt.Sprintf(
					"IdP metadata/discovery document expired past the %s staleness ceiling; the provider is no longer live",
					idpmeta.StaleMaxAge))
			}
			// The recovery loop RETURNS once nothing is dark and is started
			// once at boot, so a retirement (or any later transition into dark)
			// would otherwise have nothing retrying it — SSO down with no way
			// back short of a restart, strictly worse than the defect above.
			// Re-arming every tick makes the watchdog the supervisor and closes
			// the arm/exit race by repetition rather than by a lock.
			if idpAnyProfileDark() {
				idpArmRecovery(ctx)
			}
		}
	}
}
