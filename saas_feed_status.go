package main

// saas_feed_status.go — F3b-4: the signed SaaS URL-category feed's runtime STATUS model.
//
// A single thread-safe holder owns the feed's observable runtime state. Readers (the
// status API, /metrics, /readyz, the GUI) take an IMMUTABLE snapshot; the lifecycle,
// scheduler, and refresh orchestrator publish facts through the note* mutators. The
// derived `state` is computed from those facts at snapshot time (never stored stale).
//
// Terminology reconciliation (recorded): the on-wire FIELD set is the F0 §14 contract
// (active_source ∈ {embedded,cached,downloaded}, signature_status, active_feed_version,
// last_attempt/last_success, failures_since_start, last_error_class, last_http_status,
// last_activation_delta, manifest_expires_at/expires_in_days, and the honest
// never_succeeded null-delta rule). The single `state` field uses the richer nine-value
// vocabulary this slice was specified against — disabled · waiting_for_authority ·
// recovering · embedded · fresh · stale · syncing · degraded · critical — which is a
// superset that folds F0's five lifecycle states (disabled/never_succeeded/healthy/
// degraded/stale) together with the serving-source and in-flight dimensions. F0's
// "never_succeeded" surfaces as `embedded` (enabled, no successful activation yet, the
// baseline serving) with a null activation delta.

import (
	"sync"
	"sync/atomic"
	"time"
)

// saasFeedState is the derived runtime state (the single `state` field).
type saasFeedState int

const (
	saasFeedStateDisabled            saasFeedState = iota // feed not enabled
	saasFeedStateWaitingForAuthority                      // managed DP with no valid authoritative config
	saasFeedStateRecovering                               // startup/crash recovery in progress
	saasFeedStateEmbedded                                 // serving the compiled baseline (no signed generation active)
	saasFeedStateFresh                                    // serving a valid, non-expired signed generation
	saasFeedStateStale                                    // serving a valid-but-expired signed generation (never fail-closed on age)
	saasFeedStateSyncing                                  // a refresh is in flight and the feed is otherwise fresh
	saasFeedStateDegraded                                 // ≥1 activation exists but recent refreshes fail; LKG served
	saasFeedStateCritical                                 // corruption / equivocation / unsafe authority loss — operator must act
)

func (s saasFeedState) String() string {
	switch s {
	case saasFeedStateDisabled:
		return "disabled"
	case saasFeedStateWaitingForAuthority:
		return "waiting_for_authority"
	case saasFeedStateRecovering:
		return "recovering"
	case saasFeedStateEmbedded:
		return "embedded"
	case saasFeedStateFresh:
		return "fresh"
	case saasFeedStateStale:
		return "stale"
	case saasFeedStateSyncing:
		return "syncing"
	case saasFeedStateDegraded:
		return "degraded"
	case saasFeedStateCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Bounded sanitized failure classes (last_error_class). NEVER a raw untrusted string.
const (
	saasFeedErrNone      = ""
	saasFeedErrFetch     = "fetch"     // network / DNS / SSRF / TLS / transport
	saasFeedErrHTTP      = "http"      // non-200/304 status
	saasFeedErrVerify    = "verify"    // signature / identity / bundle
	saasFeedErrParse     = "parse"     // envelope / artifact decode / schema
	saasFeedErrFreshness = "freshness" // expired / future-dated candidate
	saasFeedErrFloor     = "floor"     // rollback-floor / equivocation reject
	saasFeedErrPersist   = "persist"   // generation / floor / activation durability
	saasFeedErrConfig    = "config"    // authority / readiness / config churn
	saasFeedErrInternal  = "internal"  // unexpected
)

// Bounded refresh outcomes (last_outcome). NEVER a raw string.
const (
	saasFeedOutcomeOK       = "ok"        // a new generation activated
	saasFeedOutcomeNoChange = "no_change" // 304 / same-version — freshness recomputed, no activation
	saasFeedOutcomeError    = "error"     // an attempt failed (see last_error_class)
	saasFeedOutcomeCanceled = "canceled"  // shutdown cancellation (NOT a failure)
	saasFeedOutcomeSkipped  = "skipped"   // readiness gate: not enabled / not authoritative / no fetch
)

// saasFeedActivationDelta is the host-count change of the last SUCCESSFUL activation.
// Nil ⇒ never_succeeded (rendered as null — never "0 new hosts").
type saasFeedActivationDelta struct {
	HostsAdded   int `json:"hosts_added"`
	HostsRemoved int `json:"hosts_removed"`
	HostsChanged int `json:"hosts_changed"`
}

// saasFeedStatusSnapshot is the IMMUTABLE read model. Timestamps are time.Time (zero =
// never); the API/metrics layers render them as unix/RFC3339 with proper null handling.
type saasFeedStatusSnapshot struct {
	State saasFeedState

	// Configuration / authority.
	Configured     bool
	Enabled        bool
	Managed        bool
	Authority      string // standalone / control-plane / managed-dp
	ConfigRevision string
	Protocol       string
	URL            string

	// Serving provenance / trust.
	ActiveSource    string // embedded / downloaded / cached / resumed
	Provenance      string // embedded / cached / downloaded (F0 §14)
	SignatureStatus string // verified / compiled_trusted / failed
	CompiledTrusted bool

	// Active generation identity + freshness.
	ActiveFeedVersion int64 // 0 ⇒ none (embedded)
	GeneratedAt       time.Time
	ExpiresAt         time.Time
	Stale             bool
	ExpiresInDays     *int // nil when no generation / unknown

	// Composed footprint.
	HostCount        int
	CategoryCount    int
	OverrideCount    int
	OverrideRevision string

	// Attempt / success bookkeeping.
	LastAttempt              time.Time
	LastSuccessfulCheck      time.Time // last attempt that reached a verified verdict (activation OR 304/no-change)
	LastSuccessfulActivation time.Time
	NextAttempt              time.Time
	LastOutcome              string
	LastErrorClass           string
	LastHTTPStatus           int // 0 ⇒ n/a
	Last304                  bool

	FailuresSinceStart  int64
	ConsecutiveFailures int
	NeverSucceeded      bool
	LastActivationDelta *saasFeedActivationDelta // nil in never_succeeded

	// Operational overlays.
	Syncing             bool
	WaitingForAuthority bool
	Recovering          bool
	Critical            bool
	CriticalReason      string
	Detail              string
}

// saasFeedStatus is the process-wide status holder. failuresSinceStart is a
// process-lifetime atomic (readable at scrape without the mutex, matching Prometheus
// process-counter semantics). Everything else is guarded by mu.
type saasFeedStatus struct {
	mu  sync.RWMutex
	now func() time.Time

	configured     bool
	enabled        bool
	managed        bool
	authority      string
	configRevision string
	protocol       string
	url            string

	activeSource      effectiveSource
	activeFeedVersion int64
	generatedAt       time.Time
	expiresAt         time.Time
	stale             bool
	sigFailed         bool // a verify attempt failed since the last success (transient signal)

	hostCount        int
	categoryCount    int
	overrideCount    int
	overrideRevision string

	lastAttempt              time.Time
	lastSuccessfulCheck      time.Time
	lastSuccessfulActivation time.Time
	nextAttempt              time.Time
	lastOutcome              string
	lastErrorClass           string
	lastHTTPStatus           int
	last304                  bool

	consecutiveFailures int
	everSucceeded       bool
	lastDelta           *saasFeedActivationDelta

	syncing             bool
	waitingForAuthority bool
	recovering          bool
	critical            bool
	criticalReason      string
	detail              string

	failuresSinceStart atomic.Int64
}

// globalSaaSFeedStatus is the process-wide status holder (wired at startup; safe to read
// before wiring — it starts in the disabled state).
var globalSaaSFeedStatus = newSaaSFeedStatus(time.Now)

func newSaaSFeedStatus(now func() time.Time) *saasFeedStatus {
	if now == nil {
		now = time.Now
	}
	return &saasFeedStatus{now: now, protocol: saasFeedProtocolV1}
}

// ─── mutators (called by lifecycle / scheduler / orchestrator) ─────────────────────

// noteConfig publishes the resolved configuration + authority classification. It clears
// the waiting flag unless the resolution says otherwise.
func (s *saasFeedStatus) noteConfig(res feedAuthorityResolution) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The signed feed is runtime-active only under EXPLICIT enablement (managed &&
	// enabled) — an unmanaged/default install stays disabled (dormant), never fetching.
	s.enabled = res.Config.runtimeEnabled()
	s.managed = res.Config.Managed
	s.authority = res.Authority.String()
	s.protocol = res.Config.Protocol
	if s.protocol == "" {
		s.protocol = saasFeedProtocolV1
	}
	s.url = res.Config.URL
	s.configured = res.Config.URL != "" || res.Config.Managed
	s.waitingForAuthority = res.WaitingForAuthority
	s.overrideRevision = res.OverrideRevision
	if res.WaitingForAuthority || res.Detail != "" {
		s.detail = res.Detail
	}
}

// noteRecoveryStart marks the transient recovering state (startup/crash recovery).
func (s *saasFeedStatus) noteRecoveryStart() {
	s.mu.Lock()
	s.recovering = true
	s.mu.Unlock()
}

// noteRecovery folds the record-driven recovery outcome into the status. It sets the
// serving source, freshness, and critical flags, and — for a real generation — the
// active version/timestamps/counts. It does NOT touch attempt counters (recovery is not
// a network attempt). Recovery from a durable generation reports `cached` provenance;
// the embedded baseline reports honest compiled trust.
func (s *saasFeedStatus) noteRecovery(res recoveryResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recovering = false
	s.stale = res.Stale
	s.critical = res.Critical
	if res.Critical {
		s.criticalReason = res.Class.String()
	} else {
		s.criticalReason = ""
	}
	s.detail = res.Detail
	if res.View != nil {
		s.activeSource = res.View.Source
		s.activeFeedVersion = res.View.FeedVersion
		s.hostCount = res.View.HostCount()
		s.categoryCount = res.View.CategoryCount()
		s.configRevision = res.View.ConfigRevision
		s.generatedAt, _ = canonicalUTCSecond(res.View.GeneratedAt)
		s.expiresAt, _ = canonicalUTCSecond(res.View.ExpiresAt)
	}
	// Recovery of a committed generation is a durable success witness (it proves an
	// activation happened previously), so mark everSucceeded when a real generation is
	// served — but do NOT stamp lastSuccessfulActivation (no fresh activation occurred)
	// and do NOT create a delta (a restart's delta is meaningless → stays null).
	if res.ActiveVersion > 0 {
		s.everSucceeded = true
	}
}

// noteWaitingForAuthority forces the waiting state (managed DP, no authority) — the
// scheduler must not run and no network attempt is made.
func (s *saasFeedStatus) noteWaitingForAuthority(detail string) {
	s.mu.Lock()
	s.waitingForAuthority = true
	s.recovering = false
	s.detail = detail
	s.mu.Unlock()
}

// noteSyncStart / noteSyncEnd bracket an in-flight refresh.
func (s *saasFeedStatus) noteSyncStart() {
	s.mu.Lock()
	s.syncing = true
	s.lastAttempt = s.now()
	s.mu.Unlock()
}

func (s *saasFeedStatus) noteSyncEnd() {
	s.mu.Lock()
	s.syncing = false
	s.mu.Unlock()
}

// noteNextAttempt records the scheduler's next planned wake (for the GUI/metrics).
func (s *saasFeedStatus) noteNextAttempt(t time.Time) {
	s.mu.Lock()
	s.nextAttempt = t
	s.mu.Unlock()
}

// noteAttemptFailure records a failed refresh attempt. context.Canceled during shutdown
// is NOT a failure (excluded from counters, never flips to degraded). Returns nothing;
// the derived state reflects it. httpStatus is 0 when not applicable.
func (s *saasFeedStatus) noteAttemptFailure(errClass string, httpStatus int, canceled bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttempt = s.now()
	s.lastHTTPStatus = httpStatus
	s.last304 = false
	if canceled {
		s.lastOutcome = saasFeedOutcomeCanceled
		return // shutdown cancellation: not a failure
	}
	s.lastOutcome = saasFeedOutcomeError
	s.lastErrorClass = errClass
	s.detail = detail
	if errClass == saasFeedErrVerify {
		s.sigFailed = true
	}
	s.consecutiveFailures++
	s.failuresSinceStart.Add(1)
}

// noteNoChange records a 304 / same-version outcome: freshness is recomputed on the
// CURRENT active manifest, provenance is UNCHANGED, and this counts as a successful
// check (resets the failure streak) but NOT an activation.
func (s *saasFeedStatus) noteNoChange(expiresAt time.Time, stale bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.lastAttempt = now
	s.lastSuccessfulCheck = now
	s.lastOutcome = saasFeedOutcomeNoChange
	s.lastErrorClass = saasFeedErrNone
	s.last304 = true
	s.lastHTTPStatus = 304
	s.consecutiveFailures = 0
	s.sigFailed = false
	if !expiresAt.IsZero() {
		s.expiresAt = expiresAt
	}
	s.stale = stale
}

// noteActivation records a fresh successful activation (a NEW generation cut over). The
// caller passes the immutable view + the host delta. Status must never claim success
// before the durable activation + live cutover complete — the orchestrator calls this
// only AFTER the coordinator reports activationCommitted.
func (s *saasFeedStatus) noteActivation(view *effectiveCategoryView, delta saasFeedActivationDelta, httpStatus int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.lastAttempt = now
	s.lastSuccessfulCheck = now
	s.lastSuccessfulActivation = now
	s.lastOutcome = saasFeedOutcomeOK
	s.lastErrorClass = saasFeedErrNone
	s.last304 = false
	s.lastHTTPStatus = httpStatus
	s.consecutiveFailures = 0
	s.everSucceeded = true
	s.sigFailed = false
	s.critical = false
	s.criticalReason = ""
	d := delta
	s.lastDelta = &d
	if view != nil {
		s.activeSource = view.Source
		s.activeFeedVersion = view.FeedVersion
		s.hostCount = view.HostCount()
		s.categoryCount = view.CategoryCount()
		s.configRevision = view.ConfigRevision
		s.stale = view.Stale
		s.generatedAt, _ = canonicalUTCSecond(view.GeneratedAt)
		s.expiresAt, _ = canonicalUTCSecond(view.ExpiresAt)
	}
}

// noteOverrides records the applied override footprint (count + revision) after an
// override-driven rebuild.
func (s *saasFeedStatus) noteOverrides(count int, revision string, view *effectiveCategoryView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overrideCount = count
	s.overrideRevision = revision
	if view != nil {
		s.hostCount = view.HostCount()
		s.categoryCount = view.CategoryCount()
		s.configRevision = view.ConfigRevision
	}
}

// noteDisabled resets the operational overlays for a disabled feed (preserving the
// process-lifetime failure counter and last-known identity for display).
func (s *saasFeedStatus) noteDisabled() {
	s.mu.Lock()
	s.enabled = false
	s.syncing = false
	s.waitingForAuthority = false
	s.recovering = false
	s.mu.Unlock()
}

// ─── snapshot + derivation ─────────────────────────────────────────────────────────

// Snapshot returns the immutable read model with the derived state computed.
func (s *saasFeedStatus) Snapshot() saasFeedStatusSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := saasFeedStatusSnapshot{
		Configured: s.configured, Enabled: s.enabled, Managed: s.managed,
		Authority: s.authority, ConfigRevision: s.configRevision, Protocol: s.protocol, URL: s.url,
		ActiveSource: s.activeSource.String(), Provenance: provenanceOf(s.activeSource),
		SignatureStatus: s.signatureStatus(), CompiledTrusted: s.activeSource == sourceEmbedded && s.activeFeedVersion == 0,
		ActiveFeedVersion: s.activeFeedVersion, GeneratedAt: s.generatedAt, ExpiresAt: s.expiresAt,
		Stale: s.stale, HostCount: s.hostCount, CategoryCount: s.categoryCount,
		OverrideCount: s.overrideCount, OverrideRevision: s.overrideRevision,
		LastAttempt: s.lastAttempt, LastSuccessfulCheck: s.lastSuccessfulCheck,
		LastSuccessfulActivation: s.lastSuccessfulActivation, NextAttempt: s.nextAttempt,
		LastOutcome: s.lastOutcome, LastErrorClass: s.lastErrorClass, LastHTTPStatus: s.lastHTTPStatus,
		Last304: s.last304, FailuresSinceStart: s.failuresSinceStart.Load(),
		ConsecutiveFailures: s.consecutiveFailures, NeverSucceeded: !s.everSucceeded,
		Syncing: s.syncing, WaitingForAuthority: s.waitingForAuthority, Recovering: s.recovering,
		Critical: s.critical, CriticalReason: s.criticalReason, Detail: s.detail,
	}
	// never_succeeded ⇒ null delta (never render "0 new hosts").
	if s.everSucceeded && s.lastDelta != nil {
		d := *s.lastDelta
		snap.LastActivationDelta = &d
	}
	if !s.expiresAt.IsZero() && s.activeFeedVersion > 0 {
		days := int(s.expiresAt.Sub(s.now()).Hours() / 24)
		snap.ExpiresInDays = &days
	}
	snap.State = s.deriveStateLocked()
	return snap
}

// deriveStateLocked computes the single derived state from the current facts (caller
// holds the lock). Precedence: the most operator-significant condition wins.
func (s *saasFeedStatus) deriveStateLocked() saasFeedState {
	switch {
	case s.critical:
		return saasFeedStateCritical
	case s.waitingForAuthority:
		return saasFeedStateWaitingForAuthority
	case !s.enabled:
		return saasFeedStateDisabled
	case s.recovering:
		return saasFeedStateRecovering
	case s.activeFeedVersion > 0 && s.stale:
		return saasFeedStateStale
	case s.activeFeedVersion > 0 && s.consecutiveFailures > 0:
		return saasFeedStateDegraded
	case s.activeFeedVersion == 0:
		// Enabled, no signed generation active ⇒ serving the compiled baseline. This is
		// F0's "never_succeeded" (valid, expected: the baseline serves).
		return saasFeedStateEmbedded
	case s.syncing:
		return saasFeedStateSyncing
	default:
		return saasFeedStateFresh
	}
}

// signatureStatus reports the honest trust of the served content (caller holds the lock).
func (s *saasFeedStatus) signatureStatus() string {
	if s.activeFeedVersion == 0 {
		if s.sigFailed {
			return "failed"
		}
		return "compiled_trusted"
	}
	if s.sigFailed {
		return "failed"
	}
	return "verified"
}

// provenanceOf collapses the four serving sources to the F0 §14 provenance vocabulary
// (embedded / cached / downloaded). A resumed floor-ahead activation is downloaded
// content completed via recovery ⇒ downloaded.
func provenanceOf(src effectiveSource) string {
	switch src {
	case sourceDownloaded, sourceResumed:
		return "downloaded"
	case sourceCached:
		return "cached"
	default:
		return "embedded"
	}
}
