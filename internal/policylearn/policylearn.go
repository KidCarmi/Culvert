// Package policylearn is the Security Policy Learning Mode engine (ADR-0025):
// the Learning Session lifecycle (M1) with schema-versioned, bounded,
// fail-closed node-local persistence, plus the observation TRANSPORT (M2) — a
// bounded drop-on-full queue with a single drain goroutine (see observe.go).
// Aggregation, recommendations, and any API/GUI surface are deliberately
// absent until M3+.
//
// Design contract (ADR-0025 — every clause is test-pinned):
//
//   - ADVISORY ONLY. Learning has no authority over active policy or any
//     enforcement subsystem. This package's import surface is walled to the
//     standard library + internal/fileutil + internal/obs (root wall test);
//     it cannot import or mutate the policy store, TLS/decryption, PAC, CDR,
//     default-action, or any other enforcement state. Everything it needs
//     from the outside arrives through injected function values on Config.
//   - INJECTED CLOCK. The engine never reads the wall clock; Config.Now is
//     required and every time-dependent decision (expiry, stamps, gaps) is a
//     pure function of it — deterministic under test.
//   - NODE-LOCAL, OFF EVERY CONFIG SURFACE. Session state persists to one
//     JSON document via fileutil.AtomicWrite (0600): never exported/imported,
//     never on the config-version rollback surface, never CP→DP synced.
//   - FAIL-CLOSED PERSISTENCE. A corrupt store is quarantined through the
//     injected seam and the engine starts empty (never half-loaded). A store
//     written by a NEWER schema is left untouched and the engine refuses to
//     write (read-only) — a downgrade can never clobber newer state.
//   - BOUNDED. Terminal sessions are pruned FIFO to MaxRetainedSessions; an
//     active session auto-completes at MaxSessionDuration (lazily, on the
//     next engine operation — no timers). The engine's ONLY goroutine is the
//     M2 observation drain, started at construction and stopped
//     deterministically by Close.
//   - EXPLICIT OFF STATE. Disabled means this engine is simply never
//     constructed: no file, no goroutine, no allocation (the root singleton
//     stays nil).
package policylearn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults and clamps for the engine bounds.
const (
	DefaultMaxRetainedSessions = 8
	maxRetainedSessionsCeiling = 64
	DefaultMaxSessionDuration  = 90 * 24 * time.Hour
	minSessionDuration         = time.Hour
)

// Sentinel errors returned by lifecycle operations.
var (
	// ErrActiveSession: StartSession while a session is already Learning
	// (the one-active-session invariant).
	ErrActiveSession = errors.New("policylearn: a learning session is already active")
	// ErrNoActiveSession: Stop/Cancel with no session in Learning.
	ErrNoActiveSession = errors.New("policylearn: no active learning session")
	// ErrStoreReadOnly: the persisted store was written by a newer schema;
	// the engine refuses every mutation so a downgrade can never clobber it.
	ErrStoreReadOnly = errors.New("policylearn: session store schema is newer than this binary (read-only)")
)

// Baseline pins the configuration generations a session's future evidence is
// valid against (ADR-0025 §6). M1 carries the minimal set; M2+ extends it via
// the same injected capture seam without touching the engine.
type Baseline struct {
	PolicyGeneration int64  `json:"policy_generation"`
	DefaultAction    string `json:"default_action,omitempty"`
	CapturedAt       string `json:"captured_at,omitempty"`     // RFC3339 UTC
	CategoryEpoch    string `json:"category_epoch,omitempty"`  // opaque category-generation identity pinned at Start (M3)
	GuardrailsHash   string `json:"guardrails_hash,omitempty"` // recommendable-category allowlist identity pinned at Start (M4)
	// PolicyContentHash is the canonical CONTENT identity of the running access
	// policy at session start (M5A): unlike PolicyGeneration (a persisted
	// counter — robust to restarts but not to counter resets or same-content
	// re-imports), this is a deterministic hash of the policy content itself,
	// captured by root wiring. Opaque to the engine; compared for staleness.
	PolicyContentHash string `json:"policy_content_hash,omitempty"`
}

// Config wires the engine. Now is REQUIRED; everything else has safe defaults.
type Config struct {
	// StorePath is the session-store JSON document. Empty = memory-only
	// (tests); the engine then never touches the filesystem.
	StorePath string
	// Now is the injected clock (required — New rejects nil).
	Now func() time.Time
	// Baseline captures the generation pins at session start. nil = zero
	// Baseline (M1 root wiring supplies the real capture).
	Baseline func() Baseline
	// Quarantine is invoked when the store fails to parse: the root wires
	// the process quarantine (rename + alert + readiness row). nil = the
	// engine still starts empty; the corrupt file is left in place and will
	// be overwritten by the next successful save.
	Quarantine func(path string, err error)
	// MaxRetainedSessions bounds retained TERMINAL sessions (FIFO prune).
	// 0 ⇒ DefaultMaxRetainedSessions; clamped to [1, 64].
	MaxRetainedSessions int
	// MaxSessionDuration auto-completes an overdue active session (lazily).
	// 0 ⇒ DefaultMaxSessionDuration; clamped up to minSessionDuration.
	MaxSessionDuration time.Duration
	// Sink consumes drained observations (M2: tests / the M3 aggregator).
	// nil = validated observations are counted and discarded. Called ONLY from
	// the single drain goroutine, with per-event panic containment. Fixed at
	// construction; never called after Close returns.
	Sink func(Observation)
	// SubjectKeyPath is the durable pseudonymization key (M3), stored
	// SEPARATELY from StorePath. Empty = ephemeral in-memory key (memory-only
	// engines; tokens are not restart-stable there by construction).
	SubjectKeyPath string
	// Categories resolves a destination host to (category, tier). Called ONLY
	// from the drain goroutine (never the request hot path). nil = everything
	// aggregates as uncategorized ("", tier "none").
	Categories func(host string) (category, tier string)
	// CategoryEpoch returns the current opaque category-generation identity
	// (feed generation + overrides revision + admin taxonomy sequence). Pinned
	// into the session baseline at Start; a mid-session change is recorded as
	// churn. nil = epoch tracking disabled.
	CategoryEpoch func() string
	// RecommendableCategories is the fail-closed ALLOWLIST of categories the
	// M4 generator may recommend (never a denylist): a cell whose category is
	// not on this list can never produce a recommendation, and an EMPTY list
	// means NOTHING is recommendable. Canonicalized deterministically at New
	// (trim/dedupe/sort, exact-match semantics); its identity (GuardrailsHash)
	// is pinned into every session Baseline at Start.
	RecommendableCategories []string
	// Recommend holds the explicit confidence-predicate thresholds (M4). Zero
	// fields take the package defaults.
	Recommend Thresholds
}

// Engine owns the Learning Session lifecycle and (M2) the observation
// transport. Session state is guarded by one mutex; accessors return copies,
// never internal pointers. learningActive mirrors "a session is Learning" as
// an atomic so the request-path Observe gate is lock-free.
type Engine struct {
	mu       sync.Mutex
	cfg      Config
	sessions []*Session // insertion order = creation order
	readOnly bool       // ErrSchemaTooNew posture: never write
	dirty    bool       // lazy-expiry flipped state in memory; persisted on next mutation/Close

	// opMu serializes the LIFECYCLE operations (Start/Stop/Cancel/Close) so a
	// finish can release e.mu for its drain barrier without a concurrent
	// lifecycle op interleaving. Never taken by Observe or the drain.
	opMu sync.Mutex

	learningActive atomic.Bool // M2: lock-free Observe gate, maintained on every state change
	closed         atomic.Bool // transport shut down: Observe refuses + counts instead of enqueueing into an abandoned channel
	tr             *transport  // M2: bounded observation queue + single drain

	// Acceptance-window generation (Codex fix): windowGen is stamped onto every
	// accepted observation; aggGen (under mu) is the generation of the CURRENT
	// aggregation target. Consumption requires equality, so a completed
	// session's aggregate is immutable and a later session can never consume
	// events accepted under an earlier window.
	windowGen atomic.Uint64
	aggGen    uint64 // under mu
	finishing bool   // under mu: a finish holds the lifecycle between window-close and persist; lazy expiry must not race it

	// M3 aggregation state (all mutated under mu; drain-owned cadence counters
	// are also only touched under mu inside consumeGuarded).
	subjKey      *subjectKey // durable pseudonymization key
	aggSession   *Session    // the session observations are attributed to (the one Learning when accepted)
	scopeScratch []string    // reusable scope buffer for the drain
	sinceFlush   int         // observations since the last aggregate persist
	sinceEpoch   int         // observations since the last category-epoch check
	tPin         ObservationStats

	// M4 recommendation state. allowlist/allowSet/guardrailsHash/th are
	// immutable after New (read without mu); recs is guarded by mu.
	allowlist      []string
	allowSet       map[string]bool
	guardrailsHash string
	th             Thresholds
	recPolicy      RecommendationPolicy // M4.1: canonical decision-policy snapshot (immutable after New)
	recPolicyHash  string               // M4.1: its deterministic identity
	recs           []*Recommendation
}

// New constructs the engine and loads the store (fail-closed; see load).
func New(cfg Config) (*Engine, error) {
	if cfg.Now == nil {
		return nil, errors.New("policylearn: Config.Now is required (injected clock)")
	}
	if cfg.MaxRetainedSessions <= 0 {
		cfg.MaxRetainedSessions = DefaultMaxRetainedSessions
	}
	if cfg.MaxRetainedSessions > maxRetainedSessionsCeiling {
		cfg.MaxRetainedSessions = maxRetainedSessionsCeiling
	}
	if cfg.MaxSessionDuration <= 0 {
		cfg.MaxSessionDuration = DefaultMaxSessionDuration
	}
	if cfg.MaxSessionDuration < minSessionDuration {
		cfg.MaxSessionDuration = minSessionDuration
	}
	e := &Engine{cfg: cfg}
	e.allowlist = canonicalizeCategories(cfg.RecommendableCategories)
	e.allowSet = make(map[string]bool, len(e.allowlist))
	for _, c := range e.allowlist {
		e.allowSet[c] = true
	}
	e.guardrailsHash = guardrailsHashFor(e.allowlist)
	e.th = cfg.Recommend.withDefaults()
	e.recPolicy = e.th.policySnapshot()
	e.recPolicyHash = recommendationPolicyHashFor(e.recPolicy)
	sk, err := loadOrCreateSubjectKey(cfg.SubjectKeyPath)
	if err != nil {
		return nil, err
	}
	e.subjKey = sk
	if err := e.load(); err != nil {
		// load only returns unexpected I/O errors (corrupt/newer-schema are
		// handled fail-closed inside); surface them to the caller.
		return nil, fmt.Errorf("policylearn: load store: %w", err)
	}
	e.learningActive.Store(e.activeLocked() != nil) // constructor: no concurrency yet
	e.startTransport()
	return e, nil
}

// ReadOnly reports the newer-schema fail-closed posture.
func (e *Engine) ReadOnly() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.readOnly
}

// Close stops the observation transport (draining everything already queued —
// deterministic shutdown), then flushes any lazily-flipped session state. Safe
// to call more than once and on a read-only engine.
func (e *Engine) Close() error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if t := e.tr; t != nil {
		// Refuse (and count) producers BEFORE the drain exits, then sweep the
		// channel once the drain is gone: a producer that raced past the
		// closed flag may have enqueued after the drain's final empty check,
		// and nothing may successfully enqueue into an abandoned channel
		// (Codex fix). Post-stop the channel has exactly one reader: us.
		e.closed.Store(true)
		// Wait for in-flight producers (registered before the flag was set)
		// to finish their enqueue decision — afterwards no send can land in
		// the channel beyond what the sweep below consumes (Codex fix).
		t.waitProducers()
		t.stopOnce.Do(func() {
			close(t.stop)
			<-t.done
		})
	sweep:
		for {
			select {
			case q := <-t.ch:
				if q.barrier != nil {
					close(q.barrier)
					continue
				}
				e.consumeGuarded(t, q.o)
			default:
				break sweep
			}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncTransportLocked() // fold the final window deltas before the flush
	if !e.dirty {
		return nil
	}
	return e.saveLocked()
}

// newID returns a 16-hex-char random session ID (stdlib-only; no external
// ULID dependency inside the wall).
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is process-fatal territory elsewhere; here a
		// zero ID would collide, so fall back to a nanosecond stamp is NOT
		// possible (no clock in scope) — return a fixed marker the caller's
		// injected-clock stamp disambiguates. In practice rand.Read on a
		// supported platform does not fail.
		return "rand-unavailable"
	}
	return hex.EncodeToString(b[:])
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
