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
//     it cannot import or mutate PolicyStore, TLS/decryption, PAC, CDR,
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
	CapturedAt       string `json:"captured_at,omitempty"` // RFC3339 UTC
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

	learningActive atomic.Bool // M2: lock-free Observe gate, maintained on every state change
	tr             *transport  // M2: bounded observation queue + single drain
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
	if t := e.tr; t != nil {
		t.stopOnce.Do(func() {
			close(t.stop)
			<-t.done
		})
	}
	e.mu.Lock()
	defer e.mu.Unlock()
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
