package catdb

// resilient.go — CHAOS-50: surviving a corrupt Layer-2 community store.
//
// The MECHANISM that makes this safe — per-attempt flock-owned poison markers,
// the store lock held across the rename, the quarantine-never-delete rule, and
// the badger open-error classifier — moved to internal/badgerguard in CHAOS-57
// (review §25), when the same uncatchable panic was found on the request-
// history store. It was moved rather than copied so the two stores cannot drift
// into two dialects of the same recovery; read that package for why each rule
// exists. This file is now the community store's POLICY and wiring:
//
//   - which returned errors count as corruption for THIS store (the default
//     posture: it is never opened with an encryption key, so a KEYREGISTRY
//     "encryption key mismatch" really is damage here — the history store,
//     which IS opened with a key, must and does exclude it), and
//   - the store's degradation contract: on failure the caller MUST fall back to
//     Layer-1-only categorisation rather than treat it as fatal. This store
//     holds no authoritative state — it is a derived cache of a downloadable
//     feed, and the syncer refills an empty one automatically — so refusing to
//     boot an in-line gateway over it is a self-inflicted outage.
//
// The gates in resilient_test.go are unchanged across the move and are the
// proof that it was faithful.

import "github.com/KidCarmi/Culvert/internal/badgerguard"

// The recovery vocabulary is the shared one. Aliases (not new types) so a
// Recovery produced by badgerguard and consumed as a catdb.Recovery — which is
// what OpenResilient returns — stays one value with one meaning.
type (
	// RecoveryTrigger names what caused a recovery attempt.
	RecoveryTrigger = badgerguard.Trigger
	// Recovery reports what OpenResilient had to do. It is data, not logging:
	// the caller owns the log line, the alert and the metrics.
	Recovery = badgerguard.Recovery
)

const (
	// TriggerNone means the store opened normally.
	TriggerNone = badgerguard.TriggerNone
	// TriggerPoisonMarker means a previous process died inside badger.Open on
	// this directory (uncatchable panic, SIGKILL, OOM, or a fatal exit).
	TriggerPoisonMarker = badgerguard.TriggerPoisonMarker
	// TriggerOpenError means badger.Open returned an error identified as
	// corruption of the on-disk store.
	TriggerOpenError = badgerguard.TriggerOpenError
)

// communityStorePolicy is this store's corruption posture. It is the FULL
// default list: the community store is opened without an encryption key, so
// "encryption key mismatch" can only mean KEYREGISTRY damage here. Any store
// opened WITH a key must narrow this — see internal/logstore/resilient.go.
func communityStorePolicy() badgerguard.Policy { return badgerguard.DefaultPolicy() }

// OpenResilient opens the community store, recovering from a store the previous
// run could not survive. It never panics on behalf of badger — the panic case
// is handled by refusing to hand badger a directory a previous process died
// inside of — and it never destroys data it has not first moved aside.
//
// Returns (db, recovery, nil) on success. On failure the caller MUST degrade
// (Layer-1-only categorisation) rather than treat it as fatal: this store is a
// cache, and refusing to boot an in-line gateway over a damaged cache is a
// self-inflicted outage.
func OpenResilient(dir string) (*CommunityDB, Recovery, error) {
	return badgerguard.Open(dir, communityStorePolicy(), Open)
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last.
// Exported so the caller can re-surface an unreconciled quarantine from a
// PRIOR boot: the in-memory record is process-local, so without this a
// self-healed store looks pristine on the next restart while the evidence — and
// the disk it occupies — is still sitting there.
func QuarantinedCopies(dir string) []string { return badgerguard.QuarantinedCopies(dir) }

// ── seams, for the gates in resilient_test.go ────────────────────────────────
//
// These keep this package's chaos suite exercising the mechanism through the
// same names it used before the move, so the extraction is verified by tests
// that did not change with it. They add no behaviour of their own.

type openErrClass = badgerguard.ErrClass

const (
	classUnknown     = badgerguard.ClassUnknown
	classEnvironment = badgerguard.ClassEnvironment
	classCorrupt     = badgerguard.ClassCorrupt

	maxQuarantinedCopies = badgerguard.MaxQuarantinedCopies

	quarantineSuffix = badgerguard.QuarantineSuffix
	markerSuffix     = badgerguard.MarkerSuffix
	markerTempSuffix = badgerguard.MarkerTempSuffix
)

func trimSep(p string) string { return badgerguard.StoreBase(p) }

var errStoreLockNotHeld = badgerguard.ErrStoreLockNotHeld

func classifyOpenError(err error) openErrClass {
	return badgerguard.Classify(err, communityStorePolicy())
}

func abandonedMarkers(dir string) []string { return badgerguard.AbandonedMarkers(dir) }

func beginAttempt(dir string) *badgerguard.OpenAttempt { return badgerguard.BeginAttempt(dir) }

func lockStore(dir string) (*badgerguard.HeldLock, error) { return badgerguard.LockStore(dir) }

func quarantineDir(lock *badgerguard.HeldLock, dir string) (string, error) {
	return badgerguard.QuarantineDir(lock, dir)
}

// No shim for ApplyQuarantine: this package's gates reach it only through
// OpenResilient, and badgerguard covers it directly. A pass-through with no
// caller is dead code, which staticcheck (U1000) is right to reject.
