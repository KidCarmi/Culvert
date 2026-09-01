package logstore

// resilient.go — CHAOS-57: surviving a request-history store the previous
// process could not open.
//
// WHY THIS EXISTS
//
// OpenTTL calls badger.Open, and a corrupted `.sst` table makes that call PANIC
// from a goroutine badger itself spawns. No recover() at any call site can
// contain it, so the process dies. CHAOS-50 (review §19) closed exactly this
// hole for the Layer-2 community store and recorded this one as still open
// (R-E, "next sweep candidate"). Two things make it the more dangerous of the
// pair, both consequences of WHERE this store gets opened:
//
//   - It is opened at RUNTIME, from the admin API. `POST /api/logs/retention
//     {"enabled":true}` reaches badger.Open on the HTTP handler's goroutine, so
//     a damaged store turns an admin toggle into an immediate death of a
//     SERVING gateway: every in-flight tunnel dropped, mid-request.
//   - The enable decision is DURABLE (`LogStoreEnabled` in admin_settings.json)
//     and is replayed on every boot. So a store that becomes damaged after it
//     was legitimately enabled produces an unattended crash loop under
//     `restart: unless-stopped` — and the lever that would turn it off lives in
//     an admin UI that never finishes starting.
//
// The mechanism that fixes it is not new and is deliberately not re-derived:
// internal/badgerguard holds the per-attempt flock-owned poison markers, the
// store lock held across the rename, and the quarantine-never-delete rule, all
// moved there from catdb rather than copied. Read that package for why each
// rule is shaped the way it is.
//
// WHAT IS DIFFERENT HERE — AND IT IS THE PART THAT MATTERS
//
// This store is opened WITH an encryption key; the community store never is.
// That inverts the meaning of one signal in the shared corruption list.
// "encryption key mismatch" out of badger is KEYREGISTRY damage for a store
// with no key, but for this one it is the ordinary, RECOVERABLE operator
// mistake — a changed CULVERT_LOGSTORE_PASSPHRASE, or a lost `.salt` sidecar —
// which the admin API already handles by name (ErrEncMismatch → "purge saved
// logs, then enable again"). Quarantining on it would move an operator's entire
// searchable history aside because they mistyped a passphrase, and it would do
// so at the exact moment they are trying to fix the passphrase. So the policy
// here REMOVES that signal, explicitly and visibly at the call site.
//
// The removal is a real guard, not a formality. OpenTTL maps badger's encrypt
// errors onto ErrEncMismatch before they are ever classified, and that
// sentinel's current wording ("saved logs use a different encryption key")
// happens not to contain the substring "mismatch" — so today the default policy
// would already decline to quarantine, BY ACCIDENT. One reword of a
// user-facing string would silently arm the destructive branch. Without() makes
// that impossible and TestHistoryPolicy_* pins it.
//
// IS QUARANTINING HISTORY EVEN ALLOWED?
//
// §19 deferred this store partly on the grounds that its content is request
// history with retention semantics, so moving it aside is "an evidence
// decision, not a cache decision". Reading the write path settles it: this
// store is NOT the record of truth. reqlog.Add enqueues every entry onto the
// durable JSONL drain and THEN hands the same entry to this store through the
// history hook (internal/reqlog/reqlog.go, `enqueue(e)` then `history(e)`;
// the hook is installed at store.go's `reqlog.SetHistory`). The JSONL file is
// the durable request log; this store is the queryable index over it. A
// quarantine therefore costs the admin their search index, not their record —
// and it costs them nothing at all silently: the caller raises an alert, an
// operator-contract row and metrics, and the damaged directory is MOVED ASIDE,
// never deleted, so the bytes are still there to be recovered from.
//
// A store that is genuinely damaged AND encrypted may surface as ErrEncMismatch
// and therefore never auto-recover. That is deliberate and is not a dead end:
// it lands on the documented manual remedy (purge, then re-enable), which is
// the right posture for the one case where "damaged" and "the operator changed
// the key" are indistinguishable from the outside.

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/badgerguard"
)

// Recovery re-exports the shared recovery record so callers of this package do
// not have to import badgerguard just to read the outcome.
type Recovery = badgerguard.Recovery

// TriggerNone is the "nothing was wrong" recovery trigger, re-exported for the
// same reason: a caller distinguishing "opened cleanly" from "opened after a
// scare" should not need a second import to say so.
const TriggerNone = badgerguard.TriggerNone

// historyStorePolicy is this store's corruption posture: the shared default,
// minus the one signal that means something different for an encrypted store.
// See the file header — this single call is the whole divergence.
func historyStorePolicy() badgerguard.Policy {
	return badgerguard.DefaultPolicy().Without("encryption key mismatch")
}

// OpenResilientTTL is the boot-and-admin-path constructor for the history
// store. It is OpenTTL with the guard around it: a directory a previous process
// died inside of is moved aside BEFORE badger is handed it again, so the
// uncatchable panic costs one restart instead of every restart.
//
// Direct OpenTTL remains available for callers that already know the directory
// is sound (tests, and this function itself).
//
// On success it returns (store, recovery, nil); `recovery.Quarantined` reports
// whether history was reset to recover. On failure the caller MUST degrade —
// history is an enhancement over the in-memory ring, so it must never stop the
// proxy from serving traffic, and it must never take a serving proxy down.
func OpenResilientTTL(dir string, ttl time.Duration, maxBytes int64, encKey []byte, minimal func() bool) (*Store, Recovery, error) {
	return badgerguard.Open(dir, historyStorePolicy(), func(d string) (*Store, error) {
		return OpenTTL(d, ttl, maxBytes, encKey, minimal)
	})
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last, so a
// quarantine from a PRIOR run stays visible to the operator: the in-memory
// record is process-local, and without this a self-healed store looks pristine
// on the next restart while the evidence — and the disk it occupies — is still
// sitting there.
func QuarantinedCopies(dir string) []string { return badgerguard.QuarantinedCopies(dir) }
