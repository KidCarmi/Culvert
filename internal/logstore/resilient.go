package logstore

// resilient.go — CHAOS-57: surviving a corrupt request-history store.
//
// WHY THIS STORE NEEDED IT SECOND
//
// CHAOS-50 gave the Layer-2 community category store a recovery path because a
// corrupt `.sst` makes badger.Open PANIC from a goroutine badger spawns, which
// no recover() at the call site can contain. That review recorded this store as
// carrying the identical exposure (register row R-E, "next sweep candidate")
// and deferred it. Re-measured here against THIS store's option set — encryption
// on, 128 MiB value log — the panic reproduces exactly: badger v4.9.6,
// `table.OpenTable ← newLevelsController`, process dead, deferred recover never
// reached.
//
// The deferral also understated the exposure in two ways.
//
// It is not boot-only. `enableLogStore` is reachable from the live admin API
// (the history toggle), so opening a damaged store kills an in-line gateway
// that is carrying production traffic at the moment an admin flips a switch in
// the GUI — no restart required, no warning available.
//
// And it LATCHES. The toggle is durable in admin_settings.json, and
// `LoadAdminSettings` re-enables the store on every subsequent boot. Under the
// shipped compose file's `restart: unless-stopped`, one unclean container kill
// that damages a table therefore becomes an unattended crash loop: no proxy, no
// admin UI, no health endpoint, and no way to turn the setting back off,
// because turning it off requires the admin UI that the setting prevents from
// starting. The category store needed a CLI flag to reach that state; this one
// gets there from an admin's saved preference.
//
// WHAT IS DIFFERENT ABOUT THIS STORE
//
// Two things, both about the encryption key, and the first is the reason
// `storeguard.Policy` exists at all.
//
//  1. badger reports KEYREGISTRY damage as "Encryption key mismatch". For the
//     category store — never opened with a key — that message can only mean
//     corruption, which is why the shared table lists it. This store IS opened
//     with a key, and measured on badger v4.9.6 the SAME error also covers two
//     conditions whose data is perfectly intact: the operator changed the
//     history passphrase, and the salt sidecar was lost. Reusing the shared rule
//     unmodified would move a healthy history store aside over an ordinary
//     configuration change — so this store exempts it, structurally on the
//     sentinel and textually on the raw badger message.
//
//  2. The salt sidecar is a SIBLING of the store directory (`<dir>.salt`), so a
//     quarantine — which renames only the directory — leaves it in place. That
//     is required in both directions: the replacement store derives the same key
//     and keeps working, and the quarantined copy stays decryptable with the
//     same sidecar, so the evidence an operator is left holding is evidence they
//     can actually read. EncKey's refusal to mint a fresh salt over an existing
//     store is what keeps that true.
//
// WHAT THE CALLER MUST DO
//
// Degrade, never exit. This store is request HISTORY — a retention-bounded
// record, not authoritative state the gateway needs in order to decide
// anything. Running without it is exactly the posture of a node that has never
// had the toggle switched on. That is also why the quarantine moves the
// directory aside rather than deleting it: history has evidentiary value, so
// the bytes stay on the volume for an operator to reconcile.

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// historyStorePolicy holds the guard back from the one shared corruption signal
// that is ambiguous for a keyed store.
//
// Both exemptions describe the same condition at two layers, deliberately.
// `OpenTTL` currently rewrites every encryption-flavoured badger error into
// ErrEncMismatch, so the structural exemption is the one that fires today; the
// textual one covers the raw badger message directly, so a future change to
// that rewrite cannot silently re-arm a quarantine over a passphrase change.
// Neither can ever widen what gets moved aside — a Policy only ever subtracts.
var historyStorePolicy = storeguard.Policy{
	NeverCorrupt:     []error{ErrEncMismatch},
	NeverCorruptText: []string{"encryption key mismatch"},
}

// OpenResilientTTL opens the history store the way OpenTTL does, but survives a
// directory the previous run could not: a store a prior process died inside of
// is quarantined before badger is allowed near it again, and a returned error
// positively identified as corruption is quarantined and the open retried once.
//
// Returns (store, recovery, nil) on success. On failure the caller MUST degrade
// (run with history off) rather than treat it as fatal — see the file comment.
//
// Direct OpenTTL remains the entry point for callers that already know the
// directory is sound.
func OpenResilientTTL(dir string, ttl time.Duration, maxBytes int64, encKey []byte, minimal func() bool) (*Store, storeguard.Recovery, error) {
	return storeguard.Open(dir, historyStorePolicy, func(d string) (*Store, error) {
		return OpenTTL(d, ttl, maxBytes, encKey, minimal)
	})
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last, so a
// caller can re-surface an unreconciled quarantine from a PRIOR run: the
// in-memory record is process-local, so without this a self-healed store looks
// pristine on the next restart while the evidence — and the disk it occupies —
// is still sitting there.
func QuarantinedCopies(dir string) []string {
	return storeguard.QuarantinedCopies(dir)
}
