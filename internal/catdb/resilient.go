package catdb

// resilient.go — CHAOS-50: surviving a corrupt Layer-2 community store.
//
// The recovery machinery this file used to carry in full now lives in
// `internal/storeguard`, because CHAOS-62 found the identical uncatchable-panic
// exposure on the request-history store (`internal/logstore`) and a second copy
// of the empirically-derived badger message table is precisely the artefact
// that must never drift — it is pinned by a test so a badger upgrade that
// rewords a message fails the build instead of silently switching recovery off.
// The reasoning behind every rule (per-attempt flock-owned poison markers, the
// lock held ACROSS the rename, environmental-before-corruption classification,
// degrade-on-unknown) is documented there and is unchanged.
//
// What stays here is the part that is genuinely about THIS store:
//
//   - it is a derived cache of a downloadable feed, holding no authoritative
//     state, so the caller's correct response to a failure is to run Layer-1
//     only — never to refuse to boot.
//   - it is opened WITHOUT an encryption key, which is what makes badger's
//     "Encryption key mismatch" unambiguous here: for this store that message
//     can only mean KEYREGISTRY damage, so the shared corruption table applies
//     as-is and the policy needs no exemptions. A store opened WITH a key must
//     not reuse that rule — see storeguard.Policy.

import (
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// Recovery / RecoveryTrigger and the trigger values are re-exported so callers
// (urlcategories_startup.go, catfeeddb_health.go) keep their existing shape.
type (
	// Recovery reports what OpenResilient had to do.
	Recovery = storeguard.Recovery
	// RecoveryTrigger names what caused a recovery attempt.
	RecoveryTrigger = storeguard.RecoveryTrigger
)

const (
	// TriggerNone means the store opened normally.
	TriggerNone = storeguard.TriggerNone
	// TriggerPoisonMarker means a previous process died inside badger.Open.
	TriggerPoisonMarker = storeguard.TriggerPoisonMarker
	// TriggerOpenError means badger.Open returned an identified corruption error.
	TriggerOpenError = storeguard.TriggerOpenError
	// TriggerRuntimeFault means a previous run contained a memory fault on the
	// store's mapped tables after a healthy open (CHAOS-74).
	TriggerRuntimeFault = storeguard.TriggerRuntimeFault
)

// communityStorePolicy is deliberately EMPTY: this store is never opened with an
// encryption key, so every signal in the shared corruption table means for it
// exactly what the table says. An exemption added here would only ever make
// recovery less likely to fire — it can never widen what gets moved aside.
var communityStorePolicy = storeguard.Policy{}

// OpenResilient opens the community store, recovering from a store the previous
// run could not survive. It never panics on behalf of badger — the panic case
// is handled by refusing to hand badger a directory a previous process died
// inside of — and it never destroys data it has not first moved aside.
//
// Returns (db, recovery, nil) on success. On failure the caller MUST degrade
// (Layer-1-only categorisation) rather than treat it as fatal: this store is a
// cache, and refusing to boot an in-line gateway over a damaged cache is a
// self-inflicted outage.
//
// Direct `catdb.Open` remains the entry point for callers that already know the
// directory is sound.
//
// The configured path is resolved through symlinks ONCE, here, and every
// recovery step — markers, the quarantine rename, the rebuild — acts on the
// real target. If it used the configured path instead, an alias such as
// `/var/lib/catdb -> /mnt/data/catdb` would have the SYMLINK renamed aside.
// badger would then create a plain directory at the alias, so the rebuilt feed
// would silently leave the persistent volume while the damaged target stayed
// where it was. The alias itself is never renamed or replaced.
func OpenResilient(dir string) (*CommunityDB, Recovery, error) {
	return storeguard.Open(resolveStoreDir(dir), communityStorePolicy, Open)
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last.
// Exported so the caller can re-surface an unreconciled quarantine from a
// PRIOR boot: the in-memory record is process-local, so without this a
// self-healed store looks pristine on the next restart while the evidence — and
// the disk it occupies — is still sitting there. dir is resolved the same way
// OpenResilient resolves it, because that is where the copies are.
func QuarantinedCopies(dir string) []string {
	return storeguard.QuarantinedCopies(resolveStoreDir(dir))
}

// resolveStoreDir returns dir with symlinks resolved, or dir unchanged when it
// cannot be resolved (first start, before the directory exists, or a dangling
// alias whose volume is not mounted — badger's open then fails and the caller
// degrades, exactly as before).
func resolveStoreDir(dir string) string {
	if dir == "" {
		return dir
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return dir
	}
	return resolved
}
