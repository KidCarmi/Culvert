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
	"errors"
	"io/fs"
	"os"
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
	// TriggerInterruptedImport means a previous run began a bulk import and never
	// certified it complete; the partial store is rebuilt (F-DISK-RECOVERY-1).
	TriggerInterruptedImport = storeguard.TriggerInterruptedImport
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
	return openResilientWith(dir, Open)
}

// openResilientWith is OpenResilient with the opener injected, so a recovery
// whose replacement cannot be created (ENOSPC after the quarantine) can be
// exercised.
func openResilientWith(dir string, open func(string) (*CommunityDB, error)) (*CommunityDB, Recovery, error) {
	return storeguard.Open(resolveStoreDir(dir), communityStorePolicy, open)
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

// resolveStoreDir returns the store's real directory: dir with symlinks
// resolved, or, when dir is an alias whose target does not exist, that target.
// Otherwise (a first start before a plain directory exists, or a path that
// cannot be read) dir is returned unchanged.
//
// The dangling-alias case is not hypothetical. A recovery that quarantines the
// target and then cannot create its replacement (ENOSPC) leaves the alias
// pointing at nothing. Handing badger the alias would fail on every later start
// (MkdirAll refuses a path that exists as a symlink), so Layer 2 would never come
// back even after space was freed. Following the link instead lets badger
// recreate the target directory where the alias says it belongs. The alias
// itself is never replaced.
func resolveStoreDir(dir string) string {
	if dir == "" {
		return dir
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	if target, ok := danglingAliasTarget(dir); ok {
		return target
	}
	return dir
}

// maxAliasHops bounds how far danglingAliasTarget follows a chain of links, so
// a symlink loop terminates.
const maxAliasHops = 8

// danglingAliasTarget follows dir through symlinks to a final path that does
// not exist and whose parent does. ok is false for anything else: not a
// symlink, a loop, an unreadable link, or a target whose parent is also missing
// (an unmounted volume, where creating the store would put it on the wrong
// filesystem).
func danglingAliasTarget(dir string) (target string, ok bool) {
	p := filepath.Clean(dir)
	for i := 0; i < maxAliasHops; i++ {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if i == 0 {
				return "", false // not an alias at all
			}
			parent, perr := filepath.EvalSymlinks(filepath.Dir(p))
			if perr != nil {
				return "", false
			}
			return filepath.Join(parent, filepath.Base(p)), true
		case err != nil || fi.Mode()&os.ModeSymlink == 0:
			return "", false
		}
		link, err := os.Readlink(p)
		if err != nil {
			return "", false
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(p), link)
		}
		p = filepath.Clean(link)
	}
	return "", false
}
