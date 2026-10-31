package storeguard

// badger.go — proving that badger.Open returned the WHOLE store.
//
// # WHY
//
// The poison marker rests on one assumption: when badger dies on a corrupt
// table, badger.Open does not return. Measured against badger v4.9.6 that is
// not guaranteed. newLevelsController opens each table in a goroutine whose
// deferred `throttle.Done(rerr); numOpened.Add(1)` runs DURING the panic's
// unwind (table.OpenTable panics on a garbled `.sst`), with rerr still nil.
// That releases throttle.Finish, so badger.Open can return (db, nil) — a store
// without the panicking table — moments before the runtime ends the process.
// If the caller then cleared its marker, the next start would find no evidence
// and hand badger the same corrupt directory: the crash loop the marker exists
// to break, broken only by luck. Reproduced at roughly 1 in 600 boots under CPU
// load by TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot.
//
// badger also drops a table ON PURPOSE in one case: newLevelsController skips
// any table whose open error starts with "CHECKSUM_MISMATCH:" and opens the
// store without it. Nothing in v4.9.6 produces that prefix, but the branch
// exists, and a store missing a table is incomplete however it got that way.
//
// # HOW
//
// OpenBadger compares the tables badger actually loaded with the tables the
// MANIFEST lists, which is deterministic — no waiting for a panic to land. Three
// reads, in an order the argument depends on:
//
//  1. BEFORE the open, the manifest's table set. That is the set badger is
//     about to load (it replays the same file with the same function), and it
//     contains no table this open could create: every table created after the
//     levels are built takes an ID above all of these. It is read before badger
//     takes its directory lock, so only a process that held this store and
//     closed it inside that gap could change the file under it — a second
//     process that badger's lock would refuse on any other timing.
//  2. AFTER the open, db.Tables() — what is really in the levels.
//  3. Only if (2) lacks a table from (1): the manifest again. A compaction that
//     started inside the open may have retired that table legitimately, and
//     badger writes a retirement to the manifest BEFORE it takes the table out
//     of its levels (runCompactDef, dropTree; tables are never moved between
//     levels, always rewritten under a new ID, and Tables() walks the levels
//     top-down to match). So a table still in the manifest at (3) was still in
//     the levels at (2) — unless badger never loaded it.
//
// A table in (1) and (3) but not in (2) is therefore one badger dropped.
// OpenBadger closes the store and returns ErrIncompleteOpen, and Open keeps the
// attempt's marker for the next start instead of clearing it.
//
// It lives here, beside the shared corruption table, for the same reason that
// table does: both stores that use this package open badger, and a second copy
// of the knowledge is the copy that drifts.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	badger "github.com/dgraph-io/badger/v4"
)

// OpenBadger is badger.Open plus proof that the store it returns holds every
// table its manifest lists. A store missing one is closed and reported as an
// error wrapping ErrIncompleteOpen; pass that through to Open unchanged so the
// attempt's marker survives.
//
// Any error badger.Open returns is returned exactly as badger produced it, so
// the classifier's empirical message table keeps meaning what it says. A
// manifest OpenBadger cannot read for itself, on a store badger opened anyway,
// closes the store and is reported as a plain error, classified like any other
// returned error. In practice that is an environmental one (descriptor
// exhaustion, a failing device): badger has just replayed the same file.
func OpenBadger(opts badger.Options) (*badger.DB, error) {
	return openBadgerWith(opts, badger.Open, (*badger.DB).Tables)
}

// openBadgerWith is OpenBadger with badger's open and table listing injected,
// so a dropped table — which real badger produces only while dying — can be
// exercised deterministically.
func openBadgerWith(opts badger.Options, open func(badger.Options) (*badger.DB, error), loaded func(*badger.DB) []badger.TableInfo) (*badger.DB, error) {
	if opts.InMemory {
		return open(opts) // no manifest, no tables on disk to lose
	}
	expected, baseErr := manifestTables(opts)
	db, err := open(opts)
	if err != nil {
		return nil, err
	}
	if baseErr != nil {
		_ = db.Close() // best-effort: the open is being refused regardless of how the close goes
		return nil, fmt.Errorf("opened the store but could not read its manifest to verify that every table loaded: %w", baseErr)
	}
	// (2) before (3): see the file comment for why this order is load-bearing.
	tables := loaded(db)
	if verr := verifyLoaded(opts, expected, tables); verr != nil {
		if cerr := db.Close(); cerr != nil {
			verr = errors.Join(verr, fmt.Errorf("closing the incompletely opened store: %w", cerr))
		}
		return nil, verr
	}
	return db, nil
}

// verifyLoaded reports the tables in expected that badger did not load and
// that the manifest still lists. A nil return means the open was complete.
func verifyLoaded(opts badger.Options, expected map[uint64]struct{}, tables []badger.TableInfo) error {
	have := make(map[uint64]struct{}, len(tables))
	for i := range tables {
		have[tables[i].ID] = struct{}{}
	}
	var absent []uint64
	for id := range expected {
		if _, ok := have[id]; !ok {
			absent = append(absent, id)
		}
	}
	if len(absent) == 0 {
		return nil
	}
	current, err := manifestTables(opts)
	if err != nil {
		return fmt.Errorf("opened the store but could not re-read its manifest to verify that every table loaded: %w", err)
	}
	missing := absent[:0]
	for _, id := range absent {
		if _, listed := current[id]; listed {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return nil // every absent table was retired by a compaction after the open
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
	return fmt.Errorf("%w: %d of the %d tables its manifest lists were not loaded (table ids %v)",
		ErrIncompleteOpen, len(missing), len(expected), missing)
}

// manifestTables replays the store's MANIFEST with badger's own replay and
// returns its table IDs. A store with no MANIFEST yet (a first start) has no
// tables to lose and yields an empty set.
func manifestTables(opts badger.Options) (map[uint64]struct{}, error) {
	f, err := os.Open(filepath.Join(opts.Dir, badger.ManifestFilename))
	if errors.Is(err, fs.ErrNotExist) {
		return map[uint64]struct{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	m, _, err := badger.ReplayManifestFile(f, opts.ExternalMagicVersion, opts)
	_ = f.Close() // read-only handle: a close error cannot change what was read
	if err != nil {
		return nil, err
	}
	ids := make(map[uint64]struct{}, len(m.Tables))
	for id := range m.Tables {
		ids[id] = struct{}{}
	}
	return ids, nil
}
