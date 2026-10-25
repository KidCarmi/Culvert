// Package catdb is Layer 2 of the two-tier URL categorisation engine — the
// community category store. It is a self-contained leaf extracted from the flat
// package main per ADR-0002; it contains the BadgerDB dependency (the proxy's
// only category-DB use of Badger) behind a narrow API.
//
// Storage: BadgerDB (v4, pure-Go, no CGo).
//
// Key layout:   []byte(domain)            e.g. "facebook.com"
// Value layout: []byte(mapped category)   e.g. "Social"
//
// Subdomain matching: domain walking — query most-specific label first, then
// strip the leftmost label and retry, stopping before a bare TLD.
// e.g. "sub.facebook.com" → "facebook.com" → stop (next would be "com").
//
// Layer 1 (the admin-managed catStore in package main) is always consulted
// first; this community store is the fallback for entries not in the
// admin-managed lists.
package catdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	badger "github.com/dgraph-io/badger/v4"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// CommunityDB wraps a BadgerDB instance for URL category lookups.
// All exported methods are safe for concurrent use.
type CommunityDB struct {
	db *badger.DB

	// writeFault, when set, is consulted after each entry BulkWrite stages
	// (test seam: SetBulkWriteFaultForTest).
	writeFault func(written int) error

	// dir is the store's REAL directory: the opened path with symlinks
	// resolved once, at open time, while the volume is known to be healthy.
	// Both uses need the resolved form. ContainFault matches a faulting
	// address against the kernel's view of the mapped files, which uses
	// resolved paths, and by the time of a fault the volume may be too far
	// gone to resolve. RecordFault must put the marker beside the real target,
	// which is where OpenResilient (resolving the same way) looks for it and
	// what it quarantines. Beside an alias, the marker would make the next
	// start rename the symlink.
	dir string

	// CHAOS-74 runtime health. The boot outcome is recorded by the caller
	// (catfeeddb_health.go); these are the counters for everything that goes
	// wrong AFTER a healthy open, which that record cannot see because it is
	// written once during startup.
	//
	// faults counts lookups that failed for a reason other than "this host is
	// not in the list" — a returned badger error. memFaults counts contained
	// memory faults on the store's mapped tables, which is the signal that the
	// backing volume can no longer supply the mapping.
	faults    atomic.Uint64
	memFaults atomic.Uint64
	// degraded latches on the first contained memory fault. Once the mapping
	// has faulted, further lookups are refused WITHOUT touching badger: the
	// damage is not transient, and every retry is another chance to fault on a
	// goroutine that is not behind the guard.
	degraded atomic.Bool
}

// LookupFaults returns the number of lookups that failed with a badger error
// rather than a clean miss, the number of contained memory faults, and whether
// the store has latched degraded.
//
// A non-zero memFaults count means the data volume damaged the store's mapped
// tables while it was open and serving. Layer-2 categorisation is off from that
// point on; Layer 1 remains authoritative.
//
// Ordering contract (invariant: degraded ⇒ memFaults ≥ 1). noteMemFault ADDS to
// memFaults BEFORE it sets degraded, and this reader loads degraded BEFORE
// memFaults. Go's atomics are sequentially consistent, so a reader that sees
// degraded==true is guaranteed to see the Add that preceded it. Loading in the
// other order could catch memFaults before the Add and degraded after the CAS,
// so a scrape would report a degraded store with "0 memory fault(s)". The order
// is pinned by TestLookupFaults_DegradedImpliesACountedFault; no mutex needed.
func (c *CommunityDB) LookupFaults() (faults, memFaults uint64, degraded bool) {
	degraded = c.degraded.Load()
	memFaults = c.memFaults.Load()
	faults = c.faults.Load()
	return faults, memFaults, degraded
}

// noteMemFault accounts one contained memory fault and latches degraded,
// reporting whether this call was the one that latched it. The Add comes
// BEFORE the CAS: that is the writer half of LookupFaults' ordering contract.
func (c *CommunityDB) noteMemFault() (first bool) {
	c.memFaults.Add(1)
	return c.degraded.CompareAndSwap(false, true)
}

// syncRecordKey holds the import completion record. The leading NUL makes it
// unreachable from any hostname: getExact refuses NUL-prefixed keys, so no
// lookup can read or match it.
var syncRecordKey = []byte("\x00culvert/ut1-import-complete")

// syncRecordVersion is the completion record's schema.
const syncRecordVersion = 1

// SyncRecord certifies that one whole feed import is durably in THIS store
// (PR #1528 §3f F-FEED-1). It lives inside the store it certifies, so a store
// that is quarantined and re-created carries none, and it names the feed it
// was imported from, so a changed feed is not mistaken for a synced one.
type SyncRecord struct {
	Version     int       `json:"version"`
	FeedURL     string    `json:"feed_url"`
	Entries     int64     `json:"entries"`
	CompletedAt time.Time `json:"completed_at"`
}

// ErrNoSyncRecord reports a store with no valid completion record: never
// imported, a legacy store written before records existed, an import that
// did not finish, or a damaged record.
var ErrNoSyncRecord = errors.New("catdb: no valid import completion record")

// Open opens (or creates) a BadgerDB at the given directory.
//
// It is NOT crash-tolerant on its own, and the comment that used to claim
// otherwise ("Truncate is enabled so a crashed container can restart without
// manual intervention") was false in two ways: badger v4 removed the Truncate
// option entirely, and the worst crash damage does not surface as an error at
// all — a corrupt `.sst` makes this call PANIC from a goroutine badger spawns,
// which no caller can recover from. Boot paths must therefore call
// OpenResilient (resilient.go), which detects and quarantines a store a
// previous process could not survive. Direct Open is for callers that already
// know the directory is sound (tests, and OpenResilient itself).
func Open(dir string) (*CommunityDB, error) {
	opts := badger.DefaultOptions(dir).
		// Reduce per-file size: 128 MiB vs the 1 GiB default.
		// Limits peak mmap memory inside Docker containers.
		WithValueLogFileSize(128 << 20).
		// Suppress BadgerDB's internal INFO logs; proxy's own logger handles them.
		WithLogger(nil)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &CommunityDB{db: db, dir: resolveStoreDir(dir)}, nil
}

// ErrDegraded is returned by a data method of a store that has latched degraded
// after a contained memory fault. The store is refused WITHOUT touching badger:
// its mappings are damaged, and every further access is another chance to fault,
// possibly on a goroutine with no guard at all.
var ErrDegraded = errors.New("catdb: community category store is degraded after a memory fault on its mapped tables; Layer 2 is off until restart")

// ── the single choke point for badger data access ────────────────────────────
//
// CHAOS-74. Containment that guards one method leaks through the others. When
// only Lookup was guarded, a latched store still had Stats (db.Tables) and
// BulkWrite reaching the damaged database, and the feed syncer calls both from
// its own goroutine. The reproduction was SIGBUS in badger's getTableInfo after
// the latch. So every method that touches badger goes through access (or, for
// Close, contain), and TestCommunityDB_EveryBadgerAccessIsGuarded fails the
// build if a method reaches c.db any other way.

// access runs op against badger. It refuses with ErrDegraded once the store has
// latched, without touching badger. Otherwise op runs under memory-fault
// containment, and a first contained fault from ANY method latches the store
// instead of killing the process.
func (c *CommunityDB) access(op func() error) error {
	if c.degraded.Load() {
		return ErrDegraded
	}
	return c.contain(op)
}

// contain runs op under memory-fault containment and latches the store on a
// contained fault. It does not refuse a degraded store. That is for Close, which
// must still release badger's resources and directory lock on a store that has
// already faulted.
func (c *CommunityDB) contain(op func() error) error {
	err := storeguard.ContainFault(c.dir, op)
	if storeguard.IsStoreFault(err) {
		c.latchFault(err)
	}
	return err
}

// latchFault accounts a contained memory fault, and on the latch transition
// reports it ONCE and records it for the next start. A log line per fault would
// be a flood driven by request volume, which is the outage shape this package
// exists to prevent.
func (c *CommunityDB) latchFault(err error) {
	if !c.noteMemFault() {
		return
	}
	// The error text is object-derived and can embed a filesystem path, so it
	// goes through the recognized sanitizer and %q rather than %v (CWE-117).
	obs.Printf("CatFeedDB: memory fault reading the community category store — Layer-2 categorisation is now OFF for the life of this process, Layer 1 is unaffected; the data volume is damaged or has gone away: %q", obs.Sanitize(err.Error()))
	c.recordFault(err)
}

// Close flushes and closes the underlying BadgerDB.
// Must be called on graceful shutdown to prevent value-log corruption.
//
// Close is contained but NOT refused on a degraded store. It still has to
// release badger's resources and its directory lock, and a fault while flushing
// a damaged store is returned as an error instead of killing a process that is
// shutting down.
func (c *CommunityDB) Close() error {
	return c.contain(func() error { return c.db.Close() })
}

// Lookup returns the mapped category for host (or any of its parent domains).
// Uses domain walking: tries host, then strips the leftmost label and retries,
// stopping when no further parent exists above the TLD.
// Returns ("", false) when no entry is found.
//
// CHAOS-74: containment is armed ONCE for the whole walk rather than per point
// lookup. The walk issues up to four or five badger reads for a deep hostname,
// and this runs on the proxy data path, so a guard per read would pay the
// defer/recover cost several times per request to protect against a fault that
// makes all of them equally hopeless. A store that has already latched degraded
// is refused by access without arming anything at all.
func (c *CommunityDB) Lookup(host string) (string, bool) {
	if c.degraded.Load() {
		return "", false // fast path: skip host normalisation on a dead store
	}
	host = hostutil.NormalizeHost(host)
	var (
		cat   string
		found bool
	)
	err := c.access(func() error {
		var walkErr error
		cat, found, walkErr = c.walk(host)
		return walkErr
	})
	switch {
	case err == nil:
		return cat, found
	case storeguard.IsStoreFault(err), errors.Is(err, ErrDegraded):
		// Latched (by access): the host is uncategorised, Layer 1 stands.
		return "", false
	default:
		// A returned badger error: the store is answering, badly. Not latched —
		// some of these are transient — but counted and reported once.
		if c.faults.Add(1) == 1 {
			obs.Printf("CatFeedDB: community category lookup failed (host treated as uncategorised): %q", obs.Sanitize(err.Error()))
		}
		return "", false
	}
}

// recordFault persists the latch for the next start. The in-memory latch dies
// with the process, and the restart the diagnostics row prescribes would
// otherwise reopen the same damaged tables: for a truncated table badger's
// reopen error (`mmapping ... size: 0`) is not a recognised corruption signal,
// so without this record every later start stays Layer-1-only instead of
// quarantining and rebuilding the store. This store is a derived cache of a
// downloadable feed, which is what makes "move it aside on the next open" the
// right answer. Runs once per process (on the latch transition), so the file
// write never sits on the request path more than once.
func (c *CommunityDB) recordFault(cause error) {
	if c.dir == "" {
		return
	}
	if err := storeguard.RecordFault(c.dir, cause.Error()); err != nil {
		obs.Printf("CatFeedDB: could not record the memory fault for the next start; the store will not be quarantined automatically on restart: %q", obs.Sanitize(err.Error()))
	}
}

// walk performs the domain walk, stopping at the first real store error.
//
// A miss is not an error here: getExact reports badger.ErrKeyNotFound as a
// clean ("", false, nil), because a host that is not in the community feed is
// the overwhelmingly common outcome and must not be counted as store trouble.
// Anything else aborts the walk and is returned for classification by the
// caller — continuing to walk a store that just failed to answer would turn one
// fault into four.
func (c *CommunityDB) walk(host string) (category string, found bool, err error) {
	for {
		cat, hit, lookupErr := c.getExact(host)
		if lookupErr != nil {
			return "", false, lookupErr
		}
		if hit {
			return cat, true, nil
		}
		dot := strings.Index(host, ".")
		if dot < 0 {
			break
		}
		parent := host[dot+1:]
		// Stop before querying a bare TLD (e.g. "com", "uk").
		if !strings.Contains(parent, ".") {
			break
		}
		host = parent
	}
	return "", false, nil
}

// getExact performs a single BadgerDB point lookup for the given domain. It
// touches badger directly and is therefore reachable ONLY through walk, inside
// Lookup's access closure (enforced by TestCommunityDB_EveryBadgerAccessIsGuarded).
//
// CHAOS-74. This used to end in `if err != nil { return "", false }`, which
// collapsed three different things into one answer: a clean miss, a store that
// returned an error, and — because the error never arrived as an error at all —
// a store whose mapped table killed the process.
//
// Now badger.ErrKeyNotFound is the ONLY error treated as a miss; everything
// else is returned so the caller can count it. The fault case is handled one
// level up, where containment is armed for the whole walk.
//
// The policy outcome on a fault is deliberately unchanged — the caller still
// answers "uncategorised". Converting a store fault into a deny would change
// the gateway's decision on the data path, which is a different decision with a
// different blast radius and is not this fix's to make. What changed is that
// the degradation is bounded, survivable and visible.
func (c *CommunityDB) getExact(domain string) (category string, found bool, err error) {
	if strings.HasPrefix(domain, "\x00") { // reserved metadata, never a domain (F-FEED-1)
		return "", false, nil
	}
	var cat string
	viewErr := c.db.View(func(txn *badger.Txn) error {
		item, getErr := txn.Get([]byte(domain))
		if getErr != nil {
			return getErr
		}
		return item.Value(func(val []byte) error {
			cat = string(val)
			return nil
		})
	})
	switch {
	case viewErr == nil:
		return cat, true, nil
	case errors.Is(viewErr, badger.ErrKeyNotFound):
		return "", false, nil
	default:
		return "", false, viewErr
	}
}

// BulkWrite writes a batch of domain→category pairs into BadgerDB.
// Existing entries for the same domain are overwritten.
//
// It is NOT atomic. badger's WriteBatch commits a large batch as many
// separate transactions, so a process that dies mid-call leaves SOME of the
// entries written and the rest missing — and with SyncWrites=false (the
// default here) even committed transactions are not yet on disk. A partial
// store is indistinguishable from a complete one by its contents; whether an
// import finished is recorded only by BeginImport/CompleteImport.
// Uses WriteBatch for high-throughput ingestion without holding a long-lived
// transaction — safe to call while the DB serves concurrent reads.
//
// A degraded store refuses with ErrDegraded and is never written. The feed
// syncer charges that as a failed round and backs off. It also checks the latch
// before downloading, so a dead store does not cost a 50 MB fetch per round. A
// fault contained here latches the store like one in Lookup. badger's own flush
// goroutines are outside any guard; see the CHAOS-74 residual-risk notes.
func (c *CommunityDB) BulkWrite(entries map[string]string) error {
	return c.access(func() error {
		wb := c.db.NewWriteBatch()
		n := 0
		for domain, category := range entries {
			key := []byte(domain)
			val := []byte(category)
			if err := wb.Set(key, val); err != nil {
				wb.Cancel()
				return err
			}
			n++
			if c.writeFault != nil {
				if err := c.writeFault(n); err != nil {
					// What a process dying mid-import leaves: the staged part
					// committed, the rest never written.
					if ferr := wb.Flush(); ferr != nil {
						return errors.Join(err, ferr)
					}
					return err
				}
			}
		}
		return wb.Flush()
	})
}

// SetBulkWriteFaultForTest makes BulkWrite commit what it has staged and fail
// once fault returns an error (called after each staged entry). Test seam
// only; nil removes it.
func (c *CommunityDB) SetBulkWriteFaultForTest(fault func(written int) error) { c.writeFault = fault }

// ForceDegradedForTest latches the store degraded exactly as a contained memory
// fault would, without needing a real SIGBUS. It lets a test drive the
// feedsync/F-DISK-RECOVERY-1 watchdog path where BulkWrite blocks while the store
// latches degraded on a badger-internal goroutine. It touches only the latch
// atomics (via noteMemFault), never badger.
func (c *CommunityDB) ForceDegradedForTest() { c.noteMemFault() }

// BeginImport durably withdraws the completion record before an import
// writes any data, so a record can never describe an import that was
// interrupted: from here until CompleteImport the store is "not certified".
//
// F-DISK-RECOVERY-1: it ALSO lays down a durable import-pending intent marker
// (a sibling file, via storeguard) BEFORE the completion record is touched. The
// marker is written while the disk still has space — the risky bulk write that
// can fill it has not started — so recovery never depends on a write to a full
// filesystem after the failure. If the intent cannot be made durable the import
// is REFUSED (fail closed): a mid-write interruption would otherwise leave a
// torn store with no marker to recover it on the next boot. The marker is a
// storeguard filesystem call, not badger, so it is outside the access/contain
// guard (the same shape as recordFault) and the guard-wall is unaffected.
func (c *CommunityDB) BeginImport() error {
	if c.dir != "" {
		if err := storeguard.MarkImportPending(c.dir); err != nil {
			return fmt.Errorf("catdb: refusing to begin import, the import intent could not be made durable: %w", err)
		}
	}
	return c.access(func() error {
		if err := c.db.Update(func(txn *badger.Txn) error { return txn.Delete(syncRecordKey) }); err != nil {
			return err
		}
		return c.db.Sync()
	})
}

// CompleteImport certifies an import that BulkWrite finished. The order is
// the guarantee: the imported data is fsynced FIRST, then the record is
// written and fsynced. A crash before the first sync loses the record with
// (or before) the data; a crash after it can only lose the record. So a
// record that survives a crash always certifies data that survived it.
func (c *CommunityDB) CompleteImport(rec SyncRecord) error {
	if rec.FeedURL == "" || rec.Entries <= 0 || rec.CompletedAt.IsZero() {
		return errors.New("catdb: refusing to certify an empty or unnamed import")
	}
	rec.Version = syncRecordVersion
	val, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := c.access(func() error {
		if err := c.db.Sync(); err != nil { // the data first
			return err
		}
		if err := c.db.Update(func(txn *badger.Txn) error { return txn.Set(syncRecordKey, val) }); err != nil {
			return err
		}
		return c.db.Sync()
	}); err != nil {
		return err
	}
	// F-DISK-RECOVERY-1: the import is now certified durable, so clear the
	// import-pending intent — otherwise the next Open would quarantine a
	// complete, healthy store. Clearing is fsynced; a clear failure is returned
	// so the caller retries (and re-runs the import), because a stale marker
	// would cost an unnecessary rebuild on the next boot. The data is safe
	// either way — this only governs whether the store is kept or rebuilt.
	if c.dir != "" {
		if err := storeguard.ClearImportPending(c.dir); err != nil {
			return fmt.Errorf("catdb: import certified durable but the import-pending marker could not be cleared: %w", err)
		}
	}
	return nil
}

// ImportRecord returns the completion record when it is present and valid,
// else ErrNoSyncRecord. It does not check which feed it names; callers
// compare FeedURL with the feed they serve.
func (c *CommunityDB) ImportRecord() (SyncRecord, error) {
	var raw []byte
	err := c.access(func() error {
		return c.db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(syncRecordKey)
			if err != nil {
				return err
			}
			raw, err = item.ValueCopy(nil)
			return err
		})
	})
	if err != nil {
		return SyncRecord{}, ErrNoSyncRecord
	}
	var rec SyncRecord
	if json.Unmarshal(raw, &rec) != nil || rec.Version != syncRecordVersion ||
		rec.FeedURL == "" || rec.Entries <= 0 || rec.CompletedAt.IsZero() {
		return SyncRecord{}, ErrNoSyncRecord
	}
	return rec, nil
}

// setRawImportRecordForTest writes arbitrary bytes under the record key.
func (c *CommunityDB) setRawImportRecordForTest(val []byte) error {
	return c.access(func() error {
		return c.db.Update(func(txn *badger.Txn) error { return txn.Set(syncRecordKey, val) })
	})
}

// HasEntries reports whether the store holds at least one key. Unlike Stats
// (an LSM-table estimate that reads 0 until the memtable is flushed) it is
// exact: one key-only iterator step under a read transaction.
func (c *CommunityDB) HasEntries() bool {
	found := false
	_ = c.access(func() error {
		return c.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()
			it.Rewind()
			found = it.Valid()
			return nil
		})
	})
	return found
}

// Stats returns the estimated number of keys stored in the DB.
//
// A degraded store, or a fault contained while reading the table metadata,
// reports 0 rather than an error. The only production caller is the feed
// syncer's "is the store empty, sync at once?" check, and a dead store answering
// 0 there is harmless: the round it triggers refuses on the latch before
// downloading anything.
func (c *CommunityDB) Stats() (keys int64) {
	if err := c.access(func() error {
		// BadgerDB provides only estimated counts via LSM metadata.
		for _, t := range c.db.Tables() {
			keys += int64(t.KeyCount)
		}
		return nil
	}); err != nil {
		return 0
	}
	return keys
}
