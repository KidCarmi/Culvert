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
	"errors"
	"strings"
	"sync/atomic"

	badger "github.com/dgraph-io/badger/v4"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// CommunityDB wraps a BadgerDB instance for URL category lookups.
// All exported methods are safe for concurrent use.
type CommunityDB struct {
	db *badger.DB
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

// BulkWrite atomically writes a batch of domain→category pairs into BadgerDB.
// Existing entries for the same domain are overwritten.
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
		for domain, category := range entries {
			if err := wb.Set([]byte(domain), []byte(category)); err != nil {
				wb.Cancel()
				return err
			}
		}
		return wb.Flush()
	})
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
