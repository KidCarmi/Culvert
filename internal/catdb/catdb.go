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
	// dir is where the store was opened, kept so a contained memory fault can
	// be recorded beside it for the next OpenResilient (storeguard.RecordFault).
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
func (c *CommunityDB) LookupFaults() (faults, memFaults uint64, degraded bool) {
	return c.faults.Load(), c.memFaults.Load(), c.degraded.Load()
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
	return &CommunityDB{db: db, dir: dir}, nil
}

// Close flushes and closes the underlying BadgerDB.
// Must be called on graceful shutdown to prevent value-log corruption.
func (c *CommunityDB) Close() error {
	return c.db.Close()
}

// Lookup returns the mapped category for host (or any of its parent domains).
// Uses domain walking: tries host, then strips the leftmost label and retries,
// stopping when no further parent exists above the TLD.
// Returns ("", false) when no entry is found.
//
// CHAOS-74: this is where memory-fault containment is armed, and it is armed
// ONCE for the whole walk rather than per point lookup. The walk issues up to
// four or five badger reads for a deep hostname, and this runs on the proxy
// data path, so a guard per read would pay the defer/recover cost several times
// per request to protect against a fault that makes all of them equally
// hopeless. One guard per walk is the same protection at a fraction of the
// cost. A store that has already latched degraded returns here without arming
// anything at all.
func (c *CommunityDB) Lookup(host string) (string, bool) {
	if c.degraded.Load() {
		return "", false
	}
	host = hostutil.NormalizeHost(host)
	var (
		cat   string
		found bool
	)
	err := storeguard.ContainFault(func() error {
		var walkErr error
		cat, found, walkErr = c.walk(host)
		return walkErr
	})
	switch {
	case err == nil:
		return cat, found
	case storeguard.IsStoreFault(err):
		// The mapping is gone. Latch degraded and report ONCE: a per-request
		// log line here would be a log flood driven by request volume, which is
		// the shape of outage this package exists to prevent.
		c.memFaults.Add(1)
		if c.degraded.CompareAndSwap(false, true) {
			// The error text is object-derived and can embed a filesystem
			// path, so it goes through the recognized sanitizer and %q
			// rather than %v (CWE-117).
			obs.Printf("CatFeedDB: memory fault reading the community category store — Layer-2 categorisation is now OFF for the life of this process, Layer 1 is unaffected; the data volume is damaged or has gone away: %q", obs.Sanitize(err.Error()))
			c.recordFault(err)
		}
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

// getExact performs a single BadgerDB point lookup for the given domain.
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
func (c *CommunityDB) BulkWrite(entries map[string]string) error {
	wb := c.db.NewWriteBatch()
	for domain, category := range entries {
		key := []byte(domain)
		val := []byte(category)
		if err := wb.Set(key, val); err != nil {
			wb.Cancel()
			return err
		}
	}
	return wb.Flush()
}

// Stats returns the estimated number of keys stored in the DB.
func (c *CommunityDB) Stats() (keys int64) {
	// BadgerDB provides only estimated counts via LSM metadata.
	tables := c.db.Tables()
	for _, t := range tables {
		keys += int64(t.KeyCount)
	}
	return keys
}
