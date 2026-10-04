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
	"strings"
	"time"

	badger "github.com/dgraph-io/badger/v4"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// CommunityDB wraps a BadgerDB instance for URL category lookups.
// All exported methods are safe for concurrent use.
type CommunityDB struct {
	db *badger.DB

	// writeFault, when set, is consulted after each entry BulkWrite stages
	// (test seam: SetBulkWriteFaultForTest).
	writeFault func(written int) error
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
	return &CommunityDB{db: db}, nil
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
func (c *CommunityDB) Lookup(host string) (string, bool) {
	host = hostutil.NormalizeHost(host)
	for {
		cat, found := c.getExact(host)
		if found {
			return cat, true
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
	return "", false
}

// getExact performs a single BadgerDB point lookup for the given domain.
func (c *CommunityDB) getExact(domain string) (string, bool) {
	if strings.HasPrefix(domain, "\x00") { // reserved metadata, never a domain
		return "", false
	}
	var cat string
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(domain))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			cat = string(val)
			return nil
		})
	})
	if err != nil {
		return "", false
	}
	return cat, true
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
func (c *CommunityDB) BulkWrite(entries map[string]string) error {
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
}

// SetBulkWriteFaultForTest makes BulkWrite commit what it has staged and fail
// once fault returns an error (called after each staged entry). Test seam
// only; nil removes it.
func (c *CommunityDB) SetBulkWriteFaultForTest(fault func(written int) error) { c.writeFault = fault }

// BeginImport durably withdraws the completion record before an import
// writes any data, so a record can never describe an import that was
// interrupted: from here until CompleteImport the store is "not certified".
func (c *CommunityDB) BeginImport() error {
	if err := c.db.Update(func(txn *badger.Txn) error { return txn.Delete(syncRecordKey) }); err != nil {
		return err
	}
	return c.db.Sync()
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
	if err := c.db.Sync(); err != nil { // the data first
		return err
	}
	if err := c.db.Update(func(txn *badger.Txn) error { return txn.Set(syncRecordKey, val) }); err != nil {
		return err
	}
	return c.db.Sync()
}

// ImportRecord returns the completion record when it is present and valid,
// else ErrNoSyncRecord. It does not check which feed it names; callers
// compare FeedURL with the feed they serve.
func (c *CommunityDB) ImportRecord() (SyncRecord, error) {
	var raw []byte
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(syncRecordKey)
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		return err
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
	return c.db.Update(func(txn *badger.Txn) error { return txn.Set(syncRecordKey, val) })
}

// HasEntries reports whether the store holds at least one key. Unlike Stats
// (an LSM-table estimate that reads 0 until the memtable is flushed) it is
// exact: one key-only iterator step under a read transaction.
func (c *CommunityDB) HasEntries() bool {
	found := false
	_ = c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Rewind()
		found = it.Valid()
		return nil
	})
	return found
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
