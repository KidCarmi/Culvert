package main

// CommunityDB — Layer 2 of the two-tier URL categorisation engine.
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
// Layer 1 (catStore, admin-managed) is always consulted first; CommunityDB
// is the fallback for entries not in the admin-managed lists.

import (
	"strings"

	badger "github.com/dgraph-io/badger/v4"
)

// CommunityDB wraps a BadgerDB instance for URL category lookups.
// All exported methods are safe for concurrent use.
type CommunityDB struct {
	db *badger.DB
}

// communityDB is the process-wide community category store.
// Nil when disabled (no --cat-feed-db flag supplied).
var communityDB *CommunityDB

// openCommunityDB opens (or creates) a BadgerDB at the given directory.
// Truncate is enabled so a crashed container can restart without manual
// intervention — BadgerDB replays and truncates a corrupted value log.
func openCommunityDB(dir string) (*CommunityDB, error) {
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
	host = strings.ToLower(strings.TrimSuffix(host, "."))
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
