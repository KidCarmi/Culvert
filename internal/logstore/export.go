package logstore

// Portable export/import of the stored request history (#1528, request-history
// recovery). The store is encrypted under a node-local key (passphrase +
// <dir>.salt) and is not part of the application backup, so without this the
// history is lost on a full restore, a volume loss, or any passphrase change
// (the store cannot be re-keyed in place). Export reads the decrypted records
// in key order; Import writes them into ANY store under THAT store's key, so a
// record outlives the key it was written under.
//
// Each record keeps its original store key (timestamp + sequence) and its
// absolute expiry, which is what makes re-importing the same archive
// idempotent: an existing key with identical content is a duplicate, never a
// second copy. Encryption of the exported stream is the caller's job (package
// main seals it in the backupcrypt streaming envelope).

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

// ExportRecord is one stored entry in portable form.
type ExportRecord struct {
	// Key is the 12-byte store key (8-byte ms timestamp + 4-byte sequence), hex.
	Key string `json:"k"`
	// ExpiresAt is the absolute expiry in unix seconds; 0 means no TTL.
	ExpiresAt uint64 `json:"x,omitempty"`
	// Entry is the stored value, byte for byte.
	Entry json.RawMessage `json:"e"`
}

// exportPage and exportPageBytes bound one read transaction (by count and by
// value bytes), so a large export never holds closeMu (which Close waits on)
// or one badger snapshot for its whole run, nor a page of huge entries in RAM.
const (
	exportPage      = 4096
	exportPageBytes = 16 << 20
)

// Export calls fn for every stored record in ascending key order (oldest
// first) and returns how many it emitted. It reads in pages of separate
// transactions: records written during the export are included if their key
// sorts after the current position, records retention removes before they are
// reached are not. An error from fn stops the export and is returned.
func (s *Store) Export(fn func(ExportRecord) error) (int64, error) {
	if s == nil {
		return 0, errors.New("logstore: export: store not open")
	}
	var after []byte
	var n int64
	for {
		page, last, err := s.exportPage(after)
		if err != nil {
			return n, err
		}
		for i := range page {
			if err := fn(page[i]); err != nil {
				return n, err
			}
			n++
		}
		if last == nil {
			return n, nil
		}
		after = last
	}
}

func (s *Store) exportPage(after []byte) ([]ExportRecord, []byte, error) {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return nil, nil, errors.New("logstore: export: store closed")
	}
	out := make([]ExportRecord, 0, 256)
	var last []byte
	var bytesInPage int
	more := false
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		if after == nil {
			it.Rewind()
		} else {
			it.Seek(after)
			if it.Valid() && bytes.Equal(it.Item().Key(), after) {
				it.Next()
			}
		}
		for ; it.Valid(); it.Next() {
			if len(out) >= exportPage || bytesInPage >= exportPageBytes {
				more = true
				break
			}
			item := it.Item()
			if len(item.Key()) != keyLen {
				continue
			}
			v, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			last = item.KeyCopy(last[:0])
			bytesInPage += len(v)
			out = append(out, ExportRecord{Key: hex.EncodeToString(item.Key()), ExpiresAt: item.ExpiresAt(), Entry: v})
		}
		return nil
	})
	if !more {
		last = nil // no further page
	}
	return out, last, err
}

// ImportStats counts what Import did with each record.
type ImportStats struct {
	Imported  int64 `json:"imported"`
	Duplicate int64 `json:"duplicate"` // same key, identical content: already present
	Rekeyed   int64 `json:"rekeyed"`   // same key, different content: written under a fresh key
	Expired   int64 `json:"expired"`   // past its expiry, or older than this store's age limit
	Invalid   int64 `json:"invalid"`   // malformed key or entry, or key/entry timestamps disagree
}

// ErrImportSizeCap is returned when importing the next batch would take the
// store past its configured size cap. Nothing of that batch is written; the
// records imported before it stay.
var ErrImportSizeCap = errors.New("logstore: import would exceed the configured history size cap")

const importBatch = 1024

// Import writes records produced by next (which returns ok=false at the end)
// into the store, under this store's encryption key. A record's expiry is its
// original absolute expiry, further limited by THIS store's age limit measured
// from the record's own timestamp; a record already past that is skipped. A
// key that exists with identical content is a duplicate; with different
// content (a same-millisecond collision with a live record) the record is
// written under a fresh sequence number, never over the existing one.
func (s *Store) Import(next func() (ExportRecord, bool, error), now time.Time) (ImportStats, error) {
	var st ImportStats
	if s == nil {
		return st, errors.New("logstore: import: store not open")
	}
	batch := make([]ExportRecord, 0, importBatch)
	for {
		rec, ok, err := next()
		if err != nil {
			return st, err
		}
		if ok {
			batch = append(batch, rec)
		}
		if len(batch) == importBatch || (!ok && len(batch) > 0) {
			if err := s.importBatch(batch, now, &st); err != nil {
				return st, err
			}
			batch = batch[:0]
		}
		if !ok {
			return st, nil
		}
	}
}

type importItem struct {
	key []byte
	val []byte
	exp uint64
}

// validateRecord decodes and checks one record; ok=false means invalid.
func validateRecord(rec *ExportRecord) (key []byte, ok bool) {
	key, err := hex.DecodeString(rec.Key)
	if err != nil || len(key) != keyLen {
		return nil, false
	}
	var e Entry
	if err := json.Unmarshal(rec.Entry, &e); err != nil || e.TS != storeKeyTS(key) {
		return nil, false
	}
	return key, true
}

// effectiveExpiry applies this store's age limit (from the record's own
// timestamp) on top of the record's original expiry.
func (s *Store) effectiveExpiry(key []byte, orig uint64) uint64 {
	ttl := time.Duration(atomic.LoadInt64(&s.ttlNanos))
	if ttl <= 0 {
		return orig
	}
	lim := time.UnixMilli(storeKeyTS(key)).Add(ttl).Unix()
	if lim <= 0 {
		return 1 // already long past: expired
	}
	if ulim := uint64(lim); orig == 0 || ulim < orig {
		return ulim
	}
	return orig
}

func (s *Store) importBatch(batch []ExportRecord, now time.Time, st *ImportStats) error {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return errors.New("logstore: import: store closed")
	}
	items, dup, rekeyed, err := s.planImport(batch, now, st)
	if err != nil {
		return err
	}
	if err := s.writeImport(items); err != nil {
		return err
	}
	st.Imported += int64(len(items)) - rekeyed
	st.Rekeyed += rekeyed
	st.Duplicate += dup
	return nil
}

// planImport classifies one batch against the current store contents: invalid
// and expired records are counted, an identical existing key is a duplicate, a
// differing one gets a fresh sequence number. A key repeated WITHIN one batch
// is invalid: an export never repeats a key, and a crafted archive must not be
// able to double-count the size cap or have its second copy silently win.
func (s *Store) planImport(batch []ExportRecord, now time.Time, st *ImportStats) (items []importItem, dup, rekeyed int64, err error) {
	nowSec := uint64(0)
	if u := now.Unix(); u > 0 {
		nowSec = uint64(u)
	}
	items = make([]importItem, 0, len(batch))
	planned := make(map[string]struct{}, len(batch))
	err = s.db.View(func(txn *badger.Txn) error {
		for i := range batch {
			key, ok := validateRecord(&batch[i])
			if !ok {
				st.Invalid++
				continue
			}
			if exp := s.effectiveExpiry(key, batch[i].ExpiresAt); exp != 0 && exp <= nowSec {
				st.Expired++
				continue
			}
			if _, seen := planned[string(key)]; seen {
				st.Invalid++
				continue
			}
			planned[string(key)] = struct{}{}
			res, err := resolveKey(txn, key, batch[i].Entry, planned)
			if err != nil {
				return err
			}
			switch {
			case res.duplicate:
				dup++
			default:
				if res.rekeyed {
					rekeyed++
					planned[string(res.key)] = struct{}{}
				}
				items = append(items, importItem{key: res.key, val: batch[i].Entry, exp: s.effectiveExpiry(res.key, batch[i].ExpiresAt)})
			}
		}
		return nil
	})
	return items, dup, rekeyed, err
}

// keyResolution is where one imported record goes.
type keyResolution struct {
	key       []byte
	duplicate bool // an identical record already holds the key: write nothing
	rekeyed   bool // the key holds DIFFERENT content: key is a fresh, free one
}

// rekeyAttempts bounds the search for a free sequence number at one
// millisecond; 2^32 sequence values make exhausting it impossible in practice.
const rekeyAttempts = 64

// resolveKey decides where one record goes. A collision is moved to a random
// sequence number at the same millisecond that is free BOTH in the store and
// in this batch's plan — never to the process counter, which restarts at 0 in
// every process and so would land on exactly the keys an earlier process wrote.
func resolveKey(txn *badger.Txn, key, val []byte, planned map[string]struct{}) (keyResolution, error) {
	item, err := txn.Get(key)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return keyResolution{key: key}, nil
	}
	if err != nil {
		return keyResolution{}, err
	}
	cur, err := item.ValueCopy(nil)
	if err != nil {
		return keyResolution{}, err
	}
	if bytes.Equal(cur, val) {
		return keyResolution{duplicate: true}, nil
	}
	ts := storeKeyTS(key)
	var rnd [4]byte
	for range rekeyAttempts {
		if _, err := rand.Read(rnd[:]); err != nil {
			return keyResolution{}, err
		}
		cand := storeKey(ts, binary.BigEndian.Uint32(rnd[:]))
		if _, taken := planned[string(cand)]; taken {
			continue
		}
		if _, err := txn.Get(cand); errors.Is(err, badger.ErrKeyNotFound) {
			return keyResolution{key: cand, rekeyed: true}, nil
		} else if err != nil {
			return keyResolution{}, err
		}
	}
	return keyResolution{}, fmt.Errorf("logstore: import: no free key at ts %d after %d attempts", ts, rekeyAttempts)
}

// writeImport writes the planned records in one batch, refusing the whole
// batch when it would take the store past its size cap.
func (s *Store) writeImport(items []importItem) error {
	var size int64
	for i := range items {
		size += int64(len(items[i].key) + len(items[i].val))
	}
	if limit := atomic.LoadInt64(&s.maxBytes); limit > 0 && atomic.LoadInt64(&s.bytesUsed)+size > limit {
		return ErrImportSizeCap
	}
	wb := s.db.NewWriteBatch()
	defer wb.Cancel()
	for i := range items {
		ent := badger.NewEntry(items[i].key, items[i].val)
		ent.ExpiresAt = items[i].exp
		if err := wb.SetEntry(ent); err != nil {
			return fmt.Errorf("logstore: import: %w", err)
		}
	}
	if err := wb.Flush(); err != nil {
		return fmt.Errorf("logstore: import: %w", err)
	}
	atomic.AddInt64(&s.bytesUsed, size)
	return nil
}
