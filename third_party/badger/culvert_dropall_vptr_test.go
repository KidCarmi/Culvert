// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md) — not part of upstream badger.

package badger

// DropAll must never leave a readable memtable whose out-of-line values point
// into a value log it has deleted and recreated (ASTRA review of bd6176ae: a
// failed replacement-memtable allocation kept the old memtable, and a read of
// its key returned ANOTHER key's bytes from the new log). DropAll now empties
// the memtables in place before it deletes anything and allocates no
// memtable, so the reproduction's blocker no longer makes it fail.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func memFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*"+memFileExt))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(m)
	return m
}

func vptrOpts(dir string) Options {
	return DefaultOptions(dir).WithLogger(nil).
		WithEncryptionKey(bytes.Repeat([]byte{7}, 32)).WithIndexCacheSize(1 << 20).
		WithMemTableSize(8 << 20).WithValueLogFileSize(16 << 20).
		WithNumCompactors(0).WithCompactL0OnClose(false)
}

func mustGet(t *testing.T, db *DB, key string) ([]byte, error) {
	t.Helper()
	var out []byte
	err := db.View(func(txn *Txn) error {
		it, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		out, err = it.ValueCopy(nil)
		return err
	})
	return out, err
}

func set(t *testing.T, db *DB, key string, v []byte) {
	t.Helper()
	if err := db.Update(func(txn *Txn) error { return txn.Set([]byte(key), v) }); err != nil {
		t.Fatal(err)
	}
}

func assertDropped(t *testing.T, db *DB, oldKey, newKey string, newVal []byte) {
	t.Helper()
	got, err := mustGet(t, db, oldKey)
	if !errors.Is(err, ErrKeyNotFound) {
		if bytes.Equal(got, newVal) {
			t.Fatalf("%s returned %s's bytes after DropAll (stale value pointer into the recreated value log)", oldKey, newKey)
		}
		t.Fatalf("%s after DropAll: err=%v len=%d, want ErrKeyNotFound", oldKey, err, len(got))
	}
	got, err = mustGet(t, db, newKey)
	if err != nil || !bytes.Equal(got, newVal) {
		t.Fatalf("%s: err=%v equal=%v", newKey, err, bytes.Equal(got, newVal))
	}
}

// ASTRA's reproduction: encrypted store, default 1 MiB value threshold, a
// 2 MiB value in the current memtable, a directory at the next WAL file name.
func TestCulvertDropAll_NoStaleValuePointerWhenAWALCannotBeCreated(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(vptrOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	oldVal, newVal := bytes.Repeat([]byte{0x6f}, 2<<20), bytes.Repeat([]byte{0x6e}, 2<<20)
	set(t, db, "old", oldVal)

	before := memFiles(t, dir)
	blocker := db.mtFilePath(db.nextMemFid)
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := db.DropAll(); err != nil {
		t.Fatalf("DropAll needs no new WAL, but failed: %v", err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if after := memFiles(t, dir); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("DropAll created or removed WAL files: before %v after %v", before, after)
	}

	set(t, db, "new", newVal)
	assertDropped(t, db, "old", "new", newVal)

	// The emptied WAL must not replay the dropped entry after a restart.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(vptrOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	assertDropped(t, db, "old", "new", newVal)
}

// Immutable memtables survive into DropAll when flushes fail (full disk), and
// they hold value pointers too.
func TestCulvertDropAll_RetainedImmutableMemtablesDoNotResolveIntoTheNewLog(t *testing.T) {
	dir := t.TempDir()
	l := &flushFailLogger{failed: make(chan struct{}, 1)}
	opts := DefaultOptions(dir).WithLogger(l).WithMemTableSize(1 << 20).WithValueLogFileSize(4 << 20).
		WithValueThreshold(64).WithNumCompactors(0).WithCompactL0OnClose(false)
	db, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	var blockers []string
	for i := 1; i <= 50; i++ {
		p := filepath.Join(dir, fmt.Sprintf("%06d.sst", i))
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		blockers = append(blockers, p)
	}
	const n = 60000
	val := func(tag byte, i int) []byte { return append(bytes.Repeat([]byte{tag}, 120), []byte(fmt.Sprint(i))...) }
	put := func(prefix string, tag byte) {
		wb := db.NewWriteBatch()
		for i := 0; i < n; i++ {
			if err := wb.Set([]byte(fmt.Sprintf("%s%06d", prefix, i)), val(tag, i)); err != nil {
				t.Fatal(err)
			}
		}
		if err := wb.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	put("o", 'o')
	waitFlushFailure(t, l)
	db.lock.RLock()
	imm := len(db.imm)
	db.lock.RUnlock()
	if imm == 0 {
		t.Fatal("setup: no immutable memtable was retained")
	}

	if err := db.DropAll(); err != nil {
		t.Fatalf("DropAll: %v", err)
	}
	for _, p := range blockers {
		_ = os.Remove(p)
	}
	put("n", 'n')

	check := func() {
		for _, i := range []int{0, 1, n / 2, n - 1} {
			o, nk := fmt.Sprintf("o%06d", i), fmt.Sprintf("n%06d", i)
			assertDropped(t, db, o, nk, val('n', i))
		}
	}
	check()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(opts.WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	check()
}
