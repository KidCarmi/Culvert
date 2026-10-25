// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md) — not part of upstream badger.

package badger

// A flush that keeps failing must not wedge the stops that wait for the
// flusher, and must not wedge the flusher either. SST creation is made to
// fail portably by putting directories at the next table file names
// (ASTRA review of 6a9d3873); removing them is "space returns".

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type flushFailLogger struct{ failed chan struct{} }

func (l *flushFailLogger) Errorf(f string, a ...interface{}) {
	if strings.Contains(fmt.Sprintf(f, a...), "error flushing memtable") {
		select {
		case l.failed <- struct{}{}:
		default:
		}
	}
}
func (*flushFailLogger) Warningf(string, ...interface{}) {}
func (*flushFailLogger) Infof(string, ...interface{})    {}
func (*flushFailLogger) Debugf(string, ...interface{})   {}

func openFailingFlush(t *testing.T, dir string) (*DB, *flushFailLogger, func()) {
	t.Helper()
	l := &flushFailLogger{failed: make(chan struct{}, 1)}
	db, err := Open(DefaultOptions(dir).WithLogger(l).WithMemTableSize(1 << 20).WithValueLogFileSize(1 << 20).
		WithValueThreshold(1024).WithNumCompactors(0).WithCompactL0OnClose(false))
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
	return db, l, func() {
		for _, p := range blockers {
			_ = os.Remove(p)
		}
	}
}

func cfPut(t *testing.T, db *DB, prefix string, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		if err := db.Update(func(txn *Txn) error {
			return txn.Set([]byte(fmt.Sprintf("%s%08d", prefix, i)), bytes.Repeat([]byte{0x41}, 512))
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFlushFailure(t *testing.T, l *flushFailLogger) {
	t.Helper()
	select {
	case <-l.failed:
	case <-time.After(10 * time.Second):
		t.Fatal("no SST creation failure observed")
	}
}

// waitDrained waits until the flusher has written tables and the immutable
// backlog is within the configured bound.
func waitDrained(t *testing.T, db *DB) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		db.lock.RLock()
		imm := len(db.imm)
		db.lock.RUnlock()
		if imm <= db.opt.NumMemtables && len(db.Tables()) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	db.lock.RLock()
	defer db.lock.RUnlock()
	t.Fatalf("flusher never resumed: %d immutable memtables (limit %d), %d tables", len(db.imm), db.opt.NumMemtables, len(db.Tables()))
}

func TestCulvertFlushStop_DropAllDoesNotWedgeTheFlusher(t *testing.T) {
	dir := t.TempDir()
	db, l, unblock := openFailingFlush(t, dir)
	defer func() { _ = db.Close() }()
	cfPut(t, db, "k", 0, 2000)
	waitFlushFailure(t, l)
	done := make(chan error, 1)
	go func() { done <- db.DropAll() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DropAll: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("DropAll waited forever on a failing flush")
	}
	unblock()
	cfPut(t, db, "k", 0, 15000)
	waitDrained(t, db)
}

func TestCulvertFlushStop_FailedDropPrefixKeepsAndLaterFlushesData(t *testing.T) {
	dir := t.TempDir()
	db, l, unblock := openFailingFlush(t, dir)
	defer func() { _ = db.Close() }()
	cfPut(t, db, "a", 0, 1000)
	cfPut(t, db, "b", 0, 1000)
	waitFlushFailure(t, l)
	done := make(chan error, 1)
	go func() { done <- db.DropPrefix([]byte("a")) }()
	select {
	case err := <-done:
		if err == nil {
			t.Log("DropPrefix succeeded despite the blockers")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("DropPrefix waited forever on a failing flush")
	}
	db.lock.RLock()
	retained := append([]*memTable(nil), db.imm...)
	for _, mt := range db.imm {
		if mt == db.mt {
			db.lock.RUnlock()
			t.Fatal("the current memtable is also in db.imm after a failed DropPrefix")
		}
	}
	db.lock.RUnlock()
	if len(retained) == 0 {
		t.Fatal("no memtable was retained: the scenario did not exercise a failed flush")
	}
	unblock()
	cfPut(t, db, "c", 0, 3000)
	waitDrained(t, db)
	// The memtables the failed DropPrefix retained must actually be FLUSHED
	// (handed back to the resumed flusher), not just kept readable in memory.
	deadline := time.Now().Add(20 * time.Second)
	for {
		db.lock.RLock()
		stuck := 0
		for _, mt := range db.imm {
			for _, r := range retained {
				if mt == r {
					stuck++
				}
			}
		}
		db.lock.RUnlock()
		if stuck == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d memtables retained by the failed DropPrefix were never flushed", stuck)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := db.View(func(txn *Txn) error {
		for _, k := range []string{"b00000000", "b00000999", "c00002999"} {
			if _, err := txn.Get([]byte(k)); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("acknowledged data lost: %v", err)
	}
}

func TestCulvertFlushStop_CloseIsBoundedAndReplays(t *testing.T) {
	dir := t.TempDir()
	db, l, unblock := openFailingFlush(t, dir)
	cfPut(t, db, "k", 0, 3000)
	waitFlushFailure(t, l)
	done := make(chan error, 1)
	go func() { done <- db.Close() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not flushed") {
			t.Fatalf("Close = %v, want the unflushed-memtable error", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Close waited forever on a failing flush")
	}
	unblock()
	db2, err := Open(DefaultOptions(dir).WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()
	if err := db2.View(func(txn *Txn) error {
		for _, k := range []string{"k00000000", "k00002999"} {
			if _, err := txn.Get([]byte(k)); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("acknowledged data lost across the close: %v", err)
	}
}
