package main

// fakeGenFS wraps a inner genFS and injects failures / hooks at each durability
// boundary so the immutable-generation store's transactionality can be proven
// deterministically (no sleeps).

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
)

type fakeGenFS struct {
	inner genFS

	failMkdirAll  bool
	failMkdirTemp bool
	failRename    bool
	failWriteOn   string // base name whose atomicWrite fails
	// corruptReadBackOn: reads of a staging file with this base name return altered
	// bytes so the immediate read-back mismatches (pre-commit failure).
	corruptReadBackOn string
	// failSyncDir: fail the Nth syncDir call (1-indexed; 1 = staging, 2 = parent).
	failSyncDir int
	syncCalls   atomic.Int64

	afterWrite   func(base string) // hook after each successful atomicWrite
	afterSyncDir func(n int64)     // hook after each successful syncDir (n = 1-indexed call)
	beforeRename func()            // hook before the commit rename
}

var errFakeGenFS = errors.New("fakeGenFS injected failure")

func newFakeGenFS(inner genFS) *fakeGenFS { return &fakeGenFS{inner: inner} }

func (f *fakeGenFS) seam() genFS {
	return genFS{
		mkdirAll: func(path string, perm os.FileMode) error {
			if f.failMkdirAll {
				return errFakeGenFS
			}
			return f.inner.mkdirAll(path, perm)
		},
		mkdirTemp: func(dir, pattern string) (string, error) {
			if f.failMkdirTemp {
				return "", errFakeGenFS
			}
			return f.inner.mkdirTemp(dir, pattern)
		},
		atomicWrite: func(path string, data []byte, perm os.FileMode) error {
			base := filepath.Base(path)
			if f.failWriteOn != "" && base == f.failWriteOn {
				return errFakeGenFS
			}
			if err := f.inner.atomicWrite(path, data, perm); err != nil {
				return err
			}
			if f.afterWrite != nil {
				f.afterWrite(base)
			}
			return nil
		},
		rename: func(oldpath, newpath string) error {
			if f.beforeRename != nil {
				f.beforeRename()
			}
			if f.failRename {
				return errFakeGenFS
			}
			return f.inner.rename(oldpath, newpath)
		},
		syncDir: func(path string) error {
			n := f.syncCalls.Add(1)
			if f.failSyncDir != 0 && int(n) == f.failSyncDir {
				return errFakeGenFS
			}
			if err := f.inner.syncDir(path); err != nil {
				return err
			}
			if f.afterSyncDir != nil {
				f.afterSyncDir(n)
			}
			return nil
		},
		readFile: func(path string) ([]byte, error) {
			b, err := f.inner.readFile(path)
			if err != nil {
				return nil, err
			}
			if f.corruptReadBackOn != "" && filepath.Base(path) == f.corruptReadBackOn {
				return append(append([]byte(nil), b...), 'X'), nil
			}
			return b, nil
		},
		stat:      f.inner.stat,
		removeAll: f.inner.removeAll,
	}
}

// strictDecodeJSON decodes exactly one JSON value with unknown fields disallowed
// (test helper for the generation.json record).
func strictDecodeJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
