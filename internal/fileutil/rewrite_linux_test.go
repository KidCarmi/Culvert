//go:build linux

package fileutil

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// rewriteFixture writes loaded to dir/ui_users.json at mode 0640 (not
// AtomicWrite's usual 0600, so a preserved mode is distinguishable) and
// returns the path and its FileInfo, as a caller that just read it holds.
func rewriteFixture(t *testing.T, loaded []byte) (path string, fi os.FileInfo) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(path, loaded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- fixture mode under test
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, fi
}

func setRewriteHooks(t *testing.T, before, after func(tmp string)) {
	t.Helper()
	rewriteHooks.beforeExchange, rewriteHooks.afterExchange = before, after
	t.Cleanup(func() { rewriteHooks.beforeExchange, rewriteHooks.afterExchange = nil, nil })
}

func setRenameExchange(t *testing.T, fn func(a, b string) error) {
	t.Helper()
	prev := renameExchange
	renameExchange = fn
	t.Cleanup(func() { renameExchange = prev })
}

// replaceAtomically is a configuration manager's write: a new file renamed
// over path.
func replaceAtomically(t *testing.T, path string, data []byte) {
	t.Helper()
	side := path + ".cm-new"
	if err := os.WriteFile(side, data, 0o600); err != nil {
		t.Error(err)
		return
	}
	if err := os.Rename(side, path); err != nil {
		t.Error(err)
	}
}

func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func assertOnlyTarget(t *testing.T, path string) {
	t.Helper()
	if names := dirEntries(t, filepath.Dir(path)); len(names) != 1 || names[0] != filepath.Base(path) {
		t.Errorf("directory holds %q, want only %q", names, filepath.Base(path))
	}
}

// TestRewriteInPlace_SameBytesSameModeNewInode pins the success path against
// the real kernel exchange: the content and permission bits are unchanged, the
// replacement really happened (new inode), and no temp file is left behind.
func TestRewriteInPlace_SameBytesSameModeNewInode(t *testing.T) {
	want := []byte("[{\"username\":\"a\"}]\n") // a legacy bare-array roster, byte for byte
	path, before := rewriteFixture(t, want)
	sumBefore := sha256.Sum256(want)

	if err := RewriteInPlace(path, want, before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(readFileT(t, path)) != sumBefore {
		t.Errorf("content changed")
	}
	if after.Mode() != before.Mode() {
		t.Errorf("mode changed: %v -> %v", before.Mode(), after.Mode())
	}
	if os.SameFile(before, after) {
		t.Error("same inode after RewriteInPlace: the exchange with the target did not happen")
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_NeverDestroysAConcurrentChange is the Codex P2
// 4315243806 gate: an external writer lands between the temp write and the
// exchange, or after the exchange through a descriptor it opened before it.
// Whatever it wrote must end up at the target, and the result must be
// ErrConcurrentChange (no write evidence). A plain rename in place of the
// exchange, or a missing compare-and-exchange-back, fails every case.
func TestRewriteInPlace_NeverDestroysAConcurrentChange(t *testing.T) {
	loaded := []byte(`{"users":[{"username":"old"}]}`)
	newer := []byte(`{"users":[]}`) // e.g. the revocation of "old"
	cases := []concurrentChangeCase{
		{
			name:   "atomic replace before the exchange",
			before: func(t *testing.T, path string, _ **os.File) { replaceAtomically(t, path, newer) },
		},
		{
			name: "in-place write before the exchange",
			before: func(t *testing.T, path string, _ **os.File) {
				if err := os.WriteFile(path, newer, 0o600); err != nil {
					t.Error(err)
				}
			},
		},
		{
			name: "in-place write after the exchange, through a descriptor opened before it",
			before: func(t *testing.T, path string, held **os.File) {
				f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test temp path
				if err != nil {
					t.Error(err)
					return
				}
				*held = f
			},
			after: func(t *testing.T, _ string, held *os.File) {
				if held == nil {
					return
				}
				if err := held.Truncate(0); err != nil {
					t.Error(err)
				}
				if _, err := held.WriteAt(newer, 0); err != nil {
					t.Error(err)
				}
				if err := held.Close(); err != nil {
					t.Error(err)
				}
			},
		},
		{
			name: "mode tightened before the exchange",
			before: func(t *testing.T, path string, _ **os.File) {
				if err := os.Chmod(path, 0o600); err != nil {
					t.Error(err)
				}
			},
			check: func(t *testing.T, path string) {
				fi, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("the operator's chmod was undone: mode %v", fi.Mode())
				}
				if !bytes.Equal(readFileT(t, path), loaded) {
					t.Errorf("content changed")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runConcurrentChangeCase(t, tc, loaded, newer) })
	}
}

// concurrentChangeCase is one external writer: what it does just before the
// exchange (it may keep a descriptor in held), just after it, and an optional
// check replacing the default "the target holds newer".
type concurrentChangeCase struct {
	name   string
	before func(t *testing.T, path string, held **os.File)
	after  func(t *testing.T, path string, held *os.File)
	check  func(t *testing.T, path string)
}

func runConcurrentChangeCase(t *testing.T, tc concurrentChangeCase, loaded, newer []byte) {
	t.Helper()
	path, fi := rewriteFixture(t, loaded)
	var held *os.File
	setRewriteHooks(t,
		func(string) {
			if tc.before != nil {
				tc.before(t, path, &held)
			}
		},
		func(string) {
			if tc.after != nil {
				tc.after(t, path, held)
			}
		})

	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrConcurrentChange", err)
	}
	if tc.check != nil {
		tc.check(t, path)
	} else if got := readFileT(t, path); !bytes.Equal(got, newer) {
		t.Errorf("the newer roster was destroyed: target holds %q, want %q", got, newer)
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_RemovedTargetIsNotResurrected: a roster deleted after it
// was loaded stays deleted.
func TestRewriteInPlace_RemovedTargetIsNotResurrected(t *testing.T) {
	loaded := []byte("{}")
	path, fi := rewriteFixture(t, loaded)
	setRewriteHooks(t, func(string) {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	}, nil)
	if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrConcurrentChange", err)
	}
	if names := dirEntries(t, filepath.Dir(path)); len(names) != 0 {
		t.Errorf("directory holds %q, want nothing", names)
	}
}

// TestRewriteInPlace_ReplacedTargetAfterExchangeIsKept: a writer that
// replaces the file by path after the exchange replaces OUR copy, so the
// displaced file is still the loaded content: the rewrite landed (nil) and
// the writer's content is at the target.
func TestRewriteInPlace_ReplacedTargetAfterExchangeIsKept(t *testing.T) {
	loaded, newer := []byte("{\"v\":1}"), []byte("{\"v\":2}")
	path, fi := rewriteFixture(t, loaded)
	setRewriteHooks(t, nil, func(string) { replaceAtomically(t, path, newer) })
	if err := RewriteInPlace(path, loaded, fi); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	if got := readFileT(t, path); !bytes.Equal(got, newer) {
		t.Errorf("target holds %q, want the writer's %q", got, newer)
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_ExchangeBackFailurePreservesTheNewerFile: when undoing
// the exchange fails, the newer content is still at the temp path, which is
// never deleted and is named in the error.
func TestRewriteInPlace_ExchangeBackFailurePreservesTheNewerFile(t *testing.T) {
	loaded, newer := []byte("{\"v\":1}"), []byte("{\"v\":2}")
	path, fi := rewriteFixture(t, loaded)
	kernelExchange := renameExchange
	var calls atomic.Int32
	setRenameExchange(t, func(a, b string) error {
		if calls.Add(1) == 2 {
			return &os.LinkError{Op: "renameat2 exchange", Old: a, New: b, Err: syscall.EIO}
		}
		return kernelExchange(a, b)
	})
	setRewriteHooks(t, func(string) { replaceAtomically(t, path, newer) }, nil)

	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrExchangeBackFailed) || errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrExchangeBackFailed only", err)
	}
	var preserved string
	for _, n := range dirEntries(t, filepath.Dir(path)) {
		if strings.HasPrefix(n, "ui_users.json.tmp.") {
			preserved = filepath.Join(filepath.Dir(path), n)
		}
	}
	if preserved == "" {
		t.Fatal("the temp file holding the newer content was deleted")
	}
	if got := readFileT(t, preserved); !bytes.Equal(got, newer) {
		t.Errorf("preserved file holds %q, want %q", got, newer)
	}
	if !strings.Contains(err.Error(), preserved) {
		t.Errorf("error %q does not name the preserved file %q", err, preserved)
	}
}

// TestRewriteInPlace_ChangedAgainDuringRestoreKeepsBoth: a second writer
// replaces the target between the exchange and the exchange back. The restore
// then displaces that writer's file into the temp path; it is not deleted.
func TestRewriteInPlace_ChangedAgainDuringRestoreKeepsBoth(t *testing.T) {
	loaded, newer1, newer2 := []byte("{\"v\":1}"), []byte("{\"v\":2}"), []byte("{\"v\":3}")
	path, fi := rewriteFixture(t, loaded)
	setRewriteHooks(t,
		func(string) { replaceAtomically(t, path, newer1) },
		func(string) { replaceAtomically(t, path, newer2) })

	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrExchangeBackFailed) {
		t.Fatalf("err = %v, want ErrExchangeBackFailed", err)
	}
	var contents [][]byte
	for _, n := range dirEntries(t, filepath.Dir(path)) {
		contents = append(contents, readFileT(t, filepath.Join(filepath.Dir(path), n)))
	}
	var has1, has2 bool
	for _, c := range contents {
		has1 = has1 || bytes.Equal(c, newer1)
		has2 = has2 || bytes.Equal(c, newer2)
	}
	if !has1 || !has2 {
		t.Errorf("an external write was destroyed: directory contents %q", contents)
	}
}

// TestRewriteInPlace_UnsupportedExchangeWritesNothing: a kernel or filesystem
// without RENAME_EXCHANGE yields ErrRewriteUnsupported with the target
// untouched (same inode) and no temp left behind.
func TestRewriteInPlace_UnsupportedExchangeWritesNothing(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSYS, syscall.EINVAL, syscall.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			loaded := []byte("{}")
			path, fi := rewriteFixture(t, loaded)
			setRenameExchange(t, func(a, b string) error {
				return &os.LinkError{Op: "renameat2 exchange", Old: a, New: b, Err: errno}
			})
			if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrRewriteUnsupported) {
				t.Fatalf("err = %v, want ErrRewriteUnsupported", err)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(fi, after) {
				t.Error("the target was replaced although the exchange is unsupported")
			}
			assertOnlyTarget(t, path)
		})
	}
}

// TestRewriteInPlace_RefusedExchangeIsAPlainFailure: EPERM (a non-owner in a
// sticky directory) and EROFS are write-refusal evidence, not "unsupported"
// and not a concurrent change; the target is untouched.
func TestRewriteInPlace_RefusedExchangeIsAPlainFailure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EROFS, syscall.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			loaded := []byte("{}")
			path, fi := rewriteFixture(t, loaded)
			setRenameExchange(t, func(a, b string) error {
				return &os.LinkError{Op: "renameat2 exchange", Old: a, New: b, Err: errno}
			})
			err := RewriteInPlace(path, loaded, fi)
			if !errors.Is(err, errno) || errors.Is(err, ErrRewriteUnsupported) || errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want a plain %v", err, errno)
			}
			if !strings.Contains(err.Error(), ": exchange: ") {
				t.Errorf("error %q does not name the exchange stage", err)
			}
			assertOnlyTarget(t, path)
		})
	}
}

// TestRewriteInPlace_DirectoryAtTargetIsRestored: RENAME_EXCHANGE swaps a
// file with a directory, so a directory at the target is displaced, detected
// and swapped back, never replaced.
func TestRewriteInPlace_DirectoryAtTargetIsRestored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteInPlace(path, []byte("y"), fi); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrConcurrentChange", err)
	}
	if after, err := os.Stat(filepath.Join(path, "child")); err != nil || !after.IsDir() {
		t.Fatalf("the directory at the target was not restored (err %v)", err)
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_NotifiesNoObserver: a content-preserving rewrite is not a
// store write, so neither outcome reaches the storage-health observers, while
// AtomicWrite (the control) notifies both.
func TestRewriteInPlace_NotifiesNoObserver(t *testing.T) {
	var fails, oks atomic.Int64
	SetWriteFailureObserver(func(string, error) { fails.Add(1) })
	SetWriteSuccessObserver(func(string) { oks.Add(1) })
	t.Cleanup(func() {
		SetWriteFailureObserver(nil)
		SetWriteSuccessObserver(nil)
	})

	path, fi := rewriteFixture(t, []byte("x"))
	if err := RewriteInPlace(path, []byte("x"), fi); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing", "f.json")
	if err := RewriteInPlace(missing, []byte("x"), fi); err == nil {
		t.Fatal("RewriteInPlace into a missing directory succeeded")
	}
	if fails.Load() != 0 || oks.Load() != 0 {
		t.Fatalf("RewriteInPlace notified observers: %d failures, %d successes", fails.Load(), oks.Load())
	}

	if err := AtomicWrite(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(missing, []byte("x"), 0o600); err == nil {
		t.Fatal("AtomicWrite into a missing directory succeeded")
	}
	if fails.Load() != 1 || oks.Load() != 1 {
		t.Fatalf("control: AtomicWrite notified %d failures, %d successes; want 1 and 1", fails.Load(), oks.Load())
	}
}

// TestRewriteInPlace_PreservesOwnerWherePermitted: a privileged process keeps
// another account's owner and group; an unprivileged one rewriting its own
// file keeps its own. Where the owner cannot be kept, nothing is exchanged:
// see TestRewriteInPlace_UnpreservableOwnerIsNotExchanged.
func TestRewriteInPlace_PreservesOwnerWherePermitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	const otherID = 65534 // nobody/nogroup
	privileged := os.Geteuid() == 0
	if privileged {
		if err := os.Chown(path, otherID, otherID); err != nil {
			t.Fatalf("chown fixture: %v", err)
		}
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteInPlace(path, []byte("{}"), before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t on this platform: %T", after.Sys())
	}
	wantUID, wantGID := uint32(os.Geteuid()), uint32(os.Getegid()) // #nosec G115 -- ids are non-negative
	if privileged {
		wantUID, wantGID = otherID, otherID
	}
	if st.Uid != wantUID || st.Gid != wantGID {
		t.Errorf("owner %d:%d after rewrite, want %d:%d (privileged=%v)", st.Uid, st.Gid, wantUID, wantGID, privileged)
	}
}

// foreignOwnedFixture is rewriteFixture with the roster owned by another
// account (nobody/nogroup), which only root can arrange.
func foreignOwnedFixture(t *testing.T, loaded []byte) (path string, fi os.FileInfo) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the fixture to another account")
	}
	path, _ = rewriteFixture(t, loaded)
	const otherID = 65534
	if err := os.Chown(path, otherID, otherID); err != nil {
		t.Fatalf("chown fixture: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, fi
}

func setFchown(t *testing.T, fn func(f *os.File, uid, gid int) error) {
	t.Helper()
	prev := fchown
	fchown = fn
	t.Cleanup(func() { fchown = prev })
}

// countExchanges wraps the kernel exchange and counts the calls.
func countExchanges(t *testing.T) *atomic.Int32 {
	t.Helper()
	kernelExchange := renameExchange
	var n atomic.Int32
	setRenameExchange(t, func(a, b string) error {
		n.Add(1)
		return kernelExchange(a, b)
	})
	return &n
}

// assertUntouched: the target is still the loaded inode, with its owner,
// group, mode and bytes, and no temp file is left beside it.
func assertUntouched(t *testing.T, path string, fi os.FileInfo, loaded []byte) {
	t.Helper()
	cur, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, cur) || !sameOwner(fi, cur) || cur.Mode() != fi.Mode() {
		t.Errorf("the target changed: %v %v -> %v %v", fi.Mode(), fi.Sys(), cur.Mode(), cur.Sys())
	}
	if !bytes.Equal(readFileT(t, path), loaded) {
		t.Error("content changed")
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_UnpreservableOwnerIsNotExchanged is the Codex P2
// 4316401892 gate: an unprivileged process may replace another account's
// roster in a writable, non-sticky directory but cannot give the replacement
// away (EPERM, injected here because the tests run as root). The rewrite must
// then exchange nothing rather than silently take the roster over. Ignoring
// the chown error fails this test.
func TestRewriteInPlace_UnpreservableOwnerIsNotExchanged(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	var path string
	var fi os.FileInfo
	if os.Geteuid() == 0 {
		path, fi = foreignOwnedFixture(t, loaded) // the reported case: another account's roster
	} else {
		path, fi = rewriteFixture(t, loaded)
	}
	setFchown(t, func(*os.File, int, int) error { return syscall.EPERM })
	exchanges := countExchanges(t)

	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrMetadataNotPreservable) || !errors.Is(err, syscall.EPERM) || errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrMetadataNotPreservable wrapping EPERM", err)
	}
	if n := exchanges.Load(); n != 0 {
		t.Errorf("%d exchange(s) ran although the owner could not be preserved", n)
	}
	assertUntouched(t, path, fi, loaded)
}

// TestRewriteInPlace_OwnerIsVerifiedAfterChown: a chown that reports success
// but leaves the replacement with another owner (here a no-op) is caught by
// the read-back, so nothing is exchanged. Dropping the owner read-back fails
// this test.
func TestRewriteInPlace_OwnerIsVerifiedAfterChown(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := foreignOwnedFixture(t, loaded)
	setFchown(t, func(*os.File, int, int) error { return nil })
	exchanges := countExchanges(t)

	if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrMetadataNotPreservable) {
		t.Fatalf("err = %v, want ErrMetadataNotPreservable", err)
	}
	if n := exchanges.Load(); n != 0 {
		t.Errorf("%d exchange(s) ran although the replacement has another owner", n)
	}
	assertUntouched(t, path, fi, loaded)
}

// TestRewriteInPlace_ConcurrentChownIsSwappedBack: another process changing
// the roster's owner just before the exchange is a metadata change like any
// other, so the exchange is undone and the original inode, with the new
// owner, is back at the target.
func TestRewriteInPlace_ConcurrentChownIsSwappedBack(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to change the fixture's owner")
	}
	loaded := []byte(`{"users":[]}`)
	path, fi := rewriteFixture(t, loaded)
	setRewriteHooks(t, func(string) {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Error(err)
		}
	}, nil)
	if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrConcurrentChange", err)
	}
	cur, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := cur.Sys().(*syscall.Stat_t)
	if !os.SameFile(fi, cur) || !ok || st.Uid != 65534 {
		t.Errorf("the chowned original was not swapped back: %v", cur.Sys())
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_UnopenableParentDirIsNotSynced: the boot rewrite's own
// directory fsync follows the same rule (Codex P2 4317365510 on PR #1601):
// the exchange landed, the directory could not be opened, so the result is
// ErrReplacedNotSynced, not success.
func TestRewriteInPlace_UnopenableParentDirIsNotSynced(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := rewriteFixture(t, loaded)
	injectParentDirOpen(t, syscall.EACCES)
	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrReplacedNotSynced) || !errors.Is(err, syscall.EACCES) {
		t.Fatalf("err = %v, want ErrReplacedNotSynced wrapping EACCES", err)
	}
	if os.SameFile(fi, statT(t, path)) {
		t.Error("same inode: the exchange did not land")
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_UnsyncedRestoreKeepsTheRecoveryEntry (Codex P2
// 4319946921 on PR #1601): after a concurrent change is swapped back, the
// directory cannot be opened, or its fsync fails. The restore may not be
// durable, so the entry it displaced is kept and named, and the result is
// ErrConcurrentChange AND ErrRestoreNotSynced. Removing the entry before the
// sync, or ignoring the sync result, fails this test.
func TestRewriteInPlace_UnsyncedRestoreKeepsTheRecoveryEntry(t *testing.T) {
	for name, inject := range map[string]func(t *testing.T){
		"directory cannot be opened": func(t *testing.T) { injectParentDirOpen(t, syscall.EACCES) },
		"directory fsync fails":      func(t *testing.T) { injectDirSync(t, syscall.EIO) },
	} {
		t.Run(name, func(t *testing.T) {
			loaded, newer := []byte("{\"v\":1}"), []byte("{\"v\":2}")
			path, fi := rewriteFixture(t, loaded)
			inject(t)
			setRewriteHooks(t, func(string) { replaceAtomically(t, path, newer) }, nil)

			err := RewriteInPlace(path, loaded, fi)
			if !errors.Is(err, ErrConcurrentChange) || !errors.Is(err, ErrRestoreNotSynced) {
				t.Fatalf("err = %v, want ErrConcurrentChange and ErrRestoreNotSynced", err)
			}
			if got := readFileT(t, path); !bytes.Equal(got, newer) {
				t.Errorf("target holds %q, want the restored newer roster", got)
			}
			var kept string
			for _, n := range dirEntries(t, filepath.Dir(path)) {
				if strings.HasPrefix(n, "ui_users.json.tmp.") {
					kept = filepath.Join(filepath.Dir(path), n)
				}
			}
			if kept == "" {
				t.Fatal("the recovery entry was removed although the restore is not synced")
			}
			if !strings.Contains(err.Error(), kept) {
				t.Errorf("error %q does not name the kept entry %q", err, kept)
			}
		})
	}
}

// TestRewriteInPlaceUnless_AbandonedBeforeTheExchange (Codex P1 4319946910):
// a rewrite abandoned at any checkpoint never exchanges, leaves no temp file
// and returns ErrRewriteAbandoned. Dropping the pre-exchange check fails the
// "after the temp is written" case.
func TestRewriteInPlaceUnless_AbandonedBeforeTheExchange(t *testing.T) {
	for name, at := range map[string]int{"before any work": 0, "after the temp is written": 1} {
		t.Run(name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			var gaveUp atomic.Bool
			if at == 0 {
				gaveUp.Store(true)
			}
			setRewriteHooks(t, func(string) { gaveUp.Store(true) }, nil) // the deadline fires with the temp written
			exchanges := countExchanges(t)
			err := RewriteInPlaceUnless(path, loaded, fi, gaveUp.Load)
			if !errors.Is(err, ErrRewriteAbandoned) {
				t.Fatalf("err = %v, want ErrRewriteAbandoned", err)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran after the rewrite was abandoned", n)
			}
			assertUntouched(t, path, fi, loaded)
		})
	}
}
