//go:build linux

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Gates for Codex P2 4319694761 on PR #1601: one predicate decides whether a
// target can be replaced at all, and RewriteInPlace's precheck and the live
// ReplacementBlocked probe both apply it.

func injectDirStatx(t *testing.T, dir string, attrs uint64) {
	t.Helper()
	prev := dirStatxAttributes
	dirStatxAttributes = func(d string) (uint64, error) {
		if d == dir {
			return attrs, nil
		}
		return prev(d)
	}
	t.Cleanup(func() { dirStatxAttributes = prev })
}

// TestReplacementBlocked_SamePredicateAsTheRewrite pins that both callers
// agree, case by case: wherever ReplacementBlocked reports a blocked target,
// RewriteInPlace refuses it the same way (ErrReplacementBlocked, no exchange,
// target untouched); where it reports none, the rewrite lands.
func TestReplacementBlocked_SamePredicateAsTheRewrite(t *testing.T) {
	cases := []struct {
		name    string
		inject  func(t *testing.T, path string, fi os.FileInfo)
		blocked bool
		errno   syscall.Errno
	}{
		{"nothing", func(*testing.T, string, os.FileInfo) {}, false, 0},
		{"immutable flag", func(t *testing.T, _ string, fi os.FileInfo) { injectInodeFlags(t, fi, fsImmutableFL, nil) }, true, syscall.EPERM},
		{"append-only flag", func(t *testing.T, _ string, fi os.FileInfo) { injectInodeFlags(t, fi, fsAppendFL, nil) }, true, syscall.EPERM},
		{"statx immutable", func(t *testing.T, _ string, fi os.FileInfo) {
			injectStatx(t, fi, always, unix.STATX_ATTR_IMMUTABLE, nil)
		}, true, syscall.EPERM},
		{"statx append-only", func(t *testing.T, _ string, fi os.FileInfo) { injectStatx(t, fi, always, unix.STATX_ATTR_APPEND, nil) }, true, syscall.EPERM},
		{"mount point", func(t *testing.T, _ string, fi os.FileInfo) {
			injectStatx(t, fi, always, unix.STATX_ATTR_MOUNT_ROOT, nil)
		}, true, syscall.EBUSY},
		{"append-only directory", func(t *testing.T, path string, _ os.FileInfo) {
			injectDirStatx(t, filepath.Dir(path), unix.STATX_ATTR_APPEND)
		}, true, syscall.EPERM},
		{"immutable directory", func(t *testing.T, path string, _ os.FileInfo) {
			injectDirStatx(t, filepath.Dir(path), unix.STATX_ATTR_IMMUTABLE)
		}, true, syscall.EPERM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			tc.inject(t, path, fi)

			probe := ReplacementBlocked(path)
			if got := errors.Is(probe, ErrReplacementBlocked); got != tc.blocked || (!tc.blocked && probe != nil) {
				t.Fatalf("ReplacementBlocked = %v, want blocked=%v", probe, tc.blocked)
			}
			exchanges := countExchanges(t)
			err := RewriteInPlace(path, loaded, fi)
			if !tc.blocked {
				if err != nil {
					t.Fatalf("RewriteInPlace: %v (the probe saw nothing blocking)", err)
				}
				return
			}
			if !errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, tc.errno) || errors.Is(err, ErrMetadataNotPreservable) {
				t.Fatalf("RewriteInPlace err = %v, want ErrReplacementBlocked wrapping %v, as the probe reported", err, tc.errno)
			}
			if !errors.Is(probe, tc.errno) {
				t.Errorf("ReplacementBlocked = %v, want it to wrap %v too", probe, tc.errno)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran on a target no save can replace", n)
			}
			assertUntouched(t, path, fi, loaded)
		})
	}
}

// TestReplacementBlocked_RealChattr: a real chattr +i or +a (root here) is
// reported by the live probe. Skips where the filesystem or privileges do
// not allow setting the flag; the injected cases above cover the logic.
func TestReplacementBlocked_RealChattr(t *testing.T) {
	for name, flag := range map[string]uint32{"+i": fsImmutableFL, "+a": fsAppendFL} {
		t.Run(name, func(t *testing.T) {
			path, _ := rewriteFixture(t, []byte("{}"))
			if err := ReplacementBlocked(path); err != nil {
				t.Fatalf("precondition: ReplacementBlocked = %v on a plain file", err)
			}
			setInodeFlagsOrSkip(t, path, flag)
			if err := ReplacementBlocked(path); !errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, syscall.EPERM) {
				t.Errorf("ReplacementBlocked = %v after chattr %s, want ErrReplacementBlocked wrapping EPERM", err, name)
			}
		})
	}
}
