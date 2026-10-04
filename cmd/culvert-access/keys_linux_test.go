//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func accessRootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned isolated /run fixture")
	}
	dir, err := os.MkdirTemp("/run", "culvert-access-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Dir(dir) != "/run" || filepath.Base(dir) == "." {
			t.Fatal("refusing unsafe fixture cleanup")
		}
		_ = os.RemoveAll(dir)
	})
	return dir
}

func TestAccessKeysPublicationIsAtomicIdempotentAndRootOwned(t *testing.T) {
	dir := accessRootFixture(t)
	target := filepath.Join(dir, "keys", "culvert-operator")
	for _, data := range [][]byte{[]byte("public-fixture\n"), []byte("public-fixture\n"), nil} {
		if err := publishOperatorKeys(target, data); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("published key contents differ")
		}
		var st unix.Stat_t
		if err := unix.Lstat(target, &st); err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0o777 != 0o644 {
			t.Fatal("key publication ownership or permissions wrong")
		}
		if err := unix.Lstat(filepath.Dir(target), &st); err != nil || st.Uid != 0 || st.Mode&0o777 != 0o755 {
			t.Fatal("key directory ownership or permissions wrong")
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	if len(entries) != 1 {
		t.Fatal("key publication left staging files")
	}
}

func TestAccessKeysRefuseSymlinkAndUnsafeParentWithoutChangingTarget(t *testing.T) {
	for _, kind := range []string{"leaf-symlink", "parent-symlink", "writable-parent"} {
		t.Run(kind, func(t *testing.T) {
			dir := accessRootFixture(t)
			outside := filepath.Join(dir, "untouched")
			if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(dir, "keys")
			target := filepath.Join(parent, "culvert-operator")
			makeUnsafeKeyPath(t, kind, dir, parent, target, outside)
			if err := publishOperatorKeys(target, []byte("replacement")); err == nil {
				t.Fatal("unsafe authorization path accepted")
			}
			got, err := os.ReadFile(outside)
			if err != nil || string(got) != "unchanged" {
				t.Fatal("unsafe target modified")
			}
		})
	}
}

func TestAccessKeyReadDropsRootAndSupplementaryGroups(t *testing.T) {
	dir := accessRootFixture(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source")
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		if err := os.WriteFile(source, []byte("public fixture"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(source, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(source, 0, 0); err != nil {
			t.Fatal(err)
		}
		got, err := readImportedKeys(t.Context(), 65534, 65534, source)
		if mode == 0o644 {
			if err != nil || string(got) != "public fixture" {
				t.Fatal("unprivileged public read failed")
			}
		} else if err == nil || got != nil {
			t.Fatal("root or inherited root-group privilege read private source")
		}
	}
	if got, err := readImportedKeys(t.Context(), 65534, 65534, filepath.Join(dir, "missing")); err != nil || len(got) != 0 {
		t.Fatal("absent import must mean no keys")
	}
}

func TestAccessKeyReadCancelsBlockedFIFO(t *testing.T) {
	dir := accessRootFixture(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(source, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if got, err := readImportedKeys(ctx, 65534, 65534, source); err == nil || got != nil || time.Since(started) > 2*time.Second {
		t.Fatal("blocked unprivileged reader was not bounded")
	}
}

func makeUnsafeKeyPath(t *testing.T, kind, dir, parent, target, outside string) {
	t.Helper()
	if kind != "parent-symlink" {
		// #nosec G301 -- public key directory must be searchable by the unprivileged SSH user.
		if err := os.Mkdir(parent, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	switch kind {
	case "parent-symlink":
		if err := os.Symlink(dir, parent); err != nil {
			t.Fatal(err)
		}
	case "leaf-symlink":
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
	case "writable-parent":
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
	}
}
