//go:build linux

package appliancehost

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func faultFilesystem(t *testing.T) string {
	t.Helper()
	if os.Getenv("CULVERT_STORAGE_FAULTS") != "1" {
		t.Skip("isolated mount faults require explicit test opt-in and CAP_SYS_ADMIN")
	}
	root := rootDirectory(t)
	mount := filepath.Join(root, "fault-volume")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", mount, "tmpfs", 0, "size=128k,nr_inodes=64,mode=0700"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mount, 0); err != nil {
			t.Error(err)
		}
	})
	return mount
}

func fillFilesystem(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	block := make([]byte, 4096)
	for range 64 {
		if _, err := f.Write(block); err != nil {
			if !errors.Is(err, unix.ENOSPC) {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("bounded fault volume did not reach ENOSPC")
}

func TestAtomicReplacementOnFullAndReadOnlyFilesystem(t *testing.T) {
	for _, mode := range []string{"full", "midwrite", "inodes", "read_only"} {
		t.Run(mode, func(t *testing.T) {
			root := faultFilesystem(t)
			path := filepath.Join(root, "state.json")
			original := []byte("previous durable recovery record")
			if err := atomicFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			want := injectStorageFault(t, root, mode)
			if err := atomicFile(path, bytes.Repeat([]byte("replacement"), 1024), 0o600); !errors.Is(err, want) {
				t.Fatalf("expected %v: %v", want, err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatalf("old state damaged: %q %v", actual, err)
			}
			stages, err := filepath.Glob(filepath.Join(root, ".culvert-stage-*"))
			if err != nil || len(stages) != 0 {
				t.Fatalf("temporary files leaked: %v %v", stages, err)
			}
		})
	}
}

func injectStorageFault(t *testing.T, root, mode string) error {
	t.Helper()
	switch mode {
	case "read_only":
		if err := unix.Mount("", root, "", unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			t.Fatal(err)
		}
		return unix.EROFS
	case "inodes":
		for i := range 128 {
			err := os.WriteFile(filepath.Join(root, fmt.Sprintf("inode-%d", i)), nil, 0o600)
			if errors.Is(err, unix.ENOSPC) {
				return unix.ENOSPC
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("bounded inode fault was not reached")
	default:
		filler := filepath.Join(root, "filler")
		fillFilesystem(t, filler)
		if mode == "midwrite" {
			info, err := os.Stat(filler)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(filler, info.Size()-4096); err != nil {
				t.Fatal(err)
			}
		}
	}
	return unix.ENOSPC
}
