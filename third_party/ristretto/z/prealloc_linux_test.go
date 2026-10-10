//go:build linux

// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md) — not part of upstream ristretto.

package z

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// On a filesystem without fallocate the range must still be ALLOCATED (not
// sparse) and existing bytes must be unchanged.
func TestPreallocateWithoutFallocateAllocatesAndPreservesData(t *testing.T) {
	saved := fallocate
	fallocate = func(int, uint32, int64, int64) error { return unix.EOPNOTSUPP }
	defer func() { fallocate = saved }()

	path := filepath.Join(t.TempDir(), "f")
	data := bytes.Repeat([]byte{0xAB}, 10000)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const total = 4 << 20
	if err := preallocate(f, 0, total); err != nil {
		t.Fatalf("preallocate: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != total {
		t.Fatalf("size %d, want %d", st.Size, total)
	}
	if allocated := st.Blocks * 512; allocated < total {
		t.Fatalf("only %d of %d bytes allocated: the range was left sparse", allocated, total)
	}
	got := make([]byte, len(data))
	if _, err := f.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("existing data changed: %v", err)
	}
}

// The fallback must report a shortage as an error, never succeed silently.
func TestPreallocateWithoutFallocateReportsWriteErrors(t *testing.T) {
	saved := fallocate
	fallocate = func(int, uint32, int64, int64) error { return unix.ENOSYS }
	defer func() { fallocate = saved }()
	path := filepath.Join(t.TempDir(), "ro")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) // read-only: every emulated write fails
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := preallocate(f, 0, 1<<20); err == nil {
		t.Fatal("a failed emulated reservation returned nil")
	}
}
