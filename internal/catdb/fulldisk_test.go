package catdb

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// F-DISK-1: a filesystem that fills while badger is writing must surface as an
// ERROR from the write, never as a SIGBUS that kills the process. Badger backs
// its memtable WAL, value log and new tables with mmapped files; created
// sparse, the first store into a page the filesystem cannot allocate faults
// (`fatal error: fault`, SIGBUS in logFile.zeroNextEntry) — reproduced on CI
// runners four times by the midwrite scenario. The local ristretto fork
// (third_party/ristretto, CULVERT-PATCH.md) preallocates those files, so the
// shortage is reported when the file is created or grown.
//
// The real store runs on a size-capped tmpfs in a CHILD process: if the write
// path still faults, the child dies and this test fails with the signal
// instead of taking the whole test binary down. Mounting needs root
// (CAP_SYS_ADMIN); elsewhere the test skips. The end-to-end proof on a real
// proxy is the midwrite scenario (test/e2e/appliance/upgrade-enospc-qualify.sh).
func TestFullFilesystemWriteReturnsErrorNotSIGBUS(t *testing.T) {
	if os.Getenv("CATDB_FULLDISK_CHILD") != "" {
		fullDiskChild(t, os.Getenv("CATDB_FULLDISK_CHILD"))
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount a size-capped tmpfs")
	}
	mnt := t.TempDir()
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1024m"); err != nil {
		t.Skipf("cannot mount tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, syscall.MNT_DETACH) })

	// #nosec G204 -- re-executes this test binary (os.Args[0]) with a fixed -test.run selector
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestFullFilesystemWriteReturnsErrorNotSIGBUS$", "-test.v")
	cmd.Env = append(os.Environ(), "CATDB_FULLDISK_CHILD="+mnt)
	out, err := cmd.CombinedOutput()
	// A Go program that faults on a mmapped page exits 2 with "fatal error:
	// fault" / "signal SIGBUS" on stderr rather than dying BY the signal.
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && (ws.Signaled() || strings.Contains(string(out), "signal SIGBUS") || strings.Contains(string(out), "fatal error: fault")) {
		t.Fatalf("the write path faulted instead of returning an error (F-DISK-1):\n%s", tail(out))
	}
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, tail(out))
	}
	for _, want := range []string{"WRITE-REFUSED", "REOPENED"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("child did not report %s:\n%s", want, tail(out))
		}
	}
}

func fullDiskChild(t *testing.T, mnt string) {
	// Leave room for the store to open, then fill the rest during the write.
	filler := filepath.Join(mnt, "filler")
	if err := os.WriteFile(filler, make([]byte, 512<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(mnt, "catfeeddb")
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("open on a filesystem with room: %v", err)
	}
	var werr error
	written := 0
	for batch := 0; batch < 400 && werr == nil; batch++ {
		entries := make(map[string]string, 20000)
		noise := make([]byte, 32)
		for i := 0; i < 20000; i++ {
			_, _ = rand.Read(noise) // incompressible, so the store really grows
			entries[fmt.Sprintf("host-%07d-%05d.example.test", batch, i)] = hex.EncodeToString(noise)
		}
		if werr = db.BulkWrite(entries); werr == nil {
			written += len(entries)
		}
	}
	if werr == nil {
		t.Fatalf("the filesystem never filled (%d entries written); grow the workload", written)
	}
	if !errors.Is(werr, syscall.ENOSPC) && !strings.Contains(strings.ToLower(werr.Error()), "no space") {
		t.Fatalf("write failed, but not on the full filesystem: %v", werr)
	}
	fmt.Printf("WRITE-REFUSED after %d entries: %v\n", written, werr)
	_ = db.Close() // may report the same shortage; the process must survive it
	// Space is freed: the store reopens and serves what it had committed.
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after freeing space: %v", err)
	}
	defer db2.Close()
	if _, ok := db2.getExact("host-0000000-00000.example.test"); !ok && written > 0 {
		t.Fatalf("an entry committed before the shortage is missing after reopen")
	}
	fmt.Println("REOPENED")
}

func tail(b []byte) string {
	s := string(b)
	if len(s) > 4000 {
		s = "…" + s[len(s)-4000:]
	}
	return s
}

// TestStoreFilesAreFullyAllocated is the unprivileged half of F-DISK-1: every
// file badger maps for writing (memtable WAL, value log) must be backed by
// real blocks, not sparse. A sparse mapping is exactly what faults when the
// filesystem fills; this fails if the root module ever stops building against
// the patched ristretto (go.mod replace → third_party/ristretto).
func TestStoreFilesAreFullyAllocated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.BulkWrite(map[string]string{"example.test": "news"}); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, pattern := range []string{"*.mem", "*.vlog"} {
		files, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, f := range files {
			fi, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			st := fi.Sys().(*syscall.Stat_t)
			if allocated := st.Blocks * 512; allocated < fi.Size() {
				t.Errorf("%s is sparse: %d of %d bytes allocated — a store into the hole SIGBUSes on a full disk", filepath.Base(f), allocated, fi.Size())
			}
			checked++
		}
	}
	if checked < 2 {
		t.Fatalf("expected at least one memtable WAL and one value log, checked %d", checked)
	}
}
