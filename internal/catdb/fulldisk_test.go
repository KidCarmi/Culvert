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
	"time"

	badger "github.com/dgraph-io/badger/v4"
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
	if mnt := os.Getenv("CATDB_FULLDISK_CHILD"); mnt != "" {
		switch os.Getenv("CATDB_FULLDISK_MODE") {
		case "close-full":
			fullDiskCloseChild(t, mnt)
		case "vlog-grow":
			fullDiskVlogChild(t, mnt)
		default:
			fullDiskChild(t, mnt)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount a size-capped tmpfs")
	}
	for _, tc := range []struct {
		mode string
		want []string
	}{
		{"retry", []string{"WRITE-REFUSED", "RETRIES-REFUSED", "WRITE-RESUMED", "REOPENED"}},
		{"close-full", []string{"CLOSED", "REOPENED"}},
		{"vlog-grow", []string{"VLOG-GROW-REFUSED", "VLOG-REOPENED"}},
	} {
		t.Run(tc.mode, func(t *testing.T) { runFullDiskChild(t, tc.mode, tc.want) })
	}
}

func runFullDiskChild(t *testing.T, mode string, want []string) {
	mnt := t.TempDir()
	size := "size=1024m"
	if mode == "vlog-grow" {
		size = "size=32m"
	}
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, size); err != nil {
		t.Skipf("cannot mount tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, syscall.MNT_DETACH) })

	// #nosec G204 -- re-executes this test binary (os.Args[0]) with a fixed -test.run selector
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestFullFilesystemWriteReturnsErrorNotSIGBUS$", "-test.v")
	cmd.Env = append(os.Environ(), "CATDB_FULLDISK_CHILD="+mnt, "CATDB_FULLDISK_MODE="+mode)
	out, err := cmd.CombinedOutput()
	// A Go program that faults on a mmapped page exits 2 with "fatal error:
	// fault" / "signal SIGBUS" on stderr rather than dying BY the signal; a
	// badger assertion exits through log.Fatalf ("Assert failed").
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && (ws.Signaled() || strings.Contains(string(out), "signal SIGBUS") || strings.Contains(string(out), "fatal error: fault")) {
		t.Fatalf("the write path faulted instead of returning an error (F-DISK-1):\n%s", tail(out))
	}
	if strings.Contains(string(out), "Assert failed") {
		t.Fatalf("badger aborted the process on the full filesystem instead of returning an error:\n%s", tail(out))
	}
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, tail(out))
	}
	for _, w := range want {
		if !strings.Contains(string(out), w) {
			t.Fatalf("child did not report %s:\n%s", w, tail(out))
		}
	}
}

// fullDiskVlogChild drives the value-log GROW path directly: values sit in
// the value log (threshold 64 B), and one request crosses the end of the
// current 2 MiB mapping on a full filesystem, so the grow itself fails
// (the REFUSAL lines name the reserve on an existing .vlog). The process must
// survive, the same process must write again once space returns, and every
// acknowledged value must read back after a restart. Measured: upstream's
// kept offset (no rollback) also passes this — the reserved range becomes an
// unused hole, values are read by pointer — so the badger rollback is
// hygiene, not a demonstrated data-loss fix (CULVERT-PATCH.md).
func fullDiskVlogChild(t *testing.T, mnt string) {
	dir := filepath.Join(mnt, "vlogdb")
	opts := badger.DefaultOptions(dir).WithLogger(nil).
		WithMemTableSize(1 << 20).WithValueLogFileSize(1 << 20).WithValueThreshold(64)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := vlogPut(db, "before"); err != nil {
		t.Fatalf("write with room: %v", err)
	}
	filler := fillLeaving(t, mnt, 256<<10) // less than one value of headroom
	refused := 0
	for i := 0; i < 3; i++ {
		err := vlogPut(db, fmt.Sprintf("full%d", i))
		if err == nil {
			continue
		}
		if !isNoSpace(err) {
			t.Fatalf("write failed, but not on the full filesystem: %v", err)
		}
		refused++
		fmt.Printf("REFUSAL: %v\n", err)
	}
	if refused == 0 {
		t.Fatal("no value-log write was refused; the filesystem did not fill")
	}
	fmt.Printf("VLOG-GROW-REFUSED %d of 3\n", refused)
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	if err := vlogPut(db, "after"); err != nil {
		t.Fatalf("write after freeing space, same process: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	for _, tag := range []string{"before", "after"} {
		for i := 0; i < 3; i++ {
			if err := vlogCheck(db2, fmt.Sprintf("%s-%d", tag, i)); err != nil {
				t.Fatalf("acknowledged %s-%d lost after reopen: %v", tag, i, err)
			}
		}
	}
	fmt.Println("VLOG-REOPENED")
}

const vlogValueSize = 700 << 10

// vlogPut writes three ~700 KiB values in ONE transaction, so the request
// crosses the end of the current value-log mapping.
func vlogPut(db *badger.DB, tag string) error {
	return db.Update(func(txn *badger.Txn) error {
		for i := 0; i < 3; i++ {
			k := fmt.Sprintf("%s-%d", tag, i)
			v := make([]byte, vlogValueSize)
			copy(v, k)
			if err := txn.Set([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	})
}

func vlogCheck(db *badger.DB, k string) error {
	return db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(k))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			if !strings.HasPrefix(string(v), k) || len(v) != vlogValueSize {
				return fmt.Errorf("value differs (%d bytes)", len(v))
			}
			return nil
		})
	})
}

// fillLeaving fills the filesystem at mnt until only headroom bytes remain
// and returns the filler path.
func fillLeaving(t *testing.T, mnt string, headroom uint64) string {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(mnt, &st); err != nil {
		t.Fatal(err)
	}
	free := st.Bavail * uint64(st.Bsize) // #nosec G115 -- block size of a mounted filesystem is positive
	if free <= headroom {
		t.Fatalf("only %d bytes free", free)
	}
	filler := filepath.Join(mnt, "filler")
	if err := os.WriteFile(filler, make([]byte, free-headroom), 0o600); err != nil {
		t.Fatal(err)
	}
	return filler
}

// fullDiskBatch is one acknowledged-or-refused unit of the child's workload.
// Keys carry the batch number so an acknowledged batch can be re-checked
// after a restart without holding every key in memory.
func fullDiskBatch(batch int) map[string]string {
	entries := make(map[string]string, 20000)
	noise := make([]byte, 32)
	for i := 0; i < 20000; i++ {
		_, _ = rand.Read(noise) // incompressible, so the store really grows
		entries[fmt.Sprintf("host-%07d-%05d.example.test", batch, i)] = hex.EncodeToString(noise)
	}
	return entries
}

func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || strings.Contains(strings.ToLower(err.Error()), "no space")
}

// closeWithin closes db and fails if Close does not return in time: a store
// that hangs on shutdown while the disk is full would stall the appliance's
// bounded shutdown sequence instead of crashing it, which is still a failure.
func closeWithin(t *testing.T, db *CommunityDB, d time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- db.Close() }()
	select {
	case err := <-done:
		fmt.Printf("CLOSED err=%v\n", err) // may report the shortage; the process must survive it
	case <-time.After(d):
		t.Fatalf("Close did not return within %s", d)
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
	var acked []int
	var werr error
	batch := 0
	for ; batch < 400 && werr == nil; batch++ {
		if werr = db.BulkWrite(fullDiskBatch(batch)); werr == nil {
			acked = append(acked, batch)
		}
	}
	if werr == nil {
		t.Fatalf("the filesystem never filled (%d batches written); grow the workload", len(acked))
	}
	if !isNoSpace(werr) {
		t.Fatalf("write failed, but not on the full filesystem: %v", werr)
	}
	fmt.Printf("WRITE-REFUSED after %d batches: %v\n", len(acked), werr)

	// The SAME process keeps writing while the disk is still full: every
	// attempt must be refused with an error. Badger used to retire the full
	// memtable before allocating its replacement, so the failed allocation
	// left no current memtable and the NEXT write was a fatal assertion.
	for i := 0; i < 3; i++ {
		if err := db.BulkWrite(fullDiskBatch(1000 + i)); err == nil {
			t.Fatalf("retry %d succeeded on a full filesystem", i)
		} else if !isNoSpace(err) {
			t.Fatalf("retry %d failed, but not on the full filesystem: %v", i, err)
		}
	}
	fmt.Println("RETRIES-REFUSED")

	// Capacity returns: the same open store must accept writes again,
	// without a restart.
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	var rerr error
	for i := 0; i < 30; i++ { // the flusher retries once a second; give it time to drain
		if rerr = db.BulkWrite(fullDiskBatch(2000)); rerr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if rerr != nil {
		t.Fatalf("write after freeing space, same process: %v", rerr)
	}
	acked = append(acked, 2000)
	fmt.Println("WRITE-RESUMED")
	closeWithin(t, db, 60*time.Second)

	// Every acknowledged batch survives a restart (first and last key of each).
	db2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after freeing space: %v", err)
	}
	for _, b := range acked {
		for _, i := range []int{0, 19999} {
			k := fmt.Sprintf("host-%07d-%05d.example.test", b, i)
			if _, ok := db2.getExact(k); !ok {
				t.Fatalf("acknowledged entry %s is missing after reopen", k)
			}
		}
	}
	closeWithin(t, db2, 60*time.Second)
	fmt.Printf("REOPENED with %d acknowledged batches intact\n", len(acked))
}

// fullDiskCloseChild closes the store while the filesystem is STILL full: the
// shutdown must be bounded and must not fault, and the store must reopen once
// space is back.
func fullDiskCloseChild(t *testing.T, mnt string) {
	filler := filepath.Join(mnt, "filler")
	if err := os.WriteFile(filler, make([]byte, 512<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(mnt, "catfeeddb")
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var werr error
	for batch := 0; batch < 400 && werr == nil; batch++ {
		werr = db.BulkWrite(fullDiskBatch(batch))
	}
	if werr == nil || !isNoSpace(werr) {
		t.Fatalf("expected the write to be refused on the full filesystem, got %v", werr)
	}
	closeWithin(t, db, 60*time.Second)
	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after a close on a full disk: %v", err)
	}
	if _, ok := db2.getExact("host-0000000-00000.example.test"); !ok {
		t.Fatal("an entry committed before the shortage is missing after reopen")
	}
	closeWithin(t, db2, 60*time.Second)
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
