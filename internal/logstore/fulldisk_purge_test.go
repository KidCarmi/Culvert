package logstore

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F-DISK-1, purge on a FULL filesystem. Purging request history is the
// operator's remedy for a disk that history has filled, so PurgeAll must
// return and free the space while the disk is full, and writes must resume
// after it.
//
// It also settles a reachability question from review: a writer can only park
// waiting for a flush AFTER it has allocated the next memtable (the
// replacement is created before the full one is handed to the flusher,
// third_party/badger/CULVERT-PATCH.md). A memtable is preallocated, so on a
// full filesystem that allocation fails first and the write is refused with
// ENOSPC instead of parking, and DropAll's blockWrite has nothing to wait for.
//
// Runs on a size-capped tmpfs in a CHILD process (a fault there fails the
// test instead of killing the binary). Needs root to mount; skips elsewhere.
func TestPurgeOnFullFilesystemFreesSpaceAndWritesResume(t *testing.T) {
	if mnt := os.Getenv("LOGSTORE_PURGE_FULL_CHILD"); mnt != "" {
		purgeFullChild(mnt)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount a size-capped tmpfs")
	}
	mnt := t.TempDir()
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=900m"); err != nil {
		t.Skipf("cannot mount tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, syscall.MNT_DETACH) })

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPurgeOnFullFilesystemFreesSpaceAndWritesResume$") // #nosec G204 G702 -- re-runs this test binary as the child
	cmd.Env = append(os.Environ(), "LOGSTORE_PURGE_FULL_CHILD="+mnt)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed (a fault here is the F-DISK-1 crash): %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && strings.HasPrefix(k, "PF_") {
			got[k] = v
		}
	}
	t.Logf("child: %v", got)
	if !strings.Contains(got["PF_WRITE_ERR"], "no space left on device") || got["PF_FILLER_KB"] == "" {
		t.Fatalf("the filesystem never filled, or the write failed for another reason: %q", got["PF_WRITE_ERR"])
	}
	if got["PF_PURGE"] != "ok" {
		t.Fatalf("PurgeAll on a full filesystem: %q (want ok within the bound)", got["PF_PURGE"])
	}
	// What an empty store occupies (preallocated memtable WAL and value log)
	// is the floor; the purge must return to it, and the fill must have been
	// well above it.
	open, _ := strconv.ParseInt(got["PF_USED_OPEN_KB"], 10, 64)
	full, _ := strconv.ParseInt(got["PF_USED_FULL_KB"], 10, 64)
	after, _ := strconv.ParseInt(got["PF_USED_AFTER_KB"], 10, 64)
	if full < open+200*1024 {
		t.Fatalf("the fill did not add data above the empty store: open %d KiB, full %d KiB", open, full)
	}
	if after > open+16*1024 {
		t.Fatalf("purge did not free the history: empty store %d KiB, full %d KiB, after purge %d KiB", open, full, after)
	}
	if got["PF_WRITE_AFTER"] != "ok" || got["PF_READ_AFTER"] != "ok" {
		t.Fatalf("store not usable after the purge: write=%q read=%q", got["PF_WRITE_AFTER"], got["PF_READ_AFTER"])
	}
	if got["PF_CLOSE"] != "ok" {
		t.Fatalf("Close after the purge: %q", got["PF_CLOSE"])
	}
}

func usedKB(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total / 1024
}

// bounded runs fn with a deadline and reports "ok", the error, or "hung".
func bounded(d time.Duration, fn func() error) string {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			return "err: " + err.Error()
		}
		return "ok"
	case <-time.After(d):
		return "hung"
	}
}

// fillRemaining preallocates path until the filesystem refuses, and returns
// how many KiB it took.
func fillRemaining(path string) int64 {
	f, err := os.Create(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	var off int64
	for _, chunk := range []int64{64 << 20, 1 << 20, 4 << 10} {
		for syscall.Fallocate(int(f.Fd()), 0, off, chunk) == nil {
			off += chunk
		}
	}
	return off / 1024
}

func purgeFullChild(mnt string) {
	key := make([]byte, 32) // the appliance encrypts history (CULVERT_LOG_PASSPHRASE)
	_, _ = rand.Read(key)
	dir := filepath.Join(mnt, "history")
	s, err := OpenTTL(dir, time.Hour, 0, key, nil)
	if err != nil {
		fmt.Println("PF_OPEN=" + err.Error())
		os.Exit(1)
	}
	fmt.Printf("PF_USED_OPEN_KB=%d\n", usedKB(dir))
	val := make([]byte, 4096)
	var werr error
	for i := int64(0); i < 1_000_000 && werr == nil; i++ {
		_, _ = rand.Read(val)
		wb := s.db.NewWriteBatch()
		for j := uint32(0); j < 64; j++ {
			_ = wb.Set(storeKey(i*64+int64(j), j), val)
		}
		werr = wb.Flush()
	}
	fmt.Printf("PF_WRITE_ERR=%v\n", werr)
	// Where the store stopped depends on timing: the space left can still fit
	// a preallocated memtable or not. Take whatever is left so the purge
	// always starts from a filesystem with no free space at all, the state in
	// which an allocate-first DropAll fails every time.
	// The flusher keeps running after the writes stop, and a flush that
	// lands deletes its memtable's WAL and frees space again, so keep taking
	// it until two consecutive rounds a second apart find none left.
	var filler int64
	for i, quiet := 0, 0; quiet < 2 && i < 60; i++ {
		got := fillRemaining(filepath.Join(mnt, fmt.Sprintf("filler-%d", i)))
		filler += got
		if got == 0 {
			quiet++
		} else {
			quiet = 0
		}
		time.Sleep(1200 * time.Millisecond)
	}
	fmt.Printf("PF_FILLER_KB=%d\n", filler)
	fmt.Printf("PF_USED_FULL_KB=%d\n", usedKB(dir))
	fmt.Printf("PF_PURGE=%s\n", bounded(60*time.Second, s.PurgeAll))
	fmt.Printf("PF_USED_AFTER_KB=%d\n", usedKB(dir))
	fmt.Printf("PF_WRITE_AFTER=%s\n", bounded(30*time.Second, func() error {
		wb := s.db.NewWriteBatch()
		if err := wb.Set(storeKey(1, 1), []byte(`{"host":"after-purge"}`)); err != nil {
			return err
		}
		return wb.Flush()
	}))
	fmt.Printf("PF_READ_AFTER=%s\n", bounded(30*time.Second, func() error {
		txn := s.db.NewTransaction(false)
		defer txn.Discard()
		_, err := txn.Get(storeKey(1, 1))
		return err
	}))
	fmt.Printf("PF_CLOSE=%s\n", bounded(60*time.Second, s.Close))
}
