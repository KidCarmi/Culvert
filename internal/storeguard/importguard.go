package storeguard

// importguard.go — F-DISK-RECOVERY-1: a durable "import in progress" intent.
//
// RecordFault (faultguard.go) records a contained runtime fault so the NEXT Open
// quarantines the damaged store. It is written AT fault time, and the fault whose
// recovery it is meant to drive is a full disk — so on the exact failure it exists
// to recover from, its own write fails with ENOSPC and the store is never
// quarantined (the proxy does not crash, nothing restarts it, and the Layer-2
// cache stays degraded across every restart until an operator deletes it).
//
// The import-pending marker closes that by inverting the timing: it is laid down
// BEFORE the risky bulk write, while the disk still has space, and cleared once the
// import is certified complete. A marker still present at the next Open means the
// previous import was interrupted — killed, faulted, or filled the disk mid-write —
// and the partial store is thrown away and rebuilt. Recovery therefore never
// depends on writing to an already-full filesystem after the failure.
//
// It is OPT-IN: only a caller that performs rebuildable bulk imports (catdb's UT1
// feed) writes it. A store that never calls MarkImportPending — logstore, or any
// future storeguard user — never has one, so Open's interrupted-import check is a
// no-op for it and its behaviour is byte-identical.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ImportPendingSuffix names the import-pending marker beside the store directory.
// A sibling, not a file inside the store, so moving the store aside on recovery
// does not carry the marker with it (the quarantine clears it explicitly).
const (
	ImportPendingSuffix     = ".importing"
	ImportPendingTempSuffix = ".importingtmp."
)

// MarkImportPending durably records that a bulk import into the store at dir is
// about to begin, so an Open that finds the marker still present quarantines the
// partial store and rebuilds it. The write is atomic and fsynced (temp file,
// fsync, rename, directory fsync), exactly like RecordFault.
//
// The error is load-bearing for the caller: an import MUST NOT proceed if its
// intent could not be made durable, because then a mid-write interruption would
// leave a torn store with no marker to recover it. Fail closed — do not start the
// write.
func MarkImportPending(dir string) error { return recordImportPending(dir, osMarkerFS) }

func recordImportPending(dir string, fsys markerFS) error {
	base := trimSep(dir)
	if base == "" {
		return errors.New("storeguard: empty store path")
	}
	parent := filepath.Dir(base)
	tmp, err := os.CreateTemp(parent, filepath.Base(base)+ImportPendingTempSuffix+"*")
	if err != nil {
		return fmt.Errorf("create import-pending marker: %w", err)
	}
	tmpName := tmp.Name()
	_, werr := fmt.Fprintf(tmp, "pid=%d ts=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmpName, base+ImportPendingSuffix)
	}
	if werr != nil {
		_ = fsys.remove(tmpName)
		return fmt.Errorf("write import-pending marker: %w", werr)
	}
	if err := fsys.syncDir(parent); err != nil {
		return fmt.Errorf("import-pending marker written but its directory could not be synced, so it may not survive a power loss: %w", err)
	}
	return nil
}

// importPending reports whether an import-pending marker is present. Only a
// regular file counts, for the same reason faultRecorded requires one: a
// directory at that path could never be cleared by os.Remove, and honouring it
// would quarantine a healthy store on every start.
func importPending(dir string) bool {
	base := trimSep(dir)
	if base == "" {
		return false
	}
	fi, err := os.Lstat(base + ImportPendingSuffix)
	return err == nil && fi.Mode().IsRegular()
}

// ClearImportPending removes the import-pending marker once the import it records
// has been certified complete (or the store it belonged to has been quarantined).
// The removal is fsynced for the same reason clearFault's is: an unlink that does
// not survive a power loss would leave the marker to quarantine a healthy store on
// the next start, and the one-copy prune would then delete the original evidence.
func ClearImportPending(dir string) error { return clearImportPending(dir, osMarkerFS) }

func clearImportPending(dir string, fsys markerFS) error {
	base := trimSep(dir)
	if base == "" {
		return nil
	}
	if err := fsys.remove(base + ImportPendingSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear import-pending marker: %w", err)
	}
	for _, tmp := range siblings(base, ImportPendingTempSuffix) {
		if fi, err := os.Lstat(tmp); err == nil && fi.Mode().IsRegular() {
			_ = fsys.remove(tmp)
		}
	}
	if err := fsys.syncDir(filepath.Dir(base)); err != nil {
		return fmt.Errorf("clear import-pending marker: sync directory: %w", err)
	}
	return nil
}
