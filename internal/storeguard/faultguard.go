package storeguard

// faultguard.go — CHAOS-74: containing a memory fault raised by a store's
// memory-mapped file AFTER a healthy open.
//
// # WHY THIS EXISTS
//
// `storeguard.Open` covers the boot path: it refuses to hand badger a directory
// a previous process died inside of. It cannot cover what happens once the
// store is open and serving, and that window has a failure mode with the same
// uncatchable shape and a much larger blast radius.
//
// badger v4 reads an `.sst` table through a memory mapping — `table.Table`
// embeds `*z.MmapFile`, and the table index is decoded straight out of the
// mapped region (`fb.TableIndex.BloomFilterBytes` ← `table.DoesNotHave`). v4
// removed the loading-mode option that earlier versions used to offer, so there
// is no configuration that reads tables through ordinary file I/O instead. The
// mapping is therefore not optional for any badger-backed store in the tree.
//
// Touching a page of a mapping whose backing file can no longer supply it
// raises SIGBUS. The Go runtime turns that into `fatal error: fault`, which is
// NOT a panic: `recover()` cannot see it, `crashguard.go` cannot see it, and no
// log line survives it. The process dies. That is the same shape §34.7 (GEO-1)
// recorded for the GeoIP reader and called the worst failure shape in the
// register, because containment is not available at all — but GEO-1 was
// recorded rather than fixed precisely because it had no reachable caller.
// This one is reached from the proxy data path on every request that resolves a
// host category (`policy_hostcat.go` → `catdb.Lookup`).
//
// # THE REMEDY, AND WHY IT IS AVAILABLE AT ALL
//
// `runtime/debug.SetPanicOnFault` changes exactly this: with it armed, a fault
// on non-Go memory — which is what a mapped file region is — is delivered as a
// RECOVERABLE panic on the faulting goroutine instead of killing the process.
// It is per-goroutine state, so it must be armed on the goroutine that performs
// the read, and restored afterwards so a caller's own setting is preserved.
//
// Measured against the real store (see `internal/catdb/catdb_fault_test.go`):
// truncating the `.sst` under an open, healthy store turns the next cold-key
// lookup into `fatal error: fault` without this guard, and into a contained
// error with it.
//
// # WHAT THIS DOES NOT FIX
//
// `SetPanicOnFault` is per-goroutine, so it protects the goroutines that run
// through this helper and nothing else. badger's own background compaction
// goroutines touch the same mappings and remain exposed: a damaged table that
// a compactor reaches first still kills the process. This helper therefore
// converts the data path's exposure — the reachable one, on every request —
// into a visible degradation; it does not make a badger store on a failing
// volume safe in general. That residual is recorded in the register rather
// than papered over here.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// ErrStoreFault reports that a memory fault raised by the store's mapped file
// was contained. It is deliberately distinct from any error badger returns:
// a returned error means badger was able to describe what went wrong, while
// this means the mapping itself could not be read and the store must be
// treated as unusable from here on.
var ErrStoreFault = errors.New("storeguard: memory fault reading the store's mapped file")

// ContainFault runs op with memory-fault containment armed on the calling
// goroutine, converting a fault on the store's mapped file into an error that
// wraps ErrStoreFault instead of a process-killing `fatal error: fault`.
//
// The previous SetPanicOnFault setting is restored before returning, so nesting
// this inside a caller that has its own setting does not change that caller's
// behavior.
//
// Only memory faults are converted. An ordinary panic raised by op — including a
// genuine nil-pointer dereference, which is a BUG and not disk damage — is NOT
// swallowed: it is re-panicked so it keeps reaching the existing crashguard
// machinery instead of being quietly reported as a failing volume.
//
// Telling those two apart matters and is not guesswork. Both arrive carrying the
// text "invalid memory address or nil pointer dereference", so the message is
// useless as a discriminator. The runtime attaches an `Addr() uintptr` method
// ONLY to the error it synthesises for a SetPanicOnFault-converted fault
// (`runtime.errorAddressString`), which is the documented way to recover the
// faulting address; a nil dereference panics with a plain runtime error that has
// no such method. Measured both ways in `faultguard_test.go`:
// a nil dereference reports hasAddr=false, and truncating a live `.sst` under an
// open store reports hasAddr=true with the mapped address.
func ContainFault(op func() error) (err error) {
	prev := debug.SetPanicOnFault(true)
	defer func() {
		debug.SetPanicOnFault(prev)
		r := recover()
		if r == nil {
			return
		}
		// Addr() is present only on a converted memory fault (see above).
		if fault, ok := r.(interface{ Addr() uintptr }); ok {
			err = fmt.Errorf("%w at 0x%x: %v", ErrStoreFault, fault.Addr(), r)
			return
		}
		panic(r)
	}()
	return op()
}

// IsStoreFault reports whether err came from a contained memory fault.
func IsStoreFault(err error) bool { return errors.Is(err, ErrStoreFault) }

// ── persisting a contained fault for the next open ───────────────────────────
//
// Containment keeps the process alive, but the in-memory latch dies with it —
// and a restart is exactly what the operator is told to do. Without a durable
// record that restart cannot tell a faulted store from a healthy one: for the
// truncation case badger's reopen returns `invalid argument ... while mmapping
// ... with size: 0`, which is not in the corruption table, and openGuarded
// clears its attempt marker on any returned error. Every later start would then
// stay degraded rather than rebuild. Widening the table would only cover that
// one shape (a table truncated to exactly zero); a partial truncation, an EIO
// page or a vanished volume reports differently on reopen, or not at all until
// a later read. The process that contained the fault is the only one holding the
// evidence, so it records it. The fault marker is that record: written once, at
// the moment the fault is contained, and honoured by Open as a quarantine
// trigger.

// FaultMarkerSuffix names the fault marker beside the store directory. Like the
// open-attempt markers it is a sibling, not a file inside the store, so moving
// the store aside never moves the evidence that justified it.
const (
	FaultMarkerSuffix     = ".faulted"
	FaultMarkerTempSuffix = ".faultedtmp."
)

// RecordFault durably records that the store at dir took a contained memory
// fault, so the next Open quarantines it instead of handing badger the same
// damaged tables. The write is atomic (temp file, fsync, rename, directory
// fsync), so a crash mid-write leaves either no marker or a complete one.
//
// Only a store whose contents are rebuildable should call this: Open treats the
// marker as sufficient grounds to move the directory aside (still gated by the
// store lock, and never a deletion). Best-effort by contract — the error is for
// the caller's log line; a volume damaged enough to fault may refuse the write.
func RecordFault(dir, cause string) error {
	base := trimSep(dir)
	if base == "" {
		return errors.New("storeguard: empty store path")
	}
	parent := filepath.Dir(base)
	tmp, err := os.CreateTemp(parent, filepath.Base(base)+FaultMarkerTempSuffix+"*")
	if err != nil {
		return fmt.Errorf("create fault marker: %w", err)
	}
	tmpName := tmp.Name()
	_, werr := fmt.Fprintf(tmp, "pid=%d ts=%s cause=%q\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano), cause)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmpName, base+FaultMarkerSuffix)
	}
	if werr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write fault marker: %w", werr)
	}
	syncDir(parent)
	return nil
}

// faultRecorded reports whether a fault marker is present. Only a regular file
// counts: a directory at that path could never be cleared by os.Remove, and
// honouring it would quarantine a healthy store on every start.
func faultRecorded(dir string) bool {
	base := trimSep(dir)
	if base == "" {
		return false
	}
	fi, err := os.Lstat(base + FaultMarkerSuffix)
	return err == nil && fi.Mode().IsRegular()
}

// clearFault removes the fault marker once the condition it records has been
// resolved, together with any temp file a death mid-write left behind (litter,
// not a signal). Called only after the damaged directory is gone, so no live
// writer can still be producing either file.
func clearFault(dir string) {
	base := trimSep(dir)
	if base == "" {
		return
	}
	_ = os.Remove(base + FaultMarkerSuffix)
	for _, tmp := range siblings(base, FaultMarkerTempSuffix) {
		if fi, err := os.Lstat(tmp); err == nil && fi.Mode().IsRegular() {
			_ = os.Remove(tmp)
		}
	}
	syncDir(filepath.Dir(base))
}
