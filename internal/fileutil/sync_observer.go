package fileutil

import "sync/atomic"

// syncObserver is a TEST-ONLY observability seam for durability
// synchronisation: every fsync this package performs on a file or a
// directory reports (kind, path) here, so a test can prove that a "durable"
// acknowledgement was preceded by the synchronisation it claims. It carries
// no behaviour of its own — nil means nobody is listening.
var syncObserver atomic.Pointer[func(kind, path string)]

// SetSyncObserverForTest installs fn as the synchronisation observer and
// returns a restore func. kind is "file", "dir", "atomic-file" or
// "atomic-dir" (see SetSyncHookForTest).
func SetSyncObserverForTest(fn func(kind, path string)) (restore func()) {
	var old *func(kind, path string)
	if fn == nil {
		old = syncObserver.Swap(nil)
	} else {
		old = syncObserver.Swap(&fn)
	}
	return func() { syncObserver.Store(old) }
}

// noteSync reports one completed synchronisation to the observer.
func noteSync(kind, path string) {
	if p := syncObserver.Load(); p != nil {
		(*p)(kind, path)
	}
}

// syncHook is a TEST-ONLY scheduling + fault seam consulted BEFORE a
// synchronisation step runs (round 6): it lets a test park a goroutine at
// the exact point between "the record was found" and "it is synchronised",
// or make one synchronisation kind fail (a directory fsync error after a
// rotation, say). A non-nil error aborts that synchronisation with the
// error. Behaviour-neutral when unset — nil means the step runs untouched.
var syncHook atomic.Pointer[func(kind, path string) error]

// SetSyncHookForTest installs fn and returns a restore func. kind is the
// synchronisation about to run: "file", "dir", "path" (SyncPath, before
// the path is examined), "atomic-file" (AtomicWrite's temp-file fsync, path
// = the temp file — a failure lands BEFORE the rename) or "atomic-dir"
// (AtomicWrite's post-rename parent-directory fsync, path = the TARGET —
// a failure is ErrReplacedNotSynced).
func SetSyncHookForTest(fn func(kind, path string) error) (restore func()) {
	var old *func(kind, path string) error
	if fn == nil {
		old = syncHook.Swap(nil)
	} else {
		old = syncHook.Swap(&fn)
	}
	return func() { syncHook.Store(old) }
}

// beforeSync consults the hook; nil when unset.
func beforeSync(kind, path string) error {
	if p := syncHook.Load(); p != nil {
		return (*p)(kind, path)
	}
	return nil
}
