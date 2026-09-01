package main

// logstore.go — package-main orchestration for the Badger-backed request-log
// history, whose engine moved to internal/logstore (ADR-0002). The package
// owns the store (key layout, async write loop, query/stats/retention, the
// priority-aware deletion passes, encryption-at-rest) and the dropped/pruned
// counters. main keeps the process-wide singleton and the enable/disable/
// purge lifecycle, the desired-retention memory, the dir/passphrase startup
// state, and the health/usage/estimate/retention views (they read main-side
// stats and the disk guard). The engine's two inversion points: the
// minimal-mode hook (logguard's state, injected at open) and RunRetention
// returning its results so the janitor in logguard records the audit event.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/logstore"
)

// logStore and LogEntry are re-exposed unqualified (engine types are
// logstore.Store / logstore.Entry).
type (
	logStore = logstore.Store
	LogEntry = logstore.Entry
	// DecryptionBlock is the nested "dec" observability block on a LogEntry
	// (ADR-0011); re-exposed unqualified for the recorder seam and callers.
	DecryptionBlock = logstore.DecryptionBlock
)

// errLogStoreEncMismatch is re-exposed for the retention API handler.
var errLogStoreEncMismatch = logstore.ErrEncMismatch

// logEntryLowPriority is re-exposed for logguard's minimal-mode path and its
// tests (engine func is logstore.LowPriority).
var logEntryLowPriority = logstore.LowPriority

// globalLogStore is the process-wide history store; nil-pointer when disabled.
// It is an atomic pointer so the request hot path reads it lock-free and the
// admin can enable/disable log saving at runtime by swapping the store safely.
var globalLogStore atomic.Pointer[logStore]

// logStoreDir is the on-disk location used when the admin enables log saving
// from the GUI (no path argument needed). Set once at startup from the data dir.
var logStoreDir string

// logStorePassphrase is set once at startup from the environment; empty =
// encryption off (saving still allowed, opt-in, with a UI warning).
var logStorePassphrase string

// logStoreEncryptionAvailable reports whether a passphrase is configured (so a
// newly created store would be encrypted).
func logStoreEncryptionAvailable() bool { return logStorePassphrase != "" }

// logStoreLastDays/GB remember the admin's chosen retention even while saving is
// OFF, so the UI and a later re-enable restore it. Guarded by logStoreCfgMu.
var (
	logStoreCfgMu    sync.Mutex
	logStoreLastDays int
	logStoreLastGB   float64
)

func setLogStoreDesired(days int, gb float64) {
	logStoreCfgMu.Lock()
	logStoreLastDays, logStoreLastGB = days, gb
	logStoreCfgMu.Unlock()
}

func getLogStoreDesired() (days int, gb float64) {
	logStoreCfgMu.Lock()
	defer logStoreCfgMu.Unlock()
	return logStoreLastDays, logStoreLastGB
}

// logStoreEnableMu serialises enable/disable lifecycle transitions so two
// concurrent admin requests can't race to open/close the store (e.g. a
// double-clicked toggle). Reads of globalLogStore stay lock-free (atomic).
var logStoreEnableMu sync.Mutex

// openLogStore opens (or creates) the history store, converting the admin's
// retention settings (days, GB) into the internal TTL/byte limits, deriving
// the encryption key from the configured passphrase, and wiring logguard's
// minimal-mode state as the engine's emergency hook.
//
// CHAOS-57: the open goes through logstore.OpenResilientTTL, never bare
// OpenTTL. A corrupt `.sst` makes badger.Open PANIC from a goroutine badger
// spawns, which no recover() here could contain — and this function is reached
// from the ADMIN API as well as from boot, so an unguarded open lets a damaged
// store kill a serving gateway from an HTTP handler, and lets the durable
// `LogStoreEnabled` setting replay that death into a crash loop. The guard
// quarantines a directory a previous process died inside of before badger is
// handed it again. The recovery is returned, not logged here: the caller owns
// the operator-facing surfaces.
func openLogStore(dir string, retentionDays int, maxGB float64) (store *logStore, recovery logstore.Recovery, err error) {
	var ttl time.Duration
	if retentionDays > 0 {
		ttl = time.Duration(retentionDays) * 24 * time.Hour
	}
	var maxBytes int64
	if maxGB > 0 {
		maxBytes = int64(maxGB * (1 << 30))
	}
	encKey, err := logstore.EncKey(dir, logStorePassphrase)
	if err != nil {
		return nil, logstore.Recovery{}, err
	}
	return logstore.OpenResilientTTL(dir, ttl, maxBytes, encKey, minimalMode)
}

// enableLogStore opens (or re-uses) the history store and publishes it as the
// global store, starting the size janitor under a per-store context so it stops
// when the store is disabled. If already enabled it just updates retention, so
// it is safe to call repeatedly (startup, admin settings load, API). The
// desired retention is recorded only after the operation succeeds.
func enableLogStore(ctx context.Context, dir string, days int, gb float64) error {
	logStoreEnableMu.Lock()
	defer logStoreEnableMu.Unlock()
	if ls := globalLogStore.Load(); ls != nil {
		ls.SetRetention(days, gb)
		setLogStoreDesired(days, gb)
		return nil
	}
	if dir == "" {
		return fmt.Errorf("log store path not configured")
	}
	ls, rec, err := openLogStore(dir, days, gb)
	// Record the outcome BEFORE the error branch: a recovery that was triggered
	// and then SKIPPED (a live lock holder, a rename that failed) is exactly the
	// state an operator has to see, and it is only reachable on the error path.
	noteLogStoreOpen(dir, rec, err)
	if err != nil {
		return err
	}
	jctx, cancel := context.WithCancel(ctx)
	ls.SetCancelJanitor(cancel)
	startLogStoreRetention(jctx, ls, time.Minute)
	globalLogStore.Store(ls)
	setLogStoreDesired(days, gb)
	return nil
}

// disableLogStore closes and unpublishes the store, KEEPING data on disk so a
// later re-enable resumes the same history. No-op when already disabled.
func disableLogStore() {
	logStoreEnableMu.Lock()
	defer logStoreEnableMu.Unlock()
	if old := globalLogStore.Swap(nil); old != nil {
		_ = old.Close()
	}
}

// purgeLogStore deletes all stored history. When saving is ON it drops the live
// store's keys; when OFF it removes the on-disk store + salt sidecar (so a
// changed encryption passphrase can take effect — the migration path). Held
// under the lifecycle mutex so it can't race enable/disable.
func purgeLogStore() error {
	logStoreEnableMu.Lock()
	defer logStoreEnableMu.Unlock()
	if ls := globalLogStore.Load(); ls != nil {
		return ls.PurgeAll()
	}
	if logStoreDir == "" {
		return nil
	}
	if err := os.RemoveAll(logStoreDir); err != nil {
		return err
	}
	_ = os.Remove(logStoreDir + ".salt") // regenerated on next enable
	return nil
}

// logStoreHealth reports CHEAP history-store usage for the frequently-polled
// dashboard health endpoint: only the atomic byte counter and drop/prune
// counters — NO Badger scan. The full count/oldest scan lives in
// logStoreUsage (called on demand by the retention panel) so an open dashboard
// doesn't trigger a large DB scan every tick.
func logStoreHealth() map[string]any {
	ls := globalLogStore.Load()
	if ls == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled": true,
		"bytes":   ls.BytesUsed(),
		"dropped": logstore.Dropped(),
		"pruned":  logstore.Pruned(),
	}
}

// logStoreUsage is the on-demand (retention panel) usage view: the cheap health
// fields plus the count/oldest scan from Stats. Not for high-frequency polling.
func logStoreUsage() map[string]any {
	u := logStoreHealth()
	ls := globalLogStore.Load()
	if ls == nil {
		return u
	}
	st := ls.Stats()
	u["count"] = st.Count
	u["capped"] = st.Capped
	u["oldestMs"] = st.OldestMs
	return u
}

// logStoreDiskEstimate projects how fast the history store would grow at the
// current traffic rate, so the admin can choose retention with eyes open. It is
// independent of whether saving is enabled (computed from the in-memory ring +
// per-minute request series), so it works on the "enable" screen too.
// bytesPerDay assumes every request is logged; rules with "Log traffic" off
// make it a conservative upper bound.
func logStoreDiskEstimate() map[string]any {
	avg := avgLogEntryBytes()
	series, _, _ := tsGet()
	var lastHour int64
	for _, v := range series {
		lastHour += v
	}
	perMin := float64(lastHour) / 60.0
	perDay := perMin * 60 * 24 * float64(avg)
	return map[string]any{
		"avgEntryBytes": avg,
		"reqPerMin":     perMin,
		"bytesPerDay":   int64(perDay),
		"bytesPerWeek":  int64(perDay * 7),
		"bytesPerMonth": int64(perDay * 30),
	}
}

// avgLogEntryBytes samples the in-memory ring to estimate the serialized size of
// one log entry. Falls back to a typical size when the ring is empty.
func avgLogEntryBytes() int64 {
	const fallback = 350
	entries := logGet()
	if len(entries) == 0 {
		return fallback
	}
	n := len(entries)
	if n > 50 {
		n = 50
	}
	var total int64
	for i := 0; i < n; i++ {
		if b, err := json.Marshal(entries[i]); err == nil {
			total += int64(len(b)) + 1 // +1 for the newline JSONL adds
		}
	}
	if total == 0 {
		return fallback
	}
	return total / int64(n)
}

// logStoreRetentionView is the GET /api/logs/retention payload: the current
// retention policy plus full (on-demand) usage stats.
func logStoreRetentionView() map[string]any {
	ls := globalLogStore.Load()
	if ls == nil {
		days, gb := getLogStoreDesired() // remembered across disable/restart
		return map[string]any{
			"enabled":             false,
			"configurable":        logStoreDir != "", // can it be enabled from the GUI?
			"retentionDays":       days,
			"retentionMaxGB":      gb,
			"encrypted":           false,
			"encryptionAvailable": logStoreEncryptionAvailable(),
			"usage":               logStoreUsage(),
			"estimate":            logStoreDiskEstimate(),
			"guard":               diskGuardStatus(),
		}
	}
	return map[string]any{
		"enabled":             true,
		"configurable":        true,
		"retentionDays":       ls.RetentionDays(),
		"retentionMaxGB":      ls.RetentionMaxGB(),
		"encrypted":           ls.Encrypted(),
		"encryptionAvailable": logStoreEncryptionAvailable(),
		"usage":               logStoreUsage(),
		"estimate":            logStoreDiskEstimate(),
		"guard":               diskGuardStatus(),
	}
}

// startLogStoreRetention runs the disk-protection + size janitor every interval
// until ctx is cancelled (graceful shutdown). Each tick enforces disk
// protection (overrides retention near the critical threshold) and the size cap.
func startLogStoreRetention(ctx context.Context, s *logStore, interval time.Duration) {
	if s == nil || ctx == nil {
		return // nil ctx would panic on <-ctx.Done(); guard defensively
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// CHAOS-24: contain the ROUND. This janitor is the only thing
				// enforcing the size cap and the disk-protection threshold, so
				// a dead loop fills the volume — which then takes down every
				// other durable writer on the box.
				runGuarded("logstore_retention", func() { runDiskGuard(s) })
			}
		}
	}()
}
