package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// Debug capture-level controller (M3). An operator can elevate the DEFAULT bundle
// capture depth (L0..L4) for a BOUNDED window so a deeper bundle can be collected
// while reproducing an incident, without leaving verbose capture on forever. Two
// safety invariants are non-negotiable:
//
//  1. Mandatory TTL. A level can NEVER be set without a positive, bounded TTL
//     (floored and hard-capped) — a forgotten elevation cannot persist.
//  2. Restart-surviving auto-revert. The EFFECTIVE level is computed from the
//     PERSISTED expiry at read time, never from an in-memory timer alone, so a
//     process that crashes/restarts mid-window still reverts to baseline the moment
//     the wall clock passes expires_at. The watchdog is only an ACTIVE cleaner +
//     auditor of that same on-disk state; correctness does not depend on it running.
//
// This governs only what a bundle CAPTURES (the level gate in the runner). It never
// mutates live proxy tracing or any hot path — a stale/corrupt state file fails
// closed to baseline, so it can only ever REDUCE capture, never widen exposure.

const (
	debugLevelBaseline = support.L1       // the un-elevated default capture depth
	debugLevelMinTTL   = 1 * time.Minute  // a meaningful floor; sub-minute windows are pointless
	debugLevelMaxTTL   = 24 * time.Hour   // hard cap: a forgotten elevation cannot outlive a day
	debugLevelTick     = 30 * time.Second // watchdog cadence
)

var errDebugTTL = errors.New("debug level requires a positive TTL within bounds")

// debugLevelState is the persisted elevation. Absent/zero ⇒ baseline.
type debugLevelState struct {
	Level     int    `json:"level"`      // elevated DebugLevel (0..4)
	ExpiresAt string `json:"expires_at"` // RFC3339 UTC; a past or unparseable value ⇒ reverted
	SetBy     string `json:"set_by,omitempty"`
	SetAt     string `json:"set_at,omitempty"`
}

var debugLevelMu sync.Mutex

func debugLevelStatePath() string { return filepath.Join(dataDir, "support", "debug_level.json") }

// readDebugLevelStateLocked reads the persisted elevation. Caller holds debugLevelMu.
// Absent or corrupt ⇒ zero state (baseline) — fail-closed: unreadable state must
// never grant an elevated capture level.
func readDebugLevelStateLocked() debugLevelState {
	b, err := os.ReadFile(debugLevelStatePath())
	if err != nil {
		return debugLevelState{}
	}
	var st debugLevelState
	if json.Unmarshal(b, &st) != nil {
		return debugLevelState{}
	}
	return st
}

// effectiveDebugLevel returns the capture level in force at now: the persisted
// elevation if it is present, in-range, and unexpired; otherwise the baseline.
func effectiveDebugLevel(now time.Time) support.DebugLevel {
	debugLevelMu.Lock()
	st := readDebugLevelStateLocked()
	debugLevelMu.Unlock()

	if st.ExpiresAt == "" {
		return debugLevelBaseline
	}
	exp, err := time.Parse(time.RFC3339, st.ExpiresAt)
	if err != nil || !now.Before(exp) { // unparseable or now >= expiry ⇒ reverted
		return debugLevelBaseline
	}
	if st.Level < int(support.L0) || st.Level > int(support.L4) {
		return debugLevelBaseline // out-of-range persisted value ⇒ fail closed
	}
	return support.DebugLevel(st.Level)
}

// currentDebugLevel is the wall-clock convenience wrapper used by request handlers.
func currentDebugLevel() support.DebugLevel { return effectiveDebugLevel(time.Now()) }

// setDebugLevel persists an elevated capture level for [now, now+ttl]. It enforces
// the mandatory-TTL invariant: ttl must be within [min,max] or it is refused with
// errDebugTTL — there is no code path that elevates without a bounded expiry.
func setDebugLevel(level support.DebugLevel, ttl time.Duration, actor string, now time.Time) (time.Time, error) {
	if level < support.L0 || level > support.L4 {
		return time.Time{}, errors.New("debug level out of range (0..4)")
	}
	if ttl < debugLevelMinTTL || ttl > debugLevelMaxTTL {
		return time.Time{}, errDebugTTL
	}
	exp := now.Add(ttl).UTC()
	st := debugLevelState{
		Level:     int(level),
		ExpiresAt: exp.Format(time.RFC3339),
		SetBy:     actor,
		SetAt:     now.UTC().Format(time.RFC3339),
	}
	debugLevelMu.Lock()
	defer debugLevelMu.Unlock()
	if err := writeDebugLevelStateLocked(st); err != nil {
		return time.Time{}, err
	}
	return exp, nil
}

// clearDebugLevel removes any elevation, reverting to baseline immediately.
func clearDebugLevel() error {
	debugLevelMu.Lock()
	defer debugLevelMu.Unlock()
	err := os.Remove(debugLevelStatePath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// writeDebugLevelStateLocked persists atomically via tmp+rename. Caller holds the mutex.
func writeDebugLevelStateLocked(st debugLevelState) error {
	dir := filepath.Dir(debugLevelStatePath())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := debugLevelStatePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, debugLevelStatePath())
}

// debugLevelWatchdogTick clears an expired elevation and reports whether it did so,
// so the loop can audit the auto-stop exactly once. A non-expired or absent state
// is left untouched.
func debugLevelWatchdogTick(now time.Time) (expired bool, level int) {
	debugLevelMu.Lock()
	defer debugLevelMu.Unlock()
	st := readDebugLevelStateLocked()
	if st.ExpiresAt == "" {
		return false, 0
	}
	exp, err := time.Parse(time.RFC3339, st.ExpiresAt)
	if err == nil && now.Before(exp) {
		return false, 0 // still within the window
	}
	// Expired or unparseable — remove the stale file (revert to baseline).
	if rmErr := os.Remove(debugLevelStatePath()); rmErr != nil && !os.IsNotExist(rmErr) {
		logger.Printf("support: debug-level watchdog could not clear expired state: %v", rmErr)
		return false, 0
	}
	return true, st.Level
}

// startDebugLevelWatchdog is the ACTIVE auto-stop: it periodically clears an
// expired elevation and emits a single audit/log line so operators see the revert
// even when no bundle is created in the meantime. Correctness (revert-on-read,
// restart survival) does NOT depend on it — it only makes the transition visible
// and reclaims the file. Parented to ctx; exits on shutdown.
func startDebugLevelWatchdog(ctx context.Context) {
	t := time.NewTicker(debugLevelTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if expired, lvl := debugLevelWatchdogTick(now); expired {
				logger.Printf("support: debug capture level auto-reverted from L%d to baseline L%d (TTL expired)", lvl, int(debugLevelBaseline))
				auditSystem("support.debug_level.auto_revert", "debug-level", "TTL expired; capture level reverted to baseline")
			}
		}
	}
}
