package main

// setup_bootstrap_window.go — CHAOS-103: the first-run bootstrap window is
// decided by the DURABLE roster, not by one process's in-memory latch.
//
// # WHAT WAS WRONG
//
// `uiAuthMiddleware` grants unauthenticated RoleAdmin to every request while
// `cfg.IsConfigured()` is false, which is the documented first-run bootstrap: a
// brand-new install has to be reachable before an admin account exists.
// `IsConfigured()` reads in-memory state (`store.go`), populated once, at boot,
// by `LoadUIUsersFile`.
//
// Per process. So a SECOND process opened against the same `/data` before the
// operator ran the wizard keeps that window open for its whole life: it answers
// `needsSetup:true` after the real gateway is configured, `POST
// /api/setup/complete` on it replaces the roster file wholesale, and every other
// admin API on it — policy writes, roster writes, the config-version series —
// is reachable with no credentials and lands on the live gateway's volume.
// Measured end to end on a build of main: the operator's admin account was
// erased from `ui_users.json`, an unauthenticated `POST /api/policy` installed
// an Allow + SSL-Bypass rule, and both became the gateway's enforced state at
// its next ordinary restart (CHAOS-ENGINEERING-REVIEW-2026-10-28.md §2, SW-1).
//
// `datadir_writer_lock.go` stops that second process from booting at all, which
// is the class fix. This file is the one that holds where the lock cannot: a
// platform or filesystem that does not report lock state degrades by design, and
// an unauthenticated RoleAdmin grant is not something to leave resting on a
// single mechanism.
//
// # THE RULE
//
// The window is open only while NO durable record of a completed setup exists.
// `IsConfigured()` stays the fast path; when it says "not configured", the
// roster FILE is asked before anyone is granted authority. The derivation below
// mirrors `loadUIUsersFile`'s acceptance exactly — including the hex-hash check
// that makes it skip a record, and the role clamp that decides whether a record
// configures anything — so that it can only ever CLOSE a window the loader would
// have left open, never open one the loader would have closed. That direction is
// the safety property, and `setup_bootstrap_window_test.go` holds it as a
// differential oracle against the real loader rather than as a restatement.
//
// It is quiet on purpose: this runs on an admin request, so it must not reach
// the loader's logging, quarantine or counter side effects. It never writes.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sync/atomic"
)

// durableSetupAnchorSeen latches the first observation of a durable completed
// setup. The latch only ever moves from open to closed, which is the direction
// that removes authority, and it keeps the file read off the admin path for the
// rest of the process's life once setup is genuinely done.
var durableSetupAnchorSeen atomic.Bool

// bootstrapWindowOpen reports whether the unauthenticated first-run bootstrap
// window is open for this request. Every gate that used to ask
// `!cfg.IsConfigured()` asks this instead.
func bootstrapWindowOpen() bool {
	if cfg.IsConfigured() {
		return false
	}
	return !durableSetupComplete()
}

// durableSetupComplete reports whether the configured roster file already
// records a completed first-run setup. False whenever that cannot be
// established — no configured path, an absent, unreadable or corrupt file, or a
// roster that would not have configured a process that loaded it.
func durableSetupComplete() bool {
	if durableSetupAnchorSeen.Load() {
		return true
	}
	path, _ := cfg.rosterPersistTarget()
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the operator-configured -ui-users-file path, read-only
	if err != nil {
		return false
	}
	if !rosterBytesConfigure(data) {
		return false
	}
	durableSetupAnchorSeen.Store(true)
	return true
}

// rosterBytesConfigure reports whether a roster file's bytes would have made
// cfg.IsConfigured() true in a process that loaded them.
//
// Both acceptance terms mirror the loader:
//
//   - the envelope form wins when it parses AND carries a non-nil `users` key,
//     exactly as loadUIUsersFile decides it; otherwise the bare-array legacy
//     form is tried. A file that satisfies neither is corrupt, and a corrupt
//     roster leaves the wizard open today (CHAOS-05 quarantines and keeps
//     going) — so it must leave it open here too.
//   - a record configures nothing unless its hash decodes as hex, which is the
//     loader's own admission test: it `continue`s past a record whose hash does
//     not, and admits every record that does to `c.uiUsers`.
//
// Any ADMITTED record anchors setup, whatever its role. This mirrors
// IsConfigured's len(c.uiUsers) term (SEC-SETUPANCHOR-1): an earlier form of
// this function asked whether a record's EFFECTIVE role — after the loader's
// least-privilege clamp — was admin, which made the durable backstop agree with
// the in-memory predicate precisely where that predicate was wrong, and left
// the first-run window open on a roster that plainly recorded a completed
// setup. A restored backup whose only admin carries a role this build does not
// enroll (clamped to RoleViewer), or a legacy pre-RBAC roster with an empty
// role, is a lockout for --reset-password to repair, not grounds to grant
// unauthenticated RoleAdmin. The role term is therefore gone rather than
// relaxed, and the username term with it: the loader keys `c.uiUsers` by
// whatever username a record carries, including the empty string, so requiring
// a non-empty one here would have been a divergence in the direction that
// leaves the window OPEN.
//
// The durable `default_auth_outcome` is the second anchor, because open mode
// ("unauth") completes setup without creating any account at all. It is resolved
// here rather than through resolveLoadedDefaultAuthOutcome because that function
// logs, and this one runs per request.
func rosterBytesConfigure(data []byte) bool {
	var env uiUsersFileEnvelope
	var records []uiUserRecord
	if err := json.Unmarshal(data, &env); err == nil && env.Users != nil {
		records = env.Users
	} else if err := json.Unmarshal(data, &records); err != nil {
		return false
	}
	if envelopeDeclaresExempt(env) {
		return true
	}
	for i := range records {
		if _, err := hex.DecodeString(records[i].PassHash); err != nil {
			continue // the loader skips this record entirely
		}
		return true // the loader admitted it, so this roster records a setup
	}
	return false
}

// envelopeDeclaresExempt is resolveLoadedDefaultAuthOutcome's Exempt verdict
// without its logging. Present-but-non-canonical fails closed to Default and
// does NOT consult the legacy mirror, which is the whole point of that
// function's pointer field — an empty value must never reopen the window, and
// here it must never close it on a value the loader would have rejected.
func envelopeDeclaresExempt(env uiUsersFileEnvelope) bool {
	if env.DefaultAuthOutcome != nil {
		outcome, ok := normalizeDefaultAuthOutcome(*env.DefaultAuthOutcome)
		return ok && outcome == OutcomeExempt
	}
	return env.UnauthMode
}

// resetDurableSetupAnchorForTest re-opens the latch between tests. Test
// isolation only.
func resetDurableSetupAnchorForTest() { durableSetupAnchorSeen.Store(false) }
