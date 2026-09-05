package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// CHAOS-58 — the admin login endpoint's attacker-controlled username
//
// POST /api/auth/login is on uiAuthMiddleware's PUBLIC allowlist: no session,
// no credential, no cluster membership. Every failed attempt copied the caller's
// chosen username VERBATIM into three places that outlive the request:
//
//  1. two lockout maps (internal/lockout: the tier-1 (ip, user) pair key and the
//     tier-2 account key), where the janitor cannot remove the entry until its
//     Window has elapsed;
//  2. the 500-entry in-memory audit ring;
//  3. the DURABLE audit JSONL — a fileutil.RotatingFile capped at 50 MB that
//     keeps exactly ONE archive, so the whole retained compliance record is
//     100 MB.
//
// Nothing bounded the username. The only limits in front of the handler are
// securityMiddleware's 1 MiB body cap and the 60-mutating-POSTs-per-minute
// per-IP API rate limit, which together admit ~60 MiB/minute of attacker-chosen
// bytes from ONE unauthenticated client. That is not a slow leak:
//
//   - the durable audit trail rotates twice and is GONE in under two minutes,
//     which is exactly the outcome internal/audit's own header calls out as the
//     thing the write-error counter exists to make visible (CWE-778,
//     OWASP A09:2021) — reached here with no disk fault and no credentials, and
//     the counter never fires because every one of these writes SUCCEEDS;
//   - the lockout maps hold ~2 MiB per attempt for at least lockout.Window
//     (10 min), so a single source parks on the order of a gigabyte of heap in
//     an in-line gateway whose OOM is a total traffic outage.
//
// The fix is a bound at the entry point, mirrored structurally in the leaf
// (lockout.MaxUsernameKeyLen) so no future caller can reintroduce it. The
// attempt is still AUDITED — a credential attack belongs in the record — but
// with a truncated actor, so the entry costs O(1) bytes instead of O(body).
//
// Deliberately NOT done here:
//
//   - No new lockout tier for oversize input. The existing 60/min per-IP API
//     limiter already bounds the attempt rate, and an oversize name can never
//     match a local account, so this path is not a credential-guessing channel
//     that a lock would have to close.
//   - No truncation inside internal/audit. The audit sink cannot tell attacker
//     bytes from a legitimate auditEventDiff before/after payload (whole policy
//     objects are marshalled into those fields on purpose), so a byte cap there
//     would destroy real compliance evidence to fix an input-validation defect.
//     The bound belongs where the untrusted value enters.
// ---------------------------------------------------------------------------

// loginOversizeRejected counts login attempts refused for an over-long
// username. Exported on /metrics as culvert_login_oversize_rejected_total: the
// rejection is otherwise invisible to an operator (the caller gets a 400 and
// nothing else changes), and a climbing counter is the signal that an
// unauthenticated source is probing the admin login endpoint.
var loginOversizeRejected atomic.Int64

// loginOversizeLogGate rate-limits the log line to one per window. The whole
// point of the bound is that a flood must not cost log bandwidth, so the flood
// itself must not be logged per attempt — onset is logged immediately, then at
// most one line per loginOversizeLogWindow. Magnitude lives in the counter.
var (
	loginOversizeLogMu   sync.Mutex
	loginOversizeLogLast time.Time
)

const loginOversizeLogWindow = time.Minute

// loginAuditActorMax bounds the username echoed into the audit entry for a
// rejected attempt. Short enough that a sustained flood cannot meaningfully
// consume the durable record, long enough that an operator can still recognise
// a probe pattern (e.g. a repeated payload prefix).
const loginAuditActorMax = 64

// truncateForAudit clamps s to loginAuditActorMax bytes on a UTF-8 rune
// boundary, appending a marker naming the original length so a reader can never
// mistake a truncated value for the value that was actually sent.
func truncateForAudit(s string) string {
	if len(s) <= loginAuditActorMax {
		return s
	}
	// Same bounded rune-boundary search as lockout.boundUsername: a rune is at
	// most 4 bytes, and falling back to the raw cut for input that is not valid
	// UTF-8 keeps the result bounded and deterministic.
	cut := loginAuditActorMax
	for i := 0; i < 4 && cut > 0; i++ {
		if utf8.RuneStart(s[cut]) {
			break
		}
		cut--
	}
	if cut == 0 || !utf8.RuneStart(s[cut]) {
		cut = loginAuditActorMax
	}
	return fmt.Sprintf("%s…[truncated, %d bytes]", s[:cut], len(s))
}

// rejectOversizeLoginUser refuses a login whose username exceeds
// maxUsernameLen, and reports true when it has written the response.
//
// It runs BEFORE loginLimiter.Check and before any credential verification:
// the whole exposure is that the untrusted value reaches durable state, so the
// guard has to sit in front of every store that would retain it. A rejected
// attempt therefore creates NO limiter entry and leaves NO attacker-sized
// bytes anywhere.
//
// A CONFIGURED account is never refused, however long its name.
// apiSetupComplete and the user-creation API cap a username at 64 characters,
// but they are not the only creation paths: `-user` / `auth.user` reach
// cfg.SetAuth and `--reset-password` reaches cfg.SetUIUser, and NEITHER the
// stores nor validateAuthStartupCredentials (which validates only the
// password) bound the name. So an over-long username can already be a valid,
// persisted admin, and refusing it here would lock that operator out of the
// admin UI on upgrade — turning a hardening change into an outage for the one
// person who has to fix it. The guard therefore refuses only a name that names
// NOTHING, which is the whole attack: the amplification comes from an
// unbounded value an attacker invents, not from one the operator configured
// (whose length is bounded by their own config, not by the 1 MiB body cap).
// Raised by Codex review on PR #1320, against exactly the claim this comment
// used to make.
//
// The narrow cost is that, for names past the bound only, a 400 rather than a
// 401 says "no such account" — and an attacker must already guess the exact
// over-long name to learn anything from it. That is a far better trade than
// refusing a real admin's login.
//
// 400 is deliberate over 401 for a name that exists nowhere: the length of a
// submitted username is not a secret, so saying so tells an honest client what
// to fix.
func rejectOversizeLoginUser(w http.ResponseWriter, r *http.Request, user string) bool {
	if len(user) <= maxUsernameLen {
		return false
	}
	// Non-retaining probe: a map hash and compare, nothing stored. Must run
	// BEFORE the rejection and must mirror VerifyUIUser's own name resolution
	// (roster or legacy single user) — see Config.LoginNameConfigured.
	if cfg.LoginNameConfigured(user) {
		return false
	}
	loginOversizeRejected.Add(1)

	// One audit entry per attempt, with a bounded actor: the attempt is
	// evidence of a probe against the admin plane and belongs in the record.
	// The entry is O(1) bytes, so this adds no eviction capacity beyond the
	// ordinary auth.login.fail entry the same request would otherwise have
	// produced at the same rate.
	auditEvent(r, "auth.login.rejected", truncateForAudit(user),
		fmt.Sprintf("username %d bytes exceeds the %d-byte limit — rejected before lockout/credential evaluation",
			len(user), maxUsernameLen))

	if noteLoginOversizeLog() {
		logWarnf("Auth: rejected login with oversized username from %s (%d bytes, limit %d); %d rejected since boot",
			sanitizeLog(realClientIP(r)), len(user), maxUsernameLen, loginOversizeRejected.Load())
	}

	http.Error(w, fmt.Sprintf("username must be at most %d bytes", maxUsernameLen), http.StatusBadRequest)
	return true
}

// noteLoginOversizeLog reports whether this rejection may emit a log line,
// arming the window when it does.
func noteLoginOversizeLog() bool {
	now := time.Now()
	loginOversizeLogMu.Lock()
	defer loginOversizeLogMu.Unlock()
	if !loginOversizeLogLast.IsZero() && now.Sub(loginOversizeLogLast) < loginOversizeLogWindow {
		return false
	}
	loginOversizeLogLast = now
	return true
}

// resetLoginOversizeStateForTest clears the process-global counter and log gate
// so tests do not inherit each other's state. Production never calls it.
func resetLoginOversizeStateForTest() {
	loginOversizeRejected.Store(0)
	loginOversizeLogMu.Lock()
	loginOversizeLogLast = time.Time{}
	loginOversizeLogMu.Unlock()
}
