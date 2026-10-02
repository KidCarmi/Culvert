package main

// SEC-REAUTH-AUDIT-1 — a FAILED re-authentication on the admin plane must be
// audited.
//
// POST /api/auth/change-password re-verifies the caller's CURRENT password
// before accepting a new one. That check is a genuine security control (it is
// what stops a stolen session from silently rotating the account's credential),
// and it is the ONLY credential check in the admin API that consults no
// lockout — a trade TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller
// records deliberately, because charging loginLimiter here would let a session
// holder lock themselves out of the login flow.
//
// What was NOT deliberate is that it also left no EVIDENCE. Every sibling
// credential rejection in ui_auth.go audits — auth.login.fail on the login
// handler, auth.basic.fail in the Basic chokepoint — and this one audited only
// on SUCCESS. So the single unlocked password oracle in the admin API was also
// the single silent one: a caller holding a stolen or hijacked session could
// guess the account's password at the mutating apiLimiter's rate, indefinitely,
// and the operator had no signal at all. The password matters even to an
// attacker who already holds the session, because it is durable persistence
// that outlives the session being revoked and may be reused elsewhere.
// CWE-778 / OWASP A09:2021.
//
// This file pins the EVIDENCE only. It deliberately does NOT assert a lockout
// or a rate limit, so it cannot drift into pinning a posture change the
// recorded trade-off rejects.
//
// Every defect gate below was verified FAILING against the reintroduced
// pre-fix shape (the 403 branch with no auditEvent call).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// reauthReq builds a change-password POST authenticated as user from a unique
// TEST-NET-2 client address, so the audit scan below cannot collide with an
// entry written by another test under -count=2 -shuffle=on.
func reauthReq(t *testing.T, user, clientIP string, body map[string]any) *http.Request {
	t.Helper()
	r := jsonReq(http.MethodPost, "/api/auth/change-password", body)
	r.RemoteAddr = clientIP + ":9999"
	return r.WithContext(context.WithValue(r.Context(), uiUserKey{}, user))
}

// reauthActor mirrors auditActor's composition for a session-identified caller.
func reauthActor(user, clientIP string) string { return user + "@" + clientIP }

// TestSecReauthAudit1_FailedCurrentPasswordIsAudited is the primary defect
// gate.
func TestSecReauthAudit1_FailedCurrentPasswordIsAudited(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	const clientIP = "198.51.100.71"
	baselineTS := time.Now().UnixMilli()

	r := reauthReq(t, "doomed", clientIP, map[string]any{
		"current_password": "not-the-password",
		"new_password":     "Rotat3dSecret9",
	})
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong current password: got %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if !hasMatchingAuditEntry(auditGet(), reauthActor("doomed", clientIP),
		"auth.password_change.fail", "doomed", baselineTS) {
		t.Errorf("a rejected re-authentication wrote NO audit entry (want Action=auth.password_change.fail "+
			"Actor=%s Object=doomed TS>=%d): the only admin-plane credential check with no lockout is also "+
			"the only one with no evidence, so password guessing from a stolen session is undetectable",
			reauthActor("doomed", clientIP), baselineTS)
	}
}

// TestSecReauthAudit1_RepeatedFailuresEachLeaveEvidence pins that the evidence
// is per ATTEMPT, not once per episode. A rate-limited or fire-once log line
// would be the wrong instrument here: the operator's question is how many
// guesses were made, and a single entry cannot answer it.
func TestSecReauthAudit1_RepeatedFailuresEachLeaveEvidence(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	const attempts = 3
	baselineTS := time.Now().UnixMilli()

	// Distinct client IPs so each attempt is independently identifiable in the
	// ring even if the ring evicts between attempts.
	for i := 0; i < attempts; i++ {
		clientIP := fmt.Sprintf("198.51.100.8%d", i)
		r := reauthReq(t, "doomed", clientIP, map[string]any{
			"current_password": fmt.Sprintf("guess-%d", i),
			"new_password":     "Rotat3dSecret9",
		})
		apiAuthChangePassword(httptest.NewRecorder(), r)
	}

	snap := auditGet()
	for i := 0; i < attempts; i++ {
		clientIP := fmt.Sprintf("198.51.100.8%d", i)
		if !hasMatchingAuditEntry(snap, reauthActor("doomed", clientIP),
			"auth.password_change.fail", "doomed", baselineTS) {
			t.Errorf("guess %d from %s left no audit entry: the trail cannot show the size of a "+
				"guessing campaign", i, clientIP)
		}
	}
}

// TestSecReauthAudit1_AuditActorIsBounded is the boundary gate. The username is
// session-derived, but -user/auth.user and --reset-password both persist a name
// the creation API's 64-byte cap never saw, so a configured account name can be
// arbitrarily long — and this entry is reachable once per mutating request.
// CHAOS-63's rule applies: bound the name before it reaches the audit ring.
func TestSecReauthAudit1_AuditActorIsBounded(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	long := strings.Repeat("v", loginAuditActorMax*3)
	if err := cfg.SetUIUser(long, "Sup3rSecret3", RoleAdmin); err != nil {
		t.Fatalf("seed oversize account: %v", err)
	}

	const clientIP = "198.51.100.72"
	baselineTS := time.Now().UnixMilli()

	r := reauthReq(t, long, clientIP, map[string]any{
		"current_password": "not-the-password",
		"new_password":     "Rotat3dSecret9",
	})
	apiAuthChangePassword(httptest.NewRecorder(), r)

	var found bool
	for _, e := range auditGet() {
		if e.Action != "auth.password_change.fail" || e.TS < baselineTS {
			continue
		}
		if !strings.HasPrefix(e.Object, "v") {
			continue
		}
		found = true
		if len(e.Object) > loginAuditActorMax+len("…[truncated,  bytes]")+24 {
			t.Errorf("audit Object is %d bytes for an oversize account name: the entry is reachable "+
				"once per request and must be bounded before it retains caller-sized bytes", len(e.Object))
		}
		if len(e.Object) == len(long) {
			t.Errorf("audit Object is the untruncated %d-byte account name", len(e.Object))
		}
	}
	if !found {
		t.Error("no auth.password_change.fail entry for the oversize account: the gate proves nothing")
	}
}

// TestSecReauthAudit1_ConcurrentFailuresAreRecorded is the concurrency gate:
// the added audit write must be safe on the admin request path under -race.
//
//	go test -race -run TestSecReauthAudit1_ConcurrentFailuresAreRecorded .
func TestSecReauthAudit1_ConcurrentFailuresAreRecorded(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	baselineTS := time.Now().UnixMilli()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r := reauthReq(t, "doomed", "198.51.100.90", map[string]any{
				"current_password": fmt.Sprintf("parallel-guess-%d", n),
				"new_password":     "Rotat3dSecret9",
			})
			apiAuthChangePassword(httptest.NewRecorder(), r)
		}(i)
	}
	wg.Wait()

	if !hasMatchingAuditEntry(auditGet(), reauthActor("doomed", "198.51.100.90"),
		"auth.password_change.fail", "doomed", baselineTS) {
		t.Error("concurrent rejected re-authentications left no audit entry")
	}
}

// ─── Controls ───────────────────────────────────────────────────────────────
//
// The cheapest way to pass every gate above is to audit UNCONDITIONALLY on
// entry, which would both report rejections that never happened and turn every
// malformed body into a credential-failure line. These fail against that.

// TestSecReauthAudit1_SuccessIsNotRecordedAsAFailure is the positive control: a
// correct current password audits the CHANGE and never the failure.
func TestSecReauthAudit1_SuccessIsNotRecordedAsAFailure(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	const clientIP = "198.51.100.73"
	baselineTS := time.Now().UnixMilli()

	r := reauthReq(t, "doomed", clientIP, map[string]any{
		"current_password": "Sup3rSecret2",
		"new_password":     "Rotat3dSecret9",
	})
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)

	if w.Code < 200 || w.Code >= 300 {
		t.Fatalf("correct current password: got %d, want 2xx (body=%s)", w.Code, w.Body.String())
	}
	snap := auditGet()
	if hasMatchingAuditEntry(snap, reauthActor("doomed", clientIP),
		"auth.password_change.fail", "doomed", baselineTS) {
		t.Error("a SUCCESSFUL password change recorded a credential-failure entry: the trail would " +
			"show guessing campaigns that never happened")
	}
	if !hasMatchingAuditEntry(snap, reauthActor("doomed", clientIP),
		"auth.password_change", "doomed", baselineTS) {
		t.Error("the successful password change was not audited")
	}
}

// TestSecReauthAudit1_MalformedBodyIsNotACredentialFailure is the second
// control: a request that never reaches the verifier presented no credential,
// so recording a rejection would be a false accusation — and would hand an
// unauthenticated-shaped caller a cheap way to flood the ring.
func TestSecReauthAudit1_MalformedBodyIsNotACredentialFailure(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	baselineTS := time.Now().UnixMilli()
	for name, body := range map[string]map[string]any{
		"empty-current": {"current_password": "", "new_password": "Rotat3dSecret9"},
		"empty-new":     {"current_password": "Sup3rSecret2", "new_password": ""},
		"both-empty":    {"current_password": "", "new_password": ""},
	} {
		clientIP := "198.51.100.74"
		r := reauthReq(t, "doomed", clientIP, body)
		w := httptest.NewRecorder()
		apiAuthChangePassword(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, w.Code)
		}
	}
	if hasMatchingAuditEntry(auditGet(), reauthActor("doomed", "198.51.100.74"),
		"auth.password_change.fail", "doomed", baselineTS) {
		t.Error("a malformed body was audited as a credential failure: no credential was presented, " +
			"so the entry is a false accusation")
	}
}

// TestSecReauthAudit1_UnauthenticatedCallerIsNotAudited is the authorization
// control: with no session the handler refuses BEFORE the verifier, so there is
// no account to name and no entry to write. Auditing here would let a caller
// with no session at all write ring entries.
func TestSecReauthAudit1_UnauthenticatedCallerIsNotAudited(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)

	baselineTS := time.Now().UnixMilli()

	// No uiUserKey in context ⇒ sessionAdmin returns "".
	r := jsonReq(http.MethodPost, "/api/auth/change-password", map[string]any{
		"current_password": "whatever",
		"new_password":     "Rotat3dSecret9",
	})
	r.RemoteAddr = "198.51.100.75:9999"
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: got %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
	for _, e := range auditGet() {
		if e.Action == "auth.password_change.fail" && e.TS >= baselineTS &&
			strings.Contains(e.Actor, "198.51.100.75") {
			t.Error("an unauthenticated caller wrote an audit entry: the refusal happens before any " +
				"credential is checked, so there is nothing to record")
		}
	}
}
