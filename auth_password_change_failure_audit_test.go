package main

// auth_password_change_failure_audit_test.go — regression coverage for
// SEC-PWCHANGE-1.
//
// apiAuthChangePassword audits a SUCCESSFUL self-service password change
// ("auth.password_change") but, before this fix, wrote nothing at all when the
// presented current password was wrong. That made it the only credential
// verification left on the admin plane with no compliance record — the same
// missing-audit half of the defect SEC-BASIC-1 closed for HTTP Basic
// (ui_basic_auth.go), surviving on a sibling row of the same surface. A
// session holder guessing the account's current password (the step that
// converts session access into durable account takeover) left no trace.
//
// These tests pin both directions: a refusal is audited, and the refusal is
// still a refusal (no mutation, 403). They assert on unique entry CONTENT
// (Action + ObjectID), never on ring length — the audit ring is bounded and
// shuffled runs saturate it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// changePasswordRequest builds a POST /api/auth/change-password carrying a
// valid session for user and the RoleViewer-satisfying context the production
// middleware chain would have installed.
func changePasswordRequest(t *testing.T, user, current, next string) *http.Request {
	t.Helper()
	cookieValue, err := encodeSession(&Session{
		Sub:      user,
		Provider: "local",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Jti:      newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	body := strings.NewReader(`{"current_password":"` + current + `","new_password":"` + next + `"}`)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/auth/change-password", body)
	r.Header.Set("Content-Type", "application/json")
	// Cookie attributes are inert here — the request never crosses the
	// network; they satisfy gosec G124 without a //nolint suppression.
	r.AddCookie(&http.Cookie{
		Name:     uiSessionCookieName,
		Value:    cookieValue,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return r
}

// auditEntryFor returns the newest entry with the given action and object, and
// whether one exists. auditEvent records the account name in Object (ObjectID
// carries a ULID and stays empty on this path), so the pair is the entry's
// unique content: a saturated ring cannot make the assertion pass or fail by
// accident, as a length delta would.
func auditEntryFor(action, object string) (AuditEntry, bool) {
	for _, entry := range auditGet() {
		if entry.Action == action && entry.Object == object {
			return entry, true
		}
	}
	return AuditEntry{}, false
}

// TestSECPWCHANGE1_WrongCurrentPasswordIsAudited is the negative-path guard:
// a refused change-password must leave a durable record. Removing the
// auditEvent call in apiAuthChangePassword's verification branch fails this.
func TestSECPWCHANGE1_WrongCurrentPasswordIsAudited(t *testing.T) {
	snapshotCfgUIUsers(t)
	restoreAudit := audit.SwapRingForTest()
	t.Cleanup(restoreAudit)

	const (
		user    = "pwchange_fail_audit_test"
		good    = "CorrectPass1234"
		guessed = "WrongGuess5678"
		wanted  = "NeverApplied9012"
	)
	if err := cfg.SetUIUser(user, good, RoleAdmin); err != nil {
		t.Fatalf("seed test user: %v", err)
	}

	w := httptest.NewRecorder()
	apiAuthChangePassword(w, changePasswordRequest(t, user, guessed, wanted))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", w.Code, http.StatusForbidden, w.Body.String())
	}

	entry, ok := auditEntryFor("auth.password_change.fail", user)
	if !ok {
		t.Fatal("a refused current-password verification wrote no audit entry — " +
			"SEC-PWCHANGE-1: a password-guessing campaign against this endpoint leaves no compliance record")
	}

	// The record must never carry the presented secret, in any field.
	body := entry.Detail + entry.Before + entry.After
	for _, secret := range []string{guessed, wanted, good} {
		if strings.Contains(body, secret) {
			t.Fatalf("audit entry leaked a password value: %+v", entry)
		}
	}

	// A refusal must not have mutated anything: the old password still works
	// and the attempted new one does not.
	if _, ok := cfg.VerifyUIUser(user, good); !ok {
		t.Error("the original password no longer verifies — a refused change mutated the roster")
	}
	if _, ok := cfg.VerifyUIUser(user, wanted); ok {
		t.Error("the attempted new password verifies — a refused change was applied")
	}
}

// TestSECPWCHANGE1_SuccessIsAuditedAndNotMisreportedAsFailure is the positive
// control: the success record is unchanged and a success never emits the
// failure action (which would poison the signal the guard above establishes).
func TestSECPWCHANGE1_SuccessIsAuditedAndNotMisreportedAsFailure(t *testing.T) {
	snapshotCfgUIUsers(t)
	restoreAudit := audit.SwapRingForTest()
	t.Cleanup(restoreAudit)

	const (
		user    = "pwchange_ok_audit_test"
		good    = "CorrectPass1234"
		updated = "ReplacementPass5678"
	)
	if err := cfg.SetUIUser(user, good, RoleAdmin); err != nil {
		t.Fatalf("seed test user: %v", err)
	}

	w := httptest.NewRecorder()
	apiAuthChangePassword(w, changePasswordRequest(t, user, good, updated))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", w.Code, http.StatusOK, w.Body.String())
	}
	if _, ok := auditEntryFor("auth.password_change", user); !ok {
		t.Error("a successful password change wrote no audit entry")
	}
	if _, ok := auditEntryFor("auth.password_change.fail", user); ok {
		t.Error("a successful password change emitted the FAILURE action")
	}
	if _, ok := cfg.VerifyUIUser(user, updated); !ok {
		t.Error("the new password does not verify — the change did not apply")
	}
}

// TestSECPWCHANGE1_MalformedAndMissingFieldsAreRefusedBeforeVerification is
// the boundary/malformed-input control. These refusals happen BEFORE any
// credential verification, so they must not emit the verification-failure
// action — otherwise the audit signal stops meaning "someone guessed".
func TestSECPWCHANGE1_MalformedAndMissingFieldsAreRefusedBeforeVerification(t *testing.T) {
	snapshotCfgUIUsers(t)

	const (
		user = "pwchange_malformed_audit_test"
		good = "CorrectPass1234"
	)
	if err := cfg.SetUIUser(user, good, RoleAdmin); err != nil {
		t.Fatalf("seed test user: %v", err)
	}

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"not JSON", `{`, http.StatusBadRequest},
		{"empty current", `{"current_password":"","new_password":"NewPass1234"}`, http.StatusBadRequest},
		{"empty new", `{"current_password":"CorrectPass1234","new_password":""}`, http.StatusBadRequest},
		{"both empty", `{}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreAudit := audit.SwapRingForTest()
			t.Cleanup(restoreAudit)

			r := changePasswordRequest(t, user, "placeholder", "placeholder")
			r.Body = http.NoBody
			r = r.Clone(r.Context())
			r.Body = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)).Body

			w := httptest.NewRecorder()
			apiAuthChangePassword(w, r)

			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
			if _, ok := auditEntryFor("auth.password_change.fail", user); ok {
				t.Error("a request refused before credential verification emitted the verification-failure action")
			}
			if _, ok := cfg.VerifyUIUser(user, good); !ok {
				t.Error("the original password no longer verifies")
			}
		})
	}
}
