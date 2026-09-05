package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/totp"
	"github.com/crewjam/saml"
)

// setupCompleteMu serializes apiSetupComplete's "is setup already done?"
// check against its own writes. The endpoint is intentionally public
// (reachable before any admin account exists), so without this lock two
// concurrent POSTs can both observe !cfg.IsConfigured() before either call
// finishes, letting more than one caller provision an admin credential —
// each one landing in the uiUsers RBAC roster as a permanent, independently
// usable admin login.
var setupCompleteMu sync.Mutex

// verifyLoginTOTP checks TOTP enrollment/code as part of an already
// credential-accepted login. Returns true when the caller should proceed to
// issue a session; false means this function already wrote the HTTP
// response (the "totp_required" first-step prompt, an invalid-code error, or
// a lockout) and the caller must return without writing anything further.
func verifyLoginTOTP(w http.ResponseWriter, r *http.Request, clientIP, user, code string) bool {
	if !cfg.UserHasTOTP(user) {
		return true
	}
	if code == "" {
		// First step: tell the client TOTP is required (no session yet).
		jsonOK(w, map[string]any{"totp_required": true})
		return false
	}
	secret := cfg.GetTOTPSecret(user)
	lastCounter := cfg.GetTOTPLastCounter(user)
	totpOK, matchedCounter := totp.VerifyTOTPReturnCounter(secret, code, time.Now().Unix(), lastCounter)
	if totpOK {
		// Persist the matched counter to close the replay window for this
		// step and all earlier steps within the skew tolerance.
		cfg.SetTOTPLastCounter(user, matchedCounter)
		cfg.SaveUIUsersFile() //nolint:errcheck // best-effort persist
		return true
	}
	if cfg.ConsumeBackupCode(user, code) {
		// Backup code consumed — persist removal.
		cfg.SaveUIUsersFile() //nolint:errcheck // best-effort persist
		return true
	}
	// TOTP failures MUST feed the lockout counter — otherwise an attacker
	// who has (or guesses) a valid password can brute-force the 6-digit OTP
	// (1M possibilities) with only the 300 ms delay as a barrier.
	nowLocked := loginLimiter.RecordFailure(clientIP, user)
	cfg.SaveUIUsersFile() //nolint:errcheck // best-effort persist
	auditEvent(r, "auth.totp.fail", user,
		fmt.Sprintf("invalid TOTP, locked=%v, attempts_left=%d", nowLocked, loginLimiter.AttemptsLeft(clientIP, user)))
	time.Sleep(300 * time.Millisecond)
	if nowLocked {
		_, secs := loginLimiter.Check(clientIP, user)
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return false
	}
	http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
	return false
}

// POST /api/auth/login — validate admin credentials, set session cookie.
// When TOTP is enrolled for the user, a first-pass response of {"totp_required":true}
// is returned (HTTP 200, no cookie); the client must re-POST with the totp field set.
func apiAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
		TOTP string `json:"totp"` // 6-digit code or backup code; empty on first step
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// CHAOS-58: bound the username BEFORE it can reach the lockout maps, the
	// audit ring or the durable audit JSONL. This endpoint is public, so an
	// unbounded name here is an unauthenticated write amplifier into all three
	// (see login_input_bounds.go).
	if rejectOversizeLoginUser(w, r, body.User) {
		return
	}
	// RISK-019: resolve the real client behind a configured trusted proxy, so
	// an L7 proxy that collapses peer IPs can't let one attacker lock out every
	// admin (falls back to the direct peer when no trusted proxy is set).
	clientIP := realClientIP(r)
	// Account lockout check — before any credential verification. Two-tier
	// (RISK-012): the (IP, user) pair lock plus the trusted-IP-bypassed
	// account lock, so a remote attacker can no longer lock the real admin
	// out by spamming failures for their username.
	if locked, secs := loginLimiter.Check(clientIP, body.User); locked {
		auditEvent(r, "auth.lockout", body.User, fmt.Sprintf("blocked — %ds remaining", secs))
		go fireAlert("auth_lockout", AlertPayload{
			Actor:  body.User,
			Detail: fmt.Sprintf("account locked for %ds", secs),
			Source: "auth",
		})
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return
	}

	role, ok := cfg.VerifyUIUser(body.User, body.Pass)
	// Pre-setup bootstrap window: uiAuthMiddleware and apiAuthStatus already
	// grant RoleAdmin to every request with no credentials at all while
	// !cfg.IsConfigured(), so this branch never needs a persisted cookie to
	// function — the setup wizard itself never even calls this endpoint pre-
	// setup (static/index.html only wires the login form for the "setup
	// already done" branch). But the endpoint is public and reachable
	// directly, so without this a caller can POST any credentials here
	// before setup, mint a real signed session for an ATTACKER-CHOSEN
	// username, and keep it: once the real operator later runs first-time
	// setup with that same username (e.g. the wizard's own suggested default
	// "admin"), the session cookie now names an existing user and remains a
	// valid admin session for its full TTL — uiAuthMiddleware's only check on
	// a local session is that the named user still exists.
	preSetup := !cfg.IsConfigured()
	if preSetup {
		role, ok = RoleAdmin, true
	}
	if ok {
		// Credentials valid — check TOTP if enrolled. Runs regardless of
		// preSetup: the bootstrap bypass above only forces role/ok, it does
		// not imply no TOTP-enrolled user exists (e.g. an admin re-running
		// setup after wiping the primary credential but not the RBAC
		// roster) — must not skip this check.
		if !verifyLoginTOTP(w, r, clientIP, body.User, body.TOTP) {
			return
		}
		loginLimiter.RecordSuccess(clientIP, body.User)
		if preSetup {
			// See the comment on preSetup above: issuing a real session here
			// would outlive first-time setup if the operator later creates a
			// user with this same name, so skip it — the bootstrap window
			// already grants full access without one.
			auditEvent(r, "auth.login", body.User, "admin UI login (pre-setup bootstrap, no session issued)")
			jsonOK(w, map[string]any{"ok": true, "user": body.User, "role": role})
			return
		}
		// Clear any pre-existing session cookie before issuing a new one
		// to prevent session fixation attacks (defense-in-depth).
		clearUISessionCookie(w, r)
		if err := setUISessionCookie(w, r, body.User, role); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "auth.login", body.User, fmt.Sprintf("admin UI login role=%s", role))
		jsonOK(w, map[string]any{"ok": true, "user": body.User, "role": role})
		return
	}
	nowLocked := loginLimiter.RecordFailure(clientIP, body.User)
	auditEvent(r, "auth.login.fail", body.User,
		fmt.Sprintf("invalid credentials, locked=%v, attempts_left=%d",
			nowLocked, loginLimiter.AttemptsLeft(clientIP, body.User)))
	time.Sleep(300 * time.Millisecond) // slow down brute-force
	if nowLocked {
		_, secs := loginLimiter.Check(clientIP, body.User)
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return
	}
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// jsonOKAuthStatus writes an /api/auth/status response, adding the
// pre-authentication TLS-fallback FLAG to every branch — the login overlay
// reads this endpoint before a session exists, so it is the only place a
// browser sitting on the login form (about to submit a password) can learn
// the connection is unencrypted.
//
// The flag only, never uiTLSFallbackReason. /api/auth/status and
// /api/setup/status are on the uiAuthMiddleware public allowlist, so anything
// they return is readable by an UNAUTHENTICATED caller, and the reason is a
// raw selfSignedTLS() error — x509.CreateCertificate rejects a bad SAN by
// quoting it, so the string can carry a -ui-san/CULVERT_PUBLIC_IP value or an
// internal hostname. That is the same rule the readiness rows follow ("FIXED
// detail because the endpoint is unauthenticated", healthcheck.go) and that
// checkIdentityBackend states outright: the cause goes to the log and to
// authenticated surfaces, never to a pre-auth one. The flag itself discloses
// nothing — a client reaching this response over plaintext already knows the
// panel is plaintext — while the cause stays available on the viewer-gated
// GET /api/settings/network and in the process log.
// Pinned by TestTLSFallback_PreAuthSurfacesCarryNoReason.
func jsonOKAuthStatus(w http.ResponseWriter, fields map[string]any) {
	fields["ui_tls_fallback"] = uiTLSFallbackActive
	jsonOK(w, fields)
}

// GET /api/auth/status — return whether the current request has a valid session.
func apiAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.IsConfigured() {
		jsonOKAuthStatus(w, map[string]any{"loggedIn": true, "user": "", "role": RoleAdmin})
		return
	}
	sess, err := readUISessionCookie(r)
	if err == nil && sess != nil {
		role := UIRole(sess.Role)
		if !role.HasRole(RoleViewer) {
			role = RoleAdmin
		}
		jsonOKAuthStatus(w, map[string]any{"loggedIn": true, "user": sess.Sub, "role": role})
		return
	}
	// Accept Basic Auth header for CLI/API callers.
	user, pass, ok := r.BasicAuth()
	if ok {
		if role, valid := cfg.VerifyUIUser(user, pass); valid {
			jsonOKAuthStatus(w, map[string]any{"loggedIn": true, "user": user, "role": role})
			return
		}
	}
	jsonOKAuthStatus(w, map[string]any{"loggedIn": false})
}

// POST /api/auth/logout — clear the admin session cookie.
func apiAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, _ := readUISessionCookie(r)
	if sess != nil {
		auditEvent(r, "auth.logout", sess.Sub, "admin UI logout")
	}
	// Revoke the session token so it cannot be reused even if the cookie is
	// replayed before it naturally expires.
	revokeSessionCookie(uiSessionCookieName, r)
	clearUISessionCookie(w, r)
	jsonOK(w, map[string]any{"ok": true})
}

// GET/POST/DELETE /api/auth/users — RBAC user management (admin only).
//
//	GET    → list all UI admin users (without passwords)
//	POST   → create or update a user: {"username":"…","password":"…","role":"admin|operator|viewer"}
//	DELETE → remove a user: ?username=…
func apiAuthUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{"users": cfg.ListUIUsers()})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if len(body.Username) < 1 || len(body.Username) > 64 {
			http.Error(w, "username must be 1-64 characters", http.StatusBadRequest)
			return
		}
		if body.Password != "" {
			if err := validatePasswordComplexity(body.Password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		role := UIRole(body.Role)
		if !role.HasRole(RoleViewer) {
			http.Error(w, "role must be admin, operator, or viewer", http.StatusBadRequest)
			return
		}
		if err := cfg.SetUIUser(body.Username, body.Password, role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cfg.SaveUIUsersFile(); err != nil {
			logger.Printf("UIUsers: failed to persist: %v", err)
		}
		auditEvent(r, "auth.users.set", body.Username, fmt.Sprintf("role=%s", role))
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		username := strings.TrimSpace(r.URL.Query().Get("username"))
		if username == "" {
			http.Error(w, "missing username param", http.StatusBadRequest)
			return
		}
		if err := cfg.DeleteUIUser(username); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := cfg.SaveUIUsersFile(); err != nil {
			logger.Printf("UIUsers: failed to persist: %v", err)
		}
		// Revoke all active sessions for the deleted user (Finding 5.2).
		sessionRevoked.RevokeUser(username)
		auditEvent(r, "auth.users.delete", username, "")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/auth/lockouts — list every currently-active login lockout (both
// the tier-1 IP+username pair lock and the tier-2 account-wide lock). Before
// this endpoint, an admin's only way to discover or clear a stuck lockout was
// waiting out lockoutDuration, restarting the process, or reading logs.
// Admin-only (like GET /api/auth/users): the listing includes usernames and
// pair-lock source IPs, which is authentication telemetry a viewer should
// not be able to enumerate.
// POST /api/auth/lockouts — clear every lock for {"username":"..."} (both
// tiers, every IP), the GUI equivalent of the existing ResetUser primitive.
func apiAuthLockouts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{"lockouts": loginLimiter.Snapshot()})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Username string `json:"username"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" {
			http.Error(w, "missing username", http.StatusBadRequest)
			return
		}
		loginLimiter.ResetUser(body.Username)
		auditEvent(r, "auth.lockout.clear", body.Username, "")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/auth/change-password — self-service password change for any authenticated user.
// Body: {"current_password": "...", "new_password": "..."}
// Verifies the current password before accepting the change.
func apiAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	username := sessionAdmin(r)
	if username == "" || username == "unknown" {
		http.Error(w, "Unauthorized: no valid session", http.StatusUnauthorized)
		return
	}
	var body struct {
		CurrentPass string `json:"current_password"`
		NewPass     string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.CurrentPass == "" || body.NewPass == "" {
		http.Error(w, "current_password and new_password are required", http.StatusBadRequest)
		return
	}
	// Verify current password.
	if _, ok := cfg.VerifyUIUser(username, body.CurrentPass); !ok {
		http.Error(w, "current password is incorrect", http.StatusForbidden)
		return
	}
	if err := validatePasswordComplexity(body.NewPass); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Preserve existing role when changing password.
	users := cfg.ListUIUsers()
	var role UIRole
	for _, u := range users {
		if u.Username == username {
			role = u.Role
			break
		}
	}
	if role == "" {
		role = RoleAdmin // legacy single-user fallback
	}
	if err := cfg.SetUIUser(username, body.NewPass, role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		logger.Printf("UIUsers: failed to persist after password change: %v", err)
	}
	auditEvent(r, "auth.password_change", username, "self-service password change")
	// Intentionally NOT calling saveConfigVersion: password hashes are
	// excluded from the rollback surface (captureConfigBackup does NOT
	// capture ui_users.json). Even if they were captured, rolling back
	// to a prior version would restore the OLD password hash — a
	// security regression by definition, since the operator typically
	// changes the password because the prior one was compromised. The
	// audit trail above is the appropriate observability tier; rollback
	// is deliberately not. Category D-sec finding from
	// roadmap/CONFIG-VERSIONING-TRIAGE.md.
	jsonOK(w, map[string]any{"ok": true})
}

// GET /api/setup/status — reports whether first-time setup is still needed.
// Always public so the browser can decide whether to show the setup wizard.
func apiSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Flag only — this route is public (isPublicUIAuthPath: /api/setup*), so
	// the raw self-sign error must not travel with it. See jsonOKAuthStatus.
	jsonOK(w, map[string]any{
		"needsSetup":      !cfg.IsConfigured(),
		"ui_tls_fallback": uiTLSFallbackActive,
	})
}

// POST /api/setup/complete — sets the initial admin credential or enables unauth mode.
// Only callable once; returns 403 if auth is already configured.
// Body (with credentials): {"user": "...", "pass": "..."}
// Body (open/unauth mode):  {"unauth": true}
// Password must be at least 8 characters to enforce minimum hygiene.
func apiSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// S4: Rate-limit setup endpoint to prevent brute-force race during initial setup window.
	// RISK-019: trusted-proxy-aware client IP (falls back to the direct peer).
	ip := realClientIP(r)
	// Setup runs BEFORE any admin account exists, so it must use the
	// PAIR-ONLY limiter (CheckPair/RecordPairFailure): pure per-IP rate
	// limiting with no account-tier aggregation. Routing it through the
	// two-tier Check would let a handful of IPs push the shared
	// accounts["setup"] counter to the account cap and globally lock the
	// bootstrap flow — the very lockout-as-DoS RISK-012 fixes (and there is
	// no RecordSuccess here to ever build a trust grant that would bypass it).
	const setupKey = "setup"
	if locked, secs := loginLimiter.CheckPair(ip, setupKey); locked {
		http.Error(w, fmt.Sprintf("too many attempts, locked for %ds", secs), http.StatusTooManyRequests)
		return
	}
	// Fast, lock-free rejection for the common "already done" case. Body
	// decode/validation below must happen BEFORE setupCompleteMu is taken —
	// otherwise a client that stalls or drips its request body could
	// monopolize the lock and block the legitimate first-time setup request
	// during the bootstrap window.
	if cfg.IsConfigured() {
		http.Error(w, "setup already complete", http.StatusForbidden)
		return
	}

	var body struct {
		User   string `json:"user"`
		Pass   string `json:"pass"`
		Unauth bool   `json:"unauth"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if !body.Unauth {
		body.User = strings.TrimSpace(body.User)
		if len(body.User) < 1 || len(body.User) > 64 {
			loginLimiter.RecordPairFailure(ip, setupKey)
			http.Error(w, "username must be 1-64 characters", http.StatusBadRequest)
			return
		}
		if err := validatePasswordComplexity(body.Pass); err != nil {
			loginLimiter.RecordPairFailure(ip, setupKey)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Authoritative re-check under setupCompleteMu: the fast check above is
	// racy by design (no lock held during body decode/validation), so a
	// concurrent request may have completed setup in the meantime. Only the
	// lock-held check below — held across the check and the write — decides
	// whether this request is allowed to mutate cfg.
	setupCompleteMu.Lock()
	defer setupCompleteMu.Unlock()
	if cfg.IsConfigured() {
		http.Error(w, "setup already complete", http.StatusForbidden)
		return
	}

	// Open (no-credential) mode — set the global default to Exempt. Uses the
	// persist-checked setter (unlike the general settings-API call site,
	// which is reached only after setup is already complete) so a save
	// failure here fails the request and rolls back in-memory state — see
	// setDefaultAuthOutcomeChecked and the credentialed branch below for why:
	// an unpersisted Exempt default would report setup as done for this
	// process's lifetime while reopening the wizard on the next restart.
	if body.Unauth {
		if err := cfg.setDefaultAuthOutcomeChecked(OutcomeExempt); err != nil {
			logger.Printf("UIUsers: failed to persist open-mode setup: %v", err)
			http.Error(w, "internal error: open-mode setup could not be saved to disk; setup did not complete — check disk space/permissions and retry", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "setup.complete", "system", "open mode (defaultAuthOutcome=Exempt) — unmatched traffic requires no credentials")
		jsonOK(w, map[string]any{"ok": true, "unauth": true})
		return
	}

	if err := cfg.SetAuth(body.User, body.Pass); err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		// SetAuth already mutated in-memory state, which would otherwise make
		// IsConfigured() true for the rest of this process's lifetime even
		// though the credential was never durably saved — a restart before a
		// later successful save would revert IsConfigured() to false on load
		// and reopen the "one-time" setup wizard to any unauthenticated
		// visitor. Roll the in-memory state back so IsConfigured() reverts to
		// false NOW: the request fails instead of claiming success, and the
		// operator's retry goes through the normal (retryable) setup path
		// rather than hitting "setup already complete" with no session and no
		// persisted credential.
		logger.Printf("UIUsers: failed to persist: %v", err)
		cfg.RollbackFailedSetupAuth(body.User)
		http.Error(w, "internal error: admin credentials could not be saved to disk; setup did not complete — check disk space/permissions and retry", http.StatusInternalServerError)
		return
	}
	// Auto-login after setup so the user lands directly in the dashboard.
	_ = setUISessionCookie(w, r, body.User, RoleAdmin)
	auditEvent(r, "setup.complete", body.User, "first-time admin password configured")
	logger.Printf("First-time setup: admin user %q created", body.User)
	jsonOK(w, map[string]any{"ok": true})
}

// ── Generic IdP Framework API ────────────────────────────────────────────────

// GET /api/idp          — list all profiles
// POST /api/idp         — create a new profile
func apiIdPList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		// Envelope (not a bare array) so the UI can warn when the registry
		// is in-memory only and profiles would be lost on restart.
		jsonOK(w, map[string]any{
			"persisted": idpRegistry.Persisted(),
			"profiles":  publicIdPProfiles(idpRegistry.All()),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var p IdPProfile
		if err := decodeJSON(r, &p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		p.ID = "" // force generation of new ID
		// Optional safe-activation preflight (?preflight=connection): a live
		// connection test must pass BEFORE anything persists (LDAP only).
		if rep := ldapActivationPreflight(r, &p); rep != nil && !rep.OK {
			writeLDAPPreflightFailure(w, rep)
			return
		}
		if err := idpRegistry.Upsert(&p); err != nil {
			http.Error(w, err.Error(), idpMutationErrorStatus(err))
			return
		}
		enforceLegacyLDAPShadowing()
		_ = publishCurrentConfigSnapshot()
		auditEventDiff(r, "idp.create", p.ID, p.Name, nil, auditIdPProfile(&p))
		logger.Printf("UI: IdP profile created id=%q name=%q type=%q", sanitizeLog(p.ID), sanitizeLog(p.Name), sanitizeLog(string(p.Type)))
		jsonOK(w, publicIdPProfile(&p))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/idp/{id}     — get profile
// PUT /api/idp/{id}     — update profile
// DELETE /api/idp/{id}  — delete profile
// apiIdPRouter dispatches /api/idp/{id} and /api/idp/{id}/groups.
func apiIdPRouter(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/idp/")
	if strings.HasSuffix(rest, "/groups") {
		id := strings.TrimSuffix(rest, "/groups")
		apiIdPGroups(w, r, id)
		return
	}
	apiIdPItem(w, r, rest)
}

func apiIdPItem(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		p := idpRegistry.Get(id)
		if p == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		jsonOK(w, publicIdPProfile(p))
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		before := idpRegistry.Get(id)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var p IdPProfile
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		p.ID = id
		preserveWriteOnlyIdPFields(before, &p, writeOnlyIdPFieldPresence{
			oidcClientSecret: oidcClientSecretPresent(body),
			samlMetadataXML:  samlMetadataXMLPresent(body),
			ldapBindPassword: ldapBindPasswordPresent(body),
		})
		// Optional safe-activation preflight (?preflight=connection): a broken
		// candidate must never replace a working enabled provider — on failure
		// nothing is mutated and the live provider stays untouched (LDAP only).
		if rep := ldapActivationPreflight(r, &p); rep != nil && !rep.OK {
			writeLDAPPreflightFailure(w, rep)
			return
		}
		if err := idpRegistry.Upsert(&p); err != nil {
			http.Error(w, err.Error(), idpMutationErrorStatus(err))
			return
		}
		enforceLegacyLDAPShadowing()
		_ = publishCurrentConfigSnapshot()
		auditEventDiff(r, "idp.update", id, p.Name, auditIdPProfile(before), auditIdPProfile(&p))
		logger.Printf("UI: IdP profile updated id=%q name=%q", sanitizeLog(id), sanitizeLog(p.Name))
		jsonOK(w, publicIdPProfile(&p))
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		p := idpRegistry.Get(id)
		if err := idpRegistry.Delete(id); err != nil {
			// A persist failure is NOT "not found": the profile still exists
			// and its live provider is still authoritative (P1-3).
			status := http.StatusNotFound
			if errors.Is(err, errIdPPersistFailed) {
				status = http.StatusInternalServerError
			}
			http.Error(w, err.Error(), status)
			return
		}
		_ = publishCurrentConfigSnapshot()
		auditEventDiff(r, "idp.delete", id, "", auditIdPProfile(p), nil)
		logger.Printf("UI: IdP profile deleted id=%q", sanitizeLog(id))
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// writeOnlyIdPFieldPresence records which write-only secret fields the update
// request body actually carried (raw-body presence check, NOT decoded-value
// emptiness): an OMITTED field preserves the stored secret, while a PRESENT
// empty field is an explicit clear — the two must stay distinguishable.
type writeOnlyIdPFieldPresence struct {
	oidcClientSecret bool
	samlMetadataXML  bool
	ldapBindPassword bool
}

// idpMutationErrorStatus maps a registry mutation error to the HTTP status:
// a persistence failure is a server-side fault (500) — the request was valid
// and NOTHING changed (transactional registry, P1-3) — while every other
// error is a validation/compile rejection of the caller's input (400).
func idpMutationErrorStatus(err error) int {
	if errors.Is(err, errIdPPersistFailed) {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

func preserveWriteOnlyIdPFields(before, next *IdPProfile, present writeOnlyIdPFieldPresence) {
	if before == nil || next == nil {
		return
	}
	preserveOIDCClientSecret(before, next, present.oidcClientSecret)
	preserveOIDCDiscoveryEndpoints(before, next)
	preserveSAMLMetadataXML(before, next, present.samlMetadataXML)
	preserveLDAPBindPassword(before, next, present.ldapBindPassword)
}

// preserveLDAPBindPassword keeps the stored bind credential when an update
// omits the write-only bindPassword field (the GET projection never returns
// it, so an edit round-trip would otherwise wipe it). A request that carries
// the field explicitly — even empty — wins: empty-with-field-present is the
// deliberate clear path (e.g. switching to anonymous bind).
func preserveLDAPBindPassword(before, next *IdPProfile, bindPasswordProvided bool) {
	if before.Type != IdPTypeLDAP || next.Type != IdPTypeLDAP || before.LDAP == nil || next.LDAP == nil {
		return
	}
	if before.LDAP.BindPassword != "" && !bindPasswordProvided && next.LDAP.BindPassword == "" {
		next.LDAP.BindPassword = before.LDAP.BindPassword
	}
}

func auditIdPProfile(p *IdPProfile) *IdPProfile {
	return publicIdPProfile(p)
}

func preserveOIDCClientSecret(before, next *IdPProfile, clientSecretProvided bool) {
	if before.Type != IdPTypeOIDC || next.Type != IdPTypeOIDC || before.OIDC == nil || next.OIDC == nil {
		return
	}
	if before.OIDC.ClientSecret != "" && !clientSecretProvided && next.OIDC.ClientSecret == "" {
		next.OIDC.ClientSecret = before.OIDC.ClientSecret
	}
}

func preserveOIDCDiscoveryEndpoints(before, next *IdPProfile) {
	if before.Type != IdPTypeOIDC || next.Type != IdPTypeOIDC || before.OIDC == nil || next.OIDC == nil {
		return
	}
	if before.OIDC.Issuer != next.OIDC.Issuer {
		return
	}
	if next.OIDC.AuthorizationEndpoint == "" {
		next.OIDC.AuthorizationEndpoint = before.OIDC.AuthorizationEndpoint
	}
	if next.OIDC.TokenEndpoint == "" {
		next.OIDC.TokenEndpoint = before.OIDC.TokenEndpoint
	}
	if next.OIDC.IntrospectionEndpoint == "" {
		next.OIDC.IntrospectionEndpoint = before.OIDC.IntrospectionEndpoint
	}
	if next.OIDC.UserinfoEndpoint == "" {
		next.OIDC.UserinfoEndpoint = before.OIDC.UserinfoEndpoint
	}
	if next.OIDC.JWKsURI == "" {
		next.OIDC.JWKsURI = before.OIDC.JWKsURI
	}
}

func preserveSAMLMetadataXML(before, next *IdPProfile, metadataXMLProvided bool) {
	if before.Type != IdPTypeSAML || next.Type != IdPTypeSAML || before.SAML == nil || next.SAML == nil {
		return
	}
	if before.SAML.MetadataXML != "" && !metadataXMLProvided && next.SAML.MetadataURL == "" && next.SAML.MetadataXML == "" {
		next.SAML.MetadataXML = before.SAML.MetadataXML
	}
}

func oidcClientSecretPresent(body []byte) bool {
	return nestedJSONFieldPresent(body, "oidc", "clientSecret")
}

func samlMetadataXMLPresent(body []byte) bool {
	return nestedJSONFieldPresent(body, "saml", "metadataXml")
}

func ldapBindPasswordPresent(body []byte) bool {
	return nestedJSONFieldPresent(body, "ldap", "bindPassword")
}

func nestedJSONFieldPresent(body []byte, section, field string) bool {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return false
	}
	rawSection, ok := root[section]
	if !ok {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawSection, &fields); err != nil {
		return false
	}
	_, ok = fields[field]
	return ok
}

// GET /api/idp/{id}/groups — returns the known-groups list for the profile.
func apiIdPGroups(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	p := idpRegistry.Get(id)
	if p == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	groups := p.KnownGroups
	if groups == nil {
		groups = []string{}
	}
	jsonOK(w, groups)
}

// POST /api/idp/discover — run OIDC discovery for a given issuer URL and
// return the discovered endpoints without saving anything.
// Requires Admin: this endpoint makes outbound HTTP requests based on user input.
func apiIdPDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body struct {
		Issuer string `json:"issuer"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validateExternalURL(body.Issuer); err != nil {
		http.Error(w, "issuer: "+err.Error(), http.StatusBadRequest)
		return
	}
	doc, err := fetchOIDCDiscovery(body.Issuer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, doc)
}

// ── Auth callbacks ───────────────────────────────────────────────────────────

// GET /auth/oidc/callback?code=...&state=...
// Called by the IdP after the user authenticates (Authorization Code flow).
func authOIDCCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	// Find provider by state (providerID is stored inside the PKCE entry).
	entry, ok := globalPKCEStore.Peek(state)
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	prov, ok := idpRegistry.LiveProvider(entry.providerID)
	if !ok {
		http.Error(w, "provider not found", http.StatusInternalServerError)
		return
	}
	oidcProv, ok := prov.(*OIDCFlowProvider)
	if !ok {
		http.Error(w, "provider is not OIDC", http.StatusInternalServerError)
		return
	}
	id, err := oidcProv.ExchangeCode(r, code, state)
	if err != nil {
		logger.Printf("OIDC callback error: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if err := setSessionCookie(w, r, id); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	// Redirect to the original URL the user was trying to reach.
	relayURL := entry.relayURL
	if relayURL == "" || !isSafeRedirectURL(relayURL) {
		relayURL = "/"
	}
	logger.Printf("OIDC login OK: user=%q email=%q provider=%q", sanitizeLog(id.Sub), sanitizeLog(id.Email), sanitizeLog(id.Provider))
	http.Redirect(w, r, relayURL, http.StatusFound)
}

// POST /auth/saml/callback
// Called by the IdP's POST binding after SAML authentication.
func authSAMLCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine which SAML provider this response belongs to.
	// We try all enabled SAML providers and use the one that validates cleanly.
	for _, prov := range idpRegistry.EnabledProviders() {
		samlProv, ok := prov.(*SAMLProvider)
		if !ok {
			continue
		}
		id, relayURL, err := samlProv.ExchangeAssertion(r)
		if err != nil {
			logger.Printf("SAML callback rejected by provider=%q: %s", sanitizeLog(samlProv.profile.ID), sanitizeLog(err.Error()))
			continue // try next provider
		}
		if err := setSessionCookie(w, r, id); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		// Inline guard for static-analysis visibility: parse the IdP-supplied
		// RelayState, require an absolute http(s) URL pointing at a public
		// host, and otherwise fall back to "/". This mirrors
		// isSafeRedirectURL — duplicated here so the validation is visible
		// at the http.Redirect call site (covered by
		// TestSAMLRelayStateInlineGuard).
		safeRelay := "/"
		if relayURL != "" {
			if u, err := url.Parse(relayURL); err == nil &&
				u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https") &&
				isPrivateHost(u.Host) == nil {
				safeRelay = u.String()
			}
		}
		logger.Printf("SAML login OK: user=%q email=%q provider=%q", sanitizeLog(id.Sub), sanitizeLog(id.Email), sanitizeLog(id.Provider))
		// gosec G710 cannot follow validation through url.Parse + multiple
		// boolean operators; the inline guard above and isSafeRedirectURL
		// are the actual safety check. Suppression is the last resort, per
		// the project convention used elsewhere (e.g. ca.go:175, cdr.go:301).
		http.Redirect(w, r, safeRelay, http.StatusFound) // #nosec G710 -- safeRelay is "/" or an absolute http(s) URL whose host passed isPrivateHost; see inline guard above
		return
	}
	http.Error(w, "SAML authentication failed", http.StatusUnauthorized)
}

// GET /auth/saml/metadata
// Publishes the Service Provider metadata admins can import into an IdP.
func authSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metadata, err := buildSAMLSPMetadata()
	if err != nil {
		logger.Printf("SAML metadata error: %v", err)
		http.Error(w, "SAML metadata unavailable", http.StatusInternalServerError)
		return
	}
	data, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		logger.Printf("SAML metadata marshal error: %v", err)
		http.Error(w, "SAML metadata unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	_, _ = w.Write(data)
}

func buildSAMLSPMetadata() (*saml.EntityDescriptor, error) {
	spKey, spCert, err := ensureSPKeyPair()
	if err != nil {
		return nil, err
	}
	rootURL, err := url.Parse(proxyBaseURL(nil))
	if err != nil {
		return nil, err
	}
	sp := &saml.ServiceProvider{
		Key:               spKey,
		Certificate:       spCert,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
	}
	configureSAMLServiceProviderURLs(sp, rootURL)
	metadata := sp.Metadata()
	if len(metadata.SPSSODescriptors) > 0 {
		// crewjam emits exactly one NameIDFormat from AuthnNameIDFormat; Culvert
		// accepts both stable formats, so publish both for IdP metadata import.
		metadata.SPSSODescriptors[0].NameIDFormats = supportedSAMLMetadataNameIDFormats()
	}
	return metadata, nil
}

func supportedSAMLMetadataNameIDFormats() []saml.NameIDFormat {
	return []saml.NameIDFormat{
		saml.EmailAddressNameIDFormat,
		saml.PersistentNameIDFormat,
	}
}

// GET /auth/select?relay=...  — IdP selection screen for multi-tenancy.
// Renders a minimal HTML page listing all enabled providers.
// filterProvidersByID keeps only providers whose bare profile ID (stripIdPPrefix
// of Name) appears in the comma-separated want list. An empty want returns the
// providers unchanged.
func filterProvidersByID(providers []IdentityProvider, want string) []IdentityProvider {
	if want == "" {
		return providers
	}
	allow := make(map[string]bool)
	for _, id := range strings.Split(want, ",") {
		if id = strings.TrimSpace(id); id != "" {
			allow[id] = true
		}
	}
	out := providers[:0]
	for _, p := range providers {
		if allow[stripIdPPrefix(p.Name())] {
			out = append(out, p)
		}
	}
	return out
}

func authSelectProvider(w http.ResponseWriter, r *http.Request) {
	relay := r.URL.Query().Get("relay")
	if relay == "" {
		relay = "/"
	}
	// Optional providers= filter (Phase 3 Slice 4) scopes the selection to a set
	// of bare IdP profile IDs (used by an SSORequired rule's providerRefs); absent
	// → all enabled providers (backward-compatible; Default flow unaffected).
	// INTERACTIVE providers only (ADR-0027): the sign-in selector must never
	// offer a credential-only provider (LDAP) — it has no browser flow.
	providers := filterProvidersByID(idpRegistry.EnabledInteractiveProviders(), r.URL.Query().Get("providers"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>Culvert — Sign In</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:0 16px}
h1{font-size:1.4rem}a.btn{display:block;padding:12px 16px;margin:8px 0;border-radius:6px;
background:#2563eb;color:#fff;text-decoration:none;text-align:center}a.btn:hover{background:#1d4ed8}
</style></head><body><h1>Sign in to Culvert</h1>`)
	for _, p := range providers {
		loginURL := p.CaptiveLoginURL(relay, r)
		if loginURL == "" {
			continue
		}
		fmt.Fprintf(w, `<a class="btn" href="%s">Continue with %s</a>`,
			html.EscapeString(loginURL), html.EscapeString(p.DisplayName()))
	}
	if len(providers) == 0 {
		fmt.Fprintf(w, `<p>No identity providers are configured.</p>`)
	}
	fmt.Fprintf(w, `</body></html>`)
}

// POST /auth/logout — clear session cookie.
func authLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

// registerSetupRoutes wires the first-run setup endpoints. Both routes are
// public (allowlisted in uiAuthMiddleware) so a fresh install can configure
// itself before any admin user exists.
func registerSetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/setup/status", apiSetupStatus)
	mux.HandleFunc("/api/setup/complete", apiSetupComplete)
}

// registerAuthRoutes wires admin session login/logout, RBAC user
// management, the generic IdP framework, and the IdP redirect callbacks.
// Login/logout/status and the /auth/* callbacks are public; the rest are
// gated by uiAuthMiddleware + per-handler requireRole.
func registerAuthRoutes(mux *http.ServeMux) {
	// ── Admin session auth ────────────────────────────────────────────────
	mux.HandleFunc("/api/auth/login", apiAuthLogin)
	mux.HandleFunc("/api/auth/status", apiAuthStatus)
	mux.HandleFunc("/api/auth/logout", apiAuthLogout)
	mux.HandleFunc("/api/auth/users", apiAuthUsers)                    // RBAC user management (admin only)
	mux.HandleFunc("/api/auth/change-password", apiAuthChangePassword) // self-service password change (any role)
	mux.HandleFunc("/api/auth/lockouts", apiAuthLockouts)              // list/clear active login lockouts (admin unlock)

	// ── Generic IdP Framework ─────────────────────────────────────────────
	mux.HandleFunc("/api/idp", apiIdPList)                                // GET list / POST create
	mux.HandleFunc("/api/idp/discover", apiIdPDiscover)                   // POST: run OIDC discovery (must be before /api/idp/)
	mux.HandleFunc("/api/idp/test", apiIdPTest)                           // POST: candidate-based LDAP directory test (ADR-0027)
	mux.HandleFunc("/api/idp/legacy-ldap", apiIdPLegacyLDAP)              // GET: legacy YAML ldap summary
	mux.HandleFunc("/api/idp/legacy-ldap/import", apiIdPLegacyLDAPImport) // POST: explicit legacy import
	mux.HandleFunc("/api/idp/", apiIdPRouter)                             // GET|PUT|DELETE /api/idp/{id} + /api/idp/{id}/groups

	// ── Auth callbacks (not behind UI auth middleware) ────────────────────
	// These are reached by browser redirects from IdPs (not admin UI calls).
	// They are registered on the same UI port; the proxy port handles traffic.
	mux.HandleFunc("/auth/oidc/callback", authOIDCCallback)
	mux.HandleFunc("/auth/saml/callback", authSAMLCallback)
	mux.HandleFunc("/auth/saml/metadata", authSAMLMetadata)
	mux.HandleFunc("/auth/select", authSelectProvider) // IdP selection screen
	mux.HandleFunc("/auth/logout", authLogout)
}

// ── Security scan API ─────────────────────────────────────────────────────────

// GET /api/security-scan/status — returns ClamAV connectivity, YARA rule count,
// threat feed statistics, and hash cache metrics.
