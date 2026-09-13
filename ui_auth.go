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
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/lockout"
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
	// CHAOS-63: bound the username BEFORE it can reach the lockout maps, the
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
		var gen int64
		if sess.Provider == "local" {
			// Same authority as uiAuthMiddleware (Blocker 2): the durable
			// record decides, so a session issued under a previous security
			// generation reads as logged out here too — this route is
			// public, so the middleware never sees it.
			curRole, curGen, ok := cfg.UserRoleAndGeneration(sess.Sub)
			if !ok || sess.Gen <= 0 || sess.Gen != curGen {
				jsonOKAuthStatus(w, map[string]any{"loggedIn": false})
				return
			}
			role, gen = curRole, curGen
		}
		if !role.HasRole(RoleViewer) {
			role = RoleAdmin
		}
		jsonOKAuthStatus(w, map[string]any{"loggedIn": true, "user": sess.Sub, "role": role, "securityGeneration": gen})
		return
	}
	// Accept Basic Auth header for CLI/API callers.
	user, pass, ok := r.BasicAuth()
	if ok {
		if role, valid := cfg.VerifyUIUser(user, pass); valid {
			gen, _ := cfg.UserSecurityGeneration(user)
			jsonOKAuthStatus(w, map[string]any{"loggedIn": true, "user": user, "role": role, "securityGeneration": gen})
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

// GET/POST/PUT/DELETE /api/auth/users — RBAC user management (admin only).
//
//	GET    → {users:[{username, role, totpEnabled}], revision}
//	POST   → CREATE a user: {"username","password","role"}; 409 user_exists
//	PUT    → UPDATE an existing user's role and/or password:
//	         {"username","role"?,"password"?,"revision"} (fenced; 428/409)
//	DELETE → remove a user: ?username=…&revision=… (fenced; 404/409 last_admin)
//
// FE-6A.0 contract: every mutation commits PERSIST-BEFORE-PUBLISH (a failed
// save is 500 persist_failed with nothing changed), the roster revision is
// the fence, create is never an upsert, TOTP enrollment survives a
// password set, the last admin cannot be demoted or deleted, sessions of a
// changed/deleted user are revoked ONLY after the durable commit and the
// response says so (sessionsRevoked / selfAffected), and every refusal is
// the typed JSON dialect (ui_refusal.go).
func apiAuthUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRoleJSON(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{
			"users":    cfg.ListUIUsers(),
			"revision": cfg.RosterRevision(),
			"scope":    "node-local",
		})
	case http.MethodPost:
		apiAuthUsersCreate(w, r)
	case http.MethodPut:
		apiAuthUsersUpdate(w, r)
	case http.MethodDelete:
		apiAuthUsersDelete(w, r)
	default:
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
	}
}

// authUsersBody is the strict write shape shared by POST and PUT.
type authUsersBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Revision int64  `json:"revision"`
}

// decodeAuthUsersBody decodes + trims and writes the 400 on failure.
func decodeAuthUsersBody(w http.ResponseWriter, r *http.Request) (authUsersBody, bool) {
	var body authUsersBody
	if err := decodeJSON(r, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return body, false
	}
	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 1 || len(body.Username) > 64 {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "username must be 1-64 characters", nil)
		return body, false
	}
	if body.Password != "" {
		if err := validatePasswordComplexity(body.Password); err != nil {
			writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, err.Error(), nil)
			return body, false
		}
	}
	if body.Role != "" && !UIRole(body.Role).HasRole(RoleViewer) {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "role must be admin, operator, or viewer", nil)
		return body, false
	}
	return body, true
}

// writeRosterRefusal maps a roster transaction error to its typed refusal.
func writeRosterRefusal(w http.ResponseWriter, err error) {
	var stale *rosterStaleError
	var genStale *rosterGenStaleError
	switch {
	case errors.As(err, &stale):
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale revision: the roster changed since you loaded it — reload and retry",
			map[string]any{"revision": stale.Current})
	case errors.As(err, &genStale):
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale generation: the account's security generation changed since you verified your credential — reload and retry",
			map[string]any{"generation": genStale.Current})
	case errors.Is(err, errRosterNotDurable):
		writeRefusal(w, http.StatusServiceUnavailable, refusalPersistenceNotConfigured,
			"the admin roster has no persistence path; administrative mutations are refused", nil)
	case errors.Is(err, errRosterNotFound):
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "user not found", nil)
	case errors.Is(err, errRosterUserExists):
		writeRefusal(w, http.StatusConflict, refusalUserExists, "user already exists — update it instead", nil)
	case errors.Is(err, errRosterLastAdmin):
		writeRefusal(w, http.StatusConflict, refusalLastAdmin, "cannot demote or delete the last admin user", nil)
	case errors.Is(err, errRosterPersistFailed):
		writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
			"the admin roster could not be persisted; nothing was changed", nil)
	default:
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, err.Error(), nil)
	}
}

func apiAuthUsersCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	body, ok := decodeAuthUsersBody(w, r)
	if !ok {
		return
	}
	if body.Password == "" || body.Role == "" {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "password and role are required to create a user", nil)
		return
	}
	if !requireDurableRoster(w) {
		return
	}
	// Blocker 4: a create is fenced on the ROSTER DOCUMENT revision — the
	// only identity that exists before the user does.
	token := revisionFence(r, body.Revision)
	if !checkRevisionFence(w, token, cfg.RosterRevision()) {
		return
	}
	rev, err := cfg.CreateUIUser(body.Username, body.Password, UIRole(body.Role), token)
	if err != nil {
		writeRosterRefusal(w, err)
		return
	}
	gen, _ := cfg.UserSecurityGeneration(body.Username)
	auditEvent(r, "auth.users.create", body.Username, fmt.Sprintf("role=%s", body.Role))
	jsonOK(w, map[string]any{
		"ok":        true,
		"user":      UIUserInfo{Username: body.Username, Role: UIRole(body.Role), SecurityGeneration: gen},
		"revision":  rev,
		"persisted": cfg.uiUsersFilePath() != "",
	})
}

func apiAuthUsersUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	body, ok := decodeAuthUsersBody(w, r)
	if !ok {
		return
	}
	if body.Password == "" && body.Role == "" {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "nothing to update: supply role and/or password", nil)
		return
	}
	if !cfg.UIUserExists(body.Username) {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "user not found", nil)
		return
	}
	if !requireDurableRoster(w) {
		return
	}
	token := revisionFence(r, body.Revision)
	if !checkRevisionFence(w, token, cfg.RosterRevision()) {
		return
	}
	res, err := cfg.UpdateUIUser(body.Username, body.Password, UIRole(body.Role), token)
	if err != nil {
		writeRosterRefusal(w, err)
		return
	}
	// Session impact is a consequence of the DURABLE commit, not a separate
	// in-memory step: a changed role or credential advanced the user's
	// security generation inside the roster transaction, and every session
	// carries the generation it was issued under, so each earlier session —
	// on this node, on a restarted node, on any node loading this roster —
	// is refused by uiAuthMiddleware. A demoted admin loses authority now,
	// not at cookie TTL (R11), and the invalidation survives a restart
	// (Blocker 2).
	revoked := res.RoleChanged || res.PasswordChanged
	self := sessionAdmin(r) == body.Username
	role := res.PreviousRole
	if body.Role != "" {
		role = UIRole(body.Role)
	}
	auditEvent(r, "auth.users.update", body.Username,
		fmt.Sprintf("role=%s roleChanged=%t passwordChanged=%t sessionsRevoked=%t", role, res.RoleChanged, res.PasswordChanged, revoked))
	jsonOK(w, map[string]any{
		"ok":                 true,
		"user":               UIUserInfo{Username: body.Username, Role: role, TOTPEnabled: cfg.UserHasTOTP(body.Username), SecurityGeneration: res.Generation},
		"revision":           res.Revision,
		"persisted":          cfg.uiUsersFilePath() != "",
		"sessionsRevoked":    revoked,
		"selfAffected":       self,
		"securityGeneration": res.Generation,
	})
}

func apiAuthUsersDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "missing username param", nil)
		return
	}
	if !cfg.UIUserExists(username) {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "user not found", nil)
		return
	}
	if !requireDurableRoster(w) {
		return
	}
	token := revisionFence(r, 0)
	if !checkRevisionFence(w, token, cfg.RosterRevision()) {
		return
	}
	rev, err := cfg.DeleteUIUserFenced(username, token)
	if err != nil {
		writeRosterRefusal(w, err)
		return
	}
	// Revoke all active sessions for the deleted user (Finding 5.2) — after
	// the durable commit, never before it.
	sessionRevoked.RevokeUser(username)
	self := sessionAdmin(r) == username
	auditEvent(r, "auth.users.delete", username, "sessionsRevoked=true")
	jsonOK(w, map[string]any{
		"ok":              true,
		"deleted":         true,
		"username":        username,
		"revision":        rev,
		"persisted":       cfg.uiUsersFilePath() != "",
		"sessionsRevoked": true,
		"selfAffected":    self,
	})
}

// GET /api/auth/lockouts — list every currently-active login lockout (both
// the tier-1 IP+username pair lock and the tier-2 account-wide lock). Before
// this endpoint, an admin's only way to discover or clear a stuck lockout was
// waiting out lockoutDuration, restarting the process, or reading logs.
// Admin-only (like GET /api/auth/users): the listing includes usernames and
// pair-lock source IPs, which is authentication telemetry a viewer should
// not be able to enumerate. Lockout state is NODE-LOCAL (never cluster
// synced) and the read model says so (scope).
// POST /api/auth/lockouts — clear every lock for {"username":"..."} (both
// tiers, every IP), the GUI equivalent of the existing ResetUser primitive.
func apiAuthLockouts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRoleJSON(w, r, RoleAdmin) {
			return
		}
		// The generation is read in the same call as the listing so a
		// caller echoes the identity of the set they actually saw.
		entries, gen := loginLimiter.Snapshot(), loginLimiter.Generation()
		jsonOK(w, map[string]any{"lockouts": entries, "generation": gen, "scope": "node-local"})

	case http.MethodPost:
		if !requireRoleJSON(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Username   string `json:"username"`
			Generation int64  `json:"generation"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" {
			writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "missing username", nil)
			return
		}
		// Blocker 4: the reset asserts the server-owned lock-set generation
		// (428 absent / 409 stale / 404 no such lock), checked and cleared
		// under one limiter lock so no failure can land between the two.
		token := generationFence(r, body.Generation)
		if token == 0 {
			writeRefusal(w, http.StatusPreconditionRequired, refusalPreconditionRequired,
				"precondition required: echo the generation from the lockout listing",
				map[string]any{"generation": loginLimiter.Generation()})
			return
		}
		status, cur := loginLimiter.ResetUserIfGeneration(body.Username, token)
		switch status {
		case lockout.ResetStale:
			writeRefusal(w, http.StatusConflict, refusalStale,
				"stale generation: the lockout set changed since you listed it — reload and retry",
				map[string]any{"generation": cur})
			return
		case lockout.ResetNotFound:
			writeRefusal(w, http.StatusNotFound, refusalNotFound, "no lockout state for that username", nil)
			return
		}
		auditEvent(r, "auth.lockout.clear", body.Username, fmt.Sprintf("generation=%d", cur))
		jsonOK(w, map[string]any{"ok": true, "username": body.Username, "generation": cur, "scope": "node-local"})

	default:
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
	}
}

// POST /api/auth/change-password — self-service password change for any authenticated user.
// Body: {"current_password": "...", "new_password": "...", "generation": N}
// (`?generation=` wins when present).
//
// FE-6A.0 correction (Blocker 1/3): the change is bound to the caller's
// SECURITY GENERATION — the per-user identity that advances on every
// role/credential change — observed together with the verified credential
// (GET /api/auth/status exposes it). Order: decode → verify the current
// password (403 invalid_credentials) → fence (428 precondition_required /
// 409 stale, current.generation) → ONE roster transaction, which
// revalidates the generation under the roster lock (a competing
// administrator update ⇒ 409 stale; a competing delete ⇒ 404 not_found;
// zero mutation either way) and commits persist-before-publish (500
// persist_failed keeps the old credential usable and the new one unusable).
// A legacy single-user identity (mirror only, no roster entry) is migrated
// by the SAME transaction — never by a separate SetAuth that would publish
// the new credential before the durable outcome is known. TOTP enrollment
// is preserved (R9/R10). After the commit every session issued under the
// previous generation is invalid (durably, across restart); the caller's
// own UI session is re-issued at the new generation so the ceremony does
// not log them out.
func apiAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	username := sessionAdmin(r)
	if username == "" || username == "unknown" {
		writeRefusal(w, http.StatusUnauthorized, "unauthorized", "no valid session", nil)
		return
	}
	var body struct {
		CurrentPass string `json:"current_password"`
		NewPass     string `json:"new_password"`
		Generation  int64  `json:"generation"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	if body.CurrentPass == "" || body.NewPass == "" {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "current_password and new_password are required", nil)
		return
	}
	// The caller IS this account (authenticated), so telling them it no
	// longer exists leaks nothing — and it must be 404, not 403: a deleted
	// account has no credential to be "incorrect" about.
	curGen, known := cfg.UserSecurityGeneration(username)
	if !known {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "user not found", nil)
		return
	}
	// Verify current password.
	if _, ok := cfg.VerifyUIUser(username, body.CurrentPass); !ok {
		writeRefusal(w, http.StatusForbidden, refusalWrongCurrent, "current password is incorrect", nil)
		return
	}
	if err := validatePasswordComplexity(body.NewPass); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, err.Error(), nil)
		return
	}
	if !requireDurableRoster(w) {
		return
	}
	token := generationFence(r, body.Generation)
	if !checkGenerationFence(w, token, curGen) {
		return
	}
	rev, gen, err := cfg.ChangeUIUserPassword(username, body.NewPass, token)
	if err != nil {
		writeRosterRefusal(w, err)
		return
	}
	// The caller keeps working: re-issue THEIR session at the new
	// generation when the request rode a UI session cookie (a Basic-auth
	// caller has no cookie to re-issue). Every other session of this user
	// was issued under the previous generation and is now refused.
	if sess, cerr := readUISessionCookie(r); cerr == nil && sess != nil && sess.Sub == username {
		role, _, ok := cfg.UserRoleAndGeneration(username)
		if !ok {
			role = RoleAdmin
		}
		if err := setUISessionCookie(w, r, username, role); err != nil {
			logger.Printf("change-password: session re-issue failed for %q: %v", sanitizeLog(username), err)
		}
	}
	auditEvent(r, "auth.password_change", username,
		fmt.Sprintf("self-service password change generation=%d sessionsRevoked=true", gen))
	// Intentionally NOT calling saveConfigVersion: password hashes are
	// excluded from the rollback surface (captureConfigBackup does NOT
	// capture ui_users.json). Even if they were captured, rolling back
	// to a prior version would restore the OLD password hash — a
	// security regression by definition, since the operator typically
	// changes the password because the prior one was compromised. The
	// audit trail above is the appropriate observability tier; rollback
	// is deliberately not. Category D-sec finding from
	// roadmap/CONFIG-VERSIONING-TRIAGE.md.
	jsonOK(w, map[string]any{
		"ok":                 true,
		"revision":           rev,
		"persisted":          cfg.uiUsersFilePath() != "",
		"sessionsRevoked":    true,
		"selfAffected":       true,
		"securityGeneration": gen,
	})
}

// generationFence returns the caller's `generation` precondition: the query
// parameter wins when present (malformed reads as 0 ⇒ 428), else the body
// value.
func generationFence(r *http.Request, body int64) int64 {
	if q := r.URL.Query().Get("generation"); q != "" {
		v, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return body
}

// checkGenerationFence is the per-user twin of checkRevisionFence: the
// fenced identity is the target account's security generation, and the
// refusal carries current.generation.
func checkGenerationFence(w http.ResponseWriter, token, current int64) bool {
	if token == 0 {
		writeRefusal(w, http.StatusPreconditionRequired, refusalPreconditionRequired,
			"precondition required: echo the security generation you observed with your verified credential",
			map[string]any{"generation": current})
		return false
	}
	if token != current {
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale generation: the account changed since you loaded it — reload and retry",
			map[string]any{"generation": current})
		return false
	}
	return true
}

// requireDurableRoster refuses an administrative roster mutation BEFORE any
// runtime state changes when the roster has no persistence path (Blocker 7):
// a `2xx persisted:false` answer would let an in-memory change masquerade as
// an administrative fact that a restart silently reverts. Reads keep
// reporting the posture (`persisted`). Bootstrap paths (setup, the
// reset-password one-shot) keep their own contract.
func requireDurableRoster(w http.ResponseWriter) bool {
	if cfg.RosterDurable() {
		return true
	}
	writeRefusal(w, http.StatusServiceUnavailable, refusalPersistenceNotConfigured,
		"the admin roster has no persistence path; administrative mutations are refused", nil)
	return false
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
//
// FE-6A.0 contract (FRONTEND-MIGRATION-PLAN.md FE-6-0 §C1–C3, R1–R8): the
// read model carries the server-minted entry `revision` and the registry
// `revision` (content-derived) plus the `degraded` posture; PUT/DELETE are
// fenced on the entry revision (428 precondition_required / 409 stale /
// 404 vanished, decided inside the registry transaction); a DELETE of a
// provider an SSORequired rule references is 409 referenced with the
// referencing rules; every mutation commits persist-before-publish and an
// enabling LDAP write records the legacy-YAML cutover DURABLY before the
// registry publishes (500 persist_failed keeps the legacy authenticator
// wired); secrets never appear on a read model — only the derived
// *Configured indicators; every refusal is typed JSON.

// idpListReadModel assembles GET /api/idp.
func idpListReadModel() map[string]any {
	out := map[string]any{
		"persisted":  idpRegistry.Persisted(),
		"degraded":   false,
		"revision":   idpRegistry.DocumentRevision(),
		"profiles":   publicIdPProfiles(idpRegistry.All()),
		"scope":      "cluster-synced",
		"cluster":    idpClusterReadModel(),
		"operations": idpRegistry.operations().readModel(),
	}
	if d := idpRegistry.Degraded(); d != nil {
		out["degraded"] = true
		out["degradedReason"] = d.Reason
		out["degradedDetail"] = d.Detail
		if d.QuarantinePath != "" {
			out["quarantineEvidence"] = filepath.Base(d.QuarantinePath)
		}
	}
	return out
}

// writeIdPRefusal maps a registry mutation error to its typed refusal.
func writeIdPRefusal(w http.ResponseWriter, err error) {
	var stale *idpStaleError
	var docStale *idpDocStaleError
	var invalid *idpValidationError
	var compile *idpCompileError
	switch {
	case errors.As(err, &stale):
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale revision: the profile changed since you loaded it — reload and retry",
			map[string]any{"revision": stale.Current})
	case errors.As(err, &docStale):
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale document revision: the registry changed since you loaded it — reload and retry",
			map[string]any{"documentRevision": docStale.Current})
	case errors.As(err, &invalid):
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, invalid.msg, nil)
	case errors.As(err, &compile):
		// Blocker 6: a dependency failure is a 502 with a BOUNDED reason
		// class — never the provider's error text.
		writeRefusal(w, http.StatusBadGateway, refusalProviderCompileFailed,
			"the identity provider could not be constructed from this profile (dependency failure); nothing was changed",
			map[string]any{"reason": compile.reason})
	case errors.Is(err, errIdPOperationLedgerDegraded):
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded,
			"the identity-provider operation ledger is damaged and fail-closed; restore or remove idp_operations.json and restart — nothing was changed", nil)
	case errors.Is(err, errIdPOperationUnsettled):
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationUnsettled,
			"an outstanding operation on this profile could not be settled durably; nothing was changed — retry, or inspect GET /api/idp/operations/{operationId}", nil)
	case errors.Is(err, errIdPOperationLedgerFull):
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerFull,
			"every operation-ledger slot holds an unresolved intent; resolve them (GET /api/idp/operations/{operationId}) before starting another operation — nothing was changed", nil)
	case errors.Is(err, errIdPOperationPersist):
		writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
			"the operation intent could not be persisted; nothing was changed", nil)
	case errors.Is(err, errIdPVanished):
		writeRefusal(w, http.StatusNotFound, refusalVanished, "profile vanished: it was deleted since you loaded it", nil)
	case errors.Is(err, errIdPRegistryDegraded):
		writeRefusal(w, http.StatusServiceUnavailable, refusalRegistryDegraded,
			"the identity-provider registry is degraded (corrupt file quarantined); acknowledge the repair first", nil)
	case errors.Is(err, errIdPOutcomeUnknown):
		writeRefusal(w, http.StatusInternalServerError, refusalOutcomeUnknown,
			"outcome unknown: the registry file was written but the cutover sentinel is not durable and the rollback failed; nothing is published — the next restart reconciles from disk",
			map[string]any{"detail": "registry_persisted_sentinel_not_durable"})
	case errors.Is(err, errIdPPersistFailed), errors.Is(err, errAdminSettingsPersist):
		writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
			"the identity-provider registry could not be persisted; nothing was changed", nil)
	default:
		// Every error the registry returns is typed above; an unclassified
		// one is reported as a FIXED message so no dependency text can ride
		// the default branch (Blocker 6).
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid identity-provider profile", nil)
	}
}

// refusalCodeOf maps a registry error to the bounded refusal code it would
// be reported as (recorded on an aborted operation intent).
func refusalCodeOf(err error) string {
	w := httptest.NewRecorder()
	writeIdPRefusal(w, err)
	var m struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m.Code
}

// requireDurableIdP refuses an administrative registry mutation BEFORE any
// runtime state changes when the registry has no persistence path (Blocker
// 7). Reads keep reporting `persisted:false`; the CP→DP sync and the boot
// loaders are not administrative mutations and keep their own contract.
func requireDurableIdP(w http.ResponseWriter) bool {
	if idpRegistry.Persisted() {
		return true
	}
	writeRefusal(w, http.StatusServiceUnavailable, refusalPersistenceNotConfigured,
		"the identity-provider registry has no persistence path (no idp_profiles_file); administrative mutations are refused", nil)
	return false
}

// ── Fleet publication facts (Blocker 8) ──────────────────────────────────

// idpFleetResult is the bounded, structured outcome of publishing the
// registry to the fleet after a LOCAL durable commit.
type idpFleetResult struct {
	Publication string // published | rejected
	Version     int64  // the published snapshot version (published only)
	Reason      string // bounded rejection class (rejected only)
}

func (f idpFleetResult) readModel() map[string]any {
	out := map[string]any{"publication": f.Publication}
	if f.Publication == "published" {
		out["version"] = f.Version
	} else {
		out["reason"] = f.Reason
	}
	return out
}

// auditSuffix distinguishes the local durable commit from the fleet outcome
// in the audit detail.
func (f idpFleetResult) auditSuffix() string {
	if f.Publication == "published" {
		return fmt.Sprintf(" fleet=published v%d", f.Version)
	}
	return " fleet=rejected:" + f.Reason
}

// idpLastFleetRejection remembers the most recent rejected registry
// publication (bounded class + time) for the read model; cleared by the next
// successful publish.
var idpLastFleetRejection atomic.Pointer[idpFleetRejection]

type idpFleetRejection struct {
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// idpPublishFleet publishes the current config to the fleet after a local
// registry commit and returns the structured fact. The raw rejection stays
// in the log; the action result carries the class only.
func idpPublishFleet(what string) idpFleetResult {
	if err := publishCurrentConfigSnapshot(); err != nil {
		reason := publishRejectionClass(err)
		idpLastFleetRejection.Store(&idpFleetRejection{Reason: reason, At: time.Now().UTC().Format(time.RFC3339)})
		logger.Printf("UI: %s committed locally but the cluster publication was rejected (%s): %v", what, reason, err)
		return idpFleetResult{Publication: "rejected", Reason: reason}
	}
	idpLastFleetRejection.Store(nil)
	return idpFleetResult{Publication: "published", Version: globalConfigStore.Version()}
}

// idpClusterReadModel derives the fleet state of the registry: `published`
// when the last published snapshot carries exactly the current registry
// document, else `pending` (a rejected or not-yet-run publication).
func idpClusterReadModel() map[string]any {
	snap := globalConfigStore.Get()
	state := "pending"
	if idpDocumentRevisionOf(snap.IdPProfiles) == idpRegistry.DocumentRevision() {
		state = "published"
	}
	out := map[string]any{"state": state, "publishedVersion": snap.Version}
	if rej := idpLastFleetRejection.Load(); rej != nil && state == "pending" {
		out["lastRejection"] = *rej
	}
	return out
}

// idpWithFleet decorates a profile response with the fleet facts.
func idpWithFleet(p *IdPProfile, fleet idpFleetResult) map[string]any {
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m == nil {
		m = map[string]any{}
	}
	m["cluster"] = fleet.readModel()
	return m
}

// errAdminSettingsPersist wraps a failed durable cutover-sentinel write so the
// enabling registry mutation reports 500 persist_failed.
var errAdminSettingsPersist = errors.New("legacy-ldap cutover sentinel could not be persisted")

// idpLegacyCutoverHook returns the pre-publish step for a write that would
// ENABLE an LDAP profile on a node that still carries an un-retired legacy
// YAML ldap block: the cutover sentinel + operation record are persisted
// (persist-before-publish) and the runtime flag flips only inside the
// save's applyOnSuccess. nil when no cutover is due.
func idpLegacyCutoverHook(r *http.Request, p *IdPProfile) func(next []*IdPProfile) error {
	if p == nil || !p.Enabled || p.Type != IdPTypeLDAP || legacyLDAPYAMLConfig() == nil || legacyLDAPRetired() {
		return nil
	}
	actor := auditActor(r)
	return func(next []*IdPProfile) error {
		rec := newLegacyLDAPCutover(p, idpDocumentRevisionOf(next), actor, "admin_api")
		err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			legacyCutover: &rec,
			applyOnSuccess: func() {
				markLegacyLDAPRetiredWith(rec, "enabled LDAP identity provider "+p.ID+" committed through the admin API")
			},
		})
		if err != nil {
			return fmt.Errorf("%w: %v", errAdminSettingsPersist, err)
		}
		return nil
	}
}

// idpDocumentRevisionOf computes the registry document revision of a
// candidate set (the same derivation as IdPRegistry.DocumentRevision).
func idpDocumentRevisionOf(profiles []*IdPProfile) string {
	parts := make([]string, 0, len(profiles))
	for _, p := range profiles {
		if p != nil {
			parts = append(parts, p.ID+"@"+strconv.FormatInt(idpEntryRevision(p), 10))
		}
	}
	sort.Strings(parts)
	return contentSecRevision(append([]string{"idp-registry"}, parts...)...)
}

// GET /api/idp          — list all profiles
// POST /api/idp         — create a new profile
func apiIdPList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRoleJSON(w, r, RoleViewer) {
			return
		}
		// Envelope (not a bare array) so the UI can warn when the registry
		// is in-memory only and profiles would be lost on restart.
		jsonOK(w, idpListReadModel())
	case http.MethodPost:
		apiIdPCreate(w, r)
	default:
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
	}
}

// apiIdPCreate is POST /api/idp (FE-6A.0 correction). Order, and why:
//
//  1. decode; 2. durability (Blocker 7: refused before ANY runtime change);
//  3. operationId (Blocker 9: a cutover-bearing write REQUIRES a client
//     UUID — 428 operation_id_required; a known id REPLAYS the recorded
//     outcome: committed ⇒ the same response with replayed:true, aborted ⇒
//     409 operation_aborted, pending ⇒ 409 operation_in_progress, unknown ⇒
//     409 operation_outcome_unknown; a different candidate under a known id
//     ⇒ 409 operation_mismatch — never a second write);
//  4. document-revision fence pre-check (Blocker 4: 428/409 with
//     current.documentRevision; decided again INSIDE the transaction);
//  5. preflight; 6. durable INTENT (pre-minted id, actor, spec digest,
//     fenced revision) BEFORE the first irreversible write; 7. the registry
//     transaction (compile outside locks; a dependency failure is 502
//     provider_compile_failed with a bounded reason — Blocker 6); 8. the
//     terminal intent state; 9. fleet publication as a STRUCTURED fact
//     (Blocker 8: `cluster.publication`, audit `fleet=…`, never the raw
//     rejection).
func apiIdPCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	var p IdPProfile
	if err := decodeJSON(r, &p); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	p.ID = "" // the registry (or the durable intent) mints the id
	if !requireDurableIdP(w) {
		return
	}
	if idpRegistry.Degraded() != nil {
		writeIdPRefusal(w, errIdPRegistryDegraded)
		return
	}
	cutover := idpLegacyCutoverHook(r, &p)
	opID, ok := idpCreateOperationID(w, r, cutover != nil)
	if !ok {
		return
	}
	if !idpCutoverConfirmGate(w, r, cutover != nil) {
		return
	}
	// Normalise the candidate the same way the registry will (write-only
	// echo fields stripped) so the intent digest is the registry's view.
	normalizeIdPProfileWriteInput(&p)
	specDigest := idpSpecDigest(&p)
	ops := idpRegistry.operations()
	if idpReplayKnownOperation(w, ops, opID, specDigest) {
		return
	}
	docRev, ok := idpCreateDocumentFence(w, r)
	if !ok {
		return
	}
	// Optional safe-activation preflight (?preflight=connection): a live
	// connection test must pass BEFORE anything persists (LDAP only).
	if rep := ldapActivationPreflight(r, &p); rep != nil && !rep.OK {
		writeLDAPPreflightFailure(w, rep)
		return
	}
	p.ID = mintIdPID()
	if !idpBeginCreateIntent(w, ops, idpOperation{
		OperationID: opID, Action: "idp.create", Actor: auditActor(r), ProfileName: p.Name,
		ProfileID: p.ID, SpecDigest: specDigest, RegistryRevision: docRev, Cutover: cutover != nil,
	}) {
		return
	}
	if err := idpRegistry.Create(&p, docRev, opID, cutover); err != nil {
		idpFinishFailedOperation(ops, opID, err)
		writeIdPRefusal(w, err)
		return
	}
	enforceLegacyLDAPShadowing()
	fleet := idpPublishFleet("IdP create")
	result := idpWithFleet(publicIdPProfile(&p), fleet)
	detail := p.Name + fleet.auditSuffix()
	if opID != "" {
		result["operationId"] = opID
		detail += " operationId=" + opID
		if !idpRecordCommittedOperation(w, ops, opID, &p, result, detail) {
			return
		}
	}
	if opID == "" {
		auditEventDiff(r, "idp.create", p.ID, detail, nil, auditIdPProfile(&p))
	} else {
		idpCompleteOperationAudit(r, ops, opID, result)
	}
	logger.Printf("UI: IdP profile created id=%q name=%q type=%q fleet=%s", sanitizeLog(p.ID), sanitizeLog(p.Name), sanitizeLog(string(p.Type)), fleet.Publication)
	jsonOK(w, result)
}

// idpCompleteOperationAudit runs the exactly-once audit completion boundary
// for an operation-identified create from its durable record (round 4): the
// operation-keyed entry is appended only if absent from the durable audit
// record, and the marker persisted only after it is durably present. A
// failure leaves the operation committed-but-audit-pending — reported as
// `auditState: pending` on the response and the lookup, and retried by the
// lookup, by settlement and at boot. The response stays 2xx: the registry
// commit and its terminal record ARE durable and provable.
func idpCompleteOperationAudit(r *http.Request, ops *idpOperationStore, opID string, result map[string]any) {
	markAuditEmitted(r) // C2c: the audit for this request is owned by the boundary
	rec, err := ops.Get(opID)
	if err == nil && rec != nil {
		err = ops.emitOperationAudit(*rec)
	}
	if err != nil {
		logger.Printf("UI: IdP operation %s committed; success audit pending (%s)", sanitizeLog(opID), boundedPersistClass(err))
		result["auditState"] = "pending"
	}
}

// idpReplayKnownOperation answers a re-dispatched operationId from its
// durable record (or refuses on a degraded ledger). Returns true when the
// response has been written. No-op without an operationId.
func idpReplayKnownOperation(w http.ResponseWriter, ops *idpOperationStore, opID, specDigest string) bool {
	if opID == "" {
		return false
	}
	prev, err := ops.Get(opID)
	if err != nil {
		writeIdPRefusal(w, err) // degraded ledger: fail closed, nothing written
		return true
	}
	if prev == nil {
		return false
	}
	apiIdPReplayOperation(w, prev, specDigest)
	return true
}

// idpRecordCommittedOperation persists the terminal record of a committed
// create BEFORE success is reported (round 3, Blocker 1). A failed terminal
// persist leaves the durable `pending` intent as the truth and answers the
// NON-terminal 500 outcome_unknown: the profile IS committed (with its
// provenance), but this response must not claim so — the lookup settles it
// once the ledger is writable again, and the success audit is emitted then,
// exactly once. Returns false when the response has been written.
func idpRecordCommittedOperation(w http.ResponseWriter, ops *idpOperationStore, opID string, p *IdPProfile, result map[string]any, detail string) bool {
	err := ops.Finish(opID, idpOpCommitted, "", idpRegistry.DocumentRevision(), result, detail, auditIdPProfile(p))
	if err == nil {
		return true
	}
	logger.Printf("UI: IdP write id=%q operation %s committed but its terminal record is not durable (%s)", sanitizeLog(p.ID), sanitizeLog(opID), boundedPersistClass(err))
	writeRefusal(w, http.StatusInternalServerError, refusalOutcomeUnknown,
		"outcome unknown: the registry write landed but the operation's terminal record could not be persisted; poll GET /api/idp/operations/{operationId} — the result is settled durably from the registry's own provenance",
		map[string]any{"detail": "operation_record_not_durable", "operationId": opID, "id": p.ID})
	return false
}

// idpCreateOperationID resolves the optional client operationId: malformed
// ⇒ 400, absent on a cutover-bearing write ⇒ 428 operation_id_required.
func idpCreateOperationID(w http.ResponseWriter, r *http.Request, cutover bool) (string, bool) {
	opID := strings.TrimSpace(r.URL.Query().Get("operationId"))
	if opID != "" && !validIdPOperationID(opID) {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "operationId must be a UUID", nil)
		return "", false
	}
	if opID == "" && cutover {
		writeRefusal(w, http.StatusPreconditionRequired, refusalOperationIDRequired,
			"this write retires the legacy YAML ldap authenticator: supply a client-generated UUID operationId so a lost response can be recovered without a second cutover", nil)
		return "", false
	}
	return opID, true
}

// idpCutoverConfirmValue is the SERVER-required confirmation value for the
// legacy-LDAP authority cutover (FE-6A.2): the legacy block's directory URL —
// the identity of the authenticator being retired. Published on
// GET /api/idp/legacy-ldap as cutoverConfirmValue; "" without a block.
func idpCutoverConfirmValue() string {
	if c := legacyLDAPYAMLConfig(); c != nil {
		return c.URL
	}
	return ""
}

// idpCutoverConfirmGate (FE-6A.2) binds the cutover ceremony to the block
// being retired by a server fact: a cutover-bearing write must echo the
// server's cutoverConfirmValue in ?cutoverConfirm= — absent ⇒ 428
// cutover_confirm_required, wrong ⇒ 409 confirm_mismatch, both carrying
// current.confirmValue — decided BEFORE anything is written. No-op when the
// write carries no cutover. Returns false when the response has been written.
func idpCutoverConfirmGate(w http.ResponseWriter, r *http.Request, cutover bool) bool {
	if !cutover {
		return true
	}
	want := idpCutoverConfirmValue()
	got := strings.TrimSpace(r.URL.Query().Get("cutoverConfirm"))
	cur := map[string]any{"confirmValue": want}
	if got == "" {
		writeRefusal(w, http.StatusPreconditionRequired, refusalCutoverConfirmRequired,
			"this write retires the legacy YAML ldap authenticator: echo the legacy block's cutoverConfirmValue (GET /api/idp/legacy-ldap) as ?cutoverConfirm= to confirm which authenticator is being retired", cur)
		return false
	}
	if got != want {
		writeRefusal(w, http.StatusConflict, refusalConfirmMismatch,
			"cutoverConfirm does not name the legacy block being retired; nothing was changed", cur)
		return false
	}
	return true
}

// idpCreateDocumentFence applies the document-revision pre-check (428 absent,
// 409 stale with current.documentRevision); the transaction re-decides it.
func idpCreateDocumentFence(w http.ResponseWriter, r *http.Request) (string, bool) {
	docRev := strings.TrimSpace(r.URL.Query().Get("documentRevision"))
	if docRev == "" {
		writeRefusal(w, http.StatusPreconditionRequired, refusalPreconditionRequired,
			"precondition required: echo the registry documentRevision you loaded",
			map[string]any{"documentRevision": idpRegistry.DocumentRevision()})
		return "", false
	}
	if cur := idpRegistry.DocumentRevision(); docRev != cur {
		writeIdPRefusal(w, &idpDocStaleError{Current: cur})
		return "", false
	}
	return docRev, true
}

// idpBeginCreateIntent persists the durable intent BEFORE the first
// irreversible write (no-op without an operationId). A concurrent dispatch
// of the same id that won the race is answered from its record.
func idpBeginCreateIntent(w http.ResponseWriter, ops *idpOperationStore, op idpOperation) bool {
	if op.OperationID == "" {
		return true
	}
	prev, created, err := ops.Begin(op)
	if err != nil {
		writeIdPRefusal(w, err)
		return false
	}
	if !created {
		apiIdPReplayOperation(w, prev, op.SpecDigest)
		return false
	}
	return true
}

// idpFinishFailedOperation records the terminal state of a refused write.
func idpFinishFailedOperation(ops *idpOperationStore, opID string, err error) {
	if opID == "" {
		return
	}
	state := idpOpAborted
	if errors.Is(err, errIdPOutcomeUnknown) {
		state = idpOpOutcomeUnknown
	}
	if ferr := ops.Finish(opID, state, refusalCodeOf(err), "", nil, "", nil); ferr != nil {
		// The intent stays durably pending; reconciliation settles it from
		// the registry's provenance (a refused write left no profile).
		logger.Printf("UI: IdP operation %s refused (%s) but its terminal record is not durable (%s)", sanitizeLog(opID), refusalCodeOf(err), boundedPersistClass(ferr))
	}
}

// apiIdPReplayOperation answers a re-dispatched operationId from the durable
// record — never by performing the write again.
func apiIdPReplayOperation(w http.ResponseWriter, prev *idpOperation, specDigest string) {
	if prev.SpecDigest != specDigest {
		writeRefusal(w, http.StatusConflict, refusalOperationMismatch,
			"this operationId was already used for a different candidate; generate a new operationId for a new write",
			map[string]any{"operationId": prev.OperationID, "state": prev.State})
		return
	}
	switch prev.State {
	case idpOpCommitted:
		var m map[string]any
		_ = json.Unmarshal(prev.Result, &m)
		if m == nil {
			m = map[string]any{"id": prev.ProfileID}
		}
		m["operationId"] = prev.OperationID
		m["replayed"] = true
		jsonOK(w, m)
	case idpOpAborted:
		writeRefusal(w, http.StatusConflict, refusalOperationAborted,
			"this operation was refused when it was first dispatched; nothing was written — generate a new operationId to try again",
			map[string]any{"operationId": prev.OperationID, "state": prev.State, "code": prev.Code})
	case idpOpOutcomeUnknown:
		writeRefusal(w, http.StatusConflict, refusalOperationUnknown,
			"the outcome of this operation is not yet known (split durable state); the next restart reconciles it — look it up, do not retry",
			map[string]any{"operationId": prev.OperationID, "state": prev.State})
	default:
		writeRefusal(w, http.StatusConflict, refusalOperationInProgress,
			"this operation is still being decided; look it up rather than re-sending",
			map[string]any{"operationId": prev.OperationID, "state": prev.State})
	}
}

// GET /api/idp/operations/{operationId} — authoritative lookup of a durable
// operation intent (Blocker 9). Admin-only: the record names the actor.
func apiIdPOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/idp/operations/")
	if !validIdPOperationID(id) {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "operationId must be a UUID", nil)
		return
	}
	ops := idpRegistry.operations()
	op, err := ops.Get(id)
	if err != nil {
		writeIdPRefusal(w, err) // degraded ledger: the lookup is refused, never guessed
		return
	}
	if op == nil {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "no such operation", nil)
		return
	}
	switch {
	case op.unresolved():
		// Round 3: settle from the registry's durable provenance NOW (the
		// terminal persist may have failed at create time); the verdict is
		// reported only once it is durable, else the record stays as is.
		idpMutationMu.Lock()
		serr := idpRegistry.settleOperation(ops, *op, idpRegistry.Get(op.ProfileID), "lookup")
		idpMutationMu.Unlock()
		if serr != nil {
			logger.Printf("UI: IdP operation %s could not be settled at lookup (%s)", sanitizeLog(id), boundedPersistClass(serr))
		} else if cur, gerr := ops.Get(id); gerr == nil && cur != nil {
			op = cur
		}
	case op.State == idpOpCommitted && !op.Audited:
		// Round 4: committed but the success audit is still owed — retry
		// ONLY the missing step (append if absent from the durable record,
		// then the marker); exactly-once is the boundary's contract.
		if aerr := ops.emitOperationAudit(*op); aerr != nil {
			logger.Printf("UI: IdP operation %s success audit still pending at lookup (%s)", sanitizeLog(id), boundedPersistClass(aerr))
		} else if cur, gerr := ops.Get(id); gerr == nil && cur != nil {
			op = cur
		}
	}
	jsonOK(w, op.lookupReadModel())
}

// GET /api/idp/{id}     — get profile
// PUT /api/idp/{id}     — update profile (fenced on the entry revision)
// DELETE /api/idp/{id}  — delete profile (fenced; 409 referenced)
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
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "missing id", nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !requireRoleJSON(w, r, RoleViewer) {
			return
		}
		p := idpRegistry.Get(id)
		if p == nil {
			writeRefusal(w, http.StatusNotFound, refusalNotFound, "not found", nil)
			return
		}
		jsonOK(w, publicIdPProfile(p))
	case http.MethodPut:
		apiIdPUpdate(w, r, id)
	case http.MethodDelete:
		apiIdPDelete(w, r, id)
	default:
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
	}
}

func apiIdPUpdate(w http.ResponseWriter, r *http.Request, id string) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	var p IdPProfile
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	// The fence token is read BEFORE the candidate is normalised (the body's
	// revision is a fallback for the query token and normalisation zeroes it).
	token := revisionFence(r, p.Revision)
	before := idpRegistry.Get(id)
	if before == nil {
		writeRefusal(w, http.StatusNotFound, refusalVanished, "profile not found", nil)
		return
	}
	if !requireDurableIdP(w) {
		return
	}
	p.ID = id
	preserveWriteOnlyIdPFields(before, &p, writeOnlyIdPFieldPresence{
		oidcClientSecret: oidcClientSecretPresent(body),
		samlMetadataXML:  samlMetadataXMLPresent(body),
		ldapBindPassword: ldapBindPasswordPresent(body),
	})
	// FE-6A.2: a cutover through PUT carries the SAME operation identity and
	// confirm fence as a cutover through POST — a lost response is recovered
	// through the ledger (replay), never by a second cutover, and the T2
	// ceremony is bound to the block being retired by the server's own value.
	cutover := idpLegacyCutoverHook(r, &p)
	opID, ok := idpCreateOperationID(w, r, cutover != nil)
	if !ok {
		return
	}
	if !idpCutoverConfirmGate(w, r, cutover != nil) {
		return
	}
	normalizeIdPProfileWriteInput(&p)
	specDigest := idpSpecDigest(&p)
	ops := idpRegistry.operations()
	// A re-dispatched operationId is answered from its durable record with
	// the ORIGINAL fence semantics: the replay never re-decides the revision.
	if idpReplayKnownOperation(w, ops, opID, specDigest) {
		return
	}
	// Fast pre-check against the value read now; the authoritative fence is
	// decided again INSIDE the registry transaction (Update).
	if !checkRevisionFence(w, token, idpEntryRevision(before)) {
		return
	}
	if idpRegistry.Degraded() != nil {
		writeIdPRefusal(w, errIdPRegistryDegraded)
		return
	}
	// Optional safe-activation preflight (?preflight=connection): a broken
	// candidate must never replace a working enabled provider — on failure
	// nothing is mutated and the live provider stays untouched (LDAP only).
	if rep := ldapActivationPreflight(r, &p); rep != nil && !rep.OK {
		writeLDAPPreflightFailure(w, rep)
		return
	}
	if !idpBeginCreateIntent(w, ops, idpOperation{
		OperationID: opID, Action: "idp.update", Actor: auditActor(r), ProfileName: p.Name,
		ProfileID: id, SpecDigest: specDigest, RegistryRevision: idpRegistry.DocumentRevision(), Cutover: cutover != nil,
	}) {
		return
	}
	if err := idpRegistry.Update(&p, token, opID, cutover); err != nil {
		idpFinishFailedOperation(ops, opID, err)
		writeIdPRefusal(w, err)
		return
	}
	enforceLegacyLDAPShadowing()
	fleet := idpPublishFleet("IdP update")
	result := idpWithFleet(publicIdPProfile(&p), fleet)
	detail := p.Name + fleet.auditSuffix()
	if opID != "" {
		result["operationId"] = opID
		detail += " operationId=" + opID
		if !idpRecordCommittedOperation(w, ops, opID, &p, result, detail) {
			return
		}
		idpCompleteOperationAudit(r, ops, opID, result)
	} else {
		auditEventDiff(r, "idp.update", id, detail, auditIdPProfile(before), auditIdPProfile(&p))
	}
	logger.Printf("UI: IdP profile updated id=%q name=%q fleet=%s", sanitizeLog(id), sanitizeLog(p.Name), fleet.Publication)
	jsonOK(w, result)
}

// idpDeletePauseHook is a TEST SEAM: when non-nil it runs inside the
// exclusive reference gate, between the reference scan and the durable
// delete — the window the gate exists to close (Blocker 5 interleaving
// proofs). Production never sets it.
var idpDeletePauseHook func()

func apiIdPDelete(w http.ResponseWriter, r *http.Request, id string) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	p := idpRegistry.Get(id)
	if p == nil {
		writeRefusal(w, http.StatusNotFound, refusalVanished, "profile not found", nil)
		return
	}
	if !requireDurableIdP(w) {
		return
	}
	token := revisionFence(r, 0)
	if !checkRevisionFence(w, token, idpEntryRevision(p)) {
		return
	}
	if idpRegistry.Degraded() != nil {
		writeIdPRefusal(w, errIdPRegistryDegraded)
		return
	}
	// Blocker 5: the reference scan and the durable delete are ONE decision
	// under the exclusive side of the shared reference-integrity gate. Every
	// SSORequired providerRefs writer holds the shared side across its own
	// validate→commit window, so neither interleaving can commit a dangling
	// reference: a writer that lands first blocks this scan until it commits
	// (the scan then sees the reference ⇒ 409 referenced); a writer that
	// arrives while this delete holds the gate waits, then revalidates its
	// target against the post-delete registry and refuses.
	refScanDeleteLock()
	defer refScanDeleteUnlock()
	if _, refs := objectReferences("idp", id); len(refs) > 0 {
		writeRefusal(w, http.StatusConflict, refusalReferenced,
			"the provider is referenced by authentication rules; remove or retarget them first",
			map[string]any{"revision": idpEntryRevision(p), "references": refs})
		return
	}
	if idpDeletePauseHook != nil {
		idpDeletePauseHook()
	}
	if err := idpRegistry.DeleteFenced(id, token); err != nil {
		writeIdPRefusal(w, err)
		return
	}
	fleet := idpPublishFleet("IdP delete")
	auditEventDiff(r, "idp.delete", id, fleet.auditSuffix(), auditIdPProfile(p), nil)
	logger.Printf("UI: IdP profile deleted id=%q fleet=%s", sanitizeLog(id), fleet.Publication)
	jsonOK(w, map[string]any{
		"ok":        true,
		"deleted":   true,
		"id":        id,
		"revision":  idpRegistry.DocumentRevision(),
		"persisted": idpRegistry.Persisted(),
		"cluster":   fleet.readModel(),
	})
}

// POST /api/idp/repair — fenced acknowledgement of a quarantined registry
// (R8): {"confirm": "<quarantined file base name>"} clears the degraded
// posture; the registry stays empty. Admin-only, audited.
func apiIdPRepair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	var body struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	d := idpRegistry.Degraded()
	if err := idpRegistry.Repair(strings.TrimSpace(body.Confirm)); err != nil {
		switch {
		case errors.Is(err, errIdPNotDegraded):
			writeRefusal(w, http.StatusConflict, refusalNotDegraded, "the registry is not degraded", nil)
		case errors.Is(err, errIdPRepairUnavailable):
			writeRefusal(w, http.StatusConflict, refusalRepairUnavailable, err.Error(), nil)
		default:
			cur := map[string]any{}
			if d != nil && d.QuarantinePath != "" {
				cur["confirmValue"] = filepath.Base(d.QuarantinePath)
			}
			writeRefusal(w, http.StatusConflict, refusalConfirmMismatch, "confirm must name the quarantined file exactly", cur)
		}
		return
	}
	evidence := ""
	if d != nil {
		evidence = filepath.Base(d.QuarantinePath)
	}
	auditEvent(r, "idp.repair", "idp-registry", "quarantine acknowledged: "+evidence)
	logger.Printf("UI: IdP registry repair acknowledged evidence=%q", sanitizeLog(evidence))
	jsonOK(w, map[string]any{"ok": true, "repaired": true, "evidence": evidence, "revision": idpRegistry.DocumentRevision()})
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
	if errors.Is(err, errIdPPersistFailed) || errors.Is(err, errIdPOutcomeUnknown) {
		return http.StatusInternalServerError
	}
	if errors.Is(err, errIdPRegistryDegraded) {
		return http.StatusServiceUnavailable
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
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	p := idpRegistry.Get(id)
	if p == nil {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "not found", nil)
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
// Audited (idp.discover) with the issuer HOST only — the admin actuated an
// outbound fetch; the discovery document itself is never audited.
func apiIdPDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	var body struct {
		Issuer string `json:"issuer"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	if err := validateExternalURL(body.Issuer); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "issuer: "+err.Error(), nil)
		return
	}
	host := body.Issuer
	if u, err := url.Parse(body.Issuer); err == nil && u.Host != "" {
		host = u.Host
	}
	doc, err := fetchOIDCDiscovery(body.Issuer)
	if err != nil {
		auditEvent(r, "idp.discover", host, "failed")
		writeRefusal(w, http.StatusBadGateway, refusalUpstreamError, "OIDC discovery failed for the issuer (see the server log for the cause)", nil)
		return
	}
	auditEvent(r, "idp.discover", host, "ok")
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
	mux.HandleFunc("/api/idp/repair", apiIdPRepair)                       // POST: fenced quarantine acknowledgement (FE-6A.0 R8)
	mux.HandleFunc("/api/idp/operations/", apiIdPOperations)              // GET: authoritative operation-intent lookup (FE-6A.0 correction, Blocker 9)
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
