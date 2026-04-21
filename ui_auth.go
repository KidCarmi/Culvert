package main

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"time"
)


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
	// Account lockout check — before any credential verification.
	if locked, secs := loginLimiter.Check(body.User); locked {
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
	if !cfg.AuthEnabled() {
		role, ok = RoleAdmin, true
	}
	if ok {
		// Credentials valid — check TOTP if enrolled.
		if cfg.UserHasTOTP(body.User) {
			if body.TOTP == "" {
				// First step: tell the client TOTP is required (no session yet).
				jsonOK(w, map[string]any{"totp_required": true})
				return
			}
			secret := cfg.GetTOTPSecret(body.User)
			lastCounter := cfg.GetTOTPLastCounter(body.User)
			totpOK, matchedCounter := verifyTOTPReturnCounter(secret, body.TOTP, time.Now().Unix(), lastCounter)
			if totpOK {
				// Persist the matched counter to close the replay window for
				// this step and all earlier steps within the skew tolerance.
				cfg.SetTOTPLastCounter(body.User, matchedCounter)
				cfg.SaveUIUsersFile() //nolint:errcheck — best-effort persist
			} else {
				// Try backup codes.
				if !cfg.ConsumeBackupCode(body.User, body.TOTP) {
					// TOTP failures MUST feed the lockout counter — otherwise
					// an attacker who has (or guesses) a valid password can
					// brute-force the 6-digit OTP (1M possibilities) with
					// only the 300 ms delay as a barrier.
					nowLocked := loginLimiter.RecordFailure(body.User)
					cfg.SaveUIUsersFile() //nolint:errcheck — best-effort persist
					auditEvent(r, "auth.totp.fail", body.User,
						fmt.Sprintf("invalid TOTP, locked=%v, attempts_left=%d",
							nowLocked, loginLimiter.AttemptsLeft(body.User)))
					time.Sleep(300 * time.Millisecond)
					if nowLocked {
						_, secs := loginLimiter.Check(body.User)
						http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
						return
					}
					http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
					return
				}
				// Backup code consumed — persist removal.
				cfg.SaveUIUsersFile() //nolint:errcheck
			}
		}
		loginLimiter.RecordSuccess(body.User)
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
	nowLocked := loginLimiter.RecordFailure(body.User)
	auditEvent(r, "auth.login.fail", body.User,
		fmt.Sprintf("invalid credentials, locked=%v, attempts_left=%d",
			nowLocked, loginLimiter.AttemptsLeft(body.User)))
	time.Sleep(300 * time.Millisecond) // slow down brute-force
	if nowLocked {
		_, secs := loginLimiter.Check(body.User)
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return
	}
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// GET /api/auth/status — return whether the current request has a valid session.
func apiAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.AuthEnabled() {
		jsonOK(w, map[string]any{"loggedIn": true, "user": "", "role": RoleAdmin})
		return
	}
	sess, err := readUISessionCookie(r)
	if err == nil && sess != nil {
		role := UIRole(sess.Role)
		if !role.HasRole(RoleViewer) {
			role = RoleAdmin
		}
		jsonOK(w, map[string]any{"loggedIn": true, "user": sess.Sub, "role": role})
		return
	}
	// Accept Basic Auth header for CLI/API callers.
	user, pass, ok := r.BasicAuth()
	if ok {
		if role, valid := cfg.VerifyUIUser(user, pass); valid {
			jsonOK(w, map[string]any{"loggedIn": true, "user": user, "role": role})
			return
		}
	}
	jsonOK(w, map[string]any{"loggedIn": false})
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
	saveConfigVersion(sessionAdmin(r), "auth.password_change")
	jsonOK(w, map[string]any{"ok": true})
}

// GET /api/setup/status — reports whether first-time setup is still needed.
// Always public so the browser can decide whether to show the setup wizard.
func apiSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]any{"needsSetup": !cfg.AuthEnabled()})
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
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	setupKey := "setup:" + ip
	if locked, secs := loginLimiter.Check(setupKey); locked {
		http.Error(w, fmt.Sprintf("too many attempts, locked for %ds", secs), http.StatusTooManyRequests)
		return
	}
	if cfg.AuthEnabled() {
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

	// Unauth (open proxy) mode — skip credential requirements.
	if body.Unauth {
		cfg.SetUnauthMode(true)
		auditEvent(r, "setup.complete", "system", "unauth mode enabled — proxy requires no credentials")
		jsonOK(w, map[string]any{"ok": true, "unauth": true})
		return
	}

	body.User = strings.TrimSpace(body.User)
	if len(body.User) < 1 || len(body.User) > 64 {
		loginLimiter.RecordFailure(setupKey)
		http.Error(w, "username must be 1-64 characters", http.StatusBadRequest)
		return
	}
	if err := validatePasswordComplexity(body.Pass); err != nil {
		loginLimiter.RecordFailure(setupKey)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := cfg.SetAuth(body.User, body.Pass); err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		logger.Printf("UIUsers: failed to persist: %v", err)
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
		jsonOK(w, idpRegistry.All())
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
		if err := idpRegistry.Upsert(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEventDiff(r, "idp.create", p.ID, p.Name, nil, &p)
		logger.Printf("UI: IdP profile created id=%q name=%q type=%q", sanitizeLog(p.ID), sanitizeLog(p.Name), sanitizeLog(string(p.Type)))
		jsonOK(w, &p)
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
		jsonOK(w, p)
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		before := idpRegistry.Get(id)
		var p IdPProfile
		if err := decodeJSON(r, &p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		p.ID = id
		if err := idpRegistry.Upsert(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEventDiff(r, "idp.update", id, p.Name, before, &p)
		logger.Printf("UI: IdP profile updated id=%q name=%q", sanitizeLog(id), sanitizeLog(p.Name))
		jsonOK(w, &p)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		p := idpRegistry.Get(id)
		if err := idpRegistry.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEventDiff(r, "idp.delete", id, "", p, nil)
		logger.Printf("UI: IdP profile deleted id=%q", sanitizeLog(id))
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
	entry, ok := globalPKCEStore.peek(state)
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
	// Determine which SAML provider this response belongs to.
	// We try all enabled SAML providers and use the one that validates cleanly.
	for _, prov := range idpRegistry.EnabledProviders() {
		samlProv, ok := prov.(*SAMLProvider)
		if !ok {
			continue
		}
		id, relayURL, err := samlProv.ExchangeAssertion(r)
		if err != nil {
			continue // try next provider
		}
		if err := setSessionCookie(w, r, id); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		safeRelay := "/"
		if relayURL != "" && isSafeRedirectURL(relayURL) {
			safeRelay = relayURL
		}
		logger.Printf("SAML login OK: user=%q email=%q provider=%q", sanitizeLog(id.Sub), sanitizeLog(id.Email), sanitizeLog(id.Provider))
		http.Redirect(w, r, safeRelay, http.StatusFound)
		return
	}
	http.Error(w, "SAML authentication failed", http.StatusUnauthorized)
}

// GET /auth/select?relay=...  — IdP selection screen for multi-tenancy.
// Renders a minimal HTML page listing all enabled providers.
func authSelectProvider(w http.ResponseWriter, r *http.Request) {
	relay := r.URL.Query().Get("relay")
	if relay == "" {
		relay = "/"
	}
	providers := idpRegistry.EnabledProviders()
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
			html.EscapeString(loginURL), html.EscapeString(p.Name()))
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

// ── Security scan API ─────────────────────────────────────────────────────────

// GET /api/security-scan/status — returns ClamAV connectivity, YARA rule count,
// threat feed statistics, and hash cache metrics.
