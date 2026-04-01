package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Session secret — generated once at startup
// ---------------------------------------------------------------------------

var sessionSecret []byte

func initSessionSecret() {
	sessionSecret = make([]byte, 32)
	if _, err := rand.Read(sessionSecret); err != nil {
		panic(fmt.Sprintf("session: failed to generate secret: %v", err))
	}
}

// ---------------------------------------------------------------------------
// Session revocation list — invalidates tokens on explicit logout.
// Entries are evicted lazily when their original expiry passes.
// ---------------------------------------------------------------------------

type revocationList struct {
	mu     sync.Mutex
	tokens map[string]time.Time // b64 payload → session expiry
}

var sessionRevoked = &revocationList{tokens: map[string]time.Time{}}

func (r *revocationList) Revoke(token string, exp time.Time) {
	r.mu.Lock()
	r.tokens[token] = exp
	r.mu.Unlock()
}

func (r *revocationList) IsRevoked(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.tokens[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(r.tokens, token) // lazy eviction
		return false
	}
	return true
}

// revokeSessionCookie adds the cookie from r to the revocation list.
func revokeSessionCookie(cookieName string, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	dot := strings.LastIndex(c.Value, ".")
	if dot < 0 {
		return
	}
	b64part := c.Value[:dot]
	// Decode just to get the expiry (HMAC already verified by decodeSession).
	if payload, decErr := base64.RawURLEncoding.DecodeString(b64part); decErr == nil {
		var s Session
		if json.Unmarshal(payload, &s) == nil {
			sessionRevoked.Revoke(b64part, time.Unix(s.Exp, 0))
		}
	}
}

// ---------------------------------------------------------------------------
// Session type
// ---------------------------------------------------------------------------

const sessionCookieName = "ps_session"

// uiSessionTTL is the lifetime of admin UI sessions.
// Configurable at runtime via /api/session-timeout; default 8 hours.
var (
	uiSessionTTL   = 8 * time.Hour
	uiSessionTTLMu sync.RWMutex
)

func getSessionTTL() time.Duration {
	uiSessionTTLMu.RLock()
	defer uiSessionTTLMu.RUnlock()
	return uiSessionTTL
}

// SetSessionTTL updates the session lifetime. Clamped to [15min, 7d].
func SetSessionTTL(d time.Duration) {
	const minTTL = 15 * time.Minute
	const maxTTL = 7 * 24 * time.Hour
	if d < minTTL {
		d = minTTL
	}
	if d > maxTTL {
		d = maxTTL
	}
	uiSessionTTLMu.Lock()
	uiSessionTTL = d
	uiSessionTTLMu.Unlock()
}

// Session is the payload stored inside the signed proxy session cookie.
// It carries just enough identity data to reconstruct an Identity object
// without talking to the IdP on every request.
type Session struct {
	Sub      string   `json:"sub"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"grp,omitempty"`
	Provider string   `json:"pvd"`
	Role     string   `json:"role,omitempty"` // UI admin role: admin|operator|viewer
	Exp      int64    `json:"exp"`            // Unix timestamp
}

// Identity converts the session payload into the canonical Identity object.
func (s *Session) Identity() *Identity {
	return &Identity{
		Sub:      s.Sub,
		Email:    s.Email,
		Name:     s.Name,
		Groups:   s.Groups,
		Provider: s.Provider,
	}
}

// ---------------------------------------------------------------------------
// Cookie encoding / decoding
// ---------------------------------------------------------------------------

// encodeSession serialises session data, signs it with HMAC-SHA256, and
// returns a cookie-safe string: base64(json).HMAC.
func encodeSession(s *Session) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := sessionMAC(b64)
	return b64 + "." + mac, nil
}

// decodeSession parses and verifies a session cookie value.
// Returns an error when the signature is invalid or the session has expired.
func decodeSession(raw string) (*Session, error) {
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		return nil, fmt.Errorf("session: malformed cookie")
	}
	b64, mac := raw[:dot], raw[dot+1:]

	// Constant-time MAC comparison.
	expected := sessionMAC(b64)
	if !hmac.Equal([]byte(mac), []byte(expected)) {
		return nil, fmt.Errorf("session: invalid signature")
	}

	// Revocation check (explicit logout).
	if sessionRevoked.IsRevoked(b64) {
		return nil, fmt.Errorf("session: revoked")
	}

	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("session: base64 decode: %w", err)
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, fmt.Errorf("session: json decode: %w", err)
	}
	if time.Now().Unix() > s.Exp {
		return nil, fmt.Errorf("session: expired")
	}
	return &s, nil
}

func sessionMAC(data string) string {
	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// HTTP cookie helpers
// ---------------------------------------------------------------------------

// setSessionCookie writes a new signed session cookie to the response.
// The Secure flag is set dynamically based on whether the request is HTTPS.
func setSessionCookie(w http.ResponseWriter, r *http.Request, id *Identity) error {
	s := &Session{
		Sub:      id.Sub,
		Email:    id.Email,
		Name:     id.Name,
		Groups:   id.Groups,
		Provider: id.Provider,
		Exp:      time.Now().Add(getSessionTTL()).Unix(),
	}
	value, err := encodeSession(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(getSessionTTL().Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// readSessionCookie extracts and validates the session cookie from the request.
// Returns (nil, nil) when no session cookie is present (not an error).
func readSessionCookie(r *http.Request) (*Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeSession(c.Value)
}

// clearSessionCookie removes the session cookie.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}
