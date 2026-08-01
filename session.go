package main

// session.go — Session shim: aliases + startup wiring + HTTP cookie helpers
// over internal/session (ADR-0002). The engine — signing-key holder (now
// race-safe: the DP cluster sync replaces the key at runtime), token
// encode/decode, revocation list + persistence, TTL, jti — lives in the
// package. main keeps: env/config key priority (env is read HERE per the
// startup-slice convention), the cookie helpers (isSecureRequest + the
// Identity hub type), and the Session→Identity conversion.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

type (
	// Session is the payload stored inside the signed proxy session cookie.
	Session = session.Session
	// RevocationEntry is a single revoked session token for gRPC gossip.
	RevocationEntry = session.RevocationEntry
)

const sessionCookieName = session.CookieName

// sessionRevoked is the process-wide revocation list (package singleton;
// pointer is stable — tests swap its contents, never the pointer).
var sessionRevoked = session.Revoked

// initSessionSecret sets the HMAC key for session cookies.
// Priority: CULVERT_SESSION_SECRET env > config file > random.
func initSessionSecret() {
	// Check the raw value for absence first — trimming before the emptiness
	// check would make a whitespace-only value indistinguishable from unset
	// and silently install a random key with no diagnostic. Only a value
	// that was actually left unset should take the random-key path; an
	// explicitly-set-but-invalid value (including whitespace-only) must
	// still hit the panic below.
	if raw := os.Getenv("CULVERT_SESSION_SECRET"); raw != "" {
		key, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil || len(key) < 32 {
			panic("CULVERT_SESSION_SECRET must be at least 32 bytes of hex (64 hex chars)")
		}
		session.SetSigningKey(key)
		logger.Printf("Session: using shared signing key from CULVERT_SESSION_SECRET")
		return
	}
	session.InitRandomKey()
}

// initSessionSecretFromConfig applies a config-file session secret.
// Called after config is loaded, before the UI starts.
func initSessionSecretFromConfig(hexKey string) {
	// Same raw-then-trim ordering as initSessionSecret: an unset field must
	// stay silent, but an explicitly-set whitespace-only value must still
	// warn (not silently fall back with no diagnostic).
	if hexKey == "" {
		return // keep env or random key
	}
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(key) < 32 {
		logWarnf("Session: session_secret must be ≥32 bytes hex — ignoring, using random key")
		return
	}
	session.SetSigningKey(key)
	logger.Printf("Session: using shared signing key from config file")
}

func newSessionJti() string { return session.NewJti() }

func getSessionTTL() time.Duration { return session.TTL() }

// SetSessionTTL updates the session lifetime. Clamped to [15min, 7d].
func SetSessionTTL(d time.Duration) { session.SetTTL(d) }

func encodeSession(s *Session) (string, error) { return session.Encode(s) }

func decodeSession(raw string) (*Session, error) { return session.Decode(raw) }

// sessionIdentity converts the session payload into the canonical Identity
// object. (Was Session.Identity(); a method can no longer live on the
// aliased package type because Identity is a main hub type.)
func sessionIdentity(s *Session) *Identity {
	return &Identity{
		Sub:      s.Sub,
		Email:    s.Email,
		Name:     s.Name,
		Groups:   s.Groups,
		Provider: s.Provider,
	}
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
			if err := sessionRevoked.SaveRevocations(); err != nil {
				logger.Printf("Session: failed to persist revocations: %v", err)
			}
		}
	}
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
		Jti:      newSessionJti(),
	}
	value, err := encodeSession(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamic: true when TLS, false for plain HTTP (by design)
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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamic: true when TLS, false for plain HTTP (by design)
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}
