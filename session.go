package main

// session.go — Session shim: aliases + startup wiring + HTTP cookie helpers
// over internal/session (ADR-0002). The engine — signing-key holder (now
// race-safe: the DP cluster sync replaces the key at runtime), token
// encode/decode, revocation list + persistence, TTL, jti — lives in the
// package. main keeps: env/config key priority (env is read HERE per the
// startup-slice convention), the cookie helpers (isSecureRequest + the
// Identity hub type), and the Session→Identity conversion.

import (
	"encoding/hex"
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

// initSessionSecret sets the HMAC key for session cookies. Reports whether
// CULVERT_SESSION_SECRET supplied it, so the caller (loadSession) can keep
// the documented priority — CULVERT_SESSION_SECRET env > config file >
// random — instead of letting a subsequent config-file value unconditionally
// clobber an explicit env key.
func initSessionSecret() bool {
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
		return true
	}
	session.InitRandomKey()
	return false
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

// revokeSessionCookie adds the cookie from r to the revocation list, if and
// only if this appliance signed it.
//
// CHAOS-73. The previous body decoded the cookie and inserted its payload
// WITHOUT verifying the HMAC, on the explicit but mistaken reasoning that the
// signature had "already [been] verified by decodeSession". It has not been on
// this path: `/api/auth/logout` is PUBLIC and apiAuthLogout calls this
// function unconditionally, not only when readUISessionCookie returned a
// session. An unauthenticated caller therefore chose the retained key, its
// length and its expiry — see session_revocation_bounds.go for the measured
// consequences (a 524 KB forged cookie retained with a 100-year expiry, and
// quadratic disk write amplification), and for why verifying is strictly
// better here than bounding.
//
// Verification loses nothing. A revocation key is the payload half of a cookie
// we signed, so a cookie we did not sign cannot name a session of ours; and
// the MAC is checked BEFORE the expiry (as in Decode), so the expired cookie
// this public route exists to clear still verifies and still logs out.
//
// The cookie is cleared by the caller either way. A refusal must not tell an
// unauthenticated prober whether the cookie it sent was genuine.
func revokeSessionCookie(cookieName string, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	changed, reason := sessionRevoked.RevokeVerified(c.Value)
	if !changed {
		// Two of the no-change reasons are ORDINARY TRAFFIC and must not be
		// charged to the probe counter, or the one signal an operator has that
		// the public endpoint is being attacked is buried in normal use:
		//
		//   RevokeAlreadyKnown — a replayed logout of a cookie we already hold
		//     (a double-submit, or a browser retrying). Also deliberately NOT
		//     persisted: "a mutation reporting no change issues no write"
		//     (CHAOS-70), which is most of what made the amplification
		//     quadratic even for an authenticated caller.
		//
		//   RevokeExpired — a genuine cookie whose session already lapsed,
		//     which is exactly what a user coming back the next day and
		//     clicking Log out produces. Decode rejects it on expiry alone, so
		//     there is nothing to record. It is still visible in the
		//     per-reason series for diagnostics, just not in the aggregate.
		//
		// Everything else means the caller sent something this appliance did
		// not sign, which ordinary traffic cannot produce.
		if reason != session.RevokeAlreadyKnown && reason != session.RevokeExpired {
			noteSessionRevokeRefusal(r, reason, len(c.Value))
		}
		return
	}
	if err := sessionRevoked.SaveRevocations(); err != nil {
		logger.Printf("Session: failed to persist revocations: %v", err)
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
