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
// Session type
// ---------------------------------------------------------------------------

const (
	sessionCookieName = "ps_session"
	sessionTTL        = 8 * time.Hour
)

// Session is the payload stored inside the signed proxy session cookie.
// It carries just enough identity data to reconstruct an Identity object
// without talking to the IdP on every request.
type Session struct {
	Sub      string   `json:"sub"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"grp,omitempty"`
	Provider string   `json:"pvd"`
	Exp      int64    `json:"exp"` // Unix timestamp
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
func setSessionCookie(w http.ResponseWriter, id *Identity) error {
	s := &Session{
		Sub:      id.Sub,
		Email:    id.Email,
		Name:     id.Name,
		Groups:   id.Groups,
		Provider: id.Provider,
		Exp:      time.Now().Add(sessionTTL).Unix(),
	}
	value, err := encodeSession(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true, // set by proxy on HTTPS; harmless on plain HTTP
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
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
