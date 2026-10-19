package main

// auth_select_relay.go — the sign-in page honours a post-login destination
// only when Culvert itself chose it (#1528 login-binding review).
//
// /auth/select?relay=… is public, and with one eligible provider it continues
// to the IdP without a click; a browser with a live IdP session then comes
// back through the callback and is redirected to the relay. Left unsigned,
// https://<ui>/auth/select?relay=https://evil.example is a zero-click open
// redirect that STARTS on the trusted UI host. The proxy's captive redirect
// (uiSelectURL) is the only producer of a non-root relay, so it signs the
// relay and the provider filter with the session signing key under a
// purpose label and a short expiry; anything unsigned, tampered or expired
// signs in and lands on "/".

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strconv"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// selectRelayTTL bounds how long a captive redirect may sit before the user
// follows it. A late follow still signs in; it only loses the destination.
const selectRelayTTL = 15 * time.Minute

// selectRelayMAC is the HMAC over the purpose label, expiry, relay and
// provider filter. The label keeps this value from ever verifying as (or
// being produced from) any other use of the session key: session tokens MAC a
// base64url payload, which cannot contain the label's "/" or newline bytes.
func selectRelayMAC(key []byte, exp int64, relay, providers string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("culvert/auth-select-relay/v1\n" + strconv.FormatInt(exp, 10) + "\n" + relay + "\n" + providers)) //nolint:errcheck // hash.Hash.Write never returns an error
	return m.Sum(nil)
}

// signSelectQuery adds exp+sig to a sign-in query that carries relay and
// providers. Without a signing key it adds nothing, and the page then falls
// back to "/" — the safe direction.
func signSelectQuery(q url.Values, now time.Time) {
	key := session.SigningKey()
	if len(key) == 0 {
		return
	}
	exp := now.Add(selectRelayTTL).Unix()
	q.Set("exp", strconv.FormatInt(exp, 10))
	q.Set("sig", base64.RawURLEncoding.EncodeToString(selectRelayMAC(key, exp, q.Get("relay"), q.Get("providers"))))
}

// selectRelayFromQuery returns the relay the sign-in page may honour: the
// signed one while its signature and expiry hold, else "/".
func selectRelayFromQuery(q url.Values, now time.Time) string {
	relay := q.Get("relay")
	if relay == "" || relay == "/" {
		return "/"
	}
	key := session.SigningKey()
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	sig, serr := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	if len(key) == 0 || err != nil || serr != nil || now.Unix() > exp ||
		!hmac.Equal(sig, selectRelayMAC(key, exp, relay, q.Get("providers"))) {
		return "/"
	}
	return relay
}
