package main

import (
	"crypto/sha256"
	"net/http"
	"testing"
)

// testLoginBindValue is the browser binding the test helpers use; any 43-char
// base64url value of 32 bytes is accepted by loginBindValueOK.
const testLoginBindValue = "dGVzdC1sb2dpbi1iaW5kaW5nLXZhbHVlLTAxMjM0NTY"

// boundLogin returns r carrying the binding /auth/select would have set, so
// a provider will mint login state for it. Present testLoginBindValue as the
// ps_login_bind cookie on the callback (or completion) to be the same browser.
func boundLogin(t *testing.T, r *http.Request) *http.Request {
	t.Helper()
	if !loginBindValueOK(testLoginBindValue) {
		t.Fatal("test binding value is malformed")
	}
	return withLoginBinding(r, sha256.Sum256([]byte(testLoginBindValue)))
}
