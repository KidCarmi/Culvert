package main

// totp.go — TOTP (RFC 6238) helpers for admin UI 2FA.
//
// Uses github.com/pquerna/otp for secret generation and validation.

import (
	"strings"

	"github.com/pquerna/otp/totp"
)

// verifyTOTP checks a 6-digit code against the stored TOTP secret.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	return totp.Validate(code, secret)
}
