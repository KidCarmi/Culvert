package main

// totp.go — TOTP (RFC 6238) helpers for admin UI 2FA.
//
// Uses github.com/pquerna/otp for secret generation and validation.
// Backup codes are 8 x 8-char alphanumeric strings, stored as bcrypt hashes.

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	totpIssuer        = "ProxyShield"
	totpWindowPeriod  = 1 // allow ±1 period (90-second tolerance)
	backupCodeCount   = 8
	backupCodeLength  = 8
	backupCodeCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // unambiguous characters
)

// generateTOTPSecret creates a new TOTP secret for username.
// Returns the base32 secret and an otpauth:// URL for QR-code display.
func generateTOTPSecret(username string) (secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// verifyTOTP checks a 6-digit code against the stored TOTP secret.
// Accepts ±1 period (configurable via totpWindowPeriod).
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	return totp.Validate(code, secret)
}

// generateBackupCodes creates a set of one-time backup codes.
// Returns the plaintext codes (to show to the user once) and their bcrypt hashes.
func generateBackupCodes() (plain, hashed []string, err error) {
	for i := 0; i < backupCodeCount; i++ {
		code, err := randomString(backupCodeLength, backupCodeCharset)
		if err != nil {
			return nil, nil, fmt.Errorf("generate backup code: %w", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, fmt.Errorf("hash backup code: %w", err)
		}
		plain = append(plain, code)
		hashed = append(hashed, string(hash))
	}
	return plain, hashed, nil
}

// randomString generates a cryptographically random string of length n
// using only characters from charset.
func randomString(n int, charset string) (string, error) {
	b := make([]byte, n)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b), nil
}

// encodeBase32Secret ensures the secret is valid base32 (no padding).
func encodeBase32Secret(raw []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}
