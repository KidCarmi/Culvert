package main

// totp.go — TOTP (RFC 6238) validation using only the standard library.
// Implements HMAC-SHA1 based one-time password with a 30-second step,
// 6-digit output, and ±1 step tolerance for clock skew.

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 — RFC 6238 TOTP mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	totpPeriod = 30 // seconds
	totpDigits = 6
	totpSkew   = 1 // ±1 step tolerance
)

// verifyTOTP checks a 6-digit code against the stored TOTP secret.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(strings.TrimSpace(secret)),
	)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	counter := now / totpPeriod

	for i := -int64(totpSkew); i <= int64(totpSkew); i++ {
		if hotp(key, counter+i) == code {
			return true
		}
	}
	return false
}

// hotp computes an HOTP value per RFC 4226.
func hotp(key []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter)) // #nosec G115 — counter is always positive (Unix timestamp / 30)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	trunc := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	otp := trunc % uint32(math.Pow10(totpDigits))

	return fmt.Sprintf("%06d", otp)
}
