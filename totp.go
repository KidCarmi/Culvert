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
	"strings"
	"time"
)

const (
	totpPeriod = 30 // seconds
	totpDigits = 6
	totpSkew   = 1 // ±1 step tolerance
)

// verifyTOTP checks a 6-digit code against the stored TOTP secret.
//
// Backwards-compatible wrapper around verifyTOTPAt; callers that need replay
// protection MUST use verifyTOTPReturnCounter and persist the matched counter
// (see Config.SetTOTPLastCounter). Empty secrets are rejected fail-closed to
// prevent validating against a zero-key HMAC in misconfigured/orphaned records.
func verifyTOTP(secret, code string) bool {
	ok, _ := verifyTOTPReturnCounter(secret, code, time.Now().Unix(), 0)
	return ok
}

// verifyTOTPReturnCounter validates a TOTP code and returns (ok, counter) where
// counter is the matched time-step. Callers MUST track the last-matched counter
// per user and reject codes whose matched counter is <= lastCounter to close
// the replay window (RFC 6238 §5.2). Passing lastCounter = 0 disables replay
// protection (legacy call sites).
//
// A nowUnix parameter is taken instead of calling time.Now() so tests can
// exercise the function deterministically without clock monkey-patching.
func verifyTOTPReturnCounter(secret, code string, nowUnix, lastCounter int64) (bool, int64) {
	return verifyTOTPAt(secret, code, nowUnix, lastCounter)
}

func verifyTOTPAt(secret, code string, nowUnix, lastCounter int64) (bool, int64) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false, 0
	}
	// Reject any non-digit characters early — prevents base10/base32 confusion
	// and ensures the constant-time compare below is comparing like strings.
	for _, r := range code {
		if r < '0' || r > '9' {
			return false, 0
		}
	}

	secret = strings.ToUpper(strings.TrimSpace(secret))
	if secret == "" {
		// Empty secret must NEVER validate any code — otherwise an orphaned
		// user record with a blank secret could authenticate an attacker who
		// can predict the deterministic HMAC output of an empty key.
		return false, 0
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return false, 0
	}

	counter := nowUnix / totpPeriod

	for i := -int64(totpSkew); i <= int64(totpSkew); i++ {
		candidate := counter + i
		// Replay protection: reject codes whose matched counter is at or
		// before the last successfully-used counter.
		if lastCounter > 0 && candidate <= lastCounter {
			continue
		}
		expected := hotp(key, candidate)
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, candidate
		}
	}
	return false, 0
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
	otp := trunc % totpModulus

	return fmt.Sprintf("%06d", otp)
}

// totpModulus is 10^totpDigits, computed at init to avoid float math in hotp.
var totpModulus = func() uint32 {
	m := uint32(1)
	for i := 0; i < totpDigits; i++ {
		m *= 10
	}
	return m
}()
