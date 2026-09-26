// Package totp implements TOTP (RFC 6238) validation using only the standard
// library: HMAC-SHA1 with a 30-second step, 6-digit output, and ±1 step clock
// skew. It has no dependencies on the rest of Culvert (first internal/ leaf
// extracted under ADR-0002).
package totp

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
// protection MUST use VerifyTOTPReturnCounter and persist the matched counter
// (see Config.SetTOTPLastCounter in package main). Empty secrets are rejected
// fail-closed to prevent validating against a zero-key HMAC in
// misconfigured/orphaned records.
func verifyTOTP(secret, code string) bool {
	ok, _ := VerifyTOTPReturnCounter(secret, code, time.Now().Unix(), 0)
	return ok
}

// decodeSecret canonicalises a stored TOTP secret and decodes it to the raw
// HMAC key.
//
// This is the ONE place that decides what a stored secret string MEANS.
// verifyTOTPAt generates codes from the key it returns and SameKey answers key
// identity from it, so the two can never disagree about whether two spellings
// name the same authenticator. That agreement is a SECURITY property, not
// tidiness: package main resets the RFC 6238 §5.2 replay counter when the key
// changes, and a comparison that canonicalised differently from the verifier
// would zero the counter for a key that is still live — reopening the replay
// window this field exists to close (Codex review, PR #1429). Pinned by
// TestDecodeSecret_IsTheOnlyCanonicalisation and, from the caller's side, by
// TestTOTPSameKey_AgreesWithTheVerifier.
//
// Returns ok=false for a secret that cannot produce a key at all (empty,
// non-base32, or decoding to zero bytes). Such a secret can never validate a
// code, so it is never "the same key" as anything, including itself.
func decodeSecret(secret string) ([]byte, bool) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if secret == "" {
		return nil, false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return nil, false
	}
	return key, true
}

// Usable reports whether a stored secret decodes to a key that could validate
// a code. A secret that is not usable authenticates nothing.
func Usable(secret string) bool {
	_, ok := decodeSecret(secret)
	return ok
}

// SameKey reports whether two stored secret strings denote the SAME
// authenticator key.
//
// It compares the DECODED keys, never the stored strings: the verifier
// canonicalises case and surrounding whitespace before decoding, so
// "jbswy3dpehpk3pxp", " JBSWY3DPEHPK3PXP " and "JBSWY3DPEHPK3PXP" are one key
// and generate identical codes. A caller deciding whether a key CHANGED must
// ask this question, not whether the stored string changed.
//
// An unusable secret is never the same key as anything, so a caller must treat
// !Usable separately rather than reading false as "the key changed" — see
// Config.SetTOTPSecret in package main.
func SameKey(a, b string) bool {
	ka, aok := decodeSecret(a)
	if !aok {
		return false
	}
	kb, bok := decodeSecret(b)
	if !bok {
		return false
	}
	// Constant-time: these are key material, even though both sides are
	// server-held here.
	return hmac.Equal(ka, kb)
}

// VerifyTOTPReturnCounter validates a TOTP code and returns (ok, counter) where
// counter is the matched time-step. Callers MUST track the last-matched counter
// per user and reject codes whose matched counter is <= lastCounter to close
// the replay window (RFC 6238 §5.2). Passing lastCounter = 0 disables replay
// protection (legacy call sites).
//
// A nowUnix parameter is taken instead of calling time.Now() so tests can
// exercise the function deterministically without clock monkey-patching.
func VerifyTOTPReturnCounter(secret, code string, nowUnix, lastCounter int64) (ok bool, counter int64) {
	return verifyTOTPAt(secret, code, nowUnix, lastCounter)
}

func verifyTOTPAt(secret, code string, nowUnix, lastCounter int64) (ok bool, counter int64) {
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

	// One canonicalisation, shared with SameKey/Usable — see decodeSecret.
	// An empty or undecodable secret must NEVER validate any code: an orphaned
	// user record with a blank secret would otherwise authenticate an attacker
	// who can predict the deterministic HMAC output of a zero-length key.
	key, ok := decodeSecret(secret)
	if !ok {
		return false, 0
	}

	counter = nowUnix / totpPeriod

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
