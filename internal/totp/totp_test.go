package totp

// Whitebox tests for the TOTP (RFC 6238) implementation. Moved verbatim from
// qa_gate_test.go and security_coverage_test.go during the internal/totp
// extraction (ADR-0002 proving PR); only verifyTOTPReturnCounter was renamed to
// the exported VerifyTOTPReturnCounter. No assertions changed.

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// ─── 1. TOTP empty-secret rejection ─────────────────────────────────────────

func TestVerifyTOTP_RejectsEmptyAndBlankSecret(t *testing.T) {
	// Historical bug: an empty base32 secret decoded to an empty HMAC key
	// which still produced a deterministic (and predictable) OTP. verifyTOTP
	// must now fail-closed on empty/whitespace secrets.
	cases := []string{"", "   ", "\t\n"}
	for _, s := range cases {
		if verifyTOTP(s, "123456") {
			t.Errorf("verifyTOTP must reject empty/blank secret %q", s)
		}
	}
}

// ─── 2. TOTP replay protection ──────────────────────────────────────────────

// deriveCodeAt produces the OTP a real authenticator would for (secret, t).
func deriveCodeAt(t *testing.T, secret string, unix int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return hotp(key, unix/totpPeriod)
}

func TestVerifyTOTPReturnCounter_ReplayRejected(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 test vector, not a real credential
	now := int64(1_700_000_000)       // deterministic moment
	code := deriveCodeAt(t, secret, now)

	// First use — must succeed and return the matching counter.
	ok, counter := VerifyTOTPReturnCounter(secret, code, now, 0)
	if !ok || counter == 0 {
		t.Fatalf("first use: ok=%v counter=%d, want ok=true counter>0", ok, counter)
	}

	// Same code a second later is still cryptographically valid, but MUST be
	// rejected because its counter is <= lastCounter. Without replay
	// protection an observer of a single OTP could reuse it for the
	// remainder of the ~90s window.
	ok2, _ := VerifyTOTPReturnCounter(secret, code, now+1, counter)
	if ok2 {
		t.Fatalf("same code must be rejected as replay once lastCounter=%d is recorded", counter)
	}

	// And critically: the very next step of the SAME authenticator MUST still
	// be accepted (replay protection must not lock the user out forever).
	nextCode := deriveCodeAt(t, secret, now+totpPeriod)
	if nextCode == code {
		// Step boundary skipped; bump further to guarantee rollover.
		nextCode = deriveCodeAt(t, secret, now+2*totpPeriod)
	}
	ok3, nextCounter := VerifyTOTPReturnCounter(secret, nextCode, now+totpPeriod+1, counter)
	if !ok3 {
		t.Fatalf("next step code must validate after replay-guarded lastCounter=%d", counter)
	}
	if nextCounter <= counter {
		t.Fatalf("nextCounter=%d must advance past lastCounter=%d", nextCounter, counter)
	}
}

func TestVerifyTOTPReturnCounter_SkewWindow(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 test vector, not a real credential
	now := int64(1_700_000_000)

	// A code from the PREVIOUS step is still accepted because totpSkew=1.
	prev := deriveCodeAt(t, secret, now-totpPeriod)
	ok, counter := VerifyTOTPReturnCounter(secret, prev, now, 0)
	if !ok {
		t.Fatalf("previous-step code must validate within ±%d skew", totpSkew)
	}
	if counter != now/totpPeriod-1 {
		t.Fatalf("matched counter = %d, want %d", counter, now/totpPeriod-1)
	}

	// A code from TWO steps ago must NOT validate (outside skew).
	tooOld := deriveCodeAt(t, secret, now-2*totpPeriod)
	if ok, _ := VerifyTOTPReturnCounter(secret, tooOld, now, 0); ok {
		t.Fatal("code from two steps ago must be outside the skew window")
	}
}

// ─── 3. TOTP code-format hardening ──────────────────────────────────────────

func TestVerifyTOTP_RejectsNonDigitCode(t *testing.T) {
	// Must reject codes that include non-digit runes even if the length is 6.
	// Prevents base10/base32 confusion and ensures the constant-time compare
	// only ever runs on like strings.
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 test vector, not a real credential
	bad := []string{"12345a", "12345 ", "abcdef", "12345\n", "١٢٣٤٥٦"}
	for _, code := range bad {
		if verifyTOTP(secret, code) {
			t.Errorf("verifyTOTP must reject non-digit code %q", code)
		}
	}
}

// ─── 4. TOTP positive round-trip ────────────────────────────────────────────

func TestVerifyTOTP_PositiveRoundTrip(t *testing.T) {
	// Generating a code with the same secret/time MUST validate. Guards
	// against silent hashing-algorithm regressions (the old `math.Pow10`
	// modulus was replaced with a computed integer constant).
	secret := strings.ToUpper("JBSWY3DPEHPK3PXP")
	now := time.Now().Unix()
	code := deriveCodeAt(t, secret, now)
	if !verifyTOTP(secret, code) {
		t.Fatalf("freshly generated code %q did not validate — HOTP regression", code)
	}
}

// ── verifyTOTP ────────────────────────────────────────────────────────────────

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	// A valid base32 secret but wrong code — should return false, not panic.
	secret := "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 test vector, not a real credential
	if verifyTOTP(secret, "000000") {
		t.Error("random code should not validate against secret")
	}
}

func TestVerifyTOTP_EmptyInputs(t *testing.T) {
	if verifyTOTP("", "") {
		t.Error("empty secret+code should not validate")
	}
	if verifyTOTP("JBSWY3DPEHPK3PXP", "") {
		t.Error("empty code should not validate")
	}
	if verifyTOTP("", "123456") {
		t.Error("empty secret should not validate")
	}
}

func TestVerifyTOTP_TrimsWhitespace(t *testing.T) {
	// Whitespace-padded code should behave the same as the trimmed version
	// (both should be false for a wrong code — the important thing is no panic).
	secret := "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 test vector, not a real credential
	r1 := verifyTOTP(secret, " 999999 ")
	r2 := verifyTOTP(secret, "999999")
	if r1 != r2 {
		t.Errorf("whitespace should be trimmed: padded=%v trimmed=%v", r1, r2)
	}
}
