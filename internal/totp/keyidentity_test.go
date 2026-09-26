package totp

// Gates for the KEY-IDENTITY surface (SEC-TOTP-1 correction round 2, PR #1429).
//
// decodeSecret/Usable/SameKey exist because a caller deciding whether a stored
// secret still denotes the SAME authenticator must ask the question the
// VERIFIER asks, never compare the stored strings. Two spellings of one secret
// generate identical codes, so treating them as different keys resets the
// replay counter for a LIVE key and reopens the RFC 6238 §5.2 window.
//
// These gates live in this package because the functions are exported security
// primitives of it. The caller-side half — that Config.SetTOTPSecret keeps or
// resets the counter accordingly — is pinned in package main by
// auth_totp_preservation_test.go.

import (
	"strings"
	"testing"
)

const kiSecret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 test vector, not a real credential

// kiSpellings are the ways one authenticator's secret can legitimately reach
// the store: the verifier upper-cases and trims before decoding, so every one
// of these denotes the SAME key and generates the SAME codes.
var kiSpellings = []string{
	kiSecret,
	strings.ToLower(kiSecret),
	"  " + kiSecret + "  ",
	"\t" + strings.ToLower(kiSecret) + "\n",
	"jbswY3dpEHpk3PXp",
}

// kiUnusable are secrets that cannot produce a key at all. None of them can
// validate any code, so none of them is ever "the same key" as anything.
var kiUnusable = []string{
	"",
	"   ",
	"\t\n",
	"not base32!",
	"JBSWY3DPEHPK3PX1", // '1' is not in the RFC 4648 base32 alphabet
	"=",                // padding only, decodes to zero bytes
}

func TestUsable_AcceptsEveryVerifierAcceptedSpelling(t *testing.T) {
	for _, s := range kiSpellings {
		if !Usable(s) {
			t.Errorf("Usable(%q) = false; the verifier decodes this spelling, so it names a key", s)
		}
	}
}

func TestUsable_RejectsSecretsThatAuthenticateNothing(t *testing.T) {
	// A secret that cannot decode must never be reported usable: the caller
	// reads Usable as "there is a key here worth protecting a counter for".
	for _, s := range kiUnusable {
		if Usable(s) {
			t.Errorf("Usable(%q) = true; this secret can validate no code", s)
		}
	}
}

func TestSameKey_SpellingsOfOneSecretAreOneKey(t *testing.T) {
	// The defect this closes: comparing the stored STRINGS read a re-spelt
	// secret as a key change, which zeroed the replay counter for a live key.
	for _, a := range kiSpellings {
		for _, b := range kiSpellings {
			if !SameKey(a, b) {
				t.Errorf("SameKey(%q, %q) = false; both spellings decode to one key", a, b)
			}
		}
	}
}

func TestSameKey_TrailingBitTwinsAreOneKey(t *testing.T) {
	// Case folding alone is NOT sufficient, which is why SameKey decodes.
	// Go's base32 decoder ignores non-canonical trailing bits, so these two
	// strings differ in every case-folded spelling and decode to one key —
	// they generate identical codes, so a counter reset here is a reopened
	// replay window.
	const a, b = "MZXW6", "MZXW7"
	if !SameKey(a, b) {
		t.Fatalf("SameKey(%q, %q) = false; both decode to the same key, so both mint the same codes", a, b)
	}
	// Prove the premise rather than asserting it: the verifier must accept a
	// code minted under a's key when the stored secret is spelt b.
	ka, ok := decodeSecret(a)
	if !ok {
		t.Fatalf("decodeSecret(%q) failed; fixture is wrong", a)
	}
	code := hotp(ka, kiCounter)
	if !kiAccepts(b, code, kiCounter*totpPeriod) {
		t.Fatalf("verifier rejected %q's own code under spelling %q; the twins are not one key after all", a, b)
	}
}

func TestSameKey_DifferentKeysAreNotTheSame(t *testing.T) {
	// The control: SameKey must not simply answer true. A caller that always
	// hears "same key" never resets the counter, so a genuinely new device is
	// refused until wall-clock time passes the old counter.
	const other = "KRSXG5BAMFWWK43UNFXGO===" // #nosec G101 -- test vector, not a real credential
	if SameKey(kiSecret, other) {
		t.Fatalf("SameKey(%q, %q) = true; these decode to different keys", kiSecret, other)
	}
	if SameKey(other, kiSecret) {
		t.Fatalf("SameKey is not symmetric for distinct keys")
	}
}

func TestSameKey_UnusableIsNeverTheSameKey(t *testing.T) {
	// Fail-closed in BOTH directions, and — the case worth stating — an
	// unusable secret is not even the same key as ITSELF. Two blank secrets
	// name no key, so "unchanged" is not a claim SameKey may make about them;
	// the caller distinguishes that case with Usable and keeps the counter for
	// its own reason (no new key to protect), never because SameKey said yes.
	for _, u := range kiUnusable {
		if SameKey(u, u) {
			t.Errorf("SameKey(%q, %q) = true; an unusable secret names no key", u, u)
		}
		if SameKey(u, kiSecret) || SameKey(kiSecret, u) {
			t.Errorf("SameKey(%q, ...) = true against a usable key", u)
		}
	}
}

// kiCounter is a fixed, positive time step. A constant keeps the gates
// deterministic and independent of when the suite runs.
const kiCounter = int64(56_666_666)

// kiAccepts asks the PRODUCTION verifier whether `secret` validates `code` at
// the fixed moment, with replay protection disabled so only key identity is
// under test. Every gate here goes through this one seam, so none of them can
// drift from what authentication really does.
func kiAccepts(secret, code string, at int64) bool {
	ok, _ := verifyTOTPAt(secret, code, at, 0)
	return ok
}

// TestDecodeSecret_IsTheOnlyCanonicalisation is the pin named in decodeSecret's
// own doc comment: the canonicalisation the comparison applies must be the one
// the VERIFIER applies, or the two layers can drift and a live key's counter is
// reset on a re-spelling. It asserts the AGREEMENT rather than either spelling
// of the rule, so it fails against drift introduced from either side.
func TestDecodeSecret_IsTheOnlyCanonicalisation(t *testing.T) {
	key, ok := decodeSecret(kiSecret)
	if !ok {
		t.Fatalf("decodeSecret(%q) failed; fixture is wrong", kiSecret)
	}
	code := hotp(key, kiCounter)
	at := kiCounter * totpPeriod

	for _, s := range kiSpellings {
		// What decodeSecret accepts, the verifier must accept …
		if _, ok := decodeSecret(s); !ok {
			t.Errorf("decodeSecret(%q) = false but the verifier canonicalises this spelling", s)
			continue
		}
		if !kiAccepts(s, code, at) {
			t.Errorf("verifier rejected the key's own code under spelling %q; decodeSecret and verifyTOTPAt disagree", s)
		}
	}

	// … and what it rejects, the verifier must reject. A secret decodeSecret
	// calls unusable must authenticate nothing, or a caller could keep a
	// counter for a secret that is in fact validating codes.
	for _, u := range kiUnusable {
		if _, ok := decodeSecret(u); ok {
			t.Errorf("decodeSecret(%q) = true; fixture claims it is unusable", u)
			continue
		}
		// Probe with GENUINE codes — the ones a real authenticator holding
		// the fixture key would emit around this moment. A secret that
		// decodes to nothing must validate none of them.
		for c := kiCounter - int64(totpSkew); c <= kiCounter+int64(totpSkew); c++ {
			if kiAccepts(u, hotp(key, c), at) {
				t.Fatalf("verifier accepted a real code under unusable secret %q", u)
			}
		}
	}
}

// TestSameKey_AgreesWithTheVerifier is the in-package half of the anti-drift
// wall: for every pair SameKey calls one key, the verifier must accept the
// other spelling's codes, and for every pair it calls different, it must not.
// A SameKey that answered by string comparison, or by case folding alone,
// fails this.
func TestSameKey_AgreesWithTheVerifier(t *testing.T) {
	const other = "KRSXG5BAMFWWK43UNFXGO===" // #nosec G101 -- test vector, not a real credential
	corpus := append(append([]string{}, kiSpellings...), other, "MZXW6", "MZXW7")
	at := kiCounter * totpPeriod

	for _, a := range corpus {
		ka, aok := decodeSecret(a)
		if !aok {
			continue
		}
		code := hotp(ka, kiCounter)
		for _, b := range corpus {
			accepted := kiAccepts(b, code, at)
			if got := SameKey(a, b); got != accepted {
				t.Errorf("SameKey(%q, %q) = %v but the verifier %s a's code under b",
					a, b, got, map[bool]string{true: "ACCEPTED", false: "rejected"}[accepted])
			}
		}
	}
}
