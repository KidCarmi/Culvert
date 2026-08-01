package senderconstraint

import (
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// MTLSInput is the material for an mTLS certificate-binding check. The caller
// supplies the OBSERVED peer certificate SHA-256 thumbprint (base64url) — PR-3
// performs no TLS handshake and no certificate-chain verification — and the
// token's confirmation thumbprint (cnf.x5t#S256).
type MTLSInput struct {
	ObservedThumbprint string // base64url SHA-256 of the observed peer certificate
	TokenX5TS256       string // the token's cnf.x5t#S256
}

func mtlsMismatch(detail string) error {
	return mcperr.New(mcperr.ReasonMTLSBindingMismatch, "senderconstraint.mtls", detail)
}

// VerifyMTLS compares the observed certificate thumbprint with the token's
// cnf.x5t#S256 in constant time. It requires both to be present and canonically
// encoded; a missing binding, missing observation, malformed value, or mismatch is
// rejected. There is no ambiguity with DPoP here — the caller selects mTLS.
func VerifyMTLS(in MTLSInput) (string, error) {
	if in.TokenX5TS256 == "" {
		return "", mtlsMismatch("token carries no x5t#S256 confirmation")
	}
	if in.ObservedThumbprint == "" {
		return "", mtlsMismatch("no observed certificate thumbprint supplied")
	}
	if !canonicalThumbprint(in.TokenX5TS256) || !canonicalThumbprint(in.ObservedThumbprint) {
		return "", mtlsMismatch("thumbprint is not a canonical base64url SHA-256")
	}
	if !jose.ConstantTimeEqual(in.ObservedThumbprint, in.TokenX5TS256) {
		return "", mtlsMismatch("observed certificate does not match the token binding")
	}
	return in.TokenX5TS256, nil
}

// canonicalThumbprint checks that s is a well-formed unpadded base64url SHA-256
// (32 bytes ⇒ 43 base64url chars) — rejecting padded, wrong-length, or non-alphabet
// values so a malformed thumbprint can never spuriously compare equal.
func canonicalThumbprint(s string) bool {
	b, err := jose.B64URLDecode(s)
	if err != nil || len(b) != 32 {
		return false
	}
	// Re-encoding must round-trip exactly (rejects non-canonical encodings).
	return jose.B64URLEncode(b) == s
}
