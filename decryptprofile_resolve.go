package main

// decryptprofile_resolve.go — the proxy hot-path resolvers that turn a matched
// rule's DecryptionProfile reference into a runtime decision. These are the "how"
// half of decryption; the engine (internal/decryptprofile) owns only storage +
// validation.
//
// FAIL-SAFE AT EVAL (the load-bearing invariant, not apply-ordering): every
// resolver reads globalDecryptionProfiles at request time. A rule that names a
// profile which does not exist (deleted, never synced, mid-apply window) resolves
// as "no profile" and falls back to the rule's inline field / engine default —
// which for InspectHTTP2 is strip/HTTP-1.1 and for cert-verify is the rule's
// TLSSkipVerify. A dangling reference can therefore only degrade H2→H1 inspection
// or keep today's verify posture; it can NEVER turn inspection off (that decision
// is resolveSSLAction, which never consults a profile).

import (
	"crypto/tls"
	"time"
)

// resolveDecryptionProfile returns the profile named by the matched rule, or nil
// when the rule names none OR the named profile does not exist (dangling ref).
func resolveDecryptionProfile(match *PolicyMatch) *DecryptionProfile {
	if match == nil || match.Rule == nil || match.Rule.DecryptionProfile == "" {
		return nil
	}
	return globalDecryptionProfiles.GetByName(match.Rule.DecryptionProfile)
}

// resolveStripALPN decides whether an SSL-inspected tunnel is downgraded to
// HTTP/1.1 (strip — today's default) or inspected natively as HTTP/2. Precedence:
//
//  1. profile InspectHTTP2 (if the rule binds a profile that sets it): true ⇒
//     native H2 (strip=false); false ⇒ force strip.
//  2. rule.StripALPN inline field (presence-aware, the pre-profile control).
//  3. default ⇒ strip (true) — a pre-feature rule never silently switches to H2.
//
// Only meaningful when SSLAction==Inspect; the Bypass path never consults it.
func resolveStripALPN(match *PolicyMatch) bool {
	if p := resolveDecryptionProfile(match); p != nil && p.InspectHTTP2 != nil {
		return !*p.InspectHTTP2 // InspectHTTP2=true ⇒ do NOT strip (native H2)
	}
	if match == nil || match.Rule == nil || match.Rule.StripALPN == nil {
		return true
	}
	return *match.Rule.StripALPN
}

// resolveH2StallTimeout returns the per-stream inactivity bound for an inspected
// H2 tunnel: the profile's StallTimeoutSecs when set (>0), else the engine default
// (h2StreamStallTimeout). Read per stream in h2InspectStream — never touches the
// shared PR3d http2.Server.
func resolveH2StallTimeout(match *PolicyMatch) time.Duration {
	if p := resolveDecryptionProfile(match); p != nil && p.StallTimeoutSecs > 0 {
		return time.Duration(p.StallTimeoutSecs) * time.Second
	}
	return h2StreamStallTimeout
}

// resolveInspectSkipVerify decides upstream (origin) certificate verification for
// the inspect leg. Profile CertVerification precedence:
//
//	"skip"                 ⇒ skip verification (== today's TLSSkipVerify=true)
//	"strict" | "permissive"⇒ verify (permissive's allow-on-fail is DEFERRED, so it
//	                          verifies like strict for now)
//	"" (inherit) / no profile ⇒ the rule's inline TLSSkipVerify (ruleSkip)
func resolveInspectSkipVerify(match *PolicyMatch, ruleSkip bool) bool {
	if p := resolveDecryptionProfile(match); p != nil {
		switch p.CertVerification {
		case "skip":
			return true
		case "strict", "permissive":
			return false
		}
	}
	return ruleSkip
}

// tlsVersionFromString maps a profile TLS-version string to the crypto/tls
// constant; unknown/"" returns def.
func tlsVersionFromString(s string, def uint16) uint16 {
	switch s {
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return def
	}
}

// applyProfileUpstreamTLSVersions raises/caps the upstream inspect handshake's TLS
// floor/ceiling from the matched profile. The default floor (TLS 1.2) is
// preserved when the profile doesn't set MinTLSVersion; MaxVersion stays unset
// (Go picks the highest) unless the profile caps it. Origin leg only in v1 — the
// client-facing forged leaf keeps its own 1.2 floor.
func applyProfileUpstreamTLSVersions(cfg *tls.Config, match *PolicyMatch) {
	p := resolveDecryptionProfile(match)
	if p == nil {
		return
	}
	if v := tlsVersionFromString(p.MinTLSVersion, 0); v != 0 {
		cfg.MinVersion = v
	}
	if v := tlsVersionFromString(p.MaxTLSVersion, 0); v != 0 {
		cfg.MaxVersion = v
	}
}

// upstreamInspectTLSConfigForMatch builds the upstream inspect tls.Config with the
// matched profile's cert-verification + TLS-version posture applied. ruleSkip is
// the rule's inline TLSSkipVerify (the inherit fallback).
func upstreamInspectTLSConfigForMatch(hostOnly string, ruleSkip bool, match *PolicyMatch) *tls.Config {
	cfg := upstreamInspectTLSConfig(hostOnly, resolveInspectSkipVerify(match, ruleSkip))
	applyProfileUpstreamTLSVersions(cfg, match)
	return cfg
}
