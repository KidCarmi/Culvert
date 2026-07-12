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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// recordInspectUpstreamALPN counts the HTTP protocol negotiated on the upstream
// (origin) leg of an inspected tunnel — the success-delta signal for
// Inspect-as-HTTP/2 (h2 = native inspection working; anything else = HTTP/1.1).
func recordInspectUpstreamALPN(proto string) {
	if proto == "h2" {
		atomic.AddInt64(&statInspectUpstreamH2, 1)
	} else {
		atomic.AddInt64(&statInspectUpstreamH1, 1)
	}
}

// profileRejectCounter is a cardinality-capped per-profile counter for upstream
// inspect-handshake failures on tunnels whose profile set a min-TLS floor. It makes
// the "floor an origin can't meet → silent 502" case VISIBLE and attributable — the
// field guardrail the reviewers required (otherwise a MinTLSVersion=1.3 against a
// 1.2-only origin just fails into a generic 502 with no signal).
type profileRejectCounter struct {
	mu     sync.RWMutex
	counts map[string]*int64
	order  []string
}

const maxDecProfRejectLabels = 200 // bound label cardinality (profile names are admin-created, but cap defensively)

var decProfMintlsRejects = &profileRejectCounter{counts: make(map[string]*int64)}

func (c *profileRejectCounter) record(profile string) {
	if profile == "" {
		return
	}
	c.mu.RLock()
	ctr, ok := c.counts[profile]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(ctr, 1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctr, ok = c.counts[profile]; ok {
		atomic.AddInt64(ctr, 1)
		return
	}
	if len(c.order) >= maxDecProfRejectLabels {
		profile = "_other_" // fold overflow into a shared bucket
		if ctr, ok = c.counts[profile]; ok {
			atomic.AddInt64(ctr, 1)
			return
		}
	}
	var n int64 = 1
	c.counts[profile] = &n
	c.order = append(c.order, profile)
}

// writePrometheus emits the counter. Profile names are validated to a safe charset
// (no quotes/newlines) at write time, but the label value is inline-sanitized so
// CodeQL sees the guard.
func (c *profileRejectCounter) writePrometheus(w *strings.Builder) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.order) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_decrypt_profile_mintls_reject_total Upstream inspect-handshake failures on tunnels whose decryption profile set a min-TLS floor (visible signal for a floor an origin can't meet)\n")
	w.WriteString("# TYPE culvert_decrypt_profile_mintls_reject_total counter\n")
	for _, p := range c.order {
		safe := strings.ReplaceAll(p, `"`, "")
		fmt.Fprintf(w, "culvert_decrypt_profile_mintls_reject_total{profile=%q} %d\n", safe, atomic.LoadInt64(c.counts[p]))
	}
}

// recordProfileMintlsReject counts an upstream inspect-handshake failure against the
// matched profile IFF that profile set a min-TLS floor — the operator-configured
// constraint most likely to break a rule's traffic (an origin below the floor).
func recordProfileMintlsReject(match *PolicyMatch) {
	if p := resolveDecryptionProfile(match); p != nil && p.MinTLSVersion != "" {
		decProfMintlsRejects.record(p.Name)
	}
}

// mintlsHint appends an operator-actionable hint to an upstream-handshake-error log
// when the matched profile set a min-TLS floor, so the failure is attributable
// rather than a generic 502 (the field-support-ticket cause the reviewers flagged).
func mintlsHint(match *PolicyMatch) string {
	p := resolveDecryptionProfile(match)
	if p == nil || p.MinTLSVersion == "" {
		return ""
	}
	return fmt.Sprintf(" — decryption profile %q sets min-TLS %s; the origin may not meet the floor",
		strings.ReplaceAll(p.Name, `"`, ""), p.MinTLSVersion)
}

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
