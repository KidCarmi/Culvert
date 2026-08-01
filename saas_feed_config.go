package main

// saas_feed_config.go — F3a-1 feed-configuration schema, constants, the official
// manifest-URL/SSRF contract, and the ownership resolver for the signed SaaS
// URL-category feed (roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §A.1/§A.2/§A.8).
//
// SCOPE (F3a-1): types, constants, validation, and the pure single-source
// resolution rule (F0 §3). There is NO downloader, scheduler, network request,
// activation, or live proxy-path behavior here — nothing in this file fetches or
// arms anything. The presence-sensitive delta (SaaSFeedConfigDelta, *bool) is the
// SCHEMA the CP→DP wire slice (F3a-2) will carry; it is defined and unit-tested
// here but not wired onto ConfigSnapshot in this slice.

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// Feed-configuration constants (F3a §A.1).
const (
	// saasFeedProtocolV1 is the ONLY supported feed protocol (F0 §13). Pinned
	// byte-equal to the producer/verifier constant; saasFeedProtocolSSOT asserts it.
	saasFeedProtocolV1 = "signed_manifest_v1"

	// The official manifest-URL contract (F0 §A.8). Only this exact origin + path
	// (over HTTPS) is accepted; there is no generic mirror capability.
	saasFeedOfficialScheme = "https"
	saasFeedOfficialHost   = "feeds.culvertlabs.com"
	saasFeedManifestPath   = "/v1/url-categories/saas/manifest.sigstore.json"

	// saasFeedDefaultRefresh / saasFeedMinRefresh bound the poll cadence (F3a §A.1).
	saasFeedDefaultRefresh = 24 * time.Hour
	saasFeedMinRefresh     = 1 * time.Hour
)

// builtinSaaSFeedURL is the official built-in manifest URL an unset/rewritten
// configuration resolves to.
const builtinSaaSFeedURL = saasFeedOfficialScheme + "://" + saasFeedOfficialHost + saasFeedManifestPath

// historicalSaaSFeedURLs are the two exact legacy GitHub raw URLs that a pre-F3
// appliance may have persisted (F0 §2.1). They are the only non-official values
// that RESOLVE (read-only) to the built-in endpoint; every other non-empty value
// is rejected. Exact-string match only — a fork must not be caught.
var historicalSaaSFeedURLs = []string{
	saasfeed.DefaultFeedURL, // .../main/internal/urlcat/default_categories.json (current pre-F3 default)
	"https://raw.githubusercontent.com/KidCarmi/Culvert/main/default_categories.json", // pre-urlcat-move default
}

// URL-contract rejection sentinels (F0 §A.8) — one per class so tests and the
// settings-write path can assert the exact reason.
var (
	ErrFeedURLParse       = errors.New("saas feed url: unparseable")
	ErrFeedURLScheme      = errors.New("saas feed url: scheme must be https")
	ErrFeedURLUserinfo    = errors.New("saas feed url: userinfo not allowed")
	ErrFeedURLHost        = errors.New("saas feed url: host must be the official feeds origin")
	ErrFeedURLPort        = errors.New("saas feed url: explicit port not allowed")
	ErrFeedURLIPLiteral   = errors.New("saas feed url: IP-literal host not allowed")
	ErrFeedURLQuery       = errors.New("saas feed url: query not allowed")
	ErrFeedURLFragment    = errors.New("saas feed url: fragment not allowed")
	ErrFeedURLPath        = errors.New("saas feed url: non-canonical manifest path")
	ErrFeedURLUnsupported = errors.New("saas feed url: unsupported value (only the official origin or a historical URL is accepted; no generic mirror)")

	ErrFeedProtocol = errors.New("saas feed protocol: only signed_manifest_v1 is supported (no unsigned/raw fallback)")
	ErrFeedRefresh  = errors.New("saas feed refresh interval: malformed")
)

// SaaSFeedConfig is the RESOLVED, validated feed configuration — the ownership
// representation the (future) downloader engine consumes. Nothing in F3a-1 acts
// on it; it is produced by ResolveSaaSFeedConfig and unit-tested.
type SaaSFeedConfig struct {
	Managed  bool          // operator expressed explicit intent
	Enabled  bool          // effective enable (on-by-default when unmanaged)
	URL      string        // resolved official manifest URL
	Protocol string        // always saasFeedProtocolV1
	Refresh  time.Duration // poll cadence (≥ saasFeedMinRefresh)
}

// SaaSFeedConfigDelta is the PRESENCE-SENSITIVE overlay the CP→DP wire will carry
// (F3a §A.2.2). Pointer fields distinguish "absent" (nil ⇒ keep the base) from an
// explicit value (including a deliberate false) — the mixed-version-rollout guard
// (a rolled-back CP that omits a field must not re-enable a durably-disabled DP).
// Defined here as schema; the ConfigSnapshot wiring is F3a-2.
type SaaSFeedConfigDelta struct {
	Managed        *bool
	Enabled        *bool
	URL            *string
	Protocol       *string
	RefreshSeconds *int64
}

// Merge overlays the non-nil delta fields onto base and returns the result. A nil
// field leaves base untouched; a non-nil field applies even when it is the zero
// value (e.g. a *bool pointing at false).
func (d SaaSFeedConfigDelta) Merge(base SaaSFeedConfig) SaaSFeedConfig {
	out := base
	if d.Managed != nil {
		out.Managed = *d.Managed
	}
	if d.Enabled != nil {
		out.Enabled = *d.Enabled
	}
	if d.URL != nil {
		out.URL = *d.URL
	}
	if d.Protocol != nil {
		out.Protocol = *d.Protocol
	}
	if d.RefreshSeconds != nil {
		out.Refresh = time.Duration(*d.RefreshSeconds) * time.Second
	}
	return out
}

// validateOfficialManifestURL enforces the F0 §A.8 contract on a NON-EMPTY URL:
// exactly https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json
// with no userinfo, no explicit port, no IP-literal host, no query, and no
// fragment. It returns the specific rejection class. This is the reusable
// settings-write validator (used by the F3a-2 API); it is NOT an SSRF substitute —
// the downloader (F3b) still applies a dial-time private-address guard.
func validateOfficialManifestURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFeedURLParse, err)
	}
	if u.Opaque != "" || u.Scheme != saasFeedOfficialScheme {
		return fmt.Errorf("%w: got %q", ErrFeedURLScheme, u.Scheme)
	}
	if u.User != nil {
		return ErrFeedURLUserinfo
	}
	host := u.Hostname()
	if host != saasFeedOfficialHost {
		return fmt.Errorf("%w: got %q", ErrFeedURLHost, host)
	}
	if net.ParseIP(host) != nil {
		return ErrFeedURLIPLiteral
	}
	if u.Port() != "" {
		return fmt.Errorf("%w: got %q", ErrFeedURLPort, u.Port())
	}
	if u.RawQuery != "" || u.ForceQuery {
		return ErrFeedURLQuery
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return ErrFeedURLFragment
	}
	if u.EscapedPath() != saasFeedManifestPath {
		return fmt.Errorf("%w: got %q", ErrFeedURLPath, u.EscapedPath())
	}
	return nil
}

// resolveFeedURL applies the §A.5.3/§15 migration+resolution matrix READ-ONLY:
//   - ""                       ⇒ the built-in official URL
//   - either historical URL    ⇒ the built-in official URL (rewritten)
//   - any official-origin URL  ⇒ itself (validated by the §A.8 contract)
//   - anything else            ⇒ ErrFeedURLUnsupported (via the specific class)
//
// It never mutates persisted state; the destructive rewrite of a persisted legacy
// URL is deferred to the slice that retires the legacy syncer.
func resolveFeedURL(persisted string) (string, error) {
	p := strings.TrimSpace(persisted)
	if p == "" {
		return builtinSaaSFeedURL, nil
	}
	for _, h := range historicalSaaSFeedURLs {
		if p == h {
			return builtinSaaSFeedURL, nil
		}
	}
	if err := validateOfficialManifestURL(p); err != nil {
		return "", err
	}
	return p, nil
}

// resolveFeedProtocol restricts the protocol to signed_manifest_v1. An empty
// value canonicalizes to it; any other (including a raw/unsigned scheme name) is
// rejected — there is no unsigned/raw fallback (F0 §13).
func resolveFeedProtocol(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "", saasFeedProtocolV1:
		return saasFeedProtocolV1, nil
	default:
		return "", fmt.Errorf("%w: got %q", ErrFeedProtocol, raw)
	}
}

// resolveFeedRefresh converts the persisted whole-second interval to a duration:
// 0 ⇒ the default; a positive value is clamped up to the minimum; a negative
// value is malformed and rejected (a fail-safe default is NOT silently
// substituted for a corrupt value).
func resolveFeedRefresh(seconds int64) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("%w: %d seconds", ErrFeedRefresh, seconds)
	}
	if seconds == 0 {
		return saasFeedDefaultRefresh, nil
	}
	d := time.Duration(seconds) * time.Second
	if d < saasFeedMinRefresh {
		return saasFeedMinRefresh, nil
	}
	return d, nil
}

// parseRefreshInterval parses an operator-supplied duration STRING (the
// settings-write form) to whole seconds, rejecting a malformed or non-positive
// value. Exposed for the F3a-2 API; unit-tested here as part of the schema
// boundary.
func parseRefreshInterval(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil // ⇒ default at resolve time
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: %v", ErrFeedRefresh, s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%w: %q must be positive", ErrFeedRefresh, s)
	}
	return int64(d / time.Second), nil
}

// ResolveSaaSFeedConfig applies the F0 §3 single-source rule to the persisted
// AdminSettings, producing the effective feed configuration. It is pure and
// read-only. managed=false means "operator never touched it" ⇒ on-by-default;
// managed=true makes enabled authoritative. An unsupported URL/protocol/refresh
// yields an error (the caller treats an invalid config as a disabled feed).
func ResolveSaaSFeedConfig(s *AdminSettings) (SaaSFeedConfig, error) {
	cfg := SaaSFeedConfig{Managed: s.SaaSFeedManaged}
	cfg.Enabled = true // on-by-default
	if cfg.Managed {
		cfg.Enabled = s.SaaSFeedEnabled
	}
	url, err := resolveFeedURL(s.SaaSFeedURL)
	if err != nil {
		return SaaSFeedConfig{}, err
	}
	cfg.URL = url
	proto, err := resolveFeedProtocol(s.SaaSFeedProtocol)
	if err != nil {
		return SaaSFeedConfig{}, err
	}
	cfg.Protocol = proto
	refresh, err := resolveFeedRefresh(s.SaaSFeedRefreshSeconds)
	if err != nil {
		return SaaSFeedConfig{}, err
	}
	cfg.Refresh = refresh
	return cfg, nil
}

// saasFeedProtocolSSOT keeps the local protocol constant byte-equal to the
// producer/verifier one; referenced by a compile-time-adjacent test.
func saasFeedProtocolSSOT() bool { return saasFeedProtocolV1 == urlcatfeed.Protocol }
