package main

import (
	"errors"
	"testing"
	"time"
)

// The local protocol constant stays byte-equal to the producer/verifier one.
func TestSaaSFeedProtocol_SSOT(t *testing.T) {
	if !saasFeedProtocolSSOT() {
		t.Fatalf("saasFeedProtocolV1 (%q) must equal urlcatfeed.Protocol", saasFeedProtocolV1)
	}
}

// The built-in URL satisfies the official-origin contract.
func TestBuiltinURL_IsOfficial(t *testing.T) {
	if err := validateOfficialManifestURL(builtinSaaSFeedURL); err != nil {
		t.Fatalf("built-in URL must pass the official contract: %v", err)
	}
}

// Every URL-contract rejection class is caught (F0 §A.8).
func TestValidateOfficialManifestURL_RejectionClasses(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want error
	}{
		{"non-https", "http://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json", ErrFeedURLScheme},
		{"non-official host", "https://evil.example.com/v1/url-categories/saas/manifest.sigstore.json", ErrFeedURLHost},
		{"userinfo", "https://user:pass@feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json", ErrFeedURLUserinfo},
		{"explicit port", "https://feeds.culvertlabs.com:8443/v1/url-categories/saas/manifest.sigstore.json", ErrFeedURLPort},
		{"ip literal", "https://93.184.216.34/v1/url-categories/saas/manifest.sigstore.json", ErrFeedURLHost},
		{"query", "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json?x=1", ErrFeedURLQuery},
		{"fragment", "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json#frag", ErrFeedURLFragment},
		{"non-canonical path", "https://feeds.culvertlabs.com/v1/url-categories/saas/other.json", ErrFeedURLPath},
		{"root path", "https://feeds.culvertlabs.com/", ErrFeedURLPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOfficialManifestURL(tc.url)
			if !errors.Is(err, tc.want) {
				t.Fatalf("url %q: want %v; got %v", tc.url, tc.want, err)
			}
		})
	}
}

// resolveFeedURL applies the matrix: unset/historical ⇒ built-in; official ⇒
// itself; unsupported ⇒ rejected.
func TestResolveFeedURL_Matrix(t *testing.T) {
	if got, err := resolveFeedURL(""); err != nil || got != builtinSaaSFeedURL {
		t.Errorf("empty ⇒ built-in; got %q, %v", got, err)
	}
	for _, h := range historicalSaaSFeedURLs {
		if got, err := resolveFeedURL(h); err != nil || got != builtinSaaSFeedURL {
			t.Errorf("historical %q ⇒ built-in; got %q, %v", h, got, err)
		}
	}
	if got, err := resolveFeedURL(builtinSaaSFeedURL); err != nil || got != builtinSaaSFeedURL {
		t.Errorf("official ⇒ itself; got %q, %v", got, err)
	}
	if _, err := resolveFeedURL("https://mirror.example.com/feed.json"); err == nil {
		t.Errorf("arbitrary mirror must be rejected (no generic mirror capability)")
	}
}

// Protocol restriction: empty canonicalizes; only signed_manifest_v1 is legal;
// an unsigned/raw scheme name is rejected (no fallback).
func TestResolveFeedProtocol(t *testing.T) {
	for _, in := range []string{"", "signed_manifest_v1"} {
		if got, err := resolveFeedProtocol(in); err != nil || got != saasFeedProtocolV1 {
			t.Errorf("protocol %q ⇒ %q; got %q, %v", in, saasFeedProtocolV1, got, err)
		}
	}
	for _, bad := range []string{"legacy_raw_json_v0", "raw", "unsigned", "signed_manifest_v2"} {
		if _, err := resolveFeedProtocol(bad); !errors.Is(err, ErrFeedProtocol) {
			t.Errorf("protocol %q must be rejected; got %v", bad, err)
		}
	}
}

// Refresh resolution: 0 ⇒ default, sub-minimum clamps up, negative rejected.
func TestResolveFeedRefresh(t *testing.T) {
	if d, err := resolveFeedRefresh(0); err != nil || d != saasFeedDefaultRefresh {
		t.Errorf("0 ⇒ default; got %v, %v", d, err)
	}
	if d, err := resolveFeedRefresh(60); err != nil || d != saasFeedMinRefresh {
		t.Errorf("sub-min clamps to min; got %v, %v", d, err)
	}
	if d, err := resolveFeedRefresh(7200); err != nil || d != 2*time.Hour {
		t.Errorf("2h passes through; got %v, %v", d, err)
	}
	if _, err := resolveFeedRefresh(-1); !errors.Is(err, ErrFeedRefresh) {
		t.Errorf("negative rejected; got %v", err)
	}
}

// parseRefreshInterval rejects malformed/non-positive duration strings.
func TestParseRefreshInterval(t *testing.T) {
	if secs, err := parseRefreshInterval("2h"); err != nil || secs != 7200 {
		t.Errorf("2h ⇒ 7200s; got %d, %v", secs, err)
	}
	if secs, err := parseRefreshInterval(""); err != nil || secs != 0 {
		t.Errorf("empty ⇒ 0 (default at resolve); got %d, %v", secs, err)
	}
	for _, bad := range []string{"24x", "abc", "-1h", "0"} {
		if _, err := parseRefreshInterval(bad); !errors.Is(err, ErrFeedRefresh) {
			t.Errorf("malformed %q must be rejected; got %v", bad, err)
		}
	}
}

// The F0 §3 single-source resolution rule.
func TestResolveSaaSFeedConfig(t *testing.T) {
	// Fresh (unmanaged) ⇒ on-by-default, built-in URL.
	got, err := ResolveSaaSFeedConfig(&AdminSettings{})
	if err != nil {
		t.Fatalf("fresh resolve: %v", err)
	}
	if got.Managed || !got.Enabled || got.URL != builtinSaaSFeedURL || got.Protocol != saasFeedProtocolV1 || got.Refresh != saasFeedDefaultRefresh {
		t.Errorf("fresh config wrong: %+v", got)
	}
	// Explicit durable disable.
	got, err = ResolveSaaSFeedConfig(&AdminSettings{SaaSFeedManaged: true, SaaSFeedEnabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Managed || got.Enabled {
		t.Errorf("managed+disabled must resolve enabled=false: %+v", got)
	}
	// Unsupported persisted URL ⇒ error (caller treats as disabled).
	if _, err := ResolveSaaSFeedConfig(&AdminSettings{SaaSFeedURL: "https://mirror.example.com/x.json"}); err == nil {
		t.Errorf("unsupported URL must make resolution fail")
	}
}

// The presence-sensitive delta distinguishes absent (nil ⇒ keep base) from an
// explicit false (applied) — the mixed-version-rollout guard schema (§A.2.2).
func TestSaaSFeedConfigDelta_Merge_Presence(t *testing.T) {
	base := SaaSFeedConfig{Managed: true, Enabled: false, URL: builtinSaaSFeedURL, Protocol: saasFeedProtocolV1, Refresh: saasFeedDefaultRefresh}

	// Empty delta (all nil) ⇒ base unchanged, including the durable disable.
	if got := (SaaSFeedConfigDelta{}).Merge(base); got != base {
		t.Errorf("nil delta must keep base; got %+v want %+v", got, base)
	}

	// Explicit false for Enabled is applied even though it is the zero value.
	f := false
	if got := (SaaSFeedConfigDelta{Enabled: &f}).Merge(SaaSFeedConfig{Enabled: true}); got.Enabled {
		t.Errorf("explicit &false must apply; got Enabled=true")
	}

	// nil Managed keeps the base's true; a rolled-back CP omitting the field cannot
	// flip a durably-managed DP.
	tr := true
	if got := (SaaSFeedConfigDelta{Enabled: &tr}).Merge(base); !got.Managed {
		t.Errorf("nil Managed must preserve base.Managed=true (rollback safety)")
	}

	secs := int64(7200)
	if got := (SaaSFeedConfigDelta{RefreshSeconds: &secs}).Merge(base); got.Refresh != 2*time.Hour {
		t.Errorf("RefreshSeconds delta ⇒ 2h; got %v", got.Refresh)
	}
}
