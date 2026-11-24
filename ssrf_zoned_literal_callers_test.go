package main

// The SSRF pre-flight guard classified a zoned IPv6 literal as public
// (internal/ssrf, classifyAnswers). The guard is shared, so each class of
// caller is pinned here in the form it hands the guard: url.URL.Host
// (bracketed, with port), url.URL.Hostname (bare), and the redirect-target
// check, which is the one caller with no connect-time guard behind it.
// Measured before the fix: every row below was accepted.

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

func TestSSRFGuard_ZonedLiteralIsRefusedForEveryCallerShape(t *testing.T) {
	ssrf.CacheReset()
	t.Cleanup(ssrf.CacheReset)
	for _, raw := range []string{
		"http://[fe80::1%25lo]:80/", "https://[fe80::1%25eth0]:8443/hook",
		"http://[::1%25lo]:8080/", "http://[fd00::1%25lo]:80/", "http://[::ffff:127.0.0.1%25lo]:80/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		// Admin-configured outbound targets: OIDC/SAML metadata, OTLP,
		// bootstrap and release URLs, OCSP (u.Host); feeds (u.Hostname).
		// (Every URL here carries a port: a bracketed host without one is
		// not a key the resolver answers, so it was already refused.)
		for shape, hostport := range map[string]string{"u.Host": u.Host, "u.Hostname": u.Hostname()} {
			if err := isPrivateHost(hostport); err == nil {
				t.Errorf("%s: isPrivateHost(%s = %q) = nil: classified public", raw, shape, hostport)
			}
			if err := isPrivateHostContext(context.Background(), hostport); err == nil {
				t.Errorf("%s: isPrivateHostContext(%s) = nil", raw, shape)
			}
			// Data-plane tunnel paths (CONNECT, WebSocket, SOCKS5).
			if err := isPrivateHostBounded(context.Background(), hostport); err == nil {
				t.Errorf("%s: isPrivateHostBounded(%s) = nil", raw, shape)
			}
		}
		if err := isPrivateHost(u.Hostname()); !errors.Is(err, errSSRFBlocked) {
			t.Errorf("%s: %v, want an SSRF-blocked verdict for a known-internal address", raw, err)
		}
		// Redirect targets (policy Redirect action at ingress and at serve
		// time, login relay): nothing dials, so this check is the only guard.
		if isSafeRedirectURL(raw) {
			t.Errorf("isSafeRedirectURL(%s) = true: a client would be redirected to a link-scoped internal address", raw)
		}
	}
	// Controls: unzoned internal literals were always refused; a public
	// literal is still a valid redirect target.
	for _, raw := range []string{"http://[fe80::1]:80/", "http://[::1]:80/"} {
		if isSafeRedirectURL(raw) {
			t.Errorf("control: isSafeRedirectURL(%s) = true", raw)
		}
	}
	if !isSafeRedirectURL("https://[2606:4700:4700::1111]:443/") {
		t.Error("control: a public IPv6 literal is no longer a valid redirect target")
	}
}

// The connect-time guard was already fail-closed for a zoned peer address;
// pinned so the two layers stay consistent.
func TestSSRFGuard_ConnectTimeControlRefusesAZonedPeer(t *testing.T) {
	for _, addr := range []string{"[fe80::1%lo]:80", "[::1%lo]:443"} {
		if err := ssrfControl("tcp6", addr, nil); !errors.Is(err, errSSRFBlocked) {
			t.Errorf("ssrfControl(%q) = %v, want blocked", addr, err)
		}
	}
}
