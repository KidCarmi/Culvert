package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// PR-C19 RED matrix — the tenth Codex round on the Batch 2 PR head
// (923406db), written against that tree BEFORE any correction.
//
//   R10-A  stripUpstreamCredentialsFromSettings decoded ONE JSON value and
//          never looked at the bytes after it, so a settings body whose
//          leading object is credential-free followed by a second value
//          (or trailing garbage) carrying a plaintext legacy upstream URL
//          was returned UNCHANGED and packed verbatim while the manifest
//          asserted credentialsOmitted: true. A body with anything but
//          whitespace after the settings object must fail the backup
//          CLOSED; trailing whitespace stays accepted.
//   R10-B  normalizeHost decided "IPv6" by net.ParseIP(host).To4() == nil,
//          so an IPv4-MAPPED IPv6 spelling (`::ffff:192.0.2.1`, To4()
//          non-nil) was left unbracketed: Authority() produced a URL
//          url.Parse refuses and the pool rebuild silently omitted the
//          persisted entry; the bracketed spelling was refused by the same
//          To4 test. IPv6 URL syntax (a colon) decides, To4() never does,
//          and exactly one bracket pair is preserved.

const r10Canary = "secret-R10-canary"

func TestUpstreamR10_NormalizeBracketsIPv4MappedIPv6BySyntax(t *testing.T) {
	for typed, want := range map[string]string{
		"::ffff:192.0.2.1":   "[::ffff:192.0.2.1]",
		"[::ffff:192.0.2.1]": "[::ffff:192.0.2.1]",
		"::FFFF:192.0.2.1":   "[::ffff:192.0.2.1]",
		"::ffff:c000:201":    "[::ffff:c000:201]",
		"64:ff9b::192.0.2.1": "[64:ff9b::192.0.2.1]",
	} {
		sp, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: typed, Port: 3128})
		if err != nil || sp.Host != want {
			t.Errorf("host %q: got %q err=%v, want %q", typed, sp.Host, err, want)
			continue
		}
		// The authority the pool rebuild parses must be a URL whose host is
		// the literal — the defect left it unparseable and the entry was
		// silently dropped from the effective pool.
		u, perr := url.Parse(sp.Authority())
		if perr != nil || u.Hostname() != strings.Trim(want, "[]") || u.Port() != "3128" {
			t.Errorf("host %q: authority %q does not parse back to the literal: err=%v", typed, sp.Authority(), perr)
		}
	}
	// A bracketed IPv4 literal and a plain dotted-quad keep their verdicts.
	if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: "[192.0.2.1]", Port: 3128}); err == nil {
		t.Errorf("host %q: expected a refusal, got accepted", "[192.0.2.1]")
	}
	if sp, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: "192.0.2.1", Port: 3128}); err != nil || sp.Host != "192.0.2.1" {
		t.Errorf("host %q: got %q err=%v", "192.0.2.1", sp.Host, err)
	}
}
