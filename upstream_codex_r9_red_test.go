package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// PR-C18 RED matrix — the ninth Codex round on the Batch 2 PR head
// (d85df4a0), written against that tree BEFORE any correction.
//
//   R9-A  refuseCredentialBearingLegacyUpstreams skipped a legacy URL that
//         url.Parse could not parse (a malformed escape in the password,
//         a scheme-less `user:pw@host` spelling), treating it as
//         password-free — so a plain backup archived the material
//         verbatim while the manifest asserted credentialsOmitted: true.
//         An unparseable legacy URL must fail the backup CLOSED.
//   R9-B  normalizeHost trimmed EVERY outer bracket before parsing the
//         IPv6 literal, so `[[::1]]` passed normalization and was
//         persisted; the pool's rebuild cannot parse the resulting
//         authority and silently omits the entry — an update could remove
//         a working parent from the effective pool. Exactly one bracket
//         pair is required.

func TestUpstreamR9_NormalizeRequiresExactlyOneBracketPair(t *testing.T) {
	for _, h := range []string{"[[::1]]", "[[2001:db8::1]", "[2001:db8::1]]", "[]", "[[]]"} {
		if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: h, Port: 3128}); err == nil {
			t.Errorf("host %q: expected a refusal, got accepted", h)
		}
	}
	for h, want := range map[string]string{"[::1]": "[::1]", "[2001:db8::1]": "[2001:db8::1]", "2001:db8::1": "[2001:db8::1]"} {
		sp, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: h, Port: 3128})
		if err != nil || sp.Host != want {
			t.Errorf("host %q: got %q err=%v, want %q", h, sp.Host, err, want)
		}
	}
}
