package backupstrip

import (
	"bytes"
	"strings"
	"testing"
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

const r9Canary = "secret-R9-canary"

func TestUpstreamR9_BackupStripRefusesUnparseableLegacyURL(t *testing.T) {
	for _, raw := range []string{
		"http://svc:" + r9Canary + "%zz@parent-a.example:3128", // malformed escape: url.Parse fails
		"svc:" + r9Canary + "@parent-a.example:3128",           // scheme-less: parses as an opaque URL
	} {
		body := []byte(`{"upstream_proxies": [{"url": "` + raw + `"}], "upstream_proxies_saved": true}`)
		out, _, err := Strip(body)
		if err == nil {
			t.Errorf("legacy URL %q was accepted for archiving", strings.ReplaceAll(raw, r9Canary, "<secret>"))
		}
		if bytes.Contains(out, []byte(r9Canary)) {
			t.Errorf("the password survived into the archive body for %q", strings.ReplaceAll(raw, r9Canary, "<secret>"))
		}
	}
}
