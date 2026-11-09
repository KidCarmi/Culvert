package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C17 RED matrix — the eighth Codex round on the Batch 2 PR head
// (c17789bc), written against that tree BEFORE any correction.
//
//   R8-A  a backup taken in the prepared-downgrade state (after
//         `--prepare-downgrade`, before the next boot re-migrates) packs the
//         legacy `upstream_proxies` URLs — which then carry the unsealed
//         passwords by design — VERBATIM, while the manifest asserts
//         credentialsOmitted: true. The same holds for any settings file
//         whose legacy list carries a password (a pre-v2 file never booted
//         on this binary). An archive must never carry material: the
//         sanitizer must refuse such a body.
//   R8-B  validateHostLabels checked emptiness only: a label longer than
//         63 octets, or a name longer than 253, is accepted by the IDNA
//         Lookup profile (no DNS-length verification) and was persisted and
//         published as an eligible parent that standard DNS cannot resolve.

const r8Canary = "hunter2-R8-canary"

func r8PreparedDowngradeSettings() []byte {
	return []byte(`{
  "upstream_proxies": [{"url": "http://svc:` + r8Canary + `@parent-a.example:3128"}],
  "upstream_proxies_saved": true,
  "upstream_prepared_downgrade": {"at": "2026-09-08T20:00:00Z", "targetSchema": 1, "fromSchema": 2, "credentials": 1}
}`)
}

func TestUpstreamR8_BackupStripRefusesPreparedDowngradeCredentials(t *testing.T) {
	out, stripped, err := Strip(r8PreparedDowngradeSettings())
	if err == nil {
		t.Fatalf("prepared-downgrade settings with a legacy password were accepted for archiving (stripped=%d)", stripped)
	}
	if bytes.Contains(out, []byte(r8Canary)) {
		t.Fatalf("the password survived into the archive body")
	}
}

func TestUpstreamR8_BackupStripRefusesLegacyPasswordWithoutMarker(t *testing.T) {
	body := []byte(`{"upstream_proxies": [{"url": "http://svc:` + r8Canary + `@parent-a.example:3128"}], "upstream_proxies_saved": true}`)
	out, _, err := Strip(body)
	if err == nil {
		t.Fatalf("a legacy list carrying a password was accepted for archiving")
	}
	if bytes.Contains(out, []byte(r8Canary)) {
		t.Fatalf("the password survived into the archive body")
	}
}

func TestUpstreamR8_BackupStripKeepsPasswordFreeLegacyList(t *testing.T) {
	body := []byte(`{"upstream_proxies": [{"url": "http://svc@parent-a.example:3128"}], "upstream_proxies_saved": true}`)
	out, stripped, err := Strip(body)
	if err != nil || stripped != 0 || !bytes.Equal(out, body) {
		t.Fatalf("a password-free legacy list must archive unchanged: err=%v stripped=%d", err, stripped)
	}
}
