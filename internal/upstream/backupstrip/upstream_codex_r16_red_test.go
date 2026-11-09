package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C26 RED matrix — the sixteenth Codex round on the Batch 2 PR head
// (90e068c6), written against that tree BEFORE any correction.
//
//   R16-A  (P1) The v2-document verification (PR-C25) ran only AFTER at
//          least one credential object had been stripped: with a v2
//          document that carries misplaced sealed fields but no
//          recognized `credential` object — `ciphertext` at document
//          level beside an empty `entries`, at entry level with no
//          credential, or a document with no `entries` key at all —
//          stripV2Credentials returned zero and the `stripped == 0`
//          branch handed back the ORIGINAL bytes before the verifier ran,
//          so the material was archived under credentialsOmitted: true.
//          A present v2 document must be verified whether or not a
//          credential object was stripped.

const r16Canary = "secret-R16-canary"

func TestUpstreamR16_V2VerificationRunsWithoutAStrip(t *testing.T) {
	for name, body := range map[string]string{
		"document-level ciphertext, empty entries":     `{"upstream_proxies_v2": {"entries": [], "ciphertext": "` + r16Canary + `"}}`,
		"document-level keyId, no entries key":         `{"upstream_proxies_v2": {"revision": 3, "keyId": "` + r16Canary + `"}}`,
		"entry-level authorityHash, no credential":     `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "authorityHash": "` + r16Canary + `"}]}}`,
		"entry-level ciphertext, no credential object": `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "ciphertext": "` + r16Canary + `"}]}}`,
		"nested unrelated object inside the document":  `{"upstream_proxies_v2": {"entries": [], "meta": {"ciphertext": "` + r16Canary + `"}}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: sealed material inside the v2 document was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r16Canary)) {
			t.Errorf("%s: the secret survived into the archive body", name)
		}
	}
	// Control: a sound v2 document with no credential archives unchanged,
	// and the names stay ordinary outside the document.
	for name, body := range map[string]string{
		"sound document, no credential": `{"upstream_proxies_v2": {"revision": 3, "entries": [{"id": "01HZZ", "host": "parent-a.example"}]}}`,
		"names outside the document":    `{"upstream_proxies_v2": {"entries": []}, "otlp_headers": {"keyId": "x", "ciphertext": "y"}}`,
	} {
		out, n, err := Strip([]byte(body))
		if err != nil || n != 0 || !bytes.Equal(out, []byte(body)) {
			t.Errorf("control %s: must archive unchanged: n=%d err=%v", name, n, err)
		}
	}
}
