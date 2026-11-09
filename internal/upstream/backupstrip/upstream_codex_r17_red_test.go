package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C27 RED matrix — the seventeenth Codex round on the Batch 2 PR head
// (290dd796), written against that tree BEFORE any correction.
//
//   R17-A  (P2) verifyV2CredentialsRemoved re-serialized the v2 document
//          and searched the BYTES for the quoted sealed-record key names,
//          so a sound entry whose VALUE equals one of them — an
//          uncredentialed parent whose username is `keyId` or
//          `ciphertext`, a host label spelled `authorityHash` — matched
//          the same quoted bytes though no sealed-record KEY remained, and
//          because PR-C26 runs the verifier for every present document
//          such a settings file made every backup fail. The verifier must
//          walk object KEYS; a value is never a key.

const r17Canary = "secret-R17-canary"

func TestUpstreamR17_V2VerifierInspectsKeysNotValues(t *testing.T) {
	sealed := `{"id": "01HZZ1", "credential": {"ciphertext": "` + r17Canary + `", "keyId": "k-1", "authorityHash": "h"}}`
	// Every body is SOUND: the sealed-record names appear only as VALUES.
	for name, body := range map[string]string{
		"username keyId, no credential":        `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "host": "parent-a.example", "username": "keyId"}]}}`,
		"username ciphertext, no credential":   `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "host": "parent-a.example", "username": "ciphertext"}]}}`,
		"host authorityHash, no credential":    `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "host": "authorityhash", "username": "authorityHash"}]}}`,
		"username keyId beside a credential":   `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "username": "keyId"}, ` + sealed + `]}}`,
		"document-level value equal to a name": `{"upstream_proxies_v2": {"note": "ciphertext", "entries": []}}`,
		"quoted name inside a longer value":    `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "username": "x\"keyId\"y"}]}}`,
	} {
		out, n, err := Strip([]byte(body))
		if err != nil {
			t.Errorf("%s: a sound body was refused: %v", name, err)
			continue
		}
		if bytes.Contains(out, []byte(r17Canary)) {
			t.Errorf("%s: the v2 credential was not stripped", name)
		}
		if bytes.Contains([]byte(body), []byte(`"credential"`)) && (n != 1 || !bytes.Contains(out, []byte(`"requiresReplacement": true`))) {
			t.Errorf("%s: the credential must be stripped and the entry marked: n=%d", name, n)
		}
	}
	// Control: a sealed-record KEY surviving inside the document still
	// refuses, wherever it sits.
	for name, body := range map[string]string{
		"entry-level keyId key":       `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "keyId": "` + r17Canary + `"}]}}`,
		"document-level ciphertext":   `{"upstream_proxies_v2": {"entries": [], "ciphertext": "` + r17Canary + `"}}`,
		"nested object authorityHash": `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "meta": {"authorityHash": "` + r17Canary + `"}}]}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("control %s: a sealed-record key inside the v2 document was accepted", name)
		}
		if bytes.Contains(out, []byte(r17Canary)) {
			t.Errorf("control %s: the secret survived into the archive body", name)
		}
	}
}
