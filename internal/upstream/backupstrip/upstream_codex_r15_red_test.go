package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C25 RED matrix — the fifteenth Codex round on the Batch 2 PR head
// (398a9f8f / a469182f), written against that tree BEFORE any correction.
//
//   R15-A  (P2) After stripping at least one v2 credential the sanitizer
//          re-serialized the WHOLE settings document and refused it if the
//          bytes `"ciphertext"`, `"keyId"` or `"authorityHash"` appeared
//          ANYWHERE — so a legitimate operator-controlled map key unrelated
//          to upstream settings (an OTLP header named `KeyId` under
//          `otlp_headers`, an unrelated section carrying `ciphertext`)
//          combined with a real v2 credential refused the backup even
//          though the credential itself had been removed. Removal must be
//          verified within the v2 credential structures, never by
//          forbidding those names throughout the sanitized settings.

const r15Canary = "secret-R15-canary"

func TestUpstreamR15_PostStripCheckScopedToV2Structures(t *testing.T) {
	sealed := `{"id": "01HZZ", "credential": {"ciphertext": "` + r15Canary + `", "keyId": "k-1", "authorityHash": "h"}}`
	for name, body := range map[string]string{
		"OTLP header named KeyId with a real credential":      `{"otlp_headers": {"KeyId": "x"}, "upstream_proxies_v2": {"entries": [` + sealed + `]}}`,
		"OTLP header named ciphertext with a real credential": `{"otlp_headers": {"ciphertext": "x"}, "upstream_proxies_v2": {"entries": [` + sealed + `]}}`,
		"unrelated section carrying authorityHash":            `{"other_section": {"authorityHash": "not-upstream"}, "upstream_proxies_v2": {"entries": [` + sealed + `]}}`,
		"unrelated section carrying all three":                `{"upstream_proxies_v2": {"entries": [` + sealed + `]}, "notes": {"ciphertext": "a", "keyId": "b", "authorityHash": "c"}}`,
	} {
		out, n, err := Strip([]byte(body))
		if err != nil {
			t.Errorf("%s: a sound body was refused after the strip: %v", name, err)
			continue
		}
		if n != 1 || bytes.Contains(out, []byte(r15Canary)) || !bytes.Contains(out, []byte(`"requiresReplacement": true`)) {
			t.Errorf("%s: the credential must be stripped and the entry marked: n=%d", name, n)
		}
		for _, keep := range []string{"otlp_headers", "other_section", "notes"} {
			if bytes.Contains([]byte(body), []byte(keep)) && !bytes.Contains(out, []byte(keep)) {
				t.Errorf("%s: the unrelated section %q was dropped", name, keep)
			}
		}
	}
	// Control: credential material that survives INSIDE the v2 structures
	// after the strip is still refused, fail-closed — an entry carrying a
	// sealed field outside its credential object, or a document-level one.
	for name, body := range map[string]string{
		"entry-level ciphertext beside a credential": `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "ciphertext": "` + r15Canary + `", "credential": {"ciphertext": "` + r15Canary + `"}}]}}`,
		"document-level keyId beside a credential":   `{"upstream_proxies_v2": {"keyId": "k-1", "entries": [` + sealed + `]}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("control %s: sealed material inside the v2 structures was accepted", name)
		}
		if bytes.Contains(out, []byte(r15Canary)) {
			t.Errorf("control %s: the secret survived into the archive body", name)
		}
	}
}
