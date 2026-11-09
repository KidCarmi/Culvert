package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C29 RED matrix — the nineteenth Codex round on the Batch 2 PR head
// (840c3fee), written against that tree BEFORE any correction.
//
//   R19-A  (P1) walkV2Keys compared the sealed-record key names and the
//          `credential` key EXACTLY, and the duplicate-key walker folds
//          case only for the keys BOUND at a structural role — so a
//          case-variant sealed field placed OUTSIDE its normal role (a
//          document-level `Ciphertext`, an entry-level `KeyId`, a nested
//          `AuthorityHash`, a document-level `Credential`) passed both the
//          walker's precheck and the verifier, and the zero-strip branch
//          archived the field unchanged while the manifest asserted
//          credentialsOmitted. The v2 document is upstream-owned in full;
//          its owned key names must be refused case-insensitively at
//          every depth.

const r19Canary = "secret-R19-canary"

func TestUpstreamR19_V2VerifierFoldsKeyCaseAtEveryDepth(t *testing.T) {
	for name, body := range map[string]string{
		"document-level Ciphertext": `{"upstream_proxies_v2": {"entries": [], "Ciphertext": "` + r19Canary + `"}}`,
		"document-level KEYID":      `{"upstream_proxies_v2": {"entries": [], "KEYID": "` + r19Canary + `"}}`,
		"entry-level KeyId":         `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "KeyId": "` + r19Canary + `"}]}}`,
		"entry-level AuthorityHash": `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "AuthorityHash": "` + r19Canary + `"}]}}`,
		"nested object CipherText":  `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "meta": {"CipherText": "` + r19Canary + `"}}]}}`,
		"document-level Credential": `{"upstream_proxies_v2": {"entries": [], "Credential": {"ciphertext": "` + r19Canary + `"}}}`,
		"nested object CREDENTIAL":  `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "meta": {"CREDENTIAL": "` + r19Canary + `"}}]}}`,
		"array-nested Credential":   `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "list": [{"Credential": "` + r19Canary + `"}]}]}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a case-variant sealed key inside the v2 document was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r19Canary)) {
			t.Errorf("%s: the material survived into the archive body", name)
		}
	}
	// Controls: a case variant IN its bound role is already refused by the
	// duplicate-key walker, and a VALUE equal to a case variant is
	// ordinary (PR-C27 R17-A).
	for name, body := range map[string]string{
		"entry-level Credential (bound role)": `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "Credential": {"ciphertext": "` + r19Canary + `"}}]}}`,
		"credential-level KeyId (bound role)": `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "credential": {"ciphertext": "x", "KeyId": "` + r19Canary + `", "authorityHash": "h"}}]}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("control %s: accepted", name)
		}
		if bytes.Contains(out, []byte(r19Canary)) {
			t.Errorf("control %s: the material survived into the archive body", name)
		}
	}
	sound := `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "host": "parent-a.example", "username": "Ciphertext", "note": "KeyId"}]}}`
	if out, n, err := Strip([]byte(sound)); err != nil || n != 0 || string(out) != sound {
		t.Errorf("control sound values: got n=%d err=%v out=%q, want unchanged", n, err, out)
	}
}
