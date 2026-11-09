package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C22 RED matrix — the thirteenth Codex round on the Batch 2 PR head
// (50fe2d6e), written against that tree BEFORE any correction.
//
//   R13-A  encoding/json matches struct fields CASE-INSENSITIVELY, so the
//          settings loader (json.Unmarshal into AdminSettings) reads
//          `UPSTREAM_PROXIES`, `Upstream_Proxies_V2`,
//          `UPSTREAM_PREPARED_DOWNGRADE`, a nested `URL`, `ENTRIES` or
//          `CREDENTIAL` exactly as the canonical spellings — while the
//          sanitizer looked every one of them up by EXACT key and treated
//          the variant as absent. A credential-bearing legacy URL under a
//          case variant bypassed the gate, a sealed record under a case
//          variant was never stripped, and a case-variant prepared-downgrade
//          marker never refused; the original bytes were archived under
//          credentialsOmitted: true. Two keys that differ only by case in
//          one object are a collision the loader resolves by a rule the
//          sanitizer cannot see. Every case-variant spelling of a key the
//          sanitizer reads, and every case-only collision, must fail the
//          backup CLOSED.

const r13Canary = "secret-R13-canary"

// TestUpstreamR13_BackupStripRefusesCaseVariantKeys pins that case-variant spellings of keys the sanitizer reads fail the backup closed.
func TestUpstreamR13_BackupStripRefusesCaseVariantKeys(t *testing.T) {
	u := `http://svc:` + r13Canary + `@parent-a.example:3128`
	sealed := `{"id": "01HZZ", "credential": {"ciphertext": "` + r13Canary + `", "keyId": "k-1", "authorityHash": "h"}}`
	for name, body := range map[string]string{
		"legacy list under UPSTREAM_PROXIES":        `{"UPSTREAM_PROXIES": [{"url": "` + u + `"}]}`,
		"legacy list under Upstream_Proxies, URL":   `{"Upstream_Proxies": [{"URL": "` + u + `"}]}`,
		"legacy item url under Url":                 `{"upstream_proxies": [{"Url": "` + u + `"}]}`,
		"case-only collision, variant carries it":   `{"upstream_proxies": [], "UPSTREAM_PROXIES": [{"url": "` + u + `"}]}`,
		"case-only collision, variant first":        `{"UPSTREAM_PROXIES": [{"url": "` + u + `"}], "upstream_proxies": []}`,
		"v2 document under Upstream_Proxies_V2":     `{"Upstream_Proxies_V2": {"entries": [` + sealed + `]}}`,
		"v2 entries under ENTRIES":                  `{"upstream_proxies_v2": {"ENTRIES": [` + sealed + `]}}`,
		"v2 credential under CREDENTIAL":            `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "CREDENTIAL": {"ciphertext": "` + r13Canary + `"}}]}}`,
		"v2 ciphertext under CipherText":            `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "credential": {"CipherText": "` + r13Canary + `"}}]}}`,
		"prepared marker under a case variant":      `{"UPSTREAM_PREPARED_DOWNGRADE": {"schema": 1}, "upstream_proxies": [{"url": "http://svc@parent-a.example:3128"}], "note": "` + r13Canary + `"}`,
		"requiresReplacement under a case variant":  `{"upstream_proxies_v2": {"entries": [{"id": "01HZZ", "REQUIRESREPLACEMENT": true}]}, "note": "` + r13Canary + `"}`,
		"nested case-only collision inside an item": `{"upstream_proxies": [{"url": "http://parent-a.example:3128", "URL": "` + u + `"}]}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a case-variant spelling was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r13Canary)) {
			t.Errorf("%s: the secret survived into the archive body", name)
		}
	}
	// Control: the canonical spellings still archive (v2 stripped, legacy
	// unchanged), and an unrelated key in any case is not a variant.
	body := `{"upstream_proxies": [{"url": "http://svc@parent-a.example:3128"}], "upstream_proxies_v2": {"entries": [` + sealed + `]}, "Other_Section": {"Name": "x"}}`
	out, n, err := Strip([]byte(body))
	if err != nil || n != 1 || bytes.Contains(out, []byte(r13Canary)) || !bytes.Contains(out, []byte(`"requiresReplacement": true`)) {
		t.Errorf("control: canonical spellings must archive with the credential stripped: n=%d err=%v", n, err)
	}
}
