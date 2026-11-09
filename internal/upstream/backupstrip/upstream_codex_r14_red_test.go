package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C23 RED matrix — the fourteenth Codex round on the Batch 2 PR head
// (3ad9adbb), written against that tree BEFORE any correction.
//
//   R14-A  (P1) Strip asserted the v2
//          document to an object and its `entries` to an array, and on
//          any other shape RETURNED THE ORIGINAL BYTES unchanged — so an
//          `entries` object (`{"entry": {"credential": {...}}}`), an
//          `entries` string, an item that is not an object, or a v2
//          document that is an array or a string carried sealed material
//          into the archive verbatim while the manifest asserted
//          credentialsOmitted: true. A present v2 document or `entries`
//          whose shape cannot be sanitized must fail the backup CLOSED.
//   R14-B  (P2) The PR-C22 case-variant and case-collision checks ran for
//          EVERY object at every depth, so a legitimate operator-controlled
//          map key unrelated to upstream settings — an OTLP header named
//          `URL` or `KeyId` persisted under `otlp_headers`
//          (AdminSettings.OTLPHeaders is map[string]string, where
//          encoding/json keeps case-distinct keys apart) — made every
//          backup fail even with no upstream credential anywhere. The
//          alias and case-collision checks must apply only where the
//          settings loader could bind the key to an upstream field.

const r14Canary = "secret-R14-canary"

func TestUpstreamR14_BackupStripRefusesMalformedV2Container(t *testing.T) {
	cred := `{"ciphertext": "` + r14Canary + `", "keyId": "k-1", "authorityHash": "h"}`
	for name, body := range map[string]string{
		"entries is an object":     `{"upstream_proxies_v2": {"entries": {"entry": {"credential": ` + cred + `}}}}`,
		"entries is a string":      `{"upstream_proxies_v2": {"entries": "` + r14Canary + `"}}`,
		"entries item is a string": `{"upstream_proxies_v2": {"entries": ["` + r14Canary + `"]}}`,
		"entries item is an array": `{"upstream_proxies_v2": {"entries": [[{"credential": ` + cred + `}]]}}`,
		"v2 document is an array":  `{"upstream_proxies_v2": [{"entries": [{"id": "a", "credential": ` + cred + `}]}]}`,
		"v2 document is a string":  `{"upstream_proxies_v2": "` + r14Canary + `"}`,
		"v2 document is null":      `{"upstream_proxies_v2": null, "note": "` + r14Canary + `"}`,
		"credential is a string":   `{"upstream_proxies_v2": {"entries": [{"id": "a", "credential": "` + r14Canary + `"}]}}`,
		"credential is an array":   `{"upstream_proxies_v2": {"entries": [{"id": "a", "credential": [` + cred + `]}]}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a malformed v2 container was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r14Canary)) {
			t.Errorf("%s: the secret survived into the archive body", name)
		}
	}
	// Control: a v2 document with no entries key, and one with an empty
	// entries array, are sound and archive unchanged.
	for name, body := range map[string]string{
		"no entries key": `{"upstream_proxies_v2": {"revision": 3}}`,
		"empty entries":  `{"upstream_proxies_v2": {"revision": 3, "entries": []}}`,
	} {
		out, n, err := Strip([]byte(body))
		if err != nil || n != 0 || !bytes.Equal(out, []byte(body)) {
			t.Errorf("control %s: must archive unchanged: n=%d err=%v", name, n, err)
		}
	}
}

func TestUpstreamR14_CaseChecksScopedToUpstreamStructures(t *testing.T) {
	sealed := `{"id": "01HZZ", "credential": {"ciphertext": "` + r14Canary + `", "keyId": "k-1", "authorityHash": "h"}}`
	// Every body below is SOUND: the case variants and case-only collisions
	// sit in operator-controlled maps or unrelated sections the loader never
	// binds to an upstream field. Each must archive, with the v2 credential
	// stripped when one is present and nothing else touched.
	for name, body := range map[string]string{
		"OTLP header named URL":                 `{"otlp_headers": {"URL": "x"}, "upstream_proxies_v2": {"entries": [` + sealed + `]}}`,
		"OTLP header named KeyId":               `{"otlp_headers": {"KeyId": "x", "Authorization": "y"}}`,
		"OTLP headers colliding by case":        `{"otlp_headers": {"x-token": "a", "X-Token": "b"}}`,
		"unrelated section with Entries":        `{"other_section": {"Entries": [{"Credential": {"CipherText": "not-upstream"}}], "Url": "u"}}`,
		"unrelated section colliding by case":   `{"other_section": {"name": "a", "Name": "b"}, "upstream_proxies": [{"url": "http://parent-a.example:3128"}]}`,
		"legacy item with an extra field cased": `{"upstream_proxies": [{"url": "http://parent-a.example:3128", "Interval": "30s"}]}`,
	} {
		out, _, err := Strip([]byte(body))
		if err != nil {
			t.Errorf("%s: a sound body was refused: %v", name, err)
			continue
		}
		if bytes.Contains(out, []byte(r14Canary)) {
			t.Errorf("%s: the v2 credential was not stripped", name)
		}
		if bytes.Contains([]byte(body), []byte("otlp_headers")) && !bytes.Contains(out, []byte("otlp_headers")) {
			t.Errorf("%s: an unrelated section was dropped", name)
		}
	}
	// Control: the upstream-bound structures keep the PR-C22 refusals.
	for name, body := range map[string]string{
		"root alias":          `{"UPSTREAM_PROXIES": [{"url": "http://svc:` + r14Canary + `@parent-a.example:3128"}]}`,
		"legacy item alias":   `{"upstream_proxies": [{"url": "http://parent-a.example:3128", "URL": "http://svc:` + r14Canary + `@parent-a.example:3128"}]}`,
		"v2 entry alias":      `{"upstream_proxies_v2": {"entries": [{"id": "a", "CREDENTIAL": {"ciphertext": "` + r14Canary + `"}}]}}`,
		"v2 credential alias": `{"upstream_proxies_v2": {"entries": [{"id": "a", "credential": {"CipherText": "` + r14Canary + `"}}]}}`,
		"v2 document alias":   `{"upstream_proxies_v2": {"ENTRIES": [` + sealed + `]}}`,
		"root case collision": `{"upstream_proxies_v2": {"entries": []}, "Upstream_Proxies_V2": {"entries": [` + sealed + `]}}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("control %s: an upstream-bound case variant was accepted", name)
		}
		if bytes.Contains(out, []byte(r14Canary)) {
			t.Errorf("control %s: the secret survived into the archive body", name)
		}
	}
}
