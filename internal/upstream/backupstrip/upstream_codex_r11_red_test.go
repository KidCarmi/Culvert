package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C20 RED matrix — the eleventh Codex round on the Batch 2 PR head
// (207ecb8a), written against that tree BEFORE any correction.
//
//   R11-A  Strip decoded the settings object
//          into a map, and encoding/json silently keeps only the LAST value
//          of a repeated key. A single settings object that repeats
//          `upstream_proxies` (a credential-bearing list first, an empty
//          list last) therefore had the credential gate inspect only the
//          empty list, and — no v2 credential being stripped — the ORIGINAL
//          bytes, plaintext password included, were packed while the
//          manifest asserted credentialsOmitted: true. The same applies to
//          a repeated nested key (`url` inside a list item). A settings
//          object carrying a duplicate key at ANY nesting level must fail
//          the backup CLOSED; a sound file never repeats a key.

const r11Canary = "secret-R11-canary"

func TestUpstreamR11_BackupStripRefusesDuplicateKeys(t *testing.T) {
	cred := `{"url": "http://svc:` + r11Canary + `@parent-a.example:3128"}`
	for name, body := range map[string]string{
		"top-level list repeated, clean last":   `{"upstream_proxies": [` + cred + `], "upstream_proxies": []}`,
		"top-level list repeated, clean first":  `{"upstream_proxies": [], "upstream_proxies": [` + cred + `]}`,
		"nested url repeated, clean last":       `{"upstream_proxies": [{"url": "http://svc:` + r11Canary + `@parent-a.example:3128", "url": "http://parent-a.example:3128"}]}`,
		"v2 document repeated":                  `{"upstream_proxies_v2": {"entries": [{"id": "a", "credential": {"ciphertext": "` + r11Canary + `"}}]}, "upstream_proxies_v2": {"entries": []}}`,
		"duplicate inside an unrelated section": `{"upstream_proxies": [` + cred + `], "other": {"k": 1, "k": 2}, "upstream_proxies": []}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a settings object with a duplicate key was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r11Canary)) {
			t.Errorf("%s: the secret survived into the archive body", name)
		}
	}
	// Control: the same key names in DIFFERENT objects are not duplicates.
	body := `{"upstream_proxies": [{"url": "http://parent-a.example:3128"}, {"url": "http://parent-b.example:3128"}], "other": [{"k": 1}, {"k": 2}]}`
	out, n, err := Strip([]byte(body))
	if err != nil || n != 0 || !bytes.Equal(out, []byte(body)) {
		t.Errorf("control: a sound body must archive unchanged: n=%d err=%v", n, err)
	}
}
