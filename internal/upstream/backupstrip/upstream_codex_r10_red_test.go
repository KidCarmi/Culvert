package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C19 RED matrix — the tenth Codex round on the Batch 2 PR head
// (923406db), written against that tree BEFORE any correction.
//
//   R10-A  Strip decoded ONE JSON value and
//          never looked at the bytes after it, so a settings body whose
//          leading object is credential-free followed by a second value
//          (or trailing garbage) carrying a plaintext legacy upstream URL
//          was returned UNCHANGED and packed verbatim while the manifest
//          asserted credentialsOmitted: true. A body with anything but
//          whitespace after the settings object must fail the backup
//          CLOSED; trailing whitespace stays accepted.
//   R10-B  normalizeHost decided "IPv6" by net.ParseIP(host).To4() == nil,
//          so an IPv4-MAPPED IPv6 spelling (`::ffff:192.0.2.1`, To4()
//          non-nil) was left unbracketed: Authority() produced a URL
//          url.Parse refuses and the pool rebuild silently omitted the
//          persisted entry; the bracketed spelling was refused by the same
//          To4 test. IPv6 URL syntax (a colon) decides, To4() never does,
//          and exactly one bracket pair is preserved.

const r10Canary = "secret-R10-canary"

func TestUpstreamR10_BackupStripRefusesTrailingDataAfterSettingsObject(t *testing.T) {
	leading := `{"upstream_proxies_saved": true, "upstream_proxies": []}`
	trailingURL := `{"upstream_proxies": [{"url": "http://svc:` + r10Canary + `@parent-a.example:3128"}]}`
	for name, body := range map[string]string{
		"second JSON object":   leading + "\n" + trailingURL,
		"trailing garbage":     leading + " svc:" + r10Canary + "@parent-a.example:3128",
		"second value no gap":  leading + trailingURL,
		"trailing scalar then": leading + " 1 " + trailingURL,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a settings body with data after the object was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r10Canary)) {
			t.Errorf("%s: the password survived into the archive body", name)
		}
	}
	// Control: whitespace after the object is not trailing data.
	for name, body := range map[string]string{
		"newline":    leading + "\n",
		"spaces+tab": leading + " \t\r\n",
	} {
		out, n, err := Strip([]byte(body))
		if err != nil || n != 0 || !bytes.Equal(out, []byte(body)) {
			t.Errorf("%s: a credential-free body followed by whitespace must archive unchanged: n=%d err=%v", name, n, err)
		}
	}
}
