package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C21 RED matrix — the twelfth Codex round on the Batch 2 PR head
// (c88c3cf0), written against that tree BEFORE any correction.
//
//   R12-A  refuseCredentialBearingLegacyUpstreams asserted the legacy
//          `upstream_proxies` value to a JSON array and silently skipped the
//          gate on any other shape — an object, a string, a number — and,
//          inside a well-formed array, skipped an item that is neither a
//          string nor an object, an object whose `url` is not a string, and
//          an object with no `url` at all. Every one of those carried the
//          plaintext material past the gate: no v2 credential was stripped,
//          so the ORIGINAL bytes were archived under credentialsOmitted:
//          true. A present `upstream_proxies` key must be an array of
//          `{url: string}` items — the persisted shape of
//          AdminSettings.UpstreamProxies, which the settings loader cannot
//          read as anything else — or the backup fails CLOSED.

const r12Canary = "secret-R12-canary"

func TestUpstreamR12_BackupStripRefusesMalformedLegacyContainer(t *testing.T) {
	u := `http://svc:` + r12Canary + `@parent-a.example:3128`
	for name, body := range map[string]string{
		"object instead of array":     `{"upstream_proxies": {"url": "` + u + `"}}`,
		"string instead of array":     `{"upstream_proxies": "` + u + `"}`,
		"array nested one level deep": `{"upstream_proxies": [["` + u + `"]]}`,
		"item is a number":            `{"upstream_proxies": [42], "note": "` + u + `"}`,
		"url is an array":             `{"upstream_proxies": [{"url": ["` + u + `"]}]}`,
		"url is an object":            `{"upstream_proxies": [{"url": {"v": "` + u + `"}}]}`,
		"url is null":                 `{"upstream_proxies": [{"url": null, "u": "` + u + `"}]}`,
		"item without url":            `{"upstream_proxies": [{"URL": "` + u + `"}]}`,
		"item with empty url":         `{"upstream_proxies": [{"url": "", "u": "` + u + `"}]}`,
		"item is a string":            `{"upstream_proxies": ["http://parent-a.example:3128"], "note": "` + u + `"}`,
		"container is null":           `{"upstream_proxies": null, "note": "` + u + `"}`,
		"container is a number":       `{"upstream_proxies": 1, "note": "` + u + `"}`,
	} {
		out, _, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a malformed legacy upstream container was accepted for archiving", name)
		}
		if bytes.Contains(out, []byte(r12Canary)) {
			t.Errorf("%s: the secret survived into the archive body", name)
		}
	}
	// Control: the persisted item shape (AdminSettings.UpstreamProxies is a
	// list of objects carrying a `url` string) archives unchanged.
	body := `{"upstream_proxies": [{"url": "http://parent-a.example:3128"}, {"url": "http://svc@parent-b.example:3128", "user": "svc"}], "upstream_proxies_saved": true}`
	out, n, err := Strip([]byte(body))
	if err != nil || n != 0 || !bytes.Equal(out, []byte(body)) {
		t.Errorf("control: a sound legacy list must archive unchanged: n=%d err=%v", n, err)
	}
	// Control: an absent key is not a malformed container.
	body = `{"upstream_proxies_saved": false}`
	if out, n, err := Strip([]byte(body)); err != nil || n != 0 || !bytes.Equal(out, []byte(body)) {
		t.Errorf("control: an absent legacy list must archive unchanged: n=%d err=%v", n, err)
	}
}
