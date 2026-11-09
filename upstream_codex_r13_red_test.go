package main

import (
	"encoding/json"
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

func TestUpstreamR13_LoaderReadsCaseVariantKeys(t *testing.T) {
	// Evidence, not a defect gate: the shapes below are what the loader
	// accepts, which is why the sanitizer must refuse them.
	var s AdminSettings
	body := `{"UPSTREAM_PROXIES": [{"URL": "http://parent-a.example:3128"}], "Upstream_Prepared_Downgrade": {"schema": 1}}`
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.UpstreamProxies) != 1 || s.UpstreamProxies[0].URL != "http://parent-a.example:3128" || s.UpstreamPreparedDowngrade == nil {
		t.Fatalf("the settings loader must read case-variant keys for this matrix to matter: %+v", s.UpstreamProxies)
	}
}
