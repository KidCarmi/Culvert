package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The appliance lifecycle harness (test/e2e/appliance/lifecycle-qualify.sh)
// writes one JSON record per check to checks.jsonl, and its report step parses
// that file line by line — one unparseable byte voids the whole run's evidence
// after every scenario has already passed. The first Deep PR Gate execution of
// the lane did exactly that: the gate image is loaded from a tar and carries no
// RepoDigests, `docker image inspect --format '{{index .RepoDigests 0}}…'`
// emits a bare newline before it fails, and that newline landed INSIDE every
// record's cur_digest string (run 37106439492, both appliance jobs). The local
// qualification runs never saw it because every locally built image carried a
// digest.
//
// This gate drives the harness's own `digest_of` + `check` definitions
// (extracted from the script, so the test cannot drift from what runs in CI)
// against a stub docker that reproduces the tar-loaded shape, and requires
// every record to parse with every field intact.

type harnessCheckRecord struct {
	Run       string `json:"run"`
	Scenario  string `json:"scenario"`
	Check     string `json:"check"`
	Result    string `json:"result"`
	Detail    string `json:"detail"`
	CurImage  string `json:"cur_image"`
	CurDigest string `json:"cur_digest"`
}

// harnessRecordFunctions returns the harness's log/digest_of/check function
// definitions verbatim.
func harnessRecordFunctions(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(pkgSourceDir(), "test", "e2e", "appliance", "lifecycle-qualify.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	a, b := strings.Index(s, "log()  {"), strings.Index(s, "\nexpect() {")
	if a < 0 || b < a {
		t.Fatalf("harness layout changed: log()/digest_of()/check() block not found (a=%d b=%d)", a, b)
	}
	funcs := s[a:b]
	for _, want := range []string{"digest_of() {", "check() {"} {
		if !strings.Contains(funcs, want) {
			t.Fatalf("extracted block lacks %q:\n%s", want, funcs)
		}
	}
	return funcs
}

// runHarnessChecks runs two check() calls under a stub docker whose `image
// inspect` behaves as dockerStub says, and returns the parsed records.
func runHarnessChecks(t *testing.T, dockerStub, detail string) []harnessCheckRecord {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(bin, "docker")
	if err := os.WriteFile(stub, []byte("#!/usr/bin/env bash\n"+dockerStub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stub, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "set -euo pipefail\nexport PATH=" + bin + ":$PATH\n" +
		"JSONL=checks.jsonl; : > \"$JSONL\"; RUN_ID=run1; FAILS=0; CUR_IMAGE=culvert:ci-smoke\n" +
		harnessRecordFunctions(t) + "\n" +
		"check A boot pass 'version=dev'\n" +
		"check X weird blocked '" + detail + "'\n"
	if out, ok := runShell(t, script, dir); !ok {
		t.Fatalf("harness check() failed:\n%s", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "checks.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 records (one per check call), got %d:\n%s", len(lines), raw)
	}
	recs := make([]harnessCheckRecord, 0, 2)
	for i, line := range lines {
		var rec harnessCheckRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("record %d does not parse (%v) — the report step would refuse the whole run:\n%q", i+1, err, line)
		}
		recs = append(recs, rec)
	}
	return recs
}

// The detail carries every byte class that must round-trip: a tab, quotes, a
// backslash, and the table delimiter the report escapes.
const harnessAwkwardDetail = "tab\there \"quoted\" back\\slash | pipe"

func TestLifecycleHarness_ChecksJSONLSurvivesAnUndigestedImage(t *testing.T) {
	// The tar-loaded gate image: docker writes a newline, then fails the
	// template on the empty RepoDigests list.
	recs := runHarnessChecks(t,
		`printf '\n'; echo 'Template parsing error: template: :1:2: executing "" at <index .RepoDigests 0>: error calling index: index out of range: 0' >&2; exit 64`,
		harnessAwkwardDetail)
	if recs[0].Check != "boot" || recs[0].Result != "pass" || recs[0].Detail != "version=dev" || recs[0].Scenario != "A" || recs[0].Run != "run1" {
		t.Fatalf("first record fields wrong: %+v", recs[0])
	}
	if recs[1].Result != "blocked" || recs[1].Detail != harnessAwkwardDetail {
		t.Fatalf("awkward detail must round-trip byte for byte: %+v", recs[1])
	}
	for i, r := range recs {
		if r.CurImage != "culvert:ci-smoke" {
			t.Errorf("record %d cur_image = %q", i+1, r.CurImage)
		}
		if r.CurDigest != "unknown|unknown" {
			t.Errorf("record %d: an undigested image must report unknown|unknown, got %q", i+1, r.CurDigest)
		}
		if strings.ContainsAny(r.CurDigest, "\n\r\t") {
			t.Errorf("record %d: cur_digest carries a control character: %q", i+1, r.CurDigest)
		}
	}
}

// Control: the cheapest way to pass the gate above is to stop recording the
// digest at all. A docker that answers must still have its answer recorded.
func TestLifecycleHarness_ChecksJSONLKeepsARealDigest(t *testing.T) {
	recs := runHarnessChecks(t, `printf 'ghcr.io/kidcarmi/culvert@sha256:abc|sha256:def\n'`, harnessAwkwardDetail)
	for i, r := range recs {
		if r.CurDigest != "ghcr.io/kidcarmi/culvert@sha256:abc|sha256:def" {
			t.Errorf("record %d: digest not carried through: %q", i+1, r.CurDigest)
		}
	}
}
