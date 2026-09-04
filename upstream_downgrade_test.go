package main

// upstream_downgrade_test.go — `--prepare-downgrade` unit proofs (2F-D, C10):
// mandatory dry-run, derived confirmation word, predecessor binding,
// refusals on unusable/mismatch/requiresReplacement/missing key, the
// atomic predecessor-compatible rewrite (credential-bearing legacy list,
// v2 document removed, marker recorded, 0600), counts-only output, and the
// next boot's re-migration reported as re-migrated_after_prepare. The
// real-binary predecessor proofs live outside the unit suite.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

const dgSecondPW = "second-pw-Zx9" // #nosec G101 -- test-only fake parent-proxy password

func dgRun(t *testing.T, dir string, target int, confirm string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runPrepareDowngrade(dir, target, confirm, &out)
	return out.String(), err
}

func dgCode(err error) string {
	var r *downgradeRefusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

func TestPrepareDowngrade_DryRunThenCommitRewritesForPredecessor(t *testing.T) {
	upEnv(t)
	id, ciphertext := pdSeed(t)
	upSeedCredentialed(t, "parent-two.test", "svc2", dgSecondPW)
	adminSettingsSaveWG.Wait()
	dir := dataDir
	before, _ := os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	word := downgradeConfirmWord(dir, adminSettingsSchemaPredecessor)
	if !strings.HasSuffix(word, "-schema1") || !strings.HasPrefix(word, filepath.Base(dir)) {
		t.Fatalf("confirmation word must be <datadir basename>-schema<target>, got %q", word)
	}

	// Dry-run: counts + the exact commit command, nothing written.
	out, err := dgRun(t, dir, adminSettingsSchemaPredecessor, "")
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	for _, want := range []string{"managed parent proxies:    2", "credentials to unseal:     2", "--confirm " + word, "This was a dry-run"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{pdCanaryPW, dgSecondPW, ciphertext, pdCanaryHost, "svc"} {
		if strings.Contains(out, leak) {
			t.Fatalf("dry-run output must carry counts only (found %q)", leak)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("a dry-run must write nothing")
	}
	// Wrong word ⇒ refused, nothing written.
	if _, err := dgRun(t, dir, adminSettingsSchemaPredecessor, "nope"); dgCode(err) != "confirm_mismatch" {
		t.Fatalf("want confirm_mismatch, got %v", err)
	}
	after, _ = os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("a refused commit must write nothing")
	}
	// Unsupported target ⇒ refused before reading anything.
	if _, err := dgRun(t, dir, 7, word); dgCode(err) != "unsupported_target_schema" {
		t.Fatalf("want unsupported_target_schema, got %v", err)
	}

	// Commit.
	out, err = dgRun(t, dir, adminSettingsSchemaPredecessor, word)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if strings.Contains(out, pdCanaryPW) || strings.Contains(out, ciphertext) {
		t.Fatal("commit output must carry counts only")
	}
	st, err := os.Stat(filepath.Join(dir, "admin_settings.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("rewritten file must be 0600 (err=%v mode=%v)", err, st.Mode())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m["upstream_proxies_v2"]; has {
		t.Fatal("upstream_proxies_v2 must be removed in the same write")
	}
	if _, has := m["admin_settings_schema"]; has {
		t.Fatal("the schema marker must be removed (predecessor shape)")
	}
	if strings.Contains(string(raw), ciphertext) {
		t.Fatal("no ciphertext may remain")
	}
	legacy, _ := m["upstream_proxies"].([]any)
	if len(legacy) != 2 {
		t.Fatalf("legacy list must carry both entries: %v", legacy)
	}
	var withPW int
	for _, l := range legacy {
		u, _ := l.(map[string]any)["url"].(string)
		if strings.Contains(u, ":"+pdCanaryPW+"@"+pdCanaryHost+":3128") || strings.Contains(u, ":second-pw-Zx9@parent-two.test:3128") {
			withPW++
		}
	}
	if withPW != 2 {
		t.Fatalf("the predecessor needs full authenticated URLs, got %v", legacy)
	}
	if m["upstream_proxies_saved"] != true {
		t.Fatal("the sentinel must stay set")
	}
	marker, _ := m["upstream_prepared_downgrade"].(map[string]any)
	if marker == nil || marker["target_schema"] != float64(1) || marker["credentials"] != float64(2) {
		t.Fatalf("the marker must record counts + target: %v", marker)
	}
	if _, err := os.Stat(filepath.Join(dir, upstream.KeyFileName)); err != nil {
		t.Fatal("the node-local key must be untouched")
	}
	// A second run finds nothing to prepare.
	if _, err := dgRun(t, dir, adminSettingsSchemaPredecessor, ""); dgCode(err) != "already_prepared" {
		t.Fatalf("want already_prepared, got %v", err)
	}

	// The next boot of THIS binary re-migrates and says why.
	snapshotUpstreamPool(t)
	upstreamPool.Configure(nil, 5, 60*time.Second)
	LoadAdminSettings(filepath.Join(dir, "admin_settings.json"))
	v := upGet(t)
	mig, _ := v["migration"].(map[string]any)
	if mig["state"] != "ok" || mig["reason"] != upstreamMigrationReasonAfterPrepare {
		t.Fatalf("re-migration must report %s, got %v", upstreamMigrationReasonAfterPrepare, mig)
	}
	_ = id // a legacy list carries no identity: the re-migrated entries are re-identified
	var reSealed int
	entries, _ := v["entries"].([]any)
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		if e["credentialState"] == upstream.CredentialConfigured {
			reSealed++
		}
	}
	if reSealed != 2 {
		t.Fatalf("re-migration must re-seal both credentials, got %d configured in %v", reSealed, entries)
	}
	raw2, _ := os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	if strings.Contains(string(raw2), pdCanaryPW) {
		t.Fatal("the re-migrated file must not carry the plaintext")
	}
	if strings.Contains(string(raw2), "upstream_prepared_downgrade") {
		t.Fatal("the marker must be consumed by the re-migration")
	}
	if pw, _ := upProxyURL(t).User.Password(); pw != pdCanaryPW && pw != dgSecondPW {
		t.Fatalf("the re-sealed credential must be usable, got %q", pw)
	}
}

func TestPrepareDowngrade_RefusesUnresolvableCredentials(t *testing.T) {
	upEnv(t)
	pdSeed(t)
	adminSettingsSaveWG.Wait()
	dir := dataDir
	// Missing key ⇒ key_unusable.
	keyPath := filepath.Join(dir, upstream.KeyFileName)
	keyBytes, _ := os.ReadFile(keyPath)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := dgRun(t, dir, adminSettingsSchemaPredecessor, ""); dgCode(err) != "key_unusable" {
		t.Fatalf("want key_unusable, got %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("the command must never mint a key")
	}
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// requiresReplacement ⇒ refused.
	path := filepath.Join(dir, "admin_settings.json")
	raw, _ := os.ReadFile(path)
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	s.UpstreamProxiesV2.Entries[0].Credential = nil
	s.UpstreamProxiesV2.Entries[0].RequiresReplacement = true
	data, _ := json.Marshal(s)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dgRun(t, dir, adminSettingsSchemaPredecessor, ""); dgCode(err) != "credential_requires_replacement" {
		t.Fatalf("want credential_requires_replacement, got %v", err)
	}
	// Mismatch (ciphertext transplanted onto another id) ⇒ refused.
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	s.UpstreamProxiesV2.Entries[0].Credential.EntryID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	data, _ = json.Marshal(s)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dgRun(t, dir, adminSettingsSchemaPredecessor, ""); dgCode(err) != "credential_mismatch" {
		t.Fatalf("want credential_mismatch, got %v", err)
	}
	// Unusable (sealed under another key) ⇒ refused.
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	s.UpstreamProxiesV2.Entries[0].Credential.KeyID = "0000000000000000"
	data, _ = json.Marshal(s)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dgRun(t, dir, adminSettingsSchemaPredecessor, ""); dgCode(err) != "credential_unusable" {
		t.Fatalf("want credential_unusable, got %v", err)
	}
	// Nothing was ever written by a refused run.
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, data) {
		t.Fatal("a refused run must leave the file untouched")
	}
}

func TestPrepareDowngrade_ConfirmFlagForms(t *testing.T) {
	c := &confirmFlag{}
	if w, err := prepareDowngradeConfirmWord(c, nil); err != nil || w != "" {
		t.Fatalf("no --confirm ⇒ dry-run, got %q %v", w, err)
	}
	if _, err := prepareDowngradeConfirmWord(c, []string{"stray"}); err == nil {
		t.Fatal("a stray positional without --confirm must be refused")
	}
	c = &confirmFlag{}
	_ = c.Set("true") // bare --confirm
	if !c.Bool() {
		t.Fatal("bare --confirm must keep its boolean meaning for restore/cleanup")
	}
	if _, err := prepareDowngradeConfirmWord(c, nil); err == nil {
		t.Fatal("bare --confirm without a word must be refused for prepare-downgrade")
	}
	if w, err := prepareDowngradeConfirmWord(c, []string{"data-schema1"}); err != nil || w != "data-schema1" {
		t.Fatalf("--confirm <word> form: got %q %v", w, err)
	}
	c = &confirmFlag{}
	_ = c.Set("data-schema1") // --confirm=<word>
	if w, err := prepareDowngradeConfirmWord(c, nil); err != nil || w != "data-schema1" {
		t.Fatalf("--confirm=<word> form: got %q %v", w, err)
	}
	if !c.Bool() {
		t.Fatal("a word-valued --confirm still counts as confirmation for the boolean consumers")
	}
}
