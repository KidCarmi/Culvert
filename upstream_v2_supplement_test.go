package main

// upstream_v2_supplement_test.go — 2F-C contracts beyond the RED matrix:
// the import preserve rule and its pre-validation, the unusable-credential
// delete refusal, the client-asserted credential_configured field, YAML
// duplicate refusal at boot, and the credential-free GET/export surface.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

func upImport(t *testing.T, body, mode string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/config/import"
	if mode != "" {
		path += "?mode=" + mode
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = upRedIP + ":40021"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigImport(rec, req)
	return rec
}

// A backup carrying a REAL password is refused whole (400
// credentials_not_importable) before any store mutation: the credentialed
// live entry is intact and no second entry appeared.
func TestUpstreamV2_ImportRealPasswordIsRefusedBeforeMutation(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	before := upDocRevision(t)
	rec := upImport(t, `{"version":1,"upstreamProxies":[{"url":"http://svc:other-secret@parent-b.test:3128"}]}`, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "credentials_not_importable") {
		t.Fatalf("want 400 credentials_not_importable, got %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "other-secret") {
		t.Fatal("the refusal must not echo the password")
	}
	if got := upDocRevision(t); got != before {
		t.Fatalf("a refused import must not mutate the pool (revision %d → %d)", before, got)
	}
	if pw, _ := upProxyURL(t).User.Password(); pw != upRedPW {
		t.Fatal("the live credential must be intact after a refused import")
	}
	entries, _ := upGet(t)["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("want the single live entry, got %d", len(entries))
	}
}

// An invalid URL in the upstream section refuses the whole import (nothing
// dropped, nothing applied) — pre-validation, not tolerant apply.
func TestUpstreamV2_ImportInvalidEntryIsRefusedWhole(t *testing.T) {
	upEnv(t)
	rec := upImport(t, `{"version":1,"upstreamProxies":[{"url":"http://parent-b.test:3128"},{"url":"://nope"}]}`, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_entry") {
		t.Fatalf("want 400 invalid_entry, got %d %s", rec.Code, rec.Body.String())
	}
	if upstreamPool.Enabled() {
		t.Fatal("a refused import must apply nothing")
	}
}

// Replace-mode import: a credentialed entry the backup omits is RETAINED
// (a credential is never removed by omission); a credential-free one is
// replaced; identity is preserved by authority.
func TestUpstreamV2_ImportReplacePreservesCredentialedAndIdentity(t *testing.T) {
	upEnv(t)
	credID := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-b.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	rec = upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-c.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	cID, _ := upJSON(t, rec)["entry"].(map[string]any)["id"].(string)

	rec = upImport(t, `{"version":1,"upstreamProxies":[{"url":"HTTP://PARENT-C.TEST:3128/"}]}`, "replace")
	if rec.Code != 200 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	entries, _ := upGet(t)["entries"].([]any)
	ids := map[string]string{}
	for _, e := range entries {
		m := e.(map[string]any)
		ids[m["host"].(string)] = m["id"].(string)
	}
	if ids[upRedHost] != credID {
		t.Fatalf("the credentialed entry must survive a replace-mode import that omits it: %v", ids)
	}
	if _, gone := ids["parent-b.test"]; gone {
		t.Fatal("a credential-free entry omitted by a replace-mode import must be removed")
	}
	if ids["parent-c.test"] != cID {
		t.Fatalf("identity must be preserved by canonical authority, got %v", ids)
	}
	if pw, _ := upProxyURLFor(t, upRedHost).User.Password(); pw != upRedPW {
		t.Fatal("the credential must be intact after the import")
	}
}

// upProxyURLFor drives the round-robin until the named host is selected.
func upProxyURLFor(t *testing.T, host string) *url.URL {
	t.Helper()
	for i := 0; i < 8; i++ {
		u := upProxyURL(t)
		if u != nil && u.Hostname() == host {
			return u
		}
	}
	t.Fatalf("host %s never selected", host)
	return nil
}

// A DELETE while the credential is UNUSABLE (key missing) is refused too —
// clearing is always the explicit, confirmed step.
func TestUpstreamV2_DeleteOfUnusableCredentialIsRefused(t *testing.T) {
	upEnv(t)
	id := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	upstreamPool.SetKey(nil, "key_missing")
	e := upEntry(t, id)
	if e["credentialState"] != upstream.CredentialUnusable {
		t.Fatalf("want unusable, got %v", e["credentialState"])
	}
	rec := upReq(t, "DELETE", fmt.Sprintf("/api/upstream/entries/%s?revision=%d", id, int64(e["revision"].(float64))), "")
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "credential_present" {
		t.Fatalf("want 409 credential_present, got %d %s", rec.Code, rec.Body.String())
	}
	if upEntry(t, id) == nil {
		t.Fatal("the entry must still exist")
	}
}

// The legacy spelling credential_configured is refused exactly like
// credentialState (C4: derived state is never accepted from a client).
func TestUpstreamV2_CredentialConfiguredFieldIsRejected(t *testing.T) {
	upEnv(t)
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-b.test","port":3128,"credential_configured":true,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusBadRequest || upJSON(t, rec)["code"] != "credential_state_not_accepted" {
		t.Fatalf("want 400 credential_state_not_accepted, got %d %s", rec.Code, rec.Body.String())
	}
	if upstreamPool.Enabled() {
		t.Fatal("nothing may be created")
	}
}

// YAML seeds that duplicate each other are refused at boot (the whole seed,
// fail-closed) and a YAML seed that duplicates a saved MANAGED authority is
// refused with the pool unchanged — never silently adopted.
func TestUpstreamV2_YAMLDuplicateSeedIsRefusedFailClosed(t *testing.T) {
	upEnv(t)
	err := upstreamPool.Configure([]UpstreamEntry{{URL: "http://parent-y.test:3128"}, {URL: "HTTP://parent-y.test:3128/"}}, 5, time.Minute)
	var dup *upstream.DuplicateAuthorityError
	if err == nil || !errors.As(err, &dup) || dup.Count != 1 {
		t.Fatalf("want a duplicate-authority refusal with count 1, got %v", err)
	}
	if upstreamPool.Enabled() {
		t.Fatal("a refused seed must publish nothing")
	}
	// A YAML password is refused outright (credentials never live in YAML).
	if err := upstreamPool.Configure([]UpstreamEntry{{URL: "http://u:p@parent-y.test:3128"}}, 5, time.Minute); err == nil {
		t.Fatal("a YAML URL with a password must be refused")
	}
	// Managed first, then a YAML seed naming the same authority.
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-y.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if err := upstreamPool.Configure([]UpstreamEntry{{URL: "http://parent-y.test:3128"}}, 5, time.Minute); err == nil {
		t.Fatal("a YAML seed duplicating a managed authority must be refused")
	}
	list := upstreamPool.List()
	if len(list) != 1 || list[0].Source != string(upstream.SourceManaged) {
		t.Fatalf("the managed entry must be unchanged and no YAML entry published, got %+v", list)
	}
}

// GET / export never carry userinfo; the export round-trips through import
// with the credential preserved (the redacted authority names it).
func TestUpstreamV2_ExportIsCredentialFreeAndRoundTrips(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	body, _ := json.Marshal(upGet(t))
	if strings.Contains(string(body), upRedPW) || strings.Contains(string(body), "svc:") {
		t.Fatalf("GET must never carry userinfo beyond the username: %s", body)
	}
	req := httptest.NewRequest("GET", "/api/config/export", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigExport(rec, req)
	if rec.Code != 200 {
		t.Fatalf("export: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), upRedPW) {
		t.Fatal("export must never carry a password")
	}
	var b configBackup
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.UpstreamProxies) != 1 || strings.Contains(b.UpstreamProxies[0].URL, ":"+upRedPW) {
		t.Fatalf("export upstream = %+v", b.UpstreamProxies)
	}
	rec = upImport(t, rec.Body.String(), "")
	if rec.Code != 200 {
		t.Fatalf("re-import of an export: %d %s", rec.Code, rec.Body.String())
	}
	if pw, _ := upProxyURL(t).User.Password(); pw != upRedPW {
		t.Fatal("re-importing an export must keep the sealed credential")
	}
}

// The settings file never carries the plaintext after any of the
// mutations above (belt-and-braces over R15).
func TestUpstreamV2_SettingsFileStaysSealedAcrossMutations(t *testing.T) {
	upEnv(t)
	id := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	e := upEntry(t, id)
	rec := upReq(t, "PUT", "/api/upstream/entries/"+id, fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":"svc","revision":%d}`, upRedHost, int64(e["revision"].(float64))))
	if rec.Code != 200 {
		t.Fatalf("same-authority PUT must succeed: %d %s", rec.Code, rec.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "admin_settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), upRedPW) {
		t.Fatal("plaintext reached admin_settings.json")
	}
	if pw, _ := upProxyURL(t).User.Password(); pw != upRedPW {
		t.Fatal("a same-authority edit must keep the credential")
	}
}
