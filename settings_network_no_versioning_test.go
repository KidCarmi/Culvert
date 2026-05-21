package main

// settings_network_no_versioning_test.go — regression coverage for
// the Category D' (direction A) fix that removed saveConfigVersion
// from apiNetworkSettings. Per roadmap/CATEGORY-D-PRIME-DIRECTION.md
// §4 and the upstream roadmap/CONFIG-VERSIONING-TRIAGE.md.
//
// Background
// ==========
// Before this PR, apiNetworkSettings (ui_config.go) called:
//
//   auditEvent(r, "settings.network", "updated", ...)
//   adminSettingsSave()
//   saveConfigVersion(sessionAdmin(r), "settings.network")
//
// The saveConfigVersion call was misleading: network settings are
// per-node operational state (proxyExternalBaseURL, uiExtraSANs,
// trustForwardedHeaders) not in captureConfigBackup, not in
// ConfigSnapshot, and not HA-replicated. The version log entry
// claimed reversibility the rollback path doesn't deliver.
//
// Direction A (remove the misleading call) was chosen over direction
// B (extend the rollback surface) because automatic rollback would
// be genuinely dangerous:
//   - trustForwardedHeaders flip-back is a security regression
//   - uiExtraSANs change triggers cert regeneration
//   - proxyExternalBaseURL change must be coordinated with the IdP
//
// What this test asserts
// ======================
// A successful POST /api/settings/network:
//   1. Returns HTTP 200.
//   2. Mutates proxyExternalBaseURL / uiExtraSANs / trustForwardedHeaders
//      to the posted values (proves the mutation path ran past the
//      audit + removed-saveCV branch).
//   3. Emits an audit-ring entry with Action="settings.network" and
//      Detail containing a unique per-run discriminator (per CLAUDE.md
//      test-authoring pitfalls — no len(auditGet()) deltas).
//   4. Does NOT produce a config-version envelope with
//      Meta.Action="settings.network" on disk.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// snapshotNetworkSettings captures and restores the three
// package-globals apiNetworkSettings mutates. Same whitebox idiom as
// snapshotCfgUIUsers / snapshotConfigVersionsDir.
func snapshotNetworkSettings(t *testing.T) {
	t.Helper()
	prevBase := proxyExternalBaseURL
	prevSANs := append([]string(nil), uiExtraSANs...)
	prevTrust := trustForwardedHeaders
	t.Cleanup(func() {
		proxyExternalBaseURL = prevBase
		uiExtraSANs = prevSANs
		trustForwardedHeaders = prevTrust
	})
}

// TestAPINetworkSettings_DoesNotCreateConfigVersion is the regression
// guard for the Category D' (direction A) fix. With the
// saveConfigVersion call restored on this handler, the test fails
// because an envelope with Meta.Action="settings.network" appears in
// the config-version directory.
func TestAPINetworkSettings_DoesNotCreateConfigVersion(t *testing.T) {
	tmp := snapshotConfigVersionsDir(t)
	snapshotNetworkSettings(t)

	// Force baseline values DIFFERENT from what we'll POST so the
	// mutation assertion is unambiguous.
	proxyExternalBaseURL = "https://baseline.invalid"
	uiExtraSANs = []string{"baseline-san.invalid"}
	trustForwardedHeaders = false

	// Unique discriminator embedded in BaseURL so the audit assertion
	// finds THIS run's entry under -count=N / -shuffle. The audit Detail
	// includes "base_url=..." (ui_config.go:867-868) so the URL string
	// flows through into the audit entry.
	discriminator := "test-settings-network-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000"), ".", "-")
	wantBaseURL := "https://post.example.invalid/" + discriminator
	wantSANs := []string{"san1.post.example.invalid", "san2.post.example.invalid"}
	const wantTrust = true

	bodyBytes, _ := json.Marshal(map[string]any{
		"base_url":                  wantBaseURL,
		"ui_sans":                   wantSANs,
		"trust_forwarded_headers":   wantTrust,
	})

	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/settings/network", bytes.NewReader(bodyBytes))
	r.Header.Set("Content-Type", "application/json")

	apiNetworkSettings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("apiNetworkSettings status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}

	// Mutation actually landed in the globals — proves the handler ran
	// past the audit + removed-saveCV branch to jsonOK.
	// SetProxyBaseURL trims any trailing "/" (store.go:1605), so
	// compare against the trimmed value.
	wantBaseTrimmed := strings.TrimRight(wantBaseURL, "/")
	if proxyExternalBaseURL != wantBaseTrimmed {
		t.Errorf("proxyExternalBaseURL = %q; want %q", proxyExternalBaseURL, wantBaseTrimmed)
	}
	if !reflect.DeepEqual(uiExtraSANs, wantSANs) {
		t.Errorf("uiExtraSANs = %v; want %v", uiExtraSANs, wantSANs)
	}
	if trustForwardedHeaders != wantTrust {
		t.Errorf("trustForwardedHeaders = %v; want %v", trustForwardedHeaders, wantTrust)
	}

	// Audit trail must still fire. Discriminator search: the audit
	// Detail (ui_config.go:867-868) is "base_url=<URL> trust_fwd=<bool>
	// sans=<list>" — the URL contains the discriminator.
	assertAuditEntryWithDiscriminator(t, "settings.network", discriminator)

	// And the key assertion: no config-version envelope with
	// Meta.Action="settings.network".
	assertNoConfigVersionWithAction(t, tmp, "settings.network")
}
