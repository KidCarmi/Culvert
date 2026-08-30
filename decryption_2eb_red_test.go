package main

// decryption_2eb_red_test.go — 2E-B Decryption Operations: red-before proofs
// against 25a80a5e, written in final (green) form so each failure at the
// candidate IS the defect evidence. All assertions are HTTP-level (no new Go
// symbols), so the file compiles and runs meaningfully at the predecessor.
//
// Defect families (each demonstrated RED at the candidate):
//
//	§A DESTINATION PRIVACY LOST UPDATE — PUT /api/decryption/redaction is a
//	   whole-object write with NO stale-writer fence and the GET carries no
//	   revision: two admins read the posture, edit independently, and the
//	   second silently overwrites (worse: the body is decoded with
//	   DisallowUnknownFields, so a client that TRIES to assert a fence gets a
//	   400). New contract: GET returns a coherent {state, revision(state)}
//	   snapshot; the PUT accepts an OPTIONAL ifRevision compared inside the
//	   AdminSettings writer domain; a mismatch is the ONE structured 409.
//	§B ROTATION EXACT-ONCE — the pseudonym-key rotation exposes NO non-secret
//	   server fact: GET reports only key_provisioned (true before AND after a
//	   rotation), so a transport-lost rotation is UNRESOLVABLE and a blind
//	   retry silently rotates twice (breaking correlation a second time). New
//	   contract: a non-secret, restart-durable key_id changes with every
//	   rotation; it is part of the revision, so a fenced retry asserting
//	   pre-rotation truth is a 409 that cannot mint another key.
//	§D TUNABLES LOST UPDATE — PUT /api/decryption-exclusions/tunables ignores
//	   ?ifRevision=, so two admins silently overwrite a newer configuration;
//	   and no surface serves a revision for the CURRENT tunable values. New
//	   contract: the exclusions GET carries tunables_revision derived from
//	   the SAME stats snapshot it returns; the PUT compares the assertion
//	   inside the AdminSettings writer domain.
//	§E/§I VOLATILE CACHE TRUTH — the evict audit records "manual eviction of
//	   a learned exclusion" even when nothing was present (removed=false),
//	   and the entry listing is unbounded at enterprise scale (up to
//	   max_entries=262144 rows). New contract: the audit detail reflects the
//	   actual outcome; GET accepts ?limit= with an explicit truncated fact.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// dec2ebIsolate isolates the destination-privacy globals + settings file.
func dec2ebIsolate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	swapDecRedact(t, false)
	swapTrafficKey(t, nil)
	return path
}

func dec2ebDo(t *testing.T, role UIRole, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := roleReq(role, method, path, body)
	switch {
	case path == "/api/decryption/redaction":
		apiDecryptionRedaction(w, r)
	case path == "/api/decryption-exclusions" ||
		len(path) > len("/api/decryption-exclusions") && path[:27] == "/api/decryption-exclusions?":
		apiDecryptionExclusions(w, r)
	default:
		apiDecryptionExclusionTunables(w, r)
	}
	return w
}

func dec2ebBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response: %v (%s)", err, w.Body.String())
	}
	return m
}

func dec2ebStr(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("response is missing the %q contract field: %v", key, m)
	}
	return v
}

// dec2ebRedactionMirror is the client-side mirror of the redaction revision
// derivation: a pure function of the returned state, so coherence is checkable
// from the response alone.
func dec2ebRedactionMirror(redact bool, keyID string) string {
	return contentSecRevision("dec-redaction", fmt.Sprintf("%t", redact), keyID)
}

// ─── §A: destination privacy — coherent GET + stale-writer fence ────────────

func TestDec2EB_RedactionGETCoherentRevisionAndKeyID(t *testing.T) {
	dec2ebIsolate(t)
	w := dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d", w.Code)
	}
	m := dec2ebBody(t, w)
	rev := dec2ebStr(t, m, "revision")
	keyID := dec2ebStr(t, m, "key_id")
	redact, _ := m["redact_hosts"].(bool)
	if want := dec2ebRedactionMirror(redact, keyID); rev != want {
		t.Fatalf("GET revision does not fingerprint the returned state: got %s want %s", rev, want)
	}
}

func TestDec2EB_RedactionStaleWriteRefused(t *testing.T) {
	dec2ebIsolate(t)
	// Admin A enables the posture and reviews the resulting state.
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true}); w.Code != 200 {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	g := dec2ebBody(t, dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil))
	staleRev := dec2ebStr(t, g, "revision")

	// Admin B lands a newer posture.
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": false}); w.Code != 200 {
		t.Fatalf("admin B disable = %d: %s", w.Code, w.Body.String())
	}

	// Admin A's stale write asserting the superseded revision must be the
	// structured 409 with NO mutation — never a silent overwrite of B's newer
	// posture (and never a 400 for daring to assert a fence).
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true, "ifRevision": staleRev})
	if w.Code != 409 {
		t.Fatalf("stale fenced PUT = %d, want the structured 409: %s", w.Code, w.Body.String())
	}
	var conflict struct {
		Error           string `json:"error"`
		CurrentRevision string `json:"currentRevision"`
		YourRevision    string `json:"yourRevision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil ||
		conflict.Error == "" || conflict.YourRevision != staleRev || conflict.CurrentRevision == "" {
		t.Fatalf("conflict dialect: %s (err=%v)", w.Body.String(), err)
	}
	if decRedactHosts() {
		t.Fatal("the stale write mutated the posture — admin B's newer configuration was overwritten")
	}
}

// ─── §B: pseudonym-key rotation — observable generation + exact-once ────────

func TestDec2EB_RotationChangesObservableGeneration(t *testing.T) {
	dec2ebIsolate(t)
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true}); w.Code != 200 {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	g := dec2ebBody(t, dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil))
	before := dec2ebStr(t, g, "key_id")
	if before == "" {
		t.Fatal("an enabled posture must report a non-empty key_id (the non-secret pseudonym generation)")
	}

	// 2E-B correction: a rotation is a fenced, operation-identified command.
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": true, "operation_id": "op-2eb-gen",
			"ifRevision": dec2ebStr(t, g, "revision")})
	if w.Code != 200 {
		t.Fatalf("rotate = %d: %s", w.Code, w.Body.String())
	}
	resp := dec2ebBody(t, w)
	if rotated, _ := resp["key_rotated"].(bool); !rotated {
		t.Fatalf("rotate response: %v", resp)
	}
	after := dec2ebStr(t, dec2ebBody(t,
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)), "key_id")
	if after == "" || after == before {
		t.Fatalf("rotation must change the observable key_id (unknown-outcome recovery depends on it): before=%q after=%q", before, after)
	}
	// The rotation must preserve the posture (rotate-only PUT).
	if !decRedactHosts() {
		t.Fatal("a rotate-only PUT silently disabled the posture")
	}
}

func TestDec2EB_RotationStaleFenceCannotDoubleRotate(t *testing.T) {
	dec2ebIsolate(t)
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true}); w.Code != 200 {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	g := dec2ebBody(t, dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil))
	preRev := dec2ebStr(t, g, "revision")

	// The v2 client always rotates FENCED against the reviewed truth.
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": true, "operation_id": "op-2eb-fence-a", "ifRevision": preRev})
	if w.Code != 200 {
		t.Fatalf("fenced rotate = %d, want 200: %s", w.Code, w.Body.String())
	}
	rotatedID := dec2ebStr(t, dec2ebBody(t,
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)), "key_id")

	// A DIFFERENT rotation operation asserting the superseded revision (a
	// stale writer, not a retry) must be refused — and must NOT mint yet
	// another generation. (The byte-identical retry of the SAME operation is
	// the idempotent-replay case, pinned by
	// TestDec2EB2_ReplaySameOperationNeverRotatesTwice.)
	w2 := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": true, "operation_id": "op-2eb-fence-b", "ifRevision": preRev})
	if w2.Code != 409 {
		t.Fatalf("retried fenced rotate = %d, want 409 (a retry must never silently rotate twice): %s", w2.Code, w2.Body.String())
	}
	stillID := dec2ebStr(t, dec2ebBody(t,
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)), "key_id")
	if stillID != rotatedID {
		t.Fatalf("the refused retry rotated anyway: %q → %q", rotatedID, stillID)
	}
}

func TestDec2EB_RotationDurableAcrossRestart(t *testing.T) {
	path := dec2ebIsolate(t)
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true}); w.Code != 200 {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	preRev := dec2ebStr(t, dec2ebBody(t,
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)), "revision")
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": true, "operation_id": "op-2eb-durable",
			"ifRevision": preRev}); w.Code != 200 {
		t.Fatalf("rotate = %d: %s", w.Code, w.Body.String())
	}
	keyID := dec2ebStr(t, dec2ebBody(t,
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)), "key_id")

	// Durable BEFORE successful completion: the settings file already carries
	// the rotated generation.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("settings decode: %v", err)
	}
	if got, _ := persisted["traffic_pseudonym_key_id"].(string); got != keyID {
		t.Fatalf("the rotated generation is not durable: file key id %q, served key id %q", got, keyID)
	}

	// Simulated restart: wipe the live state, load from disk, and the SAME
	// generation must be observable (exact-once truth survives restart).
	setDecRedactHosts(false)
	setTrafficPseudonymKey(nil)
	LoadAdminSettings(path)
	afterRestart := dec2ebStr(t, dec2ebBody(t,
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)), "key_id")
	if afterRestart != keyID {
		t.Fatalf("restart changed the pseudonym generation: %q → %q", keyID, afterRestart)
	}
	if !decRedactHosts() {
		t.Fatal("restart lost the enabled posture")
	}
}

// Secret boundary (control — green at both trees, then pins the new fields):
// no response may carry the raw pseudonym key in any common encoding, and the
// non-secret key_id must not BE one of those encodings.
func TestDec2EB_RedactionResponsesNeverCarryKeyMaterial(t *testing.T) {
	path := dec2ebIsolate(t)
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true}); w.Code != 200 {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("settings decode: %v", err)
	}
	if len(s.TrafficPseudonymKey) != trafficKeyLen {
		t.Fatalf("precondition: no persisted key (%d bytes)", len(s.TrafficPseudonymKey))
	}
	encodings := []string{
		hex.EncodeToString(s.TrafficPseudonymKey),
		base64.StdEncoding.EncodeToString(s.TrafficPseudonymKey),
		base64.RawStdEncoding.EncodeToString(s.TrafficPseudonymKey),
	}
	for _, w := range []*httptest.ResponseRecorder{
		dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil),
		dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction", map[string]any{"redact_hosts": true}),
	} {
		body := w.Body.String()
		for _, enc := range encodings {
			if enc != "" && containsStr(body, enc) {
				t.Fatalf("response leaks pseudonym key material: %s", body)
			}
		}
	}
}

// Persist-failure truth (pin — green at both trees): a failed durable write is
// a 500 and the running posture is unchanged.
func TestDec2EB_RedactionPersistFailureTruthful(t *testing.T) {
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "no-such-dir", "admin_settings.json"))
	swapDecRedact(t, false)
	swapTrafficKey(t, nil)
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true})
	if w.Code != 500 {
		t.Fatalf("PUT with a failing settings volume = %d, want 500", w.Code)
	}
	if decRedactHosts() {
		t.Fatal("a failed persist left the live posture changed (hidden restart divergence)")
	}
}

// ─── §D: tunables — coherent revision + stale-writer fence ──────────────────

// dec2ebTunablesMirror mirrors the tunables revision derivation from the
// five stats fields of the SAME response.
func dec2ebTunablesMirror(confirmN, ttl, pinned, window, maxEntries int) string {
	return contentSecRevision("autoexclude-tunables",
		strconv.Itoa(confirmN), strconv.Itoa(ttl), strconv.Itoa(pinned),
		strconv.Itoa(window), strconv.Itoa(maxEntries))
}

func dec2ebStatsInt(t *testing.T, stats map[string]any, key string) int {
	t.Helper()
	v, ok := stats[key].(float64)
	if !ok {
		t.Fatalf("stats missing %q: %v", key, stats)
	}
	return int(v)
}

func TestDec2EB_ExclusionsGETCoherentTunablesRevision(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	w := dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption-exclusions", nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d", w.Code)
	}
	m := dec2ebBody(t, w)
	rev := dec2ebStr(t, m, "tunables_revision")
	stats, ok := m["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats missing: %v", m)
	}
	want := dec2ebTunablesMirror(
		dec2ebStatsInt(t, stats, "confirm_n"),
		dec2ebStatsInt(t, stats, "ttl_secs"),
		dec2ebStatsInt(t, stats, "pinned_ttl_secs"),
		dec2ebStatsInt(t, stats, "window_secs"),
		dec2ebStatsInt(t, stats, "max_entries"),
	)
	if rev != want {
		t.Fatalf("tunables_revision does not fingerprint the returned stats snapshot: got %s want %s", rev, want)
	}
}

func TestDec2EB_TunablesStaleWriteRefused(t *testing.T) {
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	swapAutoExclude(t, autoexclude.Config{})
	g := dec2ebBody(t, dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption-exclusions", nil))
	rev0 := dec2ebStr(t, g, "tunables_revision")

	// Admin A lands a newer configuration under the reviewed revision.
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut,
		"/api/decryption-exclusions/tunables?ifRevision="+rev0,
		map[string]any{"confirm_n": 3}); w.Code != 200 {
		t.Fatalf("fenced PUT A = %d: %s", w.Code, w.Body.String())
	}

	// Admin B's write asserting the SUPERSEDED revision must be the structured
	// 409 with admin A's newer configuration intact.
	w := dec2ebDo(t, RoleAdmin, http.MethodPut,
		"/api/decryption-exclusions/tunables?ifRevision="+rev0,
		map[string]any{"confirm_n": 4})
	if w.Code != 409 {
		t.Fatalf("stale fenced PUT = %d, want 409 (admin A's newer tunables were silently overwritten): %s", w.Code, w.Body.String())
	}
	if got := autoExclude().Stats().ConfirmN; got != 3 {
		t.Fatalf("confirm_n = %d after the refused stale write, want admin A's 3", got)
	}
}

// ─── §E/§I: volatile cache truth ────────────────────────────────────────────

func TestDec2EB_EvictAuditTruthfulOnMiss(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	w := dec2ebDo(t, RoleOperator, http.MethodDelete,
		"/api/decryption-exclusions?scope=s2eb-miss&host=missing-2eb.example", nil)
	if w.Code != 200 {
		t.Fatalf("DELETE = %d", w.Code)
	}
	m := dec2ebBody(t, w)
	if removed, _ := m["removed"].(bool); removed {
		t.Fatalf("removed=true for an absent entry: %v", m)
	}
	// The audit record must not claim an eviction happened.
	found := false
	for _, e := range auditGet() {
		if e.Action == "decryption.autoexclude.evict" && e.Object == "s2eb-miss/missing-2eb.example" {
			found = true
			if !containsStr(e.Detail, "not present") {
				t.Fatalf("audit for a no-op eviction claims an eviction: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Fatal("no audit record for the eviction request")
	}
}

func TestDec2EB_ExclusionsBoundedRead(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	for _, h := range []string{"a-2eb.example", "b-2eb.example", "c-2eb.example"} {
		autoExclude().Observe("s2eb", "", "profile-2eb", h, autoexclude.ReasonUnsupportedParams, "tok")
	}
	if n := autoExclude().Len(); n != 3 {
		t.Fatalf("seed: %d active entries, want 3", n)
	}
	w := dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption-exclusions?limit=2", nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d", w.Code)
	}
	m := dec2ebBody(t, w)
	list, ok := m["exclusions"].([]any)
	if !ok {
		t.Fatalf("exclusions missing: %v", m)
	}
	if len(list) != 2 {
		t.Fatalf("?limit=2 returned %d entries — the management read is unbounded at enterprise scale", len(list))
	}
	if truncated, _ := m["truncated"].(bool); !truncated {
		t.Fatalf("a limited listing must carry the explicit truncated fact: %v", m)
	}
	stats, _ := m["stats"].(map[string]any)
	if dec2ebStatsInt(t, stats, "active") != 3 {
		t.Fatalf("stats.active must keep the full population: %v", stats)
	}
}
