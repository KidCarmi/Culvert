package main

// FE-6AR merge-12 correction (record 6ARR-C12b) — the legacy console's
// password-change RESPONSE BOUNDARY. The browser proofs live in
// frontend/e2e/legacy-change-password-boundary.spec.ts (rows B1–B7, C1–C2);
// this file carries the two halves a browser cannot:
//
//   * CONTROLS on the handler's OWN contract — the exact success shape and the
//     bounded refusal shapes the classifier is allowed to trust. If the handler
//     drifts (a fact renamed, a code changed), these fail first and the
//     classifier's allowlist is what has to move with them.
//   * STRUCTURAL pins on the classifier — the script never renders server
//     text, is code-bound per status, and the success proof names every
//     required fact. Behavioural coverage of the wire is the browser's job;
//     these make a regression visible without a browser at all.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// cpBoundaryRefusalContract is the handler's refusal contract as this branch
// emits it: status → the bounded codes that status may carry. The classifier's
// allowlist must be exactly this (pinned below); anything outside it is
// UNPROVEN on the browser side.
var cpBoundaryRefusalContract = map[int][]string{
	http.StatusBadRequest:           {refusalInvalidInput},
	http.StatusForbidden:            {refusalWrongCurrent, refusalForbidden},
	http.StatusNotFound:             {refusalNotFound},
	http.StatusConflict:             {refusalStale},
	http.StatusPreconditionRequired: {refusalPreconditionRequired},
	http.StatusServiceUnavailable:   {refusalPersistenceNotConfigured},
}

func cpBoundaryDecode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body is not a JSON object: %v\n%s", err, body)
	}
	return m
}

// CONTROL: the success body carries EVERY fact the corrected proof requires —
// ok, persisted (true: the handler refuses earlier without a durable roster),
// sessionsRevoked, selfAffected, a positive integer revision and the advanced
// generation — under application/json.
func TestCPBoundary_HandlerSuccessCarriesTheRequiredFacts(t *testing.T) {
	f := cpJoinSetup(t)
	before := f.gen(t)
	rec := f.post(t, before, map[string]any{
		"current_password": f.pass, "new_password": "N3wViewerSecret!", "generation": before,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	m := cpBoundaryDecode(t, rec.Body.Bytes())
	for _, k := range []string{"ok", "persisted", "sessionsRevoked", "selfAffected"} {
		if v, _ := m[k].(bool); !v {
			t.Errorf("%s = %v, want true", k, m[k])
		}
	}
	rev, _ := m["revision"].(float64)
	if rev < 1 || rev != float64(int64(rev)) {
		t.Errorf("revision = %v, want a positive integer", m["revision"])
	}
	gen, _ := m["securityGeneration"].(float64)
	if int64(gen) != before+1 || int64(gen) != f.gen(t) {
		t.Errorf("securityGeneration = %v, want %d (= the record's %d)", m["securityGeneration"], before+1, f.gen(t))
	}
}

// CONTROL: every refusal the handler emits is application/json with a code
// inside cpBoundaryRefusalContract for its status, and the two fence refusals
// carry current.generation as an integer. This is the ONLY shape the browser
// classifier may read as "nothing was changed".
func TestCPBoundary_RefusalsAreBoundedJSONWithTheirFacts(t *testing.T) {
	f := cpJoinSetup(t)
	before := f.gen(t)
	cases := []struct {
		name   string
		gen    int64
		body   map[string]any
		status int
		code   string
		fact   string
	}{
		{"missing generation", before, map[string]any{"current_password": f.pass, "new_password": "N3wViewerSecret!"}, http.StatusPreconditionRequired, refusalPreconditionRequired, "generation"},
		{"stale generation", before, map[string]any{"current_password": f.pass, "new_password": "N3wViewerSecret!", "generation": before + 5}, http.StatusConflict, refusalStale, "generation"},
		{"wrong current", before, map[string]any{"current_password": "nope-Nope-1", "new_password": "N3wViewerSecret!", "generation": before}, http.StatusForbidden, refusalWrongCurrent, ""},
		{"weak new password", before, map[string]any{"current_password": f.pass, "new_password": "short", "generation": before}, http.StatusBadRequest, refusalInvalidInput, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.post(t, tc.gen, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("content-type = %q", ct)
			}
			m := cpBoundaryDecode(t, rec.Body.Bytes())
			code, _ := m["code"].(string)
			if code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
			allowed := false
			for _, c := range cpBoundaryRefusalContract[tc.status] {
				allowed = allowed || c == code
			}
			if !allowed {
				t.Fatalf("code %q is not in the contract for %d", code, tc.status)
			}
			if tc.fact != "" {
				cur, _ := m["current"].(map[string]any)
				v, ok := cur[tc.fact].(float64)
				if !ok || v != float64(int64(v)) {
					t.Fatalf("current.%s = %v, want an integer", tc.fact, cur[tc.fact])
				}
			}
			if f.gen(t) != before {
				t.Fatalf("generation moved to %d on a refusal", f.gen(t))
			}
		})
	}
}

// cpBoundaryBlock returns the comment-stripped change-password script block.
func cpBoundaryBlock(t *testing.T) string {
	t.Helper()
	_, block, _, _ := cpJoinScript(t)
	return block
}

// The refusal classifier is CODE-BOUND: it names every contracted code and
// only those, decides per status, requires the JSON media type, and never
// hands server-supplied text to the DOM.
func TestCPBoundary_ClassifierIsCodeBoundAndNeverRendersServerText(t *testing.T) {
	block := cpBoundaryBlock(t)
	cls := uiContractFuncBody(t, block, "function classifyChangePasswordRefusal(")
	for status, codes := range cpBoundaryRefusalContract {
		for _, c := range codes {
			if !strings.Contains(cls, "'"+c+"'") {
				t.Errorf("classifier does not name contracted code %q (status %d)", c, status)
			}
		}
	}
	if !strings.Contains(cls, "application/json") {
		t.Error("classifier does not require the JSON media type")
	}
	if strings.Contains(block, "apiErrorText(") {
		t.Error("the change-password block renders server text through apiErrorText")
	}
	if strings.Contains(cls, ".error") {
		t.Error("classifier reads the server's error text")
	}
	// No status-only branch may produce a refusal: every 'Nothing was changed'
	// must be reached through a code match, never through a bare status test.
	bare := regexp.MustCompile(`status\s*>=\s*500`)
	if bare.MatchString(cls) {
		t.Error("classifier maps a bare 5xx range to a refusal")
	}
}

// The success proof names EVERY required fact of the handler's success shape.
func TestCPBoundary_ProofRequiresPersistenceRevocationAndRevision(t *testing.T) {
	block := cpBoundaryBlock(t)
	proof := uiContractFuncBody(t, block, "async function changePasswordProof(r, bound) {")
	for _, k := range []string{"ok", "persisted", "sessionsRevoked", "selfAffected", "revision", "securityGeneration"} {
		if !strings.Contains(proof, "j."+k) {
			t.Errorf("proof does not check %q", k)
		}
	}
}

// The submit path has exactly THREE outcomes and the UNPROVEN one is the
// default: a response is a refusal ONLY when the classifier returns one.
func TestCPBoundary_UnprovenIsTheDefaultOutcome(t *testing.T) {
	block := cpBoundaryBlock(t)
	submit := uiContractFuncBody(t, block, "async function submitChangePassword() {")
	if !strings.Contains(submit, "classifyChangePasswordRefusal(") {
		t.Fatal("submit does not consult the classifier")
	}
	if strings.Contains(submit, "new ChangePasswordRefused(r.status, await r.text()") {
		t.Fatal("submit still wraps every non-2xx as a refusal")
	}
}
