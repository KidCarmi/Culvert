package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ─── panel + nav render (the GUI deliverable) ───────────────────────────────

func TestReleaseGUI_PanelAndNavRender(t *testing.T) {
	fx := newE2EFixture(t)
	resp := mustGet(t, fx.anonClient(), fx.srv.URL+"/") // SPA shell is public
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	for _, marker := range []string{
		`data-view="releases"`,        // sidebar nav item
		`id="view-releases"`,          // view panel
		`id="release-dispatch-modal"`, // dispatch modal
		`id="rel-catalog"`,            // catalog container
		`id="rel-current"`,            // current card
		`id="rel-status"`,             // status container
		`data-click="releaseDispatchOpen"`,
		`data-click="releaseResume"`,
		`loadReleases`, // wired loader
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("rendered SPA missing release-management marker %q", marker)
		}
	}
}

// ─── RBAC through the full middleware chain ─────────────────────────────────

func TestReleaseGUI_ViewerCannotDispatch(t *testing.T) {
	fx := newE2EFixture(t)
	newReleaseFixture(t, mustLoad(t, validSource()),
		map[string]*fakeAgent{"A": {applyOpID: "op", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}})

	viewer := fx.loginAs(e2eViewUser, e2eViewPass)
	code, _ := postJSON(t, viewer, fx.srv.URL+"/api/releases/dispatch",
		map[string]any{"release_id": "rel_a", "agent": "A"})
	if code != http.StatusForbidden {
		t.Fatalf("viewer dispatch = %d; want 403", code)
	}
}

func TestReleaseGUI_AdminCanDispatch(t *testing.T) {
	fx := newE2EFixture(t)
	newReleaseFixture(t, mustLoad(t, validSource()),
		map[string]*fakeAgent{"A": {applyOpID: "op-gui", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}})

	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	code, body := postJSON(t, admin, fx.srv.URL+"/api/releases/dispatch",
		map[string]any{"release_id": "rel_a", "agent": "A"})
	if code != http.StatusAccepted {
		t.Fatalf("admin dispatch = %d; want 202 (%s)", code, body["status"])
	}
	if body["op_id"] != "op-gui" {
		t.Fatalf("202 op_id = %v; want op-gui", body["op_id"])
	}
}

func TestReleaseGUI_AdminCanResume(t *testing.T) {
	fx := newE2EFixture(t)
	newReleaseFixture(t, mustLoad(t, validSource()),
		map[string]*fakeAgent{"A": {waitState: agentStateSucceeded, runningSeq: [][]string{{dispatchRepo + "@" + digA}}}})

	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	code, _ := postJSON(t, admin, fx.srv.URL+"/api/releases/dispatch/resume", map[string]any{
		"agent": "A",
		"resume_context": map[string]any{
			"AgentID": "A", "OpID": "op-prior", "ReleaseID": "rel_a",
			"TargetPinnedRef": dispatchRepo + "@" + digA,
		},
	})
	if code != http.StatusAccepted {
		t.Fatalf("admin resume = %d; want 202", code)
	}
}

// ─── read states surfaced to the panel ──────────────────────────────────────

func TestReleaseGUI_AvailableFalseEmptyState(t *testing.T) {
	fx := newE2EFixture(t)
	newReleaseFixture(t, nil, map[string]*fakeAgent{"A": {}}) // nil catalog ⇒ available:false

	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	doc := decodeJSONMap(t, mustGet(t, admin, fx.srv.URL+"/api/releases")) //nolint:bodyclose // decodeJSONMap closes resp.Body
	if doc["available"] != false {
		t.Fatalf("available = %v; want false for the empty-state panel", doc["available"])
	}
}

func TestReleaseGUI_UnknownCurrentState(t *testing.T) {
	fx := newE2EFixture(t)
	foreign := dispatchRepo + "@sha256:" + repeat64('c')
	newReleaseFixture(t, mustLoad(t, validSource()),
		map[string]*fakeAgent{"A": {runningSeq: [][]string{{foreign}}}})

	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	doc := decodeJSONMap(t, mustGet(t, admin, fx.srv.URL+"/api/releases/current?agent=A")) //nolint:bodyclose // decodeJSONMap closes resp.Body
	if doc["known"] != false {
		t.Fatalf("known = %v; want false (custom/unrecognized current)", doc["known"])
	}
}

// postJSON POSTs a JSON body via the authenticated client and returns the status
// code + decoded JSON body.
func postJSON(t *testing.T, c *http.Client, url string, payload any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}
