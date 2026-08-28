package main

// urlcat_ownership_test.go — Blocker D proofs (2D-B final correction
// §§12–16): the server owns the mutability truth for BUILT-IN categories,
// derived from the live effective view's Source (the actual authority
// semantics), and the v2 (fenced) mutation surface refuses a write the
// enforced view would ignore.
//
// The §22-D red-before half: against the prior frozen candidate, a v2 edit
// of a feed-owned built-in category returned a durable 2xx while the policy
// path kept serving the signed generation's classes — a lie the fenced
// contract told the operator. These tests drive the REAL handlers with a
// downloaded-source view installed through the same seam the activation
// coordinator uses (saasEffectiveView.Swap — F3b-4 test precedent).

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// ownershipSetup seeds one built-in and one admin-created category and
// returns the current taxonomy revision.
func ownershipSetup(t *testing.T) string {
	t.Helper()
	urlcatAPISetup(t)
	catStore.ReplaceAll([]CategoryEntry{
		{Name: "Social Media", Hosts: []string{"social.example.com"}, BuiltIn: true},
		{Name: "Custom", Hosts: []string{"custom.example.com"}, BuiltIn: false},
	})
	return catStore.ContentFingerprint()
}

// installView swaps in a live effective view and restores the previous one on
// cleanup. Returns the installed pointer for enforcement-unchanged checks.
func installView(t *testing.T, v *effectiveCategoryView) *effectiveCategoryView {
	t.Helper()
	prev := saasEffectiveView.Swap(v)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
	return v
}

func downloadedView() *effectiveCategoryView {
	return newEffectiveView(map[string]string{"social.example.com": "Social Media"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 42, GenerationID: "gen-42"})
}

func TestFeedOwnership_V2MutationsRefusedWhileSignedGenerationServes(t *testing.T) {
	ops := []struct {
		name     string
		dispatch func(rev string) *httptest.ResponseRecorder
	}{
		{"put-hosts", func(rev string) *httptest.ResponseRecorder {
			return doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev,
				map[string]any{"hosts": []string{"edited.example.com"}})
		}},
		{"delete", func(rev string) *httptest.ResponseRecorder {
			return doURLCat(t, "DELETE", "/api/urlcat?name=Social%20Media&ifRevision="+rev, nil)
		}},
		{"host-add", func(rev string) *httptest.ResponseRecorder {
			return doURLCatHost(t, "POST", "/api/urlcat/host?ifRevision="+rev,
				map[string]any{"category": "Social Media", "host": "added.example.com"})
		}},
		{"host-remove", func(rev string) *httptest.ResponseRecorder {
			return doURLCatHost(t, "DELETE", "/api/urlcat/host?category=Social%20Media&host=social.example.com&ifRevision="+rev, nil)
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			rev := ownershipSetup(t)
			installed := installView(t, downloadedView())

			w := op.dispatch(rev)
			if w.Code != 409 {
				t.Fatalf("v2 %s of a feed-owned built-in category must be refused 409 (a durable 2xx the enforced view ignores is a lie); got %d: %s", op.name, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "saas-overrides") {
				t.Fatalf("the refusal must point at SaaS Overrides; got: %s", w.Body.String())
			}
			if got := catStore.ContentFingerprint(); got != rev {
				t.Fatalf("the refused mutation must change NOTHING durable: revision %q -> %q", rev, got)
			}
			if saasEffectiveView.Current() != installed {
				t.Fatal("the enforced view must be unchanged by the refusal")
			}
		})
	}
}

func TestFeedOwnership_AdminCreatedStaysWritableUnderSignedGeneration(t *testing.T) {
	rev := ownershipSetup(t)
	installView(t, downloadedView())

	w := doURLCat(t, "PUT", "/api/urlcat?name=Custom&ifRevision="+rev,
		map[string]any{"hosts": []string{"custom2.example.com"}})
	if w.Code != 200 {
		t.Fatalf("an admin-created (BuiltIn=false) category must stay writable under signed ownership; got %d: %s", w.Code, w.Body.String())
	}
	for _, e := range catStore.All() {
		if e.Name == "Custom" && e.BuiltIn {
			t.Fatal("Custom must survive as an admin-created (BuiltIn=false) category")
		}
	}
}

func TestFeedOwnership_BuiltInEditableWhileEmbeddedOrUnarmed(t *testing.T) {
	t.Run("unarmed-nil-view", func(t *testing.T) {
		rev := ownershipSetup(t)
		installView(t, nil)
		w := doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev,
			map[string]any{"hosts": []string{"edited.example.com"}})
		if w.Code != 200 {
			t.Fatalf("built-in edit with the lifecycle unarmed must succeed; got %d: %s", w.Code, w.Body.String())
		}
		// Effectiveness: with no view, the full catStore taxonomy serves the
		// policy fusion directly.
		if cat, _, _ := lookupHostCategory("edited.example.com"); !strings.EqualFold(cat, "Social Media") {
			t.Fatalf("edited host must be effective on the policy path; resolved %q", cat)
		}
	})
	t.Run("embedded-view", func(t *testing.T) {
		rev := ownershipSetup(t)
		// The embedded view is COMPOSED FROM catStore's built-ins, so
		// built-in rows stay locally owned and editable (a recompose folds
		// the edit into the served view — the F3b-4 recompose suite pins the
		// composition itself).
		installView(t, embeddedBaselineView())
		w := doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev,
			map[string]any{"hosts": []string{"edited.example.com"}})
		if w.Code != 200 {
			t.Fatalf("built-in edit while the EMBEDDED baseline serves must succeed; got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestFeedOwnership_StateReportsAuthorityAndWritability(t *testing.T) {
	readState := func(t *testing.T) (authority string, writable map[string]bool) {
		t.Helper()
		w := httptest.NewRecorder()
		apiURLCatState(w, getReq("/api/urlcat/state"))
		if w.Code != 200 {
			t.Fatalf("state: %d %s", w.Code, w.Body.String())
		}
		var resp struct {
			Categories []struct {
				Name     string `json:"name"`
				Writable *bool  `json:"writable"`
			} `json:"categories"`
			BuiltInAuthority string `json:"builtInAuthority"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		writable = map[string]bool{}
		for _, c := range resp.Categories {
			if c.Writable == nil {
				t.Fatalf("row %q carries no server-owned writable truth", c.Name)
			}
			writable[c.Name] = *c.Writable
		}
		return resp.BuiltInAuthority, writable
	}

	t.Run("signed-feed-owned", func(t *testing.T) {
		ownershipSetup(t)
		installView(t, downloadedView())
		authority, writable := readState(t)
		if authority != "signed-feed" {
			t.Fatalf("builtInAuthority = %q, want signed-feed", authority)
		}
		if writable["Social Media"] {
			t.Fatal("feed-owned built-in row must report writable=false")
		}
		if !writable["Custom"] {
			t.Fatal("admin-created row must report writable=true under signed ownership")
		}
	})
	t.Run("local", func(t *testing.T) {
		ownershipSetup(t)
		installView(t, nil)
		authority, writable := readState(t)
		if authority != "local" {
			t.Fatalf("builtInAuthority = %q, want local", authority)
		}
		if !writable["Social Media"] || !writable["Custom"] {
			t.Fatalf("all rows writable while locally owned; got %v", writable)
		}
	})
}

// TestFeedOwnership_LegacyUnfencedPathKeepsCompatibility pins the deliberate
// compatibility decision: the LEGACY (unfenced) PUT keeps its pre-existing
// behavior on a feed-owned built-in — a durable write that stays superseded
// until the feed releases ownership. Only the v2 contract refuses.
func TestFeedOwnership_LegacyUnfencedPathKeepsCompatibility(t *testing.T) {
	ownershipSetup(t)
	installView(t, downloadedView())
	w := doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media",
		map[string]any{"hosts": []string{"legacy-edit.example.com"}})
	if w.Code != 200 {
		t.Fatalf("legacy unfenced PUT must keep compatibility; got %d: %s", w.Code, w.Body.String())
	}
}
