package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSaaSFeedSyncer_ConfigureAndStop(t *testing.T) {
	s := &SaaSFeedSyncer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if s.Enabled() {
		t.Error("should not be enabled before Configure")
	}
	s.Configure("http://localhost:9999/feed.json", 1*time.Hour)
	if !s.Enabled() {
		t.Error("should be enabled after Configure")
	}
	s.Stop()
	if s.Enabled() {
		t.Error("should not be enabled after Stop")
	}
}

func TestSaaSFeedSyncer_SyncMerge(t *testing.T) {
	// Serve a test feed with one category.
	feed := []CategoryEntry{{
		Name:  "TestCat",
		Hosts: []string{"test1.com", "test2.com"},
	}}
	feedJSON, _ := json.Marshal(feed)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(feedJSON) //nolint:errcheck
	}))
	defer ts.Close()

	s := &SaaSFeedSyncer{
		feedURL:  ts.URL,
		client:   ts.Client(),
		interval: 1 * time.Hour,
	}
	s.enabled.Store(true)

	s.Sync(context.Background())

	// Verify category was created in catStore.
	entry := catStore.GetByName("TestCat")
	if entry == nil {
		t.Fatal("TestCat category not created after sync")
	}
	if len(entry.Hosts) < 2 {
		t.Errorf("expected at least 2 hosts, got %d", len(entry.Hosts))
	}

	// Sync again — should not duplicate.
	s.Sync(context.Background())
	entry2 := catStore.GetByName("TestCat")
	if len(entry2.Hosts) != len(entry.Hosts) {
		t.Errorf("duplicate sync added hosts: %d → %d", len(entry.Hosts), len(entry2.Hosts))
	}
}

func TestSaaSFeedSyncer_Stats(t *testing.T) {
	s := &SaaSFeedSyncer{
		feedURL:  "http://example.com/feed.json",
		interval: 24 * time.Hour,
	}
	url, _, _, interval := s.Stats()
	if url != "http://example.com/feed.json" {
		t.Errorf("url = %q", url)
	}
	if interval != 24*time.Hour {
		t.Errorf("interval = %v", interval)
	}
}

func TestSaaSFeedSyncer_EmptyURL(t *testing.T) {
	s := &SaaSFeedSyncer{client: &http.Client{}}
	s.Configure("", 1*time.Hour)
	if s.Enabled() {
		t.Error("empty URL should not enable")
	}
}

func TestCategoryStore_GetByName(t *testing.T) {
	cs := newCategoryStore(defaultCategoryEntries())

	// Should find existing category (case-insensitive).
	entry := cs.GetByName("ai")
	if entry == nil {
		t.Fatal("GetByName('ai') returned nil")
	}
	if entry.Name != "AI" {
		t.Errorf("name = %q, want 'AI'", entry.Name)
	}

	// Non-existent.
	if cs.GetByName("NonExistent") != nil {
		t.Error("expected nil for non-existent category")
	}
}

func TestApiCategoryGroups_CRUD(t *testing.T) {
	setupProxyTest(t)

	// GET - empty.
	w := httptest.NewRecorder()
	r := getReq("/api/category-groups")
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("GET status = %d", w.Code)
	}

	// POST - create.
	body := `{"name":"Test Group","categories":["AI","News"]}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/category-groups", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("POST status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify it exists.
	g := globalCategoryGroups.GetByName("Test Group")
	if g == nil {
		t.Fatal("group not found after POST")
	}

	// PUT - update.
	body = `{"name":"Test Group","categories":["AI","News","Streaming"]}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/api/category-groups", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("PUT status = %d", w.Code)
	}

	// DELETE.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/category-groups?name=Test+Group", nil)
	r = adminCtx(r)
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("DELETE status = %d, body = %s", w.Code, w.Body.String())
	}
}
