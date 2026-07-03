package saasfeed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSyncer_ConfigureAndStop(t *testing.T) {
	s := New(Deps{Client: &http.Client{Timeout: 5 * time.Second}})
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

func TestSyncer_SyncParsesAndDispatchesToMerge(t *testing.T) {
	// Serve a test feed with one category.
	feed := []Category{{
		Name:  "TestCat",
		Hosts: []string{"test1.com", "test2.com"},
	}}
	feedJSON, _ := json.Marshal(feed)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(feedJSON) //nolint:errcheck // test server write
	}))
	defer ts.Close()

	var got []Category
	s := New(Deps{
		Client: ts.Client(),
		Merge: func(cats []Category) int {
			got = cats
			n := 0
			for _, c := range cats {
				n += len(c.Hosts)
			}
			return n
		},
	})
	s.SetFeedURLForTest(ts.URL)

	s.Sync(context.Background())

	if len(got) != 1 || got[0].Name != "TestCat" || len(got[0].Hosts) != 2 {
		t.Fatalf("merge received %+v, want the parsed TestCat feed", got)
	}
	_, lastSync, count, _ := s.Stats()
	if lastSync.IsZero() || count != 2 {
		t.Errorf("Stats after sync = (%v, %d), want fresh timestamp and count 2", lastSync, count)
	}
}

func TestSyncer_Stats(t *testing.T) {
	s := &Syncer{
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

func TestSyncer_EmptyURL(t *testing.T) {
	s := New(Deps{Client: &http.Client{}})
	s.Configure("", 1*time.Hour)
	if s.Enabled() {
		t.Error("empty URL should not enable")
	}
}

func TestSyncer_NilMergeIsSafe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"name":"X","hosts":["a.com"]}]`)) //nolint:errcheck // test server write
	}))
	defer ts.Close()
	s := New(Deps{Client: ts.Client()})
	s.SetFeedURLForTest(ts.URL)
	s.Sync(context.Background()) // must not panic; added stays 0
	if _, _, count, _ := s.Stats(); count != 0 {
		t.Errorf("count with nil merge = %d, want 0", count)
	}
}
