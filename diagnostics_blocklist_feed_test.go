package main

import (
	"strings"
	"testing"
	"time"
)

func TestCheckBlocklistFeeds(t *testing.T) {
	prev := blFeedSyncer
	t.Cleanup(func() { blFeedSyncer = prev })

	blFeedSyncer = nil
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Fatalf("nil syncer: want no rows, got %+v", rows)
	}

	blFeedSyncer = newTestBlocklistSyncer(t)
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Fatalf("no feeds: want no rows, got %+v", rows)
	}

	// A loopback URL is refused by the outbound guard, so the attempt fails
	// without any network access and records a LastError.
	const secretURL = "http://127.0.0.1:1/token-abc123.txt"
	blFeedSyncer.SetFeed(secretURL, time.Hour)
	if _, err := blFeedSyncer.SyncFeed(secretURL); err == nil {
		t.Fatal("expected the loopback feed sync to fail")
	}
	rows := checkBlocklistFeeds()
	if len(rows) != 1 || rows[0].Code != "blocklist_feed" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("want one blocklist_feed WARN row, got %+v", rows)
	}
	if !strings.Contains(rows[0].Message, "1 of 1") {
		t.Errorf("message should carry counts, got %q", rows[0].Message)
	}
	if strings.Contains(rows[0].Message+rows[0].OperatorAction, "token-abc123") {
		t.Error("row must not leak the feed URL")
	}
}
