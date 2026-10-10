package main

// F-FEED-1 (PR #1528 §3f), end to end in the proxy's own wiring: a UT1 import
// interrupted after partial writes is completed by the PRODUCTION scheduler
// (Start) after a restart, and the result is what category-based
// enforcement actually consults — a UT1-only host resolves through the
// COMMUNITY tier and a category rule blocks it. A built-in taxonomy match is
// not evidence of the feed, so the probe host is asserted to be unknown to
// every other tier first.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const ffeed1Probe = "ffeed1-ut1-only.example"

func ffeed1Feed(t *testing.T) string {
	t.Helper()
	var gambling strings.Builder
	gambling.WriteString(ffeed1Probe + "\n")
	for i := 0; i < 40; i++ {
		gambling.WriteString("ffeed1-filler-" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example\n")
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range map[string]string{
		"blacklists/gambling/domains": gambling.String(),
		"blacklists/adult/domains":    "ffeed1-adult-only.example\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	tarball := buf.Bytes()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarball) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func ffeed1BlockGambling() *PolicyStore {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "block-gambling", DestCategory: "Gambling", Action: ActionBlockPage}})
	return ps
}

func TestFFeed1_InterruptedImportRecoversAndDrivesCategoryEnforcement(t *testing.T) {
	url := ffeed1Feed(t)
	dir := t.TempDir()
	prev := communityDB
	t.Cleanup(func() { communityDB = prev })

	// The probe host is unknown to every tier before the feed is imported.
	if cat, tier, _ := lookupHostCategory(ffeed1Probe); tier != "none" || cat != "" {
		t.Fatalf("probe host must be unknown before the import, got %q via %q", cat, tier)
	}

	// Boot 1: the import is cut off after 5 entries.
	db, err := openCommunityDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 5 {
			return errors.New("container recreated mid-import")
		}
		return nil
	})
	newFeedSyncer(db, url, 24*time.Hour).Sync()
	if newFeedSyncer(db, url, 24*time.Hour).ImportComplete() {
		t.Fatal("an interrupted import must not be certified")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Boot 2: the production scheduler must complete the import by itself.
	db, err = openCommunityDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	communityDB = db
	syncer := newFeedSyncer(db, url, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	syncer.Start(ctx)
	t.Cleanup(func() { cancel(); syncer.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for !syncer.ImportComplete() {
		if time.Now().After(deadline) {
			t.Fatal("the startup sync did not complete the interrupted import")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// UT1-backed lookup: through the COMMUNITY tier.
	if cat, tier, matchedBy := lookupHostCategory(ffeed1Probe); cat != "Gambling" || tier != "community" {
		t.Fatalf("probe host = %q via %q (%q); want Gambling via community", cat, tier, matchedBy)
	}
	if cat, tier, _ := lookupHostCategory("www." + ffeed1Probe); cat != "Gambling" || tier != "community" {
		t.Fatalf("subdomain walk = %q via %q; want Gambling via community", cat, tier)
	}

	// Category-based enforcement consults it.
	ps := ffeed1BlockGambling()
	m := ps.Evaluate("203.0.113.9", "", "unauth", ffeed1Probe, nil)
	if m == nil || m.Rule.Name != "block-gambling" || m.Action != ActionBlockPage {
		t.Fatalf("a Gambling rule must block the UT1-only host, got %+v", m)
	}
	// Controls: another UT1 category and an unknown host do not match it.
	if m := ps.Evaluate("203.0.113.9", "", "unauth", "ffeed1-adult-only.example", nil); m != nil {
		t.Fatalf("an Adult host must not match the Gambling rule, got %q", m.Rule.Name)
	}
	if m := ps.Evaluate("203.0.113.9", "", "unauth", "ffeed1-not-in-feed.example", nil); m != nil {
		t.Fatalf("a host outside the feed must not match, got %q", m.Rule.Name)
	}
}
