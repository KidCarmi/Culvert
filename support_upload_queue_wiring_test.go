package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// support_upload_queue_wiring_test.go: what main still owns after the queue
// engine moved to internal/supportupload/uploadqueue (IM-029, ADR-0062).
//
// Every name used here existed with the same signature before the move, and
// the digests below were captured by running these two tests against main
// `155df0944`, where the engine was still in support_upload_queue.go (and
// csbID was declared by the queue's own test file, since moved). They
// pin the bytes a node writes under <dataDir>/support/upload_queue, which a
// node upgraded across the move reads back.

// csbID builds a valid support-bundle id (csb_ + 26 base32 chars) from a short
// seed — supportBundleIDRe rejects anything else, which the queue relies on to
// keep filenames traversal-safe.
func csbID(seed string) string {
	return "csb_" + seed + strings.Repeat("a", 26-len(seed))
}

func uploadQueueFileDigest(t *testing.T, bundleID string) string {
	t.Helper()
	b, err := os.ReadFile(uploadQueuePath(bundleID))
	if err != nil {
		t.Fatalf("read queue entry: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestSupportUploadQueueWiring_PersistedBytesUnchanged walks one entry
// through every state through the root names and compares the file after
// each step with the digest main wrote.
func TestSupportUploadQueueWiring_PersistedBytesUnchanged(t *testing.T) {
	withTempUploadDir(t)
	id := csbID("wire")
	t0 := time.Unix(1_700_000_000, 0).UTC()

	step := func(name, want string) {
		t.Helper()
		if got := uploadQueueFileDigest(t, id); got != want {
			b, _ := os.ReadFile(uploadQueuePath(id)) //nolint:errcheck // diagnostic only
			t.Errorf("%s: digest %s, want %s\n%s", name, got, want, b)
		}
	}
	attempt := func(e uploadQueueEntry, at time.Time, rec *supportupload.Receipt, uploadID string, err error) uploadQueueEntry {
		t.Helper()
		out := drainUploadEntry(context.Background(), e, func(context.Context, uploadQueueEntry) (*supportupload.Receipt, string, error) {
			return rec, uploadID, err
		}, at)
		if serr := saveUploadQueueEntry(out); serr != nil {
			t.Fatalf("save: %v", serr)
		}
		return out
	}

	e, err := enqueueUpload(id, "CASE-1", "tac-2026", "deadbeef", t0)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	step("queued", "e39ebb1d536ea6bf808aff4c24b21b1894dacb2d0ccc7640099e26cba4503cf6")

	// A transient failure after init: session id kept, control bytes in the
	// error text scrubbed before they reach the disk, text bounded.
	e = attempt(e, t0.Add(time.Second), nil, "sess-1",
		errors.New("reset\r\nby peer\x1b[31m "+strings.Repeat("x", 400)))
	step("transient", "bbf25a1556e9e1af073f35ed3b7fcf0c4afad9443cd0e4cdd1f829ef806d9194")

	attempt(e, t0.Add(2*time.Second), nil, "", &supportupload.GatewayError{Status: 403, Body: "not entitled"})
	step("rejected", "e30b90da55b0d0b2506d9ab91d163916c3ecef5b53236928661a29d332948939")

	e, err = enqueueUpload(id, "CASE-2", "tac-2027", "cafe", t0.Add(3*time.Second))
	if err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	step("re-armed", "dd72f170398fcd53649356db180520d798b847243593f7eea0b6416d384b32f7")

	for i := 0; i < maxUploadAttempts; i++ {
		e = attempt(e, t0.Add(time.Duration(4+i)*time.Second), nil, "", errors.New("connection refused"))
	}
	if e.State != uploadStateDeferred {
		t.Fatalf("state after %d failures = %q, want deferred", maxUploadAttempts, e.State)
	}
	step("deferred", "d8f9009f8d33c90726b4ed7c2246b693efe2214b91d2ccb9483a4b4d77568ea9")

	e, err = enqueueUpload(id, "CASE-2", "tac-2027", "cafe", t0.Add(20*time.Second))
	if err != nil {
		t.Fatalf("re-arm deferred: %v", err)
	}
	attempt(e, t0.Add(21*time.Second),
		&supportupload.Receipt{BundleSHA256: "cafe", ReceivedAt: "2023-11-14T22:13:41Z", Sig: "SIG"}, "sess-2", nil)
	step("uploaded", "0653b9786e40a7f4578ba2e45fbea62195a294128436c1c4d0684294a8d3b61a")
}

// TestSupportUploadQueueWiring_RootOwnsPlacementAndPolicy pins the decisions
// main hands the engine: where the queue lives, which ids name a file, the
// four bounds, and that the persisted error text goes through sanitizeLog.
func TestSupportUploadQueueWiring_RootOwnsPlacementAndPolicy(t *testing.T) {
	withTempUploadDir(t)
	id := csbID("place")

	if got, want := uploadQueuePath(id), filepath.Join(dataDir, "support", "upload_queue", id+".json"); got != want {
		t.Errorf("uploadQueuePath = %q, want %q", got, want)
	}
	if maxUploadQueue != 256 || maxUploadTerminal != 256 || maxUploadAttempts != 6 || maxUploadErrLen != 256 {
		t.Errorf("bounds = %d/%d/%d/%d, want 256/256/6/256",
			maxUploadQueue, maxUploadTerminal, maxUploadAttempts, maxUploadErrLen)
	}
	if got := boundUploadErr("a\nb\x00c"); got != sanitizeLog("a\nb\x00c") {
		t.Errorf("boundUploadErr(%q) = %q, want sanitizeLog's answer", "a\nb\x00c", got)
	}

	// supportBundleIDRe is the filename authority: nothing else is written.
	for _, bad := range []string{"", "csb_short", "../" + id, id + "/x", strings.ToUpper(id), id + "\x00"} {
		if _, err := enqueueUpload(bad, "C", "", "h", time.Now()); err == nil {
			t.Errorf("enqueueUpload(%q) accepted an id supportBundleIDRe refuses", bad)
		}
		if err := saveUploadQueueEntry(uploadQueueEntry{BundleID: bad, State: uploadStateQueued}); err == nil {
			t.Errorf("saveUploadQueueEntry(%q) accepted an id supportBundleIDRe refuses", bad)
		}
		if _, ok := loadUploadQueueEntry(bad); ok {
			t.Errorf("loadUploadQueueEntry(%q) answered for an id supportBundleIDRe refuses", bad)
		}
	}
	if des, err := os.ReadDir(filepath.Join(dataDir, "support", "upload_queue")); err == nil && len(des) != 0 {
		t.Errorf("refused ids left %d files behind", len(des))
	}

	// The directory is re-read from dataDir on every call, as before: a second
	// data directory sees none of the first one's entries.
	if _, err := enqueueUpload(id, "C", "", "h", time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	first := dataDir
	dataDir = t.TempDir()
	if n := len(listUploadQueue()); n != 0 {
		t.Errorf("a fresh dataDir lists %d entries from the previous one", n)
	}
	dataDir = first
	if n := len(listUploadQueue()); n != 1 {
		t.Errorf("the original dataDir lists %d entries, want 1", n)
	}
}
