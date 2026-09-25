package main

// Nightly QA edge-case pass: readTarball had no bound on a tar entry's
// declared size before calling io.ReadAll(tr) on its body. A highly
// compressible payload (e.g. all-zero bytes) lets a tiny .tar.gz file declare
// an enormous decompressed size in its tar header — a classic decompression
// bomb — and readTarball is reached by `culvert --restore` (dry-run, no
// --confirm needed) on any tarball path an operator points it at, so a
// corrupted or hostile backup file drives an unbounded in-memory allocation.
//
// Every other tar/gzip consumer in this codebase already bounds this:
// release_catalog_bundle.go checks hdr.Size against catalogMaxReadBytes per
// entry, and support_validate.go wraps the gzip reader in an
// io.LimitReader(maxValidateDecompressed) before untarring. restore.go was
// the one place carrying no such guard despite documenting (runBackupWith)
// that a real backup is "well under 100MB".
//
// CI-REDESIGN stage 6A: these tests used to generate 300 MiB and 800 MiB
// archives on every race run (≈27 s and ≈100 s here, most of it producing and
// gzipping zeros under the race detector) and accepted ANY error as a pass.
// They now drive the same parser, readTarballLimited, with kilobyte limits and
// fixtures, and assert the specific limit refusal: a malformed tar, a
// truncated body or any other error does not satisfy them. The production
// bounds are proved separately:
//   - the constants themselves (TestReadTarball_ProductionLimitsAreFixed);
//   - the per-entry bound through readTarball at production size, at no cost:
//     an oversized declared entry needs a header only, never a body;
//   - the aggregate bound through readTarball at production size, which must
//     read 256 MiB of body before the overflowing header is reached, runs in
//     the QA gate's "On-disk contract" job (qa-gate.yml), which sets
//     CULVERT_RESTORE_PRODUCTION_SIZE=1 and requires the test's PASS line. See
//     TestReadTarball_ProductionAggregateBound_Integration.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// restoreProductionSizeEnv arms the one production-size integration case.
const restoreProductionSizeEnv = "CULVERT_RESTORE_PRODUCTION_SIZE"

// zeroReader yields an endless stream of zero bytes. clear() is the runtime's
// memclr, not a per-byte loop, so the race detector does not instrument every
// byte of a large fixture.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// tarFixtureEntry is one entry of a generated archive. body is how many
// bytes of its declared size are actually written: -1 writes all of them,
// anything less leaves the archive truncated inside this entry (and ends it —
// no later entry can follow a truncated one).
type tarFixtureEntry struct {
	name     string
	declared int64
	body     int64
	fill     byte
}

// writeTarFixture builds a .tar.gz at destPath from entries, exactly as the
// hostile or damaged backups the tests model: the tar header declares
// `declared` bytes whatever follows it.
func writeTarFixture(t *testing.T, destPath string, entries ...tarFixtureEntry) {
	t.Helper()
	out, err := os.Create(destPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("create %s: %v", destPath, err)
	}
	defer func() { _ = out.Close() }()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	truncated := false
	for i, e := range entries {
		if truncated {
			t.Fatalf("test setup: entry %d follows a truncated entry", i)
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o600, Size: e.declared, Typeflag: tar.TypeReg, ModTime: time.Now().UTC()}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		n := e.body
		if n < 0 {
			n = e.declared
		}
		var src io.Reader = zeroReader{}
		if e.fill != 0 {
			src = bytes.NewReader(bytes.Repeat([]byte{e.fill}, int(n)))
		}
		if _, err := io.CopyN(tw, src, n); err != nil {
			t.Fatalf("write body %q: %v", e.name, err)
		}
		truncated = n < e.declared
	}
	if !truncated {
		// A truncated archive deliberately skips the tar trailer: the stream
		// just ends inside the last entry's body.
		if err := tw.Close(); err != nil {
			t.Fatalf("close tar writer: %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
}

func fixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "fixture.tar.gz")
}

// requireLimitError fails unless err is the limit refusal described — the
// right bound, the right entry, the right declared figure. Any other error
// (malformed archive, truncated body, namespace or duplicate guard) fails.
func requireLimitError(t *testing.T, err error, scope, name string, declared, limit int64) {
	t.Helper()
	var le *tarballLimitError
	if !errors.As(err, &le) {
		t.Fatalf("want a %s-limit refusal for %q, got %v", scope, name, err)
	}
	if le.Scope != scope || le.Name != name || le.Declared != declared || le.Limit != limit {
		t.Fatalf("limit refusal = {scope %s, name %q, declared %d, limit %d}; want {%s, %q, %d, %d}",
			le.Scope, le.Name, le.Declared, le.Limit, scope, name, declared, limit)
	}
	if want := fmt.Sprintf("exceeding the %d-byte", limit); !strings.Contains(err.Error(), want) {
		t.Fatalf("limit refusal text %q does not name the bound (%q)", err, want)
	}
}

// requireNotLimitError fails unless err is a non-nil error that is NOT a limit
// refusal — the control that keeps requireLimitError honest.
func requireNotLimitError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	var le *tarballLimitError
	if errors.As(err, &le) {
		t.Fatalf("a non-limit fault was reported as a limit refusal: %v", err)
	}
}

// ─── Production bounds ───────────────────────────────────────────────────────

// The production bounds are fixed values, not configuration: 256 MiB per entry
// and twice that in aggregate.
func TestReadTarball_ProductionLimitsAreFixed(t *testing.T) {
	if maxRestoreEntryBytes != 256<<20 {
		t.Errorf("maxRestoreEntryBytes = %d, want %d (256 MiB)", maxRestoreEntryBytes, 256<<20)
	}
	if maxRestoreTotalBytes != 512<<20 {
		t.Errorf("maxRestoreTotalBytes = %d, want %d (512 MiB)", maxRestoreTotalBytes, 512<<20)
	}
	// The ratio is part of the contract too: every entry at its cap is
	// always below the aggregate on its own.
	if got, want := int64(maxRestoreTotalBytes), int64(2*maxRestoreEntryBytes); got != want {
		t.Errorf("maxRestoreTotalBytes = %d, want twice the per-entry bound (%d)", got, want)
	}
}

// readTarball — the production entry point — enforces the production per-entry
// bound before reading a body. Costs nothing: the archive is a header whose
// body is never written, so reading the body would surface as an unexpected
// EOF rather than as the refusal asserted here.
func TestReadTarball_ProductionEntryBoundRejectsOnTheHeader(t *testing.T) {
	for _, declared := range []int64{maxRestoreEntryBytes + 1, 300 << 20, 1 << 40} {
		t.Run(fmt.Sprint(declared), func(t *testing.T) {
			path := fixturePath(t)
			writeTarFixture(t, path, tarFixtureEntry{name: "data/blocklist.txt", declared: declared, body: 0})
			_, _, err := readTarball(path, "")
			requireLimitError(t, err, tarballLimitEntry, "data/blocklist.txt", declared, maxRestoreEntryBytes)
		})
	}
}

// The control through the production path: an entry comfortably under the
// bound still reads in full, so the bound narrows nothing about legitimate (if
// unusually large) backups.
func TestReadTarball_AcceptsEntryUnderTheBound(t *testing.T) {
	const size = 1 << 20 // 1 MiB — far under any reasonable bound
	path := fixturePath(t)
	writeTarFixture(t, path, tarFixtureEntry{name: "data/blocklist.txt", declared: size, body: -1})

	files, _, err := readTarball(path, "")
	if err != nil {
		t.Fatalf("readTarball rejected a normal %d-byte entry: %v", size, err)
	}
	if len(files["data/blocklist.txt"]) != size {
		t.Fatalf("got %d bytes back, want %d", len(files["data/blocklist.txt"]), size)
	}
}

// TestReadTarball_ProductionAggregateBound_Integration is the production-size
// aggregate case: through readTarball, with the production constants, an
// entry of exactly 256 MiB is accepted and read in full, a 1-byte entry
// follows, and a third header declaring 256 MiB takes the running total to
// 512 MiB + 1 and is refused before its (unwritten) body is read.
//
// Reaching the overflowing header requires reading 256 MiB of real body — the
// minimum any production-size aggregate case needs, since every earlier entry
// must be read in full and each is capped at 256 MiB. That costs tens of
// seconds under -race, so the ordinary suite skips it and the QA gate's
// "On-disk contract" job runs it WITHOUT -race: qa-gate.yml sets
// CULVERT_RESTORE_PRODUCTION_SIZE=1 and fails unless the log carries this
// test's PASS line (a SKIP fails the job). qa-gate.yml is a mandatory row of
// .github/release-evidence.txt, so a failure here refuses release promotion.
// restore_limits_lane_test.go pins that wiring.
func TestReadTarball_ProductionAggregateBound_Integration(t *testing.T) {
	if os.Getenv(restoreProductionSizeEnv) != "1" {
		t.Skipf("production-size case (reads 256 MiB); runs in qa-gate.yml's On-disk contract job with %s=1", restoreProductionSizeEnv)
	}
	path := fixturePath(t)
	writeTarFixture(t, path,
		tarFixtureEntry{name: "data/a.txt", declared: maxRestoreEntryBytes, body: -1},
		tarFixtureEntry{name: "data/b.txt", declared: 1, body: -1},
		tarFixtureEntry{name: "data/c.txt", declared: maxRestoreEntryBytes, body: 0},
	)
	_, _, err := readTarball(path, "")
	requireLimitError(t, err, tarballLimitTotal, "data/c.txt", maxRestoreTotalBytes+1, maxRestoreTotalBytes)
}

// ─── The same parser, kilobyte limits ────────────────────────────────────────

// testLimits keep every entry below the aggregate bound on its own, as the
// production pair does (total = 2 × entry).
var testLimits = tarballLimits{entry: 4 << 10, total: 8 << 10}

func TestReadTarballLimited_ValidArchive(t *testing.T) {
	path := fixturePath(t)
	writeTarFixture(t, path,
		tarFixtureEntry{name: "manifest.json", declared: 10, body: -1, fill: 'm'},
		tarFixtureEntry{name: "data/a.txt", declared: 100, body: -1, fill: 'a'},
		tarFixtureEntry{name: "data/b.txt", declared: 0, body: -1},
	)
	files, order, err := readTarballLimited(path, "", testLimits)
	if err != nil {
		t.Fatalf("valid archive refused: %v", err)
	}
	if strings.Join(order, ",") != "manifest.json,data/a.txt,data/b.txt" {
		t.Errorf("order = %v", order)
	}
	if string(files["manifest.json"]) != strings.Repeat("m", 10) || string(files["data/a.txt"]) != strings.Repeat("a", 100) || len(files["data/b.txt"]) != 0 {
		t.Errorf("bodies not returned intact: %d/%d/%d bytes", len(files["manifest.json"]), len(files["data/a.txt"]), len(files["data/b.txt"]))
	}
}

func TestReadTarballLimited_EntryBoundary(t *testing.T) {
	lim := testLimits.entry
	for _, size := range []int64{lim - 1, lim} {
		t.Run(fmt.Sprintf("accept-%d", size), func(t *testing.T) {
			path := fixturePath(t)
			writeTarFixture(t, path, tarFixtureEntry{name: "data/x.txt", declared: size, body: -1, fill: 'x'})
			files, _, err := readTarballLimited(path, "", testLimits)
			if err != nil {
				t.Fatalf("entry of %d bytes (cap %d) refused: %v", size, lim, err)
			}
			if int64(len(files["data/x.txt"])) != size {
				t.Fatalf("read %d bytes, want %d", len(files["data/x.txt"]), size)
			}
		})
	}
	t.Run(fmt.Sprintf("reject-%d", lim+1), func(t *testing.T) {
		path := fixturePath(t)
		writeTarFixture(t, path, tarFixtureEntry{name: "data/x.txt", declared: lim + 1, body: -1, fill: 'x'})
		_, _, err := readTarballLimited(path, "", testLimits)
		requireLimitError(t, err, tarballLimitEntry, "data/x.txt", lim+1, lim)
	})
}

func TestReadTarballLimited_AggregateBoundary(t *testing.T) {
	e, total := testLimits.entry, testLimits.total
	cases := []struct {
		name    string
		entries []tarFixtureEntry
		refuse  bool
	}{
		{"below", []tarFixtureEntry{{name: "data/a", declared: e, body: -1}, {name: "data/b", declared: total - e - 1, body: -1}}, false},
		{"exactly-at", []tarFixtureEntry{{name: "data/a", declared: e, body: -1}, {name: "data/b", declared: total - e, body: -1}}, false},
		{"above", []tarFixtureEntry{{name: "data/a", declared: e, body: -1}, {name: "data/b", declared: e, body: -1}, {name: "data/c", declared: 1, body: -1}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := fixturePath(t)
			writeTarFixture(t, path, c.entries...)
			_, _, err := readTarballLimited(path, "", testLimits)
			if !c.refuse {
				if err != nil {
					t.Fatalf("archive at or under the %d-byte aggregate refused: %v", total, err)
				}
				return
			}
			requireLimitError(t, err, tarballLimitTotal, "data/c", total+1, total)
		})
	}
}

// Every entry below its own cap, the sum over the aggregate: only the
// aggregate bound can refuse this.
func TestReadTarballLimited_AggregateOverflowWithEveryEntryUnderItsCap(t *testing.T) {
	per := testLimits.entry - 1
	path := fixturePath(t)
	writeTarFixture(t, path,
		tarFixtureEntry{name: "data/part-0", declared: per, body: -1},
		tarFixtureEntry{name: "data/part-1", declared: per, body: -1},
		tarFixtureEntry{name: "data/part-2", declared: per, body: -1},
	)
	if 2*per > testLimits.total || 3*per <= testLimits.total {
		t.Fatalf("test setup: 3 × %d must cross the %d aggregate on the third entry only", per, testLimits.total)
	}
	_, _, err := readTarballLimited(path, "", testLimits)
	requireLimitError(t, err, tarballLimitTotal, "data/part-2", 3*per, testLimits.total)
}

// An over-bound declared size is refused on the header, before any of its
// body is read or allocated: each archive below ends right after the offending
// header, so a parser that read the body would report an unexpected EOF
// instead. The control shows that EOF is what a read produces.
func TestReadTarballLimited_RejectsBeforeReadingTheBody(t *testing.T) {
	t.Run("entry", func(t *testing.T) {
		path := fixturePath(t)
		writeTarFixture(t, path, tarFixtureEntry{name: "data/big", declared: 1 << 40, body: 0})
		_, _, err := readTarballLimited(path, "", testLimits)
		requireLimitError(t, err, tarballLimitEntry, "data/big", 1<<40, testLimits.entry)
	})
	t.Run("aggregate", func(t *testing.T) {
		path := fixturePath(t)
		writeTarFixture(t, path,
			tarFixtureEntry{name: "data/a", declared: testLimits.entry, body: -1},
			tarFixtureEntry{name: "data/b", declared: testLimits.entry, body: -1},
			tarFixtureEntry{name: "data/c", declared: testLimits.entry, body: 0},
		)
		_, _, err := readTarballLimited(path, "", testLimits)
		requireLimitError(t, err, tarballLimitTotal, "data/c", 3*testLimits.entry, testLimits.total)
	})
	t.Run("control: a truncated body within the bounds is read and fails as a read", func(t *testing.T) {
		path := fixturePath(t)
		writeTarFixture(t, path, tarFixtureEntry{name: "data/short", declared: 100, body: 10})
		_, _, err := readTarballLimited(path, "", testLimits)
		requireNotLimitError(t, err)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("want an unexpected-EOF read failure, got %v", err)
		}
	})
}

// Other archive faults are not limit refusals, so they can never satisfy a
// limit test.
func TestReadTarballLimited_OtherFaultsAreNotLimitRefusals(t *testing.T) {
	dir := t.TempDir()
	notGzip := filepath.Join(dir, "not.tar.gz")
	if err := os.WriteFile(notGzip, []byte("this is not a gzip stream"), 0o600); err != nil {
		t.Fatal(err)
	}
	var garbage bytes.Buffer
	gz := gzip.NewWriter(&garbage)
	_, _ = gz.Write(bytes.Repeat([]byte{0xff}, 1024))
	_ = gz.Close()
	badTar := filepath.Join(dir, "bad.tar.gz")
	if err := os.WriteFile(badTar, garbage.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.tar.gz")
	writeTarFixture(t, outside, tarFixtureEntry{name: "etc/passwd", declared: 1, body: -1})

	for name, path := range map[string]string{"not gzip": notGzip, "malformed tar": badTar, "outside data/": outside} {
		t.Run(name, func(t *testing.T) {
			_, _, err := readTarballLimited(path, "", testLimits)
			requireNotLimitError(t, err)
		})
	}
}
