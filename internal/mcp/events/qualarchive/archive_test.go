package qualarchive

// The first four tests moved from the root mcp_telemetry_test.go with their
// names and assertions unchanged (IM-024). The rest are new with the package.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/export"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// The archive is the sink the export contract names.
var _ export.Exporter = (*Exporter)(nil)

// gatewayPartitions mirrors the set package main hands NewCursorStore.
var gatewayPartitions = []evmodel.Partition{evmodel.PartCrit, evmodel.PartOrd, evmodel.PartDen}

// unknownSchemaVersion is a version no build supports.
const unknownSchemaVersion = 9999

// denialEvent crafts a safe P-DEN model event with a controlled digest (exporter
// unit tests need deterministic identities without a live pipeline).
func denialEvent(digest string) evmodel.Event {
	return evmodel.Event{
		SchemaVersion: evmodel.SchemaVersion,
		Capability:    evmodel.CapGateway,
		Partition:     evmodel.PartDen,
		EventID:       "ev-" + digest,
		EventDigest:   digest,
	}
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, _ error) error {
		if info != nil && info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	return n
}

// ── archive exporter ─────────────────────────────────────────────────────────

func TestArchiveExporter_AtomicIdempotentConflict(t *testing.T) {
	dir := t.TempDir()
	exp, err := NewExporter(dir, 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	batch := []evmodel.Event{denialEvent("d1"), denialEvent("d2"), denialEvent("d3")}

	n, err := exp.Export(context.Background(), batch)
	if err != nil || n != 3 {
		t.Fatalf("export = (%d,%v), want (3,nil)", n, err)
	}
	// Idempotent retry: same batch accepted again, still one file.
	n, err = exp.Export(context.Background(), batch)
	if err != nil || n != 3 {
		t.Fatalf("idempotent retry = (%d,%v)", n, err)
	}
	if got := countFiles(t, dir); got != 1 {
		t.Fatalf("archive files = %d, want 1 (idempotent)", got)
	}
	// Conflict: same batch identity (first/last/count) but different middle content.
	conflict := []evmodel.Event{denialEvent("d1"), denialEvent("dX"), denialEvent("d3")}
	if _, err := exp.Export(context.Background(), conflict); err == nil {
		t.Fatal("conflicting batch under the same identity must be rejected")
	}
}

func TestArchiveExporter_SaturationNoSilentDrop(t *testing.T) {
	dir := t.TempDir()
	exp, err := NewExporter(dir, 8) // 8-byte cap: any real batch exceeds it
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	n, err := exp.Export(context.Background(), []evmodel.Event{denialEvent("d1")})
	if err == nil || n != 0 {
		t.Fatalf("saturated export must reject (0,err), got (%d,%v)", n, err)
	}
	if countFiles(t, dir) != 0 {
		t.Fatal("saturated export must not write (spool retained, no silent drop)")
	}
	if !exp.Stats().Saturated {
		t.Fatal("exporter must report saturated state")
	}
}

func TestTelemetryCursor_DurableAndPerPartition(t *testing.T) {
	dir := t.TempDir()
	cs, err := NewCursorStore(dir, gatewayPartitions)
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	if err := cs.Advance(evmodel.PartDen, 42); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if err := cs.Advance(evmodel.PartDen, 10); err != nil { // backward is a no-op
		t.Fatalf("backward advance: %v", err)
	}
	if got := cs.Get(evmodel.PartDen); got != 42 {
		t.Fatalf("cursor = %d, want 42 (monotonic)", got)
	}
	if got := cs.Get(evmodel.PartCrit); got != 0 {
		t.Fatalf("crit cursor = %d, want 0 (per-partition isolation)", got)
	}
	// Restart: a fresh store loads the durable cursor.
	cs2, err := NewCursorStore(dir, gatewayPartitions)
	if err != nil {
		t.Fatalf("reopen cursor store: %v", err)
	}
	if got := cs2.Get(evmodel.PartDen); got != 42 {
		t.Fatalf("restarted cursor = %d, want 42", got)
	}
}

// TestValidateBatch_AcceptsV1AndV2RejectsUnknown pins the SHADOW-EVIDENCE-ROUTING-1
// qualification-archive fix: the export-pump batch validator must accept a SUPPORTED
// schema version — v1 AND the v2 durable-Shadow-evidence envelope — not just the default
// v1. A hardcoded `!= v1` check would reject the first v2 Shadow event, and because the
// pump retries an all-or-nothing batch without advancing its cursor, that would wedge the
// whole partition out of the durable archive (Codex P1, PR #1235). A genuinely unknown
// version is still rejected. Mutation: reverting to `!= evmodel.SchemaVersion` fails the
// v2 assertion below.
func TestValidateBatch_AcceptsV1AndV2RejectsUnknown(t *testing.T) {
	v2 := func(d string) evmodel.Event {
		return evmodel.Event{
			SchemaVersion: evmodel.SchemaVersionV2, Capability: evmodel.CapGateway,
			Partition: evmodel.PartCrit, EventID: "ev-" + d, EventDigest: d,
		}
	}
	if _, _, err := validateBatch([]evmodel.Event{denialEvent("d1"), denialEvent("d2")}); err != nil {
		t.Fatalf("a v1 batch must validate: %v", err)
	}
	if _, _, err := validateBatch([]evmodel.Event{v2("a"), v2("b")}); err != nil {
		t.Fatalf("a v2 shadow batch must validate (else its partition wedges out of the archive): %v", err)
	}
	bad := v2("c")
	bad.SchemaVersion = unknownSchemaVersion
	if _, _, err := validateBatch([]evmodel.Event{bad}); err == nil {
		t.Fatal("an unsupported schema version must be rejected")
	}
}

// ── new with the package ─────────────────────────────────────────────────────

func shadowEvent(digest string) evmodel.Event {
	return evmodel.Event{
		SchemaVersion: evmodel.SchemaVersionV2, Capability: evmodel.CapManagement,
		Partition: evmodel.PartCrit, EventID: "ev-" + digest, EventDigest: digest,
	}
}

// treeDigest hashes every regular file under root as relpath NUL bytes NUL, in
// walk order, and returns the relative paths with their modes.
func treeDigest(t *testing.T, root string) (digest string, files []string) {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			if rel != "." && info.Mode().Perm() != 0o700 {
				t.Errorf("directory %s has mode %o, want 700", rel, info.Mode().Perm())
			}
			return nil
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file %s has mode %o, want 600", rel, info.Mode().Perm())
		}
		raw, err := os.ReadFile(p) // #nosec G304,G122 -- test temp dir
		if err != nil {
			return err
		}
		h.Write([]byte(rel + "\x00"))
		h.Write(raw)
		h.Write([]byte{0})
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)), files
}

// TestOnDiskFormat_UnchangedByTheMove pins the persisted bytes. The digest and
// the file list were captured from package main at ef94311, before the move,
// with the same four batches and three cursor writes. A node that restarts
// across this change must find its batch files under the same names (or the
// idempotent-retry check re-archives them) and its cursors under the same
// names (or it re-exports from zero).
func TestOnDiskFormat_UnchangedByTheMove(t *testing.T) {
	dir := t.TempDir()
	exp, err := NewExporter(filepath.Join(dir, "a"), 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	ord := func(id, digest string) evmodel.Event {
		return evmodel.Event{
			SchemaVersion: evmodel.SchemaVersion, Capability: evmodel.CapGateway,
			Partition: evmodel.PartOrd, EventID: id, EventDigest: digest,
		}
	}
	for _, batch := range [][]evmodel.Event{
		{denialEvent("d1"), denialEvent("d2"), denialEvent("d3")},
		{shadowEvent("a")},
		{ord("o", "o1"), ord("p", "o2")},
		{{SchemaVersion: evmodel.SchemaVersion, Capability: evmodel.CapGateway, Partition: evmodel.Partition(99), EventDigest: "z"}},
	} {
		if n, err := exp.Export(context.Background(), batch); err != nil || n != len(batch) {
			t.Fatalf("export = (%d,%v), want (%d,nil)", n, err, len(batch))
		}
	}
	cs, err := NewCursorStore(filepath.Join(dir, "c"), gatewayPartitions)
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	for part, seq := range map[evmodel.Partition]uint64{evmodel.PartDen: 42, evmodel.PartCrit: 7, evmodel.Partition(99): 3} {
		if err := cs.Advance(part, seq); err != nil {
			t.Fatalf("advance: %v", err)
		}
	}

	digest, files := treeDigest(t, dir)
	wantFiles := []string{
		"a/gateway/den/fc3e833087d83ca2b20eabd96e23d3950be629a355dd863ef27241ec8ee294fc.json",
		"a/gateway/none/db68c5a3438bf47cb9a8786d0b953e09367b72c4bab6b5b2d9e347a375f2df68.json",
		"a/gateway/ord/c0ce771ef94cca723e25e5638bb26ff7431ff0f4748a626d68cdb1c7b22b5c5a.json",
		"a/management/crit/e8e184e59636eef9c690e841dbcd1fb799a03c23cb4bb989e3044d92ea0b837f.json",
		"c/crit.cursor",
		"c/den.cursor",
		"c/none.cursor",
	}
	if strings.Join(files, "\n") != strings.Join(wantFiles, "\n") {
		t.Fatalf("files =\n%s\nwant\n%s", strings.Join(files, "\n"), strings.Join(wantFiles, "\n"))
	}
	const want = "30df5b32cfdb45e43912bf194d808675b75761de391e28efc99ab4b1daecb730"
	if digest != want {
		t.Fatalf("tree digest = %s, want %s (the persisted bytes changed)", digest, want)
	}
	if got := exp.Stats(); got.BytesUsed != 3778 || got.BatchesOK != 4 || got.MaxBytes != 1<<20 {
		t.Fatalf("stats = %+v, want 3778 bytes in 4 batches", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "c", "den.cursor")) // #nosec G304 -- test temp dir
	if err != nil || string(raw) != `{"cursor":42}` {
		t.Fatalf("den.cursor = %q, %v", raw, err)
	}
}

// TestErrorPhrases_UnchangedByTheMove pins the fixed error text, which package
// main classifies by substring and which never carries a path or a digest.
func TestErrorPhrases_UnchangedByTheMove(t *testing.T) {
	root := t.TempDir()
	exp, err := NewExporter(root, 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	if _, err := exp.Export(context.Background(), []evmodel.Event{denialEvent("d1"), denialEvent("d2"), denialEvent("d3")}); err != nil {
		t.Fatalf("export: %v", err)
	}
	full, err := NewExporter(t.TempDir(), 8)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	unknown := denialEvent("u")
	unknown.SchemaVersion = unknownSchemaVersion
	for _, tc := range []struct {
		name  string
		exp   *Exporter
		batch []evmodel.Event
		want  string
	}{
		{"conflict", exp, []evmodel.Event{denialEvent("d1"), denialEvent("dX"), denialEvent("d3")}, "mcp telemetry: conflicting duplicate batch identity"},
		{"saturated", full, []evmodel.Event{denialEvent("d1")}, "mcp telemetry: archive capacity saturated"},
		{"schema", exp, []evmodel.Event{unknown}, "mcp telemetry: unsupported event schema version"},
		{"digest", exp, []evmodel.Event{{SchemaVersion: evmodel.SchemaVersion}}, "mcp telemetry: event missing digest"},
		{"mixed", exp, []evmodel.Event{denialEvent("d1"), shadowEvent("q")}, "mcp telemetry: mixed capability/partition in one batch"},
	} {
		n, err := tc.exp.Export(context.Background(), tc.batch)
		if n != 0 || err == nil || err.Error() != tc.want {
			t.Errorf("%s: export = (%d,%v), want (0,%q)", tc.name, n, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), root) {
			t.Errorf("%s: error carries the archive path", tc.name)
		}
	}
	if n, err := exp.Export(context.Background(), nil); n != 0 || err != nil {
		t.Fatalf("empty batch = (%d,%v), want (0,nil)", n, err)
	}
	if got := exp.Stats().LastReason; got != "conflict" {
		t.Fatalf("last reason = %q, want conflict (validation rejects do not overwrite it)", got)
	}
	if got := full.Stats(); !got.Saturated || got.LastReason != "saturated" || got.BytesUsed != 0 {
		t.Fatalf("full exporter stats = %+v", got)
	}
}

// TestExporter_RestartCountsWhatIsOnDisk: capacity is recomputed from the
// directory at open, so a restart cannot reset the cap.
func TestExporter_RestartCountsWhatIsOnDisk(t *testing.T) {
	dir := t.TempDir()
	exp, err := NewExporter(dir, 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	if _, err := exp.Export(context.Background(), []evmodel.Event{denialEvent("d1")}); err != nil {
		t.Fatalf("export: %v", err)
	}
	used := exp.Stats().BytesUsed
	if used == 0 {
		t.Fatal("an accepted batch must count toward capacity")
	}
	again, err := NewExporter(dir, used) // exactly full
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := again.Stats().BytesUsed; got != used {
		t.Fatalf("reopened bytes used = %d, want %d", got, used)
	}
	if _, err := again.Export(context.Background(), []evmodel.Event{denialEvent("d2")}); err == nil {
		t.Fatal("a reopened full archive must reject a new batch")
	}
	// The batch already on disk is still an idempotent success at the cap.
	if n, err := again.Export(context.Background(), []evmodel.Event{denialEvent("d1")}); err != nil || n != 1 {
		t.Fatalf("idempotent retry at the cap = (%d,%v), want (1,nil)", n, err)
	}
}

// TestExporter_CorruptPriorFileIsReplacedNotAdded: an unreadable file at the
// batch path is repaired, and its old size is discounted from the running
// total and from the capacity check.
func TestExporter_CorruptPriorFileIsReplacedNotAdded(t *testing.T) {
	dir := t.TempDir()
	probe, err := NewExporter(dir, 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	batch := []evmodel.Event{denialEvent("d1"), denialEvent("d2")}
	if _, err := probe.Export(context.Background(), batch); err != nil {
		t.Fatalf("export: %v", err)
	}
	size := probe.Stats().BytesUsed
	var path string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, _ error) error {
		if info != nil && info.Mode().IsRegular() {
			path = p
		}
		return nil
	})
	garbage := []byte(strings.Repeat("x", int(size)+50))
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	// Cap equals the corrupt file's size: only a replacement fits.
	exp, err := NewExporter(dir, int64(len(garbage)))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n, err := exp.Export(context.Background(), batch); err != nil || n != len(batch) {
		t.Fatalf("repair = (%d,%v), want (%d,nil)", n, err, len(batch))
	}
	if got := exp.Stats(); got.BytesUsed != size || got.Saturated {
		t.Fatalf("stats after repair = %+v, want %d bytes and not saturated", got, size)
	}
}

func TestExporter_NotesAndStats(t *testing.T) {
	exp, err := NewExporter(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	exp.NoteFailure("cursor_persist")
	exp.NoteFailure("") // counts, keeps the last reason
	exp.NoteExported(3)
	exp.NoteExported(2)
	got := exp.Stats()
	if got.Failures != 2 || got.LastReason != "cursor_persist" || got.ExportedEvents != 5 || got.LastOKUnixNano == 0 {
		t.Fatalf("stats = %+v", got)
	}
	// maxBytes 0 means no cap.
	if _, err := exp.Export(context.Background(), []evmodel.Event{denialEvent("d1")}); err != nil {
		t.Fatalf("uncapped export: %v", err)
	}
}

// TestInstances_ShareNothing: two exporters and two cursor stores over
// different directories never observe each other.
func TestInstances_ShareNothing(t *testing.T) {
	a, err := NewExporter(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	dirB := t.TempDir()
	b, err := NewExporter(dirB, 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	if _, err := a.Export(context.Background(), []evmodel.Event{denialEvent("d1")}); err != nil {
		t.Fatalf("export: %v", err)
	}
	a.NoteExported(1)
	a.NoteFailure("x")
	if got := b.Stats(); got != (Stats{MaxBytes: 1 << 20}) {
		t.Fatalf("second exporter observed the first: %+v", got)
	}
	if countFiles(t, dirB) != 0 {
		t.Fatal("second archive holds a file it never wrote")
	}
	ca, err := NewCursorStore(t.TempDir(), gatewayPartitions)
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	cb, err := NewCursorStore(t.TempDir(), gatewayPartitions)
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	if err := ca.Advance(evmodel.PartOrd, 9); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if got := cb.Get(evmodel.PartOrd); got != 0 {
		t.Fatalf("second cursor store = %d, want 0", got)
	}
}

// TestCursorStore_OpenRules: an absent or undecodable file starts at zero, only
// the listed partitions are loaded, and an unusable directory is an error.
func TestCursorStore_OpenRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ord.cursor"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "den.cursor"), []byte(`{"cursor":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crit.cursor"), []byte(`{"cursor":8}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := NewCursorStore(dir, []evmodel.Partition{evmodel.PartOrd, evmodel.PartDen})
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	if got := cs.Get(evmodel.PartOrd); got != 0 {
		t.Fatalf("undecodable cursor = %d, want 0", got)
	}
	if got := cs.Get(evmodel.PartDen); got != 5 {
		t.Fatalf("den cursor = %d, want 5", got)
	}
	if got := cs.Get(evmodel.PartCrit); got != 0 {
		t.Fatalf("unlisted partition = %d, want 0 (not loaded)", got)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCursorStore(filepath.Join(blocker, "sub"), gatewayPartitions); err == nil {
		t.Fatal("a cursor directory under a regular file must fail")
	}
	if _, err := NewExporter(filepath.Join(blocker, "sub"), 1); err == nil {
		t.Fatal("an archive root under a regular file must fail")
	}
}

func TestPartitionName_FixedTokens(t *testing.T) {
	got := []string{
		PartitionName(evmodel.PartCrit), PartitionName(evmodel.PartOrd),
		PartitionName(evmodel.PartDen), PartitionName(evmodel.Partition(200)),
	}
	if strings.Join(got, ",") != "crit,ord,den,none" {
		t.Fatalf("partition names = %v", got)
	}
	if capabilityName(evmodel.CapManagement) != "management" || capabilityName(evmodel.CapGateway) != "gateway" {
		t.Fatal("capability names changed")
	}
	for n, want := range map[int]string{0: "0", 7: "7", 4096: "4096"} {
		if got := itoaLen(n); got != want {
			t.Fatalf("itoaLen(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestConcurrentUse runs every method of one exporter and one cursor store
// from many goroutines; it is a race-detector target and checks the totals.
func TestConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	exp, err := NewExporter(dir, 1<<30)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	cs, err := NewCursorStore(t.TempDir(), gatewayPartitions)
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	const workers, each = 8, 10
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				digest := "w" + itoaLen(w) + "-" + itoaLen(i)
				if n, err := exp.Export(context.Background(), []evmodel.Event{denialEvent(digest)}); err != nil || n != 1 {
					t.Errorf("export = (%d,%v)", n, err)
				}
				exp.NoteExported(1)
				_ = exp.Stats()
				if err := cs.Advance(evmodel.PartDen, uint64(w*each+i+1)); err != nil { // #nosec G115 -- small test index
					t.Errorf("advance: %v", err)
				}
				_ = cs.Get(evmodel.PartDen)
			}
		}(w)
	}
	wg.Wait()
	if got := exp.Stats(); got.BatchesOK != workers*each || got.ExportedEvents != workers*each {
		t.Fatalf("stats = %+v, want %d batches", got, workers*each)
	}
	if got := countFiles(t, dir); got != workers*each {
		t.Fatalf("files = %d, want %d", got, workers*each)
	}
	if got := cs.Get(evmodel.PartDen); got != workers*each {
		t.Fatalf("cursor = %d, want %d (monotonic maximum)", got, workers*each)
	}
}
