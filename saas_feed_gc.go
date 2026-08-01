package main

// saas_feed_gc.go — F3b-3: safe generation garbage collection.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §B.10 (GC roots), §B.12
// (invariants). GC deletes an immutable generation ONLY when it is provably unreferenced:
// not in the root set AND outside the retention window AND the durable state is
// consistent (no corruption/ambiguity/equivocation). It runs ONLY after a fully-committed
// activation (a valid activation record) and never before a replacement commits. It never
// follows symlinks, never deletes outside the fixed generation root, never touches a
// staging or GC-tombstone path owned by another operation, and never infers retention from
// a filename, directory order, or mtime (retention ranks by the VERSION in each
// generation's validated canonical metadata). Deletion is two-step and recoverable
// (validated rename into an owned tombstone → remove → parent-dir sync), so an
// interruption never affects an active/floor-rooted generation, and GC is idempotent.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// gcTombstonePrefix marks a directory owned by an in-flight two-step deletion. A leftover
// tombstone from an interrupted GC is swept idempotently.
const gcTombstonePrefix = ".gc-tombstone-"

var (
	errGCRoot   = errors.New("saas feed gc: empty generations root")
	errGCEscape = errors.New("saas feed gc: refusing to delete outside the generations root")
)

// gcFS is the injectable filesystem seam (production: os.*). Tests inject per-step
// failures (root collection / tombstone rename / deletion / dir sync).
type gcFS struct {
	readDir   func(path string) ([]os.DirEntry, error)
	lstat     func(path string) (os.FileInfo, error)
	readFile  func(path string) ([]byte, error)
	rename    func(oldpath, newpath string) error
	removeAll func(path string) error
	syncDir   func(path string) error
}

func osGCFS() gcFS {
	return gcFS{
		readDir:   os.ReadDir,
		lstat:     os.Lstat,
		readFile:  os.ReadFile, // #nosec G304 -- fixed constructed paths under the generations root
		rename:    os.Rename,
		removeAll: os.RemoveAll,
		syncDir:   fsyncDir,
	}
}

// gcCollector performs the safe collection. It reads the durable records (via the floor +
// activation stores) to compute the root set and to gate on consistency.
type gcCollector struct {
	genRoot    string
	fs         gcFS
	floor      *floorStore
	activation *activationStore
	retain     int
}

func newGCCollector(genRoot string, floor *floorStore, activation *activationStore) (*gcCollector, error) {
	return newGCCollectorFS(osGCFS(), genRoot, floor, activation)
}

func newGCCollectorFS(fs gcFS, genRoot string, floor *floorStore, activation *activationStore) (*gcCollector, error) {
	if genRoot == "" {
		return nil, errGCRoot
	}
	return &gcCollector{genRoot: genRoot, fs: fs, floor: floor, activation: activation, retain: generationRetentionCount}, nil
}

// gcResult is the structured outcome. On a disabled run nothing is deleted.
type gcResult struct {
	Enabled   bool
	Roots     []string // generation ids protected as roots (active + floor records)
	Retained  []string // generation ids kept by the retention window
	Collected []string // generation ids deleted
	Skipped   []string // dirs skipped (symlink / staging / tombstone / unvalidatable)
	Errors    []string // per-deletion errors (do NOT roll back the activation)
	Detail    string
}

// Collect runs one GC pass. It is safe to call repeatedly (idempotent). It NEVER returns
// a hard error for a per-generation deletion failure (those are collected into Errors);
// it returns an error only for a structural problem (unreadable root, escape attempt).
func (g *gcCollector) Collect(ctx context.Context) (gcResult, error) {
	if err := ctx.Err(); err != nil {
		return gcResult{}, err
	}
	// Sweep leftover tombstones first (recovers an interrupted prior GC), idempotently.
	g.sweepTombstones()

	// Gate: durable state must be consistent AND a replacement activation must be committed.
	arec, ast, _ := g.activation.Read()
	if ast != activationValid {
		return gcResult{Enabled: false, Detail: "no committed activation record"}, nil
	}
	frec := g.floor.Recover(arec.ActiveVersion)
	if !g.durableStateConsistent(frec) {
		return gcResult{Enabled: false, Detail: "durable floor/activation state is corrupt, ambiguous, or equivocal"}, nil
	}

	roots := g.rootSet(arec)
	candidates, skipped, err := g.enumerateGenerations()
	if err != nil {
		return gcResult{}, err
	}
	keepRetained, collect := g.applyRetention(candidates, roots)

	res := gcResult{Enabled: true, Skipped: skipped, Detail: "gc pass complete"}
	for id := range roots {
		res.Roots = append(res.Roots, id)
	}
	sort.Strings(res.Roots)
	res.Retained = keepRetained
	for _, c := range collect {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if derr := g.deleteGeneration(c.id); derr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", c.id, derr))
			continue
		}
		res.Collected = append(res.Collected, c.id)
	}
	return res, nil
}

// durableStateConsistent reports whether GC may run: no equivocation, no corrupt-all, and
// neither floor replica corrupt/unreadable. A benignly-absent replica (fresh/one-record)
// is allowed. Equivocation/corruption disables GC (§B.10).
func (g *gcCollector) durableStateConsistent(frec floorRecovery) bool {
	if frec.FailClosed || frec.Health == floorHealthEquivocation || frec.Health == floorHealthCorruptAll {
		return false
	}
	for _, st := range frec.Statuses {
		if st == floorCorrupt || st == floorUnreadable {
			return false
		}
	}
	return true
}

// rootSet is the union of the active generation + every valid floor record's generation
// (which also covers a resumable floor-ahead candidate, since it IS a floor record). The
// caller has already gated on durable-state consistency (durableStateConsistent), so this
// re-reads the two floor replicas directly rather than taking the recovery struct.
func (g *gcCollector) rootSet(arec activationRecord) map[string]struct{} {
	roots := map[string]struct{}{arec.GenerationID: {}}
	recs, sts := readBothFloorRecords(g.floor.fs, g.floor.paths)
	for i := 0; i < 2; i++ {
		if sts[i] == floorValid {
			roots[recs[i].GenerationID] = struct{}{}
		}
	}
	// The activation record's embedded floor copy also names a generation-bound version;
	// the active generation id already covers it.
	return roots
}

// gcCandidate is a validated, deletable-eligible generation directory.
type gcCandidate struct {
	id      string
	version int64
}

// enumerateGenerations lists the generation root and returns the VALIDATED candidate
// generations (id + version from canonical metadata) plus the skipped dirs. It never
// follows symlinks and never validates a staging/tombstone path. Roots are applied later
// by applyRetention, so this stage does not need the root set.
func (g *gcCollector) enumerateGenerations() (candidates []gcCandidate, skipped []string, err error) {
	entries, err := g.fs.readDir(g.genRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("saas feed gc: read generations root: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, genStagePrefix) || strings.HasPrefix(name, gcTombstonePrefix) {
			skipped = append(skipped, name) // owned by another operation — never touch
			continue
		}
		full := filepath.Join(g.genRoot, name)
		info, lerr := g.fs.lstat(full)
		if lerr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			skipped = append(skipped, name) // symlink / non-dir / unstatable — never delete
			continue
		}
		ver, ok := g.validateGenerationDir(name)
		if !ok {
			skipped = append(skipped, name) // unvalidatable metadata — conservatively kept
			continue
		}
		candidates = append(candidates, gcCandidate{id: name, version: ver})
	}
	return candidates, skipped, nil
}

// validateGenerationDir reads + canonically validates generations/<name>/generation.json
// and returns its feed version. A dir whose metadata is missing/corrupt/non-canonical or
// whose generation_id disagrees with the directory name is NOT a deletable candidate
// (returns ok=false so it is conservatively kept, never blindly removed).
func (g *gcCollector) validateGenerationDir(name string) (int64, bool) {
	if !validGenerationID(name) {
		return 0, false
	}
	b, err := g.fs.readFile(filepath.Join(g.genRoot, name, genFileMeta))
	if err != nil || len(b) == 0 || len(b) > maxGenerationMetaBytes {
		return 0, false
	}
	var meta generationMeta
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&meta); derr != nil || dec.More() {
		return 0, false
	}
	canon, cerr := floorCanonicalBytes(meta)
	if cerr != nil || !bytes.Equal(canon, b) {
		return 0, false
	}
	if meta.GenerationID != name || meta.GenerationID != strconv.FormatInt(meta.FeedVersion, 10) || meta.FeedVersion < 1 {
		return 0, false
	}
	return meta.FeedVersion, true
}

// applyRetention keeps the newest `retain` candidates by VERSION (over ALL committed
// generations, ranked from validated metadata — never filename/mtime) UNIONED with every
// explicit root, and returns (retained-by-window ids, collectible candidates). A root is
// never collectible regardless of age/count.
func (g *gcCollector) applyRetention(candidates []gcCandidate, roots map[string]struct{}) ([]string, []gcCandidate) {
	ranked := append([]gcCandidate(nil), candidates...)
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].version != ranked[j].version {
			return ranked[i].version > ranked[j].version
		}
		return ranked[i].id < ranked[j].id
	})
	// The keep set = the newest `retain` by version ∪ the explicit roots.
	keep := make(map[string]struct{}, len(roots)+g.retain)
	for id := range roots {
		keep[id] = struct{}{}
	}
	var retained []string
	for i, c := range ranked {
		if i < g.retain {
			keep[c.id] = struct{}{}
			retained = append(retained, c.id)
		}
	}
	var collect []gcCandidate
	for _, c := range ranked {
		if _, kept := keep[c.id]; !kept {
			collect = append(collect, c)
		}
	}
	sort.Strings(retained)
	return retained, collect
}

// deleteGeneration performs the two-step, recoverable deletion of generations/<id>: it
// validates the target is inside the root, renames it into an owned tombstone, removes the
// tombstone, and syncs the parent. An interruption after the rename leaves only a tombstone
// (swept next pass) and never a half-deleted active/root generation.
func (g *gcCollector) deleteGeneration(id string) error {
	src := filepath.Join(g.genRoot, id)
	if !g.withinRoot(src) {
		return fmt.Errorf("%w: %q", errGCEscape, src)
	}
	tomb := filepath.Join(g.genRoot, gcTombstonePrefix+id)
	// Clear any leftover tombstone for this id (interrupted prior GC) before renaming onto it.
	_ = g.fs.removeAll(tomb)
	if err := g.fs.rename(src, tomb); err != nil {
		return fmt.Errorf("tombstone rename: %w", err)
	}
	if err := g.fs.removeAll(tomb); err != nil {
		return fmt.Errorf("tombstone remove: %w", err)
	}
	if err := g.fs.syncDir(g.genRoot); err != nil {
		return fmt.Errorf("parent sync: %w", err)
	}
	return nil
}

// withinRoot guards against ever operating outside the fixed generation root.
func (g *gcCollector) withinRoot(p string) bool {
	rel, err := filepath.Rel(g.genRoot, p)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !strings.Contains(rel, string(os.PathSeparator))
}

// sweepTombstones idempotently removes leftover GC tombstones from an interrupted pass.
func (g *gcCollector) sweepTombstones() {
	entries, err := g.fs.readDir(g.genRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), gcTombstonePrefix) {
			_ = g.fs.removeAll(filepath.Join(g.genRoot, e.Name()))
		}
	}
	_ = g.fs.syncDir(g.genRoot)
}
