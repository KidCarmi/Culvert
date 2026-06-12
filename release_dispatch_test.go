package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeCatProvider is a catalogSnapshotProvider that counts GetCatalog calls.
type fakeCatProvider struct {
	cat   *Catalog
	calls int
}

func (f *fakeCatProvider) GetCatalog() *Catalog {
	f.calls++
	return f.cat
}

const (
	dispatchRepo = "ghcr.io/kidcarmi/culvert" // == validSource() repo
	mirrorRepo   = "registry.local/culvert"
)

func newDispatcher(t *testing.T, cat *Catalog, cfg DispatchConfig) (*Dispatcher, *fakeCatProvider) {
	t.Helper()
	p := &fakeCatProvider{cat: cat}
	d, err := NewDispatcher(p, cfg)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	d.newOpID = func() string { return "TESTOP" } // deterministic idempotency key
	return d, p
}

// ─── refusals ────────────────────────────────────────────────────────────────

func TestDispatch_NoCatalogRefuses(t *testing.T) {
	d, _ := newDispatcher(t, nil, DispatchConfig{ProxyRepo: dispatchRepo})
	if _, err := d.Plan(DispatchTarget{Channel: ChannelRecommended}, nil, DefaultDispatchOptions()); !errors.Is(err, errDispatchNoCatalog) {
		t.Fatalf("no catalog: err = %v; want errDispatchNoCatalog", err)
	}
}

func TestDispatch_UnknownTargetRefuses(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	if _, err := d.Plan(DispatchTarget{ReleaseID: "rel_nope"}, nil, DefaultDispatchOptions()); !errors.Is(err, errDispatchUnknownTarget) {
		t.Fatalf("unknown release_id: err = %v; want errDispatchUnknownTarget", err)
	}
	if _, err := d.Plan(DispatchTarget{Channel: Channel("beta")}, nil, DefaultDispatchOptions()); err == nil {
		t.Fatal("unknown channel must refuse")
	}
	if _, err := d.Plan(DispatchTarget{}, nil, DefaultDispatchOptions()); !errors.Is(err, errDispatchNoTarget) {
		t.Fatalf("empty target: err = %v; want errDispatchNoTarget", err)
	}
	if _, err := d.Plan(DispatchTarget{ReleaseID: "rel_a", Channel: ChannelLTS}, nil, DefaultDispatchOptions()); !errors.Is(err, errDispatchAmbiguousTarget) {
		t.Fatalf("ambiguous target: err = %v; want errDispatchAmbiguousTarget", err)
	}
}

func TestDispatch_RepoMismatchRefuses(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: "ghcr.io/someone/else"})
	if _, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions()); !errors.Is(err, errDispatchRepoMismatch) {
		t.Fatalf("repo mismatch: err = %v; want errDispatchRepoMismatch", err)
	}
}

// ─── current / already-current ───────────────────────────────────────────────

func TestDispatch_AlreadyCurrentOnExactMatch(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	target := dispatchRepo + "@" + digA // rel_a's pinned ref

	plan, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{target}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.AlreadyCurrent {
		t.Fatal("running the target digest must be AlreadyCurrent")
	}
	if plan.ApplyValid {
		t.Fatal("AlreadyCurrent must not produce an apply request")
	}
	if !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("Current = %+v; want Known rel_a", plan.Current)
	}
}

// Current/already-current must consider EVERY repo_digests entry, not just the first.
func TestDispatch_MatchesAnyRepoDigestEntry(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	target := dispatchRepo + "@" + digA
	// The matching list digest is the SECOND entry (e.g. a per-arch digest first).
	running := []string{dispatchRepo + "@sha256:" + strings.Repeat("e", 64), target}

	plan, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, running, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.AlreadyCurrent || !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("must match a non-first repo_digests entry: AlreadyCurrent=%v Current=%+v", plan.AlreadyCurrent, plan.Current)
	}
}

func TestDispatch_UnknownCurrentAllowed(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	// Running a foreign/legacy digest not in the catalog.
	running := []string{dispatchRepo + "@sha256:" + strings.Repeat("f", 64)}

	plan, err := d.Plan(DispatchTarget{Channel: ChannelRecommended}, running, DefaultDispatchOptions())
	if err != nil {
		t.Fatalf("unknown current must still allow dispatch: %v", err)
	}
	if plan.Current.Known {
		t.Fatal("Current should be Unknown for a foreign digest")
	}
	if plan.AlreadyCurrent || !plan.ApplyValid {
		t.Fatal("unknown current ⇒ not already-current, apply request built")
	}
}

// ─── repo rewrite ────────────────────────────────────────────────────────────

func TestDispatch_RepoRewriteForwardAndReverse(t *testing.T) {
	cat := mustLoad(t, validSource())
	cfg := DispatchConfig{
		ProxyRepo:   mirrorRepo,
		RepoRewrite: &RepoRewrite{From: dispatchRepo, To: mirrorRepo},
	}
	d, _ := newDispatcher(t, cat, cfg)

	// FORWARD: the target ref is rewritten to the deployment (mirror) repo.
	// REVERSE: a running mirror-repo digest reverse-maps to the catalog release.
	runningMirror := mirrorRepo + "@" + digA
	plan, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{runningMirror}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetRef != mirrorRepo+"@"+digA {
		t.Fatalf("forward rewrite: TargetRef = %q; want %q", plan.TargetRef, mirrorRepo+"@"+digA)
	}
	if !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("reverse rewrite: Current = %+v; want Known rel_a", plan.Current)
	}
	if !plan.AlreadyCurrent {
		t.Fatal("a mirror-repo running digest equal to the target must be AlreadyCurrent")
	}
}

// ─── apply request ───────────────────────────────────────────────────────────

func TestDispatch_ApplyRequestRollbackExplicit(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	plan, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyValid {
		t.Fatal("a fresh dispatch must build an apply request")
	}
	if !plan.Apply.RollbackOnFailure {
		t.Fatal("rollback_on_failure must default to true")
	}
	if plan.Apply.ImageRef != dispatchRepo+"@"+digA {
		t.Fatalf("image_ref = %q", plan.Apply.ImageRef)
	}
	if plan.Apply.IdempotencyKey != "rel-rel_a-TESTOP" {
		t.Fatalf("idempotency_key = %q", plan.Apply.IdempotencyKey)
	}
	// rollback_on_failure must be serialized EXPLICITLY (no omitempty).
	b, err := json.Marshal(plan.Apply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"rollback_on_failure":true`) {
		t.Fatalf("apply JSON must carry rollback_on_failure explicitly: %s", b)
	}

	// pre_backup default true but no passphrase ⇒ pre_backup=false + skip note (§6).
	if plan.Apply.PreBackup || plan.Apply.PassphraseRef != "" {
		t.Fatalf("no passphrase ⇒ pre_backup must be false with no ref; got %+v", plan.Apply)
	}
	if !plan.BackupSkipped {
		t.Fatal("BackupSkipped must be recorded when pre_backup was requested without a ref")
	}

	// With a passphrase ref, pre_backup is true and the ref is carried.
	plan2, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DispatchOptions{PreBackup: true, PassphraseRef: "env:CULVERT_CA_PASSPHRASE"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan2.Apply.PreBackup || plan2.Apply.PassphraseRef != "env:CULVERT_CA_PASSPHRASE" || plan2.BackupSkipped {
		t.Fatalf("with a passphrase ref, pre_backup must be true: %+v skipped=%v", plan2.Apply, plan2.BackupSkipped)
	}
}

// ─── pinning ─────────────────────────────────────────────────────────────────

// The catalog snapshot is read exactly once per Plan (pinned for the op).
func TestDispatch_CatalogPinnedPerOp(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, p := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	if _, err := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions()); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 {
		t.Fatalf("GetCatalog called %d times in one Plan; want exactly 1 (pinned snapshot)", p.calls)
	}
}
