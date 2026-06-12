package main

import (
	"encoding/json"
	"errors"
	"regexp"
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
	return d, p
}

// ─── refusals (fail-closed, structured) ──────────────────────────────────────

func TestDispatch_NoCatalogRefuses(t *testing.T) {
	d, _ := newDispatcher(t, nil, DispatchConfig{ProxyRepo: dispatchRepo})
	plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, nil, DefaultDispatchOptions())
	if !plan.Refused() || !errors.Is(plan.Reason, errDispatchNoCatalog) {
		t.Fatalf("no catalog: outcome=%s reason=%v; want refused/errDispatchNoCatalog", plan.Outcome, plan.Reason)
	}
}

func TestDispatch_UnknownTargetRefuses(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	if plan := d.Plan(DispatchTarget{ReleaseID: "rel_nope"}, nil, DefaultDispatchOptions()); !errors.Is(plan.Reason, errDispatchUnknownTarget) {
		t.Fatalf("unknown release_id: reason = %v; want errDispatchUnknownTarget", plan.Reason)
	}
	if plan := d.Plan(DispatchTarget{Channel: Channel("beta")}, nil, DefaultDispatchOptions()); !plan.Refused() {
		t.Fatal("unknown channel must refuse")
	}
	if plan := d.Plan(DispatchTarget{}, nil, DefaultDispatchOptions()); !errors.Is(plan.Reason, errDispatchNoTarget) {
		t.Fatalf("empty target: reason = %v; want errDispatchNoTarget", plan.Reason)
	}
	if plan := d.Plan(DispatchTarget{ReleaseID: "rel_a", Channel: ChannelLTS}, nil, DefaultDispatchOptions()); !errors.Is(plan.Reason, errDispatchAmbiguousTarget) {
		t.Fatalf("ambiguous target: reason = %v; want errDispatchAmbiguousTarget", plan.Reason)
	}
}

func TestDispatch_RepoMismatchRefusesBeforeApply(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: "ghcr.io/someone/else"})
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions())
	if !errors.Is(plan.Reason, errDispatchRepoMismatch) {
		t.Fatalf("repo mismatch: reason = %v; want errDispatchRepoMismatch", plan.Reason)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("a refused plan must not build an apply request")
	}
}

func TestDispatch_InvalidRewriteMappingRefuses(t *testing.T) {
	cat := mustLoad(t, validSource())
	bad := []DispatchConfig{
		{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: dispatchRepo, To: "ghcr.io/other/repo"}}, // to != proxy_repo
		{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: mirrorRepo, To: mirrorRepo}},             // from == to
		{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: "bad repo!", To: mirrorRepo}},            // bad shape
		{ProxyRepo: "bad repo!"}, // bad proxy_repo
	}
	for i, cfg := range bad {
		if _, err := NewDispatcher(&fakeCatProvider{cat: cat}, cfg); err == nil {
			t.Fatalf("case %d: NewDispatcher must reject an invalid rewrite mapping", i)
		}
	}
}

// ─── forward path ────────────────────────────────────────────────────────────

func TestDispatch_ChannelResolveBuildsDigestApply(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, nil, DefaultDispatchOptions())
	if plan.Outcome != OutcomePlan {
		t.Fatalf("outcome = %s; want plan", plan.Outcome)
	}
	if plan.ReleaseID != "rel_a" || plan.VersionID != "1.10.0" {
		t.Fatalf("resolved = %s/%s; want rel_a/1.10.0", plan.ReleaseID, plan.VersionID)
	}
	want := dispatchRepo + "@" + digA
	if plan.PinnedRef != want || plan.ImageRef != want || plan.Apply.ImageRef != want {
		t.Fatalf("refs: pinned=%q image=%q apply=%q; want %q", plan.PinnedRef, plan.ImageRef, plan.Apply.ImageRef, want)
	}
}

// The dispatch target is a release_id/channel and the image_ref is ALWAYS a
// digest ref — never a tag, never reconstructed from one.
func TestDispatch_NeverTagShaped(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	// A tag-shaped running ref is not a repo@digest and never matches Current.
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{dispatchRepo + ":1.10.0"}, DefaultDispatchOptions())
	if plan.Current.Known {
		t.Fatal("a tag-shaped running ref must not be recognized as Current")
	}
	if plan.AlreadyCurrent {
		t.Fatal("a tag-shaped running ref must not count as already-current")
	}
	// The produced image_ref is digest-shaped.
	digestShape := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	if !digestShape.MatchString(plan.Apply.ImageRef) {
		t.Fatalf("apply image_ref %q is not a digest ref", plan.Apply.ImageRef)
	}
	if strings.Contains(plan.Apply.ImageRef, ":1.10.0") {
		t.Fatal("apply image_ref must never carry a tag")
	}
}

// ─── current / already-current ───────────────────────────────────────────────

func TestDispatch_AlreadyCurrentOnExactMatch(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	target := dispatchRepo + "@" + digA

	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{target}, DefaultDispatchOptions())
	if plan.Outcome != OutcomeAlreadyCurrent || !plan.AlreadyCurrent {
		t.Fatalf("outcome = %s; want already_current", plan.Outcome)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("already-current must not produce an apply request")
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
	running := []string{dispatchRepo + "@sha256:" + strings.Repeat("e", 64), target} // match is SECOND

	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, running, DefaultDispatchOptions())
	if !plan.AlreadyCurrent || !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("must match a non-first repo_digests entry: already=%v current=%+v", plan.AlreadyCurrent, plan.Current)
	}
}

func TestDispatch_UnknownCurrentAllowed(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	running := []string{dispatchRepo + "@sha256:" + strings.Repeat("f", 64)} // foreign/legacy digest

	plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, running, DefaultDispatchOptions())
	if plan.Outcome != OutcomePlan {
		t.Fatalf("unknown current must still allow dispatch; outcome=%s reason=%v", plan.Outcome, plan.Reason)
	}
	if plan.Current.Known {
		t.Fatal("Current should be Unknown for a foreign digest")
	}
	if plan.AlreadyCurrent {
		t.Fatal("unknown current is not already-current")
	}
}

// ─── repo rewrite ────────────────────────────────────────────────────────────

func TestDispatch_AirgapForwardPreservesDigestTargetsProxyRepo(t *testing.T) {
	cat := mustLoad(t, validSource())
	cfg := DispatchConfig{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: dispatchRepo, To: mirrorRepo}}
	d, _ := newDispatcher(t, cat, cfg)

	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions())
	if plan.Outcome != OutcomePlan {
		t.Fatalf("outcome=%s reason=%v", plan.Outcome, plan.Reason)
	}
	if plan.PinnedRef != dispatchRepo+"@"+digA {
		t.Fatalf("PinnedRef = %q; want the catalog ref", plan.PinnedRef)
	}
	if plan.ImageRef != mirrorRepo+"@"+digA {
		t.Fatalf("forward rewrite: ImageRef = %q; want mirror repo + SAME digest", plan.ImageRef)
	}
	// digest byte-for-byte identical across the rewrite.
	if _, catAt, _ := splitRepoRef(plan.PinnedRef); true {
		_, imgAt, _ := splitRepoRef(plan.ImageRef)
		if catAt != imgAt {
			t.Fatalf("digest changed by rewrite: %q vs %q", catAt, imgAt)
		}
	}
}

func TestDispatch_AirgapReverseMakesCurrentKnown(t *testing.T) {
	cat := mustLoad(t, validSource())
	cfg := DispatchConfig{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: dispatchRepo, To: mirrorRepo}}
	d, _ := newDispatcher(t, cat, cfg)

	// The running node reports the MIRROR repo; reverse-rewrite finds the release.
	running := []string{mirrorRepo + "@" + digA}
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, running, DefaultDispatchOptions())
	if !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("reverse rewrite: Current = %+v; want Known rel_a", plan.Current)
	}
	if !plan.AlreadyCurrent {
		t.Fatal("a mirror-repo running digest equal to the target must be already-current")
	}
}

// ─── apply request flags ─────────────────────────────────────────────────────

func TestDispatch_ApplyFlags(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	// Default: rollback on, no passphrase ⇒ pre_backup=false + skip note.
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions())
	if !plan.Apply.RollbackOnFailure {
		t.Fatal("rollback_on_failure must default to true")
	}
	b, err := json.Marshal(plan.Apply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"rollback_on_failure":true`) {
		t.Fatalf("rollback_on_failure must be serialized explicitly: %s", b)
	}
	if plan.Apply.PreBackup || plan.Apply.PassphraseRef != "" || !plan.BackupSkipped {
		t.Fatalf("no passphrase ⇒ pre_backup=false, no ref, BackupSkipped; got %+v skipped=%v", plan.Apply, plan.BackupSkipped)
	}

	// passphrase_ref present iff pre_backup=true.
	plan2 := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DispatchOptions{PreBackup: true, PassphraseRef: "env:CULVERT_CA_PASSPHRASE", IdempotencyKey: "op-123"})
	if !plan2.Apply.PreBackup || plan2.Apply.PassphraseRef != "env:CULVERT_CA_PASSPHRASE" || plan2.BackupSkipped {
		t.Fatalf("with a passphrase ref, pre_backup=true + ref carried: %+v", plan2.Apply)
	}
	// idempotency_key is passed through from input (not generated).
	if plan2.Apply.IdempotencyKey != "op-123" {
		t.Fatalf("idempotency_key = %q; want the input op-123", plan2.Apply.IdempotencyKey)
	}
	// pre_backup=false must never carry a passphrase_ref (agent 400s the pair).
	plan3 := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DispatchOptions{PreBackup: false, PassphraseRef: "env:X"})
	if plan3.Apply.PreBackup || plan3.Apply.PassphraseRef != "" {
		t.Fatalf("pre_backup=false must drop the passphrase_ref; got %+v", plan3.Apply)
	}
}

// ─── pinning ─────────────────────────────────────────────────────────────────

// The catalog snapshot is read exactly once per Plan (pinned for the op; no I/O).
func TestDispatch_CatalogPinnedPerOp(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, p := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions())
	if p.calls != 1 {
		t.Fatalf("GetCatalog called %d times in one Plan; want exactly 1 (pinned snapshot)", p.calls)
	}
}
