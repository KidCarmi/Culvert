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
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "v1.9.0"})

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
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "v1.9.0"})

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

// INVERTED (appliance readiness): the fixture's 1.10.0 declares
// min_upgrade_from 1.2.0, so a running release the catalog cannot name AND
// the binary cannot name ("dev") is refused until acknowledged — the policy
// is enforced, not merely parsed. The binary's own version stamp is the
// ordinary way the predecessor becomes known (single-entry catalogs never
// list the release being upgraded FROM).
func TestDispatch_UnknownCurrentRequiresAcknowledgementOrSelfVersion(t *testing.T) {
	cat := mustLoad(t, validSource())
	running := []string{dispatchRepo + "@sha256:" + strings.Repeat("f", 64)} // foreign/legacy digest

	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "dev"})
	plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, running, DefaultDispatchOptions())
	if plan.Kind != RefusedUnknownCurrent {
		t.Fatalf("unknown current with a floor must be refused until acknowledged; kind=%q outcome=%s", plan.Kind, plan.Outcome)
	}
	if plan.Current.Known || plan.CurrentVersion != "" {
		t.Fatalf("Current should be Unknown for a foreign digest and a dev build: %+v", plan)
	}
	plan = d.Plan(DispatchTarget{Channel: ChannelRecommended}, running, DispatchOptions{AcknowledgeUnknownCurrent: true})
	if plan.Outcome != OutcomePlan || plan.AlreadyCurrent {
		t.Fatalf("acknowledged unknown current must plan; outcome=%s reason=%v", plan.Outcome, plan.Reason)
	}

	// The binary's own stamp names the predecessor when the catalog cannot.
	d, _ = newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "v1.3.7"})
	plan = d.Plan(DispatchTarget{Channel: ChannelRecommended}, running, DefaultDispatchOptions())
	if plan.Outcome != OutcomePlan || plan.CurrentVersion != "1.3.7" || plan.CurrentVersionSource != "binary" {
		t.Fatalf("self version >= floor must plan via the binary stamp: %+v reason=%v", plan, plan.Reason)
	}
	d, _ = newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "v1.1.9"})
	plan = d.Plan(DispatchTarget{Channel: ChannelRecommended}, running, DefaultDispatchOptions())
	if plan.Kind != RefusedUnsupportedTransition {
		t.Fatalf("self version below the floor must be refused: kind=%q", plan.Kind)
	}
	// A catalog identity outranks the binary stamp.
	d, _ = newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "v1.1.9"})
	plan = d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{dispatchRepo + "@" + digB}, DefaultDispatchOptions())
	if plan.CurrentVersionSource != "catalog" {
		t.Fatalf("catalog identity must win over the binary stamp: %+v", plan)
	}
}

// ─── repo rewrite ────────────────────────────────────────────────────────────

func TestDispatch_AirgapForwardPreservesDigestTargetsProxyRepo(t *testing.T) {
	cat := mustLoad(t, validSource())
	cfg := DispatchConfig{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: dispatchRepo, To: mirrorRepo}, SelfVersion: "1.9.0"}
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
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo, SelfVersion: "v1.9.0"})

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

// ─── P1.6a.1: already-current unified with Current ──────────────────────────

// Current.Known on the TARGET release ⇒ already-current (no apply).
func TestDispatch_CurrentKnownTargetIsAlreadyCurrent(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{dispatchRepo + "@" + digA}, DefaultDispatchOptions())
	if plan.Outcome != OutcomeAlreadyCurrent || !plan.AlreadyCurrent {
		t.Fatalf("outcome = %s; want already_current", plan.Outcome)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("already-current must not build an apply request")
	}
}

// Current.Known on a DIFFERENT release ⇒ NOT already-current; dispatch is planned.
func TestDispatch_CurrentKnownDifferentReleaseStillPlans(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	// Target rel_a (1.10.0) while the node runs rel_b's digest (1.9.0).
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{dispatchRepo + "@" + digB}, DefaultDispatchOptions())
	if !plan.Current.Known || plan.Current.ReleaseID != "rel_b" {
		t.Fatalf("Current = %+v; want Known rel_b", plan.Current)
	}
	if plan.AlreadyCurrent {
		t.Fatal("running a DIFFERENT release must not be already-current")
	}
	if plan.Outcome != OutcomePlan || plan.Apply.ImageRef != dispatchRepo+"@"+digA {
		t.Fatalf("outcome=%s apply=%q; want a planned dispatch to rel_a", plan.Outcome, plan.Apply.ImageRef)
	}
}

// The target digest later in repo_digests must NOT be masked by a different
// known release appearing earlier — scan the WHOLE array for the target.
func TestDispatch_TargetAfterDifferentKnownReleaseIsAlreadyCurrent(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	// repo_digests = [rel_b's digest (a DIFFERENT known release), rel_a's digest (the target)].
	running := []string{dispatchRepo + "@" + digB, dispatchRepo + "@" + digA}
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, running, DefaultDispatchOptions())
	if !plan.AlreadyCurrent || plan.Outcome != OutcomeAlreadyCurrent {
		t.Fatalf("a later target entry must win: outcome=%s already=%v", plan.Outcome, plan.AlreadyCurrent)
	}
	if !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("Current must reflect the matched target: %+v", plan.Current)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("already-current must not build an apply request")
	}
}

// Air-gap edge: a node that reports the CATALOG repo (not the mirror) while
// running the target release is still recognized as already-current — the
// unified logic derives this from Current (release identity), not a repo-bound
// string compare.
func TestDispatch_AirgapCatalogRepoRunningRefIsAlreadyCurrent(t *testing.T) {
	cat := mustLoad(t, validSource())
	cfg := DispatchConfig{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: dispatchRepo, To: mirrorRepo}}
	d, _ := newDispatcher(t, cat, cfg)

	// running reports the CATALOG repo digest, not the mirror repo.
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{dispatchRepo + "@" + digA}, DefaultDispatchOptions())
	if !plan.Current.Known || plan.Current.ReleaseID != "rel_a" {
		t.Fatalf("Current = %+v; want Known rel_a", plan.Current)
	}
	if !plan.AlreadyCurrent || plan.Outcome != OutcomeAlreadyCurrent {
		t.Fatalf("catalog-repo running ref of the target must be already-current; got outcome=%s already=%v", plan.Outcome, plan.AlreadyCurrent)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("already-current must not build an apply request")
	}
}

// ─── P1.6a.1: rollback opt-out ──────────────────────────────────────────────

func TestDispatch_RollbackOptOut(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DispatchOptions{NoRollback: true})
	if plan.Apply.RollbackOnFailure {
		t.Fatal("NoRollback:true must produce rollback_on_failure=false")
	}
	b, err := json.Marshal(plan.Apply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"rollback_on_failure":false`) {
		t.Fatalf("rollback_on_failure must be serialized explicitly as false: %s", b)
	}
}

// ─── P1.6a.1: refusal taxonomy ──────────────────────────────────────────────

func TestDispatch_RefusalKinds(t *testing.T) {
	cat := mustLoad(t, validSource())
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	dMismatch, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: "ghcr.io/someone/else"})

	cases := []struct {
		name string
		plan *DispatchPlan
		want RefusedKind
	}{
		{"no catalog", (&Dispatcher{provider: &fakeCatProvider{cat: nil}, cfg: DispatchConfig{ProxyRepo: dispatchRepo}}).Plan(DispatchTarget{Channel: ChannelRecommended}, nil, DefaultDispatchOptions()), RefusedNoCatalog},
		{"no target", d.Plan(DispatchTarget{}, nil, DefaultDispatchOptions()), RefusedNoTarget},
		{"ambiguous", d.Plan(DispatchTarget{ReleaseID: "rel_a", Channel: ChannelLTS}, nil, DefaultDispatchOptions()), RefusedAmbiguousTarget},
		{"unknown release_id", d.Plan(DispatchTarget{ReleaseID: "rel_nope"}, nil, DefaultDispatchOptions()), RefusedUnknownTarget},
		{"unknown channel", d.Plan(DispatchTarget{Channel: Channel("beta")}, nil, DefaultDispatchOptions()), RefusedUnknownTarget},
		{"repo mismatch", dMismatch.Plan(DispatchTarget{ReleaseID: "rel_a"}, nil, DefaultDispatchOptions()), RefusedRepoMismatch},
	}
	for _, c := range cases {
		if !c.plan.Refused() {
			t.Errorf("%s: expected a refusal", c.name)
			continue
		}
		if c.plan.Kind != c.want {
			t.Errorf("%s: Kind = %q; want %q", c.name, c.plan.Kind, c.want)
		}
		// The classification is also reachable from the Reason error.
		if RefusalKind(c.plan.Reason) != c.want {
			t.Errorf("%s: RefusalKind(Reason) = %q; want %q", c.name, RefusalKind(c.plan.Reason), c.want)
		}
	}
}

// Construction-time refusals are classified too.
func TestDispatch_NewDispatcherRefusalKinds(t *testing.T) {
	cat := mustLoad(t, validSource())
	if _, err := NewDispatcher(&fakeCatProvider{cat: cat}, DispatchConfig{ProxyRepo: "bad repo!"}); RefusalKind(err) != RefusedInvalidConfig {
		t.Fatalf("bad proxy_repo: RefusalKind = %q; want invalid_config", RefusalKind(err))
	}
	if _, err := NewDispatcher(&fakeCatProvider{cat: cat}, DispatchConfig{ProxyRepo: mirrorRepo, RepoRewrite: &RepoRewrite{From: dispatchRepo, To: "ghcr.io/other/repo"}}); RefusalKind(err) != RefusedInvalidRewriteMapping {
		t.Fatalf("bad rewrite: RefusalKind = %q; want invalid_rewrite_mapping", RefusalKind(err))
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

// ─── transition policy (appliance readiness) ─────────────────────────────────

// transitionCatalog builds a two-release catalog (1.9.0 → 1.10.0 per
// testdata/release/valid) and lets a test stamp min_upgrade_from on the
// newer one without touching fixtures on disk.
func transitionCatalog(t *testing.T, minFrom string) *Catalog {
	t.Helper()
	cat := mustLoad(t, validSource())
	newestID := ""
	for id := range cat.byReleaseID {
		if newestID == "" || catalogCompareSemver(cat.byReleaseID[id].VersionID, cat.byReleaseID[newestID].VersionID) > 0 {
			newestID = id
		}
	}
	if newestID == "" {
		t.Fatal("fixture catalog is empty")
	}
	rel := cat.byReleaseID[newestID]
	rel.MinUpgradeFrom = minFrom
	cat.byReleaseID[newestID] = rel
	return cat
}

func releaseByVersion(t *testing.T, cat *Catalog, want string) Release {
	t.Helper()
	for id := range cat.byReleaseID {
		if cat.byReleaseID[id].VersionID == want {
			return cat.byReleaseID[id]
		}
	}
	t.Fatalf("no release %s in fixture", want)
	return Release{}
}

func TestDispatch_Transition_RefusesBelowMinUpgradeFrom(t *testing.T) {
	cat := transitionCatalog(t, "1.9.5")
	newest := releaseByVersion(t, cat, "1.10.0")
	older := releaseByVersion(t, cat, "1.9.0")
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	plan := d.Plan(DispatchTarget{ReleaseID: newest.ReleaseID}, []string{older.PinnedRef}, DefaultDispatchOptions())
	if plan.Kind != RefusedUnsupportedTransition || !errors.Is(plan.Reason, errDispatchUnsupportedTransition) {
		t.Fatalf("kind=%q reason=%v; want unsupported_transition", plan.Kind, plan.Reason)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("a refused transition must never build an apply request")
	}
	if plan.MinUpgradeFrom != "1.9.5" || plan.Current.VersionID != "1.9.0" {
		t.Fatalf("refusal must carry the floor and the running release: %+v", plan)
	}
	// No acknowledgement admits an unqualified jump.
	plan = d.Plan(DispatchTarget{ReleaseID: newest.ReleaseID}, []string{older.PinnedRef},
		DispatchOptions{AcknowledgeUnknownCurrent: true, AllowDowngrade: true})
	if plan.Kind != RefusedUnsupportedTransition {
		t.Fatalf("acknowledgements must not admit a below-floor transition, got kind=%q", plan.Kind)
	}
	if refusalHTTPStatus(plan.Kind) != 409 {
		t.Fatalf("transition refusals map to 409, got %d", refusalHTTPStatus(plan.Kind))
	}
}

func TestDispatch_Transition_AdmitsAtOrAboveFloor(t *testing.T) {
	for _, floor := range []string{"1.9.0", "1.8.0", ""} {
		cat := transitionCatalog(t, floor)
		newest := releaseByVersion(t, cat, "1.10.0")
		older := releaseByVersion(t, cat, "1.9.0")
		d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
		plan := d.Plan(DispatchTarget{ReleaseID: newest.ReleaseID}, []string{older.PinnedRef}, DefaultDispatchOptions())
		if plan.Outcome != OutcomePlan {
			t.Fatalf("floor %q: running 1.9.0 → 1.10.0 must plan, got outcome=%s kind=%q reason=%v", floor, plan.Outcome, plan.Kind, plan.Reason)
		}
	}
}

func TestDispatch_Transition_UnknownCurrentNeedsAcknowledgement(t *testing.T) {
	cat := transitionCatalog(t, "1.9.0")
	newest := releaseByVersion(t, cat, "1.10.0")
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	custom := []string{dispatchRepo + "@sha256:" + strings.Repeat("c", 64)}

	plan := d.Plan(DispatchTarget{ReleaseID: newest.ReleaseID}, custom, DefaultDispatchOptions())
	if plan.Kind != RefusedUnknownCurrent || !errors.Is(plan.Reason, errDispatchUnknownCurrent) {
		t.Fatalf("kind=%q reason=%v; want unknown_current", plan.Kind, plan.Reason)
	}
	plan = d.Plan(DispatchTarget{ReleaseID: newest.ReleaseID}, custom, DispatchOptions{AcknowledgeUnknownCurrent: true})
	if plan.Outcome != OutcomePlan {
		t.Fatalf("acknowledged unknown current must plan, got kind=%q reason=%v", plan.Kind, plan.Reason)
	}
	// A target WITHOUT a floor constrains nothing for an unknown current
	// (pre-policy catalogs; existing installs keep their behaviour).
	cat = transitionCatalog(t, "")
	newest = releaseByVersion(t, cat, "1.10.0")
	d, _ = newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	if plan := d.Plan(DispatchTarget{ReleaseID: newest.ReleaseID}, custom, DefaultDispatchOptions()); plan.Outcome != OutcomePlan {
		t.Fatalf("no floor ⇒ unknown current must plan, got kind=%q", plan.Kind)
	}
}

func TestDispatch_Transition_DowngradeNeedsBreakGlass(t *testing.T) {
	cat := transitionCatalog(t, "")
	newest := releaseByVersion(t, cat, "1.10.0")
	older := releaseByVersion(t, cat, "1.9.0")
	d, _ := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})

	plan := d.Plan(DispatchTarget{ReleaseID: older.ReleaseID}, []string{newest.PinnedRef}, DefaultDispatchOptions())
	if plan.Kind != RefusedDowngrade || !errors.Is(plan.Reason, errDispatchDowngrade) {
		t.Fatalf("kind=%q reason=%v; want downgrade", plan.Kind, plan.Reason)
	}
	if plan.Apply.ImageRef != "" {
		t.Fatal("a refused downgrade must never build an apply request")
	}
	plan = d.Plan(DispatchTarget{ReleaseID: older.ReleaseID}, []string{newest.PinnedRef}, DispatchOptions{AllowDowngrade: true})
	if plan.Outcome != OutcomePlan || plan.Apply.ImageRef == "" {
		t.Fatalf("allow_downgrade must plan, got kind=%q reason=%v", plan.Kind, plan.Reason)
	}
	// Channel targets go through the same check (Catalog.Resolve carries the floor).
	cat = transitionCatalog(t, "1.9.5")
	newest = releaseByVersion(t, cat, "1.10.0")
	older = releaseByVersion(t, cat, "1.9.0")
	for ch, id := range cat.channels {
		if id == newest.ReleaseID {
			d, _ = newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
			if plan := d.Plan(DispatchTarget{Channel: ch}, []string{older.PinnedRef}, DefaultDispatchOptions()); plan.Kind != RefusedUnsupportedTransition {
				t.Fatalf("channel %s: want unsupported_transition, got kind=%q", ch, plan.Kind)
			}
		}
	}
}

func TestReleaseSpec_MinUpgradeFromStamped(t *testing.T) {
	in := SpecInputs{Version: "1.4.3", Repo: dispatchRepo, ListDigest: "sha256:" + strings.Repeat("a", 64),
		Platforms: []string{"linux/amd64"}, Mode: specModeRelease, CommitISO: "2026-01-02T03:04:05Z", MinUpgradeFrom: "1.4.0"}
	spec, err := buildReleaseSpec(in)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Entries[0].MinUpgradeFrom != "1.4.0" {
		t.Fatalf("min_upgrade_from not stamped: %+v", spec.Entries[0])
	}
	in.MinUpgradeFrom = "1.5.0"
	if _, err := buildReleaseSpec(in); err == nil {
		t.Fatal("a floor newer than the release must be refused")
	}
	in.MinUpgradeFrom = "v1.4.0"
	if _, err := buildReleaseSpec(in); err == nil {
		t.Fatal("a non-bare floor must be refused")
	}
	// The repo policy constant is well-formed and is what CI stamps by default.
	if !catalogVersionCoreRE.MatchString(releaseMinUpgradeFrom) {
		t.Fatalf("releaseMinUpgradeFrom %q is not X.Y.Z", releaseMinUpgradeFrom)
	}
	t.Setenv("CULVERT_RELEASE_SPEC_MIN_UPGRADE_FROM", "")
	if got := resolveSpecMinUpgradeFrom(); got != "" {
		t.Fatalf("explicit empty override must mean unconstrained, got %q", got)
	}
}
