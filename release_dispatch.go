// Release Dispatch — P1.6 Slice a (CP-side dispatch kernel, PURE PLANNING).
//
// The Dispatcher turns an operator target (release_id or channel) into a
// DispatchPlan: it resolves the release from a PINNED immutable catalog
// snapshot (P1.5 holder), reconciles the catalog repo against the deployment's
// proxy_repo (repo equality / one explicit air-gap rewrite, design §4), derives
// Current/already-current from the agent's running_image.repo_digests (P1.1,
// design §3/§5), and builds the EXISTING upgrades.apply request object (design
// §6) — WITHOUT sending it.
//
// It is a PURE, deterministic planner: no I/O, no randomness, no agent contact.
// The idempotency key is an INPUT (higher orchestration owns op identity); the
// catalog snapshot is read exactly once at plan start. The agent receives only
// an image_ref + existing apply flags — no release/channel/version/catalog data
// crosses to it, and it stays release-agnostic.
//
// Scope (roadmap/D1.6d-P1.6-release-dispatch-plan.md — Slice a): planning + the
// request object + tests. NO agent POST, NO upgrades.check, NO tags, NO tag
// updater, NO new agent endpoint, NO agent changes, NO GUI, NO auto-update, NO
// rollback-candidate computation, NO legacy-updater changes.
package main

import (
	"errors"
	"fmt"
	"strings"
)

var (
	errDispatchNoCatalog       = errors.New("dispatch: no catalog published")
	errDispatchNoTarget        = errors.New("dispatch: no target (release_id or channel) given")
	errDispatchAmbiguousTarget = errors.New("dispatch: both release_id and channel given")
	errDispatchUnknownTarget   = errors.New("dispatch: unknown release_id")
	errDispatchRepoMismatch    = errors.New("dispatch: catalog repo does not match deployment proxy_repo")
	errDispatchMalformedRef    = errors.New("dispatch: malformed pinned ref")
)

// catalogSnapshotProvider yields the currently-published immutable catalog
// (nil ⇒ no-catalog). Both *CatalogHolder and *Refresher satisfy it.
type catalogSnapshotProvider interface {
	GetCatalog() *Catalog
}

// DispatchOutcome is the result class of planning one dispatch.
type DispatchOutcome int

const (
	// OutcomeRefused — planning refused fail-closed; Reason is set.
	OutcomeRefused DispatchOutcome = iota
	// OutcomePlan — a fresh dispatch; Apply is the request to send.
	OutcomePlan
	// OutcomeAlreadyCurrent — the node already runs the target; no apply.
	OutcomeAlreadyCurrent
)

func (o DispatchOutcome) String() string {
	switch o {
	case OutcomeRefused:
		return "refused"
	case OutcomePlan:
		return "plan"
	case OutcomeAlreadyCurrent:
		return "already_current"
	default:
		return "unknown"
	}
}

// RepoRewrite maps the catalog's repo (From) to the deployment/local-registry
// repo (To) for air-gapped sites. The digest is NEVER rewritten — only the repo
// prefix, and only through this one explicit mapping (design §4).
type RepoRewrite struct {
	From string // catalog repo, e.g. ghcr.io/kidcarmi/culvert
	To   string // deployment repo (== proxy_repo), e.g. registry.local/culvert
}

// DispatchConfig is the CP-side deployment binding: the agent's proxy_repo
// (P1.4) and an optional air-gap repo rewrite.
type DispatchConfig struct {
	ProxyRepo   string
	RepoRewrite *RepoRewrite // nil for connected deployments
}

func (c DispatchConfig) validate() error {
	if err := catalogValidateRepo(c.ProxyRepo); err != nil {
		return fmt.Errorf("dispatch: proxy_repo: %w", err)
	}
	if c.RepoRewrite == nil {
		return nil
	}
	if err := catalogValidateRepo(c.RepoRewrite.From); err != nil {
		return fmt.Errorf("dispatch: repo_rewrite.from: %w", err)
	}
	if err := catalogValidateRepo(c.RepoRewrite.To); err != nil {
		return fmt.Errorf("dispatch: repo_rewrite.to: %w", err)
	}
	if c.RepoRewrite.From == c.RepoRewrite.To {
		return errors.New("dispatch: repo_rewrite.from and .to are identical")
	}
	// The rewrite target IS the deployment repo, so it must equal proxy_repo —
	// otherwise every dispatch would fail repo-mismatch.
	if c.RepoRewrite.To != c.ProxyRepo {
		return fmt.Errorf("dispatch: repo_rewrite.to %q must equal proxy_repo %q", c.RepoRewrite.To, c.ProxyRepo)
	}
	return nil
}

// forward maps a catalog PinnedRef (catalog repo) to the deployment ref. reverse
// maps a running deployment ref back to the catalog repo for Lookup. Both leave
// the @digest byte-for-byte untouched and are no-ops without a configured
// rewrite or when the ref's repo does not equal the mapping side.
func (c DispatchConfig) forward(ref string) string { return rewriteRepo(ref, c.RepoRewrite, false) }
func (c DispatchConfig) reverse(ref string) string { return rewriteRepo(ref, c.RepoRewrite, true) }

func rewriteRepo(ref string, rw *RepoRewrite, reverse bool) string {
	if rw == nil {
		return ref
	}
	repo, at, ok := splitRepoRef(ref)
	if !ok {
		return ref // not a repo@digest ref (e.g. a tag) — never rewritten
	}
	from, to := rw.From, rw.To
	if reverse {
		from, to = rw.To, rw.From
	}
	if repo != from {
		return ref // exact match only — no partial match, no fallback
	}
	return to + at
}

// splitRepoRef splits "repo@sha256:<hex>" into the repo and the "@<digest>"
// suffix. ok is false for any ref without a single repo + digest (a tag-shaped
// ref like "repo:1.2.3" returns ok=false).
func splitRepoRef(ref string) (repo, at string, ok bool) {
	r, digest, found := strings.Cut(ref, "@")
	if !found || r == "" || digest == "" {
		return "", "", false
	}
	return r, "@" + digest, true
}

// DispatchTarget names the release to dispatch: exactly one of ReleaseID or
// Channel.
type DispatchTarget struct {
	ReleaseID string
	Channel   Channel
}

// DispatchOptions are the per-dispatch operator choices. Use
// DefaultDispatchOptions for the standard (pre_backup desired, rollback on).
type DispatchOptions struct {
	PreBackup      bool   // request a pre-restart config backup (needs PassphraseRef — §6 invariant)
	PassphraseRef  string // REQUIRED by the agent iff pre_backup ends up true
	NoRollback     bool   // opt out of rollback_on_failure (default: rollback ON)
	IdempotencyKey string // op identity from higher orchestration; passed through verbatim (may be empty)
}

// DefaultDispatchOptions returns the standard options: pre_backup desired,
// rollback-on-failure on, no idempotency key (orchestration fills it).
func DefaultDispatchOptions() DispatchOptions { return DispatchOptions{PreBackup: true} }

// UpgradeApplyRequest is the CP's view of the agent's existing
// POST /v1/upgrades/apply body. rollback_on_failure has NO omitempty so it is
// always serialized explicitly (design §6). image_ref is the ONLY field derived
// from the release; no release/channel/version data is included.
type UpgradeApplyRequest struct {
	ImageRef          string `json:"image_ref"`
	PreBackup         bool   `json:"pre_backup"`
	PassphraseRef     string `json:"passphrase_ref,omitempty"`
	RollbackOnFailure bool   `json:"rollback_on_failure"`
	IdempotencyKey    string `json:"idempotency_key,omitempty"`
}

// DispatchPlan is the structured result of planning one dispatch op.
type DispatchPlan struct {
	Outcome DispatchOutcome
	Reason  error // non-nil iff Outcome == OutcomeRefused

	ReleaseID string
	VersionID string
	Severity  Severity
	PinnedRef string      // catalog pinned ref (pre-rewrite)
	ImageRef  string      // dispatch image_ref (post-rewrite) — what the agent receives
	Current   CurrentView // what is running now (reverse-mapped); !Known ⇒ unknown/custom

	AlreadyCurrent bool
	Apply          UpgradeApplyRequest // valid iff Outcome == OutcomePlan
	BackupSkipped  bool                // pre_backup requested but no passphrase_ref ⇒ built pre_backup=false (§6)
}

// Refused reports whether planning was refused.
func (p *DispatchPlan) Refused() bool { return p.Outcome == OutcomeRefused }

// Dispatcher plans dispatches against a pinned catalog snapshot. It performs no
// I/O and never contacts the agent (Slice a).
type Dispatcher struct {
	provider catalogSnapshotProvider
	cfg      DispatchConfig
}

// NewDispatcher validates the deployment binding and returns a planner. An
// invalid repo-rewrite mapping is rejected here (fail-closed).
func NewDispatcher(provider catalogSnapshotProvider, cfg DispatchConfig) (*Dispatcher, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Dispatcher{provider: provider, cfg: cfg}, nil
}

// Plan resolves target against the catalog snapshot taken ONCE at entry (pinned
// for the op — the snapshot is immutable, so a concurrent refresh cannot change
// this plan), reconciles repos, derives Current/already-current from running
// (the agent's running_image.repo_digests), and builds the apply request.
// Refusals return a plan with Outcome == OutcomeRefused and a non-nil Reason.
func (d *Dispatcher) Plan(target DispatchTarget, running []string, opts DispatchOptions) *DispatchPlan {
	cat := d.provider.GetCatalog() // single read — pins the snapshot for this op
	if cat == nil {
		return refuse(errDispatchNoCatalog)
	}

	rel, err := d.resolveTarget(cat, target)
	if err != nil {
		return refuse(err)
	}

	// Forward-rewrite the catalog ref to the deployment repo and require repo
	// equality with proxy_repo (the agent's allowlist is the independent backstop).
	imageRef := d.cfg.forward(rel.PinnedRef)
	repo, _, ok := splitRepoRef(imageRef)
	if !ok {
		return refuse(fmt.Errorf("%w %q", errDispatchMalformedRef, rel.PinnedRef))
	}
	if repo != d.cfg.ProxyRepo {
		return refuse(fmt.Errorf("%w: catalog ref repo %q != proxy_repo %q", errDispatchRepoMismatch, repo, d.cfg.ProxyRepo))
	}

	plan := &DispatchPlan{
		ReleaseID:      rel.ReleaseID,
		VersionID:      rel.VersionID,
		Severity:       rel.Severity,
		PinnedRef:      rel.PinnedRef,
		ImageRef:       imageRef,
		Current:        d.detectCurrent(cat, running),
		AlreadyCurrent: containsRef(running, imageRef),
	}
	if plan.AlreadyCurrent {
		plan.Outcome = OutcomeAlreadyCurrent
		return plan
	}
	plan.Outcome = OutcomePlan
	plan.Apply, plan.BackupSkipped = buildApplyRequest(imageRef, opts)
	return plan
}

func refuse(err error) *DispatchPlan {
	return &DispatchPlan{Outcome: OutcomeRefused, Reason: err}
}

func (d *Dispatcher) resolveTarget(cat *Catalog, t DispatchTarget) (ResolvedRelease, error) {
	switch {
	case t.ReleaseID != "" && t.Channel != "":
		return ResolvedRelease{}, errDispatchAmbiguousTarget
	case t.ReleaseID != "":
		rel, ok := cat.byReleaseID[t.ReleaseID]
		if !ok {
			return ResolvedRelease{}, fmt.Errorf("%w %q", errDispatchUnknownTarget, t.ReleaseID)
		}
		return ResolvedRelease{ReleaseID: rel.ReleaseID, VersionID: rel.VersionID, Severity: rel.Severity, PinnedRef: rel.PinnedRef}, nil
	case t.Channel != "":
		return cat.Resolve(t.Channel) // channel-unknown error is descriptive enough
	default:
		return ResolvedRelease{}, errDispatchNoTarget
	}
}

// detectCurrent reverse-rewrites each running repo_digest and looks it up in the
// catalog, returning the first match. It iterates ALL entries (the array may
// hold list + per-arch digests; the deployment path records the list digest —
// B1; the agent itself only reads RepoDigests[0]). Absent/unmatched/tag-shaped
// ⇒ Unknown (a normal state, design §3.1).
func (d *Dispatcher) detectCurrent(cat *Catalog, running []string) CurrentView {
	for _, ref := range running {
		if v := cat.Current(d.cfg.reverse(ref)); v.Known {
			return v
		}
	}
	return CurrentView{Known: false}
}

func buildApplyRequest(imageRef string, opts DispatchOptions) (req UpgradeApplyRequest, backupSkipped bool) {
	req = UpgradeApplyRequest{
		ImageRef:          imageRef,
		RollbackOnFailure: !opts.NoRollback, // default true, ALWAYS explicit
		IdempotencyKey:    opts.IdempotencyKey,
	}
	// pre_backup <-> passphrase_ref is a hard agent invariant (it 400s a
	// mismatch): pre_backup=true only when a passphrase_ref is available, else
	// pre_backup=false with NO ref (§6).
	switch {
	case opts.PreBackup && opts.PassphraseRef != "":
		req.PreBackup = true
		req.PassphraseRef = opts.PassphraseRef
	case opts.PreBackup:
		backupSkipped = true // requested but no ref ⇒ skipped (audited by the caller)
	}
	return req, backupSkipped
}

func containsRef(refs []string, target string) bool {
	for _, r := range refs {
		if r == target {
			return true
		}
	}
	return false
}
