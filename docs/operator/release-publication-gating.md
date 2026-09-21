# Release publication gating

**What this guarantees:** no container image tag that a consumer resolves as
"the release", and no public GitHub Release asset, exists before the required
evidence has succeeded *for that exact source commit*.

---

## 1. The defect this closes

Measured on `ci.yml` run
[35507615339](https://github.com/KidCarmi/Culvert/actions/runs/35507615339)
(SHA `3d8c9bb`):

| time (UTC) | event |
| --- | --- |
| 11:40:09 | `docker` → "Apply version tag": ghcr `latest`, `v0.0.N`, `0.0.N` published |
| 11:40:31 | `docker` → "Sign proxy image": those tags cosign-signed |
| 12:09:14 | `auto-tag` → "Require Security + QA gate approval" **concludes** |
| 12:09:15 | the `v*` tag is created |

The image tags were public and signed for **29 minutes before any verdict
existed**. `auto-tag` waited for the gates; image publication did not, because
the `docker` job's only gate step carried `if: startsWith(github.ref,
'refs/tags/v')` and a main push is not a tag ref.

`latest` is a real delivery channel: `packaging/culvert-maint/install.sh` seeds
a fresh install from `${PROXY_REPO}:latest`. So the window shipped unverified
bytes to new installs.

In the same push, [Install Lifecycle E2E
35507615001](https://github.com/KidCarmi/Culvert/actions/runs/35507615001)
**failed** 25 s in, at "Build, push, capture v1 + v2 proxy digests" — every
Phase 1-4 lifecycle assertion was skipped — and the same SHA was tagged anyway.

Separately, release **assets** were uploaded by `catalog-pipeline` and
`release` into a *live* release, while `verify-reproducible` (independent
rebuild hash-match) and `provenance` (SLSA L3) were still running downstream —
and stayed public if either then failed.

---

## 2. The release predicate

One script, one manifest.

- **`.github/release-evidence.txt`** — the manifest. One row per workflow,
  classified `mandatory` or `advisory`. Its header records why every other
  workflow in the repository is *not applicable*.
- **`.github/scripts/require-release-evidence.sh <sha> <wait|assert>`** — the
  enforcing side. Resolves every row and refuses unless all `mandatory` rows
  have a run for that exact SHA that concluded `success`.
- **`.github/scripts/require-gate.sh`** — resolves one row. Binds the evidence
  to the workflow **file path** (a check-run display name is not a trust
  boundary), `head_sha`, `event=push` and `head_branch == main`.

**Currently mandatory:** `security-release-gate.yml`, `qa-gate.yml`.

**Currently advisory:** `install-lifecycle-e2e.yml`, `maint-agent-update-e2e.yml`,
`catalog-e2e.yml`. Their verdict is resolved and printed to the step summary,
but does not block. Promoting one is a one-word edit on its row — deliberately,
so that turning a ~35-minute e2e into a hard release interlock is an owner
decision made in a reviewable diff.

Everything fails **closed**: failed, cancelled, timed-out, **skipped**,
neutral, still-running, absent, and an unreachable API all refuse. An empty,
malformed or unreadable manifest refuses. Evidence from another SHA, another
workflow, a `workflow_dispatch`, or a tag-triggered re-run of the same SHA
cannot authorize a release.

---

## 3. Before / after

### Before

```
main push ─ test ─ smoke ─ docker ──────────────────────────► latest, vX.Y.Z, X.Y.Z  (PUBLIC, unverified)
                              │                                cosign-signed
                              ├─ catalog-pipeline
                              └─ auto-tag ─ [wait QA+Security] ─ push v* tag

v* tag ─ docker [assert QA+Security] ─ catalog-pipeline ──► LIVE release + catalog  (PUBLIC)
                                            └─ release ──► LIVE release + binaries  (PUBLIC)
                                                  └─ aggregate ─ verify-reproducible ─ provenance
                                                                 (run AFTER the assets are public)
```

### After

```
main push ─ test ─ smoke ─ docker ──► candidate-<run_id>, sha-<short>   (candidate only)
                              │        digest cosign-signed
                              ├─ resolve-candidate  (pass-through on main)
                              │        ↓
                              ├─ catalog-pipeline
                              ├─ promote-image [PREDICATE] ──► latest, main
                              └─ auto-tag      [PREDICATE] ──► push v* tag

v* tag ─ docker ──► candidate-<run_id>
            ↓
     resolve-candidate ──► BINDS candidate-vX.Y.Z → D   (or RECOVERS it)
            ↓                    every job below uses D, never the rebuild
     catalog-pipeline [PREDICATE] ──► DRAFT release + catalog pinning D
            ↓
     release [PREDICATE] ──► DRAFT release + binaries
            ↓
     aggregate-subjects ─ verify-reproducible ─ provenance
            ↓
     promote-release-channels [PREDICATE] ──► vX.Y.Z, X.Y.Z, X.Y, X
            ↓                                  (the first public act of this release)
     publish-release [PREDICATE] ──► draft=false                        (PUBLIC)
```

The tag path's public version channels are now written **after** every required
release check, from a digest a retry cannot change.

---

## 4. Candidate vs. promoted

The `docker` job pushes only non-channel tags:

| tag | role |
| --- | --- |
| `candidate-<run_id>` | the **promotion binding**. Run-scoped, because the main-push run and the tag run share a commit — `auto-tag` pushes the `v*` tag while the main run's `promote-image` is still resolving, so a per-commit binding could be overwritten by the other run's build. |
| `sha-<short>` | the conventional per-commit tag (unchanged). |

`promote-image` then runs `promote-image-tags.sh`, which:

1. rejects a malformed digest;
2. resolves `candidate-<run_id>` in the registry and **refuses unless it is
   exactly the digest this run built** — so the job cannot be handed an
   arbitrary digest to publish;
3. applies the re-run rule (below);
4. promotes with `docker buildx imagetools create --tag … <image>@<digest>` —
   the tested immutable digest, never a rebuild.

### Immutable vs. floating targets

Targets come in two kinds, and **only one of them can be superseded**:

| kind | tags | rule |
| --- | --- | --- |
| **immutable** | the exact version, `X.Y.Z` **and** `vX.Y.Z` | names THIS release and nothing else, so it is never deferred to a newer run — and both aliases move together, from one digest. **Write-once**: promoted when absent or already at this digest, refused when it already points somewhere else. |
| **floating** | `latest`, `main`, `X.Y`, `X` | moving channels naming "the current thing". An older run must never roll them backwards. |

Which path owns which:

| path | immutable | floating |
| --- | --- | --- |
| main push | *(none)* | `latest`, `main` |
| `v*` tag | `X.Y.Z`, `vX.Y.Z` | `X.Y`, `X` |

The **main path promotes no exact version at all**. Two reasons, and both are
load-bearing: its version is speculative until `auto-tag` creates the tag, and
the main and tag runs deliberately build *different digests* — so a main run
promoting `vX.Y.Z` while the tag run promoted `X.Y.Z` left the two aliases of
one version pointing at two different images, with `vX.Y.Z` on a digest that
release's own catalog does not pin. One version, one digest, one owner: the tag
run.

### Serialization

`ci.yml`'s workflow concurrency key includes the ref, so two `v*` tags run at
the same time — and "am I the channel tip?" is a check-then-act. `promote-image`
therefore takes a **ref-independent** job-level lock
(`concurrency: group: release-channel-promotion`, `cancel-in-progress: false`)
and reads the tip **from the remote** inside it (`git fetch --tags --force`),
never from the checkout's snapshot.

The accepted cost is GitHub's queue depth of one: a *third* concurrent promotion
cancels the pending one, which fails the job, skips `publish-release` and leaves
that release a draft. Fail-closed and re-runnable — and strictly better than a
silently rolled-back public channel.

### Write-once, and why

"Always promoted" is not "repointed on every run". **This image build is not
reproducible over time** — the Dockerfile rides a floating `alpine:3.24`, runs
`apk upgrade`, and downloads a GeoIP database whose URL embeds
`$(date +%Y-%m)` — so re-running an already-published tag's workflow produces a
*different digest for the same version*. Repointing `X.Y.Z` at it would serve
different bytes under a released version while that release's published catalog
still pins the old digest.

| state of `X.Y.Z` in the registry | outcome |
| --- | --- |
| **proven** absent | promote |
| already this digest | no-op, success (idempotent re-run) |
| a **different** digest | **refuse** — cut a new version instead |
| registry did not answer | **refuse** — absence was not proven |

The refusal names the remedy: if those bytes must ship, they ship as a new
version, never as a quiet substitution under the old one. This is enforceable
only because the tag run is now the sole writer of the exact aliases.

**Absence must be proven, not inferred from a failed lookup.** `imagetools
inspect` exits 1 for every failure, so reading any nonzero exit as "the tag is
free" makes a transient registry, auth or network fault indistinguishable from
an unused tag — and the very next step would then repoint an already-published
`X.Y.Z` at the rebuild, defeating the whole rule (Codex review, PR #1441).
`resolve_tag_digest` classifies by message against a deliberately **narrow**
not-found allowlist and treats anything unrecognised as ambiguous, because the
two directions are not symmetric: a missed not-found refuses a legitimate first
promotion (loud, and recovered by re-running), while a missed transient failure
silently overwrites a released version. An ambiguous answer is retried a bounded
number of times — a single blip must not discard forty minutes of build and gate
work — and then refuses.

`404 Not Found` counts as absence on evidence rather than assumption: the
candidate-tag probe resolved moments earlier in the *same* repository with the
*same* credentials, so the registry is reachable and this run is authorized.
Without that preceding probe the branch would not be safe.

**…and "absent" is the only state in which an exact tag may be written.** There
is no exception for a still-Draft GitHub Release. A registry tag is public the
instant it is written, so Draft is not a visibility boundary for GHCR, and an
earlier revision of this branch that let a Draft unlock a repoint was wrong.

Retry safety comes from upstream instead — see *One version, one digest* below.
Because a retry promotes the **same** digest, an already-written alias is an
idempotent no-op and the write-once branch is never reached on a legitimate
retry. Reaching it means the exact tag and the candidate binding disagree; that
refuses, names the recovery and **deletes nothing**.

### One version, one digest

`resolve-candidate` runs before anything is published and binds the version to
one candidate digest, recorded as the write-once registry tag
`<image>:candidate-vX.Y.Z`. Every downstream job — catalog generation, `cosign
verify`, both promoters — reads the digest from **there**, never from the build.

| situation | what happens |
| --- | --- |
| first run for this version | binds `candidate-vX.Y.Z` → this run's digest, reads it back to prove the write landed |
| retry after any failure | resolves the existing binding, **discards its own rebuild**, resumes on the bound digest |
| binding names another commit | **refuse** — publishing would ship one commit's bytes under another's tag |
| binding names no commit, or several | **refuse** — provenance that cannot be read cannot drive publication |
| binding unreadable (registry down) | **refuse** — an unreadable binding is not an absent one |
| another run bound it first | **refuse**; the re-run adopts the winner |

The binding is verified through the image's own
`org.opencontainers.image.revision` label, on the **first** run as well as on
retries: if the provenance mechanism is broken, the run that creates the binding
is the cheapest place to find out, because nothing has been published yet.

**No cross-service atomicity is claimed.** GHCR and the GitHub Releases API fail
independently. What the binding buys is that every attempt at a version
converges on one digest, so whatever is left unfinished can be completed without
changing what a released version means.

### Failure and retry states

| failure point | public GHCR state | GitHub Release | retry behaviour |
| --- | --- | --- | --- |
| `docker`, `resolve-candidate` | nothing written (binding may exist) | none/draft | rebuild; adopt the binding if present |
| `catalog-pipeline` | no version channel | draft | regenerate against the **same** bound digest |
| `release`, `aggregate-subjects` | no version channel | draft, partial assets | assets replaced in place |
| `verify-reproducible`, `provenance` | **no version channel** — this is the ordering fix | draft | re-run; still no repoint, because promotion never ran |
| mid-promotion (some aliases written) | some aliases at the bound digest | draft | written aliases are no-ops; missing ones are completed |
| `publish-release` | all aliases at the bound digest | draft | un-draft retried; no alias changes |
| after publication | all aliases | published | the whole run is refused up front |

### A published release is write-once too

Every asset step stages with `draft: true`, and `action-gh-release` applies that
to an **existing** release as well. So a re-run of an already-published `v*`
workflow PATCHes the live release back to draft — and the run cannot put it
back, because the rebuild's digest is refused against the write-once exact tag
above and `publish-release` (which needs `promote-image`) is then skipped. The
release is left stranded: unpublished, with its catalog asset replaced by one
pinning a digest that was rejected (Codex review, PR #1441).

`.github/scripts/assert-release-unpublished.sh` therefore runs as the first step
of every job that stages an asset — `catalog-pipeline` and `release` — *before*
the first mutation:

| release for this tag | outcome |
| --- | --- |
| absent | proceed (first run) |
| `draft: true` | proceed — exactly the recoverable re-run draft staging exists for |
| `draft: false` | **refuse**, nothing mutated; the public release keeps its state and assets |
| API did not answer | **refuse** — same rule as above: a failed lookup is not proof of absence |

A published release is finished; a re-run has nothing to add to it. If its bytes
must change, that is a new version. The catalog **re-sign** dispatch is the one
sanctioned mutation of a published release and is deliberately not guarded: it
skips `docker` and therefore the whole staging chain, and uses `gh release
upload`, which does not touch draft state.

### Re-run rule

| situation | immutable (`X.Y.Z`) | floating (`latest`, `X.Y`, `X`) |
| --- | --- | --- |
| release SHA **is** the channel tip | promote (idempotent on re-run) | promote |
| release SHA is an **ancestor** of the tip | **promote** — a version tag cannot be superseded | **skip**, exit 0 — a newer run owns them. Normal on a busy `main`, where the next merge lands during this run's build+gate window. |
| anything else (divergent, force-push) | **refuse**, exit 1 | **refuse**, exit 1 |

Channel tip = `origin/main`'s head on the main path; on the tag path it is the
highest `v*` tag's **name**, not just its commit. Two version tags can name the
same commit (a re-tag, or a second tag cut on an already-tagged commit), and a
SHA-only comparison then lets the *lower* tag believe it owns the channels and
roll `X.Y`/`X` back to itself. The commit comparison remains the main path's
rule and the tag path's fallback for telling superseded from divergent.

> **Why the split exists.** The first shipped shape gated ONE target list on
> supersession, so a tag run overtaken by a newer tag skipped *everything* —
> including its own `X.Y.Z` — while `publish-release` still undrafted the
> release. The result was a public release whose exact version tag was absent,
> or pointed at the main run's digest rather than the one its own catalog pins
> (Codex review, PR #1441).

---

## 5. Signing identity — the constraint, resolved

Cosign keyless SANs are
`https://github.com/KidCarmi/Culvert/.github/workflows/<file>@<ref>` — per
workflow **file** and ref, **not** per job. `promote-image` and
`publish-release` live inside `ci.yml`, so their certificates carry the
identity already pinned in `release_identity.env`, in the baked constants in
`release_catalog_sigstore.go`, and by `TestReleaseIdentitySSOT` /
`TestInstallScriptPinsSameReleaseIdentity`. Nothing about the pinned issuer or
SAN regex changes.

**Do not move promotion or publication into a separate workflow file** — that
would change the SAN and break every one of those pins.

Cosign signatures are also **digest-scoped**: `cosign sign <ref>@<digest>`
stores the signature at `sha256-<hex>.sig`, so the `docker` job's signature of
the candidate reference already verifies for every tag later pointed at the
same digest, and `catalog-pipeline`'s digest-addressed
`cosign verify ghcr.io/kidcarmi/culvert@<digest>` is unaffected.
`promote-image` signs the promoted references *in addition*, so the signed
`docker-reference` claim also names the public channel.

---

## 6. Release assets

Every `softprops/action-gh-release` step now passes `draft: true`.
`publish-release` is the only job that runs `gh release edit --draft=false`,
and it needs `release`, `catalog-pipeline`, `promote-image`,
`aggregate-subjects`, `verify-reproducible` and `provenance`.

**The "Latest" designation is GitHub's to decide, not this job's.** It is
load-bearing — `scripts/install.sh` resolves its bootstrap verifier through
`/releases/latest` — so an unconditional `gh release edit --latest` pointed fresh
installs at an older verifier whenever a superseded tag's run finished after a
newer release, or when an old tag's workflow was re-run.

Comparing against `git tag` does not fix it, even refreshed: that is a
check-then-act, and a tag created between the read and the edit still wins.
`publish-release` instead clears the draft through the releases API with
**`make_latest: legacy`**, so the decision happens *inside the same atomic call*
and GitHub arbitrates it from the full set of releases by semantic version and
creation date. There is no window in which this run can observe stale state, and
no cross-tag lock is needed.

Do not replace this with `--latest` or `--latest=false` — both assert an answer
this job cannot compute without a race.

Before un-drafting it runs `assert-release-complete.sh`, which refuses unless
every required asset is present **and non-empty**: 5 proxy binaries + 2
`culvert-maint` binaries with their `.sigstore.json` bundles, 2 signed SBOMs,
the signed catalog bundle, and the SLSA provenance `*.intoto.jsonl`. A green
needs-chain proves every job returned zero; this proves the artifacts landed.

---

## 6b. The catalog re-sign path (declared exemption)

`catalog-resign` republishes an **already-released** bundle with a fresh
`generated_at`/`expires_at` and nothing else changed. It is deliberately
**exempt** from the workflow-run predicate, and the exemption is declared and
asserted in `release_publication_gating_test.go` rather than left implicit.

Requiring the predicate here would be strictly worse: a re-signed tag can be
months old and its QA/Security runs age out of the Actions retention window, so
`require-gate.sh` would refuse forever and the 180-day freshness mechanism
would die.

Its requirement is **cryptographic instead of procedural**, and the test pins
each substitute control:

- `TestReleaseResignGate` verifies the source bundle through the baked Sigstore
  root and the pinned identity **before any field is read** (SEC-F1);
- the dispatch ref must be the highest `vX.Y.Z` tag (SEC-F2a) — pinned on the
  step's mechanism, not its display name;
- a bare tag dispatch (no `resign=true`) is refused by `resign-dispatch-guard`,
  and `docker` skips on a tag dispatch, so the whole build/release chain is
  unreachable from that path;
- it attaches a **new versioned** asset and never replaces the original;
- the test additionally refuses to let this job ever run `imagetools create` or
  `--draft=false`.

---

## 7. Operator runbook

**"Release evidence predicate REFUSED"** — open the step summary. It prints a
table of every row and its verdict. The refusing row names a workflow; fix that
workflow's failure on the **main push** for that SHA and re-run the CI run. A
row reading "skipped" means the workflow did not actually execute; that is not
approval and never will be.

**A release is stuck as a draft** — the chain failed after staging. Find the
failed job (`verify-reproducible` and `provenance` are the usual ones), fix it,
and re-run. The draft is re-used; assets are replaced in place. Nothing is
public until `publish-release` succeeds. Do **not** flip the draft by hand
unless you have independently verified reproducibility and provenance.

**`promote-image` reported "superseded by channel tip"** — expected. Another
commit landed on `main`, or a newer `v*` tag was created, during this run. On
the main path nothing is promoted (its version was speculative); on the tag path
the exact `X.Y.Z` is still promoted and only the moving channels defer. No
action.

**A release published without being marked "Latest"** — expected when a higher
`v*` tag already exists. GitHub decides this, not the workflow; the release is
public and complete, and only the Latest pointer stays with the newer tag. The
step summary prints which tag GitHub resolved Latest to.

**`promote-image` refused: "is ALREADY PUBLISHED at … and this run built …"** —
you re-ran a tag whose image was already promoted, and the rebuild produced
different bytes (expected; the build is not reproducible over time). The
published version keeps its original digest. If the new bytes must ship, cut a
new version. Do not delete the tag to force it through. On a normal retry this refusal
should be unreachable, because the candidate binding makes the retry promote the
same digest. Reaching it means the exact tag and `<image>:candidate-vX.Y.Z`
disagree — compare them and have an owner decide.

**`resolve-candidate` said "recovering that candidate"** — expected on any
retry. The version was already bound to a digest, so this run's rebuild is
discarded and everything downstream resumes on the bound bytes. This is what
makes a retry safe.

**`resolve-candidate` refused: "was built from … not …"** — the candidate bound
to this version came from a different commit. Nothing is deleted automatically.
An owner decides: remove `<image>:candidate-vX.Y.Z` to rebind, or cut a new
version.

**`promote-image` refused: "could not determine whether … already exists"** —
the registry did not answer the existence question (after a bounded retry). It
is refusing because an ambiguous answer is not proof the tag is free, not
because the tag is taken. Nothing was written. Confirm ghcr.io is reachable and
re-run the run; the release is still a draft, so the re-run is clean.

**"the release for vX.Y.Z is ALREADY PUBLISHED"** — you re-ran the full workflow
for a tag that is already released. The run refused before touching anything;
the public release, its assets and its Latest pointer are untouched. There is
nothing a re-run can add to a published release. If its bytes must change, cut a
new version. To refresh only the catalog's freshness window, use the catalog
re-sign dispatch, which does not re-stage assets.

**`promote-image` queued for a long time, or cancelled** — it holds a
repository-wide promotion lock so two tag releases cannot move the same channels
at once. A cancellation means three promotions were in flight; the release stays
a draft. Re-run that tag's workflow.

**`promote-image` refused with "divergent history"** — `main` was force-pushed,
or the run is from a branch that is no longer an ancestor. Investigate before
re-running; do not promote by hand.

**Making an advisory check mandatory** — edit its row in
`.github/release-evidence.txt` from `advisory` to `mandatory`. That is the
whole change; `release_publication_gating_test.go` and
`.github/scripts/test/release-gating-cases.sh` prove the mechanism.

---

## 7b. Catalog origin: R2 only

GitHub Pages has been retired as a catalog origin. `publish-catalog-r2.yml`
publishes to `https://catalog.culvertlabs.com`, and
`verify-catalog-publish.yml` (formerly `verify-dual-publish.yml`) proves that
origin serves the release's signed bytes.

**Nothing about trust changed, and that is why the removal is safe.** The
catalog's integrity comes from its keyless Sigstore signature, verified
in-binary against the baked trusted root and the pinned `ci.yml` identity. The
host was always untrusted transport, so a second host of the same bytes added no
trust — only a divergence surface, a second freshness obligation and a second
thing to keep alive. The verify workflow still performs every check it used to
perform per origin: content match against the release bundle, a baked-root
served verify that must PASS (a skip is not a pass), availability convergence,
and the weekly SEC-F5 freshness canary.

**Migration impact.** The baked default client URL
(`defaultReleaseCatalogURL`, `release_wiring.go`) is already the R2 origin, and
no Go, installer or packaging code references `kidcarmi.github.io` — so **no
shipped client defaults to Pages**. The one affected case is an operator who
explicitly set `CULVERT_RELEASE_CATALOG_URL` to the Pages URL; they must repoint
it at `https://catalog.culvertlabs.com/release-catalog`. Because the appliance
verifies the signature regardless of origin, that repoint is a configuration
change, not a trust change.

**A dormant publisher is no longer safe.** While Pages also served the catalog,
`vars.R2_PUBLISH_ENABLED` being unset was a harmless no-op. Now it means nothing
is published at all. `publish-catalog-r2.yml` therefore runs
`assert-publication-target` first, which FAILS when the variable is not `true`,
so the state is loud. It fails rather than warns because the publisher is
downstream of the release: a red run is an operator signal and blocks nothing.

**Remaining settings-level cleanup (owner action, NOT done here).** This patch
changes repository *content* only. To fully retire Pages an owner must, in
repository Settings → Pages, unpublish/disable the site (the last deployment
keeps serving until then) and, if a custom domain or DNS record points at it,
remove that. This session cannot read or change repository settings, so none of
that is verified here.

**Not verified from this environment.** `vars.R2_PUBLISH_ENABLED` is a
repository variable that cannot be read from a workflow-less context, and this
environment's network policy blocks both `catalog.culvertlabs.com` and
`kidcarmi.github.io` (403 at the proxy CONNECT), so neither origin's live state
was observed. The `assert-publication-target` job exists precisely because that
precondition could not be confirmed ahead of time: it converts an unverifiable
assumption into a CI-visible failure.

---

## 8. Not covered by this slice

- **The main-run digest and the tag-run digest differ.** The tag run rebuilds
  the image (embedded provenance attestations carry the run ID), so the digest
  the release catalog pins is not the digest the main run promoted as `latest`.
  The exact version tags are no longer affected — both aliases now come from the
  tag run — but `latest` still tracks the main build while `X.Y.Z` tracks the tag
  build. Both digests are evidence-gated and both are signed, so nothing
  unverified ships; the two channels are simply not byte-identical. Unifying them
  (promote the main run's digest and have the tag run verify rather than rebuild)
  is a separate slice.
- **Branch protection and repository rulesets were not inspected** — this
  session has no permission to read them. Every statement here is about
  in-repository workflow code. The `v*` tag ruleset (F3) and the
  `RELEASE_TAG_PAT` bypass actor remain the only controls against an
  attacker-supplied tagged tree, exactly as `require-gate.sh`'s
  THREAT-MODEL LIMIT note already records.
- **`publish-feeds.yml` / `resign-feeds.yml`** are a separate publication
  surface (threat/category feeds, not release artifacts) with their own gating,
  pinned by `feeds_publish_workflow_test.go`. Untouched.
