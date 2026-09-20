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
main push ─ test ─ smoke ─ docker ──────────────────────────► candidate-<run_id>, sha-<short>  (candidate only)
                              │                                digest cosign-signed
                              ├─ catalog-pipeline
                              ├─ promote-image [PREDICATE] ──► latest, main, vX.Y.Z, X.Y.Z
                              └─ auto-tag      [PREDICATE] ──► push v* tag

v* tag ─ docker [PREDICATE] ─ catalog-pipeline [PREDICATE] ─► DRAFT release + catalog
                │                    ├─ promote-image [PREDICATE] ─► X.Y.Z, X.Y, X
                └───────────────────►└─ release [PREDICATE] ─────► DRAFT release + binaries
                                            └─ aggregate ─ verify-reproducible ─ provenance
                                                  └─ publish-release [PREDICATE] ─► draft=false  (PUBLIC)
```

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
| **immutable** | the exact version, `X.Y.Z` | names THIS release and nothing else. Promoting it is never a rollback, so it is **always** promoted. |
| **floating** | `latest`, `main`, `X.Y`, `X` | moving channels naming "the current thing". An older run must never roll them backwards. |

The **main path declares no immutable targets**: the version it computes is
speculative until `auto-tag` creates the tag, so a superseded main run promotes
nothing. The tag run is what makes `X.Y.Z` authoritative.

### Re-run rule

| situation | immutable (`X.Y.Z`) | floating (`latest`, `X.Y`, `X`) |
| --- | --- | --- |
| release SHA **is** the channel tip | promote (idempotent on re-run) | promote |
| release SHA is an **ancestor** of the tip | **promote** — a version tag cannot be superseded | **skip**, exit 0 — a newer run owns them. Normal on a busy `main`, where the next merge lands during this run's build+gate window. |
| anything else (divergent, force-push) | **refuse**, exit 1 | **refuse**, exit 1 |

Channel tip = `origin/main`'s head on the main path, the highest `v*` tag's
commit on the tag path.

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

**`--latest` is decided, never asserted.** GitHub's "Latest" designation is
load-bearing — `scripts/install.sh` resolves its bootstrap verifier through
`/releases/latest` — so `publish-release` compares the tag against the highest
`v*` tag and passes `--latest` only when it wins, and an explicit
`--latest=false` otherwise. An unconditional `--latest` pointed fresh installs
at an older verifier whenever a superseded tag's run finished after a newer
release, or when an old tag's workflow was re-run (Codex review, PR #1441).

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
`v*` tag already exists. The release is public and complete; only the Latest
pointer stays with the newer tag.

**`promote-image` refused with "divergent history"** — `main` was force-pushed,
or the run is from a branch that is no longer an ancestor. Investigate before
re-running; do not promote by hand.

**Making an advisory check mandatory** — edit its row in
`.github/release-evidence.txt` from `advisory` to `mandatory`. That is the
whole change; `release_publication_gating_test.go` and
`.github/scripts/test/release-gating-cases.sh` prove the mechanism.

---

## 8. Not covered by this slice

- **The main-run digest and the tag-run digest differ.** The tag run rebuilds
  the image (embedded provenance attestations carry the run ID), so the digest
  the release catalog pins is not the digest the main run promoted as `latest`,
  and the tag run repoints `X.Y.Z` onto its own rebuild. Both digests are
  evidence-gated and both are signed, so nothing unverified ships — but the two
  channels are not byte-identical. Unifying them (promote the main run's digest
  and have the tag run verify rather than rebuild) is a separate slice.
- **Branch protection and repository rulesets were not inspected** — this
  session has no permission to read them. Every statement here is about
  in-repository workflow code. The `v*` tag ruleset (F3) and the
  `RELEASE_TAG_PAT` bypass actor remain the only controls against an
  attacker-supplied tagged tree, exactly as `require-gate.sh`'s
  THREAT-MODEL LIMIT note already records.
- **`publish-feeds.yml` / `resign-feeds.yml`** are a separate publication
  surface (threat/category feeds, not release artifacts) with their own gating,
  pinned by `feeds_publish_workflow_test.go`. Untouched.
