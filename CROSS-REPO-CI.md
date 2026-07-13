# Cross-Repository CI (Phase 6)

**Principle:** each repository's *normal* build and test is **fully self-contained
and has no network dependency on any other repository.** Culvert builds without
tac-platform or tac-infrastructure present; tac-platform builds without Culvert;
tac-infrastructure validates without pulling either at build time. Cross-repo
compatibility is proven on a **separate, scheduled/release-time lane** that is
never on the critical path of a routine commit.

---

## 1. Per-repo CI (independent, no cross-repo network dependency)

| Repo | Normal CI gate | Cross-repo dependency at build time |
|---|---|---|
| **Culvert** | existing Fast/Deep PR gates (`go build ./...`, `-race` tests, lint, gosec, govulncheck, gitleaks). tac-platform is a **nested module excluded from `./...`**, so its presence or absence cannot affect the appliance build. | **none** |
| **tac-platform** | `.github/workflows/ci.yml`: `go vet`, `go build ./...`, `go test -race -count=1 ./...` against a `postgres:16` service (per-schema isolation ⇒ **no `-p 1`**). | **none** |
| **tac-infrastructure** | `.github/workflows/ci.yml`: `tofu fmt -check`, `init -backend=false`, `validate`, plus the `no-mutable-tags` guard. | **none at validate time** (digests are pinned data, not a live fetch) |

Removing the nested `tac-platform/` and `tac-infra/` directories from Culvert (Phase 7)
therefore cannot change Culvert's CI result — they were never compiled or tested
by it.

---

## 2. Contract artifact publication

Each contract owner (see `CONTRACTS-OWNERSHIP.md`) publishes its **versioned**
schema as a build artifact from its own CI:

- **Culvert** publishes `csb/<N>` JSON Schema and the identity-document schema.
- **tac-platform** publishes the upload-API OpenAPI, the error-code enum, and the
  deployed-artifact provenance schema.

Publication is **versioned by directory** and immutable per version. Consumers
**vendor a pinned copy** of the version they support — they never fetch a live
schema from another repo during a normal build.

---

## 3. Compatibility CI (scheduled / release-time only)

A dedicated lane — run on a schedule (e.g. nightly) and at release tagging, **not**
on every PR — proves the pinned contract versions still agree:

1. **Bundle ⇄ upload-API compatibility.** tac-platform's cloud extractor is run
   against a golden `csb/<N>` fixture produced from Culvert's schema; a
   `csb` version the server no longer accepts fails the lane (signal to open a
   coordinated version bump, never to break either normal build).
2. **Provenance ⇄ infra compatibility.** tac-infrastructure validates its pinned
   `release-pin.auto.tfvars` against tac-platform's published provenance schema
   and asserts every referenced image is a **digest**, never a tag.
3. **Error-code drift.** Culvert's client-side error-class mapping is checked
   against tac-platform's published error enum (unknown codes must fall into a
   defined range class).
4. **Protocol negotiation overlap.** The union of advertised capabilities is
   checked for a non-empty intersection across the pinned versions.

Each check reads **pinned, vendored copies** — the lane clones the other repos
read-only at a pinned ref; it does **not** wire live inter-repo calls into any
product build.

---

## 4. Image digest publication (platform → infrastructure)

- tac-platform's release CI builds the analysis-worker image and publishes it
  **by digest** (`sha256:…`) together with release version, source commit, and
  an SBOM/provenance reference.
- tac-infrastructure consumes that tuple as **data** in
  `environments/<env>/release-pin.auto.tfvars` and surfaces it via the
  `deployed_provenance` output. `tofu validate` needs no network; the digest is a
  pinned string. Deployment (out of scope here — no cloud is touched) would pull
  the digest, never a tag.

---

## 5. What stays independent (non-negotiable)

- **Appliance builds alone.** Culvert's green build never depends on tac-platform
  or tac-infrastructure being reachable, present, or green.
- **No AI/model in any mutation path.** Compatibility CI reads and asserts; it
  never applies infrastructure and never connects a model to a mutation tool.
- **No PRs opened across repos automatically.** A compatibility failure is a
  human signal to coordinate a versioned change, not an automated cross-repo push.
