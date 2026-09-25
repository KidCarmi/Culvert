# Changelog

All notable changes to Culvert are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the API contract
version is `info.version` in `api/openapi/openapi.yaml` and follows
`docs/api/API-VERSIONING-POLICY.md`.

## [Unreleased]

### Security

- **A request header could name a root-executed artifact (SEC-BOOTSTRAP-HOST-1).**
  The Control Plane's one-click DP bootstrap renders two artifacts a human is
  told to run with root authority — the install script it documents as
  `curl -fsSL … | sudo bash`, and the `docker-compose.yml` that script
  downloads. Two of the values interpolated into them came straight off the
  wire (`r.Host`, and `X-Forwarded-Host` when `proxy.trust_forwarded_headers`
  is on), and the script carried them inside a **double-quoted** shell word:
  `CP_BASE="{{.CPBase}}"`. A double-quoted shell word still performs command
  substitution, so a request whose Host header was `cp.example.com$(…)`
  produced a script that ran the attacker's command, as root, before it did
  anything else. Go's header validation is not a mitigation — measured against
  `net/http`, it rejects `"`, a backtick, `{` and space but accepts
  `$ ( ) ' ;`, and `X-Forwarded-Host` is filtered not at all.

  Both bootstrap endpoints and `POST /api/cluster/token` now **refuse** a
  derived authority that is not a plain `host[:port]` (400, nothing rendered),
  the renderers re-validate at the sink, and the templates single-quote what
  they interpolate. A compose document is also refused (503) when the cluster
  CA has no fingerprint to pin, rather than served with an unpinned enrollment
  URL. Refusals are counted on `culvert_bootstrap_host_refused_total` and
  logged once a minute; the caller is told only `invalid host`. Operators
  behind a reverse proxy should confirm it sets `Host` / `X-Forwarded-Host`
  explicitly rather than appending a client value — see
  `docs/operator/dp-bootstrap-artifact-safety.md`.

- Public release promotion ran ahead of the evidence that was supposed to
  authorize it. On `ci.yml` run 35507615339 (SHA `3d8c9bb`) the `docker` job
  published and cosign-signed the `latest`, `v0.0.N` and `0.0.N` image tags at
  11:40:09Z, while the Security and QA verdict for that same commit only
  concluded at 12:09:14Z — 29 minutes of publicly pullable, unverified bytes on
  a channel `packaging/culvert-maint/install.sh` seeds fresh installs from. The
  cause was one predicate written out by hand in four places and omitted from
  the fifth: `docker`'s gate step carried
  `if: startsWith(github.ref, 'refs/tags/v')`, and a main push is not a tag
  ref. In the same push Install Lifecycle E2E failed before reaching any
  lifecycle assertion and the SHA was tagged regardless. Release *assets* had
  the same shape on the tag path: `catalog-pipeline` and `release` uploaded
  into a live release while `verify-reproducible` and SLSA `provenance` were
  still running downstream, and the assets stayed public if either then failed.

  The predicate is now one script over one manifest
  (`.github/scripts/require-release-evidence.sh` +
  `.github/release-evidence.txt`), every publishing job calls it, and each row
  is explicitly classified mandatory or advisory with the not-applicable
  workflows and their reasons recorded in the manifest header. `docker` pushes
  only non-channel candidate tags (`candidate-<run_id>`, `sha-<short>`); a new
  evidence-gated `promote-image` job moves `latest`/semver onto that exact
  tested digest via `imagetools create`, after proving the candidate tag
  resolves to the digest this run built and after a re-run rule that skips a
  superseded run and refuses a divergent one. Every release asset is staged
  `draft: true`, and a new `publish-release` job — needing `release`,
  `catalog-pipeline`, `aggregate-subjects`, `verify-reproducible` and
  `provenance` — is the only place `--draft=false` runs, after
  `assert-release-complete.sh` proves every required binary, signature bundle,
  SBOM, the signed catalog and the SLSA provenance are present and non-empty.
  `require-gate.sh` now treats a `skipped` or `neutral` gate conclusion as an
  immediate refusal rather than letting `wait` mode poll for 30 minutes first.
  A `workflow_dispatch` on a branch no longer republishes `latest` at all.

  Two review rounds on the gating change itself, both real and both fixed:
  promotion targets are now split into IMMUTABLE (the exact `X.Y.Z`, always
  promoted — a version tag cannot be superseded) and FLOATING (`latest`,
  `main`, `X.Y`, `X`, deferred to the newer run), because a single
  supersession-gated list meant a tag run overtaken by a newer tag skipped its
  OWN version tag while `publish-release` still undrafted the release; and
  `--latest` is now decided against the highest `v*` tag rather than asserted,
  because `scripts/install.sh` resolves its bootstrap verifier through
  `/releases/latest` and an unconditional flag moved fresh installs onto an
  older verifier whenever a superseded tag's run finished last.

  A third round found three more, all in the same family and all fixed: the
  exact version aliases split across paths (the main run promoted `vX.Y.Z` and
  the tag run `X.Y.Z`, from deliberately different digests, so one version named
  two images and `vX.Y.Z` sat on a digest its own catalog did not pin) — exact
  aliases now belong to the tag run alone and move together; image promotion
  read the channel tip from a checkout snapshot and took no cross-ref lock,
  while ci.yml's concurrency key includes the ref, so an older tag run could
  roll `X.Y`/`X` back — promotion now holds a ref-independent job lock and
  refreshes tags from the remote inside it; and the `--latest` comparison was
  itself a check-then-act, so the un-draft now goes through the releases API
  with `make_latest: legacy` and GitHub arbitrates Latest atomically, which
  removes the race rather than narrowing it.

  A fourth round closed the last two. An exact version tag is now WRITE-ONCE:
  this image build is not reproducible over time (floating `alpine:3.24`, `apk
  upgrade`, and a GeoIP URL embedding `$(date +%Y-%m)`), so re-running a
  published tag's workflow builds different bytes, and repointing `X.Y.Z` at
  them would serve a released version content its own published catalog does
  not pin — promotion now refuses unless the tag is absent or already at this
  digest, and says to cut a new version instead. And channel ownership on the
  tag path compares TAG IDENTITY, not just the commit: two version tags can
  name the same commit, which let the lower one believe it owned `X.Y`/`X` and
  roll them back to itself.

  A fifth round closed two write-once holes that the fourth round's rule had
  opened rather than closed. Absence of an exact tag must be PROVEN, not
  inferred: `imagetools inspect` exits 1 for every failure, so reading any
  nonzero exit as "the tag is free" made a transient registry, auth or network
  fault indistinguishable from an unused tag, and the next step would repoint an
  already-published `X.Y.Z` at the rebuild — the exact overwrite the rule
  exists to prevent. Classification is now by message against a deliberately
  narrow not-found allowlist, anything unrecognised is ambiguous and refuses
  after a bounded retry, and the asymmetry is the argument: a missed not-found
  refuses a legitimate first promotion loudly and is recovered by re-running,
  while a missed transient failure silently overwrites a released version. And
  a PUBLISHED release is write-once too — every asset step stages with
  `draft: true`, which `action-gh-release` applies to an existing release as
  well, so a re-run of an already-published tag PATCHed the live release back
  to draft and could not put it back (the rebuild's digest is refused against
  the write-once exact tag, so `publish-release` is skipped), stranding a
  public release unpublished with a catalog asset pinning a rejected digest.
  `assert-release-unpublished.sh` now runs as the first step of every staging
  job and refuses before the first mutation, leaving the public release and its
  assets untouched; the catalog re-sign dispatch is the one sanctioned mutation
  of a published release and is deliberately unguarded, since it skips the
  whole staging chain and uses `gh release upload`, which does not touch draft
  state.

  A sixth round closed the deadlock the fifth had left. Write-once protects
  what a RELEASED version means, and the fifth round had no way to tell a
  released version from an unfinished publication — so a first tag run that
  promoted `X.Y.Z` and then lost `verify-reproducible` or `provenance` WEDGED
  PERMANENTLY: the release stayed a draft, the full re-run was allowed (nothing
  had been published), the rebuild produced a different digest because this
  build is not reproducible over time, write-once refused it, `publish-release`
  was skipped for want of promotion, and the only escape was deleting a public
  image tag by hand — which the runbook forbids. Both guards now key on ONE
  fact from ONE query: `catalog-pipeline` resolves the release's draft state
  before anything is mutated and exports it, `promote-image` consumes it, and a
  still-DRAFT release lets its exact tag be repointed to finish the publication
  while published, absent, unreadable and unset all still refuse. Exporting it
  rather than re-querying also keeps `promote-image` on `contents: read` —
  GitHub shows a draft release only to a token with push access.

  An OWNER CORRECTION reversed the sixth round and closed the ordering defect
  underneath it. The draft-state exception was wrong on its premise: a GHCR tag
  is public the instant it is written, so a GitHub Release's Draft flag is not a
  visibility boundary for the registry, and letting a Draft license a repoint
  weakened exactly the immutability it was guarding. It is removed — an exact
  version tag is write-once with no exception. The ordering defect that made an
  exception look necessary is fixed at the same time: `promote-image` depended
  only on `docker` and `catalog-pipeline`, so public version tags appeared while
  `verify-reproducible` and `provenance` were still running, and stayed public
  if either then failed. Promotion is now SPLIT — `promote-image` moves only
  `latest`/`main` on the main push, and a new `promote-release-channels` writes
  `vX.Y.Z`/`X.Y.Z`/`X.Y`/`X` only after every required release check has
  succeeded, so a reproducibility or provenance failure promotes nothing.

  Retry safety is bought properly instead of by exception. `resolve-candidate`
  binds each version to ONE candidate digest before anything is published —
  recorded as the write-once registry tag `candidate-vX.Y.Z`, read back to prove
  the write landed, and verified against this commit through the image's own
  `org.opencontainers.image.revision` label on the first run as well as on
  retries. Every downstream job (catalog generation, `cosign verify`, both
  promoters) reads the digest from the binding, never from the build, so a retry
  DISCARDS its own rebuild and resumes: aliases already written are idempotent
  no-ops, missing ones are completed, and no public version tag ever changes
  digest. Missing, unreadable, multi-valued or wrong-commit bindings all refuse
  with a named recovery, and nothing is ever deleted or overwritten
  automatically. No cross-service atomicity is claimed — GHCR and the Releases
  API fail independently; what the binding guarantees is that every attempt at a
  version converges on one digest, so partial publication is completed rather
  than re-decided.

  The binding is also the reference promotion is VERIFIED against, and getting
  that wrong defeated the whole mechanism: `promote-image-tags.sh` refuses a
  digest no candidate tag resolves to, and the tag path was handing it the
  run-scoped `candidate-<run_id>`. A re-run keeps its run id and force-pushes
  non-reproducible new bytes over that tag, so the promoter compared the bound
  digest against the rebuild and refused EVERY retry — the resume path dead on
  exactly the occasion it exists for. `resolve-candidate` now emits
  `candidate_tag` (the version binding on a tag, the run-scoped tag on main) and
  both promoters read it from there; the name is never re-derived at a call
  site, so the binding and the reference checked against it cannot drift apart.

  Pinned by `release_publication_gating_test.go` (16 structural walls over
  `ci.yml` and the manifest, each verified failing against the pre-fix tree)
  and `.github/scripts/test/release-gating-cases.sh` (65 behavioural cases
  against mocked `gh`/`docker`/`git` — no registry, no release, no Sigstore).
  Signing identities are unchanged: cosign keyless SANs are per workflow FILE
  and ref, and both new jobs live in `ci.yml`. See
  `docs/operator/release-publication-gating.md`.

- Release staging is DRAFT-AWARE end to end. `GET /releases/tags/{tag}` does not
  return drafts, and the #1441 staging design puts every asset on one, so every
  reader in the chain was blind to the release it was reasoning about. On
  v1.0.234 the SLSA generator's uploader (`action-gh-release@v2.2.1`, by-tag)
  404'd on the draft and CREATED A SECOND, PUBLISHED release carrying only the
  attestation; it became the repository's Latest, `assert-release-complete.sh`
  read it, reported 19 assets missing and refused, and `scripts/install.sh` —
  which resolves its bootstrap verifier through `/releases/latest` — broke for
  fresh installs. The generator now runs with `upload-assets: false` and a new
  `attach-provenance` job stages the attestation on the draft with the v3.0.2
  action (which enumerates releases and can see a draft); every other reader
  resolves the staged release by id through `resolve_staged_release_id`
  (`.github/scripts/lib/release.sh`), which prefers the draft, warns when a
  stray published release shares the tag, and refuses on ambiguity. The one
  legitimate by-tag lookup, `assert-release-unpublished.sh`, is allowlisted with
  its reason. Walled by `TestPublicationGating_NoDraftBlindReleaseLookup` plus 8
  behavioural cases including the exact v1.0.234 shape; both verified failing
  against the defect.

- GitHub Pages is retired as a release-catalog origin; Cloudflare R2
  (`https://catalog.culvertlabs.com`) is the sole publication target.
  `publish-catalog-pages.yml` is deleted, `verify-dual-publish.yml` becomes the
  R2-only `verify-catalog-publish.yml`, the weekly re-sign scheduler no longer
  dispatches a Pages publisher, and no workflow may grant `pages: write` or name
  `kidcarmi.github.io` (pinned structurally by `TestCatalogOriginIsR2Only`).

  **The trust contract is unchanged, which is exactly why the second origin was
  removable.** Catalog integrity comes from the keyless Sigstore signature
  verified IN-BINARY against the baked trusted root and the pinned `ci.yml`
  identity — never from the host. A second host of the same bytes therefore
  bought no trust while costing a divergence surface, a second freshness
  obligation and a second thing to keep serving. The verify workflow still
  applies every check it previously applied per origin: content match against
  the release's signed bundle, a baked-root served verify that must PASS (a skip
  is not a pass), availability convergence, and the weekly SEC-F5 freshness
  canary.

  **Migration impact:** the baked default client URL
  (`defaultReleaseCatalogURL`) was already the R2 origin and no Go, installer or
  packaging code references the Pages host, so no shipped client defaulted to
  Pages. Only an operator who explicitly set `CULVERT_RELEASE_CATALOG_URL` to
  the Pages URL is affected, and must repoint it. **A dormant publisher stops
  being safe** once R2 is the only target — `vars.R2_PUBLISH_ENABLED` being
  unset used to be a harmless skip and now means nothing is published at all —
  so `publish-catalog-r2.yml` gains an `assert-publication-target` job that
  FAILS in that state rather than skipping green. Disabling the Pages site
  itself is a repository-settings action an owner must still take; this change
  touches repository content only.

- OCSP revocation checking accepted responses it should have refused
  (CHAOS-65). Every input the checker acts on comes from the peer's own
  certificate — the responder URLs live in its AIA extension — so the party
  being checked chooses which responder is asked and therefore what comes
  back. `ParseResponse` was called with a nil certificate, which takes the
  first status in the response and never compares the serial, so a genuine
  CA-signed "good" about any *other* certificate of the same issuer was
  accepted as this one's verdict: a revoked certificate went through, with no
  network position required. Alongside it, `ThisUpdate`/`NextUpdate` were
  parsed and never checked (the request carries no nonce and OCSP rides
  plaintext HTTP, so a pre-revocation "good" replayed indefinitely); an
  `unknown` status — which a CA returns for a certificate it never issued —
  was treated as a pass while an *unreachable* responder failed closed; and
  the verdict cache was keyed on the certificate serial alone, which is unique
  only within an issuer, so a cached "good" could admit a revoked certificate
  from a different CA. Responses are now bound to the certificate under test
  (`ParseResponseForCert`), validated for freshness with a 5-minute skew
  tolerance and a 24-hour ceiling, accepted only when affirmative, and cached
  under the full RFC 6960 CertID.
- The OCSP responder URL was an unguarded SSRF sink: it was fetched with
  `http.DefaultClient` with no scheme allow-list, no private-address check and
  redirects followed, so any operator of any destination the gateway reaches
  could name an internal address and have the proxy POST to it. It is now
  guarded inline, dialed through the SSRF-controlled dialer, and redirects are
  refused. The responder list was also walked in full under a *per-responder*
  5-second timeout: a certificate listing 200 blackholed responders held a
  request goroutine — and its connection, file descriptor and per-IP limiter
  slot — for about seventeen minutes inside one TLS handshake while aiming 200
  outbound requests at hosts it chose. At most four responders are now
  consulted, all inside one 5-second envelope, single-flighted per
  certificate.
- OCSP: binding a response to a certificate was only half the check — the
  *signer* was never bound to an authority. Go's OCSP library verifies an
  embedded responder certificate by asking only whether the issuer signed it,
  never whether it carries the `id-kp-OCSPSigning` extended key usage RFC 6960
  requires. A peer's own certificate is, by definition, one the issuer signed,
  and the peer holds its private key — so it could sign a "good" response about
  its own serial, embed its own certificate as the responder, and have a revoked
  certificate accepted with no other party involved. Only the issuer, and
  delegates it signed that carry the OCSP-signing usage and are within their own
  validity period, are now accepted as responders. Related: a confirmed verdict
  was cached for a fixed hour regardless of the response's own `NextUpdate`, so
  a response a minute from expiry kept admitting the certificate for another 59;
  cache lifetime is now capped at the responder's own deadline.
- **Behaviour change for operators running `proxy.ocsp_check: true`:**
  responder queries are now made directly and no longer honour `HTTP(S)_PROXY`
  from the environment, and a responder on a private address is refused. An
  egress-restricted deployment must allow the responder hosts named in its
  upstreams' certificates. See `docs/operator/ocsp-revocation-checking.md`.

### Changed

- The production image now cross-compiles the proxy and the bundled
  maintenance agent on the build platform instead of compiling them under QEMU
  for arm64. The shipped binaries are byte-identical to before; only the build
  got faster. **Building the image now requires BuildKit.** It has been
  Docker's default builder since Engine 23.0 and is the only builder Compose v2
  uses. The deprecated legacy builder (`DOCKER_BUILDKIT=0`) stops at the first
  `FROM` with `failed to parse platform : ""`. Pulling the published image is
  unaffected.

- OCSP now reports which TLS handshakes it actually covers. Enabling it
  installs the check on the shared upstream transport only, which for a
  forward proxy means the handshake to an `https://` parent proxy — inspected
  HTTPS origin handshakes build their own TLS config and are **not**
  revocation-checked. Because every counter reads zero either way, "found
  nothing wrong" and "never consulted" were the same reading. The appliance now
  says so in a warning at the moment the control is enabled, in a banner on the
  OCSP panel, in `coverage`/`uncheckedEnforcingPaths` on `GET /api/ocsp`, and
  in `culvert_ocsp_path_checked{path}` — alongside a new `culvert_ocsp_*`
  series set (the only OCSP surface before this was an admin JSON endpoint
  nothing scrapes). Covering inspected HTTPS is tracked as an owner decision:
  doing it fail-closed would make every inspected HTTPS request depend on
  outbound port 80 to arbitrary responder hosts.

- Scan-service credential exposure on the viewer-role read surfaces
  (`GET /api/security-scan/svc`, `GET /api/security-scan/status`). The
  userinfo redaction added for those surfaces returned unparseable input
  verbatim, so a `-scan-svc-url` password containing a bare `%`, a control
  character or a space — all of which make `url.Parse` fail while remaining
  perfectly legal in a password — was echoed in cleartext to any viewer.
  The same input also produced a `*url.Error{Op:"parse"}` carrying the raw
  URL, which both surfaces spliced into their JSON. Redaction is now
  fail-closed (`internal/redaction.URLUserinfo`, lexical fallback), probe
  failures render a bounded reason class only
  (`internal/secscan.ProbeFailureReason`), and the two startup log lines
  that wrote the configured URL verbatim are redacted.
- MCP live side-effect boundary: `AdmitSideEffect` switched on the
  admission denial class with no `default`, so a class added later would
  fall through onto the admit path and authorize an irreversible upstream
  tool call. Every class defined today was handled, so the hole was latent;
  the boundary now denies what it cannot classify.
- `google.golang.org/grpc` bumped `v1.83.1` → `v1.83.2` (CVE-2026-84445,
  HIGH: gRPC-Go xDS servers, denial of service via crash). Module graph
  only; no code change.
- The Cluster panel's Distributed Rate Limiting card now shows **Stale
  Episodes** — the number of times this node's cluster-wide rate-limit
  broadcast has gone fresh→stale since startup (`GET /api/cluster/rate-limits`
  already returned `remote_counts_stale_episodes`; the panel never rendered
  it). The existing stale banner only appears while the broadcast is
  *currently* stale, so an operator reviewing the panel after a Control Plane
  blip had recovered saw a fully healthy panel with no way to tell "did this
  happen once overnight, or six times" without SSHing in and grepping the
  process log for the CHAOS-61 transition line. Read-only, no behavior change.

### Performance

- The threat feed's full-URL check no longer re-parses a URL it was handed
  already parsed. `preDispatchBlocked` runs it on every forwarded plain-HTTP
  request, on the request goroutine, before the policy engine — and called it
  as `CheckURL(r.URL.String())`, so a `*url.URL` net/http had just parsed was
  serialised and the feed immediately parsed it back, purely to read the three
  fields (scheme, host, path) the caller already had. Measured against a
  100k-entry feed for an ordinary destination that misses — what every
  *allowed* request pays — the check cost **887 ns and 4 allocations**, against
  **109 ns and 0 allocations** for the domain check beside it doing the same
  amount of real work. The new `CheckRequestURL` takes the parsed URL:
  **376 ns / 112 B / 2 allocations** (330 → 162 ns at 4× parallel). Verdicts
  are unchanged and the equivalence is structural: the fast path is taken only
  for the URL shape on which `String()` followed by `Parse()` is provably the
  identity for those fields, and every other shape falls through to the
  verbatim string derivation. Only deployments with threat intelligence
  enabled are affected; with the feed off the check already returned early.

### Added

- New React/TypeScript admin frontend, Batch 2 (`CULVERT_EXPERIMENTAL_UI`,
  `/app/`): Policies (Access Rules, Authentication Rules, Policy Tester,
  Header Rewrite, Policy Learning), Objects (URL Categories, Category Groups,
  Decryption Profiles, File Profiles), Security (Content Security,
  Decryption, CDR Integration) and Network (PAC, Upstream Proxies), with the
  backend trust and concurrency corrections recorded in
  `docs/design/FRONTEND-MIGRATION-PLAN.md` §FE-5.
- Admin UI listener health surfaces (CHAOS-57), all on the **proxy** port so
  they survive the fault they describe: `admin_ui` on `GET /health`, a
  report-only `admin_ui` row on `GET /ready`, the `admin_ui_listener`
  operator-contract row on `GET /api/diagnostics`, the
  `culvert_admin_ui_{up,unavailable,listen_failures_total,binds_total,listen_backoff_seconds}`
  series, and the `admin_ui_unavailable` alert. The readiness row never gates
  the default verdict — a node whose admin UI is down is still proxying.
- `CULVERT_DATA_DIR` — startup-scoped override of the persisted-state root
  (default `/data`, unchanged when unset). Every persisted-state path —
  including the config-version store, registry settings, the CDR
  enrollment certs root and runtime marker, and the alert retry queue —
  follows the override.
- The admin UI's own serving certificate now reports its expiry
  (`ui_tls_cert_not_after`/`ui_tls_cert_days_remaining` on
  `GET /api/settings/network`, shown on the Certificates panel) whenever a
  custom pair (`-tls-cert`/`-tls-key`, or one uploaded via the panel) has
  bound — the one certificate in the product whose expiry was previously
  untracked; the MITM inspection root CA and the outbound upstream mTLS
  client cert already surfaced theirs.
- Admin API operations (contract 2.0.0): `GET /api/rewrite/state`,
  `GET /api/fileblock/profiles/state`, `GET /api/urlcat/state`,
  `GET /api/pac/profiles/{name}/lifecycle`, the Upstream v2 entry endpoints
  (`/api/upstream/entries`, `/api/upstream/entries/{id}`,
  `/api/upstream/entries/{id}/credential`) and the CDR enrollment recovery
  endpoints (`/api/cdr/instances/enroll/recover`,
  `/api/cdr/instances/enroll/receipts`).

### Changed — API contract 1.2.0 → 2.0.0 (BREAKING)

The admin API contract takes a MAJOR bump. Every change below is the
documented behaviour of the appliance after the Batch 2 backend corrections;
consumers of the affected operations must migrate.

- **Structured refusals replace `text/plain` error bodies** on the policy,
  authentication-policy and upstream mutation operations (400) and on the
  PAC lifecycle operation (409): a refusal is now `application/json`
  `{error, code, current}` (the `RefusalBody`/`UpstreamRefusal` schemas).
  Consumers that parsed the plain-text body must read `code` instead.
- **Delete operations answer 204 No Content instead of 200**:
  `DELETE /api/authpolicy`, `DELETE /api/pac/pools/{name}`,
  `DELETE /api/pac/posture/exceptions/{name}`,
  `DELETE /api/pac/profiles/{name}`.
- **Revision fencing is required on PAC deletes**: `?etag=` on
  `DELETE /api/pac/pools/{name}`, `?revision=` on
  `DELETE /api/pac/posture/exceptions/{name}` and
  `DELETE /api/pac/profiles/{name}` (428 when absent, 409 `stale` when
  behind, 404 `vanished` when gone).
- **Identity parameters became required**: `?name=` on
  `DELETE /api/cdr/policies`, `?pattern=` on `DELETE /api/content-scan` and
  `DELETE /api/dpi`, `?id=` on `DELETE /api/security-scan/yara/rules`
  (the former `name` selector was removed).
- **Request bodies tightened**: `enabled` is required on
  `PUT /api/cdr/config`; the body is required on
  `POST /api/cdr/instances/revoke`; `proxies[].url` is required on
  `POST /api/upstream` (the credential-free v1 adapter); the decryption
  profile security fields are closed enumerations on
  `POST`/`PUT /api/decryption-profiles` (`permissive` is no longer
  accepted); `?dryRun=` on `POST /api/config/import` is the enumeration
  `1`.
- The credential-free `POST /api/upstream` adapter and
  `DELETE /api/upstream/entries/{id}` refuse while an entry holds credential
  material OR carries the `requiresReplacement` marker (409
  `credentialed_entries_present` / `credential_present`).

Migration: read `code` from JSON refusal bodies; treat 204 as success on the
listed deletes; echo the current `etag`/`revision` on PAC deletes; send the
now-required identity parameters and body fields; use the per-entry Upstream
endpoints for credentialed parents.

### Performance

- Concurrent leaf-certificate cache misses for one host are collapsed onto a
  single sign. `Manager.GetCert` is the `tls.Config.GetCertificate` callback
  for every SSL-inspected CONNECT, so a miss there is the most expensive unit
  of work the appliance performs per connection — `signLeaf` measures 144 µs,
  19.6 KB and 327 allocations on the reference box, 85% of it the irreducible
  P-256 sign inside `x509.CreateCertificate`. Nothing stood between the cache
  probe and the sign, so every handshake that arrived for a host while the
  first was still signing started its own, and the duplicates were pure waste:
  same host, same CA, same shared leaf key, same 24-hour window, with the last
  writer simply overwriting the others in the cache. The amplification grew
  with core count, because what bounded the herd was how many signs could be
  in flight at once — 64 workers over 256 cold hosts measured 1.00 signs per
  host at `GOMAXPROCS=1`, 1.35 at 2 and 1.61 at 4, so the 16/32-core hardware
  the appliance ships to sat further up that curve. It landed during exactly
  the cold-cache burst the cache exists to absorb: a restart, a TTL boundary
  (entries are created by traffic and expire on one uniform 1-hour TTL, so a
  working set goes cold together), or a traffic spike. A leader/follower
  single flight — the same shape already used for `hostIPCache`, `jwksCache`
  and `internal/ocsp` — takes that cold burst from 28.13 ms to 14.37 ms
  (−48.9%), 157,550 allocations to 92,329 (−41.4%) and 9.75 MB to 5.85 MB
  (−40.0%), at exactly 1.00 signs per host. A follower receives the leader's
  certificate, which is the one it would have signed itself, so the cache, its
  TTL, the LRU, the CA-validity refusal and the fail-closed posture are
  unchanged, and the steady-state hit path is at parity (190.1 ns against
  189.6 ns, same 32 B and one allocation). New counter
  `culvert_cert_sign_singleflight_joined_total` reports the duplicate signs
  avoided; `culvert_cert_cache_misses_total` keeps its meaning — hits plus
  misses is still the number of `GetCert` calls — but is no longer the same
  thing as the sign count, for which
  `culvert_cert_sign_duration_seconds_count` is exact.
- The per-request policy decision line is built by appending rather than by
  `logger.Printf`, and the benchmark that measured it was measuring a disabled
  logger. `applyPolicyDecision` emits exactly one `POLICY_*` line per proxied
  request — HTTP, CONNECT, WebSocket and SOCKS5 all reach it — and the
  end-to-end allocation profile ranked it the largest Culvert-owned allocation
  site in the run, 7 objects per request. `log.Logger.output` returns
  immediately when its writer *is* `io.Discard`, so every benchmark that
  silenced the logger that way never formatted anything and under-reported the
  line by 3.6x (283 ns/op against `io.Discard`, 1042 ns/op against a sink
  `log.Logger` cannot recognise); the shared `benchSilenceLogger` behind the
  end-to-end proxy qualification had the same defect, so that figure was
  omitting ~1 µs of real per-request work. Measured correctly, the nine boxed
  format arguments were two thirds of the line's CPU profile before `fmt`
  parsed a verb, and the two `%q` verbs cost ~200 ns on their own
  (`strconv.AppendQuote` decodes rune-by-rune through `strconv.IsPrint`: 99 ns
  for a 17-byte ASCII host). The emitters now append into a stack buffer and
  `appendQuotedForLog` settles printable ASCII with one byte scan, falling back
  to `strconv.AppendQuote` for `"`, `\`, control bytes and everything at or
  above 0x80. Serial cost goes 1042 → 428 ns/op (-59%) and allocations 8 → 1;
  bytes per op rise 128 → 192 deliberately, one right-sized string in place of
  eight small objects, because GC mark cost is per object. The parallel gain is
  smaller (462 → 374 ns) because four cores queue on `log.Logger`'s own mutex,
  which this does not touch, and the end-to-end benchmark cannot resolve ~614 ns
  inside a 148 µs in-process operation — what it does show exactly is the
  allocation drop, 185 → 179 per request overall and 7.0 → 1.0 at this site.
  Emitted bytes are unchanged, which is the acceptance condition for lines that
  SIEM forwarders and log parsers consume: the four format strings survive as an
  executable specification and every branch is rendered both ways over a corpus
  of control characters, quotes, backslashes, and multi-byte and invalid UTF-8.

- The rate-limit exempt check is lock-free and flat in the exempt-CIDR count.
  `RateLimiter.IsExempt` is the first decision inside `Allow`, so once a rate
  limit is configured it runs on every proxied request; it took a
  process-wide `RWMutex` read lock and then ran a linear `net.IPNet.Contains`
  scan, which made the length of an operator's exempt list the price of the
  gate for every *other* client. On a 4-core box it measured 59.7 ns with no
  exemptions and 3.95 µs at 256 exempt CIDRs (~15 ns per configured CIDR);
  reading an immutable view and probing a prefix-length-bucketed set it
  measures 3.06 ns and 63.9 ns — flat from 1 to 256 prefixes. End to end the
  whole `Allow` gate goes 1176 → 279 ns at 256 exempt CIDRs at four cores,
  and the per-op cost now falls with core count (3.99x from 1→4) where it used
  to rise (0.65x). The prefix-bucketing machinery is now one implementation
  (`prefixSet`) shared with the IP filter rather than a second copy. Verdicts
  are preserved exactly, including an IPv4-mapped probe continuing *not* to
  match a plain-v4 single-IP exemption — canonicalising that would widen an
  exemption. `RateLimiter.AddExemptions` is added as the bulk-load primitive
  and used by the boot settings restore and config import, so restoring a
  large exempt list stays linear. No API, metric, or dashboard change.
- The top-hosts counter's tracked-host path is lock-free. `topHosts.Record`
  runs on every allowed request and took a process-wide `RWMutex` read lock
  to read a map that in steady state never changes; `RLock`/`RUnlock` are two
  atomic read-modify-writes on one shared word, so this was a throughput
  ceiling rather than a constant cost — on a 4-core box it measured 35.8 /
  92.6 / 96.8 ns/op at 1 / 2 / 4 cores, i.e. four cores delivered 0.37x the
  throughput of one. Backed by a `sync.Map` it measures 42.0 / 26.1 / 16.1
  ns/op — 6.0x at four cores and a curve that improves with core count. The
  distinct-host cap, the decay pass and `Top` are unchanged and still
  serialised. No API, metric, or dashboard change.
- Destination-category rules no longer allocate once per rule per request.
  `urlcat.Store.MatchesHost` / `MatchesHostAdmin` answer "is this host in
  category C?" and are called once per category-scoped access rule per proxied
  request. Both derived their index key with
  `strings.ToLower(string(cat))`, which allocates whenever the name carries an
  uppercase letter — and all 21 shipped SaaS category names do — so a rulebase
  with N `destCategory` rules charged N heap allocations to every proxied
  request to re-derive a value that is pure configuration: the rule's category
  name is fixed when the admin writes the rule. The key is now folded into a
  caller-owned stack buffer and the map is probed against those bytes
  directly. A category name too long for that buffer (the admin API accepts up
  to 256 bytes) or carrying non-ASCII keeps the string `strings.ToLower`
  already produced and is probed as a string, so no supported name became more
  expensive than it was before the optimization. On a 4-core box, with both
  arms benchmarked in one session (medians of n=5), the probe goes
  204.4 → 137.4 ns on a miss and 170.1 → 105.7 ns on a hit, at 1 alloc → 0 in
  every posture; through the real policy
  scan against an uncategorized destination it goes 2420 → 1635 ns at 10
  rules, 8572 → 5524 ns at 50, and 31670 → 19106 ns at 200, with 10 / 50 / 200
  allocs → 0. Under 4-way concurrency the same probe moves only 94.3 → 88.2 ns,
  because the per-call read lock — untouched here — dominates once several
  cores contend. Matching semantics are unchanged exactly: a pure-ASCII name
  folds byte-wise as `strings.ToLower` already did, and anything non-ASCII
  falls back to `strings.ToLower` itself, so Unicode folding is never
  reimplemented. Pinned by a differential against the verbatim pre-fix key
  expression, a fuzz target, and a deterministic zero-allocation gate. No API,
  metric, or dashboard change.

### Fixed

- A leaf-certificate sign already in flight could outlive the CA it was started
  against. Replacing the root CA (`InitCA`, `ImportBundle`, `LoadCustomCA`, and
  `ClearCache`) cleared the leaf cache, which is not sufficient on its own: a
  sign that began before the replacement was still running against the outgoing
  CA, and when it completed it repopulated the just-cleared cache with that
  outgoing CA's leaf — served to every client for the full one-hour cache TTL,
  and rejected by any client that trusts only the newly installed CA. A CA
  replacement is exactly the moment an operator expects the old CA to stop
  being used. The cache now carries a CA *generation* retired in the same
  locked step that clears it, a sign records the generation it started under,
  and a result whose generation has been retired is dropped rather than cached;
  a new CA-install path that cleared the cache without retiring the generation
  would silently reintroduce this, so that is pinned structurally rather than
  behaviourally. Found by Codex review on the leaf-sign single flight above,
  which briefly widened the same window: a caller arriving *after* the
  replacement could join the pre-replacement sign and be handed its leaf, where
  previously it would have signed against the new CA itself. Flights are now
  scoped to the generation, so generations never join each other.

- A SOCKS5 listener bind failure no longer terminates the whole appliance
  (CHAOS-66). `startSOCKS5` bound with a single `logFatalf` branch, and
  `initSOCKS5` runs *before* the admin UI and the proxy listener start — so an
  occupied SOCKS5 port meant the HTTP/HTTPS proxy and the admin UI never came
  up at all, and under `restart: unless-stopped` an unattended crash loop
  recoverable only with shell access. This is the CHAOS-57 fault one plane
  over and it lands harder: there the management plane killed the data plane,
  here an *optional*, off-by-default listener killed the primary data plane,
  the management plane and the health endpoints together. The triggers are
  routine and invisible to `validatePortCollisions`, which only compares
  Culvert's own three ports to each other: a predecessor container still
  draining, a privileged port after `CAP_NET_BIND_SERVICE` was dropped, an
  interface not yet up. The listener now rebinds with a jittered,
  interruptible backoff for as long as the process lives, and an accept-loop
  failure that invalidates the socket — previously terminal until a restart —
  recovers the same way. **No SOCKS5 fault requires a node restart any more**,
  and the `socks5_listener` diagnostics row no longer tells operators to
  perform one. New read-only surfaces: `culvert_socks5_unavailable`,
  `culvert_socks5_bind_failures_total`, `culvert_socks5_binds_total` and
  `culvert_socks5_bind_backoff_seconds`, emitted only on a node with a
  configured listener. `runProxyUntilShutdown`'s fatal proxy-listener branch
  is deliberately unchanged. See `docs/operator/socks5-listener-health.md`.
- A SOCKS5 listener outage is now reported the moment its threshold elapses,
  not on the next retry. Both episode durations were measured between the first
  and *last* recorded failure, so they stopped advancing between attempts: with
  the rebind backoff at its 30 s ceiling (±20% jitter), a failure landing at
  29 s left `/healthz` reporting *degraded*, `culvert_socks5_listener_up` at
  `1`, the `socks5_listener` row saying *retrying* and the `socks5_listener_down`
  alert unfired for up to 36 s after the documented 30 s outage threshold had
  passed. Durations are now aged against the clock, and one sleep per outage is
  shortened so it cannot carry the supervisor past the threshold without an
  attempt to observe it (the alert is attempt-driven). A clock that jumps
  backwards can no longer shrink an outage already observed. The accept plane
  carried the same shape with a 1 s ceiling and is fixed identically.
- The `socks5_listener` row's suggested action now matches the failure reason.
  One action string — check the port owner and bind permission — was printed for
  every class, so a node out of file descriptors, or one whose interface had not
  come up, was directed to hunt the owner of a port nobody holds. Each bounded
  reason class now carries its own remedy; `network_error` and `listen_failed`
  remain the unrecognised classes and point at the log line.
- Listener failures are no longer misreported as network faults. Every bind
  error arrives wrapped in `*net.OpError`, which satisfies `net.Error`
  unconditionally, so the admin UI listener's classifier labelled every
  unrecognised errno `network_error` — pointing an operator at network
  troubleshooting for a socket or permission fault — and could reach
  `listen_failed` only for an error the `net` package had not produced. Both
  listener classifiers now require an actual timeout for `network_error`.
- A `config.yaml` `auth.user` (or CLI `-user`) value written with a YAML
  literal block scalar (`user: |` instead of `user: admin`) silently
  appended a trailing newline to the stored admin username. Every other
  local-admin-credential entry point (the web setup wizard) already trims
  this field; the CLI/config.yaml startup path did not, so the operator was
  permanently locked out of the admin UI — nothing typed at a login prompt
  can produce a trailing newline — with no error at startup and no
  indication of the cause. `resolveAuthStartupConfig` now trims the
  resolved username (never the password, which may legitimately carry
  whitespace) before it reaches `cfg.SetAuth`. Two review-round follow-ups
  closed the same gap at its other two edges: the CLI/YAML precedence pick
  (`s.authU = firstStr(...)`) now trims both candidates first, so a
  whitespace-only `-user` can no longer shadow a real `config.yaml`
  `auth.user`; and a resolved-empty username paired with a non-empty
  password is now a fatal startup error instead of silently reaching
  `cfg.SetAuth("", pass)`, which disabled local authentication entirely
  and discarded the configured password.
- The root-CA recovery record (CHAOS-50) could report a recovery with the
  wrong attempt count. A successful attempt set `recovered` from inside the
  attempt while the campaign loop counted it only after the attempt returned,
  so a reader of `GET /api/ca/status` or `/metrics` landing between the two
  writes saw `loadRecoveryAttempts` one short of the attempt that recovered it
  — including zero. Each attempt is now recorded as one locked transition
  carrying its count together with its outcome (error or recovered), so no
  snapshot can pair one attempt's count with another attempt's result. No
  change to the retry schedule, the never-mint rule or the log lines.
- An admin UI listener failure no longer terminates the proxy data plane
  (CHAOS-57). `startUI`'s listen goroutine called `logFatalf`, so an occupied
  admin port or an unreadable `-tls-cert`/`-tls-key` pair exited the whole
  process — under `restart: unless-stopped`, an unattended crash loop with no
  proxy, no admin UI and no health endpoint. The listener now rebinds with a
  jittered, interruptible backoff for as long as the process lives, re-reading
  the certificate on every attempt so a rotation self-heals with no restart,
  while the proxy keeps enforcing policy throughout. `runProxyUntilShutdown`'s
  fatal proxy-listener branch is deliberately unchanged. See
  `docs/operator/admin-ui-listener-recovery.md`.
- `culvert --prepare-downgrade` now writes its counts-only audit record to
  the durable audit log named by `-audit-log` before exiting.
- The real-binary browser smoke and the upstream test suites are hermetic
  under any user and any shuffle order (per-instance data roots; the
  rejected-document latch is reset per test environment).
