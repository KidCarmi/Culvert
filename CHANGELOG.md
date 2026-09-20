# Changelog

All notable changes to Culvert are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the API contract
version is `info.version` in `api/openapi/openapi.yaml` and follows
`docs/api/API-VERSIONING-POLICY.md`.

## [Unreleased]

### Security

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

  Pinned by `release_publication_gating_test.go` (13 structural walls over
  `ci.yml` and the manifest, each verified failing against the pre-fix tree)
  and `.github/scripts/test/release-gating-cases.sh` (47 behavioural cases
  against mocked `gh`/`docker`/`git` — no registry, no release, no Sigstore).
  Signing identities are unchanged: cosign keyless SANs are per workflow FILE
  and ref, and both new jobs live in `ci.yml`. See
  `docs/operator/release-publication-gating.md`.

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
- **Behaviour change for operators running `security.ocsp_check: true`:**
  responder queries are now made directly and no longer honour `HTTP(S)_PROXY`
  from the environment, and a responder on a private address is refused. An
  egress-restricted deployment must allow the responder hosts named in its
  upstreams' certificates. See `docs/operator/ocsp-revocation-checking.md`.

### Changed

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

### Fixed

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
