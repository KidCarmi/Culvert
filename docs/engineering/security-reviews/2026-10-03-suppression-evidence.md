# Suppression evidence audit — 2026-10-03

Decision authority: [TECHNICAL-RISK-REGISTER](../TECHNICAL-RISK-REGISTER.md),
RISK-002, RISK-006, RISK-009, RISK-015 and RISK-023. This is a dated evidence snapshot,
not a second risk register. Owner: default CODEOWNER @KidCarmi; an explicitly
assigned security DRI is still missing. Follow-up review: 2026-11-03 (this does
not extend any exception). Scanner findings are leads, not confirmed vulnerabilities.

## Baseline and overlap

Freshly fetched `origin/main`: `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`.
Worktree `Culvert-suppression-evidence`, branch `security/suppression-evidence`.
Read applicable `CLAUDE.md`; no applicable AGENTS.md found. Go pin: 1.26.8.
Merged #1523/#1525 admission changes are reused. Open PRs inspected before edits:
#1532 (Opus, `claude/epic-bardeen-8lh4p6`) touches enrollment secret writes and
reauth audit; no code from that branch was modified/reimplemented. CHANGELOG is
shared, so expect a possible text conflict. #1534 (gRPC bind/HA), #1533 (category
index/race), #1528 (on-prem readiness) are pending adjacent security work; #1511
updates toolchain/base versions. This audit does not depend on them. Final head
and updated CI results belong in the PR body, avoiding a self-referential SHA.

## Before/after inventory and scope

[Inline inventory](2026-10-03-inline-suppression-inventory.tsv) records every Go
comment suppression, including test helpers, build constraints and the nested
maintenance module: exact annotation, function/location, assumptions, owner,
classification, evidence path and missing evidence. It distinguishes standalone
staticcheck directives from gosec and golangci-only directives. Counts describe
annotations, not distinct vulnerabilities or scan findings:

| Inventory | Baseline | After |
|---|---:|---:|
| `.trivyignore` advisory entries | 1 expired (not an effective active exception) | 0 |
| Root standalone gosec global rules | G104,G302,G304,G703,G704 | G104,G302,G304,G703 |
| Maintenance standalone global rules | G104,G302,G304,G703,G704 | G104,G302,G304 |
| golangci gosec global rules | G104,G302,G304,G704 | G104,G302,G304 |
| Inline Go annotations (production / test) | 551 (207 / 344) | 562 (217 / 345) |
| `#nosec` / golangci-only / staticcheck-only | 431 / 105 / 15 | 442 / 105 / 15 |
| Gitleaks allowances | one whole commit, two paths | unchanged |
| Obituary ignore-file package entries | 8 (file not wired into action) | unchanged |

[Configuration inventory](2026-10-03-scanner-policy-inventory.tsv) separates
individual allowances, global exclusions and gate-policy filters. It includes
scanner paths, severity/unfixed filters, report error masking and conditional
execution. Scope is root and `cmd/culvert-maint` Go modules, frontend and its
`tools/openapi-gen` npm workspace, workflows/scripts and actual image contents.
Installer cleanup `|| true`, smoke diagnostic tails, mutation-campaign cleanup,
and optional race-artifact downloads with a completeness verdict are not scanner
exclusions; they were inspected but not counted as vulnerabilities.

Many historical annotations remain **under investigation**, not silently endorsed.
In particular, “admin-controlled” does not establish path integrity, symlink
safety or absence of request-tainted input. Existing secret-write fixes on main
are reused; enrollment overlap stays with #1532. Missing per-site owners/expiry
are recorded rather than fabricated as historical approvals.

## Rule diagnostics and focused decision

Pinned gosec **2.27.1**, Linux amd64, Go **1.26.8**, default build tags, non-test
production source. Diagnostic command in each module:
`gosec -include=G104,G302,G304,G703,G704 -nosec -fmt=json -out=report.json ./...`.
This exposes both globals and inline ignores; no Go scan errors.

| Module | G104 | G302 | G304 | G703 | G704 |
|---|---:|---:|---:|---:|---:|
| Root baseline | 118 | 1 | 127 | 44 | 10 |
| Maintenance baseline | 0 | 3 | 6 | 1 | 0 |

All ten G704 findings are management/request paths: six OIDC introspection/JWKS,
two signed-feed downloads and two configured release-agent calls. They are not
“forward proxy by design.” OIDC inherited a public environment proxy; the guard
then checked that proxy, not the private request destination. Fixed via
`newOIDCTransport` (direct destination dial); no new ignore conceals the defect.

| Suppression → claim | Evidence | CI execution | Disposition |
|---|---|---|---|
| OIDC six G704 sites → resolved destination guarded, redirects included | `TestOIDCTransport_SSRFBoundary`, legacy/flow/JWKS request paths, real HTTP transport + real IP Control, public positive controls | Fast/QA root race; Fast + Security gosec; golangci | Global retired; narrow protected-by-control annotations; RISK-009 residual |
| Signed feed two G704 sites → pinned origin/path, per-hop checks, dial actual IP | `TestF3b2_SSRFPrivateAddressRejected`, `TestF3b2_RedirectEscapeRejected`, `TestF3b2_DialsResolvedIPWithOfficialHostAndSNI` | Fast/QA root race | Reuse existing tests; narrow protected-by-control annotations |
| Release-agent two G704 sites → intentional configured UDS/private HTTP(S) endpoint | `TestLocalAgentEndpoint`, `TestService_EndpointRebindingUsesNewClient` prove wiring/selection only | Fast/QA root race | Narrow **accepted risk**, proxy/redirect override destination safety unproven |
| Maintenance G703 → canonical ULID lexical confinement | `TestOperationsEndpoint_RejectsInvalidOpID`, existing scoped annotation | Fast security-fast; Deep maint; QA qa-agent | Global retired; StateDir/symlink assumption remains |
| Expired OpenSSL CVE → installed packages already fixed | Actual candidate apk database + upstream fixed-version boundary below | Deep trivy-image; CI qualify-candidate both platforms | Removed obsolete entry; no renewal |
| Static Go binaries → these ELF bytes have no interpreter/dynamic segment and CGO=0 metadata | `TestStaticArtifactEvidence`, `ArtifactEvidenceTests`, `TestCandidatePromotion_Behaviour`, actual image binary hashes | Fast hygiene/QA OS; Deep trivy-image; CI qualify-candidate | Replace ldd inference; binary-only claim |
| Exception metadata → explicit owner/scope/classification/evidence/review deadline | `MetadataEvidenceTests`, `ReportEvidenceTests` | Fast gitleaks every PR; Security source scan | Link/expiry enforcement, never proof of mitigation |

After policy changes, blocking standalone gosec has **0 findings and no Go errors**
in both modules. Full unfiltered root scan has **371 findings**, including ten
G704 sites; not an exploitability verdict. PR and nightly JSON/Markdown preserve
all rules and inline sites; errors/empty scans and mismatched finding counts are refused even with `-no-fail`.
Root G304/G703 remain globally excluded because 127/44 diagnostic findings span
uploads, restore/support paths and local state operations. Retiring them requires
boundary-specific product work; the old operator-path rationale is withdrawn.
G104/G302 also need per-site triage; “log permissions” is not a blanket decision.

## OpenSSL vendor and actual artifact evidence

Authoritative CNA record:
[CVE-2026-14456](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/14xxx/CVE-2026-14456.json),
[OpenSSL advisory 2026-08-13](https://openssl-library.org/news/secadv/20260813.txt),
[3.5 branch fix](https://github.com/openssl/openssl/commit/08e7756c3900bcfd77a720e7b74e27d6e4ed01a9),
[Alpine 3.24 package recipe/secfixes](https://github.com/alpinelinux/aports/blob/3.24-stable/main/openssl/APKBUILD)
(retrieved 2026-10-03). QUIC listener Initial packets with unknown connection IDs
can grow a queue without bound. Vendor severity LOW differs from CVSS 7.5/HIGH;
fixed versions **3.5.8**, **3.6.4**, **4.0.2**. Alpine recipe publishes **3.5.9-r0**
and records the CVE at **3.5.8-r0**. Recipe availability alone is not installed evidence.

Baseline CI [36842294278](https://github.com/KidCarmi/Culvert/actions/runs/36842294278)
qualified candidate index
`sha256:eca28e0f99b342e13c73fedbef27b21214e16b5389ee97b4d1f539a8d5bda632`.
The actual images were pulled and inspected without executing their binaries:

| Platform | Manifest digest | Proxy SHA256 | Bundled agent SHA256 |
|---|---|---|---|
| linux/amd64 | `f1e48f7430ca969e0d5b0d76565747bb5e0390f07e9b76b46d7f1b5d72d41511` | `10a10e4682b200c16e316b6abe05cb377840bcbef40bfed340880aa9d0fdb42b` | `f5dfd3e589d3b3c048e9a8e0f4a5d03782f4d331efca805a69721d8e1852d9af` |
| linux/arm64 | `edd6e3c24bed840b61e995109334397eadc6acb5fd37c3da5a8bd64a40223eb8` | `12971875c5692e4fc3c00eb1cd5739c826de2f778dcdbbe6dbf848c418dfec45` | `99fd656a9f050e94f729ab324602a9da08a0833b4499f43d3a8d306fb94cfda5` |

Both revision labels match baseline SHA; both binaries/platforms pass actual ELF
inspection and report Go 1.26.8 / CGO=0. Both installed apk databases contain
`libcrypto3`/`libssl3` **3.5.9-r0**. The amd64 executable inventory includes BusyBox
(and its wget alias), apk, musl loader, CA-update utilities, the packaging shell
installer, proxy and bundled agent. Entry point executes proxy; configured
arguments include no QUIC listener. This is not proof that all those executables
can never use libssl or that a host/external service cannot expose OpenSSL QUIC.
The remediation version makes that reachability argument unnecessary for this CVE.

Trivy **0.69.3**, full severity/unfixed/suppressed + package listing on actual amd64
image: 18 apk packages, 101 proxy dependency records, 4 agent records; no OS
findings, one UNKNOWN `GO-2026-5932` (`x/crypto` v0.57.0, OpenPGP advisory).
Dependency presence is not proof of a reachable OpenPGP vulnerability; source
reachability remains govulncheck's job. This finding stays visible, not ignored.
Arm64 installed/linkage evidence was inspected separately; no local arm64 Trivy
result is claimed. PR evidence is linux/amd64; promotion validation covers both
platforms on the **same candidate digest**, with no extra build.

## Negative controls and validation limits

All mutations were isolated and restored, none committed:

- Removed `transport.Proxy=nil`: all 18 private-target cases across legacy
  introspection, flow introspection and JWKS refresh accepted the request
  (`err=nil`); all three redirect cases reached two requests. Restored: race/shuffle count=2 passed.
- Disabled ELF-segment refusal in a temporary checker: genuine Go ELF with a
  PT_NOTE replaced by PT_DYNAMIC/PT_INTERP was accepted; corresponding test failed
  (`0 == 0`). Disabled CGO-metadata refusal: cgo fixture reached the wrong refusal
  (dynamic segment), failing the expected CGO reason assertion. Restored: real
  amd64/arm64 and cgo/header cases all passed; mutated bytes were never executed.
- Disabled exception expiry: expired/today cases failed (`ValueError not raised`).
  Disabled advisory scan-error validation: scan-error case failed likewise.
  Disabled finding-count validation: a truncated retained array was accepted and
  its refusal test failed. Restored: all 10 Python tests passed, including complete
  empty/nonempty reports that preserve the actual findings in the advisory output.

Behavioral attempts establish these representative controls, not universal
non-exploitability. OCSP G123 wiring tests set VerifyConnection, but do not perform
resumed handshakes; retain that coverage gap. Existing OCSP responder tests cover
malicious URLs, redirects and DNS rebinding; TLS enable/soft-fail configuration
still changes the security contract. Accepted `InsecureSkipVerify` probes in
RISK-023 and credential-channel opt-outs in RISK-009 have different residual risk.
Gitleaks whole-commit allowance exceeds its single hex-fixture rationale; replace
with a finding/path-specific allowance after historical-secret triage, not blindly.

CI cost: one extra unfiltered gosec pass per module in Fast (nightly replaces its
old report pass); small metadata tests; real tiny ELF fixtures take ~1 second
locally. Image inspection reuses existing built/qualified artifacts; one cached
Trivy report pass per PR platform and two per candidate, no rebuild, platform or
service added. Reports retained 30 days. Existing blocking severity/unfixed
policies and vulnerability checks are preserved. Run times depend on DB/cache.
