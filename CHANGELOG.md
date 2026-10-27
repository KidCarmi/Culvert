# Changelog

All notable changes to Culvert are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the API contract
version is `info.version` in `api/openapi/openapi.yaml` and follows
`docs/api/API-VERSIONING-POLICY.md`.

## [Unreleased]

### Changed

- **Diagnostics now warns when OCSP checking is enabled but does not cover
  inspected HTTPS origins.** The coverage gap (CHAOS-65 OCSP-8) was visible only
  on the OCSP panel and in a one-time log line; the one-page diagnostics report
  read as healthy. A new `ocsp_coverage` WARN row (additive, report-only, no row
  while OCSP is off) names the unchecked paths. No handshake behavior changes.

### Security

- **The scan sidecar reported a truncated read as `clean: true`, so content past
  its own window was admitted with an affirmative clean verdict (CHAOS-101).**
  `scan_svc.go` `handleScan` read `io.LimitReader(body, maxBytes+1)` — the
  classic overflow probe — and then never compared `len(data)` against
  `maxBytes`, so it paid for the probe byte and discarded what it proved. The
  reply then carried the PREFIX's verdict as the whole object's, and
  `secscan.ScanResponse` has no truncation field to say otherwise.

  No code bug is needed to reach this, only configuration: each process derives
  `maxScanBufferBytes()` from its OWN `security.max_scan_mb`, and nothing
  reconciles the caller's window with the sidecar's — which is precisely the
  topology the handler's own doc comment recommends ("multiple proxy instances
  sharing one scanner"). A fleet of 20 MiB proxies in front of a sidecar left at
  the 5 MiB default had scanning silently off for every byte past 5 MiB, with no
  counter, no log line and no alert anywhere, and the caller's own overflow
  signal correctly did not fire because the body fit the CALLER's window. The
  in-process path has had a signal for this exact event since Finding 4.2
  (`logScanLimitExceeded`: counter, one log line, `scan_skipped` alert); the
  process-isolated deployment recommended as the *remedy* for the local path's
  failure modes was the one without it.

  `handleScan` now uses the probe byte and refuses with 413 rather than
  answering for a prefix, and publishes `oversize_refused` and
  `scan_window_bytes` on `/health` — it is the only process that knows its
  window, and an operator needs it to compare against the caller's.

  **Ordering is the correctness argument.** Refusing on size FIRST — the obvious
  shape — turns a body whose malware sits inside the window into a 413, which
  the client classifies as a size limit and therefore forwards fail-open: the
  one case where the sidecar holds a real block verdict is the case the refusal
  would throw away, so the "safe" check would have admitted content the unfixed
  code blocked. The verdict therefore wins and truncation is not reported at all
  on a block, the same asymmetry `readScanPrefix` documents for the local path.
  A negative control pins it, and failed against the first draft of this fix.

  Client side, 413 is classified as the size limit it is and charges the LOCAL
  path's vocabulary — `statScanSkipped`, hence `culvert_scan_skipped_total`, and
  the `scan_skipped` alert with `Source: "size_limit"` — for the same reason
  `remoteScanRefused` reuses the timeout vocabulary: it is the same decision, so
  one phenomenon keeps one counter and one alert class whichever window clipped
  the object, and an operator already alerting on `scan_skipped` needs no second
  name. A load balancer in front of the sidecar enforcing its own smaller body
  limit returns 413 for the same reason, so the classification is right there
  too; every other status keeps its fault classification.

  Operators running a mismatched fleet will see NEW `scan_skipped` volume on
  upgrade. That volume is the defect becoming visible, not a regression; the
  remedy is named in the log line and measurable from `/health`. The posture for
  oversize bodies is the local path's, unchanged: fail-open, counted and
  alerted. Refusing the object outright is the safer answer and a real option,
  but it is a posture change for large downloads that no operator asked for, and
  is left to the owner as the open half of CHAOS-101.

- **Diagnostics reported "session revocation healthy … no drops" while a
  legitimate remote revocation had in fact been dropped (SEC-REVDIAG-1).**
  CHAOS-73 bounds what an untrusted origin — cluster gossip, or the on-disk
  revocations file — may insert into the revocation list, and charges a reason
  for each refusal. `checkSessionRevocation` summed two of the three:
  `RevokeOversize` and `RevokeCapacity`, but not `RevokeFarFuture`. A node that
  dropped only far-future entries took the `diagOK` branch and printed "no
  refusals, no drops" — on the one authenticated surface whose own contract is
  that a dropped entry "means a session an operator deliberately killed may
  still authenticate, here or on another node" (CWE-778; the underlying drop is
  CWE-613).

  `RevokeFarFuture` is the reason with a benign trigger, which is what made the
  omission matter. `admitUntrustedLocked` refuses a gossiped entry whose expiry
  exceeds `now + MaxSessionLifetime + revocationExpirySkew`; that is exactly 7
  days plus 1 hour, and `POST /api/session-timeout` admits `hours` up to 168 —
  so at the maximum *supported* session TTL the entire inter-node clock-skew
  budget is one hour. In a cluster at `session_timeout: 168h` with a peer whose
  clock runs more than an hour ahead, that peer's legitimate revocations are
  dropped on the receiving node, the revoked cookie keeps authenticating there
  for the remainder of its life, and Diagnostics affirmatively said revocation
  was healthy. The count is now summed, the row names the expiry bound among the
  causes, and the operator action names clock skew as the benign cause to check
  FIRST — this file's own rule that a refusal surface must not assert an attack.
  The bound itself is unchanged: widening `revocationExpirySkew` is a security
  behavior change and is recorded as an owner decision instead.
- **Peer-supplied Control Plane addresses reached the Data Plane's process log
  unsanitized (CWE-117).** `applyAddressesLocked` adopts the CP config
  snapshot's `cp_addresses` verbatim into the client's address list and states
  that both lists "are peer-supplied … so they are untrusted log values under
  the CWE-117 rule" — but four older sinks in the same file printed an address
  from that same list with a bare `%s`: both of `connect`'s lines and both of
  `failover`'s. `validateConfigSnapshot` count-caps `cp_addresses` at 100 and
  never validates an entry as `host:port`, so a newline inside one forged
  records in the DP's process log and in every downstream syslog/OTLP consumer.
  All four now use `sanitizeLog` with `%q`, and the failover line sanitizes the
  wrapped error too, since it carries the same address. Pinned by a source gate
  so a fifth sink cannot reintroduce it. A hostile Control Plane already
  dictates the Data Plane's policy, so the marginal impact is log integrity —
  but the convention is the convention, and the inconsistency sat inside one
  file.
- **A sixth log sink retained the decrypted inner request path, unbounded, after
  CHAOS-92 bounded the other five (CHAOS-92e).** The CHAOS-92 sweep enumerated
  three retaining sink families and clamped each at a chokepoint, with a source
  gate to keep future sinks bounded. The gate matches call sites carrying both
  `sanitizeLog(` and `URL.Path` — so it never examined
  `fileblock.LogBlock`, which sanitizes in the callee (`obs.Sanitize`, the
  independent internal twin, ADR-0003) and writes the client-chosen path into the
  50 MB/one-archive rotating process log as `FILE_BLOCKED (tunnel %s)`. Six
  `emitFileBlock` call sites reach it, four of them passing `req.URL.Path`
  straight from the decrypted inner request.

  It is worse per request than the five that were fixed: those are fed by a path
  net/http caps at `MaxHeaderBytes + 4096`, while this one is fed by
  `http.ReadRequest` on the decrypted stream — `readRequestLimit(b,
  math.MaxInt64)` over a `textproto.ReadLine()` with no limit — so the inner
  request line is unbounded on the wire. Measured through the emitter: a 1 MiB
  path wrote 1 048 646 log bytes, and a 1 MiB path of `0xFF` wrote 4 194 375,
  because `obs.Sanitize` folds control bytes but `0xFF` is not one and `%q`
  renders each as the 4-character `\xff`. Every write succeeds, so the logsink
  backpressure counter and every storage-health surface stay green while the
  retained record rotates away (CWE-778, OWASP A09:2021). Reachability is the one
  CHAOS-69 named for the inner path — an allowed destination with SSL inspection
  enabled — not CHAOS-92's stock-install reachability.

  `emitFileBlock` now clamps with the sweep's own `boundRetainedPath`, inside the
  `fileblock.LogBlock` argument so the sanitiser's scan and its copy are bounded
  too. It is package main's only route into `LogBlock`, so one edit bounds all
  six call sites, and a source gate now fails on a direct
  `fileblock.LogBlock`/`BlockConn` call from package main. **Enforcement and the
  client-visible response are untouched**: every matcher ran on the whole value
  at the call site before the emitter, and the 403 body derives from the
  extension and source only — pinned by a control that asserts the emitted bytes
  are identical at 16 B and 1 MiB. Recorded with its measurements in
  `roadmap/CHAOS-ENGINEERING-REVIEW.md` §53.11.
- **The `file_profile_resolution` diagnostics row went blind to the very rules
  SEC-POLICYACTION-1 taught the request path to honour.** That change made
  `applyPolicyDecision` (`proxy.go`) dispatch on `canonicalPolicyAction`, which
  folds ASCII case and resolves an EMPTY action to Allow — so a rule persisted as
  `"allow"`, `"ALLOW"` or with no action at all (the shape an operator-managed
  `policy_file` or a replayed CP snapshot produces) now reaches the `ActionAllow`
  branch and really does have `FileProfileBlocked` evaluated against it.

  `fileProfileEnforced` (`file_profile_health.go`) still compared the RAW action,
  so it answered "not enforced" for exactly those rules. With a dangling
  `FileProfileID`, every file-bearing transaction such a rule matched was blocked
  fail-closed — correctly — while the row reported `ok`. That row exists for one
  purpose: to tell an administrator whose users report "downloads are blocked"
  why, instead of sending them to SSH and `grep`. Its own stated contract is
  "ever evaluated by `FileProfileBlocked` on the request path", so it has to read
  the action the way the request path does, and it now does. Enforcement is
  untouched — the predicate feeds only the diagnostics row — and the negative
  control is pinned too: an action this build cannot dispatch at all is blocked
  outright by the fail-closed branch, so its profile is never evaluated and the
  predicate still says so.
- **An unauthenticated request chose how many bytes Culvert retained, on a stock
  install (CHAOS-92).** `r.URL.Path` was the last unbounded client-chosen string
  on the data path. Its two siblings were already closed and neither reaches it:
  `request_tracing_bounds.go` (SEC-REQID-1) bounds the tracing headers and
  `proxy_host_bounds.go` (CHAOS-69) bounds the destination authority, whose own
  "deliberately NOT done" note named the path as its own finding. The path was
  copied, unbounded, into three retaining sinks — the process log (5 sites), a
  **buffered HTML response body** (5 sites, through `serveBlockPage`) and the
  request-log `URI` field (4 sites, through `policyLogURI`). Measured through the
  real `handleRequest`, with no authentication, no operator opt-in and no
  configuration (`.exe` is in the shipped `fileblock.DefaultBlockedExts`): a
  1 048 581-byte path wrote **1 048 636 bytes** to the process log and served a
  **5 245 731-byte** block page when filled with `'`, because `html/template`
  escapes it to the 5-byte `&#39;` — so the amplification factor was the
  client's to choose. Wire-verified rather than only via `httptest`: that target
  arrives as `r.URL.Path` byte for byte through a real `net/http` server, since
  the proxy listener sets no `MaxHeaderBytes` and net/http's 1 MiB default
  governs the request line. The process log is a 50 MB `fileutil.RotatingFile`
  keeping exactly one archive, and every write **succeeded**, so the logsink
  backpressure counter, `storageDegraded()` and `storage_write_failed` all
  reported healthy while the whole retained forensic record rotated away in
  seconds (CWE-778, OWASP A09:2021). The bound is on **retention, not
  admission**: a long path can be legitimate, unlike an authority RFC 1035 caps,
  so refusing the request would be an egress outage — but a truncated path is
  still a usable log value. Every matcher continues to decide on the **complete**
  path; clamping what a matcher sees would be fail-open, because truncating the
  end removes the extension a file-block rule matches. `serveBlockPage` and
  `policyLogURI` clamp at the chokepoint so one edit bounds every present and
  future sink, the five log sites clamp inside the `sanitizeLog` argument so the
  scan and its copy are bounded too, the cut backs off to a UTF-8 boundary, and
  the retained value carries an explicit marker naming the original length. New
  counter `culvert_retained_path_truncated_total`. Thirteen gates, seven of them
  verified to fail against the pre-fix tree with the measured numbers and two of
  them source gates, so a new sink reintroduces the defect loudly. Full
  write-up: `roadmap/CHAOS-ENGINEERING-REVIEW.md` §53, which also records the
  CDR-sidecar filename sink and a >8 KiB refusal tier as open owner decisions.

- **An inspected tunnel's inner-host pin accepted an authority `net/http` will
  not send, so the upstream received no authority at all.** A CONNECT tunnel is
  authorized once, against the CONNECT authority, and `innerHostPinnedToTunnel`
  (`inspect_host_pin.go`) exists so an inner request cannot name a different
  destination on that already-authorized tunnel. Its own documentation refuses
  an EMPTY inner host for a specific reason: `Request.Write` serializes that as
  a literal `Host: `, and a shared front end answers an authority-less
  HTTP/1.1 request from its default or fallback vhost — a destination policy
  never evaluated, with the log row, scan verdicts and CDR decisions all still
  naming the CONNECT host.

  That refusal was reachable **through** the comparison. `hostutil.StripHostPort`
  ends in `net.SplitHostPort`, which splits on the last colon and never
  validates the port, so `Host: allowed.example.com:0/x` reduced to the
  authorized host and PINNED — while `Request.write` applied
  `httpguts.ValidHostHeader` to the same value, found the `/`, and (with
  `usingProxy=false`) zeroed the authority entirely. Measured on go1.27.3:
  `allowed.example.com:0/x`, `allowed.example.com:443?x` and
  `allowed.example.com:@blocked.example.com` all pinned and all put `Host: ` on
  the wire. This is the same defect class #1632's own review fixed for square
  brackets ("the pin compares a REPAIRED value while the origin receives an
  UNREPAIRED one"); two further repairs did the same thing and were not covered.

  The second was IDNA case. `NormalizeHostStrict` lowercases before
  `idna.ToASCII` while `httpguts.PunycodeHostPort` does not, and punycode
  carries case in its payload — so against tunnel `xn--bcher-kva.example.com`,
  an inner `BÜCHER.example.com` pinned while the wire carried
  `xn--BCHER-2pa.example.com`: a different label, not a case variant
  (`bcher-2pa` != `bcher-kva`), i.e. a name policy never evaluated. The comment
  asserting a U-label inner host was safe is corrected rather than left to
  invite a maintainer back toward the hole.

  Both are closed by one rule instead of a list of refused spellings:
  `innerAuthorityAsSent` canonicalizes through the SAME helpers `net/http` and
  the HTTP/2 header encoder use and refuses anything they would not forward
  verbatim, so the pin cannot drift from the wire because it now reads the
  wire's own definition. Nothing a conforming client sends is newly refused —
  every pre-existing accepted spelling (trailing root dot, lowercase U-label,
  `host:443`, bracketed IPv6, IP-literal tunnel) still pins, and the two shapes
  that look divergent but are the same destination (an ASCII-case A-label
  variant, an empty port) are now pinned explicitly by the table.
  `TestInnerHostPin_WireAgreesWithWhatWasPinned` is the differential oracle and
  the reason this is not a spelling list: for every inner authority the pin
  accepts, it drives the real `ReadRequest` → `Request.Write` path and asserts
  the serialized `Host` still canonicalizes to the tunnel host, with a
  non-vacuity guard. `go.mod` is unchanged (`golang.org/x/net` was already a
  direct dependency).

- **The new access-list Diagnostics row served the admin-only UI allowlist
  posture to a viewer.** `checkAccessCIDRLists` joined the operator contract,
  which `/api/diagnostics` and `/api/health/explain` serve at RoleViewer, but
  was not classified in `redactContractForRole` — so a viewer or operator read
  the rejected entry verbatim (the message embeds
  `fmt.Errorf("invalid IP/CIDR: %s", c)` over the configured value) together
  with whether the allowlist IN FORCE is empty, spelled out as "the admin UI
  accepts every client IP", or else its entry count. `GET /api/ui-allow-ips`
  requires RoleAdmin in both methods and nothing else reads that list, so the
  row answered "is admin-UI IP restriction in force on this node?" — the
  question asked before trying a stolen credential from off-network — to the
  lowest authenticated role.

  `accessCIDRListsRows` now renders the row twice from ONE read of the
  rejection state (the `rosterViewerRow` discipline, so the two renderings
  cannot straddle a settings save and disagree), and `redactContractForRole`
  swaps in the non-admin rendering. The status stays `warn` below admin — a
  non-admin must still see that a network list is misconfigured and escalate —
  and an `ok` row is returned identical to both roles. The **trusted-proxy**
  clause is deliberately carried through unredacted: `GET /api/settings/network`
  already returns `trusted_proxy_cidrs` at RoleViewer, so withholding it would
  cost an operator remediation detail without concealing anything. Both
  directions are pinned, including an over-redaction control and a positive
  control that the admin keeps the full evidence.

- **`scripts/install.sh` had two disagreeing answers to "is this secret already
  set?", and the looser one guarded the cluster session key.**
  `secret_already_set` knows what docker compose resolves — `VAR=`, `VAR=""`,
  `VAR=''`, `VAR=` with an inline comment and a CRLF-only value are all EMPTY —
  while `persist_host_env_session_secret` kept its own `^VAR=.+`, which matches
  every one of those shapes. Measured against both revisions of the real
  function: for all four empty shapes the installer reported "already
  configured" and declined to persist the operator's `CULVERT_SESSION_SECRET`,
  so compose interpolated `""` and every node fell back to its own random
  per-process signing key instead of the shared cluster key — admin sessions
  silently stop validating across nodes, which is exactly the failure that
  function's header comment exists to prevent. (The fallback key is freshly
  random, so this is a cluster-availability failure, not a weak-key one.)

  Both callers now delegate to one predicate, `env_file_value_set`, reporting
  0 = set, 1 = absent or empty, 2 = could not read. That third code is
  load-bearing and preserved: the session-secret path must tell "no entry, safe
  to add" from "could not look", because confusing them overwrites a signing
  key it was unable to read. An empty entry is overwritten; a non-empty one is
  still never touched.

### Fixed

- **`README.md` documented the opposite of CDR's fail-closed guarantee.** The
  `-cdr-fail-mode` row still said that when no Sluice instance is available at
  all "CDR is skipped and the file passes through in either mode" — the exact
  behaviour the CDR unavailable fail-mode fix replaced, and which
  `docs/OPERATIONS.md` §6 and `config.example.yaml` were updated for while the
  README was not. An operator reading it concludes `fail_mode: closed` does not
  cover a Sluice outage, the one case the setting exists for. The row now states
  that the configured mode applies when no instance can be called, that `open`
  passes the file through unsanitized and that `closed` refuses it with block
  reason `cdr_unavailable`, counted in `culvert_cdr_fail_closed_total`.
  `TestREADMEDocumentsCDRUnavailableFailMode` asserts the row against the code's
  own `cdrUnavailableBlockReason` constant, with negative controls for the
  retired claim and a positive control that the fail-open half is still
  documented.

- **Two merge-gate workflows reached their actions through MUTABLE tags, and a
  repository-wide gate now refuses that.** `.github/workflows/pr-api-governance.yml`
  (designed to be a REQUIRED branch-protection check) and
  `.github/workflows/api-contract.yml` referenced `actions/checkout@v7.0.1`,
  `actions/setup-go@v7.0.0` and `actions/cache@v6` by tag while every one of the
  hundred-plus other `uses:` refs under `.github/` is pinned to a 40-character
  commit SHA with a `# vX.Y.Z` comment. A tag is a pointer its owner can move, so
  the commit that actually ran inside those jobs was not the commit anyone
  reviewed — and because those jobs *are* the gate, a moved tag could make a
  blocking check report green without having gated anything. That is the same
  failure shape `codeql_action_pin_test.go` exists for, where a mis-pinned SAST
  action produced a job that looked like it ran and executed zero queries.

  The convention was enforced per file, so these two drifted and kept drifting:
  the dependency sweep that rewrote `actions/setup-go@v7` to `@v7.0.0` touched
  those exact lines and left them mutable, because nothing failed. All six refs
  are now SHA-pinned to the revisions already in use elsewhere in the tree, and
  `workflow_action_pin_test.go` enforces the rule across every workflow and
  composite action under `.github/` — so a new file, or a bump that rewrites a
  ref, cannot reintroduce a mutable one silently.

  The gate enumerates refs by **parsing the YAML**, not by scanning for
  `^uses:`, because the line-based first revision had a hole of exactly the kind
  it exists to catch: YAML also accepts `uses : x@v7`, `"uses": x@v7`,
  `'uses': x@v7` and the flow mapping `- {uses: x@v7}`, all four of which
  GitHub Actions honours and none of which that regex matched — while the
  hundred-odd refs it did match kept its "scanned nothing" guard satisfied. A
  mutable tag in any of those spellings would have run with the gate green.
  `TestWorkflowActionRefEnumerationSeesEveryUsesKey` pins all four plus the
  job-level reusable-workflow form, so a future simplification back to a regex
  fails instead of silently un-seeing refs. A SHA pin's comment must also now
  *name* the revision (`# v1.2.3`, or `# branch @ YYYY-MM-DD` as `ci.yml` pins
  an action with no releases); the first revision accepted any `#`, so `# TODO`
  passed a check whose own message promised it named a release.

  Two further holes in the same gate, both measured: a repeated pin was checked
  against the FIRST occurrence's line, so in a file with fourteen
  `actions/checkout` steps — or the two `actions/setup-go` steps in
  `pr-api-governance.yml` — a later pin with no comment inherited an earlier
  one's `# v7.0.1` and passed; one ref is now emitted per matching source line.
  And a `docker://` container action was skipped entirely, on the incorrect
  grounds that registry digest rules covered it (they govern the release
  catalog's images, not a workflow's `uses`), so `docker://alpine:latest` would
  have satisfied every applicable check; it now needs an `@sha256:` digest, with
  `TestWorkflowDockerDigestRuleBites` proving the rule on fixtures because
  nothing in `.github/` uses the scheme yet.

  `slsa-framework/slsa-github-generator` is a recorded exception with its reason:
  the generator verifies its own provenance against the invoking tag and refuses
  to run from a SHA, so pinning it would disable release provenance rather than
  harden it. The exception is still constrained to an exact
  `vMAJOR.MINOR.PATCH` release, never a moving major alias, and the test fails if
  an exception stops being used — the allowlist is exact, not a dumping ground.
  No runtime, policy or proxy behaviour changes; this is CI trust only.

  The three `actions/checkout` steps in those two workflows also set
  `persist-credentials: false` (CWE-522, CodeRabbit on this PR): each job runs
  PR-authored code, which could otherwise read the run's `GITHUB_TOKEN` from
  `.git/config`. Nothing in them needs the credential — the base-ref
  `git fetch` reads a public repository.

### Changed

- **The pinned Go toolchain moves from go1.26.10 to go1.27.3.** The `go.mod`
  `toolchain` line, both production Docker builder stages and the maint-agent E2E
  builder move together, so CI, release binaries and images keep using one
  compiler (`toolchain_consistency_test.go`). The images are pinned to the
  multi-arch index `golang:1.27.3-alpine@sha256:b8c9b82a…`. The module minimum
  (`go 1.26.6`) is unchanged. The two prerequisites from roadmap/CI-REDESIGN.md §20
  landed first: golangci-lint v2.15.0 (#1683) and graceful GOAWAY for inspected
  HTTP/2 tunnels on the Go 1.27 x/net server (#1684). 1.27.3 rather than 1.27.2,
  because 1.27.2 is still affected by GO-2026-6809. The CI gates keep the gosec
  v2.29.0 rules, but now build them from a `tools/gosec` module that raises only
  `golang.org/x/tools` to v0.52.0. The released v2.29.0 cannot load Go 1.27
  export data, and v2.30.0 regressed package loading.

### Fixed

- **The backup archive was published world-readable, and a restore accepted an
  archive that was never encrypted (CHAOS-82).** Four defects on the two paths
  that decide who can read a backup and what a restore will install, all
  recorded with file and line by the CHAOS-74 sweep and unfixed until now.

  `writeBackupTarball` used `os.Create` — 0666 before umask, so **0644** as
  measured — with no `Chmod` anywhere in the file, while the archive aggregates
  files that are individually 0600: `cluster-ca.key` (the fleet's MITM-capable
  CA key), `ui_users.json` (password hashes, TOTP secrets) and
  `idp_profiles.json` (OIDC client secrets, LDAP bind credentials). Any local
  account or co-mounted container with read access to `/backup` obtained all of
  it. The same writer published through a fixed, symlink-following
  `<out>.tmp`: with the pre-fix writer restored, a symlink planted at that path
  **received the entire archive** (687 bytes onto a canary outside the output
  directory) and `runBackup` returned success — an exfiltration primitive for
  the CA key available to anyone who can create one directory entry in
  `/backup`. `os.Create` also truncates, so a stale file there was destroyed,
  and two concurrent backups to one `outPath` shared an inode and interleaved
  into a corrupt archive reported as success. Publication now goes through
  `os.CreateTemp` (`O_EXCL` on an unpredictable name) plus an explicit `Chmod`
  to 0600, which is what makes the mode independent of the process umask;
  streaming is preserved.

  On the restore side, `loadAndMaybeDecrypt` chose the envelope by magic-byte
  sniff and consulted the passphrase **only** in the encrypted branch, so a
  plaintext blob returned before the passphrase was ever examined. Anyone who
  could write into `/backup` substituted a hand-built unencrypted tarball
  carrying their own `ui_users.json`; the manifest is self-referential, so every
  content check still passed and the restore installed an attacker-authored
  admin roster. A plaintext archive is now refused when a passphrase is
  configured, symmetric with the KDF-iteration downgrade `backupcrypt` already
  refuses at the header level. The legitimate plaintext restore — no passphrase
  supplied, which is what the maintenance agent already does for an unencrypted
  archive — is unaffected, and is pinned by a negative control.

  Finally, `parseEncHeader` enforced an iteration floor and no ceiling, and
  `DecryptBlob` fed the archive-declared count straight to `pbkdf2.Key`: with
  the new `encMaxIters` removed, a declared `0xFFFFFFFF` did not complete in
  280 s before the harness killed it, against an instant refusal with the
  ceiling in place — four attacker-controlled header bytes on a blob that could
  never have authenticated.

  Every gate was mutation-tested against its reverted fix. Two backup-plane
  rows stay open with their reasoning recorded (§51.5): unbounded restore
  memory, and `modeFull` silently dropping live artifacts absent from the
  archive — the latter needs an operator-contract decision because
  `admin_settings.json` is where `default_action` persists.
- **The syslog/SIEM writer handle was published without synchronization, so a
  "disable forwarding" click could abort an in-flight proxy request, and every
  runtime retarget leaked a delivery goroutine and its collector socket
  (CHAOS-78).** `globalSyslog` was a plain `*syslogWriter`: written at runtime
  from the admin handler goroutine (`InitSyslog` via `POST /api/syslog`; the
  disable branch stored `nil`) and read unsynchronized on the proxy request
  path at `persistLogEntry` — the chokepoint every request-log record flows
  through — and on the audit SIEM hook.

  The nil check and the dereference were two separate unsynchronized loads, so
  a request goroutine could pass the check and then dereference the `nil` the
  disable branch had just stored. Measured: 14 reported data races under
  `-race` between `persistLogEntry` and `InitSyslog`. The proxy crash guard
  contains the panic per request, so the cost is a dead request or tunnel and a
  crash record, not a dead appliance.

  The subtler half is the one a nil guard would **not** have fixed. The engine
  sets its queue in `startAsync` *after* the struct literal and treats a zero
  queue as "deliver synchronously" — a path that holds the writer mutex across
  three serialized network ops, which the engine's own comment puts at ~15 s
  worst case (`writeTimeout` + dial + `writeTimeout`). A plain pointer write
  carries no
  release edge, so on a weakly ordered target (the appliance ships
  `linux/arm64`) a request goroutine could observe a non-nil writer whose queue
  was still zero, take that path, and pay ~15 s on the data path with every
  other logging caller queued behind it — exactly the proxy-wide stall the
  async design exists to prevent, reached through the pointer rather than the
  engine.

  The handle is now an `atomic.Pointer[syslogWriter]` read once into a local at
  every site, which supplies both the single load and the release edge. This is
  the pattern the codebase already uses for every other hot-path-read,
  runtime-reconfigured global (`globalLogStore`, `logSink`, `obs.sink`, and the
  syslog engine's own `panicObserver`); the pointer holding the engine was the
  one left plain.

  Separately, `InitSyslog` published over the previous writer without closing
  it, and the engine's `drainLoop` exits **only** via `Close` — so each runtime
  SIEM retarget stranded one delivery goroutine and one collector socket for
  the life of the process (measured: 8 retargets, 8 leaked, 7 still live after
  a disable). `InitSyslog` now closes the writer it displaces. The enable
  branch also dereferenced the global twice more with no nil guard at all, so a
  second admin's concurrent disable nil-panicked the admin handler; the format
  now resolves from one load.

  Closing that leak opened a narrower hole, which review caught: `send` read
  `closed` and only *then* enqueued, while `Close` closed `stop` and let
  `drainLoop` exit — so a sender preempted between its check and its enqueue
  could put a line on a queue whose drain goroutine had already returned.
  `Close` never closes the channel, so the send succeeds and the line is
  **neither delivered nor counted in `Drops`** — silent loss, in audit records.
  The leak had been masking it: a leaked `drainLoop` keeps running, so that same
  line was delivered. `Close` now stores `closed`, waits for in-flight senders,
  and only then closes `stop`, so every line is either delivered or counted
  provided the sender clears within the bound; the wait is bounded so it can
  never hang shutdown, and that bound is the one path that can still lose a
  line. Measured: against the pre-fix ordering the conservation test fails 6
  runs in 10, typically losing exactly one line (`delivered 2091 + dropped 5273
  = 7364; want exactly 7365 sent`), and the `Close`-waits-for-a-sender ordering
  is ~108 µs pre-fix against a required 150 ms.

  Closes `OBS-1` of the chaos register's §42, which nominated it as the
  recommended first follow-up. Gated by a `-race` reconfigure-versus-request
  test, a goroutine-leak test counting delivery goroutines by stack, an AST
  wall (the handle stays an `atomic.Pointer`, only `syslog.go` names it, and
  no caller may write `syslogHandle().Method()`), and a compile-time type
  assertion. Full write-up: `roadmap/CHAOS-ENGINEERING-REVIEW.md` §45.

- **Built with Go 1.27, the shutdown drain sent no GOAWAY to inspected HTTP/2
  tunnels.** Under `go1.27 && !http2legacy`, x/net v0.61 compiles a different
  `http2.Server` (`server_wrap.go`) that wraps net/http's HTTP/2 server. That
  server serves a `ServeConn` call with a non-nil `BaseConfig` through a one-off
  copy of the `http.Server`, so the shared base server's `Shutdown` never reached
  the tunnel. Clients kept opening streams until the 15 s drain deadline
  force-closed them along with their in-flight streams. This was not a policy
  bypass, but it broke the graceful-drain contract;
  `TestH2InspectDrain_GracefulGoawayCompletesInflightAndRefusesNew` failed 10/10
  on go1.27.3 and passed on go1.26.10. Inspected tunnels are now served through a
  single `serveConn` wiring that picks `BaseConfig` per implementation. The pick
  uses the same build constraint x/net uses, so both always agree. The wrapping
  server gets a nil `BaseConfig` and serves through the base server it was
  configured with. The original server keeps the base server, which is the only
  place it reads `MaxHeaderBytes` from. Both toolchains now get the GOAWAY and
  keep every limit. New tests pin the advertised `MAX_CONCURRENT_STREAMS`,
  `MAX_FRAME_SIZE` and `MAX_HEADER_LIST_SIZE`, a `431` for an over-cap header
  list, the per-tunnel context, and the GOAWAY re-fire for a tunnel that starts
  after the first wave. The default build (go1.26.10) is unchanged in behavior.

- **A bodyless `POST`/`PUT` was forwarded upstream re-framed as
  `Transfer-Encoding: chunked` instead of the client's own `Content-Length: 0`.**
  Both legs that serialize an outbound request wrapped the request body
  unconditionally — `prepareHTTPForward` with a `MaxBytesReader` plus a
  `countingReader`, and the SSL-inspected H1 inner loop with a
  `stallDetectReadCloser`. `net/http` keys its no-body fast path on the
  **identity** of `http.NoBody` (`Request.outgoingLength` returns 0 only for a
  nil body or that sentinel, and reads `ContentLength == 0` on any other
  non-nil body as "length unknown"), so wrapping the sentinel told
  `newTransferWriter` the length was unknown. For methods that normally *do*
  carry a body it does not probe — it chunks. A forward proxy re-framing a
  request the client framed correctly is wrong on its own terms, and origins,
  WAFs and CDNs do not all treat the two forms alike.

  Both legs now leave the sentinel alone, so the origin sees the client's
  framing. Pinned by `TestHandleHTTP_EmptyBodyPOSTKeepsContentLengthZero` on
  the plain-HTTP leg and `TestInspectInnerLeg_EmptyBodyKeepsClientFraming`
  through a real CONNECT / forged-leaf tunnel; reverting either guard alone
  fails its own test. The cost half of the same root cause is under
  **Performance**.
- **go-ldap v3.4.15 would have reclassified malformed-packet faults as "the directory answered".** v3.4.15 adds `ErrorMalformedPacket` (207) for decode
  faults that v3.4.14 returned as plain errors, which `ldapUserBindIsUnreachable`
  treats as unreachable. With the client-error ceiling still at 206, those faults
  would have fallen outside the range: they would no longer arm the CHAOS-47
  cooldown and would count as reachability evidence that clears it. The ceiling
  now tracks `ErrorMalformedPacket`, so classification is unchanged across the
  bump; `TestLDAPClientErrorCeil_TracksLibrary` caught the drift.

- **A Control Plane gRPC listener fault terminated the whole appliance, and a
  listener that died after binding was silent and terminal (CHAOS-71).** The CP
  boot path had exactly one error branch — `logFatalf("ControlPlane gRPC: %v",
  err)` — reached from `initCluster`, which `main.go` runs **before**
  `initSOCKS5`, `startAdminUI` and `buildAndStartProxyServer`. So an occupied
  gRPC address or an unreadable mTLS pair meant no proxy, no SOCKS5, no admin
  UI and no health endpoint; under `restart: unless-stopped`, an unattended
  crash loop recoverable only with shell access.

  Both triggers were reproduced against the real binary (`EXIT CODE: 1`,
  `proxy http_code=000`, `adminui http_code=000`). Neither is visible to
  `validatePortCollisions`, which compares the proxy, UI and SOCKS5 ports to
  each other — the CP gRPC address is not even among the three it knows about.
  Process death is *not* "fail closed": it delegates the posture to your
  topology (an explicit-proxy fleet loses all egress; a PAC/WPAD fleet with a
  `DIRECT` fallback goes unfiltered).

  Separately, `srv.Serve(ln)` ran in a bare goroutine whose only branch was one
  log line, so a listener that died after a successful bind never rebound —
  while `clusterRole.role` and `grpcAddr` stayed set, so
  `GET /api/cluster/status` reported a healthy Control Plane with its listening
  address, forever, on a node with no listener. This was the only listener in
  the appliance with no health plane at all.

  The listener now has a supervisor owning bind → serve → rebind: the boot path
  is non-fatal and retries at a bounded rate (1 s doubling to 30 s, ±20 %
  jitter, interruptible by shutdown), the mTLS material is re-read on every
  attempt so a cert-manager/certbot rotation self-heals with no restart, and a
  serve that ends is counted, classified and rebound. **The node's role is
  claimed only on an observed bind** — while the listener is down it reports
  `standalone`, so every surface says what is true — and the HA leadership
  resume rides the same rule, so a node never asserts a term it cannot
  exercise. The live admin path (`POST /api/cluster/mode`) keeps its
  synchronous `409`: an admin at the keyboard can retype an address, and a
  background retry there would report success for a Control Plane that may
  never exist.

  New surfaces, all on the **proxy** port (the CP's own gRPC port cannot report
  that it is unreachable): a `cp_grpc_listener` diagnostics row with a
  per-reason operator action, a **report-only** `/ready cp_grpc` row, a
  `cp_grpc` field on `/health`, and
  `culvert_cp_grpc_{up,unavailable,bind_failures_total,binds_total,bind_backoff_seconds}`
  — emitted only on a node that asked to be a Control Plane. Page on
  `culvert_cp_grpc_unavailable == 1`, not on `up == 0`, which drops for the few
  seconds of rebinding after an ordinary rollout.

  **Action required for alerting:** `cp_grpc_listener_down` is a new alert event
  (named per the `<contract-row>_down` convention) and will not reach existing
  webhooks until you add it to their subscriptions — the admin UI's webhook
  editor now lists it. See `docs/operator/cp-grpc-listener-recovery.md`.

  Also fixed in the same change: `StopControlPlaneGRPC` read
  `clusterRole.grpcSrv` with no lock — latent while that field was written once
  per process, a real data race once anything rebinds. The handle now lives on
  the supervisor under its own mutex.

  **HA interaction.** A lease-mode HA leader whose CP gRPC listener has been
  unavailable past the 30 s threshold (or whose listener supervisor stopped)
  now **stops renewing its fencing lease**: the fence no longer vouches for a
  leader no Data Plane or standby can reach, the node self-fences when its
  last confirmed window ends, and the standby acquires the lapsed lease
  through its ordinary fence-gated promotion. Renewal resumes if the listener
  serves again before the window ends. HA promotion through the synchronous
  `enableControlPlane` no longer risks main's `clusterRoleMu` self-deadlock
  (the pre-bind snapshot is taken with the role lock released), a promote whose
  listener cannot bind leaves the node a retryable standby, and once the role
  is committed the Data Planes' CP address list is updated to name the
  promoted node instead of only the dead leader (the CHAOS-71
  address-republish rider, ported from #1618). That update MERGES onto the
  latest committed config snapshot (it can no longer roll back an admin
  publish that committed in between), and a rejected update fails the
  activation — the role is rolled back and the listener retries — instead of
  reporting success. Because a retried bind can land long after boot, the
  activation also aborts once shutdown has begun (no HA resume after
  `globalHA.Stop`), never replaces an established Data Plane role (refused,
  alerted as `cp_grpc_listener_down`, reason `role_conflict`), and re-reads the
  persisted HA config before resuming leadership. The other way round,
  Data-Plane startup no longer overwrites a Control Plane role the listener
  already claimed: every role write goes through one arbiter, the role claimed
  first wins, and the refused claim is reported FAIL by the `cluster_posture`
  diagnostics row; every reader of the role takes one locked snapshot.
  A serve that ends on its own now stops the retired gRPC server (closing the
  Data Planes' transports to it) before rebinding, shares the bind path's
  threshold clamp and alert latch, and a full config publish can no longer
  overwrite the CP address list the activation published. A self-fenced
  ex-leader whose CP listener is still dark is no longer AUTO-promoted
  (manual promotion unchanged). Every exit of the listener supervisor —
  including a panic between bind and serve — now releases the server, the
  socket and the role claim it holds; a terminal listener failure pages even
  after a recoverable episode already paged; and a full publish validates the
  snapshot with the CP address list it actually commits. With HA on, every
  Control Plane RPC is now leader-gated: a self-fenced standby whose listener
  rebinds refuses Data Planes with a retriable error, so they fail over to the
  new leader instead of staying on its stale config; and a listener alert
  raised before the webhooks load at boot is queued, not lost. Every HA
  transition (enable, resume, standby entry, promote, self-fence) now
  republishes the Control Plane address list itself, so a persisted leader
  whose listener bound late no longer hands Data Planes a list without its
  standby. If that republish is rejected (a config at its sync size cap),
  the transition still stands; a new `cp_address_list` diagnostics row reports
  the pending list until a background retry publishes it. An unreadable
  Control Plane TLS file now reports `tls_certificate` instead of the
  bind-permission advice. Address-list publishes now carry the current
  fencing epoch, so Data Planes accept the new list after HA is enabled, and
  they no longer clear the "config publish rejected" banner left by an
  earlier rejected config change. A listener-down alert raised before the
  webhooks loaded is dropped if the listener recovered first. Concurrent config
  publishes now commit only onto the exact version they validated against, so a
  publish racing an HA promotion can no longer ship a stale fencing epoch. A
  re-promoted former leader no longer republishes below the version it
  replicated from the new leader. A Control Plane listener whose socket dies
  right after every bind is now treated as one continuous outage, so it pages
  and (in lease mode) gives up the fencing lease instead of resetting each
  cycle. An outage closes only after 60 s of stable serving. An admin HA
  enable made while a restarted leader is still re-acquiring its fencing lease
  is no longer overwritten by the restart's resume. A node whose Control Plane
  listener ends terminally (a Data Plane role won, or the loop crashed) no
  longer reports itself as an active Control Plane. The rebind-backoff gauge
  reads 0 while the listener serves. A restarted leader that is still waiting
  out its fencing lease when shutdown begins now stops at once instead of
  outliving the shutdown watchdog. A `role_conflict` listener alert now
  describes a local CP/DP configuration conflict rather than a fleet outage. A
  Control Plane address list that keeps being rejected at commit now pages
  once per episode instead of every 30 s. A refused admin/promote
  activation (409) now leaves the listener health plane unconfigured instead
  of reporting `stopped`. The rebind backoff now resets to its 1 s floor after
  a serve that stayed up for 60 s, so a one-off socket loss after a long
  healthy run is not charged the 30 s ceiling. The `ha_resume_unfenced` page
  for an HA config that cannot be read at boot and the read-only
  leader-resume page are now queued until the alert webhooks load, so they
  are no longer lost at boot; each is dropped if its condition cleared first.
  A fencing grant that a leader resume, promotion or lease recovery took but
  did not install (the HA config changed during the acquisition, shutdown
  began, another HA transition claimed the node, or the promotion failed) no
  longer leaves the node advertising that epoch with no role; the lease still
  runs out its TTL. An ordinary config publish no longer re-adds a Control
  Plane address that a terminal listener exit withdrew: a full publish now
  always carries the committed address list, and only the owned address
  publish changes it. While rewrite management identity is degraded, a
  Control Plane activation or HA promotion no longer fails at its address
  publish (full config publishes are still refused). A Control Plane listener
  that ends terminally is reported down, and stops renewing the fencing lease,
  before its address is withdrawn rather than after.

- A damaged data volume could kill the gateway outright from the proxy request
  path, with no log line and no containment available (CHAOS-74, §41 of the
  chaos register). badger v4 reads every `.sst` table through a memory mapping
  and removed the option to do otherwise, so when the pages behind that mapping
  stop existing — the file shrinks, the volume detaches, a page fault returns
  EIO — the read raises SIGBUS. Go delivers that as `fatal error: fault` rather
  than a panic, so neither `recover()` nor `crashguard.go` could see it. The
  Layer-2 community category lookup runs on the data path for every request that
  resolves a host category, which made one damaged table a total, evidence-free
  outage and, the damage being on disk, a restart loop rather than a recovery.

  Reproduced against the real store and contained with
  `debug.SetPanicOnFault`, which delivers a fault on mapped memory as a
  recoverable panic; the guard is armed once per domain walk and re-panics
  anything that is not a mapping fault, so a genuine bug still reaches
  `crashguard` instead of being reported as a failing disk. A Linux node that
  takes such a fault now latches Layer-2 categorisation off and keeps serving on the
  admin-managed Layer 1, which is the existing posture for a store that never
  opened. **The policy outcome is unchanged** — an affected host is still
  "uncategorised", not denied.

  Visibility was the other half. `culvert_catfeeddb_available` promises in its
  own HELP text to mean "open and serving lookups" but was sourced purely from
  the boot record, so it reported `1` for a store whose every lookup had stopped
  answering. It now reports `0` on a latched degradation, alongside two new
  counters — `culvert_catfeeddb_lookup_errors_total` and
  `culvert_catfeeddb_memory_faults_total` — and a `category_feed_db` diagnostics
  row that names the Layer-1-only impact and the restart that re-opens (and
  quarantines) the store. The fault is recorded durably beside the store
  (`<store>.faulted`), so that restart quarantines it with trigger
  `runtime_fault` and re-creates it empty for the feed to re-sync — badger's
  reopen error for a truncated table is not a recognised corruption signal, and
  without the record every later start stayed Layer-1-only.
  `culvert_catfeeddb_memory_faults_total > 0` is the
  alerting rule to add: it means a node's data volume is damaging a live store.

  Containment is **Linux-only**. A fault is contained only when its address can
  be shown to lie in one of the store's mapped files, which is checked against
  `/proc/self/maps`; anything else re-panics. On the Darwin and Windows release
  binaries a mapping fault keeps the prior behaviour, and the
  `category_feed_db` row says `runtime fault containment: unavailable on
  <GOOS>`. Production deployments (Docker/OVA) are Linux.

  Known limit: `SetPanicOnFault` is per-goroutine, so badger's own compaction
  goroutines remain exposed. This closes the reachable, request-driven exposure,
  not the class.

### Performance

- **A policy publication now allocates one array per revision instead of one
  object per rule.** `sortLocked` cloned every definition with its own
  `new(PolicyRule)` and sorted the clones; it now decides the order first, on a
  private copy of the live pointers, and clones into ONE contiguous
  `[]PolicyRule` in publication order. The permutation is identical by
  construction — the same comparator over the same input sequence, and the clone
  preserves `Priority` — so this is a layout and allocation change only.

  It is a control-plane cost with a **data-plane consequence**, which is the
  reason to care: `sortLocked` runs under `ps.mu`, the writer lock, and
  `evaluationSnapshot` takes the matching RLock before every scan, so a
  publication stalls ALL policy evaluation for exactly as long as it takes.
  Every policy edit, config-version restore and cluster config sync pays it.

  Measured with benchstat (n=10, 4-core Xeon @2.10GHz, go1.27.3) on the new
  `BenchmarkPolicyPublish_SortLocked`: allocations/op **-25% at every rule
  count**, wall time **1 000 rules 582.4 µs → 483.8 µs (-16.9%, p=0.000)** and
  **10 000 rules 4.932 ms → 4.034 ms (-18.2%, p=0.002)**, with **no significant
  change at 100 rules** (54.5 µs → 50.3 µs, p=0.105). `ReplaceAll` inherits it
  (**100 rules -8.5%**, **10 000 rules -16.1%**); bytes/op is essentially
  unchanged (-0.4%), because the same definitions are still copied — what goes
  away is the per-rule allocation, not the data.

  Two negative results are recorded on `sortLocked` itself so they are not
  re-derived. First, the layout does **not** measurably help the per-request
  scan: `BenchmarkPolicyEvaluate_NoMatch`/`MatchLast`/`CIDRRules` came out at
  -3.75% geomean with every size at p > 0.05, because the replaced per-rule
  `new(PolicyRule)` loop already drew from a single 576-byte size-class span and
  so was near-contiguous before this change. Second, the engine's superlinear
  scaling above ~1 000 rules (**7.6 ns/rule at 1 000 → 29.3 ns/rule at
  10 000**) is the touched working set (~5.7 MB of definitions) leaving L2, not
  heap scatter; only shrinking what the scan streams per rule can address it,
  and this change deliberately does not attempt that.

  `TestPolicyPublish_RevisionIsOneContiguousArray` is the regression gate and is
  **structural, not timed**: the property is worth one allocation out of the ~3
  a definition clone costs, so a wall-clock or allocation-count bound would have
  a thin margin and would rot. It asserts the published definitions sit at
  one-struct stride from a single base, in scan order, and it fails against the
  pre-change shape (verified). `TestPolicyPublish_OrderingIsUnchangedByTheLayout`
  is the behavioral control for ordering and for the precompute still landing on
  the published definitions. `BenchmarkPolicyPublish_EvaluateDuringPublish` is
  the concurrency arm: evaluation latency with a background publisher holding
  and releasing the writer lock underneath it.

- A scheduled rule's **timezone is now resolved once per policy evaluation**
  instead of once per rule. Both halves of the per-rule work depend only on
  `(instant, timezone)` and never on the rule, yet `matchScheduleAt` redid both
  for every scheduled rule of every proxied request:

  - `scheduleLocationResolved` keeps tzdata off the hot path, but its
    process-wide `sync.Map` is **interface-keyed**, so each probe pays
    `runtime.nilinterhash` → `typehash` → `aeshashbody`. On a 1 000-scheduled-rule
    rulebase that probe alone measured **38.7%** of the evaluation
    (`scheduleLocationResolved` 41.0% cumulative) — a thousand identical
    lookups of the single timezone the deployment had configured.
  - `now.In(loc)`, `Weekday()`, `Hour()` and `Minute()` each re-split the
    absolute seconds: a further **~25%** of the same scan.

  `evalAccessRules` now shares one evaluation-scoped `scheduleClock` across the
  rulebase, the same lazy pointer-passed idiom `clientSource` and
  `hostCatScratch` already use — it stays on the caller's stack, is never
  retained, and a rulebase with no scheduled rule still reads no clock at all.
  The memo holds **one** entry keyed on the timezone string, which is the shape
  real postures have (one configured zone, or empty for UTC); a rulebase that
  alternates zones rule-by-rule simply re-derives, i.e. degrades to the
  pre-change cost and measured no worse (60.5 µs vs 69.9 µs at 1 000 rules).

  Measured with benchstat (n=6, 4-core Xeon @2.10GHz, go1.26.9):
  **10 rules 887.7 ns → 401.8 ns (-54.7%)**, **100 rules 7.289 µs → 2.525 µs
  (-65.4%)**, **1 000 rules 69.92 µs → 23.02 µs (-67.1%)**. Isolated, the
  per-rule schedule check went from ~66 ns to ~15.2 ns (**-77%**). Allocations
  stay at **0/op** — the zero-allocation scan contract is unchanged — and an
  unscheduled rulebase is untouched.

  `scheduleDayMatch` and `scheduleTimeMatch` split into shared cores taking the
  already-derived weekday and minutes-of-day, and `matchScheduleAt` became a
  one-shot use of the memo. There is therefore exactly **one** schedule-matching
  code path, so the Stage-1 auth gate, CDR policy and the policy simulator keep
  their behavior by construction rather than through a parallel implementation
  that could drift. `TestBenchGate_PolicyEvalScheduleOverheadBounded` gates the
  scheduled-to-unscheduled scan ratio at 3.5x (measured 2.19x; 4.63x with the
  memo un-shared); the existing allocation gate could not see this regression,
  because resolving per rule allocates nothing.
- A **known-empty request body is no longer wrapped** on either leg that
  serializes an outbound request, so `net/http` stops probing it. Wrapping the
  `http.NoBody` sentinel reports the body length as unknown (see the companion
  entry under **Fixed** for why), and for the methods that usually lack a body —
  `GET`, `HEAD`, `DELETE`, `OPTIONS`, `PROPFIND`, `SEARCH` —
  `transferWriter.shouldSendChunkedRequestBody` resolves that unknown with
  `probeRequestBody`: a fresh **goroutine** reading one byte, a buffered
  channel and a 200 ms `time.Timer`, with the request line blocked on that
  channel round trip. Bodyless methods are most of proxied web traffic, and on
  an inspecting gateway nearly every decrypted inner request takes the second
  leg too, so this was paid on the majority of requests the product serves —
  and it bought nothing: the probe's only conclusion was the emptiness the
  sentinel had already stated.

  Nothing is lost by skipping the wrappers. An empty body cannot exceed
  `maxRequestBody`, its byte counter would stay at 0 — exactly what the
  pre-existing nil branch contributes to `statBytesSent` — and a body with no
  bytes has no trickle for the inspect loop's stall detector to catch, with
  that loop's 60 s header read deadline still bounding a client that sends
  nothing. Scope is the sentinel's identity only: every other body, `nil`
  included, behaves as before.

  Measured on go1.27.3 (the `go.mod` toolchain pin), linux/amd64, 4-core Xeon
  @2.10GHz, medians of n=5, as *before* → **after** — the "before" arm being the
  frozen pre-change wrapping kept in `proxy_emptybody_bench_test.go` so the
  comparison stays reproducible in-tree:

  | | allocs/op | B/op | ns/op |
  |---|---|---|---|
  | bodyless `GET` forward | 80 → **69** | 10 485 → **9 662** | loopback-bound |
  | bodyless `POST` forward | 82 → **70** | 10 341 → **9 676** | loopback-bound |
  | inspected inner-leg `Request.Write` | 13 → **6** | 665 → **248** | 3 734 → **1 088** |

  The same benchmarks on go1.26.10 (the pin before the go1.27.3 bump) measured
  the forward pair one allocation lower on **both** arms — 79 → 68 and 81 → 69 —
  and the inner-leg pair identically. The absolute counts track the toolchain;
  the saving does not move: **−11** allocations on a bodyless `GET`, **−12** on a
  bodyless `POST`, **−7** on the inner leg, on both toolchains.

  The inner-leg pair is the strongest evidence: it carries no network at all,
  so its **~3.4× CPU** gap is the probe's channel round trip and nothing else,
  reproduced in all five runs on both toolchains with no overlap. The forward pair's `ns/op` is
  loopback- and scheduler-bound on a shared 4-vCPU runner and its medians
  overlap across runs, so it is **not** quoted as a result; allocation counts
  are deterministic, which is why `TestBenchGate_EmptyBodyForwardAllocs` and
  `TestBenchGate_EmptyBodyInnerWriteAllocs` key on them and assert the
  before/after relationship as well as an absolute bound.

  End to end, `BenchmarkPerfQual_ProxyHTTPForward` goes from **176 to 165
  allocs/op** and ~14 765 to ~13 895 B/op, identically at `rules=10/100/500`
  and in every run of an A/B against the pre-change tree. Its `ns/op` and
  `cpu-ns/op` move the same way (~−3%) but inside this runner's spread, so they
  are reported as directional only.

  The inspected **H2** leg is deliberately untouched: `x/net/http2`'s server
  never hands out `http.NoBody` (`newWriterAndRequestNoBody` always installs a
  `*requestBody`), so this guard cannot fire there and the analogous cost on
  that path is not one Culvert's wrapper introduces.
- **The per-request category-group match no longer takes a lock.**
  `matchDestNorm` calls `categoryGroupMatchesHostScratch` once per rule
  carrying a destination category group, inside the policy scan every proxied
  request walks, and each call took an `s.mu.RLock`/`RUnlock` pair — two atomic
  read-modify-writes on one shared word, so every request wrote the same cache
  line once per category-group rule to read tables that in steady state never
  change. (The ID leg's linear scan of every group was already retired by the
  `byID` index; this change removes the lock from every leg.) That is the
  throughput ceiling already found and fixed in `internal/threatfeed`,
  `internal/urlcat`, `internal/connlimit`, the IP filter and `topHosts`;
  `policy_category_bench_test.go` carried it as an **open** finding (91.9% of
  samples in `GetByName`, 68.6% in its `RLock` atomic).

  `MatchesCategoryByID`, `MatchesCategory`, `GetByName`, `GetByID` and
  `Revision` now read an immutable `readView` published under `s.mu` by the
  `bumpRevLocked` chokepoint: a `byName` map, a `byID` map projected through
  the same fail-closed `groupByIDLocked` resolution the writers use, and the
  `rev` memo counter, which travels **inside** the view so contents and change
  signal are one publication and cannot be observed out of step (published
  separately, a reader that loaded the bumped counter and then the
  pre-publication contents would memoize stale contents under the new revision
  — permanently stale, because the counter will not move again).

  Measured on the PR's development box (medians of n=5, 4-core Xeon @2.80GHz,
  go1.26.9, before the `byID` index landed), end to end,
  `BenchmarkPolicyEvaluate_CategoryGroupRulesParallel` with 50 category-group
  rules and an uncategorized destination:

  | GOMAXPROCS | 1 | 2 | 4 | 1→4 throughput |
  |---|---|---|---|---|
  | RLock | 1926 ns | 3699 ns | 3996 ns | 0.48x — cores *subtracted* throughput |
  | read view | 1748 ns | 980 ns | 537 ns | 3.25x |

  Re-measured against the `byID`-indexed store, which is the comparison that
  describes what this change still buys: both arms on one box, one toolchain
  (go1.27.3), medians of n=5, back to back — the base arm is `origin/main`
  with this package's benchmark file copied in.

  | benchmark, ns/op | main | +view | |
  |---|---|---|---|
  | `ByID_HitParallel` 8 groups, `GOMAXPROCS=1` | 64.1 | 47.2 | 1.4x |
  | `ByID_HitParallel` 8 groups, **`GOMAXPROCS=4`** | **194.2** | **11.1** | **17.5x** |
  | `ByID_HitParallel` 64 groups, `GOMAXPROCS=4` | 211.9 | 12.3 | 17.3x |
  | `ByID_HitParallel` 256 groups, `GOMAXPROCS=4` | 154.6 | 13.1 | 11.8x |
  | `MatchesCategory_NameParallel`, `GOMAXPROCS=4` | 124.0 | 16.0 | 7.8x |
  | `MatchesCategory_UnknownNameParallel`, `GOMAXPROCS=4` | 108.5 | 10.9 | 9.9x |
  | `MatchesCategoryByID_Hit` 256 groups, serial | 88.3 | 52.7 | 1.7x |

  The row that matters is the shape, not the ratio: on the `byID`-indexed
  store the parallel figures are **worse than its own single-core figures**
  (64.1 → 194.2 ns at 8 groups, 82.5 → 211.9 at 64), because with the scan
  gone the `RLock` is all that is left and it is the thing that does not
  scale. Off the view the same op costs ~11–13 ns at four cores regardless of
  group count. The serial gain is real but modest (1.4–1.7x on the ID leg:
  the view resolves an ID in one probe where the locked path walks
  `byID` → name key → group). `MatchesCategory_ByName`, main's own serial
  single-probe benchmark, is ~1.0–1.3x — unchanged, as expected for a shape
  with no contention to remove. Zero allocations on every path, before and
  after.

  Two **ownership** corrections made the lock-free read safe. `Update`,
  `UpdateByID` and `Rename` now copy-on-write instead of editing the live
  `*Group`: `GetByName` hands that pointer out and its doc comment claimed
  "catSet is immutable between mutations", but the mutators edited it in
  place, so a caller reading `g.catSet` or `g.Name` raced the writer. And
  `ReplaceAll` / `restoreSnapshot` now copy each `Group` rather than
  publishing `&groups[i]`: aliasing the *caller's* backing array cannot honour
  "a published Group is never mutated in place", and handing the same slice to
  `ReplaceAll` twice wrote groups a reader was mid-probe on. One behavioural
  consequence, deliberate: the caller's slice no longer has its IDs backfilled
  in place — no call site reads them back, and `Save()` persists them from the
  store.

  The view contract is pinned three ways — behaviourally through every public
  mutator including the `MutateDurable` rollback path, structurally by an AST
  wall over the package (every group-tree writer publishes, directly or
  through `bumpRevLocked`, which must itself call `publishLocked`) with a
  pre-fix control and a writer inventory, and as a differential oracle against
  a verbatim copy of the pre-fix linear scan.

- The destination host is now canonicalized **once per policy scan** instead of
  once per category-scoped rule. `urlcat.Store.MatchesHost` /
  `MatchesHostAdmin` and `effectiveCategoryView.MatchesCategory` each opened
  with `host = hostutil.NormalizeHost(host)`, and
  `hostCatScratch.matchesCategory` calls one of them per category-scoped access
  rule per proxied request — so a scan re-derived the same canonical host once
  per rule, and **twice** per rule on a signed-feed-armed deployment, where the
  `catStore` and view matchers normalized independently.

  Decomposing the probe (shipped taxonomy, 3-label uncategorized destination —
  the clean-traffic case that cannot short-circuit; medians of n=5, 4-core Xeon
  @2.10GHz, go1.26.8) put `NormalizeHost` at **45.97 ns of a 105.8 ns total,
  43%** and the largest single term. The per-rule `RLock` previously recorded
  as this path's open item is ~10.2 ns of it — the fourth-largest term. The
  scan already held the value: `matchDestNorm` receives a once-per-request
  `normHost` as a parameter and handed the matchers the *raw* host beside it.

  `hostCatScratch.normHost()` memoizes it lazily (a scan with no
  category-scoped rule still normalizes nothing) and the three matchers gained
  `*Norm` entry points taking the canonical host; the old names survive as
  normalizing wrappers, so every caller outside the scan is unchanged in cost
  and behaviour. The hoist relies on **no idempotence property** —
  `NormalizeHost` is not idempotent, since an empty ACE label decodes to
  nothing (`NormalizeHost("a.xn--") == "a."`, `NormalizeHost("a.") == "a"`) —
  because every consumer is handed `NormalizeHost(sc.host)`, the same function
  on the same input the pre-hoist body used. Only *where* it is computed moves,
  so no matching decision can change.

  The scan entry points already held that value — `accessEvalInput.normHost`,
  a `normHost :=` one line above the CDR scratch, and `authMatchScratch`'s own
  memo — so the scratch is **seeded** from it rather than re-deriving it
  (`newHostCatScratchNorm`), which also collapses the auth path's two memos of
  one value into one. The seed's contract is `normHost == normalizeHost(host)`,
  checked at all five production pairs and pinned by a gate that drives the
  real `Evaluate` with hosts whose raw and canonical forms differ.

  Measured: the per-rule probe **112.6 → 71.0 ns (−37%)**, both arms timed in
  ONE run. The real `DestCategory` policy scan cannot be timed same-run (that
  would need two production trees in one binary), so it is an **adjacent pair**
  — identical command, identical machine state: **1 rule 191.7 → 157.6 ns,
  10 rules 1035 → 933, 50 rules 2809 → 2519, 200 rules 9617 → 8452**, i.e.
  **~10–18%**, with **0 allocations preserved on every path**.

  An earlier draft of this entry quoted −28%/−38.6%/−44.3% for that scan.
  Those were **cross-run and overstated the gain by roughly 3–4x**: the
  baseline was measured hours before the post arm and this hardware drifted
  enough to move the same pre-change tree from 17292 ns to 9617 ns at 200
  rules. Run-to-run drift is up to ~12% even between adjacent pairs, so the
  claim is the direction and rough magnitude, not a precise percentage.

  One limit recorded rather than rounded away: the gain shrinks with core
  count (50-rule interleaved parallel scan, same-run: −39.5% at 1 core,
  −14.8% at 2, −8.7% at 4), because removing CPU work from a probe whose
  critical section is unchanged moves the bottleneck onto `catStore.mu`. Both
  arms take exactly the same number of read locks, so they converge under
  saturation and the hoist is never the slower of the two. (Those figures
  predate the lock-free membership probe in the next entry; the `*Norm` entry
  points now read the same published forward view, so neither arm takes
  `catStore.mu` any more.)

  Relationship to the IDNA memo landed separately in this window: that memo
  sits strictly BELOW `NormalizeHostStrict`'s already-canonical ASCII fast
  path, so it makes the *slow* (A-label / U-label) branch cheap and leaves
  the ASCII branch these figures were measured on untouched. The two are
  complementary rather than alternatives: the memo collapses a repeat across
  INDEPENDENT engines, which is the fan-out it was written for, while this
  hoist removes the repeat inside ONE scan's per-rule loop, where the
  multiplier is the rule count rather than the engine count. Re-measured on
  the merged tree, the same-run per-rule probe reproduces at 141.8 → 89.9 ns
  (−36.6%) against the −37% published here — the absolutes moved because the
  hardware did, the ratio did not, which is why this entry quotes ratios.

  Equivalence is the deliverable, not the speed: a divergence here is a
  silently mis-enforced Allow/Deny rule. Both differentials run against
  **verbatim frozen copies of the pre-hoist bodies** (comparing the new wrapper
  against the new `Norm` function would be vacuous, since the wrapper is now
  defined in terms of it), with randomized sweeps, their own not-vacuous
  checks, and two fuzz targets (299k and 101k executions, no divergence). The
  regression gate is **structural** because re-introducing a per-rule
  `NormalizeHost` changes no decision at all — every differential and control
  keeps passing while the cost silently returns — so
  `TestWall_PerRuleCategoryMatchersTakeTheHoistedHost` AST-walks
  `matchesCategory` and requires every membership matcher to be a `*Norm` entry
  point handed `sc.normHost()`, tracked PER MATCHER rather than as an aggregate
  count — a count of three is satisfied by three calls to the same entry point,
  so the aggregate form passed when `MatchesHostAdminNorm` was replaced by a
  duplicate `MatchesHostNorm`, leaving the admin tier unguarded (verified: the
  old form returned `ok` against that mutation, the new one fails it).

  A second structural wall pins that every SCAN seeds the memo
  (`TestWall_ScanEntryPointsSeedTheCanonicalHost`). Swapping
  `newHostCatScratchNorm` back to the lazy constructor is semantically
  identical — the scratch then derives the same value itself — so every
  differential, control, fuzz target and real-`Evaluate` gate keeps passing
  while the scan canonicalizes the destination twice again. It covers all
  three scan entry points (access-rule, CDR, Stage-1 auth) rather than the one
  that was reported; the three single-shot callers hold no precomputed
  `normHost` and are deliberately excluded.

  Thirteen reintroduced defects were each verified failing — four against the
  matcher wall, four against the differentials, two against the seeding
  behaviour, and three against the seeding wall (one per scan entry point).

  A pre-existing asymmetry is confirmed unchanged and now asserted so it is
  not mistaken for a regression: the forward index keys a pattern without
  IDNA-normalizing it while a query is normalized, so a unicode pattern is
  stored verbatim and never matches the A-label form its own queries
  canonicalize to.

- The per-rule URL-category **membership** probe no longer takes a read lock.
  `urlcat.Store.MatchesHost` / `MatchesHostAdmin` answer "is this host in
  category C?" and are called once per category-scoped access rule per proxied
  request (`hostCatScratch.matchesCategory`, deliberately not memoized — the
  answer depends on the rule's category, not just the host). Each took
  `s.mu.RLock` purely to read **one outer map entry**, and `RLock`/`RUnlock`
  are two atomic read-modify-writes on one shared word — so every request in
  the process wrote the same cache line once per category rule.

  That is a throughput **ceiling**, not a constant cost. A 4-core CPU profile
  of `BenchmarkStoreMatchesHost_Parallel` put **80.6% of all samples in the
  `RLock`/`RUnlock` atomic** (41.1% + 39.8% cumulative) against ~15% doing the
  real work, and the scaling curve is the finding: `MatchesHost` delivered
  **0.56x** the throughput at four cores that it did at one — adding cores
  *subtracted* throughput.

  Both entry points now read an immutable view through an `atomic.Pointer`: a
  single pointer load, with no read-modify-write on any shared word. Measured
  on a 4-core Xeon @2.30GHz with **both arms timed in one run** (the `_Legacy`
  benchmark arms call a verbatim copy of the pre-view body), medians of n=7:

  | | 1 core | 2 cores | 4 cores | scaling 1→4 |
  |---|---|---|---|---|
  | `MatchesHost` before | 85.2 ns | 158.1 ns | 151.0 ns | **0.56x** |
  | `MatchesHost` after | 83.7 ns | 43.0 ns | **21.3 ns** | **3.94x** |
  | `MatchesHostAdmin` before | 97.1 ns | 109.7 ns | 154.6 ns | 0.63x |
  | `MatchesHostAdmin` after | 95.1 ns | 47.4 ns | 23.8 ns | 4.00x |

  End to end through the real policy scan
  (`BenchmarkPolicyEvaluate_CategoryRulesParallel`, 50 `DestCategory` rules
  over 12 categories / 480 patterns, uncategorized destination — the
  clean-traffic case that cannot short-circuit): **8764 → 1025 ns/op at four
  cores (8.55x)**, scaling **0.46x → 3.71x**, allocations unchanged at 0.

  There is **no low-concurrency price and no gain either** — the serial arms
  measure 1.007x / 0.991x / 1.020x, i.e. parity. An uncontended `RLock` is
  cheap, so the entire win is the scaling, which is the axis the hardware this
  appliance ships to actually runs on.

  Semantics are unchanged exactly, which is the deliverable rather than the
  speed: this is a policy membership matcher, so a divergence would be a
  silently mis-enforced — or silently **unenforced** — Allow/Deny rule. The
  equivalence is pinned by a differential against verbatim copies of the
  pre-view bodies, and the publication contract three further ways (structurally
  per writer, structurally as an inventory, and behaviourally through all twelve
  public mutators), because a forgotten publish would leave the policy path
  probing a stale view — a Deny rule keyed on a just-added category host would
  fail **open**. The structural scan covers every non-test source file in
  `internal/urlcat` and any receiver name, so a writer added in a new file or
  under a renamed receiver is still caught. The two entry points now share one
  probe body (`matchesHostIn`) so they cannot drift apart.

  The publish's cost is a **benchmark, not a gate**. A wall-clock ratio bounded
  at 1.25x was tried and removed: run the way CI runs every non-root package
  (race detector + coverage + ~115 packages at once) it measured the shipped
  implementation at 1.453x and, in the same run, the deep-copy defect it existed
  to catch at 1.43x — converged, so it failed CI while no longer able to
  distinguish health from the pathology it asserted against. The invariant is
  asserted structurally instead, by map identity, which catches that defect
  deterministically including under `-race`.

### Security

- **CHAOS-73 review rounds.** A genuine revocation whose cookie exceeded the
  untrusted-origin key bound was dropped when the revocations file was
  reloaded, so the revoked cookie authenticated again after a restart;
  locally verified entries are now persisted with a provenance MAC
  (domain-separated, never the cookie's own signature, never on the gossip
  wire) and restored past both the size bound and the entry cap, while gossip
  and legacy entries keep the untrusted rules. Untrusted entries may no longer
  claim an expiry beyond the maximum session lifetime: such entries are never
  swept, and enough of them permanently fill the list so that legitimate
  remote revocations are refused at capacity. A revocation whose durable write
  failed is repaired by the browser's retry instead of being lost at the next
  restart. The Control Plane bounds the memory it retains per node, not just
  the entry count, and clears peer-supplied provenance before storing or
  re-broadcasting an entry. The refusal counter, its metric help, the
  `session_revocation` contract row and the runbook no longer assert that a
  refusal is an attack — a cookie signed under a previous session secret is
  genuine and unverifiable, and a key rotation makes ordinary browsers
  produce one. Concurrent revocation saves are serialized end to end: the
  snapshot and the write under the owner's lock, and the save together with
  the flag that records whether it landed under the coordinator's, so a
  writer whose save succeeded can no longer clear the retry a writer whose
  save failed had just recorded and leave the file behind memory with nothing
  owed. Reconciled with SEC-REVOKE-1 (already on main), which fixed the same
  unsigned-cookie write by gating `apiAuthLogout`'s revocation on
  `decodeSession`: the audit entry keeps that gate, but the revocation is
  routed through `revokeSessionCookie`'s own MAC verification instead, because
  `Decode` also refuses an already-revoked token and so blocked the replay that
  repairs a failed save or reconciles a shorter peer-imported expiry.

- `/api/auth/logout` is on the admin-UI auth middleware's **public** allowlist
  — correctly, since an expired or already-revoked session cannot authenticate
  a request and must still be able to clear its own cookie. But
  `revokeSessionCookie` then base64-decoded whatever cookie arrived, read the
  expiry out of the *decoded* payload, inserted the payload bytes as the
  session-revocation key, and rewrote the entire revocations file. **The HMAC
  was never checked** (CHAOS-73), and the call site's comment asserted the
  opposite — "HMAC already verified by decodeSession" is true of `Decode` and
  false here, because `apiAuthLogout` calls the function unconditionally; the
  `sess != nil` guard above it covers only the audit entry.

  So an **unauthenticated** caller chose the retained key, its **length** and
  its **expiry**. Measured against the real handler behind a real `net/http`
  server: a **524,389-byte** forged cookie answered `200` and was retained with
  a 100-year expiry, which the evictor — keyed on that same attacker-chosen
  value — can never reclaim; 200 requests carrying 16 KiB each (3.2 MB in)
  wrote **441 MB** to disk, the amplification running 17x → 34x → 68x → 135x as
  the request count doubled (**quadratic**, because every insert rewrites the
  whole file); and in a cluster the entry reaches the payload each Data Plane
  pushes to the Control Plane every 3 s, so one unauthenticated request to one
  node's admin port becomes durable state on **every** node. `MergeRevocations`
  separately accepted 50,000 peer-supplied entries with no cap at all.

  The fix **authenticates rather than bounds**: a revocation key is the payload
  half of a cookie this appliance signed, so a cookie it did not sign cannot
  name a session of its own and refusing it loses nothing. Verification costs no
  availability for the case the public route exists to serve — `Decode` checks
  the MAC before the expiry, so a genuine *expired* cookie still verifies and
  still logs out, and it is deliberately not counted as a probe. The two writers
  authentication cannot reach (cluster gossip, the on-disk file) keep a derived
  key-size bound and an entry cap with counted refusals; the MAC-verified local
  path is **exempt** from both, so a real session stays revocable however large
  its cookie grew. The Control Plane's revocation aggregator is bounded in the
  same change, the persist is gated on an actual change (which removes the rest
  of the quadratic term even for authenticated callers), and the expired-entry
  sweep no longer depends on a read of the exact key — previously an
  un-clustered node had no evictor at all.

  A refusal stays silent to the caller (same status, body and `Set-Cookie` as a
  genuine logout) so logout cannot become a cookie-validity oracle. New
  surfaces: `culvert_session_revoke_refused_total`,
  `culvert_session_revoke_rejected_total{reason}`,
  `culvert_session_revocations_tracked`,
  `culvert_cluster_revocation_drops_total`, a WARN-only `session_revocation`
  diagnostics row (counts only), and a rate-limited `SESSION_REVOKE_REFUSED`
  log line. No new alert event and no `/readyz` row. Gates: 21 functions in
  `session_revocation_chaos_test.go`, with ten mutations each verified failing
  its gate. Runbook: `docs/operator/session-revocation-plane.md`.
- The IDNA memo's value bound (`len(norm) > maxMemoHostLen`, 253 bytes) had no
  gate on its main-tier axis: an in-limit host that **expands** past the bound
  through punycode encoding. The long tier's oversize cases exercise the same
  branch, but nothing pinned that a host arriving inside the limit cannot be
  retained once encoded, so a tier-specific rewrite of the check could drop it
  silently; measured with the main-tier check removed, the table retains
  **969 KB against its 554 KB ceiling**, holding a 668-byte canonical form in a
  slot. The guard itself is present and correct, so no release was affected and
  no behavior changes here. The ACE overhead (`xn--`, the delimiter, the
  encoded deltas) is paid per **label**, so while a dense script compresses — a
  252-byte CJK host measures 98 bytes as an A-label — one non-ASCII rune in
  each of many short labels expands instead: `é.é.é…` at 251 bytes normalizes
  to 671 and `aé.aé.aé…` at 251 bytes to 629, up to ~2.7x the bound, from
  ordinary authorities well inside the 1 KiB HTTP raw pre-cap.
  `TestIDNMemo_PunycodeExpansionIsNotRetained` (per-shape retention, with both
  preconditions asserted so a future `x/net` encoding change fails loudly
  rather than passing vacuously) and `TestIDNMemo_ExpansionCannotBreachTheCeiling`
  (the bound under a stream of nothing but expanding hosts) now gate it, and
  `TestIDNMemo_StoredEntriesRespectTheBound`'s corpus carries the expanding
  shapes, which it previously reached for only through CJK. Verdicts were
  never at issue — an expanding host is still normalized, just not retained.
- `fileutil.AtomicWrite`'s new post-rename `fstat` duplicate was created
  without `syscall.ForkLock`, so the descriptor was briefly inheritable
  (CWE-403). `holdInode` ran `syscall.Dup` and then `syscall.CloseOnExec` as
  two separate calls; `dup(2)` cannot set `FD_CLOEXEC` itself, so between them
  the duplicate was an ordinary inheritable descriptor. A `fork`+`exec` started
  in that window by any goroutine would hand the child a **read** descriptor of
  the file the write is landing — and `AtomicWrite` is the single chokepoint for
  every durable write in the appliance, the admin roster, data-plane and cluster
  CA key-at-rest material and enrollment receipts among them.

  No shipped `culvert` binary execs a subprocess, so this was latent rather
  than reachable; the duplicate is new on every durable write regardless, and
  the exposure would turn on whenever a future caller does exec. The dup and
  the flag now run inside `syscall.ForkLock.RLock`, the pattern the `syscall`
  package documents for descriptor-creating code: `forkExec` takes that lock
  for writing, so no exec can begin in the window. The failure path releases
  the lock (holding it would wedge every later exec in the process).
  Pinned by `TestHoldInode_DuplicateIsCloseOnExec` and
  `TestHoldInode_ReleasesForkLockWhenTheDupFails`.
- Defensive zero-value hardening of the admission engine. No production crash
  is reachable today: every production `IPFilter`/`RateLimiter` (including the
  one `applySnapshotAdmission` builds before `AddAll`) comes from
  `NewIPFilter`/`NewRateLimiter`, and no non-test code constructs a bare value.
  The ADR-0039 admission extraction nevertheless left the zero value of both
  front-door gates usable only under a documented PRECONDITION, with nothing
  enforcing it.
  Three map writes panicked on a nil map — `IPFilter.addLocked`,
  `RateLimiter.Allow` and `RateLimiter.AllowClusterAware` — while
  `addExemptionLocked` in the same file already lazily initialized, so the
  package was internally inconsistent about an invariant it already asserts for
  the exemption path (`TestRLExemptView_BareLiteralLimiterIsSafe`: a bare
  limiter "must still accept a first mutation").

  Measured against the tree: a bare `IPFilter{}` panics on `Add` and on
  `AddAll`, and a bare `RateLimiter{}` that has been `Configure`d panics on
  `Allow`. The extraction makes that trap easier to reach rather than harder —
  both types now carry only unexported fields, so the complete literal package
  main used to write (`&IPFilter{single: map[string]bool{}}`) no longer compiles
  outside the package and `&IPFilter{}`, the silently broken shape, is the only
  literal form left. A future caller that wrote it would have panicked on its
  first `Add`/`AddAll`, or on the request path once a bare limiter was
  `Configure`d.

  The precondition is replaced by a guarantee using the idiom already present
  in `addExemptionLocked`. This is an availability hardening, not a policy
  change: the nil checks sit in the cold miss branch (a nil map reads as a
  miss), so the steady-state hot path pays nothing, the allocation benchgates
  still measure zero, and no allow/deny verdict moves — a bare instance is
  differentially pinned equal to a constructed one across every mode and probe.
  Gates: 5 in `internal/admission/bare_literal_safety_test.go`, each verified
  failing against the reintroduced pre-fix shape and four of them additionally
  against the cheapest wrong fix (skip the store when the map is nil, which
  silences the panic while silently not enforcing the entry). `doc.go` and
  ADR-0039 are amended rather than left asserting the narrower contract.
- OIDC credential/JWKS transports now dial the guarded destination directly:
  an inherited forward proxy could bypass the resolved-IP SSRF guard. A
  behavioral regression checks private destinations, DNS rebinding and
  redirect targets with a public-proxy hook configured. OIDC no longer uses
  environment proxies.
  G704 is enforced with scoped exceptions, the expired OpenSSL exception is
  removed, and CI records unfiltered findings and the actual image's package
  and static-binary evidence (RISK-002/RISK-006).
- The C2 route-metadata index resolved every wildcard admin route to the
  **public `/` catch-all** (SEC-C2WILDCARD-1). `buildMetadataIndex` classified a
  Go 1.22 `{name}` pattern as an *exact* path and stored it under its literal
  pattern text, so a real request path — `/api/support/bundles/csb_…` — never
  matched it, fell through the prefix list and landed on the SPA shell's entry,
  which is `Public: true`, `RolePublic`. For all ten such routes (the
  support-bundle download, sealed-export, delete, manifest and upload-consent
  surfaces, plus `/api/support/recipients/{name}`) that silently disabled C2
  role enforcement, the C4 role-divergence observation and the C2c audit-gap
  check — and because `Lookup` still answered "found", `c2ShadowMissingMetaTotal`
  never incremented, so nothing showed it in metrics either.

  Not exploitable as it stood: every one of those handlers carries its own
  handler-level `requireRole`, so what was lost is the second layer, not the
  only one. The mux itself resolves these patterns correctly; only the mirror
  did not. The index now keeps wildcard patterns in a segment-matched list,
  tried after the exact map and before the prefix list, with ServeMux's own
  semantics — literals byte-for-byte, `{name}` exactly one non-empty segment,
  `{name...}` the trailing segments, most specific first. Exact lookups and the
  catch-all fallback are unchanged, and the new matcher cannot over-claim:
  `/api/support/bundles/` and a path with one segment too many are both
  refused. `TestC2_MetadataIndex_ResolvesEveryRoute` passed vacuously because it
  iterates the pattern literals; the new gates substitute a concrete value for
  each `{…}` segment and were verified failing against the pre-fix index, where
  10 of 10 routes resolve to `"/"` with `public=true`.

  Resolution for a live request goes through the ESCAPED path. `*http.ServeMux`
  matches on `EscapedPath()` and unescapes each segment on its own, so a `%2F`
  stays inside one wildcard value — it routes
  `/api/support/bundles/foo%2Fbar` to `{id}` with `id="foo/bar"`, while
  `r.URL.Path` has already turned that into a second segment. Resolving from
  the decoded path therefore reopened the same hole for one percent-encoded
  character, which the built index confirmed by answering `("/", public=true)`
  for all three affected shapes. Matching the raw escaped text would be wrong
  in the other direction, because `appro%76e` really does reach the literal
  `approve` route, so each segment is unescaped separately; a malformed escape
  is left as-is, making the worst case a miss rather than a wrong route. The
  decoded path still feeds the exact and prefix tiers unchanged.

- Revoking a cluster **enrollment token** left no audit record
  (SEC-ENROLLAUDIT-1). `DELETE /api/cluster/tokens` destroys cluster trust
  material, yet it was the one mutation on that route with no `auditEvent`: the
  POST that mints a token audits, node revocation audits, and the route
  metadata claimed `"audit delegated"` for a method that had no delegate. With
  `AuditExpected` false, C2c's runtime audit-gap check could not notice the
  omission either, and `api/route-classification.yaml` agreed with the wrong
  answer. An admin-session holder could therefore remove enrollment capability —
  durably, the store is saved — with nothing recording who did it or when.
  The handler now emits `enrollment.token_revoked` **after** the store has
  persisted, so a record cannot claim a revocation that did not survive the
  write; the metadata and the manifest declare it. `saveConfigVersion` is
  deliberately still absent — enrollment tokens are outside the rollback
  surface. The write-failure path is covered too: `DeleteToken()` runs before
  `Save()`, so a failed store write leaves the token already gone from memory
  — this node has stopped honouring it whatever the 500 says, and a later
  successful save makes the deletion durable — which now records a distinct
  `enrollment.token_revoke_unpersisted` event rather than nothing. The token is
  not restored; putting live enrollment material back because a disk write
  failed is the less safe direction, and the 500 already says to retry.
  Gates include two negative controls (a 404 and a 400 must audit nothing),
  assert on unique entry content rather than a length delta because the audit
  ring is bounded, and mint a fresh token hash per invocation so a `-count=2`
  run cannot satisfy the positive assertion from the previous run's entry.

  Both findings were recorded as R2 and R4 in the 2026-10-17 review and are
  closed here. Full analysis, plus a review of the 28 open pull requests —
  including one that flips a fail-closed installer gate to fail-open and four
  pairs of mutually incompatible remediations of the same defect — is in
  `docs/engineering/security-reviews/2026-10-18-open-pr-fleet-and-metadata-audit-gaps.md`.
- Built with Go 1.26.10 (was 1.26.9) for GO-2026-6809: `crypto/x509` did
  not distrust compromised intermediate certificates. Culvert reaches it
  through certificate verification (`x509.Certificate.Verify`, for example
  the MCP acceptance PKI check). The `go.mod` toolchain line and both
  Docker builder images move together; the `go` language minimum is
  unchanged.
- An inspected (TLS-decrypted) tunnel enforced policy on the CONNECT authority
  but forwarded each inner request's own `Host` / `:authority` upstream verbatim,
  and nothing compared the two (SEC-TUNHOST-1). A CONNECT is authorized **once**:
  `handleTunnelInspect` derives `hostOnly` from the CONNECT line and everything
  downstream is decided against it — `policyStore.Evaluate` ran on it, the
  decryption profile resolved on it, the upstream TLS `ServerName` is it, and
  every log row, scan verdict and CDR decision the tunnel produces is attributed
  to it, because `runInspectExchange` threads `ex.host` and never `ex.req.Host`.

  The decrypted stream, however, carries its own destination on every request.
  `rq.Write` writes `req.Host` on the H1 leg and `upstreamCC.RoundTrip` sends it
  as `:authority` on the H2 leg, so a client could open a tunnel to a destination
  policy allowed and then ask that connection for a different one:

      CONNECT allowed.example.com:443   → evaluated, allowed, MITM established
        GET / Host: blocked.example.com → forwarded verbatim

  The upstream connection is pinned to the CONNECT target's address, so this is
  not SSRF — but any shared front end (a CDN, a cloud load balancer, any
  multi-tenant vhost) routes by `Host`/`:authority`, so the response is the one
  the **client** named, not the one policy allowed. Policy is consulted once, on
  a host the client then declines to use, and the request log records the
  authorized host for a retrieval of the unauthorized one, so the bypass is also
  invisible to the operator reviewing traffic afterwards. Scan and CDR verdicts
  are mis-keyed the same way. The H2 path's own comment had recorded the gap as a
  pending refinement ("strict `:authority` pinning / 421 handling").

  The inner host is now pinned to the CONNECT authority in `runInspectExchange`,
  ahead of the round trip and of the header scrub — so an unauthorized
  destination is never fetched, and the refusal does not depend on anything the
  scrub rewrites. Both sides are reduced identically (port and IPv6 brackets
  stripped, then IDNA-canonicalized), so the spellings the matchers already fold
  to one destination still pass: case, a trailing dot, an explicit port, and a
  U-label against the A-label the CONNECT carried. The pin anchors on the CONNECT
  authority rather than the client's SNI deliberately: a client controls both its
  SNI and its `Host`, so it can make them agree with each other and still name a
  destination policy never saw — only the authorizing value is a safe anchor.
  Fail-closed: a host that cannot be canonicalized on either side is refused
  rather than compared loosely. Refusing cannot break a conforming client, since
  the forged leaf carries a single SAN (`DNSNames` is exactly `[]string{host}`),
  so HTTP/2 connection reuse for a second origin (RFC 9113 §9.1.1) is never
  certificate-authorized; the client may open a tunnel for the host it actually
  wants, which then receives its own policy decision. One gate serves both
  protocols because `runInspectExchange` is the shared enforcement seam
  (invariant C5).

  **Scope, stated rather than implied:** the pin does not fire when the CONNECT
  authority is an IP literal. A client that resolved the name itself legitimately
  CONNECTs to an address and names the origin in SNI and `Host` (`curl
  --resolve`, any client with its own resolver, and the shape this repository's
  own inspect harness models by passing `target` and `serverName` separately to
  `connectAndTLS`), so there is no name to compare and refusing would break
  supported traffic. A deployment whose rules authorize by IP or CIDR therefore
  still gets no name-level enforcement on the inner request, exactly as before.
  Closing that means *evaluating* policy on the inner host rather than comparing
  it — re-running the rulebase, the decryption profile and the attribution per
  inner request — which is a policy-engine change, not a gate, and is the
  recorded follow-up. This change closes the case that is both exploitable today
  and decidable at this seam: a tunnel authorized for a **name**, reused for a
  different name.

  **Correction round — an absent inner authority is not harmless (Codex P1, PR
  #1632).** The first revision treated an empty inner host as pinned, reasoning
  that it names no competing destination and that an origin requiring a `Host`
  would reject it anyway. The second half was the real error: it assumed the
  ORIGIN's behaviour instead of enforcing here, which is the same fail-open
  asymmetry this gate exists to remove. Measured against the tree rather than
  argued — `runH1InspectLoop` reads inner requests with `http.ReadRequest`, NOT
  through an `http.Server`, so the server's "missing required Host header" 400
  never runs; `ReadRequest` accepts `"GET / HTTP/1.1\r\n\r\n"` and yields
  `req.Host == ""`, and `Request.Write` then serializes a literal `Host: ` and
  returns no error. A shared front end with a default or fallback virtual host
  (an nginx `server_name _`, a CDN catch-all) answers such a request from that
  vhost — a destination policy never evaluated, with the scan verdicts and the
  log row still attributed to the CONNECT host. Empty inner hosts are now
  refused, ahead of the IP-literal scope skip, because the default-vhost concern
  does not depend on the tunnel target being a name. Substituting the authorized
  authority was considered and rejected: it would have the gateway synthesize a
  `Host` the client never sent. `TestInnerHostPin_EmptyInnerHostIsRefused` gates
  it and states the mechanism rather than trusting the claim — it proves against
  the real stdlib that the request is both accepted by the reader this path uses
  and serialized with an empty `Host`, then asserts the refusal, so the branch
  cannot be reverted by repeating the original reasoning.

  **Correction round 2 — the comparison must not repair what the wire keeps
  (Codex P1, PR #1632).** Square brackets are legal only around an IP literal,
  but `hostutil.StripHostPort` ends in `strings.Trim(host, "[]")` — correct for
  its own callers, which must accept the de-bracketed IPv6 shapes that reach
  scan/bypass lookups — so it turned `Host: [allowed.example.com]` into the bare
  authorized name. Measured, not argued: `http.ReadRequest` accepts that header
  and keeps the brackets in `req.Host`, and `Request.Write` forwards those bytes
  **verbatim**. So the pin saw a match for the authorized host and forwarded a
  bracketed authority no vhost is configured for, letting a shared front end
  answer from its default vhost — this gate's own bypass, reached *through* the
  comparison rather than around it. The inner authority's bracket syntax is now
  validated before anything is stripped: brackets must enclose a value that
  parses as an IP, and a stray, unmatched or nested bracket is refused. The
  check sits in this gate, not in `StripHostPort`, because that helper is a
  shared seam the threat feed, DPI scanner, scan-exclusion matcher, autoexclude
  cache and traffic redactor all read through. Only the inner side is checked:
  `handleTunnelInspect` derives `hostOnly` through `net.SplitHostPort`, so a
  bracketed CONNECT authority is already de-bracketed consistently for policy,
  the dial and the upstream `ServerName`.

  The sibling spellings were measured too, and are deliberately still accepted
  because they are not this defect: a U-label is sent as the A-label by
  `Request.Write` (`bücher.example.com` goes out as `xn--bcher-kva.example.com`),
  so its forwarded bytes already match what was authorized; the `Host` field is
  case-insensitive; and a trailing root dot is a valid authority for the same DNS
  name. `TestInnerHostPin_BracketedDNSAuthorityIsRefused` gates the refusal and
  pins the U-label control beside it, both asserted against the real stdlib
  before the predicate is consulted, since the defect is exactly that the
  comparison and the wire disagreed.

  New counter `culvert_proxy_inner_host_mismatch_blocked_total` (always emitted,
  so a flat zero means "no client has done this", never "the gate is off") and an
  `INNER_HOST_MISMATCH` log line naming **both** hosts, since either alone says
  nothing; both are client-influenced and go through `sanitizeLog` + `%q`
  (CWE-117). Gates: the defect gate asserts the upstream was never *contacted*,
  not merely that the exchange was blocked — a refusal taken after the round trip
  would still have fetched the unauthorized resource — and was verified failing
  against the verbatim pre-fix body. Controls pin that the authorized
  destination still flows, that the client-resolved-address shape still flows on
  both IPv4 and IPv6, that a self-consistent SNI/`Host` pair naming an
  unauthorized destination is still refused (this fails CI if the pin is ever
  "simplified" to compare against the SNI), and that `MatchFQDNNorm`'s
  subdomain-inclusive semantics — correct for a policy rule, wrong here — are not
  reused for the comparison. Plus the boundary table (case, trailing dot,
  U-label/A-label, ports, IPv6 brackets, empty hosts, unnormalizable input), the
  403 wire bytes on each protocol responder, and 400 concurrent refusals under
  `-race`.
- An admin session was any session the cookie was *named* after
  (SEC-UISESS-1). `ps_session` (the proxy end-user cookie,
  `setSessionCookie`) and `ps_ui_session` (the admin operator cookie,
  `setUISessionCookie`) are signed with the same HMAC key and carry the same
  `Session` payload, with no audience or purpose field between them — so the
  cookie name was the only separation, and the caller picks the name.

  Both fields that could have refused the replay declined instead.
  `sessionRoleOrReject("")` resolves to `RoleAdmin`, deliberately, for
  pre-RBAC sessions minted before the role field existed — and a proxy
  session never sets `Role`, so every `ps_session` carried exactly the empty
  string that branch promotes. The roster-existence backstop that would have
  caught the unknown subject was gated on `sess.Provider == "local"`, and a
  proxy IdP session carries the IdP profile id, so the check was skipped
  rather than failed.

  The result was reproduced end to end by minting through the real proxy
  issuer and re-presenting the cookie value under the admin cookie name:
  HTTP 200 with injected role `admin`. An ordinary proxy end user who
  completed a normal captive-portal OIDC/SAML login with their own corporate
  credentials — no forgery, no XSS, no MITM, no knowledge of the signing key
  — was a control-plane admin, above every handler `requireRole` gate and
  every C2 metadata role. The CP distributes one signing key to every DP, so
  the token was admin on every node in the cluster. This contradicted
  `docs/enterprise/IDENTITY-AND-ACCESS-DEPLOYMENT.md`, which states that
  external IdPs authenticate proxy end users and "never issue an admin
  session" (GAP-IAM-02).

  The fix is the narrowest one available. `setUISessionCookie` is the only
  minter of `ps_ui_session` and has always stamped `Provider "local"`, so
  that value becomes the named constant `uiSessionProvider` — read by the
  issuer and by `uiAuthMiddleware`, deliberately one constant so the two
  cannot drift open — and a UI session naming any other provider is refused.
  The roster check loses its provider guard, which is not a widening: it
  already applied to every local session, and a non-local one is now refused
  by the clause before it. Together they leave the empty-role compatibility
  branch reachable only for a local session whose user is still on the
  roster, which is the pre-RBAC single-admin deployment it was written for.
  Nothing on the wire or on disk changes — admin cookies already carry
  `Provider "local"` — so no operator session is invalidated. An explicit
  `aud` claim would be the deeper fix and is recorded for follow-up; it would
  refuse every cookie currently in flight.

  Gates: a defect gate that mints through the production proxy issuer and
  asserts 401, a class gate over foreign providers crossed with every role
  value (including an explicitly elevated one, which a restored proxy-side
  roster could carry), and three controls — the pre-RBAC empty-role local
  session still resolves to admin, enrolled local roles pass through at their
  exact role, and a local session for a deleted user is still refused, so the
  fix did not trade one bypass for another.

- **`cdr.fail_mode: closed` was not enforced when CDR was unavailable — the
  one case it exists for.** `cdrErrorOutcome` has always applied the setting
  to a Sluice that *answers* with an error, but the unavailable path — every
  instance's circuit breaker open, or no instance enrolled — returned an
  unconditional `cdrPassSkipped("SKIPPED")` from both the proxy-side liveness
  gate (`runCDRStage`) and the picker inside `safeCDRSanitize`, and
  `runCDRStage` forwards a pass. So a fail-CLOSED deployment delivered every
  document **unsanitized** for as long as no instance was available, while
  `/api/cdr/*` and the startup banner still reported CDR enabled and
  fail-closed. The in-code contract said otherwise at both sites ("the
  caller's fail_mode then decides", "callers treat nil as skip CDR and apply
  fail_mode"), and so did the runbook — `docs/OPERATIONS.md` §6 tells an
  operator to switch to fail-open "to keep traffic flowing while you fix the
  engine", advice that was a no-op because fail-closed already kept it
  flowing.

  The gap was reachable, not merely theoretical: the breaker opens after
  `FailureThreshold` consecutive failures (default 5) and stays open for
  `ResetTimeout` (default 30 s), so anything able to make Sluice fail that
  often — a crafted document class that errors the engine, resource pressure,
  a network fault — opened a 30 s window in which nothing was scanned, and
  could hold it open by repeating, with only one probe per window getting
  through. The refused documents themselves were still blocked, so the
  attacker's own failing requests did not reveal the open window.

  Both sites now route through `cdrUnavailableOutcome`, which applies
  `fail_mode`: fail-closed refuses the document with reason `cdr_unavailable`
  through the same emission as a verdict-driven block (extracted as
  `cdrEmitStageBlock`, so the two cannot drift), counts it in
  `culvert_cdr_fail_closed_total`, and leaves the breaker untouched — the
  refusal takes no reservation, so it cannot strand a half-open probe
  (CHAOS-72). A **disabled** CDR never blocks, whatever `fail_mode` says: an
  empty pool is also what "off" looks like to the picker. Fail-OPEN
  deployments — the default, and any explicit `fail_mode: open` — are
  unchanged down to the counters the skip path does not touch.

  A second way to lose the posture was closed with it (Codex #1668 P1):
  `initCDRClient` returned its "every instance failed to dial / none enrolled"
  error **before** publishing the config it was applying, so `cdrActiveCfg`
  stayed at its zero value. An appliance configured enabled + fail-closed that
  booted while Sluice was unreachable therefore read ITSELF as disabled and
  forwarded every document unsanitized — the same hole, reached by the most
  ordinary route to it, since `initCDRInfrastructure` logs the init error and
  carries on by design. The failure path now publishes the config before
  returning the error, which also stops `checkCDR` reporting a broken appliance
  as `"disabled"`/OK instead of `enabled-broken`, and stops the two recovery
  re-inits (`propagateServerRotation`, the RenewCert poller — both calling
  `initCDRClient(cdrActiveConfig())`) being handed a disabled config that
  shut CDR down until restart rather than retrying. Breaker seeding is
  unaffected: nothing is constructed after that publish.

  `cdr_fail_closed_unavailable_test.go` pins both halves: every `fail_mode`
  spelling `CDRFailOpen` folds (`CLOSED`, `Closed`, padded), the two
  disabled-CDR negative controls, a healthy instance under fail-closed still
  returning its verdict, the `runCDRStage` gate blocking the tunnel and
  writing one block page, the fail-open gate forwarding the original bytes
  with no counter movement, and 24 concurrent refusals under `-race` that
  leave the breaker open with no stale probe. The cold-start pair
  (`TestCDRUnavailable_FailClosedSurvivesPoolInitFailure` and its fail-open
  negative control) drives the real `initCDRClient` failure and was confirmed
  to fail against the un-fixed `cdrstore.go` before it passed against the
  fixed one.
  The Diagnostics `cdr` row now keys on availability as well as pool size:
  enrolled instances whose breakers are all open report FAIL `enabled-dark`
  instead of `enabled-healthy` (ported from #1421, CHAOS-67), read without
  reserving a half-open probe.

- The CDR circuit breaker could strand itself in half-open for the whole
  process lifetime, silently disabling content sanitization (CHAOS-72).
  `Allow()` hands out a half-open probe reservation that only
  `OnSuccess`/`OnFailure`/`Reset` release, and the half-open branch had no
  timer of its own — the `ResetTimeout` re-check lives only under
  `cbStateOpen`. A single caller that took a reservation and never recorded
  an outcome therefore denied every later `Allow()`, verified to still deny a
  simulated year later.

  `runCDRStage` guaranteed exactly that unpaired `Allow()` on the first
  inspected upload past `ResetTimeout`: its liveness gate ran
  `cdrActiveClient()` → `Pick()` → `Allow()`, which issues no RPC and so can
  never report an outcome, and `safeCDRSanitize`'s own `Pick()` was then
  denied and took the skip-CDR branch. `Reset()` has no production caller and
  `cdrClientPool.replace` deliberately carries breaker state across pool
  rebuilds, so nothing cleared it short of a restart. Under the default
  fail-OPEN `cdr.fail_mode` every document was then forwarded **unsanitized**,
  indefinitely, signalled only by the `culvert_cdr_pool_breaker_state` gauge.

  Two independent guarantees now hold. `HalfOpenProbeTimeout` re-arms a budget
  whose reserved probe never reported an outcome, so the breaker self-heals
  against any non-recording caller; it is the larger of 2×`ResetTimeout` and
  the configured per-file deadline (`cdr.timeout_sec`, seeded from the config
  being applied) plus a 30s grace, with a 90s floor, so it cannot preempt a
  probe that is merely slow, and each re-arm is counted as `staleProbes` in the
  breaker stats because a non-zero value means some caller is taking a
  reservation it cannot release. And `Breaker.Available()` /
  `cdrAnyInstanceAvailable()` give the hot path a non-consuming liveness gate,
  leaving the probe for the call that can record the outcome. No persisted
  state, wire format or configuration default changes.

  The same reservation leaked on two more paths. Inside `safeCDRSanitize`
  the instance is picked (reserving the probe) before the oversize gate,
  which needs that instance's profile cap, and before the cache lookup —
  both return without calling Sluice and so without an outcome, so an
  oversize file arriving first after each re-arm kept the breaker half-open
  indefinitely. And the status/UI/diagnostic selectors (`cdrActiveClient()`
  behind `GET /api/cdr/config` and five other admin handlers, plus the
  revoke/recovery client pickers) reserved through `Pick()`/`Allow()` for a
  read. The API is now split by whether the caller issues the data-path
  RPC. Every `Sanitize` caller — `safeCDRSanitize` and the admin
  `POST /api/cdr/test` — reserves (`cdrPickPooledReserved`), owns the
  reservation, records the outcome on its RPC paths, and hands it back
  through a deferred, outcome-neutral, generation-scoped `Release` on every
  return that records none (oversize, cache hit, client-side
  `file_too_large`, panic). An admin test that finds no free probe slot gets
  `503 CDR is recovering; retry shortly` instead of running uncounted beside
  the recovery probe. `Pick()`, `cdrActiveClient()` and every other caller
  select through the non-consuming `Available()`; the control-plane RPCs
  (Health, RenewCert, RevokeClient, EnrollStatus) are deliberately outside
  the data-path breaker and never feed it. Two AST walls pin both
  directions: no production code reserves except the Sanitize callers
  (`TestCDRBreaker_ReservingCallsOnlyOnTheSanitizePath`), and every
  Sanitize call reserves and defers its Release, while every control-plane
  call site is individually classified
  (`TestCDRRPC_EverySanitizeCallOwnsAReservation`).

  The breaker's coupled state — state, reset timer, half-open generation,
  newest-reservation stamp, probe budget — is now changed under ONE
  per-breaker mutex per transition instead of as independent atomics, which
  had admitted a failed probe's cleanup erasing a concurrently re-armed
  half-open episode (half-open with no generation: every reserver spun) and
  two stale re-armers both admitted past a one-probe budget. The critical
  sections are a few loads and stores, never span the RPC, and run once per
  inspected document against a sanitize RPC measured in milliseconds. The
  wedge escape measures staleness from the newest reservation rather than
  the arm time, so a slot handed back and re-taken is never reclaimed while
  live.

  Probe age and the reset timer now run on a monotonic clock. They had been
  differences of wall-clock `UnixNano` readings while the probe's own deadline
  is monotonic, so a forward wall-clock step of `HalfOpenProbeTimeout` (NTP
  correction, VM resume) declared a live probe stale and admitted a
  replacement, and a backward step held an open breaker open for the size of
  the step. Outcomes are also generation-aware: `OnSuccess`/`OnFailure` take
  the reservation the RPC ran under, and a reservation that no longer belongs
  to the current episode — a probe the wedge escape reclaimed, or a request
  admitted before the breaker opened — is dropped and counted as
  `staleOutcomes` in the breaker stats. Its late failure previously reopened
  the breaker under the replacement probe (a fail-open window), and its late
  success closed it past the probe budget. `openedAt` in the stats stays wall
  time for display. The same rule covers closed-state reservations: every
  reservation records the state episode it was admitted under, the episode
  advances on every transition (closed→open, open→half-open, half-open→closed
  or open, `Reset`), and an outcome counts only for its own episode. Without
  that, closed-state RPCs still in flight when the breaker tripped and then
  recovered fed their late failures into the new closed episode's threshold,
  and `FailureThreshold` of them reopened a just-recovered breaker.

  `cdr.timeout_sec` is bounded below (30s) but not above, and its conversions
  wrapped instead of saturating. At `9223372036` the deadline fits but
  deadline + 30s grace wrapped negative, so `HalfOpenProbeTimeout` fell to the
  90s floor and could reclaim a live probe; one second more and the
  seconds→duration conversion itself wrapped, giving the Sluice client and the
  per-call context a negative deadline that expired every `Sanitize` at once.
  Every conversion of the setting (client deadline, call context, breaker
  seed) and the probe-timeout arithmetic now saturate at the largest
  `time.Duration`; accepted values and the configuration surface are unchanged.

- The viewer-readable operator contract rendered **admin-only roster state**
  (SEC-DIAG-ROSTER-1). `GET /api/diagnostics` is deliberately `RoleViewer` — a
  management-plane health surface must not require admin — but the oversize
  admin-username row added in this window became the first contract row derived
  from the admin roster (`cfg.ListUIUsers`/`GetUser`/`UserHasTOTP`), which
  `GET /api/auth/users` gates at `RoleAdmin` on every method. With no role
  filtering in `apiDiagnostics`, a viewer or operator could read the affected
  account count, the longest username's byte length, that a legacy single-user
  login exists and is oversize, whether it is mirrored into the roster, that
  login's effective role interpolated verbatim, and **whether at least one
  affected account has TOTP enrolled**.

  The second-factor fact is the one with real attacker value: it tells a
  lower-privileged insider — or a stolen read-only monitoring session — whether
  a high-value administrator is single-factor, which is precisely the input to
  choosing a credential-stuffing or phishing target. Before the row existed the
  only signal was a one-shot boot log line, not reachable through the API at
  all, so this was a new cross-role flow (CWE-497/CWE-200/CWE-1220,
  OWASP A01:2021). `TestApiDiagnostics_NoSensitiveValues` did not catch it and
  is not vacuous — it is a secret-*material* wall (session-secret symbols, PEM,
  `/data/` paths, long hex runs) and identity metadata was outside its scope.

  `redactContractForRole` now withholds that detail below admin. The row stays
  **visible** at every role (code, `warn` status and the rolled-up verdict are
  unchanged, so monitoring and the SPA still see the condition) and only the
  roster-derived detail is withheld — hiding the row would conceal a live
  management-plane fault and is pinned by a control. The redacted message is a
  constant carrying no roster-derived value, an `ok` row is never redacted, and
  the decision is fail-closed by construction: the only input that un-redacts
  is a proven admin. No allow/deny decision, proxy path, or admission behaviour
  changes. **Operator-visible change:** viewers and operators now see this one
  row without its remediation text; sign in as an admin for the full
  remediation.

  **Review round (P1):** the first version wired the redaction into
  `/api/diagnostics` only, while `GET /api/health/explain` renders the same
  contract at the same viewer floor and returned it raw — a complete bypass
  through the alternate endpoint. Both renderers are now redacted, and a wall
  enumerates every caller of `buildOperatorContract` repo-wide so a third
  renderer fails the build until it is redacted or granted a stated exception
  (the support-bundle collector is the one recorded exception: a separate,
  admin-approved trust boundary that writes through the bundle redactor).

- The **rendered audit `Actor` is now bounded** (`boundAuditActor`, applied to
  every `AuditEntry` at the single audit write chokepoint `addAuditEntry` behind
  `auditAdd`, `store.go`).
  `truncateForAudit` was being applied by call sites to the audit **Object**,
  which made each one look bounded, while `auditEvent` derives the **Actor**
  independently and rebuilt `name + "@" + ip` from the session with no bound —
  so a CONFIGURED account name longer than the 64-byte cap (which
  `-user`/`auth.user` and `--reset-password` can persist, and which is
  deliberately never refused for its length) was retained full-length in the
  audit ring. Measured: a 300-byte name produced a 314-byte Actor. Low severity
  (the name is configured, not attacker-chosen: a retention bound, not an
  unauthenticated amplifier). Found by Codex review of the
  `auth.password_change.fail` entry added in this same window, whose first
  version claimed in its comment that the actor was "still truncated" and whose
  gate was named `AuditActorIsBounded` while asserting only on `Object`. The
  bound (`boundAuditIdentity`) keeps a 64-byte prefix plus the original length
  AND a short SHA-256 digest of the full name, so two distinct oversize accounts
  stay distinguishable in the trail. **`auditActor` itself stays the full,
  unbounded principal**: a first version of this fix bounded it, and Codex
  review showed that is not display-only — the MCP publication and approval
  handlers cast it to `approval.PrincipalID`, so two distinct admins sharing the
  bounded prefix and length compared equal and the second one's legitimate
  four-eyes approval was refused as self-approval. Non-audit consumers (MCP
  four-eyes and tool-trust, policy learning, CDR receipts, release dispatch,
  support recipients) therefore keep main's behaviour, and so does the PAC
  intent's `AuditActor`, which is bounded when its entry is rendered. A second
  Codex round found that a bound living only in `auditEventDiffID` was bypassed
  by every producer that builds an `AuditEntry` itself — the release
  `DispatchService` handed the full `auditActor` straight to `auditAdd` — so the
  bound moved to the one write chokepoint every producer reaches, the two direct
  `audit.Add` callers were routed through it, and `TestAuditActorBoundWall`
  fails if any non-test file in main or `internal/` reaches `audit.Add` another
  way or `auditAdd` stops pointing at the chokepoint. Gates: `auth_change_password_reauth_audit_test.go` asserts both rendered
  fields and that `auditActor` is unbounded, with a control requiring an
  ordinary name to pass through verbatim; `audit_actor_principal_test.go` drives
  the four-eyes publication flow with two colliding names (verified failing
  against the bound-at-`auditActor` tree) plus a self-approval control. **The
  rules: a gate must assert the property it is named for, and a length bound
  belongs to the rendering, never to a value something compares for identity.**

- The **cluster CA private key** backup completed SEC-SECRETWRITE-1. That sweep
  was scoped to the four key writers introduced in its own review window, so
  `backupCAFiles` (`enrollment.go`) — which predates it — still wrote
  `cluster-ca.key.bak` and `cluster-ca.crt.bak` with `os.WriteFile` on a fully
  predictable path, with both halves of the same defect reachable: the open
  follows a symlink planted at the path, and `perm` applies only on *creation*,
  so a `0666` file pre-created at `cluster-ca.key.bak` receives the key and
  stays world-readable. The asset is larger than any of the four already fixed —
  the cluster CA signs every Data Plane node certificate, so disclosure lets an
  attacker mint a node cert, impersonate a DP to the Control Plane and receive
  the full `ConfigSnapshot`, which carries `SessionHMAC` and the IdP secrets.
  Both writes now use `fileutil.AtomicWrite` (random `O_EXCL` temp beside the
  target, chmod + fsync, rename over it). The POSTURE is unchanged: the
  plaintext branch is still plaintext (the recorded CA-3 trade) and the
  encrypted branch already routed through `secret.SealToFile` → `AtomicWrite`;
  only the primitive changed. Gates: `enrollment_ca_backup_secretwrite_test.go`
  — 3 defect gates verified failing against the reintroduced `os.WriteFile`
  shape, plus 4 controls verified failing against a `backupCAFiles` that writes
  nothing, because deleting the dual-CA overlap recovery copy is the cheapest
  way to pass every defect gate.

- A **failed re-authentication on the admin plane is now audited**
  (SEC-REAUTH-AUDIT-1). `POST /api/auth/change-password` re-verifies the
  caller's current password, and by SEC-BASIC-1's own analysis it is the only
  credential check in the admin API that consults no lockout — a deliberate
  trade, since charging `loginLimiter` there would let a session holder lock
  themselves out of the login flow. But it audited only on SUCCESS, so the one
  unlocked password oracle was also the only silent one: a caller holding a
  stolen or hijacked session could guess the account's password at the mutating
  `apiLimiter`'s rate, indefinitely, with no trace in the compliance record —
  and the password is durable persistence that outlives the session being
  revoked (CWE-778 / OWASP A09:2021). The rejection now emits
  `auth.password_change.fail` with a bounded actor and object, deliberately
  NOT reusing `auth.password_change.refused` (which `refuseRosterChange` already
  uses for the persistence refusal — an operator must be able to tell "wrong
  password" from "the disk failed"). The lockout trade-off is unchanged; this
  adds the missing EVIDENCE and alters no authentication decision. Gates:
  `auth_change_password_reauth_audit_test.go` — 4 defect gates verified failing
  against the pre-fix branch, plus 3 controls, two of them verified failing
  against the obvious wrong fix of auditing unconditionally on entry.
- An explicitly logged-out session cookie was still accepted for up to one
  second (SEC-REVEXP-1). Two predicates decided whether a session's lifetime
  had ended and they disagreed in the fail-open direction: `Decode` accepts
  while `time.Now().Unix() <= s.Exp`, while the revocation list retained an
  entry only while `!time.Now().After(exp)`. Every production revocation
  expiry is a whole second (`revokeSessionCookie` stores `time.Unix(s.Exp, 0)`,
  `MergeRevocations` stores `time.Unix(e.Expiry, 0)`) and `time.Now()` carries
  a sub-second remainder, so for the whole wall-clock second numbered `s.Exp`
  the revocation was evicted — and `delete`d — while the cookie it named was
  still honoured.

  Reproduced against the real `Decode`: a session with `Exp == time.Now().Unix()`,
  revoked the way the logout path revokes it, reported `IsRevoked=false` and
  `Decode err=<nil>`. `ExportRevocations` applied the same test, so the hole
  also propagated: the entry vanished from the on-disk revocations file and
  from the next DP→CP gossip export on the same tick. The window is predictable
  to anyone holding the cookie, because `exp` is in it.

  There is now one oracle (`internal/session/revocation_expiry.go`) and the
  revocation list is the side that moved, because a revocation must outlive the
  session it revokes and never the reverse. `Decode` was deliberately left
  alone: tightening it would shorten every session and change the meaning of
  the `exp` claim this appliance signs into a cookie. The change can only
  retain an entry longer — by under one second — and never drop one sooner, so
  it cannot resurrect a session, refuse a legitimate logout, or unbound the
  list. Applied at all four sites that decided the question: `IsRevoked`,
  `IsUserRevoked`, `ExportRevocations` and `MergeRevocations`.

  Gates: 9 new tests in `internal/session/revocation_expiry_test.go` — **7
  regression gates**, each measured to fail against the pre-fix predicate and
  pass after it (the differential against `Decode`, the map-level boundary, the
  persistence and cluster-merge paths, the username-keyed list that gates a
  deleted account, and a concurrent storm across all five entry points under
  `-race`), plus **2 controls** that pass under both predicates by design and
  are therefore not regression evidence: `UnambiguouslyPastEntriesStillEvict`
  (2 s / 1 min / 24 h old entries still evict — had it flipped, the fix would
  have made the list an unbounded leak) and `MalformedPeerExpiries` (`Expiry` of
  `0`, `-1`, `-(1<<40)` refused, none panics — widening retention must not
  widen what a peer can inject). An earlier revision of this entry claimed all
  of them failed pre-fix; that was wrong and is corrected here, because
  presenting a control as a regression gate makes the evidence irreproducible.

  One pre-existing assertion (`TestRevocationList_PastExpiryEvicts`) used a
  `-1ms` expiry, which is inside the current second and therefore no longer
  expired; it now uses `-1m` and the boundary it used to straddle is pinned by
  two of the new gates.

  Review of the rest of the in-flight change set — the IDNA memo, the urlcat
  lock-free read view, the config BOM fix, and four reported findings against
  branches this change does not own — is recorded in
  `docs/engineering/security-reviews/2026-10-11-in-flight-session-and-category-plane-window.md`.

- Distributed rate limiting could admit a request over the cluster-wide limit
  whenever a Control Plane broadcast landed in the middle of a decision.
  `AllowClusterAware` samples its clock before taking the shard lock and hands
  that instant to `FreshCount`; the gossip loop's `ApplyRemoteCounts` stamps
  the broadcast with its own `time.Now()`. A broadcast applied between the two
  steps therefore carried a stamp a few microseconds *ahead* of the decision's
  clock, `FreshCount` computed a negative age, and CHAOS-61's clock-rollback
  rule zeroed the remote half of the decision — the node decided on its local
  count alone and admitted (observed in CI as
  `TestDistributedAdmission_ProductionWiring` admitting the SOCKS5 leg, 6 local
  + 2 remote against a limit of 8, with gossip every millisecond).
  `ClusterFreshness` never had the defect because it loads the stamp and then
  reads the clock, so diagnostics reported "fresh" while enforcement treated
  the same instant as stale. `FreshCount` now re-reads the clock once, only on
  a negative age and after the stamp was loaded: a stamp still in the future
  against that read is a genuine rollback and stays stale (all 17 CHAOS-61
  gates unchanged); one that merely postdates the caller's clock is fresh. The
  steady-state hot path takes no extra clock read. Gates:
  `internal/admission/cluster_ratelimit_inflight_broadcast_test.go`
  (deterministic injected-clock gate RED on the previous code; an end-to-end
  gate through `AllowClusterAware` that caught 2 fail-open admissions in 5000
  on the previous code; and the rollback control).

- The Control Plane → data-plane snapshot apply replaced the IP filter by
  storing a freshly built filter into the package-level `ipf` handle, which
  `proxy.go` and `socks5.go` read on every request with no synchronization
  (RISK-030). That is a data race on the first admission gate of an inline
  gateway — undefined behaviour under the Go memory model — reproduced with
  `go test -race` on main. The apply now replaces the live filter's contents in
  place through the new `IPFilter.Replace`: one writer lock, one immutable view
  publish, so a lock-free reader observes the previous configuration or the new
  one and never an intermediate, and the handle itself is never written after
  its declaration (the posture `rl` and `bl` already had). No allow/deny verdict
  changes: a differential gate compares every mode, including the fail-closed
  corrupt one, against the previous fresh-filter shape. A source wall now
  rejects any production reassignment of `ipf` or `rl`, and the snapshot test
  fixtures bind fresh owners into both handles instead of restoring the object
  the apply mutated. Gates: `controlplane_snapshot_ipf_race_test.go`
  (`TestRISK030_*`, RED under `-race` against the previous code),
  `TestIPFilterReplace_*` and the `Replace` republish case in the IPFilter
  mutator inventory.

- A read-only **viewer** could read the HA join token and from it obtain the
  **cluster CA private key** (SEC-HATOKEN-1). `GET /api/cluster/ha` is gated at
  `RoleViewer` — correctly, it is a dashboard — and on a leader it
  unconditionally included `deploy_cmd`, which interpolates the live
  `--ha-token` plus the gRPC address and the CP TLS cert/key/CA paths. That
  token is the *sole* credential for the `HASync` RPC (`VerifyToken` is the only
  gate, and the CP listener uses `tls.VerifyClientCertIfGiven`, so no client
  certificate is required), and `HASync` answers with the exported cluster
  state, the full published `ConfigSnapshot`, and the cluster CA private key
  wrapped under PBKDF2 of *that same token*. With that key an attacker mints
  node certificates the Control Plane trusts and enrolls as a data plane. The
  field is now suppressed per role rather than by raising the route's `MinRole`,
  which would have removed the HA panel from operators and viewers.

  The admin UI needed the same fix on its own side: the HA panel's
  `<pre id="ha-deploy-cmd">` was only ever *assigned* when a response carried
  `deploy_cmd` and never cleared, so in a single tab an admin who opened the
  Cluster panel and logged out left the join token in the DOM — and in the
  click-to-copy handler — for whoever signed in next. Three guards now close it:
  the render path clears on an absent field, `applySession` clears on any
  non-admin session, and the write re-checks the current role — `loadHA` is
  async, so an admin response still in flight could otherwise resolve after the
  session changed and write the token back into the DOM that had just been
  cleared.

- Host-header case variation evaded every country-scoped **deny** rule
  (SEC-GEOHOST-1). `geoHostKey` stripped a port and nothing else — no
  lowercasing, no IDNA, no trailing-dot trim — while `matchDestNorm` hands the
  country branch the raw host; its comment claiming country checks "normalize
  internally" was false, and every other destination matcher (blocklist, urlcat,
  policy FQDN) already normalized. Each spelling was a distinct host→IP cache
  key and the warm is off the request path, so every first request missed, the
  rule did not match, and evaluation fell through to a lower-priority allow. A
  19-character hostname has ~2^15 spellings, so the supply of misses is
  unlimited, and DNS is case-insensitive so the connection still reached the
  blocked destination. `geoHostKey` now returns `hostutil.NormalizeHost`, which
  is the chokepoint all four call sites share, closing case, trailing-dot and
  IDN U-label variance at once while passing IP literals through verbatim.

- A matched rule carrying an **action this build does not dispatch** was
  ALLOWED, and shadowed every deny rule beneath it (SEC-POLICYACTION-1).
  `applyPolicyDecision`'s `switch match.Action` had no `default:`, so an
  unrecognized action fell through to the trailing `return "OK", false`: the
  request proceeded, no decision was recorded, and because the scan is
  first-match-wins, no lower-priority rule was consulted. One such action on a
  priority-1 `destFqdn: "*"` rule disabled the whole rulebase under it. `Action`
  was validated only on the API ingress path, so `PolicyStore.Load` (the
  operator-managed policy file) and `PolicyStore.ReplaceAll` (the CP→DP snapshot
  apply and replace-mode import) installed one verbatim — reachable from a
  mixed-version cluster, a restored backup or a renamed action without any hand
  editing. Now fail-closed on both sides: `applyPolicyDecision` resolves the
  action through `canonicalPolicyAction` and blocks when it cannot, and
  `policyRulePersistable` refuses to install such a rule — both halves, because
  blocking at dispatch *without* dropping at install would turn a rule that
  previously allowed into one that blocks and shadows everything beneath it.

  `canonicalPolicyAction` is deliberately tolerant in two ways, neither ever
  more permissive than the pre-fix fall-through: **case is folded**, because
  policy files carry lowercase spellings and pre-fix `"allow"` was allowed (it
  still is, while `"drop"` and `"block_page"` now block where they previously
  allowed); and **unset is not unrecognized** — an empty action resolves to
  `Allow`, exactly what the fall-through did, so no deployment's traffic changes
  direction. The hole being closed is the version-skew case, which is never
  empty. The API ingress validator keeps its exact-spelling contract, because
  ingress refuses sloppy input at the door while this decides what to do with
  data already on disk. The sibling gate in the same engine already behaves this
  way: `IPFilter.Allowed` denies all traffic on an unrecognized mode.

- A policy file the load gate refused **in full** read downstream as "no policy
  configured" and flipped the startup default action to passthrough
  (SEC-POLICYDROP-1). With `proxy.default_action` unset, the derivation in
  `loadRewriteAndDefaultAction` selects `allow` for an empty rulebase and `deny`
  for a non-empty one — and the shim fed it `len(policyStore.List())`, the
  **installed** count. Because `PolicyStore.Load` drops the rules its
  fail-closed gate refuses, and `initPolicy` runs before
  `initRewriteAndDefaultAction`, a file whose every rule was refused installed
  nothing, counted zero, and turned the gateway into an open forward proxy on
  restart. The composition is the defect: a gate refusing one fail-open *rule*
  produced a fail-open *default*. Fixing SEC-POLICYACTION-1 made it reachable
  from the most plausible shape of all — a hand-written or downgraded-binary
  policy with one consistently wrong action spelling — so for that
  configuration the fail-closed fix alone would have admitted strictly more
  traffic than the defect it closed. The older `SubjectMatch` and invalid-auth
  refusals could empty a rulebase the same way.

  `PolicyStore.ConfiguredRuleCount()` now reports installed **plus** refused
  (banked per load by `droppedOnLoad`, cleared by a clean reload, untouched by a
  load that failed to read or parse), and the shim passes it. `Load` also emits
  one aggregate warning when it refused anything, since the per-rule warnings
  said what was dropped but not what it meant for the posture. The loader's own
  logic is unchanged — it was always correct for the question it was asked, and
  only the question changed — and an explicit `default_action` still wins in
  both directions. Rejecting the load outright was considered and not taken:
  `initPolicy` escalates a `Load` error to `logFatalf`, so one unrecognized
  action in an operator's file would become a boot failure, which is an
  availability decision for the product owner rather than a regression fix.

- An **unauthenticated** `POST /api/auth/logout` wrote attacker-chosen,
  **unsigned** entries into the persisted and cluster-gossiped revocation list
  (SEC-REVOKE-1). `apiAuthLogout` discarded `decodeSession`'s error
  (`sess, _ :=`) and then called `revokeSessionCookie` unconditionally — and
  that function does its own base64+JSON decode with no signature check, on the
  stated premise that the "HMAC [was] already verified by decodeSession", which
  was false on exactly this path. The route is on the public allowlist, so a
  cookie of the shape `base64({"sub":"…","exp":9999999999}).garbage` inserted a
  permanent entry (the expiry is attacker-chosen and eviction is lazy-on-expiry)
  into an unbounded map. `SaveRevocations` then rewrote the whole revocations
  file on every request — O(n) per insert over a set the caller is growing — and
  the cluster revocation sync gossiped the entries to every node, which merged
  and persisted them. The admin server sets no `MaxHeaderBytes`, and the 1 MiB
  `MaxBytesReader` bounds the body rather than the `Cookie` header, so each of
  the 60 requests/min/IP the API limiter allows could carry ~1 MiB of
  permanently retained key. The revocation write now requires a cookie whose
  HMAC actually **verified** — and deliberately not an *admissible* session: a
  token this build refuses (a deleted user's, or one minted for the proxy plane)
  is still a token the appliance signed, and revoking it is right. A signed
  token can only revoke itself, and whoever holds it could already use it. What
  must not be revocable is a payload nobody signed. Clearing the cookie stays
  unconditional and the answer stays 200, so a browser holding a junk cookie can
  still get rid of it and the endpoint is not an oracle.

- A **partial** `POST /api/security` silently disabled the per-IP rate limiter
  and persisted the change (SEC-SECPARTIAL-1). `rateLimitRPM` was a plain `int`
  guarded by `if body.RateLimitRPM >= 0`; an absent JSON field decodes to `0`
  and `0 >= 0` is always true, so every body omitting it called
  `rl.Configure(0, …)` = disabled, after which `adminSettingsSave` and
  `saveConfigVersion` made it durable. The endpoint's own published contract
  declares the body a "Partial update — supply only the fields to change" with
  `rateLimitRPM` optional, every other field honoured that, and three of the
  shipped admin UI's buttons send exactly such bodies (`{ipAdd}`, `{ipRemove}`,
  `{ipFilterMode}`) — so adding one IP to the IP filter turned off proxy rate
  limiting. The field is now a `*int`, so absence means unchanged and an
  explicit `0` still disables; a negative value is refused with 400 **before**
  any field is applied, where it was previously ignored in silence.

- Node-local key material was written with `os.WriteFile` on a predictable
  path, which follows a planted symlink and inherits a planted file's mode
  (SEC-SECRETWRITE-1). Four writers introduced in this window were affected:
  the upstream credential KEK (`.upstream_cred_key`, which unseals every
  parent-proxy password), the webhook KEK (`.alert_webhook_key`), the request
  history PBKDF2 salt (`<history>.salt`), and the CDR mTLS client bundle staged
  at `<bundle>.{crt,key}.tmp`.

  Both halves were reproduced against the tree. `os.ReadFile` on a **dangling**
  symlink reports `fs.ErrNotExist` — exactly the condition every mint treats as
  "no key yet" — so planting a link at a key path steers control flow into the
  mint branch and then redirects the write out of the state root entirely. And
  `perm` applies only on *creation*, so a `0666` file planted at
  `client.key.tmp` receives the CDR client private key and stays
  world-readable, no symlink required. In the escape case the appliance
  believes it persisted a key: remove the target and every sealed upstream
  credential becomes `credentialState: unusable`, no parent is eligible, and
  the pool fails **open to DIRECT egress** — the parent-proxy chain bypassed.

  The three mints with no rendezvous requirement now use `fileutil.AtomicWrite`
  — the repository's existing durable-write chokepoint, already used for the
  policy-learning subject key — whose `rename(2)` *replaces* a planted link
  rather than writing through it. `installRenewedPEMs` cannot: its `.tmp` names
  are a deliberate rendezvous `finishStagedRenewal` looks up by path at the next
  boot, so it uses the new `fileutil.WriteFileExclusive`, which clears any
  pre-existing entry and creates with `O_EXCL` at the requested mode (and
  fsyncs, which makes that function's existing "never a half-written file"
  promise true). No path, content or mode on disk changes; only the branch that
  *creates* a file is affected. Gates: 26 across five files, every defect gate
  verified failing against the verbatim `os.WriteFile` shape, with controls
  pinning that a stale rendezvous file is still superseded (refusing it would
  wedge CDR renewals after the first crash), that SEC-WHSIGN-1's "a failed
  decrypt never mints" and CHAOS-62's `ErrSaltUnusable` refusal are unchanged,
  and that 120 racing writers never leave a torn file. Review:
  `docs/engineering/security-reviews/2026-09-22-resilience-sweep-and-upstream-v2-window.md`.

- A role string this build does not enroll became FULL ADMIN
  (SEC-RBAC-ROLE-1). `POST /api/auth/users` validates the role it is given,
  but `LoadUIUsersFile` — the door the same roster arrives through from disk —
  validated nothing and stored `role` verbatim. `VerifyUIUser` then returned
  that value on a successful login, `apiAuthLogin` minted a genuinely signed
  session with it, and `uiAuthMiddleware`'s backwards-compatibility branch
  promoted it: the branch was written for the pre-RBAC *empty* role but keyed
  on `!role.HasRole(RoleViewer)`, and because `rolePriority` is a map whose
  unenrolled keys read as 0, that predicate is true of *every* unrecognized
  string — so `"read-only"`, `"Admin"` and `"superuser"` all resolved to
  `RoleAdmin`, on every request, for the full session TTL, with
  `/api/auth/status` reporting `role: admin` to match. Nothing is forged; the
  appliance signs the cookie itself. The reachable sources are the ordinary
  raw-persistence ones: restoring a backup taken by a newer build that enrolls
  a role this one does not, a hand-edited or partially-corrupted
  `ui_users.json`, or any future writer that bypasses the admin API. Fixed at
  all three layers — `HasRole` now refuses an unenrolled *requirement* (which
  also closes a latent hole where `MinRole: RolePublic` or a typo in
  `ui_routes_meta.go` would have admitted a viewer to an elevated method),
  `LoadUIUsersFile` clamps an unenrolled non-empty roster role to `viewer`
  rather than dropping the account, and the session resolver splits the compat
  branch so `""` still means admin for pre-RBAC deployments while every other
  unenrolled value is refused with a 401 and a cleared cookie. The clamp is
  surfaced as `culvert_admin_roster_role_clamped_total` and as
  `adminRosterRoleClamped` on `/healthz` and `/api/stats` when non-zero. The
  earlier names `culvert_ui_roster_role_clamped_total` and
  `uiRosterRoleClamped` (T-64) are still emitted with the same value as
  deprecated aliases for one release window.
- An unauthenticated client could park a gateway core for minutes with one
  request by choosing a very long destination host (CHAOS-69, register rows
  PX-21/PX-23/PX-24/PX-25). The destination authority is written by the client,
  `net/http` admits its 1 MiB default of request line plus headers, and nothing
  bounded it. It was copied verbatim into the process log and the durable
  request-log entry — a 256 KiB host wrote 262,228 bytes to a rotating file that
  keeps one archive — but the copy was the smaller half: the authority is also
  walked label by label by every destination matcher, and two of those walks are
  quadratic in its length. The URL-category store probes every suffix beginning
  just past a `.` against its reverse index, and the Layer-2 community feed
  (enabled by default in the shipped compose file) opens one BadgerDB read
  transaction per label. Measured through the real request path with one
  ordinary category-group rule present: 4 KB of host cost 19.6 ms, 16 KB cost
  260 ms and 64 KB cost **3.94 s** of CPU — so roughly sixteen minutes at the
  1 MiB header default, inside the request goroutine, holding the connection and
  a per-IP connection slot, and spent *before* authentication. Roughly 256 KB/s
  from one client saturated a four-core gateway, and the three front-door
  limiters ship disabled. The same value was also retained as a top-hosts map
  key, whose 10,000-entry cap bounds the entry count and never bounded the key
  size (about 10 GiB of heap at the cap with megabyte keys), and reached the same
  quadratic lookup from two viewer-role admin endpoints.

  The destination is now bounded in two tiers, because the DNS limit governs the
  *canonical* form of a hostname rather than the bytes on the wire: a **1024-byte
  pre-cap on the raw authority** at the entry point, ahead of every sink and every
  matcher (in particular ahead of the IP filter and rate limiter, which both write
  the host into the request log), and a **253-byte bound on the normalized A-label
  form** at the existing canonicalization gate. The raw tier has to be generous
  because an internationalized domain name *shrinks* under IDNA — `é`×40 in four
  labels is 323 raw bytes and 187 canonical, and the widest legitimate case is 883
  raw to 251 canonical — so a raw bound at the DNS limit would have refused
  ordinary international destinations with a 400; its value is derived from the
  maximum Punycode expansion and re-measured against the shipped normalizer by
  test. The canonical tier is what keeps that generosity from being a hole, since
  dot-dense ASCII does not shrink and is therefore refused. A refused request
  answers 400 without echoing the value, creates no state, and is counted by
  `culvert_proxy_oversize_host_rejected_total` with a rate-limited log line naming
  the length and the tier rather than the value. Operator runbook:
  `docs/operator/destination-host-bounds.md`.

- An ordinary password change silently destroyed the account's TOTP second
  factor (SEC-TOTP-1 / RISK-029). `apiAuthLogin` refuses to issue a session for
  an enrolled account until `verifyLoginTOTP` accepts a code, so the enrolment
  is a real second factor whose purpose is to survive a password compromise —
  but `Config.SetUIUser` and `Config.SetAuth` assigned a freshly-built
  `uiAdminUser` record over the stored one, so every credential write dropped
  `totpSecret`, `backupCodes` and `totpLastCounter`. The removal was durable
  (the next roster save persisted it), carried no audit entry naming the
  de-enrolment, gave the account holder no signal, and required no proof of
  possession of the authenticator. Whoever held the current password could
  therefore permanently remove the control that outranks it, turning a
  temporary session or credential compromise into durable password-only access
  to the admin plane. Reachable from `POST /api/auth/change-password` (any
  principal from viewer up, for its own account), `POST /api/auth/users`
  (admin, any account) and `POST /api/settings/auth`. Resetting
  `totpLastCounter` to zero was a second defect on the same line: it reopens
  the one-time-password replay window (RFC 6238 §5.2) that the restore path
  refuses to reopen without `--allow-counter-rollback`. Every credential write
  now goes through one constructor that carries the enrolment across;
  de-enrolment stays the job of the explicit `ClearTOTP` primitive. The
  `--reset-password` break-glass keeps its outcome — an operator who lost the
  authenticator as well as the password depends on it — but now clears
  deliberately and prints that the account became single-factor. The replay
  counter is part of the enrolment, not a separate durable fact: `ClearTOTP`
  now clears it too, and `SetTOTPSecret` resets it when the KEY changes
  (but not when backup codes are re-issued for the same key, which would
  reopen the replay window for a live secret). Without that, the counter
  outlived de-enrolment and refused the re-enrolment the break-glass warning
  instructs the operator to perform — it had been zeroed only as a side effect
  of the record replacement this change removes. That comparison asks whether
  the KEY changed, not whether the stored string did: the verifier folds case
  and trims whitespace before base32-decoding, and Go's decoder ignores a
  secret's non-canonical trailing bits, so spellings that differ as strings can
  name one authenticator (`MZXW6` and `MZXW7` decode to the same key). A
  string comparison read a backup-code re-issue in a different spelling as a
  key change and zeroed the counter for a live key. The canonicalisation is now
  one function that the verifier itself uses and that backs the exported
  `totp.SameKey`/`totp.Usable`, so the comparison and the code generator cannot
  disagree, and an unusable incoming secret never counts as evidence that the
  key changed.

- **The tracing-header bound is now proven over a socket, and one of its stated
  exposures was not reachable (SEC-REQID-2).** Every SEC-REQID-1 gate drove
  `httptest.NewRequest` + `Header.Set`, which installs a header value the wire
  may not be able to deliver — the trap `bootstrap_host_injection_test.go`
  already exists for, and the reason the Host-header bound carries an empirical
  wall while these headers carried none. Measured against a real `net/http`
  server: of 256 byte values, **224 are delivered into a header value verbatim
  and 32 draw a 400 before the handler runs** — exactly `0x00`–`0x1F` minus
  `TAB`, plus `0x7F` — because `textproto.ReadMIMEHeader` refuses them, and
  `setupRequestTracing` has exactly one caller whose request always comes from
  that parser. So `ESC`, `NUL` and `BEL` never reached a log line by any path,
  and the claim that they did (in the code comment, this changelog and the
  operator runbook) came from measuring the function rather than the wire; all
  three are corrected. The archived agent note still carries it
  (`docs/agent-context/history/observability-and-alerts.md`), and that copy is
  hash-frozen by design — all 108 preserved blocks must reconstruct the
  original `CLAUDE.md` byte for byte — so the correction is recorded in
  `docs/agent-context/errata.md`, the mechanism that tree provides for a
  verified conflict in the preserved guide, rather than by editing the
  archive. The bound is **not** redundant for it: it is
  load-bearing on 130 delivered byte values — `TAB`, `SPACE` and every byte
  `0x80`–`0xFF` — and the length half is reachable in full. Seven new gates
  drive the real `setupRequestTracing` behind a real listener and pin the
  delivered/refused partition in both directions, so a future Go release that
  widens what a header value may carry fails the build instead of quietly
  widening what reaches the forensic log. No behaviour change: bound, charset,
  counters and emitted bytes are untouched.

- Client-supplied tracing headers reached the process log unbounded
  (SEC-REQID-1). `setupRequestTracing` runs on 100% of proxied traffic — the
  second statement in `handleRequest`, ahead of the connection limiter, the IP
  filter and authentication — and reads two headers the *client* chooses,
  `X-Request-Id` and `Traceparent`. It bounded neither. The accepted request id
  then reached roughly twenty process-log sites (every `POLICY_*` decision line
  plus `AUTH_FAIL` / `IP_BLOCKED` / `RATE_LIMITED` / `BLOCKED` / `INVALID_HOST`)
  as a bare `%s` inside the `{req_id=… identity=… action=…}` block, the response
  header, and the forwarded request. The only sanitisation was `strings.ReplaceAll`
  for CR and LF — the CWE-117 barrier, which correctly stops whole-record forgery
  but is not what `sanitizeLog` does, since `sanitizeLog` scrubs every byte below
  `0x20` and `0x7F`. A space or a `TAB` could therefore inject extra `key=value`
  tokens into the decision line's brace block, and any byte `0x80`–`0xFF` reached
  the log unchecked. (No other control character was among the reachable cases —
  see the SEC-REQID-2 entry above, which corrects an earlier version of this
  paragraph.) Nothing bounded the length at all: the proxy
  listener sets no `MaxHeaderBytes`, so net/http's 1 MiB default was the only
  ceiling, and eight requests carrying a 512 KiB request id wrote 4,194,968 bytes
  into the process log — the same amplification CHAOS-63 measured against the
  audit log, reached here through the unauthenticated data plane rather than the
  admin API, and invisible to every storage-health surface because each of those
  writes succeeds (CWE-778, OWASP A09:2021). Both headers are now bounded and
  charset-checked where they are read: at most 128 bytes (request id) or 255
  (traceparent), visible ASCII with no whitespace. A value that fails is treated
  exactly as an absent one — a fresh id is minted and overwrites the hostile value
  on the request, the response and the wire — so a tracing header can never decide
  whether traffic flows. Rejections are counted as
  `culvert_tracing_header_rejected_total{header=…}`, surfaced on `GET /api/stats`
  and in the admin UI, and logged once per minute without ever echoing the
  refused value. A repeated header is refused on the same grounds — `Header.Get`
  validates only the first field value, so an acceptable first `X-Request-Id`
  paired with a hostile second one previously reached the upstream uncounted —
  and the minted value replaces the whole field, so exactly one value is
  forwarded.

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
- Admin-roster changes reported success on a durable write that never landed
  (CHAOS-70). `ui_users.json` is the only durable home of the admin roster,
  password hashes, roles, TOTP secrets, consumed backup codes and the TOTP
  replay counter, and every mutation changes memory first and persists second.
  Three handlers logged the persist error and answered 2xx anyway — precisely
  the three an operator reaches for during an incident. On a full or read-only
  data volume, deleting a compromised administrator returned `204 No Content`
  and was audited as done while the account returned at the next restart with
  its original password hash, role and TOTP enrolment; a role downgrade returned
  `{"ok":true}` and the privilege came back; a password rotation returned
  `{"ok":true}` and the leaked password still authenticated. The response, the
  UI and the audit log all reported success, and the divergence between memory
  and disk stayed invisible until a restart materialised it. The same rule was
  already written down, reasoned out and tested twenty lines away — for the
  one-time setup wizard only. `POST/DELETE /api/auth/users` and
  `POST /api/auth/change-password` are now durable-or-refused: the in-memory change is
  rolled back wholesale (hash, role, TOTP secret, backup codes and replay
  counter together), the request fails with an actionable `500`, and the
  refusal is audited as `<action>.refused`. `fileutil.ErrReplacedNotSynced` is
  deliberately treated as committed — the content already landed. New counters
  `culvert_admin_roster_persist_failures_total` and
  `culvert_admin_roster_persist_degraded_total` name which administrative
  decision was affected, which the pre-existing `storage_write_failed` alert
  cannot. The two login-path roster writes (TOTP replay counter, backup-code
  consumption) stay fail-open by recorded decision — refusing them would lock an
  operator out of the appliance during the incident they need it to diagnose —
  but no longer discard their error. See
  `docs/operator/admin-roster-durability.md`.
- **Security (admin UI): the Settings panel's Save button changed the admin
  credential without ever writing it to disk, accepted an empty password, and
  could disable local authentication.** `POST /api/settings` called the
  credential setter and nothing else, and the admin credential is not carried in
  `admin_settings.json`, so a rotated admin password answered `200 {"ok":true}`,
  was audited as a successful `settings.update`, authenticated immediately — and
  **reverted at the next restart, where the previous (possibly leaked) password
  authenticated again**. No disk fault was required, which makes it worse than
  the three handlers above. Password complexity was validated only when the field
  was non-empty, so saving the panel with a blank password box installed
  `bcrypt("")` as an admin credential — and, for a changed username, a new admin
  account that authenticated with no password; clearing both fields disabled local
  admin authentication outright, behind a *"Settings saved"* toast. Empty user and
  empty password are now refused with `400` (run unmatched traffic without
  credentials via `defaultAuthOutcome=Exempt`, which says so), and the credential
  change is durable-or-refused through the same transaction as the other three.
  Fixing the persistence alone would have been a regression, because persisting is
  what would have made the two input faults survive a restart. The roster snapshot
  now also captures the legacy credential pair, so a refused rotation **restores
  the previous credential** instead of deleting the account — a control caught
  that the first version of this fix locked the administrator out.  See
  `docs/operator/admin-roster-durability.md`.

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

- The MCP live side-effect boundary's pre-send re-ask is documented and its
  concurrency premise is now pinned. PR #1370 added a second authority re-ask
  inside the upstream client's TLS dialer, after the handshake and before
  anything is written — the right place for the check, but net/http runs a dial
  on its own goroutine (`Transport.queueForDial` → `go dialConnFor`), and that
  goroutine is not joined to the request. When the caller's context is cancelled
  while a dial is in flight — an ordinary client disconnect or request timeout —
  `Call` unwinds at once while the dial goroutine completes its handshake and
  invokes the hook, so `CallOptions.PreSend` can still be running after `Call`
  has returned. Reading a refusal back out of variables the hook captured is
  therefore a data race, and synchronising them removes the race without
  establishing a hand-off, since a late hook can still write after the only
  reader has gone; the executor consequently carries the verdict in the returned
  error instead. That correction shipped with the read-first identity-band change;
  what is added here is the evidence and the contract it rests on.
  `TestPreSend_MayStillBeRunningAfterCallReturns` pins the lifetime property
  deterministically against the real transport — the executor's own gates use a
  fixture that joins the hook's goroutine, which is exactly the happens-before
  edge production lacks, so nothing else asserts it — and `CallOptions.PreSend`
  now states the contract for every future caller: it is a pure predicate whose
  lifetime is not `Call`'s, so everything a verdict needs in order to be
  diagnosed belongs on the error. What the gate asserts is the HAZARD, not the
  schedule: a transport that NARROWS the hook's lifetime by joining its dial
  goroutine leaves the carrier correct — conservative rather than required — so
  the gate skips with that finding rather than failing, and only a `Call` that
  will not return even once the hook is released is a real failure. Asserting
  that the hook DOES outlive `Call` would have made a safe narrowing look like a
  regression, and would have reported it as a 30-second deadlock.

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

- Two security-regression gates added for the memoized IDNA slow path
  (`internal/hostutil/idnamemo.go`), each run against **both** retention tiers
  and each verified failing in both against the specific defect it claims to
  catch. No runtime behaviour changes; ported from the closed PR #1617.

  `NormalizeHostStrict` is the fail-closed dispatch gate: `ok=false` means the
  request is REFUSED, so a host that cannot be canonicalized never reaches FQDN,
  blocklist or category matching un-normalized (RISK-013). The memo's slots are
  shared by design — each tier is direct-mapped and a colliding host overwrites
  the entry that was there — so the crossing that matters is a REJECTED host
  meeting a resident ACCEPTED entry, which the existing collision test cannot
  observe because it alternates two accepted hosts.
  `TestIDNMemo_RejectionIsNeverUpgradedToAcceptance` pins that crossing in
  both directions in the main tier, and in the long tier (which never retains a
  rejection) on every round. Against a memo whose hit skips the full-key
  re-verification, `xn--0.example.com` is answered as another host's A-label
  with `ok=true` — a client-chosen unnormalizable authority admitted and
  evaluated as a different destination than the one it names.

  `TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer` pins that the stored key is
  a CLONE of the caller's string. The key arrives as a substring of whatever
  buffer the caller holds — on the request path, net/http's header buffer — so
  an entry that kept it would pin that whole backing array per slot while every
  byte-counting test still reported a short key. The gate drops every
  reference it holds to a 16 MiB buffer the probe host was sliced out of and
  asks the collector what is still reachable: a few hundred bytes when the key
  is cloned, ~16.8 MB against the un-cloned shape, for a 25-byte main-tier key
  and a 505-byte long-tier key alike. The review is
  `docs/engineering/security-reviews/2026-10-13-idna-memo-and-host-bounds-window.md`;
  its single-tier "un-memoized band is deliberate" finding is superseded by the
  long tier and its gate for that gap is intentionally not ported.
### Performance

- Category-group membership is now resolved by index instead of by walking
  every group. `categoryGroupMatchesHostScratch` runs once per category-group
  access rule per proxied request and prefers the rule's
  `DestCategoryGroupID` — the authoritative, rename-safe link the admin API
  stamps on every rule saved against an existing group — but
  `MatchesCategoryByID` resolved that id by ranging the whole group map
  comparing IDs, with the store's read lock held across the walk, because the
  map is keyed by *name*. So the path production takes was O(number of groups)
  while the denormalized-name fallback it supersedes was already an O(1)
  probe, and the store is capped at 1000 groups.

  Measured on a 4-core Xeon @2.10 GHz (medians of n=3, both arms in one
  session), one resolve: **117.6 → 89.5 ns at 4 groups, 349.3 → 82.2 at 64,
  1317 → 89.0 at 256, 5298 → 86.6 at 1000** — linear at ~5 ns/group before,
  flat after. End to end through the policy scan with 20 category-group rules
  and a categorized destination: **121 µs → 2.25 µs per request** at the
  1000-group cap (53.8×). An *uncategorized* destination — clean traffic to a
  host no tier classifies, and the common case — now short-circuits the whole
  per-rule probe at the call site, because neither branch can match an empty
  category: **125 µs → 395 ns** (317×). Verdicts are unchanged; the index is
  derived state rebuilt wholesale at the one content-mutation chokepoint, and
  a stale index degrades to "not resolved" rather than to a wrong group.

  Also fixes a **data race** on the same path, reported by the race detector:
  `MatchesCategory` resolved through `GetByName`, which releases the lock
  before returning the live group, and then read that group's category set
  with no lock held — while `Update`, `UpdateByID`, `Load`, `ReplaceAll` and
  the rollback path all *reassign* that field under the write lock. Reachable
  as proxy traffic evaluating an un-migrated category-group rule concurrent
  with an admin edit of that group. The probe now happens inside the single
  read-lock critical section, which also removes the old shape's second lock
  round trip. Only deployments using category groups in policy rules are
  affected; no configuration, API or metric surface changes.

### Fixed

- Six support-domain durable writes bypassed `fileutil.AtomicWrite`, the
  repository's durable-write chokepoint (CHAOS-85) — the same chokepoint the
  SEC-SECRETWRITE-1 entry above adopted for key material. They hand-rolled
  `os.WriteFile(tmp)` + `os.Rename`, which is atomic for a *reader* (no torn
  file is ever visible) but is **not fsynced**, and — the serious half — is
  invisible to the storage-health plane. `storageDegraded()`, the rate-limited
  `storage_write_failed` alert, the degraded operator-contract row and the
  Prometheus series are all driven by the observers `storage_health.go`
  installs on `fileutil`, so a write that never calls `fileutil` cannot raise
  any of them: on a full or read-only volume these writes failed **silently**
  while the operator contract kept reporting healthy. Affected: the secure-upload
  config (whose `Enabled`/`Origin` gate egress), the upload queue entry and its
  sealed blob, the support-recipient registry, the debug-level elevation, and
  the support-bundle approval state. This is the defect class
  `audit_writefail_test.go` already pins for the audit JSONL (ST-8), in a domain
  whose own sibling `support_telemetry_config.go` already used the chokepoint.

  The durability half matters most at `writeBundleState`. `createSupportBundle`
  deliberately writes the PENDING state **first**, before the tgz and the
  manifest, because `readBundleState` grandfathers an **absent** state file to
  READY — which is exactly what the download gate checks, so a bundle whose
  manifest committed without its state would be downloadable with no admin
  approval, exporting its INTERNAL sections without the mandatory redaction
  preview. That ordering is correct and sufficient for a *process* crash, where
  the page cache survives. It is not sufficient for power loss or a kernel
  panic: with no fsync barrier, the relative durability of the state commit and
  the manifest commit is a filesystem- and mount-option-dependent accident the
  code never asserted. `AtomicWrite` supplies the barrier (fsync file, then
  parent directory). The bundle commit sequence (tgz, redaction report, preview,
  manifest) moves with it, since those are the artifacts the manifest commits.
  `cdr_health.go` is deliberately unchanged: it documents why it needs a
  predictable `.tmp` rendezvous and already fsyncs via
  `fileutil.WriteFileExclusive`. Gates: a table-driven chokepoint test over all
  six entry points (red before the change at 6/6) plus fault injection on the
  approval-gate path asserting degradation, exactly one alert, and the inherited
  base-name path-redaction contract (red before at 0 alerts).

- A support durable write that LANDED was reported as a failure, so the HTTP
  response and the audit trail could contradict the state on disk.
  `fileutil.AtomicWrite` returns `ErrReplacedNotSynced` only *after* its rename
  has succeeded — the target already carries the new bytes and every reader sees
  them; what is unproven is narrower, the rename's durability across an
  immediate crash. `apiSupportBundleApprove` returns 500 and returns *before*
  its `auditEvent`, so a bundle could be READY and downloadable (the
  mandatory-preview download gate reads exactly that landed file) while the
  admin was told the approval failed and nothing recorded who authorized
  exporting its INTERNAL sections. The same audit-after-save shape covers the
  `support.upload.config` egress posture flip and the debug-level elevation, so
  the fix sits at the writer: `durableSupportWrite` treats the sentinel as
  committed for every support writer. The storage-health plane keeps the signal
  — `AtomicWrite` notifies the write-failure observer on that branch before
  returning, so the failure is still counted, logged, alerted as
  `storage_write_failed` and reflected in `storageDegraded()`. This divergence
  arrived with the chokepoint conversion above: the previous `os.WriteFile` +
  `os.Rename` pair returned nil whenever the rename succeeded and so had no
  error-after-landing case at all. Found by Codex review on PR #1658. Gates: the
  unit contract with a negative control that a pre-rename ENOSPC is still an
  error, plus the handler contract that a landed approval returns 204 and leaves
  a `support.bundle.approve` entry; both verified failing against the unfixed
  shape.

- Every Data-Plane → Control-Plane poll failure was charged **twice**
  (CHAOS-86): `backoff()` incremented `failCount` that `pollConfig`'s error path
  had already incremented. Both of the function's documented contracts were
  violated. The delay schedule, promised as "2s, 4s, 8s, … capped at 60s",
  actually ran 4s, 16s, 60s — reaching the ceiling on the 3rd consecutive
  failure instead of the 6th, so policy and blocklist convergence lagged by up
  to 60s after a blip that had already cleared. And the failover guard
  `if c.failCount < 3`, written under the comment "Only attempt failover after 3
  consecutive failures", was already false on the **second** failure, so a ~10s
  network blip or a rolling CP upgrade moved an entire data-plane fleet off a
  healthy leader. `failCount` is owned by the caller and `backoff()` now only
  reads it, which corrects the schedule and the threshold together and makes the
  `backing off … (failure #N)` log line report the real streak rather than twice
  it. A `max(failCount, 1)` clamp keeps the documented 2s floor on the one path
  that reaches `backoff()` with a cleared streak — `failover()` zeroes it on
  success and its immediate retry can then fail. Gates: the single-count
  invariant, a success-resets control, the threshold (asserted on `activeIdx`,
  since a successful failover resets the streak), and the floor; nothing
  previously pinned either the schedule or the threshold.
- The parent-proxy circuit breaker and six operator signals stopped expiring
  when the wall clock stepped **backwards** (CHAOS-84). Go's monotonic reading
  protects an interval only while it stays inside a `time.Time`;
  `time.Unix(0, n)` and `time.UnixMilli(n)` rebuild one without it, so every
  interval measured from a stamp held as a bare `int64` is a wall-clock
  interval. An NTP correction after a wrong RTC, a resumed hypervisor snapshot
  or an operator fixing the date made those intervals negative, so each
  `elapsed >= limit` test stayed false until the clock caught up. Nothing
  errored, nothing was counted, nothing was logged.

  The parent-proxy breaker (`internal/upstream`) is the sharpest: it stayed
  open, and since the pool falls back to **direct egress** when no parent is
  eligible, one parent blip plus a clock correction left the appliance
  egressing around the parent-proxy chain long after the parents recovered. It
  now re-anchors its trip instant (published on `/api/diagnostics`, so it keeps
  its wall-clock basis) and serves one fresh window measured from the step,
  rather than probing at once at parents that may still be down. Five evidence
  and log gates read a future stamp as "already logged" and suppressed their
  notice for the whole step: the crash-evidence throttle (a backward step made
  `recordCrash` return before writing the stack-bearing log and audit entry for
  every subsequent same-component crash), the scanner and YARA degraded-log
  gates, the Sluice call-error line, the fail-closed file-profile block warning
  and the OCSP responder-cap notice. They now decide on the MAGNITUDE of the
  interval rather than its sign, so a rollback costs at most one suppressed line
  and a caller that loses a gate's compare-and-swap is not mistaken for a clock
  step. The tunnel idle reaper, the DP readiness grace and the roster-durability
  gates have the same defect and are fixed by CHAOS-83 (monotonic stamps); the
  CDR breaker was already monotonic on main. No configuration, metric, alert or
  persisted format changes, and behaviour with a sane clock is unchanged. See
  `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-10-17.md`.
- **A shrinking Control Plane address list crashed the Data Plane, and a
  de-listed but still-responsive CP kept serving it (CHAOS-91).** `activeIdx` is
  an index *into* `c.addrs` naming the address the live connection holds, and
  `updateDPAddresses` replaced that slice without re-resolving it.
  `reconnectActive` indexes it directly and its `len == 0` guard does not cover
  an index past a *non-empty* slice, so a shrinking list panicked with
  `index out of range [1] with length 1` — and `reconnectActive` is the
  certificate-renewal redial, which runs unattended on a healthy node. An HA
  promotion's one-element list (the CHAOS-71 address-republish rider already on
  main) is exactly that shrink. Fixed by re-resolving the active entry by
  **address** rather than clamping the index, and by redialling when the active
  address is no longer listed: `call` uses `c.conn`, so a de-listed CP that
  still answered would otherwise keep serving this node indefinitely. (The
  promotion deadlock and address republish this round also found were ported to
  main as CHAOS-71 riders, #1556.)

- **The Data Plane's backoff against its Control Plane was defeated three ways
  (CHAOS-89).** Measured, not inferred:

  The consecutive-failure streak was incremented twice per failed poll — once
  by `pollConfig`, once again inside `backoff` — so the ladder documented as
  `2s, 4s, 8s, …, 60s` was really **`4s, 16s, 60s`**: the ceiling on the third
  failed poll instead of the sixth, and the documented "3 consecutive failures"
  failover gate tripping on the **second**. The log line was wrong in the same
  way, reporting "backing off 4s (failure #2)" for a node's *first* failed
  poll, so an operator could not reconstruct the real cadence from it.
  `backoff` no longer increments; the streak has exactly one writer.

  Worse, `failover()` cleared the streak on a successful *dial*. A Control
  Plane pair that answered TCP while failing `GetConfig` — overloaded, fenced
  out, or timing out an oversized snapshot — therefore held every Data Plane on
  the ladder's low rungs **indefinitely**: the streak never passed the failover
  threshold, so no delay ever grew beyond the 30s poll ticker and the ladder
  never engaged at all. `pollLoop` is ticker-driven and `backoff` sleeps inside
  a tick, so the effect was not a faster poll rate — it was a Control Plane that
  was already failing being polled at the full 30s cadence by every node
  forever, with a fresh gRPC connection every other poll. Connectivity is not evidence that a Control
  Plane is serving config; only a successful poll is. The failover gate is now
  re-crossed every `dpFailoverAfterFailures` rather than tested once, so a
  sustained outage still probes each configured address periodically without
  redialling on every poll.

  Neither the ladder nor any of the five Control-Plane-facing tickers was
  jittered or phase-offset, so a fleet whose Control Plane went away — one
  shared event — retried in lockstep and reconnected in a single instant. The
  ladder is now jittered per attempt (±10%, matching `internal/feedsched`), and
  a one-time per-loop phase offset, bounded by both the loop's own interval and
  5s, staggers all five tickers. The cold-start poll is deliberately **not**
  staggered: a node with no last-known-good snapshot enforces nothing until it
  lands, so delaying it to smooth a one-time boot burst would trade a security
  property for load. This closes the registered WK-13/HA-11 herd rows for the
  cluster plane; they remain open for `internal/blocklistfeed` and
  `internal/otlp`.

- **An unbounded per-peer-IP map on the Control Plane (CHAOS-90).**
  `unenrolledConfigPull.attempts`, which throttles pre-enrollment config pulls,
  prunes a peer's timestamps only on that same peer's *next* pull, so an
  address that pulled once and never returned left a permanent entry — one
  request per source address was enough to grow it for the process lifetime, on
  a port reachable by any routable peer. The structurally identical
  `enrollRateLimit` has had a periodic sweep for exactly this, wired into the
  shared security-limiter janitor, and its own comment names the hazard; the
  fix had never been carried across. It is now, alongside its sibling. The
  throttle's *decision* is unchanged — a sweep reclaims aged-out state and does
  not re-admit an exhausted peer.

  Round report, risk matrix and the backlog it opened are in
  `roadmap/CHAOS-REVIEW-2026-10-13.md`.

### Changed

- A panic in either of the release-dispatch plane's detached worker goroutines
  no longer takes the appliance down, and no longer reports an upgrade that
  never started as a success (CHAOS-75). `POST /api/releases/dispatch` and
  `.../dispatch/resume` hand the upgrade to a goroutine that outlives its
  request — correctly, since the 202 ships before the watch finishes — and
  neither goroutine had a panic tap, so a fault anywhere under
  `DispatchService` killed the proxy data plane, the admin plane and `/healthz`
  together from one authenticated admin POST.

  Containment alone would have made it worse, which is the part that shaped the
  fix. The worker's only `defer` was `close(done)`, and a defer fires *during*
  unwinding — before the outcome assignment lands — so a panicking worker woke
  the parked handler on a zero report/error pair and `respondPreApply` fell
  through to its `default` arm: **`200 {"status":"ok"}`** for an upgrade that
  never started. That false success shipped in 6 of 30 runs against the
  pre-fix tree before the process died; with the panic merely contained it
  shipped in 10 of 10, because the process now survives to deliver it.

  Both workers now run under `runGuarded` (the existing background-worker
  primitive, so the panic lands on `culvert_crash_records_total{component}`
  under the new `release_dispatch` / `release_resume` labels, plus a
  `system`-actor `panic_recovered` audit entry), and the panic is converted
  into an explicit outcome rather than a silent one: **HTTP 500
  `{"status":"internal_error"}`** when no op had started, or a
  `FAILED_NEEDS_ATTN` status record over the live `op_id` — telling the
  operator to *resume*, not re-dispatch — when the agent had already accepted
  the apply. A no-outcome pair is now rejected ahead of `respondPreApply`'s
  switch independently of that, so a future detached writer cannot reproduce
  the 200. No route, request body, or successful-response shape changes.

  Left open with the reasoning recorded in
  `roadmap/CHAOS-ENGINEERING-REVIEW.md` §43: `DispatchResumeContext` is
  documented as a persistable restart-recovery record but lives only in an
  in-memory map, so a restart mid-upgrade still loses the `op_id` and recovery
  degrades to hand-assembling a `resume_context` from the audit trail.

- `GET /api/diagnostics` now carries a `saas_feed` row when the signed SaaS feed
  is stale, failing to refresh, waiting for authority, or critical. Previously
  that state was visible only on `/ready` and the Signed SaaS Feed tab, so the
  one-page health report read as an all-clear. It also reports an enabled feed
  that has never activated while every refresh fails. The row names the source
  actually serving and keys its remedy on the failure class. Additive and
  report-only; no row is emitted when the feed is healthy, disabled or serving
  the embedded baseline without failures.
- The pinned Go compiler moves from 1.26.8 to **1.26.9** (`go.mod` `toolchain`
  line and the digest-pinned `golang:1.26.9-alpine` builder images, index
  `sha256:cdfd4fe2…`, verified against Docker Hub), and `golang.org/x/net`
  from v0.59.0 to v0.60.0. Both are the fixes govulncheck named for twelve
  standard-library advisories (`html/template`, among others, fixed in
  1.26.9) and GO-2026-6617 (an HTTP/2 HPACK encoder race reachable from the
  inspected-HTTP/2 tunnel and the control-plane gRPC server); the Fast gate's
  `govulncheck` job was red on every code-classified PR until both moved.
  The candidate-promotion test fixtures now read the compiler from `go.mod`
  instead of repeating the literal. The frontend lockfile takes the semver-
  compatible `npm audit fix` for four dev-tree advisories
  (`http-cache-semantics`, `ip-address`, `postcss-selector-parser`,
  `source-map-js`); the committed `frontend/dist` is byte-identical.
- The Fast gate's agent-guidance checker (`docs/agent-context/check.py`) now
  runs as the `docs-guidance` job on every pull request that touches a
  guidance path, and root `CLAUDE.md` eagerly imports
  `docs/agent-context/conventions.md`. The golangci-lint analysis budget is
  10 minutes (it exceeded 5 with 0 issues on a cold runner).
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
  nothing wrong" and "never consulted" were the same reading. Culvert now
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

- Session-cookie verification no longer builds HMAC state per request. The
  signed cookie is the FIRST credential arm `resolveRequestAuth` tries, so
  `session.Decode` runs on the proxy authentication hot path and not just the
  admin UI — every authenticated proxied request verified one MAC. Building the
  state, not hashing the ~250-byte payload, dominated that step:
  `crypto/hmac.New` costs five allocations (the HMAC struct, the ipad and opad
  blocks, an inner and an outer `sha256.Digest`), and the old form paid them per
  request plus a payload copy for `Write`, a digest for `Sum(nil)`, two for
  `EncodeToString`, and two more for the `[]byte` conversions `hmac.Equal`
  needed — nine allocations in `mac` alone, each with a named owner under
  `-memprofilerate=1`.

  HMAC state is explicitly reusable (`Reset` re-primes the inner hash with
  ipad), so it is now built ONCE per signing key and recycled through a pool
  published atomically beside the key, and the digest is summed and
  base64url-encoded through inline buffers so the verify path compares bytes
  without ever materialising the expected signature as a string. The hashing is
  untouched — same key, same two block compressions, same alphabet,
  byte-identical output — and `SetSigningKey` remains the single install
  funnel, now rebinding the engine only when the key actually CHANGED, because
  `applySnapshotSessionSecret` reinstalls the CP-synced secret on every
  snapshot apply whether or not it moved and an unconditional rebind would
  discard the warm pool on each of those no-ops. Because the engine now caches
  the key instead of re-reading it per MAC, `SetSigningKey` also stores a COPY:
  holding the caller's slice would let a caller that mutated the slice it had
  installed and then reinstalled it hand that comparison the same bytes on both
  sides, skipping the rebind — after which cookies from before the rotation
  would keep verifying and `SigningKey`, which feeds the Control Plane snapshot
  export, would report a key local verification no longer used. The copy sits on
  the rebind path, so the no-op reinstall stays allocation-free.

  Measured on the development box (linux/amd64, 4-core Xeon @ 2.80GHz, medians
  of 3 runs, each pair timed in the SAME run against a verbatim copy of the
  replaced form) under the toolchain this branch now pins, go1.27.3: the verify
  step 2 521 → 1 454 ns and 9 allocations / 896 B → ZERO; four-way parallel
  1 061 → 367 ns; a whole `Decode` 6 563 → 3 879 ns, 15 → 6 allocations,
  1 304 → 408 B; four-way parallel 2 565 → 1 290 ns.

  The same measurement under go1.26.9, the pin when this work began, read
  `Decode` 6 134 → 4 903 ns, 26 → 17 allocations, 1 648 → 752 B. Go 1.27 made
  the `encoding/json` half of `Decode` dramatically cheaper on its own — 17
  allocations to 6, none of it this change — while this change's own
  contribution is IDENTICAL on both pins: nine allocations and 896 bytes of
  HMAC construction. The relative timing win on `Decode` therefore GREW, from
  −20% to −41%, because a fixed cost removed from a smaller total is a larger
  share of it. The allocation gate's absolute bound was retightened 20 → 10
  with that remeasurement, since a bound set against 17 would have let a
  threefold regression pass once the measured value fell to 6.

  What remains in `Decode` is the base64 payload decode and `encoding/json`'s
  unmarshal into `Session`, deliberately left alone. The size of the timing win
  depends on how expensive the runner's
  allocator is relative to SHA-256, so the gate asserts the structural
  property instead — the verify step builds no HMAC state, no digest and no
  expected-signature string — and extends the zero bound to the reject path,
  so an unauthenticated client cannot drive allocation by replaying garbage
  cookies. Equivalence is pinned by a differential test (five key shapes x ten
  payload shapes x ten signature shapes, plus an end-to-end `Decode` oracle)
  and a fuzz target; the pooling-specific hazards — key rotation under
  concurrent verification, no-op reinstall keeping the pool, a real rotation
  swapping it, the engine owning its key copy — have their own tests.

- The per-IP connection limiter now does its whole job in ONE critical section
  per call, and stores the counter by value. `Acquire` + a deferred `Release`
  run on every proxied request (`handleRequest`, `socks5.go`), not once per TCP
  connection. Sharding the limiter reduced contention between distinct clients
  and left the per-request lock COUNT at three, because `Release` took the shard
  lock twice: once to look the counter up and again to delete the entry after an
  unlocked decrement returned zero. On a keep-alive connection with no second
  request in flight — the ordinary shape — the count returns to zero on every
  request, so every request paid an 8-byte allocation, a map insert, a map
  delete, three lock acquisitions and two atomic read-modify-writes.

  The profile named it. On the distinct-IP parallel benchmark at GOMAXPROCS=1,
  mutex `Lock`+`Unlock` was 34% of all samples and `mapdelete_faststr` 28%, with
  `Release` at 62% of cumulative time against `Acquire`'s 34% — the cheaper half
  of the pair costing nearly twice as much, structurally. In the single-NAT-
  egress case at four cores, mutex machinery was 64% of all samples, with
  `procyieldAsm` and `futex` showing real parking. That case is an ordinary
  enterprise deployment and the package header had recorded it, together with
  the three lock acquisitions, as deliberately unfixed.

  Storing the count as `map[string]int64` and collapsing both halves removes the
  allocation, the pointer chase, the GC write barriers, the per-counter atomics,
  one of `Release`'s two lock acquisitions, and `Acquire`'s increment-then-undo
  dance on the reject path (it simply never commits the count — the same net
  accounting with no window to guard). Measured with the pre-change shape frozen
  in-tree as the `_Legacy` benchmark arms so both are timed in one run (4-core
  Xeon @2.10GHz, Go 1.26.8, medians of n=6, ns/op per `Acquire`+`Release` pair):
  single NAT egress **103.2 → 66.3 (−35.8%)** at one core and **267.6 → 199.6
  (−25.4%)** at four; distinct IPs **105.7 → 70.0 (−33.8%)** and **108.3 → 85.6
  (−21.0%)**; entry churn **99.8 → 67.4 (−32.5%)** and **105.9 → 68.0
  (−35.8%)**; the reject path **62.6 → 29.6 (−52.7%)** and **245.1 → 101.3
  (−58.7%)** — with **1 → 0 allocs/op** on the shapes that create an entry per
  operation (distinct IPs and entry churn at both core counts, single NAT
  egress at one core). The reject and retained-entry arms, and single NAT
  egress at four cores, already report **0 allocs/op in both forms**: the entry
  exists before the timed operation, so neither form allocates a counter for
  it. End to end,
  `BenchmarkPerfQual_ProxyHTTPForward` goes 177 → 176 allocs/op and `connlimit`
  leaves the `alloc_objects` profile entirely.

  One of the ten measured shapes regressed and is recorded rather than rounded
  away: the retained-entry case (an IP with a second request already in flight,
  so the count never returns to zero) is 58.3 → 60.7 ns at one core, **+4.2%**
  with overlapping distributions at n=15, and parity at four cores — there the
  old form did a lookup plus an atomic add through the pointer already in hand,
  where this one does a lookup plus a `mapassign` in each half. It is bought
  with the two shapes that dominate a real gateway: entry churn, and the reject
  path an attacker drives, where a flood used to cost the limiter more per
  refusal than per admission.

  It is also a **fail-open fix**. `Release`'s second pass re-checked the
  counter's *value* without re-checking its *identity*, while `Acquire`'s reject
  path carried exactly that guard (`cur == ctr`) — the pattern was known and
  applied in one of the two places that needed it. Release A reads the counter,
  unlocks, decrements 1 → 0 and is descheduled; B acquires and releases,
  deleting the entry; C then misses, allocates a fresh counter and takes it to 1
  (a live, admitted connection); A re-locks, loads its stale pointer, sees 0,
  and deletes C's entry. C's accounting is destroyed and the IP goes on to hold
  `limit+1` concurrent connections — past a configured per-IP cap, the same
  direction as the #503 bug the unconditional-accounting contract exists to
  close (measured: 3 admitted against a cap of 2). Reproduced deterministically
  by `TestRelease_LegacyTwoPhaseLosesALiveSlot`, which owns a verbatim legacy
  copy with one injected pause point rather than racing for the interleaving.
  Every behavioural test in the package keeps passing against the two-phase
  shape, so the regression instruments are deliberately structural: an AST wall
  requiring exactly one `sh.mu.Lock()` and zero per-counter atomics in each half
  (with a not-vacuous control that rejects a verbatim pre-fix copy), and a
  `testing.AllocsPerRun` gate across the churning, steady-state and reject
  postures — the churn posture is load-bearing, since a gate measuring only the
  retained entry reads zero against the defect too. Both were verified failing
  against the reverted implementation. The admit/reject boundary, the
  unconditional-accounting contract and the delete-when-last behaviour are
  unchanged.

- The request log's JSONL persistence gate no longer takes a process-wide
  mutex on every logged request. `reqlog.Add` runs once per logged request on
  the proxy request goroutine, and the `enqueue` it calls opened with an
  unconditional `persistMu.Lock()` purely to read two pointers that are `nil`
  for the whole life of the process in the **default** configuration — no
  request-log file is configured, so no drain goroutine is ever started. A
  `sync.Mutex` Lock/Unlock pair is two atomic read-modify-writes on one shared
  word, so every request in the process was writing the same cache line to
  discover that persistence is switched off: a throughput ceiling rather than a
  constant cost, the same shape already removed from `internal/threatfeed`,
  `internal/connlimit` and the top-hosts counter. A lock-free `atomic.Bool`
  gate now short-circuits the disabled path. Measured on a 4-core Xeon @
  2.80 GHz, both arms in one run, medians of `-count=5`: in `RunParallel` arms
  (where ns/op is wall time per op across all workers, so a genuinely parallel
  cost *falls* as cores are added) the gate goes from **15.5 / 28.6 / 74.4 ns**
  at GOMAXPROCS 1/2/4 — rising 4.8×, because it serialises — to **1.72 / 0.86 /
  0.43 ns**, halving as the cores double. That is the sharper statement of the
  defect: the mutex converted a read every core could do at once into a word
  every core had to take turns owning. One whole logged request goes from
  **52.2 / 104.1 / 185.5 ns** to **49.0 / 96.1 / 157.4 ns** — ~6% serially,
  ~15% at four cores, zero allocations either way. No entry, field or byte on
  any sink changes, and the enabled path is untouched: the shutdown-sweep
  invariant (every sender registered in the same critical section that
  published the channel) still holds, because the gate can only short-circuit
  ahead of that section. `Add` remains flat in core count; the ceiling left is
  the ring's own lock, which guards real shared state and is recorded on
  `BenchmarkAddParallel` rather than changed.

- Destination-host IDNA normalization is memoized, so an internationalized
  destination no longer re-runs `idna.ToASCII` once per engine on every request.
  `hostutil.NormalizeHostStrict` already had an already-canonical fast path
  covering pure-ASCII, ACE-free hosts at zero allocations, but everything else
  fell through to `idna.ToASCII` — and the same destination is normalized ~10x
  per proxied request by engines that each correctly canonicalize their own
  input (the strict dispatch gate, SOCKS5, `PolicyStore.Evaluate`, auth policy,
  category resolution, the blocklist, the threat feed, the SSL-bypass matcher,
  autoexclude, urlcat, traffic redaction). That fan-out is deliberate and
  correct, so the cost was ten conversions of one string per request: measured
  **6.90 µs and 70 allocations** for a single request to an A-label host,
  against **0.70 µs and 0 allocations** for the ASCII equivalent — an ~11x
  asymmetry on a path every request walks.

  This is not an exotic shape. Browsers put the A-label in the `Host` header
  and the CONNECT authority, so `xn--bcher-kva.example.com` is what a request
  to `bücher.example.com` actually carries; the seven-allocation row is the
  live cost of every request to an internationalized domain, not a Unicode
  edge case. It is also client-selectable at no cost to the sender.

  The slow path now answers a repeat from a fixed-capacity table: **0.55 µs and
  0 allocations** warm (−92% CPU, and the 70 allocations become none), and
  **1.82 µs / 6 allocations** (−73% / −88%) for a destination never seen
  before — the per-request fan-out supplies the reuse by itself, because one
  engine misses and the other nine hit. Verdicts cannot change: IDNA
  normalization is a pure function of its input, with no clock, configuration
  or I/O, so there is no staleness to invalidate and a hit is indistinguishable
  from recomputing. The existing `FuzzNormalizeHostStrict` differential against
  the pre-optimization reference ran 598k executions with no divergence.

  The key is a client-chosen authority, so the table is direct-mapped with
  fixed slots and a per-process random slot seed, and no entry retains a
  canonical value longer than the 253-byte DNS name maximum. That value bound
  is load-bearing rather than decorative: `handleRequest`'s raw pre-cap admits
  a 1 KiB authority and the 253-byte canonical refusal runs *after*
  `canonicalDestHost` has normalized it, while the zero-option `idna.ToASCII`
  profile enforces no length limit of its own, so an oversize A-label host
  would otherwise be retained whole (~2.1 MB across a full table). The table
  therefore cannot grow — 103 KiB retained after 65 536 distinct IDN hosts,
  against a 720 KiB absolute ceiling across both tiers — a collision costs a
  recomputation rather than a wrong answer, because every hit re-verifies the
  full key, and an adversary who could force collisions would obtain the
  pre-memo behaviour. Ordinary ASCII traffic is untouched: it returns from the
  fast path above the memo and never reads or writes the table, pinned by
  `TestIDNMemo_FastPathNeverTouchesMemo`.

  **Retention is bounded on two tiers, because one bound could not do both
  jobs.** The first version measured the 253-byte bound on the KEY as the
  client spelled it, on the stated reasoning that refusing such a host "costs
  nothing" because "no DNS server can resolve a longer name, and both dispatch
  gates refuse it immediately". Both halves were wrong, and the mistake was
  reading a bound on the raw spelling as a bound on the name. IDNA *shrinks* a
  U-label authority: `proxy_host_bounds.go`'s own derivation records the worst
  legitimate case as **883 raw bytes collapsing to a 251-byte A-label**, which
  is precisely why the raw pre-cap is 1 KiB and not 253. So a host whose raw
  spelling exceeded the bound could canonicalize comfortably inside the DNS
  limit, with every label inside the 63-byte A-label limit too — a resolvable,
  ordinary internationalized destination — and **both dispatch gates accepted
  it**. It was not refused; it walked the full ~10x fan-out with nothing
  memoized, which is the asymmetry the memo exists to close. Measured per
  normalization of one such accepted destination (eight U-labels of 20 CJK code
  points, 499 raw bytes against 227 canonical): `idna.ToASCII` **5.32 µs and 18
  allocations**, i.e. ~53 µs and 180 allocations per request across the
  fan-out, against **71 ns and 0 allocations** for a memo hit. Such a key is
  now retained in a separately bounded long tier — 128 slots, keys to 1024
  bytes, values still to 253 — which adds ~165 KiB to the ceiling and leaves
  the main tier's capacity untouched. The key bound is the request path's raw
  pre-cap itself, not the 883-byte empirical maximum, so "every authority a
  dispatch gate admits is memoizable" holds by construction rather than by a
  measurement; the root gate asserts that relation between the two constants,
  so raising the raw pre-cap fails there instead of re-opening the asymmetry
  for the newly admitted band.
  Per-request fan-out for that destination, both measured through the full
  `NormalizeHostStrict` body: **~85–94 µs and 200 allocations before, ~27–29 µs
  and 0 allocations after**. Verdicts are unchanged in both tiers — a host past *both*
  key bounds is still normalized, just not retained.

  Gates, both verified failing against the pre-fix bound:
  `TestIDNMemo_LongRawULabelHostIsAcceptedAndRetained` (proves the probe host
  is DNS-valid and that both gate predicates admit it *before* asserting it is
  retained, so the test cannot pass by accident) and the root
  `TestHostutilLongRawULabelReachesTheMemo`, which calls the real
  `rawAuthorityOversize` / `canonicalHostOversize` so the two bounds cannot
  drift apart again. Plus `TestIDNMemo_LongTierHitIsAllocationFree`,
  `TestIDNMemo_BeyondLongTierIsNormalizedButNotRetained` (outer boundary,
  including one byte over), `TestIDNMemo_LongTierBoundedFootprint` and
  `TestIDNMemo_LongTierConcurrentStress`;
  `TestIDNMemo_StoredEntriesRespectTheBound` now asserts the invariant over
  every live entry in both tiers against that tier's key bound.

  **What this does not fix, stated plainly.** `strings.ToLower` runs
  `strings.Map(unicode.ToLower, …)` for a non-ASCII input — a per-rune table
  walk over the whole authority — and it sits in `NormalizeHostStrict` *ahead*
  of both the fast path and the memo, so no tier can collapse it. At **2.84 µs
  per call** it is ~28 µs per request across the fan-out, against ~50 ns for an
  ASCII destination, and the client selects it with ~500 header bytes. That
  residual asymmetry is left open deliberately: narrowing or hoisting the
  lowering pass changes what canonicalization does to non-ASCII input, which is
  the IDN-homograph contract `NormalizeHost` exists to enforce (RISK-013), and
  that belongs to the differential fuzz harness and review rather than to a
  performance patch.

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

- The operator contract (`GET /api/diagnostics`, `GET /api/health/explain`)
  now carries an `admin_roster_durability` row (CHAOS-70 evidence): `warn`
  when no `-ui-users-file` is configured, so admin account deletes, role
  changes and password rotations revert on restart; when the configured file
  failed to load at startup or is not a usable regular-file target (a
  read-only check); when no write to the roster file has landed since
  startup (*not verified yet*); and when admin-roster
  changes were refused or login-time roster writes failed since process
  start. Counts, the remedy and the degraded login-write state are shown to
  admins only. Viewers and operators get a fixed message for "not durable" and
  "a change was refused", and the row shows nothing for a degraded write
  (SEC-DIAG-ROSTER-1). `GET /api/auth/users` (admin-only) adds
  `adminRosterPersistFailures` / `adminRosterPersistDegraded`. They feed a new
  Admin Users panel hint and are deliberately absent from `/api/stats`.
- The `admin_roster_durability` row reports persistence only on evidence: a
  roster save that landed in this process. Culvert does not write the roster
  at startup, so after every restart the row reads `warn` with the distinct,
  non-alarming *not verified yet* state ("the next admin account change
  verifies that it persists"; viewers see a fixed message) until the first
  admin account change lands, which turns it `ok`. That `ok` states evidence,
  never capability: "the last admin roster save was written to disk and the
  file is unchanged since" (viewers: "an admin roster file is configured; the
  file on disk is the last one Culvert wrote, unchanged since"). It does not
  claim that the roster "is persisting" or that the next save will be allowed.
  No read-only check can authorise that: an SELinux `add_name`/`remove_name`
  denial, AppArmor, an NFSv4 or server-side ACL, or a quota can refuse it
  while `faccessat` passes. The live checks below are advisory: they report
  what they detect, and passing them is no claim. A refused save is rolled
  back, answers `500` and is counted, and the next read of the row reports it
  in place of `ok`. A stat is not evidence: a
  readable roster on a read-only mount, or one owned by another user in a
  sticky directory, stats like a writable one. Hard problems found by the
  row's one live probe take precedence over *not verified yet*: a configured
  roster file that does not exist yet, a directory that no longer lets
  Culvert create and replace files (`faccessat(W_OK|X_OK, AT_EACCESS)` and
  `statfs`: a `chmod 0555`, a revoked ACL, a read-only remount), a roster no
  save can replace (immutable or append-only, a bind-mounted file, or an
  immutable or append-only directory; Linux, read-only
  `fileutil.ReplacementBlocked`), and storage that does not answer within
  2 s. After a landed save the row also warns when the roster file is
  removed, replaced or edited outside Culvert (each landed save records the
  size and SHA-256 of the bytes written), replaced by an identical copy owned
  by another account where that makes the next save's rename be refused,
  changed or replaced outside Culvert in any other way, or when the save's
  directory could not be synced. A landed save is evidence only for the exact
  file it wrote, unchanged since: on Linux and macOS it also records that
  file's device, inode and `ctime` (fstat of the written file after the
  rename), and any difference — a new inode, or a same-inode `touch`, `chmod`,
  `chown`, ACL, extended attribute or label change — reports the new
  `warn` *the roster file was changed or replaced outside Culvert since its
  last save* (no action needed if intentional; the next admin account change
  re-verifies). Deliberately, a `touch`, a `chmod` or an identical re-copy
  now warns instead of reading `ok`. Changed contents, a refused-rename owner
  change, a missing or immutable file and an unwritable directory take
  precedence. Other Unix systems compare size, SHA-256 and owner; Windows
  compares size and SHA-256 only. The probe runs on its own
  goroutine, holds no roster lock, runs at most once at a time, is reused for
  5 s, and is read once per diagnostics request (the viewer rendering reuses
  it), so a stalled volume costs a request at most one 2 s wait and never
  blocks admin changes or TOTP logins. `fileutil.AtomicWriteInfo` returns
  the landed file's own `FileInfo` and whether its directory was synced;
  `fileutil.AtomicWrite` is unchanged for its callers.
- The `admin_roster_durability` row now picks its state from one ordered list,
  and the admin and viewer renderings both use that list (Codex P2 4326470080).
  Previously each renderer ranked the states in its own order. That let a
  refused first save after a restart hide behind *not verified yet* ("No action
  is needed now"). The order is:
  1. setup incomplete
  2. no roster file
  3. storage not responding
  4. refused saves
  5. failed login-time writes (admin-only)
  6. unusable target
  7. missing target
  8. replaced
  9. owner changed
  10. immutable
  11. directory not writable
  12. changed externally
  13. directory not synced
  14. not verified yet
  15. ok

  The admin remedy for a refusal also names the highest-ranked problem the live
  checks see below it. The row now counts refused and failed writes from the
  last save that landed (from startup before the first one), so a refusal stays
  visible until a later save lands. The since-startup totals are still shown,
  and the counters, metrics and Admin Users panel are unchanged. The identity
  probe reports content, owner and inode changes as independent facts, and the
  list ranks them.
- A failed startup load of `ui_users.json` no longer pins the
  `admin_roster_durability` row (Codex P2 4327431894). Before, the row kept
  reporting "could not be loaded at startup" after a later save landed at the
  same path, and it skipped the live probe. Now a landed save clears the load
  error, under the same lock that records the save. Pointing at another path
  resets it as before. The live probe now runs whether or not the load failed.
- **Deferred:** the boot-time in-place rewrite of `ui_users.json` (which would
  verify persistence at startup instead of at the first admin change) is
  split out of this change into its own follow-up PR.
- `GET /api/policy` now reports `persisted` (whether the access-rule
  rulebase is written to disk vs. in-memory only), and the Access Rules
  panel shows a red banner when it is false. Every rule mutation already
  returned 200 OK regardless of persistence — `PolicyStore.SaveErr()` is a
  no-op when no `-policy`/`policy_file` path is configured, which is also
  `config.example.yaml`'s shipped default — so an admin editing rules
  through the GUI had no way to discover that a restart would silently
  discard the entire rulebase short of it actually happening. Mirrors the
  existing `idpRegistry.Persisted()` warning already shown for identity
  providers. No behavior change: read-only field + banner.
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
- Admin API operations (contract 2.1.0): `GET/PUT /api/traffic/redaction` —
  the canonical name for the traffic-log destination-privacy posture
  (terminology governance T-17); `/api/decryption/redaction` remains a
  fully supported, non-deprecated alias of the same operations.

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

- The per-request policy publication check is O(1) instead of O(rulebase).
  `PolicyStore.Evaluate` runs on every proxied request, and its first act —
  `evaluationSnapshot` — scanned the entire rulebase for a rule with a nil
  counters cell before returning. Production rules always carry one, so the
  scan never short-circuited: it ran to completion on every request to prove a
  negative, under the process-wide policy read lock. On a 4-core box the
  snapshot measured 15.4 ns at 10 rules, 51.3 ns at 100, 524 ns at 1 000 and
  29 761 ns at 10 000 — superlinear, because the scan is a pointer chase that
  leaves cache as the rulebase grows. Because it ran *before* evaluation it
  taxed even requests the engine decides in O(1): a request matching the
  highest-priority rule cost 465 ns at 10 rules and 30 900 ns at 10 000, so at
  10 000 rules roughly 98% of `Evaluate` was the pre-scan and 2% was the
  policy decision. The question the scan was really asking — "has this slice
  been published?" — is a property of the slice, so it is now answered once
  per publication instead of once per request: the snapshot is flat at ~13 ns
  from 10 to 10 000 rules (2 294x at 10 000) and the O(1)-match request is
  flat at ~390-460 ns (81x at 10 000), with zero allocations throughout.
  Verdicts are unchanged — pinned by a differential against a verbatim frozen
  copy of the pre-change body over 400 randomized mutation sequences, by
  per-mutator immediate-visibility tests, and by a race-detector reader/mutator
  run; the memo fails safe by construction (any write to the rulebase installs
  a different slice, so a stale memo costs one scan, never a wrong verdict).
  Operators with large rulebases see the largest gain; nothing about policy
  semantics, ordering or default-deny changes.

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

- Three decisions measured elapsed time on the **wall clock** and stopped firing
  across a backwards clock step — an NTP correction of a drifted clock, a VM
  suspend/resume, a container host's clock change, `hwclock` at boot. All three
  stamped with `time.Now().UnixNano()` and read back with
  `time.Since(time.Unix(0, stamp))`; `UnixNano()` discards the monotonic reading
  and `time.Unix(0, n)` reconstructs a value that has none, so Go subtracts two
  wall-clock values. A step backwards leaves the stamp in the *future* and the
  elapsed duration goes **negative**, which satisfies neither `>= deadline` nor
  `>= grace`, so each decision was suspended for however far the step went.

  The **tunnel idle reaper** (1h window) stopped reaping, and the tunnels it
  then held were precisely the idle, possibly half-open ones it exists to
  collect — peer still ACKs, never sends, never FINs — at two sockets, two
  goroutines and two pooled relay buffers each, on the CONNECT-bypass and
  SOCKS5 paths alike. Under many simultaneous connections or long-lived tunnels
  that is file-descriptor and memory exhaustion on the data plane; a step
  *forwards* is the mirror image and tears down every long-lived tunnel at once.
  The **data-plane readiness grace** (5min) stopped closing, so `/ready` kept
  reporting `cp_poll: ok` while the control plane was genuinely unreachable and
  the node's policy went stale. The default verdict is report-only on that row,
  so there the loss is the signal itself; on a strict probe (`/ready?strict=1`),
  which does gate on the row, the suppressed `fail` also kept the node's verdict
  `ready` and so held it in the load-balancer rotation. And both **roster durability-degraded log gates** latched
  suppressed (a negative age is always under the interval), silencing the only
  operator-visible signal that admin roster writes are not surviving a restart
  while the suppressed counter climbed where nobody reads it.

  Sorting the affected and unaffected sites by how they *store* the stamp makes
  the cause exact: every site that was wrong holds it in an `atomic.Int64`,
  which cannot hold a `time.Time` and so forces the `UnixNano()` conversion that
  drops the monotonic reading. `atomic.Int64` remains the right choice at all of
  them — a lock-free stamp shared between two relay goroutines, or read on a
  probe path — so the fix is one shared primitive (`monoNanos`/`monoSince`) that
  makes that representation safe by construction rather than four local patches.
  The HA self-fence deadline was already correct and explicitly so, because it
  keeps a `time.Time` field, which retains its monotonic reading for free.

  Deliberately *not* implemented as `internal/admission`'s negative-age guard:
  there a bad stamp must fail toward the local decision, but here "expired"
  tears a tunnel down or flips a readiness row to fail, so "negative means expired"
  would reap live tunnels and flap every node's probe on any backwards step,
  including the sub-second NTP corrections that are routine. A negative control
  pins that choice. Absolute-time decisions are untouched: session and IdP token
  expiry, certificate validity and log-timestamp rendering are civil instants
  and stay on the wall clock. Gates: 9, four verified failing against the
  pre-fix tree, including an AST guard over all 385 package-main sources that
  bans the `time.Unix(0, nanos)` elapsed idiom while leaving the legitimate
  `time.Unix(seconds, 0)` absolute uses alone. `internal/ocsp` has the same
  defect in a log gate, recorded as register row CA-21 rather than widening this
  change into another package. Review:
  `roadmap/CHAOS-ENGINEERING-REVIEW.md` §47 (CHAOS-83).

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
