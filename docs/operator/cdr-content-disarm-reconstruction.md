# CDR (Content Disarm & Reconstruction) via Sluice

CDR is an optional inspection stage that strips active content (macros,
embedded OLE objects, PDF JavaScript, and similar) from files downloaded
through SSL-inspected HTTPS traffic, by streaming the file body to an
external engine called **Sluice** over mutually-authenticated gRPC. It is
disabled by default and is a Zero-Trust-scoped policy stage, not a
replacement for the ClamAV/YARA scanner. This guide covers architecture,
enrollment, certificate lifecycle, policy configuration, and the security
model. For day-to-day troubleshooting of a stuck or unhealthy pool, see
[Operations §6](../OPERATIONS.md#6-cdr-sluice-recovery) — this guide does
not repeat that material.

## Known limitations (read before enabling in production)

These were confirmed against the current implementation and are not yet
fixed; they materially affect how safely CDR can be relied on today.

- **CDR alone does not trigger body buffering.** The proxy only buffers a
  response body for inspection when the remote scan service, DPI (on text
  content), or the local ClamAV/YARA body scanner is enabled
  (`bodyNeedsBuffering`, `security_scan.go:249-263`) — CDR's own enabled
  state is not part of that decision. Enabling CDR with every other
  scanner disabled results in `scanInspectBody` returning before CDR is
  ever reached (`proxy_tunnel.go:1280-1284`), so **no file is inspected or
  sanitized at all**, silently. Enable at least one of the other body
  scanners alongside CDR.
- **Only the scan-window prefix is sanitized, not the whole file.** The
  proxy buffers at most `maxScanBufferBytes()` bytes (driven by DPI/ClamAV's
  own configured limits, not a CDR-specific one) and passes only that
  prefix to CDR; the untouched remainder is appended and forwarded as-is
  after CDR returns (`proxy_tunnel.go:1294-1330`, `1369-1378`). For a file
  larger than that window, only the leading prefix is scanned/sanitized —
  the tail reaches the client exactly as the origin sent it. The same
  buffering also means a file larger than `cdrMaxFileSize` (50 MiB) does
  not reliably trip that check via this path, since CDR only ever sees a
  prefix capped by the (typically smaller) scan window.
- **An unreachable/empty pool fails open regardless of `fail_mode`.** When
  no pool member is selectable — the pool is empty, or every circuit
  breaker is open — `runCDRStage` returns the original file untouched and
  unblocked without consulting `fail_mode` at all
  (`cdr_proxy.go:391-395`, `cdrstore.go:485-496`). A deployment configured
  as fail-closed is **not** protected against this specific case: `fail_mode`
  is only consulted once a live client attempts (and fails) a call, not
  when there is no client to try. See
  [Fail-open vs fail-closed behavior](#fail-open-vs-fail-closed-behavior)
  below.
- **Runtime enablement does not start the health/renewal poller.** The
  poller that drives client-certificate auto-renewal and Sluice
  server-cert rotation handling is started from exactly one place —
  process startup with CDR already enabled (`cdr_startup.go:47-70`).
  Enabling CDR at runtime (first enrollment, or `PUT /api/cdr/config`)
  initializes the client pool but does **not** start the poller, so none
  of the [certificate rotation](#certificate-rotation) behavior described
  below runs until the process is restarted with CDR enabled.
- **A sanitized response whose size changed can be delivered broken.**
  When CDR strips content in `ENFORCE` mode, `runCDRStage` swaps in the
  sanitized bytes as the new `resp.Body`, but neither it nor
  `scanInspectBody` updates `resp.ContentLength` or the response's
  `Content-Length` header to match the new size (no assignment to either
  exists in `proxy_tunnel.go`). If sanitization changed the byte count,
  the client is served against the *original* length: on HTTP/1.1 this
  can truncate the body or surface a length-mismatch error, and on
  inspected HTTP/2 the stale header is forwarded as-is. This is
  independent of the scan-window-prefix limitation above — it can happen
  even when the whole file fit inside the scan window.
- **Deleting one instance can take the whole pool offline.** In a
  multi-instance deployment, `DELETE /api/cdr/instances?name=` shuts down
  the *entire* client pool — not just the named instance — whenever any
  instance was still selectable at the time of the call
  (`cdr_ui.go:302-309` calling `shutdownCDRClient()`, which clears the
  effective config and empties the whole pool: `cdrstore.go:551-556`).
  The remaining, still-enrolled instances stop serving until an operator
  re-enrolls one of them or restarts the process.

## Architecture

Culvert is the gRPC client; Sluice is a separate service (typically a
Docker sidecar) that never needs to be trusted with Culvert's own TLS
material. The two communicate over a bidirectional-streaming `Sanitize`
RPC plus unary `Health`, `Enroll`, `EnrollStatus`, `RenewCert`, and
`RevokeClient` calls (`cdr.go`). Every call is per-file: the header frame
(filename, content-type, profile, mode) goes first, then the body in
64 KiB chunks by default (`cdrChunkSize`, `cdr.go:47-62`, `376-459`) —
overridable via `cdr.chunk_size_kb` in `config.yaml` (16–3072, YAML-only,
no CLI flag; `config.go:382-384`, `620-622`) — then Sluice streams back
the sanitized bytes plus a threat report. A single Sanitize call is
bounded by a 35-second client-side deadline by default
(`cdrDefaultTimeout`, `cdr.go:53`), overridable via `cdr.timeout_sec` in
`config.yaml` or `-cdr-timeout-sec` on the CLI (must be `>= 30`, Sluice's
own cap; `config.go:373-376`, `614-615`; `main.go:351`). Files above
50 MiB (or a lower Sluice-advertised per-profile cap) are rejected before
any bytes cross the wire (`cdrMaxFileSize`, `cdr.go:61`;
`cdr_proxy.go:248-265`) — subject to the scan-window-prefix caveat in
[Known limitations](#known-limitations-read-before-enabling-in-production).

Culvert can enroll **multiple** Sluice instances. Each becomes a
`cdrPooledClient` with its own gRPC connection and its own circuit
breaker (closed → open after consecutive failures → half-open probe →
closed; `cdr_breaker.go:1-30`). The proxy path (`cdrPickPooled`) skips
open-breaker instances and round-robins across the rest; if every
instance's breaker is open (or the pool is empty), no client is
selectable and the file is forwarded unsanitized and unblocked —
**`fail_mode` is not consulted in this case** (see
[Known limitations](#known-limitations-read-before-enabling-in-production)).
A background poller (`cdr_health.go`) calls
`Health` on every pool member every 15 seconds, caches the result for
`GET /api/cdr/health`, and drives auto-renewal and server-cert-rotation
handling (below).

## Enrolling a Sluice instance

Enrollment (`POST /api/cdr/instances/enroll`, admin-only) is a one-shot
token exchange: `{name, endpoint, serverFingerprint, token}`
(`cdr_ui.go:369-378`). `name` must match
`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}` (it becomes a directory name on disk);
`endpoint`, `token`, and `serverFingerprint` are all required
(`cdr_ui.go:718-736`).

`serverFingerprint` is the **TOFU (trust-on-first-use) pin**: the
SHA-256 of Sluice's server certificate, obtained out-of-band (Sluice
prints it on first boot) and pasted into the enrollment form. Whenever a
fingerprint is configured, Culvert's TLS layer sets
`InsecureSkipVerify: true` for the Sluice channel and relies *entirely*
on a constant-time comparison of the presented leaf certificate's
SHA-256 against this pin — there is no hostname verification and no
chain verification, even if a CA bundle is also supplied (a supplied CA
bundle is only used as the verification method in the separate, no-pin
fallback mode, which the enrollment flow above does not use)
(`cdr.go:216-307`, `339-371`). This protects against a man-in-the-middle
presenting a different (even validly-signed-by-some-other-CA)
certificate: without the correct pin, the handshake is refused
regardless of what CA issued the presented cert. The pin check also runs
on `VerifyConnection`, not just `VerifyPeerCertificate`, specifically to
close a TLS session-resumption gap that could otherwise skip the check
entirely, and session resumption is disabled for the same reason
(`cdr.go:290-306`).

Enrollment exchanges the token for an mTLS bundle (CA cert, client cert,
client key), verified against the pin before the token is ever
consumed, and persists it to
`<dataDir>/integrations/sluice/<name>/{ca,client}.pem` and `client.key`
(0600) (`cdr_ui.go:380-391`, `625-680`). CDR auto-enables on an
instance's first successful enrollment if it was not already enabled,
and the actual post-enable state (including a failed persist of the
enable sentinel) is reported back in the response rather than assumed
(`cdr_ui.go:493-519`).

Because Sluice consumes the enrollment token in one exchange, a response
lost to a network fault (client saw a timeout; Sluice already issued the
credential) would otherwise leave an untraceable, un-revocable trusted
client credential. Every enrollment therefore carries a client-minted
128-bit `operationId` that Sluice durably binds to the issued fingerprint
before responding, and Culvert persists a **receipt** (operation id,
name, endpoint, pin, actor, lifecycle state — never the token or key
material) *before* dispatching the RPC; if the receipt cannot be
persisted, nothing is sent (`cdr_enroll_receipts.go:1-33`). If enrollment
returns an ambiguous error, `POST /api/cdr/instances/enroll/recover`
performs a fresh authoritative `EnrollStatus` check against Sluice and
classifies the operation as `LANDED_AND_STORED`,
`ISSUED_BUT_NOT_STORED` (with an exact revocation path for the orphaned
credential), `NOT_ISSUED`, or `AMBIGUOUS` (`cdr_enroll_receipts.go:34-42`,
`553-702`). `GET/DELETE /api/cdr/instances/enroll/receipts` lists and
prunes these receipts; an unresolved receipt cannot be deleted
(`cdr_enroll_receipts.go:375-395`).

Deleting an instance (`DELETE /api/cdr/instances?name=…`) removes
Culvert's local registry entry and shreds the local PEM copies — it does
**not** revoke trust on the Sluice side. Sluice keeps trusting every
still-valid certificate generation until it expires or is explicitly
revoked there; the response and audit event report every fingerprint
that remains trusted so the operator knows what still needs revoking
(`cdr_ui.go:238-323`, `267-276`). In a multi-instance deployment this
delete also shuts down the *entire* client pool, not just the named
instance, whenever any instance was still selectable — see
[Known limitations](#known-limitations-read-before-enabling-in-production).

## Certificate rotation

Everything in this section is driven by the background health poller,
which only starts at process startup with CDR already enabled — see
[Known limitations](#known-limitations-read-before-enabling-in-production)
for what that means for an instance enrolled or enabled at runtime.

**Sluice server certificate** (the side Culvert pins by fingerprint):
the health poller reads `HealthResponse.rotated_fingerprint` /
`rotated_fingerprint_until_unix`. While a rotation is signalled, Culvert
dual-pins — it accepts either the original or the new server
fingerprint (`cfg.SecondaryFingerprintHx` / `SecondaryValidUntil`,
`cdr.go:117-124`, `271-280`) — so Sluice can present its new certificate
without an outage. Once the grace window (`RotatedFingerprintUntilUnix`)
passes, Culvert promotes the new fingerprint to the canonical pin,
clears the rotation fields, and reinitializes the pool to drop the old
pin (`cdr_health.go:118-188`).

**Culvert's client certificate** auto-renews: when a pooled instance's
client cert is within `cdrRenewWindow` (30 days) of expiry, the poller
fires a `RenewCert` RPC (single-flighted per instance so a flapping
poller can't double-renew) (`cdr_health.go:190-217`). Sluice issues a new
cert under the same CN without revoking the old one, so an in-flight
renewal never breaks a live stream (`cdr.go:574-589`). The new
credential's fingerprint is recorded durably (as a "staged" generation
in the instance's credential lineage) *before* the new key/cert PEMs are
written, and the PEM swap itself is atomic (tmp file + rename, cert then
key) so a crash mid-swap leaves either the old or the new pair intact,
never a half-written one (`cdr_health.go:219-341`). If a renewal's RPC
outcome is lost (e.g. a network timeout after Sluice already issued),
the next poll cycle resolves it via `EnrollStatus` before attempting any
new renewal, marking an issued-but-never-landed credential as
**orphaned** so it surfaces for revocation rather than silently
disappearing (`cdr_health.go:343-405`).

## Revocation

`POST /api/cdr/instances/revoke` (admin-only) is distinct from deleting
an instance: it actually tells Sluice, via `RevokeClient`, to reject
future RPCs bearing the named credential. Because Sluice refuses
self-revocation, the call must be issued by *another* pooled, healthy
instance (`cdrPickOtherClient`) — a single-instance deployment cannot
revoke that instance's own credential from the API and must use the
Sluice-host CLI instead (`cdr_ui.go:988-996`, `cdr_enroll_receipts.go:
512-527`).

The security-critical property (`cdr.instance.revoke_rpc`) is that a
revocation is only recorded locally, and PEMs only shredded, **after
Sluice proves a durable deny** — an explicit `REVOKED` /
`ALREADY_REVOKED` / `TOMBSTONED` outcome (or, against an older Sluice
that only reports a boolean, `revoked=true`). An "unknown fingerprint"
answer (`revoked=false`, no outcome) proves nothing and is refused, not
treated as "already safely revoked" (`cdr_ui.go:895-931`). Revocation
targets **every still-valid credential generation** in the instance's
lineage, not just the currently-active one, and progress is durable
per-generation so a failure partway through can be retried without
re-revoking what already succeeded (`cdr_ui.go:933-941`, `1038-1057`).
An orphaned credential with no registry entry (see receipts above) can
be revoked directly by fingerprint via the same endpoint
(`{"fingerprint": "sha256:…"}`) (`cdr_ui.go:882-889`, `1084-1124`).

Revocation is deliberately excluded from config-version rollback (see
Security considerations) precisely so that "roll back to version N" can
never silently un-revoke a compromised credential.

## CDR policies

CDR policy rules decide *which* Sluice profile and mode apply to a given
request, mirroring the syntax of ordinary Access Rules
(`CDRPolicyRule`, `cdrpolicy.go:37-65`). A rule can match on:

- **Source**: `sourceIP` (IP/CIDR), `sourceIdentity`, `sourceGroup`,
  `authSource`.
- **Destination**: `destFQDN`, `destCategory`, `destCategoryGroup`,
  `destCountry` (ISO-3166 α2 list).
- **Schedule**: the same `PolicySchedule` type used by Access Rules.
- **Action**: `profileName` (must match a profile Sluice's `Health`
  response advertises) and `mode` — `ENFORCE` (strip and forward
  sanitized bytes — see the Content-Length caveat under
  [Known limitations](#known-limitations-read-before-enabling-in-production)
  if the sanitized size differs from the original), `REPORT_ONLY` (detect
  only, deliver the original bytes), or `BYPASS_WITH_REPORT` (VIP
  carve-out: report threats but still deliver the original)
  (`cdrpolicy.go:60-64`, `91-115`).

Rules are evaluated first-match by descending `priority`; an unmatched
request falls through to the config's `default_profile` /
`default_mode` (`cdrpolicy.go:476-536`). Rule names are the identity key
used by `DELETE ?name=`, so duplicate or empty names put the store into
a **degraded** state (reported via `integrity.ok` on `GET
/api/cdr/policies`) in which new rules can't be added until the operator
repairs it. `DELETE ?name=` cannot identify the affected rule once names
collide or are empty, so the repair path is positional instead:
`DELETE /api/cdr/policies?position=N&name=<verbatim name at that
position>` — the verbatim name is a fence against removing the wrong
entry if the store changed since it was listed (`cdrpolicy.go:167-246`,
`280-311`; `cdr_ui.go:833-851`).

## Fail-open vs fail-closed behavior

Whether an *erroring* Sluice call blocks traffic or lets it through
unsanitized is controlled by the `fail_mode` setting (`cdr.fail_mode` in
`config.yaml`, or `-cdr-fail-mode {open|closed}` on the CLI; default
`open`) — see `CDRFailOpen()` (`config.go:401-406`) and the runtime
toggle at `PUT /api/cdr/config`. This governs the outcome of a call that
was *attempted* and failed; it does **not** govern the case where no
pool member was selectable in the first place (empty pool, or every
circuit breaker open) — that case always forwards the file unsanitized
and unblocked, `fail_mode` notwithstanding (see
[Known limitations](#known-limitations-read-before-enabling-in-production)).
An oversize file
(`SKIPPED_OVERSIZE`) is never subject to fail-mode — it always passes
through unsanitized with a log line, the same as any other scan being
skipped for size (`cdr_proxy.go:436-453`). For the three diagnostics
states this drives (`enabled-healthy`, `enabled-degraded`,
`enabled-broken`) and the recovery steps for each, see
[Operations §6](../OPERATIONS.md#6-cdr-sluice-recovery).

## Security considerations

- **Client private key at rest.** By default the client's mTLS private
  key is stored as plaintext PEM. Setting
  `CULVERT_CDR_CLIENT_KEY_ENCRYPT` (truthy) enables AES-GCM-at-rest
  encryption under a per-instance KEK anchored to the key file itself
  (`<keyPath>.kek`, or the shared `CULVERT_KEK` when configured); the
  *read* path is content-driven (an already-encrypted key is always
  decrypted regardless of the flag, and a decrypt failure never
  triggers silent regeneration or re-enrollment) (`cdr_client_keyatrest.go:
  1-30, 54-92`). An existing plaintext key is migrated in place on
  first use once the flag is set, with the original quarantined to
  `<key>.plaintext.bak` until the operator confirms recovery and
  removes it (`cdr_client_keyatrest.go:106-166`). The client cert and
  Sluice's CA cert are always stored as plaintext (they are public).
- **Not in the config-version rollback surface.** `cdr_enabled`,
  `cdr_instances.json`, and `cdr_policies.json` are per-node local
  state — `captureConfigBackup` does not read them and
  `applyConfigBackup` does not restore them. Rolling back to an earlier
  config version has **no effect** on CDR enablement, enrolled
  instances, or policy rules; they are also outside export/import and
  CP→DP cluster sync (`cdr_ui.go:1-34`). Manage CDR state on each node
  independently.
- **RBAC.** All `/api/cdr/*` reads (`GET`) require `RoleViewer`; every
  mutation — config toggle, enroll, delete, revoke, recover, and the
  admin test harness — requires `RoleAdmin` (verified against
  `ui_routes_meta.go:748-779`, matching the intent stated in
  `cdr_ui.go`'s header comment).
- **Admin test harness** (`POST /api/cdr/test`) always runs in
  `REPORT_ONLY` mode against the configured default profile, so it
  never mutates the uploaded file, but it does exercise the live pool
  and credentials and is audited (`cdr_ui.go:1241-1310`).

## Admin API reference

| Method | Path | Min role | Purpose |
|---|---|---|---|
| GET | `/api/cdr/config` | viewer | Effective runtime config + derived `clientActive`/`failOpen` |
| PUT | `/api/cdr/config` | admin | Toggle `cdr.enabled` at runtime (persists across restart) |
| GET | `/api/cdr/instances` | viewer | List enrolled instances, enriched with cert expiry + circuit-breaker state |
| DELETE | `/api/cdr/instances?name=` | admin | Remove local registry entry + shred local certs (does not revoke on Sluice) |
| POST | `/api/cdr/instances/enroll` | admin | Enroll a new Sluice instance (token exchange) |
| POST | `/api/cdr/instances/enroll/recover` | admin | Authoritatively resolve an ambiguous enrollment/renewal operation |
| GET | `/api/cdr/instances/enroll/receipts` | viewer | List enrollment recovery receipts |
| DELETE | `/api/cdr/instances/enroll/receipts` | admin | Remove a resolved (terminal) receipt |
| POST | `/api/cdr/instances/revoke` | admin | Revoke a credential on Sluice (`name` or orphan `fingerprint`) |
| GET | `/api/cdr/policies` | viewer | List CDR policy rules |
| POST | `/api/cdr/policies` | admin | Add a CDR policy rule |
| DELETE | `/api/cdr/policies?name=` | admin | Remove a CDR policy rule |
| DELETE | `/api/cdr/policies?position=N&name=` | admin | Degraded-store repair: remove the rule at position `N`, fenced on its verbatim name |
| GET | `/api/cdr/health` | viewer | Cached (or on-demand) Sluice `Health` result |
| POST | `/api/cdr/test` | admin | Run an uploaded file through Sluice in REPORT_ONLY mode |

(Source: route table in `ui_routes_meta.go:748-779`; handlers in
`cdr_ui.go` and `cdr_enroll_receipts.go`.)

## GUI

The legacy admin UI exposes CDR as its own top-level nav item ("CDR",
under the Policies section, `data-view="cdr"`, visible from the
`operator` role up) (`static/index.html:812-833`). The newer
React/TypeScript frontend (behind `CULVERT_EXPERIMENTAL_UI`, ADR-FE-001)
has a Security → CDR Integration page with four tabs — Overview &
Health, Instances, Policies, and Test — where every mutation, including
the imperative test run, requires the admin role
(`frontend/src/features/security/CDRPage.tsx:1-44`). The Instances tab's
enrollment-recovery marker only surfaces to a matching authenticated
owner and is discarded on a confirmed mismatch or logout, per the 2F-G
frontend closure work (see `CLAUDE.md`'s Architecture Notes).

## See also

- [`docs/OPERATIONS.md` §6 — CDR (Sluice) recovery](../OPERATIONS.md#6-cdr-sluice-recovery)
  for the `enabled-healthy` / `enabled-degraded` / `enabled-broken`
  diagnostics states and step-by-step recovery.
- `roadmap/SLUICE-CDR-HANDOFF.md` — the original pre-implementation
  design brief for the Sluice engine (architecture rationale, protocol
  sketch); historical context only, not a source of truth for the
  shipped API surface.
