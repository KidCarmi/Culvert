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

## Architecture

Culvert is the gRPC client; Sluice is a separate service (typically a
Docker sidecar) that never needs to be trusted with Culvert's own TLS
material. The two communicate over a bidirectional-streaming `Sanitize`
RPC plus unary `Health`, `Enroll`, `EnrollStatus`, `RenewCert`, and
`RevokeClient` calls (`cdr.go`). Every call is per-file: the header frame
(filename, content-type, profile, mode) goes first, then the body in
64 KiB chunks (`cdrChunkSize`), then Sluice streams back the sanitized
bytes plus a threat report (`cdr.go:47-62`, `376-459`). A single Sanitize
call is bounded by a 35-second client-side deadline (`cdrDefaultTimeout`,
`cdr.go:53`) and files above 50 MiB (or a lower Sluice-advertised
per-profile cap) are rejected before any bytes cross the wire
(`cdrMaxFileSize`, `cdr.go:61`; `cdr_proxy.go:248-265`).

Culvert can enroll **multiple** Sluice instances. Each becomes a
`cdrPooledClient` with its own gRPC connection and its own circuit
breaker (closed → open after consecutive failures → half-open probe →
closed; `cdr_breaker.go:1-30`). The proxy path (`cdrPickPooled`) skips
open-breaker instances and round-robins across the rest; if every
instance's breaker is open, CDR falls through to the configured fail
mode (`cdr_pool.go:12-15`). A background poller (`cdr_health.go`) calls
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

Deleting an instance (`DELETE /api/cdr/instances?name=…`) only removes
Culvert's local registry entry and shreds the local PEM copies — it does
**not** revoke trust on the Sluice side. Sluice keeps trusting every
still-valid certificate generation until it expires or is explicitly
revoked there; the response and audit event report every fingerprint
that remains trusted so the operator knows what still needs revoking
(`cdr_ui.go:238-323`, `267-276`).

## Certificate rotation

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
  sanitized bytes), `REPORT_ONLY` (detect only, deliver the original
  bytes), or `BYPASS_WITH_REPORT` (VIP carve-out: report threats but
  still deliver the original) (`cdrpolicy.go:60-64`, `91-115`).

Rules are evaluated first-match by descending `priority`; an unmatched
request falls through to the config's `default_profile` /
`default_mode` (`cdrpolicy.go:476-536`). Rule names are the identity key
used by `DELETE ?name=`, so duplicate or empty names put the store into
a **degraded** state (reported via `integrity.ok` on `GET
/api/cdr/policies`) in which new rules can't be added until the operator
repairs the store by position (`cdrpolicy.go:167-246`, `280-311`).

## Fail-open vs fail-closed behavior

Whether an unreachable/erroring Sluice pool blocks traffic or lets it
through unsanitized is controlled by the `fail_mode` setting
(`cdr.fail_mode` in `config.yaml`, or `-cdr-fail-mode {open|closed}` on
the CLI; default `open`) — see `CDRFailOpen()` (`config.go:401-406`) and
the runtime toggle at `PUT /api/cdr/config`. An oversize file
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
