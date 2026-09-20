# Content Disarm & Reconstruction (CDR)

Culvert's CDR stage sends files passing through SSL-inspected traffic to
**Sluice**, a separate CDR microservice (gRPC + mTLS), which strips active
content (macros, embedded OLE objects, PDF JavaScript/launch actions, etc.)
and returns a sanitized file. CDR runs **after** file-type/extension
checks and **before** ClamAV/YARA scanning in the inspect pipeline. Manage it
under the **CDR** panel in the admin UI (`data-view="cdr"`), or via
`/api/cdr/*`. The nav item itself is gated at the **operator** role and
above; the underlying `GET` endpoints accept **viewer** (see **API
reference** below) — a viewer with a direct link can still read CDR state,
they just won't see the nav entry.

Sluice is a standalone project (`github.com/KidCarmi/Sluice`) that Culvert
talks to as a client — it is not bundled into the Culvert binary or image.
Sluice must be deployed and reachable (typically as a Docker sidecar) before
CDR can be enabled. See `roadmap/SLUICE-CDR-HANDOFF.md` for the Sluice-side
protocol and deployment shape; this page covers only the Culvert-side
integration an operator manages.

**Disabled by default.** With no configuration, no gRPC dial happens and the
inspect pipeline is byte-identical to a build with CDR compiled out.

## Enabling it

Two ways to turn CDR on, and either one is enough — you do not need both:

1. **Config file / CLI flags**, then restart. Config-file values are
   overridden by CLI flags when both are set:

   | CLI flag | `config.yaml` key | Meaning | Default |
   |---|---|---|---|
   | `-cdr-enabled` | `cdr.enabled` | Turn the CDR stage on | `false` |
   | `-cdr-endpoint` | `cdr.endpoint` | Sluice gRPC address, `host:port` (e.g. `sluice:8443`) | — |
   | `-cdr-default-profile` | `cdr.default_profile` | Sanitization profile sent when no CDR policy rule matches; must name a profile Sluice's `Health` RPC advertises | `default` |
   | `-cdr-default-mode` | `cdr.default_mode` | Mode sent when no rule matches: `ENFORCE`, `REPORT_ONLY`, or `BYPASS_WITH_REPORT` | `ENFORCE` |
   | `-cdr-timeout-sec` | `cdr.timeout_sec` | Per-file deadline; must be ≥ 30 (Sluice's own cap is 30s — Culvert adds 5s so its own timeout fires last) | 35 |
   | `-cdr-max-file-size-mb` | `cdr.max_file_size_mb` | Reject files above this size **before** any bytes are sent to Sluice | 50 |
   | `-cdr-server-fingerprint` | `cdr.server_fingerprint` | TOFU-pinned SHA-256 of Sluice's server certificate (hex; `sha256:` prefix optional) | — |
   | `-cdr-certs-dir` | `cdr.certs_dir` | Directory holding the Sluice mTLS client bundle (`ca.pem`, `client.pem`, `client.key`) | — |

   There is no `fail_mode` CLI flag — set `cdr.fail_mode` in `config.yaml`
   (`open` or `closed`; see **Failure behavior** below).

2. **GUI enrollment**, no restart or config-file edit required: open
   **CDR → Enroll new Sluice instance**, paste the one-time enrollment token
   Sluice printed on first boot plus its server-certificate fingerprint.
   `POST /api/cdr/instances/enroll` exchanges the token for mTLS client
   credentials via Sluice's `Enroll` RPC, persists them, and **enables CDR
   automatically** — enrolling your first instance is a complete on-switch by
   itself. `PUT /api/cdr/config` (`{"enabled": true|false}`) is the plain
   runtime toggle for an already-enrolled deployment; it flips the enable
   sentinel at `<dataDir>/cdr_enabled` so the setting survives a restart, and
   starts/stops the connection pool immediately.

Enrolled instances, the client credential bundle, and CDR policy rules are
tracked at `<dataDir>/cdr_instances.json` and `<dataDir>/cdr_policies.json`,
loaded unconditionally (even while CDR is disabled) so a GUI enrollment done
before enabling still persists.

**Cluster note:** CDR is deliberately **not** part of the CP→DP
`ConfigSnapshot`, the config-version rollback surface, or config
export/import. Enrollment, policy rules, and the enable toggle are per-node
state — each node that terminates inspected TLS and needs CDR must be
enrolled with Sluice separately. (Client-key material at rest is covered
by the shared key-at-rest mechanism — see `key-at-rest.md`, `cdr-client`
key class.)

## Failure behavior

CDR failures are governed by `cdr.fail_mode` (`open` by default):

| Outcome | `open` (default) | `closed` |
|---|---|---|
| Sluice unreachable / times out / returns `ERROR` | Original file passes through unchanged; `CDR_ERROR` audit event + log line; `culvert_cdr_fail_open_total` | Delivery refused (block page); `culvert_cdr_fail_closed_total` |
| Sluice returns `BLOCKED` (file is unsalvageable) | Delivery refused (block page) — **always**, regardless of `fail_mode` | same |
| A panic anywhere in the CDR call path | Delivery refused (block page) — **always fail-closed**, regardless of `fail_mode` (`culvert_cdr_panics_total`) | same |
| File exceeds `cdr.max_file_size_mb` | Skipped client-side before any bytes reach Sluice (`culvert_cdr_oversize_skipped_total`) — original file continues down the pipeline unsanitized | same |

`fail_mode` only governs *transport/availability* failures. A `BLOCKED`
verdict or an internal panic is never passed through, no matter how
`fail_mode` is set — those are content decisions, not availability ones.

Per-request outcomes are also gated by the CDR policy rule's own **Mode**
(`ENFORCE` strips and delivers the sanitized file; `REPORT_ONLY` detects and
logs but delivers the original bytes; `BYPASS_WITH_REPORT` is a VIP carve-out
— report threats, still deliver the original). An unrecognized mode string
defaults to `ENFORCE` (the safer choice over the alternative of silently
falling back to `REPORT_ONLY`, which would let active content through).

Identical files are not re-sanitized: results are cached by SHA-256 of the
file body for up to one hour or 10,000 entries (`culvert_cdr_cache_hits_total`
/ `_cache_misses_total` / `_cache_size`), invalidated whenever the CDR policy
rule set changes.

## Multi-instance pool and circuit breaker

More than one Sluice instance can be enrolled. Each enrolled instance gets
its own circuit breaker (closed → open after 5 consecutive failures → half-open
after a 30s reset timeout → closed again after one successful probe). Live
requests round-robin across instances whose breaker is closed; an instance
with an open breaker is skipped. If every enrolled instance's breaker is
open, the pool reports "no active client" and the request falls through to
`fail_mode` as if CDR were unreachable. `culvert_cdr_instance_healthy` and
`culvert_cdr_queue_depth` come from the 15-second background health poll
(`GET /api/cdr/health`) and are a leading indicator of an instance nearing
its own worker/queue capacity, independent of the breaker state.

**Revocation requires a second active instance**: `POST /api/cdr/instances/revoke`
issues the revoke RPC *from* another enrolled, reachable Sluice — a
single-instance deployment cannot revoke its own credential through the API
(Sluice itself refuses self-revocation). Enroll a second instance first, or
remove the credential material out of band, if you need to revoke in a
single-instance deployment.

## Certificate lifecycle

Client certificates issued at enrollment are valid for one year (Sluice
v0.1). There is no zero-touch renewal yet — when a certificate is close to
expiry, re-enroll with a fresh one-time token and fingerprint from the Sluice
admin. If Sluice's **server** certificate is regenerated, the TOFU pin
(`cdr.server_fingerprint`) breaks on every enrolled instance until the
fingerprint is updated; there is no dual-pin rotation grace window yet (also
planned for a later Sluice version).

## Policy rules

CDR policy rules (`/api/cdr/policies`) choose **which sanitization profile**
and **which mode** apply to a given request — they do not decide whether to
allow or inspect the connection at all (that's the ordinary access-policy
engine). Fields intentionally mirror `PolicyRule` so the same matching mental
model applies:

- **Source**: source IP/CIDR, authenticated identity, IdP group, IdP name.
- **Destination**: FQDN, URL category, category group, destination country.
- **Schedule**: the same weekly time-window object used elsewhere.
- **Action**: `profileName` (must match a name Sluice's `Health` RPC
  advertises) + `mode` (`ENFORCE` / `REPORT_ONLY` / `BYPASS_WITH_REPORT`).

Rules are evaluated first-match by `priority`. When no rule matches, the
request falls through to `cdr.default_profile` / `cdr.default_mode`. Use
**CDR → Add CDR policy rule** in the GUI, or `POST /api/cdr/policies`.

## Testing a file

**CDR → (test upload)** / `POST /api/cdr/test` (admin-only) submits a file to
the active Sluice instance in `REPORT_ONLY` mode without touching live
traffic — use it to confirm connectivity and see what a given file would
trigger before writing a policy rule around it.

## Observability

Audit/request-log events: `CDR_SANITIZED`, `CDR_BLOCKED`, `CDR_ERROR` (each
carries the matched profile, mode, and threat summary). Filter them from
**CDR → Recent CDR events** in the GUI.

Prometheus metrics (`culvert_cdr_*`, all counters unless noted):
`files_processed_total`, `threats_detected_total`, `errors_total`,
`fail_open_total`, `fail_closed_total`, `panics_total`,
`oversize_skipped_total`, `cache_hits_total`, `cache_misses_total`,
`cache_size` (gauge), `bytes_in_total`, `bytes_out_total`,
`instance_healthy` (gauge, per enrolled instance), `queue_depth` (gauge, per
enrolled instance). Labels are deliberately low-cardinality — no filename,
destination host, or user identity — by contract with Sluice.

## API reference

All endpoints are under `/api/cdr/`, admin-UI-session-authenticated, RBAC
per the table below (reads = viewer, mutations = admin; `/api/cdr/config`
GET is viewer, PUT is admin):

| Endpoint | Method | Role | Purpose |
|---|---|---|---|
| `/api/cdr/config` | GET | viewer | Effective runtime config + derived fields (`clientActive`, `failOpen`) |
| `/api/cdr/config` | PUT | admin | Toggle `enabled`; persists and applies immediately |
| `/api/cdr/instances` | GET | viewer | List enrolled Sluice instances |
| `/api/cdr/instances` | DELETE | admin | Remove a registry entry (`?name=…`) and shred its local cert material — does **not** notify Sluice |
| `/api/cdr/instances/enroll` | POST | admin | Exchange a one-time token + fingerprint for mTLS credentials |
| `/api/cdr/instances/enroll/recover` | POST | admin | Resolve an enrollment whose outcome was left unknown (e.g. a client-side timeout mid-exchange) |
| `/api/cdr/instances/enroll/receipts` | GET | viewer | Bounded recovery receipts for past enrollment operations |
| `/api/cdr/instances/revoke` | POST | admin | Actively invalidate a credential at Sluice (by instance name or an orphaned fingerprint) — the Sluice-side counterpart to the local-only `DELETE` above |
| `/api/cdr/policies` | GET/POST/DELETE | viewer / admin / admin | CDR policy rule CRUD |
| `/api/cdr/health` | GET | viewer | Cached (or live, on demand) Sluice `Health` response |
| `/api/cdr/test` | POST | admin | Submit a file in `REPORT_ONLY` mode against the active instance |

## Common pitfalls

- **Enabling CDR with no reachable Sluice instance** leaves every
  SSL-inspected file download depending on `fail_mode`: `open` (default)
  silently stops sanitizing everything; `closed` blocks every eligible
  download. Confirm `/api/cdr/health` reports a healthy instance before
  relying on `closed`.
- **`default_profile` must exist on Sluice.** There is no client-side
  validation that the configured or rule-selected profile name is one Sluice
  actually advertises; a typo surfaces as a Sluice-side `ERROR` at request
  time, not at config time.
- **CDR state does not travel with cluster config sync, rollback, or
  export/import.** A restored config-version snapshot or a DP node's synced
  `ConfigSnapshot` will not carry CDR's enable state, enrolled instances, or
  policy rules — those must be reproduced per node.
