# Culvert Support — Redaction & Data-Governance Model

- **Status:** Proposed (design). Decision recorded in ADR-0020.
- **Depends on:** `config_surfaces.go` (existing classification registry — the template), `internal/secret` (ADR-0007, the `NEVER_EXPORT` enforcement), `SUPPORT-BUNDLE-SPEC.md`, `COLLECTOR-CONTRACT.md`.
- **Core stance:** **Redact structurally at the source, fail closed on the highest class, and treat regexes as a backstop — never the primary control.** Support data may contain secrets, identities, URLs, headers, tokens, certificates, keys, and traffic metadata; none of these may leave the appliance except deliberately and provably.

---

## 1. Data classification taxonomy (`DataClass`)

Five ordered classes. Higher = more restricted.

| Class | Meaning | May appear in a shareable CSB? | Examples |
|---|---|---|---|
| `PUBLIC` | Non-sensitive; safe for anyone | Yes | product version, build, uptime, metric counts, readiness status |
| `INTERNAL` | Operationally revealing but not secret | Yes (default ceiling for a shareable bundle) | policy rule names, hostnames in config, health verdicts, rule stats, cert **metadata** (subject/expiry/fingerprint), audit actions |
| `SENSITIVE` | Identifying or confidential; masked before export | Only in masked form | usernames/emails, client IPs, full request URLs, LDAP DNs, group names, IdP issuer URLs |
| `SECRET` | Credential/authenticator material | **No** — dropped, never masked-and-kept | passwords/bcrypt hashes, TOTP secrets, session HMAC, OIDC/SAML client secrets, webhook HMAC, metrics token, OTLP header API keys, upstream-proxy credentials, enrollment tokens |
| `NEVER_EXPORT` | Key material that must never cross the process boundary | **No** — no code path yields the bytes | KEK, CA private keys (root/cluster/DP), TLS private keys |

**The default for an unclassified field is `SENSITIVE`** (fail closed, P3): a new struct field with no classification is masked, not leaked. `SECRET`/`NEVER_EXPORT` are never emitted in any form — they are *dropped*, and the drop is recorded in `redaction-report.json` as a count.

`NEVER_EXPORT` is not enforced by the redactor at all — it is enforced by `internal/secret`: those bytes are only reachable through `Sealed.WithPlaintext`, which no collector calls. "Never export" = "no exported accessor returns the bytes," a compile-time property (ADR-0007). The redactor's job for `NEVER_EXPORT` is only to assert, in tests, that no collector can name such a field.

---

## 2. The classification registry (extends `config_surfaces.go`)

`config_surfaces.go` already classifies the **config plane** with a `Sensitive bool` + `Redacted bool` and a bidirectional parity test. We generalize that proven pattern into a **`DataClassRegistry`** (`internal/redaction/registry.go`) covering **three domains**, each with its own parity wall:

1. **Config surfaces** — reuse `config_surfaces.go` directly: `Sensitive:true` rows map to ≥`SECRET`, `Redacted` accessors map to `SENSITIVE`-masked. No duplication; the redactor reads the existing registry.
2. **Persisted `/data` files** — a new `dataFileClasses` table classifying every artifact in the state inventory (from `roadmap/D1.0-state-inventory.md`, reconciled): e.g. `ca.bundle`→`NEVER_EXPORT` contents, `ui_users.json`→`SECRET`, `admin_settings.json`→mixed (per-field), `logstore/`→`SENSITIVE`, `config_versions/`→`INTERNAL` via redacted export. A `/data` collector consults this table and **defaults an unlisted file to `SECRET`** (fail closed).
3. **Log / stream field classes** — a `logFieldClasses` table classifying `logstore.Entry`/`reqlog.Entry`/audit fields (e.g. `Identity`→`SENSITIVE`, `URI`→`SENSITIVE`, `IP`→`SENSITIVE`, `Action`→`INTERNAL`, byte counts→`PUBLIC`).

**Parity wall (`data_surfaces_test.go`, mirroring `config_surfaces_test.go`):** reflection over the collected structs asserts *every field of every struct a collector serializes is claimed by exactly one registry row with an explicit class*. Adding a field to a collected struct without classifying it fails CI. **This is the load-bearing CI gate** the prompt demands ("prevent new configuration fields or secrets from being added without redaction coverage").

---

## 3. Redaction techniques (in priority order)

The model deliberately layers structural mechanisms first and regex last.

1. **Structural drop at the type boundary (strongest).** `internal/secret` handles render `REDACTED` under every fmt verb and expose no byte accessor — a `SECRET`/`NEVER_EXPORT` value is *unreachable*, so it cannot be serialized. New secret-bearing types adopt the `Sealed` pattern. This is why "do not rely only on regexes" is satisfiable: the crown-jewel material is gone by construction.
2. **Structured-field redaction (primary for collected data).** The redactor walks a Go value using the `DataClassRegistry`: `SECRET`+ fields are dropped, `SENSITIVE` fields are masked per §4, `PUBLIC`/`INTERNAL` pass. This is field-name/type driven, not content driven — deterministic and testable.
3. **Redacting accessors (reuse existing).** Collectors prefer `List()`/`URL.Redacted()`/`GetConfig`-scrub paths that already strip secrets (`internal/upstream`, `internal/alerts`, `controlplane_server.go:88-108`).
4. **Free-form scrubber (backstop, for log lines and agent output).** For unstructured text where field classification can't apply (system log lines, container logs), a bounded scrubber masks known secret *shapes*: `KEY=VALUE` env pairs for known secret keys, `Authorization:`/`Cookie:`/`Set-Cookie:` header values, bearer tokens, PEM blocks (`-----BEGIN … -----`), hex/base64 blobs adjacent to secret-y key names, and the configured secret values themselves (the redactor is seeded with the live secret values so it can catch them verbatim even in an unexpected position). Regexes are the *last* layer and are treated as defense-in-depth, never the guarantee.

---

## 4. Masking semantics (what `SENSITIVE` becomes)

Masking must preserve diagnostic value without revealing the datum:

| Type | Masked form | Preserves |
|---|---|---|
| Client IP | `203.0.113.0/24`-style prefix or stable salted token `ip_7f3a…` | co-occurrence / grouping |
| Username/email | stable salted token `user_9c2e…` (same input → same token within a bundle) | correlation across sections |
| Full URL | scheme+host kept (host itself INTERNAL), path/query masked to `…` | reachability/host diagnosis |
| DN / group | last RDN kept, rest masked | structure without identity |
| Fingerprint/serial | first/last 4 chars, middle masked | matching without full value |

Masking uses a **per-bundle random salt** (not persisted) so tokens correlate *within* a bundle but not *across* bundles — preventing cross-bundle re-identification. The salt is in `NEVER_EXPORT` (never written to the bundle).

---

## 5. Customer-controlled exclusions

Operators can tighten (never loosen) redaction:
- **Named redaction profiles** (`default`, `strict`, `paranoid`): `strict` masks all hostnames; `paranoid` additionally drops request logs and audit details entirely. A profile can only *raise* classes, never lower them.
- **Custom exclusion rules**: an admin-managed list of additional field paths/regexes to mask or drop, persisted as config (and thus itself governed by `config_surfaces`). Applied *on top of* the built-in registry — additive only.
- **Section opt-out**: an operator may exclude whole sections (e.g. "no request logs") at request time; the excluded section is recorded as `skipped:operator` in the manifest.

The active profile + exclusions are recorded in `manifest.redaction` and `redaction-report.json` so TAC knows exactly what governance applied.

---

## 6. Preview before export (mandatory, P4)

Before any bundle is exportable, the operator sees:
- `redaction-report.json`: per-class **counts** of dropped/masked items, per-section `class_max`, the profile + exclusions applied, and the redaction model version — **counts only, never the redacted values**.
- The `SUMMARY.md` and manifest.

Only after preview (GUI confirm / CLI `--yes`) does the bundle become `READY`. The CLI `collect` refuses to write an exportable file without confirmation. `culvert support inspect <bundle>` re-renders the redaction report from a finished bundle for re-verification.

---

## 7. Certificate & key handling (explicit)

- **Private keys** (CA root/cluster/DP, TLS, KEK) are `NEVER_EXPORT` — structurally unreachable (§1). No collector references them.
- **Certificates (public)** are `INTERNAL`: subject, issuer, SANs, validity window, fingerprint, chain metadata may be collected (they diagnose expiry/trust issues) — but the DER/PEM of a *leaf with an embedded key* is never bundled; only the public cert metadata.
- **CSRs / enrollment tokens** are `SECRET` (dropped).
- The `tls.json` collector asserts, in test, that its output contains no `PRIVATE KEY` PEM marker under any input (`TestTLSCollectorNoPrivateKey`).

---

## 8. Redaction evidence & versioning

- **Evidence:** every bundle carries `redaction-report.json` (§6) and per-section `class_max` in the manifest. This is auditable proof of what governance ran.
- **Versioning:** `redaction.model_version` in the manifest ties a bundle to a specific taxonomy/registry version. When the registry changes (new class, new masking), the version bumps and the change is ADR/changelog-recorded so a bundle's redaction can be interpreted years later.
- **Determinism:** masking of the same input under the same salt is deterministic; without the salt it is not reversible.

---

## 9. Fail-closed rules (the invariants tests enforce)

| Invariant | Enforcement test |
|---|---|
| Unclassified collected field ⇒ treated as `SENSITIVE` (masked), never passed through | `TestUnclassifiedFieldIsMasked` |
| `SECRET`/`NEVER_EXPORT` never appear in any section, masked or raw | `TestNoSecretInBundle` (golden, all-collectors, planted secrets) |
| No collector can name a `NEVER_EXPORT` accessor | compile + `TestNeverExportUnreachable` (import-graph / `internal/secret` fitness test) |
| A section whose actual class exceeds its declared `MaxClass` is dropped + errored | `TestSectionClassCeiling` |
| Live secret values (seeded) are caught even in free-form text | `TestFreeFormScrubberCatchesLiveSecrets` |
| Backup artifacts (`ui_users.json`, `ca.bundle`, `cluster-ca.key`, `admin_settings.json`) are never included as files | `TestRawStateFilesExcluded` |
| Raising a profile can only add masking, never remove it | `TestProfileMonotonic` |

---

## 10. What must NEVER leave the appliance (the absolute list)

Independent of profile, class, or operator override, these are `NEVER_EXPORT` and have no code path into a CSB:

- KEK material (`internal/secret`), CA private keys (root/cluster/DP), any TLS private key.
- Raw `ca.bundle`, `cluster-ca.key`, `*.kek` files.
- `ui_users.json` bcrypt hashes and TOTP secrets (the *fact* of a user may be `SENSITIVE`-masked; the authenticator never).
- Session HMAC, OIDC/SAML client secrets, webhook HMAC, metrics token, OTLP header values, upstream-proxy credentials (the redacted config export already strips these; the raw files are never bundled).
- The per-bundle redaction salt.

This list is duplicated as constants + a fitness test so it cannot silently shrink.

## Sighted consent gate — retained free-form preview (P4/P6 companion)

The scrubber is precision-first by design (no entropy rule) so it will not catch a
**bare, shapeless secret** an operator types into an INTERNAL free-form field (a
policy rule name, an upstream endpoint, a diagnostic message). That value is KEPT
in the shareable bundle, and the bundled `redaction-report.json` is counts-only —
so the human approving an export could not *see* the value they release.

To close that gap without weakening the counts-only bundle report or the scrubber's
deliberate precision, the runner captures a **bounded, post-scrub sample of the
retained INTERNAL free-form values** per section (`Result.RetainedFreeForm`, capped
and deduped) and writes it to **`redaction-preview.json`** in the server-side bundle
directory. This file is **NEVER added to the tar and NEVER downloaded** — it exists
only so the mandatory pre-export consent surface (`GET /api/support/bundles/{id}/
redaction-report`, and the SPA panel) can show the approver the actual strings being
released, with an explicit "review before approving" warning. It is a review aid,
not a redaction control: it never changes what is exported, only what the approver
can see. PUBLIC fields (version/counts) and masked SENSITIVE/dropped SECRET values
are never surfaced; a value the scrubber fully replaced (a lone `[redacted:…]`
token) is skipped. Pinned by `redactor_retained_test.go` and
`TestRunner_ConsentPreview_SurfacedButNotInTar`.
