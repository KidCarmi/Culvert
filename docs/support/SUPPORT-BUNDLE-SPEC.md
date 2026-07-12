# Culvert Support Bundle (CSB) — Format Specification

- **Status:** Proposed (design). Format id: `csb/1`.
- **Depends on:** `SUPPORTABILITY-ARCHITECTURE.md` (vocabulary), `COLLECTOR-CONTRACT.md` (section producers), `REDACTION-MODEL.md` (classification).
- **Reuses:** `backup.go` tar/manifest/atomic-write machinery, `internal/backupcrypt` encryption, `backup.go`'s per-file SHA-256 discipline. **Does not reuse** `defaultBackupArtifacts` (that is a restore surface, not a diagnostic one).

---

## 1. Container format

A CSB is a **gzipped tar** (`.csb.tgz`) or, when encrypted, a `backupcrypt`/age envelope over the gzipped tar (`.csb.age`). Layout:

```
culvert-support-<node>-<utc>.csb.tgz
├── manifest.json          # REQUIRED, FIRST entry (streaming validators read it first)
├── SUMMARY.md             # REQUIRED human-readable digest (health verdict, top findings, errors)
├── redaction-report.json  # REQUIRED evidence of what was masked (counts by class, never values)
├── sections/
│   ├── product.json           # versions, build metadata, appliance/runtime
│   ├── health.json            # CHR set + rolled-up verdict
│   ├── readiness.json         # /readyz snapshot
│   ├── diagnostics.json       # OperatorContract
│   ├── config.json            # redacted config export (via config_surfaces)
│   ├── config-versions.json   # version history + latest diff
│   ├── policy.json            # policy summary + rule stats + object-ref graph
│   ├── tls.json               # CA/cert state (no private material)
│   ├── logs/system.log        # recent system log (redacted, bounded)
│   ├── logs/requests.jsonl    # recent request-log entries (redacted, bounded)
│   ├── audit.jsonl            # recent audit trail (actor-enriched)
│   ├── events/timeline.jsonl  # operational timeline
│   ├── metrics/snapshot.prom  # point-in-time /metrics
│   ├── metrics/window.json    # incident-window metrics (60-min ring + counters)
│   ├── runtime/goroutine.txt  # goroutine dump (L2+)
│   ├── runtime/heap.pprof     # heap profile (L3+, gated)
│   ├── host/*.json            # container/host facts via /v1/collect (redacted at agent)
│   ├── cluster/*.json         # per-node + fan-out correlation (cluster only)
│   └── ...                    # one path per collector section
└── collection-errors.json # REQUIRED (may be empty []) — per-collector failures
```

**Ordering is deterministic** (collector ID ascending, then path ascending) so two bundles of identical state diff cleanly and hashes are stable modulo timestamps (P7). `manifest.json` is always the first tar entry.

---

## 2. Manifest schema (`SupportBundleManifest`)

```jsonc
{
  "format": "csb/1",                       // bundle format id; consumers reject unknown major
  "bundle_id": "csb_01J...",               // deterministic: base32(sha256(node_id | created_at | nonce))[:26], ULID-shaped
  "created_at": "2026-07-12T10:04:11Z",    // RFC3339 UTC
  "generated_by": {
    "product": "culvert",
    "version": "v1.2.3",                   // main.version (linker-injected; "dev" if untagged)
    "build": { "commit": "…", "built_at": "…", "go": "go1.25.12" },
    "collector_engine_version": 1          // internal/support engine schema
  },
  "node": {
    "node_id": "…",                        // hostname / enrolled NodeID
    "role": "standalone|control-plane|data-plane|ha-standby",
    "runtime": "compose|k8s|host|unknown",
    "cluster_id": "…"                      // omitted when standalone
  },
  "scope": {
    "incident_scope": "tls_inspection_failure|standard|…",
    "debug_level": 1,                      // L0..L4 in effect during collection
    "time_window": { "from": "…", "to": "…" }   // requested evidence window
  },
  "case_id": "TAC-000123",                 // optional; binds bundle to a support case
  "redaction": {
    "model_version": 1,                    // REDACTION-MODEL schema version
    "profile": "default",                  // named redaction profile applied
    "fail_closed": true                    // asserts the fail-closed default was active
  },
  "sections": [
    {
      "id": "diagnostics",
      "path": "sections/diagnostics.json",
      "collector": "diagnostics",
      "collector_version": 1,              // per-section schema version (compat)
      "owner": "observability",            // subsystem team/owner
      "class_max": "INTERNAL",             // highest DataClass present after redaction (never > INTERNAL for shareable)
      "sha256": "…",                       // integrity hash of the section bytes
      "size_bytes": 20481,
      "started_at": "…", "ended_at": "…",  // per-collector timing
      "status": "ok|partial|skipped|failed|unavailable",
      "truncated": false                   // true if a byte/row budget clipped output
    }
    // … one entry per section, present even for failed collectors
  ],
  "integrity": {
    "manifest_sha256": "…",                // hash of this manifest with the field zeroed
    "bundle_sha256": "…"                   // hash of the whole tar (sealed after assembly)
  },
  "collection": {
    "engine_started_at": "…", "engine_ended_at": "…",
    "total_collectors": 24, "ok": 22, "failed": 1, "skipped": 1,
    "error_count": 1                       // == len(collection-errors.json)
  }
}
```

### Field rules
- **`format`** — consumers reject an unknown *major* (`csb/2`) and warn on unknown minor; forward-compatible additive fields only within a major.
- **`bundle_id`** — deterministic + collision-resistant; the same node+instant+nonce yields the same ID (idempotency/dedup). The nonce prevents two concurrent requests from colliding.
- **`class_max` per section** — a shareable bundle asserts `class_max ≤ INTERNAL` for every section (see REDACTION-MODEL); a section that would exceed it is dropped and recorded in `collection-errors.json`, never emitted.
- **`sha256` per section + `bundle_sha256`** — integrity is verifiable offline; TAC validates before opening (`culvert support validate`).
- **`status` per section** — `ok` (complete), `partial` (budget-truncated but usable), `skipped` (feature/runtime-gated), `unavailable` (dependency down — e.g. DB), `failed` (collector error, see errors file). The bundle succeeds as long as the engine ran; individual `failed` sections are expected and non-fatal (P2).

---

## 3. Collection-errors schema (`collection-errors.json`)

```jsonc
[
  {
    "collector": "host_facts",
    "phase": "execute",                    // preflight|execute|redact|assemble
    "error_class": "timeout|panic|unavailable|permission|budget|runtime_unsupported",
    "message": "maintenance agent unreachable at /run/culvert-maint/… (redacted)",
    "fatal": false                          // ALWAYS false for a collector; true only for engine-level abort
  }
]
```

Errors are themselves redacted (no paths/secrets in `message`). A collector panic is caught, converted to an `error_class: panic` entry, and the section is marked `failed` — the bundle continues.

---

## 4. Versioning & compatibility

Three independent version axes so one can move without churning the others:

| Axis | Field | Bump when | Consumer rule |
|---|---|---|---|
| **Bundle format** | `format` (`csb/N`) | The container layout / manifest shape changes incompatibly | Reject unknown major; warn unknown minor |
| **Collector engine** | `collector_engine_version` | Orchestration semantics change | Informational |
| **Per-section schema** | `sections[].collector_version` | A section's JSON shape changes | Consumer parses per-section version; unknown newer minor → best-effort |

**Compatibility rules**
1. **Additive-only within a major.** New sections/fields are always additive; removing or retyping a field bumps the axis's major.
2. **A newer bundle opens in an older tool degraded, not broken.** Unknown sections are listed but not parsed; unknown manifest fields ignored.
3. **CI gate:** golden-schema tests pin `csb/1` and every section schema; a change to any section's shape without a `collector_version` bump fails CI (`TEST-STRATEGY §golden`).
4. **Cross-version tests:** a corpus of frozen bundles from each released `collector_version` must still validate under the current tool (`TestBundleBackwardCompat`).

---

## 5. Integrity, determinism, and tamper-evidence

- **Per-section SHA-256** computed over the exact section bytes as written; recorded in the manifest before `bundle_sha256` is sealed.
- **`manifest_sha256`** is the hash of the manifest with `integrity.manifest_sha256` and `integrity.bundle_sha256` zeroed — self-verifying.
- **`bundle_sha256`** covers the full tar; when encrypted, the AEAD tag (backupcrypt AAD-bound header) provides tamper-evidence and the hash binds plaintext identity for the recipient.
- **Determinism:** fixed section ordering + fixed key ordering in JSON + timestamps confined to explicit fields ⇒ two runs over identical frozen state produce byte-identical sections (verified by injecting a fixed clock, mirroring the autoexclude/engine test pattern). `TestBundleDeterministic`.
- **Zip-bomb / size defense:** the engine enforces a **total bundle budget** and **per-section budgets**; a section that would exceed its budget is truncated (`truncated:true`) not expanded; decompression on the consumer side is bounded (documented limit) — see THREAT-MODEL T-BOMB.

---

## 6. Bundle lifecycle (state machine)

```
REQUESTED → AUTHORIZED → PREFLIGHT → COLLECTING → REDACTING → VALIDATING
          → PREVIEW → [ENCRYPTING] → READY → EXPORTED/UPLOADED → EXPIRED → DELETED
                                              └→ (any error) → FAILED
```

Each transition is audited (`support.bundle.<transition>`), and every state is persisted so a crash mid-collection leaves a recoverable, cleanly-`FAILED` bundle (never a half-written READY). Rules:

- **PREVIEW is mandatory before export** (P4) — no path skips it in a UI/API flow; the CLI `collect` prints the redaction report and requires `--yes` (or interactive confirm) before writing an exportable file.
- **Retention:** bundles live under `<dataDir>/support/bundles/<bundle_id>/`; default retention 7 days or 5 bundles (whichever first), configurable; **retention is enforced by a janitor** that deletes oldest-first and audits each deletion (`support.bundle.expire`).
- **Deletion** is a hard delete of the bundle dir; the manifest record (id, case_id, hashes, timestamps — no contents) is retained in an append-only index for audit/history (`culvert support history`).
- **Disk safety:** the janitor and preflight share the disk-headroom check; a full disk blocks new bundles with a clear error rather than partially writing (P5).

---

## 7. Section catalog (what each section contains, and its source)

| Section | Source (reuse) | Max class (post-redaction) | Level gate |
|---|---|---|---|
| `product.json` | `main.version`, build vars, runtime probe, `/v1/status` | PUBLIC | L0 |
| `health.json` | CHR aggregator (extends `OperatorContract`) | INTERNAL | L0 |
| `readiness.json` | `/readyz` (`healthcheck.go`) | PUBLIC | L0 |
| `diagnostics.json` | `buildOperatorContract` (`diagnostics.go`) | INTERNAL | L1 |
| `config.json` | `apiConfigExport` redacted accessors + `config_surfaces` | INTERNAL | L1 |
| `config-versions.json` | `configVersions.List()` + `diffConfigs` | INTERNAL | L1 |
| `policy.json` | `policyStore.List()` + hit counters + object-ref resolver | INTERNAL | L1 |
| `tls.json` | `certMgr.CACertInfo()`, cert expiries, chain metadata (no keys) | INTERNAL | L1 |
| `logs/system.log` | rotating logger tail (redacted, bounded) | INTERNAL | L1 |
| `logs/requests.jsonl` | `internal/logstore` / `reqlog` (redacted) | SENSITIVE→redacted to INTERNAL | L1 |
| `audit.jsonl` | `internal/audit` (actor-enriched) | INTERNAL | L1 |
| `events/timeline.jsonl` | Timeline recorder | INTERNAL | L1 |
| `metrics/*` | `/metrics` + 60-min ring | PUBLIC | L1 |
| `runtime/goroutine.txt` | `runtime.Stack` (new authenticated dump) | INTERNAL | L2 |
| `runtime/heap.pprof` | `runtime/pprof` (new gated endpoint) | INTERNAL | L3 |
| `host/*.json` | maintenance-agent `POST /v1/collect` | INTERNAL | L2 |
| `cluster/*.json` | fan-out collectors + CP/DP additions | INTERNAL | L1 (cluster) |

Traffic-metadata sections (`logs/requests.jsonl`) inherit the codebase's existing privacy posture: query strings excluded, identity separated from the SIEM `auth_*` block (`logstore.go:60-92`), and identities masked per the redaction profile.

---

## 8. Machine + human duality

Every CSB carries both `manifest.json`/section JSON (machine) and `SUMMARY.md` (human): the rolled-up health verdict, the top 3 failing/warning CHRs with probable cause + remediation, the incident scope, the collection error count, and a one-line "what changed before the incident" from the timeline. TAC reads `SUMMARY.md` first, automation parses `manifest.json` first. Both are generated from the same in-memory model so they never disagree.
