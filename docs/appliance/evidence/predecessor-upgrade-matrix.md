# Predecessor upgrade/downgrade qualification — matrix (appliance pilot)

Executed 2026-10-02 with the REAL published linux/amd64 release binaries from GitHub Releases
(`culvert-linux-amd64-v1.0.{235,250,258,259}`), one fresh state root per pair, three boots per
root (FROM → TO → FROM again). Driver: [`test/appliance/predecessor-upgrade.sh`](../../../test/appliance/predecessor-upgrade.sh).

| pair | FROM reports | TO reports | leg A (FROM, fresh root) | leg B (TO, same root — upgrade) | leg C (FROM again — downgrade tolerance) | verdict | evidence |
|---|---|---|---|---|---|---|---|
| 258 → 259 | `v1.0.258` | `v1.0.259` | 17 pass / 0 fail | 19 pass / 0 fail | 19 pass / 0 fail | **PASS** | [predecessor-upgrade-258-to-259.md](predecessor-upgrade-258-to-259.md) |
| 250 → 259 | `v1.0.250` | `v1.0.259` | 17 pass / 0 fail | 19 pass / 0 fail | 19 pass / 0 fail | **PASS** | [predecessor-upgrade-250-to-259.md](predecessor-upgrade-250-to-259.md) |
| 235 → 259 | `v1.0.235` | `v1.0.259` | 17 pass / 0 fail | 19 pass / 0 fail | 19 pass / 0 fail | **PASS** | [predecessor-upgrade-235-to-259.md](predecessor-upgrade-235-to-259.md) |

No assertion failed on any leg of any pair. No `*.corrupt.*`/quarantine artefact appeared on any
root. Every durable file (`admin_settings.json` with `admin_settings_schema: 2`, `ui_users.json`,
`policy.json`, `alert_webhooks.json`, `ca.bundle`, `.upstream_cred_key`, `.alert_webhook_key`, the
two config-version snapshots) is byte-identical after all three boots of every root; only the
append-only logs and `hit_counters.json` change.

## Binaries (sha256, as downloaded)

| file | sha256 |
|---|---|
| `culvert-linux-amd64-v1.0.235` | `5a2c6cf8c3d9d5a829e030dc8044a59d5276907c87cc06f150d5470f4d7aa91e` |
| `culvert-linux-amd64-v1.0.250` | `49484d95e92904e01bdd74b3a812533ae9c8adfe8e4bcd77407a44a500fc7760` |
| `culvert-linux-amd64-v1.0.258` | `667eeae8583cbba2544571597dc2ccc9e5575ed18c3b8e0a5162a84c569a6ea5` |
| `culvert-linux-amd64-v1.0.259` | `3ba95443374ea7bbf1b8d1fe826089267414a3de93e6b51f1081a99c9bb0b5a0` |
| `culvert-maint-linux-amd64-v1.0.235` | `751e38ed6219e5de0a03d9c7353035be01f9c01aef6142ad096ad8fd4e373c9a` |
| `culvert-maint-linux-amd64-v1.0.250` | `6cbd4e3a6afa8c764d389cc06d62eb6e8ccf9ec9df1e985d312228d10cc0c20b` |
| `culvert-maint-linux-amd64-v1.0.258` | `1a7fea60fe41d7516bc10be23f6247dcff0771f8d0375b4bad2782675f3120e7` |
| `culvert-maint-linux-amd64-v1.0.259` | `ed499b2abd6c0e58b82cac24a8afcec9242adec27e6f5bd3c58add9d97ec8cc5` |

The `culvert-maint` agent binaries were not executed (the maintenance agent is the host-root
component and holds no state under the appliance root); their digests are recorded so the release
pair is fully identified.

## What one run does

1. **Leg A — FROM on a fresh root.** Boot with the compose-equivalent flag set
   (`CULVERT_DATA_DIR=<root>`, `CULVERT_CA_PASSPHRASE` set so `ca.bundle` is encrypted), wait for
   `/ready`, `POST /api/setup/complete {user,pass}`, `POST /api/auth/login` (cookie jar), then seed:
   `POST /api/default-action {"action":"deny"}`, one Allow rule (`destFQDN: localhost`, `action: Allow`),
   one upstream v2 entry pointing at a local **credential-requiring** parent proxy plus
   `POST /api/upstream/entries/{id}/credential {action: replace}` (sealed under `.upstream_cred_key`),
   and one alert webhook with a signing secret (encrypted under `.alert_webhook_key`). Verify a config
   version was auto-created, snapshot every file's sha256, record the audit tail, then run the three
   enforcement probes.
2. **Leg B — TO on the same root (upgrade).** SIGTERM FROM (wait by PID), boot TO, and assert: no
   quarantine files; `admin_settings.json` parses with the same `admin_settings_schema`; login with the
   same password; the upstream entry is still `credentialState: configured`; the webhook is still
   listed and not `signing_degraded`; default action still `deny`; the Allow rule is present with the
   same id; the SAME three enforcement probes; `/ready` has no fail row that leg A did not have;
   `ca.bundle` sha unchanged; `/api/diagnostics` verdict not worse. Record `version` from `/healthz`.
3. **Leg C — FROM again on the same root (reverse leg).** SIGTERM TO, boot FROM, repeat leg B's
   assertions. A failure here is a downgrade-tolerance FINDING about the predecessor, not a script bug.

The three enforcement probes, identical on every leg (proxy env cleared, `-x` the Culvert proxy):

| probe | expected | evidence |
|---|---|---|
| `GET http://localhost:<origin>/` with admin Basic credentials | `200`, and `X-Parent-Proxy: seen` (the request was chained through the credentialed parent, i.e. the sealed credential unsealed on this binary) | the Allow rule + the upstream credential |
| `GET http://127.0.0.1:<origin2>/` with admin Basic credentials | `403` block page | default-deny on an unmatched host |
| `GET http://localhost:<origin>/` without credentials | `407 Proxy Authentication Required` | credential-required Stage-1 default |

## Compatibility notes across the matrix

- The v1.0.259 OpenAPI body shapes for every seeding call were accepted unchanged by 1.0.235,
  1.0.250 and 1.0.258; the script needed no version branch.
- `GET /api/policy` gained `persisted:true` between 1.0.235 and 1.0.250 (additive).
- `GET /api/diagnostics` gained the `rewrite_identity` row between 1.0.235 and 1.0.250 and the
  `admin_username_length` row (CHAOS-63) between 1.0.250 and 1.0.258 (additive `ok` rows).
- Policy rule `action` is capitalised (`Allow`); a lowercase `allow` is refused with
  `400 action must be Allow, Drop, Block_Page, or Redirect` on every version tested.
- `curl --noproxy '*'` also bypasses the `-x` proxy under test, so proxied probes clear the
  `*_proxy`/`no_proxy` environment instead (the admin-API calls keep `--noproxy '*'`).

## Reproduce

```bash
PORT_BASE=20200 test/appliance/predecessor-upgrade.sh \
  /path/to/culvert-linux-amd64-v1.0.258 /path/to/culvert-linux-amd64-v1.0.259 \
  /abs/fresh/state-root /abs/evidence-dir
# exit 0 = every assertion passed; summary.json, report.md, transcript.log and the
# per-leg curl captures land in the evidence dir. Use a distinct PORT_BASE and root per pair.
```
