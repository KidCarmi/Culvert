# Admin threat-domain allowlist preserved across fresh recovery — owner P1 (PR #1528)

**Finding (owner review 5547382867):** a supported backup restored onto a fresh
appliance lost the administrator-managed threat-feed DomainAllowlist (including
an explicit full clear). The allowlist was persisted only inside the threat-feed
DB, which `defaultBackupArtifacts` deliberately omits as a re-downloadable cache,
so defaults or newly fetched threat data produced different enforcement despite
restore success. The lab's earlier post-restore re-exemption was a workaround,
not evidence the original configuration survived.

**Fix (app bytes; new candidate identity a80be4b6):**
- `internal/threatfeed`: the admin allowlist is persisted to its OWN file,
  `threat_domain_allowlist.json`, independent of the disposable feed DB.
  `InitWithAllowlist` reconciles it: present ⇒ authoritative (absent-vs-empty —
  an explicit `[]` is honoured, never re-seeded to defaults); absent ⇒ migrate
  the current allowlist into it so the first backup after upgrade captures it.
  A pointer slice distinguishes nil (field absent) from `&[]` (explicit clear)
  from entries. Both writers — the admin API and the CP→DP snapshot apply —
  persist BOTH stores (feed DB for rollback compat + the backed-up file).
- `backup.go`: `data/threat_domain_allowlist.json` added to the artifacts.
- scanning startup: `<dataDir>/threat_domain_allowlist.json` derived and wired.

**Proof — unit (internal/threatfeed/allowlist_backup_survival_test.go):** custom
entries and an explicit full clear survive a fresh recovery (feed DB absent,
allowlist file restored); absent file seeds defaults and writes the file; a
legacy feed-DB-only allowlist is migrated on first boot; the standalone file is
authoritative over the feed DB; a cleared list serializes as `[]`, not absent.

**Proof — end to end (lab run 38903245843, candidate a80be4b6, failures 0):** a
distinct admin marker `allowlist-survives-marker.example` is set as a fixture
BEFORE the backup; after restore it is asserted present via GET WITHOUT being
re-added, in both paths:
- `[6b] allowlist-survived-restore` — same-volume down → restore --confirm → up.
- `[H] allowlist-survived-recovery` — fresh-volume: data volume destroyed, restored
  from an encrypted backup, log key rotated, rebooted (source-absent recovery).
`example.com` remains only the policy-canary fixture, kept visibly separate from
the restore assertions. The explicit-clear case is proven by unit test (clearing
the live allowlist would break the canary-dependent phases, so it is not run
end-to-end; the backed-up file is exactly what the unit test round-trips).

Aligns with ASTRA's read-only source/restore equality check: the lab assertion
observes survival and records a mismatch, it does not repair the restored state.
