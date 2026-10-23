# Appliance lifecycle qualification — run 20261003T062347Z

| artifact | reference | digest / image id |
|---|---|---|
| image under qualification | `culvert:ci-smoke` | `culvert/proxy@sha256:e752cc38608d5f2e7e627081c6533b88cdef2f9bf0d008215d5c5032686f6c5b|sha256:e752cc38608d5f2e7e627081c6533b88cdef2f9bf0d008215d5c5032686f6c5b` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.250` | `ghcr.io/kidcarmi/culvert@sha256:a754b94bb61aba717e1f6123906b924bc8a9fb830ee522b903fa1a8daab044ee|sha256:a754b94bb61aba717e1f6123906b924bc8a9fb830ee522b903fa1a8daab044ee` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.258` | `ghcr.io/kidcarmi/culvert@sha256:ffc9ab99d43566dee5dfcb7d3b7b24de22c21abd6b561e350c4aec6844dca2fc|sha256:ffc9ab99d43566dee5dfcb7d3b7b24de22c21abd6b561e350c4aec6844dca2fc` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` | `127.0.0.1:5055/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e|sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e` |
| docker | 29.6.2 | compose 5.3.1 |
| host | Linux 6.18.44-fc-v64 | 4 cpu |

## Checks

| scenario | check | result | detail |
|---|---|---|---|
| A | boot | **PASS** | version=dev |
| A | ready-before-setup | **PASS** | setup_complete=fail policy_posture=default-deny (CULVERT_DEFAULT_ACTION=deny) |
| A | setup | **PASS** | http 200 |
| A | login | **PASS** | http 200 |
| A | enforcement:after-setup | **PASS** | allowed=200 blocked=403 |
| A | ready-after-setup | **PASS** | setup_complete=ok policy_posture=default-deny |
| A | strict-ready | **PASS** | rows ok; failing=['clamav'] (clamav stub) |
| A | login-after-restart | **PASS** | http 200 |
| A | rules-after-restart | **PASS** | present |
| A | default-action-after-restart | **PASS** | deny |
| A | enforcement:after-restart | **PASS** | allowed=200 blocked=403 |
| A | no-default-admin-credential | **PASS** | compose carries no admin credential |
| B:v1.0.250 | boot-predecessor | **PASS** | version=v1.0.250 |
| B:v1.0.250 | setup | **PASS** | http 200 |
| B:v1.0.250 | enforcement:predecessor | **PASS** | allowed=200 blocked=403 |
| B:v1.0.250 | predecessor-state-files | **PASS** | admin_settings.json audit.jsonl ca.bundle catfeeddb config_versions decryption_profiles.json fileprofiles.json hit_counters.json policy.json policy.json.meta proxy.log requests.jsonl saas_feed threatfeeds.json ui_users.j |
| B:v1.0.250 | boot-after-upgrade | **PASS** | version=dev |
| B:v1.0.250 | login-after-upgrade | **PASS** | http 200 |
| B:v1.0.250 | rules-after-upgrade | **PASS** | present |
| B:v1.0.250 | default-action-after-upgrade | **PASS** | deny |
| B:v1.0.250 | enforcement:after-upgrade | **PASS** | allowed=200 blocked=403 |
| B:v1.0.250 | ready-after-upgrade | **PASS** | ok |
| B:v1.0.250 | no-unexpected-errors | **PASS** | no panic/FATAL/corrupt lines in proxy log |
| C:v1.0.250 | older-binary-on-newer-state | **PASS** | boots; login=200 rules=yes default=deny (informational — downgrade is unsupported; restore-from-backup is the supported way back) |
| C:v1.0.250 | older-binary-warnings | **PASS** |  |
| B:v1.0.258 | boot-predecessor | **PASS** | version=v1.0.258 |
| B:v1.0.258 | setup | **PASS** | http 200 |
| B:v1.0.258 | enforcement:predecessor | **PASS** | allowed=200 blocked=403 |
| B:v1.0.258 | predecessor-state-files | **PASS** | admin_settings.json audit.jsonl ca.bundle catfeeddb config_versions decryption_profiles.json fileprofiles.json hit_counters.json policy.json policy.json.meta proxy.log requests.jsonl saas_feed threatfeeds.json ui_users.j |
| B:v1.0.258 | boot-after-upgrade | **PASS** | version=dev |
| B:v1.0.258 | login-after-upgrade | **PASS** | http 200 |
| B:v1.0.258 | rules-after-upgrade | **PASS** | present |
| B:v1.0.258 | default-action-after-upgrade | **PASS** | deny |
| B:v1.0.258 | enforcement:after-upgrade | **PASS** | allowed=200 blocked=403 |
| B:v1.0.258 | ready-after-upgrade | **PASS** | ok |
| B:v1.0.258 | no-unexpected-errors | **PASS** | no panic/FATAL/corrupt lines in proxy log |
| C:v1.0.258 | older-binary-on-newer-state | **PASS** | boots; login=200 rules=yes default=deny (informational — downgrade is unsupported; restore-from-backup is the supported way back) |
| C:v1.0.258 | older-binary-warnings | **PASS** |  |
| B:v1.0.259 | boot-predecessor | **PASS** | version=v1.0.259 |
| B:v1.0.259 | setup | **PASS** | http 200 |
| B:v1.0.259 | enforcement:predecessor | **PASS** | allowed=200 blocked=403 |
| B:v1.0.259 | predecessor-state-files | **PASS** | admin_settings.json audit.jsonl ca.bundle catfeeddb config_versions decryption_profiles.json fileprofiles.json hit_counters.json policy.json policy.json.meta proxy.log requests.jsonl saas_feed threatfeeds.json ui_users.j |
| B:v1.0.259 | boot-after-upgrade | **PASS** | version=dev |
| B:v1.0.259 | login-after-upgrade | **PASS** | http 200 |
| B:v1.0.259 | rules-after-upgrade | **PASS** | present |
| B:v1.0.259 | default-action-after-upgrade | **PASS** | deny |
| B:v1.0.259 | enforcement:after-upgrade | **PASS** | allowed=200 blocked=403 |
| B:v1.0.259 | ready-after-upgrade | **PASS** | ok |
| B:v1.0.259 | no-unexpected-errors | **PASS** | no panic/FATAL/corrupt lines in proxy log |
| C:v1.0.259 | older-binary-on-newer-state | **PASS** | boots; login=200 rules=yes default=deny (informational — downgrade is unsupported; restore-from-backup is the supported way back) |
| C:v1.0.259 | older-binary-warnings | **PASS** |  |
| D | backup | **PASS** | Backup written to /backup/qual.tar.gz.enc (encrypted, AES-256-GCM, PBKDF2-SHA256/600000) |
| D | mutation-visible | **PASS** | laterjoiner can log in before restore |
| D | commit-refused-while-running | **PASS** | lock held by the proxy |
| D | dry-run | **PASS** | validation passed incl. encrypted ca.bundle |
| D | commit | **PASS** |   Previous data preserved at: /data/.restore-bak.20261003T062658Z-1 |
| D | bak-inside-volume | **PASS** | previous data preserved inside the volume |
| D | boot-after-restore | **PASS** | version=dev |
| D | original-admin-restored | **PASS** | original admin logs in |
| D | later-mutation-rolled-back | **PASS** | post-backup account is gone |
| D | rules-restored | **PASS** | present |
| D | enforcement:after-restore | **PASS** | allowed=200 blocked=403 |
| D | ssl-inspection-ready | **PASS** | ssl_inspection=ready (restored ca.bundle decrypts under the install passphrase) |
| D | leftovers-listed | **PASS** | listed |
| D | leftovers-cleaned | **PASS** | deleted |
| E | boot-refused | **PASS** | status=running: interrupted restore detected: a restore commit in /data was interrupted in phase "promoting"  |
| E | inspect | **PASS** |   Phase:          promoting |
| E | recover-complete | **PASS** | completed |
| E | boot-after-recovery | **PASS** | version=dev |
| E | marker-landed | **PASS** | staged content promoted |
| E | login-after-recovery | **PASS** | admin logs in |
| E | enforcement:after-recovery | **PASS** | allowed=200 blocked=403 |
| G | backup | **PASS** | Backup written to /backup/qual.tar.gz.enc (encrypted, AES-256-GCM, PBKDF2-SHA256/600000) |
| G | data-footprint | **PASS** | used 164 KiB of 106420 KiB, 103636 KiB free 52	/data/config_versions 20	/data/catfeeddb 16	/data/lost+found 12	/data/yara  |
| G | volume-filled | **PASS** | filled: 4 KiB free of 106420 |
| G | refused-at-stage | **PASS** | Restore commit error: restore: stage failed: stage tarball data/ca.bundle: atomic write /data/.restore-staging.20261003T062848Z-1/ca.bundle: write: write /data/.restore-staging.20261003T062848Z-1/ca.b |
| G | no-journal-no-leftovers | **PASS** | no journal, no staging dir, no bak dir |
| G | data-untouched | **PASS** | content digest 7a5c859a9acaff94 unchanged |
| G | boot-after-refusal | **PASS** | version=dev |
| G | login-after-refusal | **PASS** | admin logs in |
| G | enforcement:after-refusal | **PASS** | allowed=200 blocked=403 |
| G | commit-after-space-freed | **FAIL** |  Network aq-g_default Creating   Network aq-g_default Created   Container aq-g-cli-run-b066af2be9a4 Creating   Container aq-g-cli-run-b066af2be9a4 Created  Restore plan (dry-run, --mode=full):  Backup metadata:   Source: |
| G | login-after-commit | **PASS** | admin logs in |
| X | clamav-real-sidecar | **BLOCKED** | ClamAV replaced by a stub (docker-compose.qualify.yml); the real sidecar's signature download cannot verify TLS behind this sandbox's intercepting proxy. Prerequisite: run on a host with direct egress and CULVERT_QUALIFY |

Failures: 1
