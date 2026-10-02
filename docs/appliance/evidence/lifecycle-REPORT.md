# Appliance lifecycle qualification — run 20261002T193353Z

| artifact | reference | digest / image id |
|---|---|---|
| image under qualification | `culvert/proxy:dev-final` | `127.0.0.1:5055/culvert@sha256:e6a67d49974c3e0a1ee52e0c6edd4c2c6c7335a15a8acf5782a87f23e63cbbb4|sha256:e6a67d49974c3e0a1ee52e0c6edd4c2c6c7335a15a8acf5782a87f23e63cbbb4` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.250` | `ghcr.io/kidcarmi/culvert@sha256:a754b94bb61aba717e1f6123906b924bc8a9fb830ee522b903fa1a8daab044ee|sha256:a754b94bb61aba717e1f6123906b924bc8a9fb830ee522b903fa1a8daab044ee` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.258` | `ghcr.io/kidcarmi/culvert@sha256:ffc9ab99d43566dee5dfcb7d3b7b24de22c21abd6b561e350c4aec6844dca2fc|sha256:ffc9ab99d43566dee5dfcb7d3b7b24de22c21abd6b561e350c4aec6844dca2fc` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` | `127.0.0.1:5055/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e|sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e` |
| docker | 29.6.2 | compose 5.3.1 |
| host | Linux 6.18.44-fc-v51 | 4 cpu |

## Checks

| scenario | check | result | detail |
|---|---|---|---|
| A | boot | **PASS** | version=1e9e051 |
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
| B:v1.0.250 | boot-after-upgrade | **PASS** | version=1e9e051 |
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
| B:v1.0.258 | boot-after-upgrade | **PASS** | version=1e9e051 |
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
| B:v1.0.259 | boot-after-upgrade | **PASS** | version=1e9e051 |
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
| D | commit | **PASS** |   Previous data preserved at: /data/.restore-bak.20261002T193604Z-1 |
| D | bak-inside-volume | **PASS** | previous data preserved inside the volume |
| D | boot-after-restore | **PASS** | version=1e9e051 |
| D | original-admin-restored | **PASS** | original admin logs in |
| D | later-mutation-rolled-back | **PASS** | post-backup account is gone |
| D | rules-restored | **PASS** | present |
| D | enforcement:after-restore | **PASS** | allowed=200 blocked=403 |
| D | ssl-inspection-ready | **PASS** | ssl_inspection=ready (restored ca.bundle decrypts under the install passphrase) |
| D | leftovers-listed | **PASS** | listed |
| D | leftovers-cleaned | **PASS** | deleted |
| E | boot-refused | **PASS** | status=restarting: interrupted restore detected: a restore commit in /data was interrupted in phase "promoting"  |
| E | inspect | **PASS** |   Phase:          promoting |
| E | recover-complete | **PASS** | completed |
| E | boot-after-recovery | **PASS** | version=1e9e051 |
| E | marker-landed | **PASS** | staged content promoted |
| E | login-after-recovery | **PASS** | admin logs in |
| E | enforcement:after-recovery | **PASS** | allowed=200 blocked=403 |
| X | clamav-real-sidecar | **BLOCKED** | ClamAV replaced by a stub (docker-compose.qualify.yml); the real sidecar's signature download cannot verify TLS behind this sandbox's intercepting proxy. Prerequisite: run on a host with direct egress and CULVERT_QUALIFY |

Failures: 0
