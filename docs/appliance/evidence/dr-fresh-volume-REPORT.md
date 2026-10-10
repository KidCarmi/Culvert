# Appliance lifecycle qualification — run 20261003T104730Z

| artifact | reference | digest / image id |
|---|---|---|
| image under qualification | `culvert/proxy:dev-r3b` | `127.0.0.1:5055/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1|sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` | `127.0.0.1:5055/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e|sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e` |
| docker | 29.6.2 | compose 5.3.1 |
| host | Linux 6.18.44-fc-v64 | 4 cpu |

## Checks

| scenario | check | result | detail |
|---|---|---|---|
| R | original-ca | **PASS** | root CA sha256 5C:94:B7:7A:49:65:01:AD:10:D6:08:16:CC:3A:8C:2B:44:4E:4D:BF:E0:44:14:BD:FD:B3:30:7C:67:9D:CD:80 |
| R | backup | **PASS** | Backup written to /backup/dr.tar.gz.enc (encrypted, AES-256-GCM, PBKDF2-SHA256/600000) |
| R | escrowed | **PASS** | archive 10087 bytes + .env held off-box |
| R | original-gone | **PASS** | data and backup volumes of aq-r1 removed |
| R | new-install-unclaimed | **PASS** | fresh install up, no admin roster (wizard not completed) |
| R | root-ca-guard | **PASS** | refused without --accept-root-ca-change: Restore commit error: restore: the inspection root CA (ca.bundle) would be replaced; every client trusting the current root loses inspected HTTPS. Pass --accept |
| R | restore-commit | **PASS** | Restore committed. |
| R | boot-after-dr | **PASS** | version=dev |
| R | admin-recovered | **PASS** | original admin logs in on the new appliance |
| R | ca-identity-recovered | **PASS** | root CA sha256 5C:94:B7:7A:49:65:01:AD:10:D6:08:16:CC:3A:8C:2B:44:4E:4D:BF:E0:44:14:BD:FD:B3:30:7C:67:9D:CD:80 (same root: clients keep trusting it) |
| R | ssl-inspection-ready | **PASS** | ssl_inspection=ready (ca.bundle decrypts under the escrowed passphrase) |
| R | rules-recovered | **PASS** | present |
| R | default-deny-recovered | **PASS** | deny |
| R | enforcement:after-dr | **PASS** | allowed=200 blocked=403 |
| X | clamav-real-sidecar | **BLOCKED** | ClamAV replaced by a stub (docker-compose.qualify.yml); the real sidecar's signature download cannot verify TLS behind this sandbox's intercepting proxy. Prerequisite: run on a host with direct egress and CULVERT_QUALIFY |

Failures: 0
