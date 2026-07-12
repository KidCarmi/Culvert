# Production Readiness Checklist (Go-Live Gate)

Every row must be **Pass** (or a consciously accepted, documented risk) before production cutover. Columns: **Requirement · Validation method · Required evidence · State · Blocker severity if failed · Owner · Rollback plan.**

State: ☐ Pass · ☐ Fail · ☐ Accepted-risk. Blocker severity references the [Gap Register](../engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md).

---

## Network

| Requirement | Validation | Evidence | Severity if failed | Owner | Rollback |
|---|---|---|---|---|---|
| Inbound ports (8080/9090, +1080/50051 if used) reachable only from intended sources | `nmap`/curl from client + admin nets; host firewall review | firewall rules; `-ui-allow-ip` set | P1 | Network | tighten firewall |
| Admin UI restricted to management net | curl :9090 from non-mgmt net = blocked | `ui_allow_ips` + firewall | P1 | Network | — |
| Outbound egress reviewed & approved | egress log; `CULVERT_RELEASE_CATALOG_URL` decision | approved allowlist | P2 (GAP-NET-01/02) | Security | set `=off` |
| Load balancer health checks wired | LB routes only to `/ready`=200 / `/healthz`=200 nodes | LB config | P2 | Network | — |

## DNS / NTP / Time

| DNS records (appliance, VIP, CP/DP, IdP) resolve | `dig` from the host | resolution output | P2 | Network | — |
| NTP sync healthy (skew < 30s) | `chronyc tracking` **[HOST]** | tracking output | P1 (SSO/TLS) | Platform | — |
| Timezone set (`TZ`) | `/health` timestamps | env | P3 | Platform | — |

## PKI / TLS inspection

| Inspection CA generated & `ca.bundle` backed up | `/health` `ssl_inspection: ready`; backup exists | health + backup | P1 | PKI | restore bundle |
| CA passphrase in a secret store | `.env`/secret review | — | P1 | Security | — |
| Root CA distributed to endpoints | pilot endpoint browses inspected site cleanly | endpoint trust proof | P1 | Endpoint | remove trust |
| Bypass list covers pinned/banking/mTLS | `/api/ssl-bypass` review | bypass list | P2 (GAP-PKI-06) | Security | add bypass |
| `cert_expiry` alert + external expiry monitor | webhook test; `/api/ca/status` monitored | alert config | P2 (GAP-PKI-05) | Ops | — |
| BYO-CA caveats understood (ECDSA-only, non-persistent, rotation-clobber) | decision recorded | sign-off | P1 (GAP-PKI-01/02/03) | PKI | use auto-CA |

## Authentication

| ≥2 admin accounts provisioned | Auth → Users | roster | **P1 (GAP-IAM-01)** | Security | — |
| TOTP enabled for admins | account settings | — | P2 | Security | — |
| Admin UI restricted + firewalled during/after setup | setup done before exposure | — | P2 (GAP-APP-04) | Security | — |
| Proxy IdP profiles tested & fail-closed | built-in test action | test result | P1 | IdP | disable profile |
| `proxy.base_url` set before SSO enabled | config | — | P1 | IdP | — |
| Break-glass documented (host-exec + `--reset-password` + backup) | runbook present; access retained | sign-off | **P1 (GAP-IAM-01)** | Ops | — |

## Authorization / Policy

| `default_action: deny` set (Zero Trust) | `/api/default-action` = deny | config | P1 | Security | rollback |
| Policy validated via Policy Tester | tester output for key cases | screenshots | P2 | Security | — |
| Pilot scoped by IP/IdP-group; monitored before enforce | pilot rules reviewed | pilot plan | P1 (GAP-POL-01/02) | Security | rollback |
| Config snapshot taken before cutover | Config Versions list | version id | P2 | Ops | rollback |

## Logging / Monitoring

| Persistent audit on (`-audit-log`) | `/api/audit?source=file` returns file data | — | P2 (GAP-IAM-04) | Ops | — |
| Syslog/SIEM forwarding live | SIEM receives events; `/api/syslog` test | SIEM screenshot | P2 | SecOps | — |
| Prometheus scraping + `/metrics` token set | target up in Prometheus | scrape config | P3 (GAP-MON-03) | Ops | — |
| Dashboard/alerts wired | Grafana panels populated | dashboard | P3 | Ops | — |
| Support-evidence procedure documented (no bundle) | runbook §Log collection | — | P2 (GAP-MON-01) | Ops | — |

## Backups / Restore

| Encrypted backup runs & copied off-host | `--backup --encrypt` output; off-host copy | archive listing | **P1 (GAP-BAK-01/02)** | Ops | — |
| Backup schedule (cron) in place | cron entry **[HOST]** | crontab | P2 (GAP-BAK-02) | Ops | — |
| Restore dry-run passes | `--restore` (no `--confirm`) = PASS | validation output | P1 | Ops | — |
| Restore rehearsed on staging | staging boots from prod backup | rehearsal notes | P2 (GAP-BAK-03) | Ops | — |
| Host-access break-glass retained for restore | access confirmed | sign-off | P1 (GAP-BAK-01) | Ops | — |

## Updates / Rollback

| Maintenance agent installed & reachable | Release panel not "Agent unreachable" | screenshot | P2 (GAP-UPD-04) | Ops | — |
| `compose_override_file` wired (socket survives recreate) | agent config review | — | P2 (GAP-UPD-04) | Ops | — |
| Update trust posture confirmed (enforce) | `/api/releases` verify_mode | screenshot | P1 | Security | — |
| Air-gap update path decided (if restricted) | decision recorded | sign-off | P1 (GAP-UPD-01) | Security | — |
| Rollback tested (auto + manual `/v1/rollbacks`) | test on staging | notes | P1 (GAP-UPD-02) | Ops | — |

## Capacity / Recovery

| Sizing validated against workload | load test | results | P2 | Platform | scale out |
| HA posture decided (etcd fencing for auto-failover) | `/api/cluster/ha` | config | P2 | Platform | manual promote |
| Disk-loss DR procedure documented & rehearsed | runbook §Disk-loss | notes | P2 (GAP-BAK-04) | Ops | — |
| Operational handoff complete (runbook + drills) | operators execute 6 core drills | sign-off | P1 | Ops | — |

## Security validation

| Security review of egress, TLS, RBAC, secrets-at-rest | review record | sign-off | P1 | Security | — |
| `/data` secrets encrypted at rest (CA passphrase, log passphrase) | env review; `/health` | — | P1 | Security | — |
| No `--cluster-insecure` in production | Diagnostics `cluster_posture` = ok | screenshot | P1 | Security | re-issue mTLS |

---

## Go-live decision

Cutover is authorized only when: every **P1** row is Pass or a signed Accepted-risk with a named owner and mitigation; the six core operator drills (health, config rollback, backup, restore dry-run, admin recovery, upgrade+rollback) have been executed successfully; and a current encrypted off-host backup exists. Record the decision, the accepted risks, and the rollback plan owner.
