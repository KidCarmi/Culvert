# Maintenance-agent update-flow qualification — run 20261003T063211Z

| artifact | reference |
|---|---|
| image under qualification | `culvert:ci-smoke` → `127.0.0.1:5055/culvert@sha256:e752cc38608d5f2e7e627081c6533b88cdef2f9bf0d008215d5c5032686f6c5b` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f` |
| agent | built from `cmd/culvert-maint` at cbe0f4c, privilege_mode=docker_group_lab (no systemd in this environment) |

| scenario | check | result | detail |
|---|---|---|---|
| F0 | seeded-predecessor | **PASS** | running v1.0.259 |
| F0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| F1 | apply-accepted | **PASS** | op=01M407E63DNFZZWDEJZ1XXRXWR http=202 |
| F1 | apply-succeeded | **PASS** | state=succeeded |
| F1 | running-is-target | **PASS** | 127.0.0.1:5055/culvert@sha256:e752cc38608d5f2e7e627081c6533b88cdef2f9bf0d008215d5c5032686f6c5b |
| F1 | state-preserved | **PASS** | admin login http 200 after upgrade |
| F2 | duplicate-deduped | **PASS** | http 200 01M407E63DNFZZWDEJZ1XXRXWR True |
| F5 | duplicate-after-agent-restart | **PASS** | http 200 01M407E63DNFZZWDEJZ1XXRXWR True |
| F3 | killed-mid-apply | **PASS** | SIGKILL at the restart stage of 01M407EEMFXKC9WGG3R1C0DWAM |
| F3 | reconcile-classified | **PASS** | attention_required=True interrupted=1 verdicts=[('01M407EEMFXKC9WGG3R1C0DWAM', 'reup', True)] |
| F3 | explicit-resolve-converged | **PASS** | http 202 resolve op=01M407EN3BTH7WSF64VK5TBCM1 running=127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| F3 | duplicate-resolve-refused | **PASS** | http 404 |
| F4 | rollback-accepted | **PASS** | op=01M407EXR12DKTPZK8S9D40NF3 (registry stopped) |
| F4 | rollback-succeeded-offline | **PASS** | state=succeeded |
| F4 | pull-skipped-local | **PASS** | rollback_pull: skipped (image present locally) |
| F4 | running-is-prior | **PASS** | 127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| F4 | state-preserved-after-rollback | **PASS** | http 200 |

Failures: 0
