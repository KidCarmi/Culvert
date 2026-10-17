# Maintenance-agent update-flow qualification — run 20261003T065216Z

| artifact | reference |
|---|---|
| image under qualification | `culvert/proxy:dev-r3b` → `127.0.0.1:5055/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f` |
| agent | built from `cmd/culvert-maint` at a4d977e, privilege_mode=docker_group_lab (no systemd in this environment) |

| scenario | check | result | detail |
|---|---|---|---|
| F0 | seeded-predecessor | **PASS** | running v1.0.259 |
| F0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| F1 | apply-accepted | **PASS** | op=01M408J7NYG1KCP090MAX16V3N http=202 |
| F1 | apply-succeeded | **PASS** | state=succeeded |
| F1 | running-is-target | **PASS** | 127.0.0.1:5055/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1 |
| F1 | state-preserved | **PASS** | admin login http 200 after upgrade |
| F2 | duplicate-deduped | **PASS** | http 200 01M408J7NYG1KCP090MAX16V3N True |
| F5 | duplicate-after-agent-restart | **PASS** | http 200 01M408J7NYG1KCP090MAX16V3N True |
| F3 | killed-mid-apply | **PASS** | SIGKILL at the restart stage of 01M408JG5T3PWR6PP6BABFF92J |
| F3 | reconcile-classified | **PASS** | attention_required=True interrupted=1 verdicts=[('01M408JG5T3PWR6PP6BABFF92J', 'reup', True)] |
| F3 | explicit-resolve-converged | **PASS** | http 202 resolve op=01M408JPNMJ8DFK95THVC5E94W running=127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| F3 | duplicate-resolve-refused | **PASS** | http 404 |
| F4 | rollback-accepted | **PASS** | op=01M408K19CRZ6NEV9ZWS1C8N6Q (registry stopped) |
| F4 | rollback-succeeded-offline | **PASS** | state=succeeded |
| F4 | pull-skipped-local | **PASS** | rollback_pull: skipped (image present locally) |
| F4 | running-is-prior | **PASS** | 127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| F4 | state-preserved-after-rollback | **PASS** | http 200 |

Failures: 0
