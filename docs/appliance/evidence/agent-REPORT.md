# Maintenance-agent update-flow qualification — run 20261002T200809Z

| artifact | reference |
|---|---|
| image under qualification | `culvert/proxy:dev-final` → `127.0.0.1:5055/culvert@sha256:e6a67d49974c3e0a1ee52e0c6edd4c2c6c7335a15a8acf5782a87f23e63cbbb4` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f` |
| agent | built from `cmd/culvert-maint` at a716c16, privilege_mode=docker_group_lab (no systemd in this environment) |

| scenario | check | result | detail |
|---|---|---|---|
| F0 | seeded-predecessor | **PASS** | running v1.0.259 |
| F0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| F1 | apply-accepted | **PASS** | op=01M3Z3PT92SRYTHZP517EG4WV4 http=202 |
| F1 | apply-succeeded | **PASS** | state=succeeded |
| F1 | running-is-target | **PASS** | 127.0.0.1:5055/culvert@sha256:e6a67d49974c3e0a1ee52e0c6edd4c2c6c7335a15a8acf5782a87f23e63cbbb4 |
| F1 | state-preserved | **PASS** | admin login http 200 after upgrade |
| F2 | duplicate-deduped | **PASS** | http 200 01M3Z3PT92SRYTHZP517EG4WV4 True |
| F5 | duplicate-after-agent-restart | **PASS** | http 200 01M3Z3PT92SRYTHZP517EG4WV4 True |
| F3 | killed-mid-apply | **PASS** | SIGKILL at the restart stage of 01M3Z3Q2WXVTCAAA5DJ84RYFCF |
| F3 | reconcile-classified | **PASS** | attention_required=True interrupted=1 verdicts=[('01M3Z3Q2WXVTCAAA5DJ84RYFCF', 'reup', True)] |
| F3 | explicit-resolve-converged | **PASS** | http 202 resolve op=01M3Z3Q9BRFVQVDJ0JZE69JA9C running=127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| F3 | duplicate-resolve-refused | **PASS** | http 404 |
| F4 | rollback-accepted | **PASS** | op=01M3Z3QM042XQ687A0Y1XZ7S35 (registry stopped) |
| F4 | rollback-succeeded-offline | **PASS** | state=succeeded |
| F4 | pull-skipped-local | **PASS** | rollback_pull: skipped (image present locally) |
| F4 | running-is-prior | **PASS** | 127.0.0.1:5055/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| F4 | state-preserved-after-rollback | **PASS** | http 200 |

Failures: 0
