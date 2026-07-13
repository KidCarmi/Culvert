# Failure-Injection Matrix — Results

| # | Scenario | Persisted state | Recovery |
|--|--|--|--|
| 1 | chat disconnect during planning | `REVIEW_PENDING` | reconnect via get_operation; plan intact |
| 2 | chat disconnect during execution | `VALIDATING` | op continues in executor; reconnect resumes |
| 3 | duplicate execution request | `same_op` | idempotency UNIQUE; dup returned existing (True) |
| 4 | stale approval | `APPROVAL_PENDING` | execute rejected: REJECTED:approval expired |
| 5 | plan changes after approval | `APPROVAL_PENDING` | execute REJECTED:approval/plan mismatch (pidA=PLAN-564358adf9a3 != pidB=PLAN-1b91f13080d5); re-approval required |
| 6 | policy rejection (unapproved digest) | `POLICY_REJECTED` | rejected rules=P4 |
| 7 | executor crash before provider call | `FAILED` | reconciler: resolved->FAILED |
| 8 | executor crash after provider call | `VALIDATING` | reconciler read provider truth: resumed->VALIDATING |
| 9 | partial provider success | `ROLLED_BACK` | reverse-deploy -> ROLLED_BACK |
| 10 | validation failure | `ROLLED_BACK` | auto rollback -> ROLLED_BACK |
| 11 | rollback failure / prev image gone | `MANUAL_INTERVENTION_REQUIRED` | -> MANUAL (human via tacctl) |
| 12 | concurrent op on same worker | `second_blocked` | per-worker apply lease serializes; B waits |
| 13 | malicious log prompt injection | `inert` | no run_arbitrary_* tool; L3 needs human approval; worst case = a rejected/low-impact proposal, audited |
| 14 | expired credentials mid-apply | `FAILED` | re-mint + safe re-apply; reconciler: resolved->FAILED |
| 15 | provider unavailable | `FAILED` | FAILED cleanly; retry same saved plan later |
| 16 | AI unavailable | `SUCCEEDED` | tacctl-only; platform fully operable without AI |
