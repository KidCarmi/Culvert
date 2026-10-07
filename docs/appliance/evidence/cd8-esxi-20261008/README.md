# cd8 ESXi evidence — 2026-10-08

This directory contains the reviewed, sanitized evidence for [the integrated report](../../esxi-cd8-20261008.md). `SHA256SUMS` binds every payload's exact published bytes. Raw console captures, credentials, tokens, signing keys, transport contents and unrelated ESXi inventory remain private. Only five individually reviewed screenshots are public.

**Subsequent integration finding:** cd8 was superseded after a real browser SAML callback failed in the source-level replay. The [independent follow-up](integration-followup.md) verifies the pre-fix/fixed artifact bindings. The integrated report records the fixed source and new login-CSRF finding. Original ESXi and closeout snapshot evidence below remains historical; none of its passes transfers to a replacement OVA.

The tested OVA SHA256 is `46cb60078eb2adbc2f8704046268f68e56798bc2b37cd824ba70f8a919bd2ab1`, source `cd8e44505bd329e5de675592ad4c23f92a534d55`. Main lifecycle/measurement execution used `7acb405c`; final identity observation, source deletion and fresh recovery used separately frozen `bf4ff824`. The integrated report provides full controller identities and manifests. Copied orchestration scripts are evidence of the exact invocation logic; use the frozen controller and its scope, not these report copies, for execution.

Three maintenance recoveries, backup availability, both P1 regressions, scanner outage/recovery, authenticated source-absent application restore and the listed visual checks pass. Original pre-authentication decoder failures, capture gaps, F2 input uncertainty and the first truncated sampler verdict remain recorded alongside tightly bound continuations. The retained VM console was returned to its read-only public menu after recovery; the UI still truthfully distinguishes local checks from externally verified traffic.

[Production closeout](production-closeout.md) and [security dispositions](security-dispositions.json) retain the unresolved adopted-image scan, live IdP replay and historical-log recovery requirements. No merge, release or risk acceptance is implied.
