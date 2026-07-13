# ADR-0017: Local bundle queue, resumable retry, and offline export

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0014 (outbound-only), ADR-0015 (cloud independence). Basis: `docs/support/SECURE-UPLOAD-ARCHITECTURE.md §5-6`.

## Context
Cloud-first analysis must not create a stall or data loss when the cloud is slow, unreachable, or absent (including permanently, for air-gapped customers). The appliance already models this pattern elsewhere (DP last-known-good config, alert retry loop).

## Decision
A generated bundle that cannot be uploaded is **queued locally** and retried on the appliance's own outbound schedule with bounded, jittered exponential backoff; uploads are **resumable** from the last acknowledged chunk offset (idempotent per-offset PUTs). The queue is persisted under `<dataDir>/support` and survives restart. **Offline export** (write the encrypted bundle to disk/media for manual transfer) is always available regardless of cloud reachability and is the primary path for air-gapped customers. Retry/queue runs as a bounded background op that never blocks the proxy hot path and never holds the collection single-flight lock. Repeated failure ends in a `deferred` state the operator can re-arm or offline-export — never an unbounded loop.

Enforced by `TestUploadResumable`, `TestBundleQueuePersistsRestart`, `TestOfflineExportAirGapped`, `TestBundleBudgetsEnforced` (queue respects disk/retention).

## Consequences
**Positive:** no data loss or stall on cloud outage; air-gapped customers are first-class; the customer's network variability never affects support reliability or the proxy.
**Negative:** a persisted queue consumes bounded local disk (governed by preflight + retention janitor).
**Neutral:** resumability requires the gateway to accept offset-addressed idempotent chunks (a cloud-side contract).

## Alternatives considered
- **Fail the bundle if upload fails.** Rejected: loses collected evidence and forces recollection; queue+retry is cheap and safer.
- **Unbounded retry.** Rejected: a permanently-unreachable cloud would loop forever; bounded backoff → `deferred` + offline export is the safe terminal.
