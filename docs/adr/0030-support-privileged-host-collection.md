# ADR-0030: Privileged host/container collection via the maintenance agent (read-only `/v1/collect`)

- **Status:** Accepted — implemented (shipped as part of appliance track M0–M5; see `docs/support/SUPPORTABILITY-ROADMAP.md`)
- **Date:** 2026-07-12
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (ratified through shipped implementation)
- **Relates to:** ADR-0028 (bundle framework), the maintenance-agent design (`roadmap/D1.6-maintenance-agent-design.md`), the P1.4 pin-binding sudoers model. Full design in `docs/support/SUPPORTABILITY-ARCHITECTURE.md §6`.

## Context

A support bundle needs host/container facts — compose state, container/system logs, disk usage, image identity, clock — but the appliance's core promise is that customers do **not** get OS/shell access. The proxy process has no host visibility and no `exec` (the only production `exec.Command` is in the maintenance agent's runner). The maintenance agent already provides a hardened, shell-free privileged surface: UDS-only (`0660`), `SO_PEERCRED` UID allowlist, a **fixed argv template registry** (never operator input), no `sh -c`, a closed env allowlist, sudoers scoped per-command with no wildcards, and per-op ULID audit. It also demonstrates the key hazard: raw `docker inspect --format {{json .Config.Env}}` / `docker logs` would leak CA passphrase, session HMAC, and IdP secrets as root — which is why the sudoers file already enumerates only `inspect --format {{json .Image}}`.

Giving the proxy host access, or adding a second privileged daemon, would both enlarge the attack surface unnecessarily.

## Decision

Extend the **existing maintenance agent** with a **read-only `POST /v1/collect`** operation. No new privileged process; no host access for the proxy.

1. **Read-only, allowlisted templates only:** `compose ps`, `compose logs --no-color --tail=N` (bounded), `df`/`stat` on the data volume, `inspect --format {{json .Image}}` (reusing the existing whitespace-safe enumerated pattern), `date -u`, `uname`. **No** `--format {{json .Config.Env}}`, **no** arbitrary path, **no** state-changing verb.
2. **Redaction at the agent boundary:** logs and inspect output are field-allowlisted / line-scrubbed (env `KEY=…`, auth headers, tokens, passphrases, PEM blocks) **before** they are ever written to an op log or returned — generalizing the parse-only `capture_running.go` pattern. The proxy re-runs the result through `internal/redaction` before writing the section.
3. **Bounded & audited:** per-call byte cap (`boundedBuffer`), time budget, single-flight lock, ULID op id, per-op audit with peer identity — reusing the existing op machinery.
4. **Sudoers additions follow the project's four-step contract:** narrowly enumerated, whitespace-safe, no wildcards, reviewed as security-critical, no state-changing command added. A sudoers-diff CI check gates any change.
5. **Graceful degradation:** if the agent is absent or the runtime is not Compose, the host section is `unavailable` with a reason — the bundle still generates.

## Consequences

**Positive**
- Host facts become collectable **without** exposing Docker/Linux to the customer or the proxy, satisfying the hard constraint "must not require unrestricted Docker/Linux access."
- The blast radius stays exactly where it already is (the audited agent), with only read-only additions.
- The `docker inspect`/`logs` secret-leak vector is closed by construction (allowlisted formats + agent-side scrub), not by hope.

**Negative / cost**
- New sudoers entries are the highest-scrutiny change in the program; each requires security review and a CI diff-gate. Adding container/system-log reads specifically must be justified per incident scope, not blanket-enabled.
- Agent-side redaction is a second redaction locus; mitigated by re-redacting in the proxy and by testing the agent scrubber against planted secrets.

**Neutral**
- The agent gains one read-only verb; its 13→14 endpoint surface stays UDS+peercred-gated (even the 404 path is authenticated).

## Alternatives considered

1. **Give the proxy the docker socket / host mounts.** Rejected: catastrophic attack-surface increase; the proxy is internet-adjacent.
2. **A dedicated support daemon.** Rejected: a second privileged process to secure; the agent already solves the hard parts.
3. **Collect only in-process state, no host facts.** Rejected as insufficient for disk-exhaustion / crash-loop / container-state incidents — but this **is** the fallback when the agent is unavailable (degraded bundle, P5).
4. **Ship a support shell/`kubectl exec`-style escape hatch for TAC.** Rejected outright — violates the no-shell rule; remote support (if ever built) is per-command allowlisted, not a shell (ADR-0031 / SECURE-UPLOAD §remote).
