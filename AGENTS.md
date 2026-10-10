# Culvert contributor guide

Culvert is a Go HTTP/HTTPS/SOCKS5 forward proxy and security gateway. This is
shared, current task guidance. `CLAUDE.md` is a compatibility adapter.

## Establish the contract before changing it

- Inspect the checked-out revision, dirty worktree, relevant callers and tests.
  Preserve unrelated work. Do not mix an unmerged branch's behavior into main.
- Evidence order: source → tests → CI → configuration → deployment → prose.
  Flag conflicts; do not change runtime behavior just to match stale prose.
- Keep domain state/logic and white-box tests in cohesive `internal/<domain>`
  owners. Main owns startup, concrete wiring, HTTP/config/transport adapters and
  cross-domain integration. Inject dependencies; do not create a generic app hub
  or export mutable internals to keep a root test. Record new boundaries per
  [package isolation](roadmap/PACKAGE-ISOLATION.md) and the relevant ADR.
- Preserve security posture, persistence/wire compatibility, cancellation and
  shutdown ownership. Fail-open/fail-closed is domain-specific, not a slogan.
  For example, empty configured default action allows with zero rules, denies
  with rules; explicit configuration wins. See [errata](docs/agent-context/errata.md).
- For implementation, use [current conventions](docs/agent-context/conventions.md)
  as relevant: contextual I/O, SSRF/log sanitization, immutable publication,
  approved GUI/configuration exceptions, and global-test cleanup.

## Read the applicable guidance, not the entire archive

Before editing a subsystem, inspect any `AGENTS.md` between repository root and
that directory. A root-started Codex session must explicitly read descendants;
do not assume editing a nested file automatically loads them. Claude adapters
import the matching shared guide. For root-level adapters, use the semantic
routes below even though no directory boundary is crossed. Follow every route
whose contract the change affects; filename matches are examples, not an exhaustive filter.

- Core IP filtering/rate limiting: `internal/admission`, `admission.go`,
  `security.go`, `cluster_ratelimit*`, snapshot/startup/config-restore callers →
  [admission contract](docs/agent-context/domains/admission.md) and
  [scoped guide](internal/admission/AGENTS.md). `internal/connlimit` is a separate owner.
- Admin routes/RBAC/auditing/config surfaces: `ui*.go`, `cdr_ui.go`, `pac.go`,
  `diagnostics.go`, `store.go`, `configversion.go`, `static/index.html` →
  [admin control plane](docs/agent-context/domains/admin-control-plane.md).
- Credentials, sessions, IdPs, TOTP or roster writes, including mutations in
  `store.go` → [authentication](docs/agent-context/README.md#authentication-and-identity).
- Proxy, destination parsing, TLS, CA, OCSP, DNS, policy/category/threat feeds →
  [proxy/security routes](docs/agent-context/README.md#proxy-policy-and-scanning).
- Startup, optional listeners, shutdown/drain, persistence, audit/log queues,
  metrics, alerts, support/redaction → [lifecycle and storage](docs/agent-context/README.md#lifecycle-storage-and-observability).
- Cluster/HA, configuration/upstream, releases/install/maintenance or CI →
  [configuration and delivery](docs/agent-context/README.md#configuration-cluster-and-delivery).
- React frontend or legacy UI → [frontend route](docs/agent-context/README.md#frontend).
- MCP or policy learning → [MCP and learning](docs/agent-context/README.md#mcp-and-policy-learning).
  MCP listener fairness and execution admission are not the core IP limiter.
- Architecture advice, unknown ownership or cross-domain work →
  [full task index](docs/agent-context/README.md) and relevant ADRs. The
  [Engineering Constitution](docs/engineering/ENGINEERING-CONSTITUTION.md)
  defines the advisory role; its persona does not replace an implementation task.

Historical incident narratives, measurements, rejected alternatives and original
rules remain losslessly mapped in [history](docs/agent-context/README.md#historical-source-inventory).
Read relevant topics when their failure mode matters. Do not load every history
file, treat old measurements as current results, or dismiss a critical contract
merely because its rationale is historical. Verify it in the current owner/tests.

## Verification and review

- Choose checks from changed behavior and current `go.mod`, Makefile and CI.
  The `toolchain` line is the compiler; `go` is the language minimum. Do not
  override workflow `GOTOOLCHAIN` or weaken a gate to obtain a pass.
- For nontrivial code, behavior or instruction-routing changes, use the
  `culvert-verify` skill, or read [verification](docs/agent-context/workflows/verification.md)
  directly when skills are unavailable. Run focused checks while iterating;
  distinguish them from full module/aggregate CI results for the exact SHA.
- For an explicit review or readiness assessment, use `culvert-review`, or read
  [review-change](docs/agent-context/workflows/review-change.md). Trace relevant
  callers, concurrency, lifecycle and error paths beyond the diff.
- Review findings need a concrete supported failure scenario, affected contract,
  file/line evidence and impact. Prioritize security, compatibility, ownership,
  durability and test gaps. Avoid speculative, style-only or duplicate lint findings.
  Existing deliberate exceptions (for example stale remote counts falling back to
  local limiting, or permanent root aliases) are not automatically defects.
- Parallelize independent investigations when useful, with source paths and
  bounded questions. Avoid competing writers. Inspect critical evidence yourself;
  a worker summary or an agent's confidence is not verification.
- Report changed scope, commands/results, checks not run and why, and remaining
  risks. A passing local check is not a passing hosted review or merge gate.
  Instructions/skills do not grant permission to push, post, merge or deploy.

## Maintain this guidance

Put durable contracts beside their owner and executable tests, repeatable
procedures in shared workflows, and incident chronology in history. Update this
root only for universal guidance or changed routes. For instruction changes run
`python3 docs/agent-context/check.py`, use realistic positive/negative retrieval
cases, and obtain an independent pass. The [migration record](docs/agent-context/migration.md)
explains preservation, branch reconciliation and actual validation limits.
