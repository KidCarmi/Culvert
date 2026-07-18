# Culvert Content Standard

This is the authoring contract for every artifact produced by the Culvert
content foundation (documentation website, YouTube packages, administrator
training, product demonstrations, enterprise onboarding). It exists to keep the
content credible beside documentation from mature enterprise security vendors.

If a rule here conflicts with a draft, the rule wins.

---

## 1. Evidence-first authoring

Every material claim about Culvert's behavior must be traceable to product
evidence before it is written down. The accepted evidence hierarchy, strongest
first:

1. **Runtime implementation** — the Go source that executes the behavior.
2. **Automated test coverage** — a `_test.go` that asserts the behavior.
3. **Public API or configuration contract** — a route in `uiRoutes`, a handler,
   a documented config field, a CLI flag.
4. **Authoritative architecture decision** — an ADR under `docs/adr/`, or a
   frozen spec the code implements.
5. **Reproducible lab evidence** — a command run in this environment with its
   output captured.

Not evidence: `README` marketing lines on their own, code comments, `TODO`s,
issue text, roadmap documents, proposed designs, or "coming soon" fields.

Each content unit carries a **claim-evidence ledger** (`evidence.md` beside the
article, or an embedded section) mapping every material claim to a
`file:line`, test name, API route, ADR, or captured command.

## 2. Supported vs. planned

State only what is implemented today. When something is partial, planned, or
explicitly deferred in the code (`coming soon`, `not yet implemented`, a nil
provider path), say so plainly and mark it **Planned** or **Known limitation** —
never blur the line. The existing operator docs (e.g.
`docs/operator/decryption-profiles.md`) model this; match that honesty.

## 3. Audience

Write for **enterprise administrators and security engineers** evaluating,
deploying, or operating Culvert. Assume competence with TLS, HTTP proxying,
identity federation, and container operations. Do **not** assume any internal
Culvert knowledge — every Culvert-specific term is defined on first use.

## 4. Voice and structure

- Lead with what the reader can do and why it matters, not with history.
- One introduction per document. No repeated throat-clearing between sections.
- Prefer tables, ordered procedures, and concrete commands over prose.
- Use exact product terminology: **Decryption Profile**, **Control Plane**,
  **Data Plane**, **policy rule**, **default-deny**, **fail-open / fail-close**.
- Reference config fields, API routes, metrics, and files by their exact names.
- Every command must be copy-pasteable and correct for the shipped artifact
  (Docker image paths differ from binary-flag defaults — see the README note).

## 5. Prohibited

- Generic AI phrasing ("In today's fast-paced world…", "unlock the power of…").
- Unsupported superlatives, marketing claims without evidence.
- Unverified competitive comparisons or named-customer stories.
- Fabricated benchmarks, screenshots, or "we tested and it…" without a captured
  run.
- Concealing uncertainty. If evidence is incomplete, mark it and move on.

## 6. Documentation article shape

Where applicable, include: Purpose · Supported use cases · Prerequisites ·
Configuration procedure · Operational behavior · Security implications ·
Validation steps · Failure modes · Troubleshooting · Known limitations ·
Related documentation · Source evidence.

## 7. YouTube package shape

Include: Video objective · Target viewer · Expected viewer outcome · Title
options · Thumbnail brief · Full narration script · Demonstration plan · Exact
commands / UI actions · Lab prerequisites · Expected results · Failure &
recovery path · Chapter timestamps · Video description · Pinned comment ·
Related-doc placeholders · Short-form version · Claim-evidence ledger.

Never claim a demonstration was performed or show a synthetic screenshot unless
the run was actually reproduced in a lab and captured.

## 8. Diagrams

Represent diagrams as Mermaid so they render on the website and stay
diffable. Keep them faithful to the code paths they depict.

## 9. Verification before commit

Before committing a content unit, verify: Markdown formatting · links and
relative paths · commands · file names · config fields · API routes · product
terminology · supported-vs-planned accuracy · consistency with the current
codebase. Run whatever build/lint/link checks are available. Never weaken an
existing check to make content pass.

## 10. Terminology baseline

| Term | Definition |
|---|---|
| **SWG** | Secure Web Gateway — a policy-enforcing forward proxy for egress traffic. |
| **Control Plane (CP)** | The node that owns configuration and distributes it to Data Plane nodes over gRPC/mTLS. |
| **Data Plane (DP)** | A stateless proxy node that enrolls with the CP and applies pushed config snapshots. |
| **Policy rule** | A priority-ordered, first-match rule combining up to 8 condition types with an action and a TLS action. |
| **Default-deny** | Zero-Trust posture: traffic matching no rule is blocked. |
| **Decryption Profile** | A named, reusable "how to decrypt" object a policy rule references for TLS inspection behavior. |
| **TLS inspection (MITM)** | Opt-in interception that re-originates TLS using leaf certs signed by Culvert's internal CA. |
| **Adaptive decryption exclusion** | A bounded, volatile in-memory cache of hosts that could not be decrypted, used to fail open on subsequent CONNECTs when a profile opts in. |
