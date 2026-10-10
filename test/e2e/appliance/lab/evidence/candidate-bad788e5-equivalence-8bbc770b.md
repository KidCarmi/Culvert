# Candidate input equivalence: `bad788e54ffe` → `8bbc770b605c`

48 files differ; **0 are build inputs**.

No changed build input means a rebuild would consume the same source inputs. It is NOT a byte-identity claim (VCS stamp, commit-named OVA, build-time GeoLite/apt fetches). The qualified OVA is evidence for its own hash only.

| file | build input | reason |
|---|---|---|
| `.agents/skills/culvert-review/SKILL.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `.agents/skills/culvert-verify/SKILL.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `.claude/skills/culvert-review/SKILL.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `.claude/skills/culvert-verify/SKILL.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `.github/scripts/test/candidate-promotion-cases.sh` | no | .dockerignore .github; CI gating only (not one of the build workflows above) |
| `.github/workflows/pr-fast-gate.yml` | no | .dockerignore .github; CI gating only (not one of the build workflows above) |
| `AGENTS.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `CHANGELOG.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `CLAUDE.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/README.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/check.py` | no | not embedded, not copied by any build stage |
| `docs/agent-context/conventions.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/domains/admin-control-plane.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/domains/admission.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/errata.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/admin-control-plane.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/admission-and-connection-limits.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/architecture-index.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/authentication-and-identity.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/build-and-test.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/ci-and-release.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/cluster-and-ha.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/configuration-and-upstream.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/conventions.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/governance-and-roadmaps.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/mcp-gateway.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/observability-and-alerts.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/policy-category-feeds.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/policy-learning.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/project-map.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/proxy-tls-and-certificates.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/release-and-maintenance.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/run-and-environment.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/scanning.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/startup-shutdown-listeners.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/storage-and-durability.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/history/support-and-redaction.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/migration.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/preservation-map.json` | no | not embedded, not copied by any build stage |
| `docs/agent-context/research.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/routing-cases.json` | no | not embedded, not copied by any build stage |
| `docs/agent-context/workflows/review-change.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/agent-context/workflows/verification.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/appliance/readiness-report.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/appliance/sbom-cve-evidence.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `fast_gate_race_shards_test.go` | no | .dockerignore *_test.go; never compiled into a shipped binary |
| `internal/admission/AGENTS.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `internal/admission/CLAUDE.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
