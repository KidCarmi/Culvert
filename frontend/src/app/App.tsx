import type { JSX } from "react";

// FE-1A hello shell. This is NOT the production UI — it exists only to prove
// the platform (strict TS, lint bans, deterministic CSP-clean build, embed
// readiness). Feature work begins in later slices per
// docs/design/FRONTEND-MIGRATION-PLAN.md.
export function App(): JSX.Element {
  return (
    <main className="foundation">
      <h1 className="foundation-title">CULVERT</h1>
      <p className="foundation-subtitle">Frontend Platform Foundation</p>
    </main>
  );
}
