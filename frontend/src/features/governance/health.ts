// Governance health badge mapping (Codex review fix, PR #1194): the
// backend's TOP-LEVEL governance_health.status vocabulary is
// "healthy" | "warn" | "drift" (ui_governance.go statusHealthy/Warn/Drift);
// "ok" exists only in the per-AXIS fields. A healthy appliance must render
// the success badge — an unknown future value degrades to warn (visible,
// never silently green).
import type { Status } from "../../design-system/primitives";

export function governanceHealthBadgeStatus(health: string): Status {
  if (health === "healthy") return "ok";
  if (health === "drift") return "critical";
  return "warn";
}
