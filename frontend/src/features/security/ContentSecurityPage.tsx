// 2E-A — Content Security: the operational surface for the scan engines
// (ClamAV / YARA / DPI), threat intelligence, scan exclusions, and the scan
// verdict cache. SERVER TRUTH ONLY: every fact rendered here is a field the
// appliance reported; nothing is derived into "healthy/protected" language,
// and enum-ish strings the client does not recognize render verbatim with an
// unrecognized posture. Manual Refresh is the operational model (ADR-FE-002).
//
// Scope fences (2E decomposition): Decryption operations (health, redaction,
// auto-exclusions) belong to 2E-B; CDR/Sluice belongs to 2E-C; Decryption
// Profiles CRUD stays on Objects → Decryption Profiles (2D-A). None of that
// is duplicated here.
import { useState, type JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import { Button } from "../../design-system/primitives";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { OverviewTab } from "./OverviewTab";
import { ThreatIntelTab } from "./ThreatIntelTab";
import { YaraTab } from "./YaraTab";
import { DpiTab } from "./DpiTab";
import { ExclusionsCacheTab } from "./ExclusionsCacheTab";
import styles from "../policy/policy.module.css";

const TABS = [
  "Overview",
  "Threat Intelligence",
  "YARA",
  "DPI",
  "Exclusions & Cache",
] as const;
type Tab = (typeof TABS)[number];

export function ContentSecurityPage(): JSX.Element {
  const [tab, setTab] = useState<Tab>("Overview");
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  const isOperator = hasRole(role, "operator");
  const isAdmin = hasRole(role, "admin");

  return (
    <>
      <PageHeader
        title="Content Security"
        subtitle="Scan engines, threat intelligence, YARA rules, DPI patterns, and scan exclusions — the appliance's reported state, refreshed on demand."
      />
      <div
        className={styles.toolbar}
        role="tablist"
        aria-label="Content Security sections"
      >
        {TABS.map((t) => (
          <Button
            key={t}
            size="sm"
            variant={t === tab ? "primary" : "ghost"}
            role="tab"
            aria-selected={t === tab}
            onClick={() => {
              setTab(t);
            }}
          >
            {t}
          </Button>
        ))}
      </div>
      {tab === "Overview" && <OverviewTab />}
      {tab === "Threat Intelligence" && <ThreatIntelTab isAdmin={isAdmin} />}
      {tab === "YARA" && <YaraTab isOperator={isOperator} isAdmin={isAdmin} />}
      {tab === "DPI" && <DpiTab isOperator={isOperator} isAdmin={isAdmin} />}
      {tab === "Exclusions & Cache" && <ExclusionsCacheTab isAdmin={isAdmin} />}
    </>
  );
}
