// 2E-C — CDR / Sluice Integration: the management surface for the Content
// Disarm & Reconstruction engine — runtime enablement, the enrolled-instance
// TRUST registry, CDR policy rules, and the admin test harness.
//
// SERVER TRUTH ONLY (§1): nothing here derives "Protected / Sanitized / Safe"
// claims; every state keeps its real scope distinct — configured vs enabled,
// enrolled vs credentialed vs trusted, reachable vs healthy, "last test
// passed" vs "production path healthy" — and unknown values render verbatim.
// EVERYTHING on this page is NODE-LOCAL (outside export/import, rollback,
// and CP→DP sync — recorded backend posture).
//
// Scope fences: Content Security (2E-A) and Decryption (2E-B) have their own
// pages; certificate management is not built here. This page links, never
// duplicates. Sections follow the ACTUAL contract (§13): the runtime-mutable
// configuration is ONE boolean, so it lives on Overview & Health rather than
// forcing a separate Configuration tab.
import { useState, type JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import { Button } from "../../design-system/primitives";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { CDROverviewTab } from "./CDROverviewTab";
import { CDRInstancesTab } from "./CDRInstancesTab";
import { CDRPoliciesTab } from "./CDRPoliciesTab";
import { CDRTestTab } from "./CDRTestTab";
import styles from "../policy/policy.module.css";

const TABS = ["Overview & Health", "Instances", "Policies", "Test"] as const;
type Tab = (typeof TABS)[number];

export function CDRPage(): JSX.Element {
  const [tab, setTab] = useState<Tab>("Overview & Health");
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  // §14 exact-mount RBAC: reads are viewer; EVERY mutation on this surface —
  // including the imperative test — is admin (never operator).
  const isAdmin = hasRole(role, "admin");

  return (
    <>
      <PageHeader
        title="CDR Integration"
        subtitle="Content Disarm & Reconstruction via enrolled Sluice engines — runtime enablement, instance trust lifecycle, sanitization policy rules, and an admin test harness. Node-local; refreshed on demand."
      />
      <div
        className={styles.toolbar}
        role="tablist"
        aria-label="CDR sections"
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
      {tab === "Overview & Health" && <CDROverviewTab isAdmin={isAdmin} />}
      {tab === "Instances" && <CDRInstancesTab isAdmin={isAdmin} />}
      {tab === "Policies" && <CDRPoliciesTab isAdmin={isAdmin} />}
      {tab === "Test" && <CDRTestTab isAdmin={isAdmin} />}
    </>
  );
}
