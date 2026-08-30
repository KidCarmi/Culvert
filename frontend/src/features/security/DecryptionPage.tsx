// 2E-B — Decryption Operations: the OPERATIONAL surface for TLS-decryption
// health & coverage, the node-local destination-privacy posture (incl.
// pseudonym-key rotation), and the volatile auto-exclusion cache + tunables.
// SERVER TRUTH ONLY: nothing here is derived into "healthy/safe/100%"
// language; counters are labeled with their real scope (process lifetime),
// unknown taxonomy values render verbatim, and the page never invents a
// second security model. Manual Refresh is the operational model (ADR-FE-002).
//
// Scope fences (2E decomposition): Decryption Profiles CRUD stays on
// Objects → Decryption Profiles (2D-A); CA/certificate management is not
// built here; CDR/Sluice belongs to 2E-C. This page links, never duplicates.
import { useState, type JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import { Button } from "../../design-system/primitives";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { DecryptionHealthTab } from "./DecryptionHealthTab";
import { DestinationPrivacyTab } from "./DestinationPrivacyTab";
import { AutoExclusionsTab } from "./AutoExclusionsTab";
import styles from "../policy/policy.module.css";

const TABS = [
  "Health & Coverage",
  "Destination Privacy",
  "Auto-Exclusions",
] as const;
type Tab = (typeof TABS)[number];

export function DecryptionPage(): JSX.Element {
  const [tab, setTab] = useState<Tab>("Health & Coverage");
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  const isOperator = hasRole(role, "operator");
  const isAdmin = hasRole(role, "admin");

  return (
    <>
      <PageHeader
        title="Decryption"
        subtitle="TLS-decryption coverage and failures, the node-local destination-privacy posture, and runtime auto-exclusions — the appliance's reported state, refreshed on demand."
      />
      <div
        className={styles.toolbar}
        role="tablist"
        aria-label="Decryption sections"
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
      {tab === "Health & Coverage" && <DecryptionHealthTab />}
      {tab === "Destination Privacy" && (
        <DestinationPrivacyTab isAdmin={isAdmin} />
      )}
      {tab === "Auto-Exclusions" && (
        <AutoExclusionsTab isOperator={isOperator} isAdmin={isAdmin} />
      )}
    </>
  );
}
