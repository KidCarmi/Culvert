// 2F-E — PAC (proxy auto-config): profiles + their node-local publish
// lifecycle, pools, DIRECT-exception governance, and the legacy default PAC.
//
// SERVER TRUTH ONLY: the lifecycle state machine, the bound DIRECT
// challenge, the fence tokens and the history are rendered from the
// appliance's own answers; the browser never invents a token, never
// reproduces a revision, never re-dispatches an unresolved operation.
// EVERY PAC mutation is ADMIN (C7 — the parity doc's "operator" claim is
// corrected in 2F-G); viewers read every tab and mount zero write controls.
import { useState, type JSX } from "react";
import { PageHeader } from "../../../layouts/AppShell";
import { Button } from "../../../design-system/primitives";
import { useAuth } from "../../../auth/AuthProvider";
import { hasRole } from "../../../auth/rbac";
import { ProfilesTab } from "./ProfilesTab";
import { PoolsTab } from "./PoolsTab";
import { ExceptionsTab } from "./ExceptionsTab";
import { LegacyPacTab } from "./LegacyPacTab";
import { useDiscardGuard } from "./discardGuard";
import styles from "../../policy/policy.module.css";

const TABS = ["Profiles", "Pools", "DIRECT Exceptions", "Legacy PAC"] as const;
type Tab = (typeof TABS)[number];

export function PACPage(): JSX.Element {
  const [tab, setTab] = useState<Tab>("Profiles");
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  const isAdmin = hasRole(role, "admin");
  // 2F-E correction (finding 4): tabs are LOCAL state, not routes — a
  // dirty editor on the current tab asks before it is unmounted.
  const [dirty, setDirty] = useState(false);
  const discard = useDiscardGuard("the unsaved changes on this tab");

  return (
    <>
      <PageHeader
        title="PAC — Proxy Auto-Config"
        subtitle="Per-site PAC profiles with a node-local draft → publish → history lifecycle, proxy pools, DIRECT-exception governance, and the legacy default PAC. Refreshed on demand."
      />
      <div className={styles.toolbar} role="tablist" aria-label="PAC sections">
        {TABS.map((t) => (
          <Button
            key={t}
            size="sm"
            variant={t === tab ? "primary" : "ghost"}
            role="tab"
            aria-selected={t === tab}
            onClick={() => {
              if (t === tab) return;
              discard.request(dirty, () => {
                setDirty(false);
                setTab(t);
              });
            }}
          >
            {t}
          </Button>
        ))}
      </div>
      {discard.element}
      {tab === "Profiles" && (
        <ProfilesTab isAdmin={isAdmin} onDirtyChange={setDirty} />
      )}
      {tab === "Pools" && <PoolsTab isAdmin={isAdmin} />}
      {tab === "DIRECT Exceptions" && <ExceptionsTab isAdmin={isAdmin} />}
      {tab === "Legacy PAC" && (
        <LegacyPacTab isAdmin={isAdmin} onDirtyChange={setDirty} />
      )}
    </>
  );
}
