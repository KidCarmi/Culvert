// Design-system preview gallery (FE-2 §6). Experimental-surface only — this
// route exists for visual/interaction review while CULVERT_EXPERIMENTAL_UI is
// a preview; it is not a future production navigation item. All content is
// realistic appliance fixture data; nothing calls an API.
// Lazy-loaded on purpose: this route is the production dynamic-import chunk
// that exercises the FE-1B manifest-graph validator end to end.
import { useState } from "react";
import type { JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  Card,
  Divider,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  Spinner,
  StatusBadge,
  Timestamp,
  Tooltip,
} from "../../design-system/primitives";
import {
  Checkbox,
  InputField,
  SelectField,
  Switch,
  TextareaField,
} from "../../design-system/forms";
import { DataTable } from "../../design-system/table";
import type { Column } from "../../design-system/table";
import {
  ConfirmationDialog,
  Dialog,
  DialogBody,
  DialogFooter,
} from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { useToast } from "../../design-system/toast";
import {
  AuditTimeline,
  ConfigDiff,
  DiagnosticsResult,
  HealthCheck,
  OperationProgress,
  RollbackBanner,
} from "../../design-system/appliance";
import { DonutChart, LineChart } from "../../design-system/charts";
import { IconInfo } from "../../design-system/icons";
import styles from "./gallery.module.css";

interface NodeRow {
  name: string;
  role: string;
  version: string;
  requests: number;
  status: "ok" | "warn" | "critical";
  statusLabel: string;
}

const nodeRows: readonly NodeRow[] = [
  {
    name: "gw-fra-01",
    role: "Control Plane",
    version: "v1.9.2",
    requests: 148_221,
    status: "ok",
    statusLabel: "Healthy",
  },
  {
    name: "gw-fra-02",
    role: "Data Plane",
    version: "v1.9.2",
    requests: 96_410,
    status: "ok",
    statusLabel: "Healthy",
  },
  {
    name: "gw-ams-01",
    role: "Data Plane",
    version: "v1.9.1",
    requests: 88_302,
    status: "warn",
    statusLabel: "Update available",
  },
  {
    name: "gw-ams-02",
    role: "Data Plane",
    version: "v1.9.2",
    requests: 0,
    status: "critical",
    statusLabel: "Unreachable",
  },
];

const nodeColumns: ReadonlyArray<Column<NodeRow>> = [
  { key: "name", header: "Node", render: (r) => <Mono>{r.name}</Mono> },
  { key: "role", header: "Role", render: (r) => r.role },
  { key: "version", header: "Version", render: (r) => r.version },
  {
    key: "req",
    header: "Requests (24h)",
    numeric: true,
    render: (r) => r.requests.toLocaleString("en-US"),
  },
  {
    key: "status",
    header: "Status",
    render: (r) => <StatusBadge status={r.status}>{r.statusLabel}</StatusBadge>,
  },
];

export function GalleryPage(): JSX.Element {
  const toast = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [tier3Open, setTier3Open] = useState(false);
  const [typed, setTyped] = useState("");
  const [tier3Result, setTier3Result] = useState<ConfirmResult>("idle");

  const runTier3 = (): void => {
    setTier3Result("pending");
    window.setTimeout(() => {
      setTier3Result("unknown"); // demo the first-class unknown state
    }, 900);
  };
  const closeTier3 = (): void => {
    setTier3Open(false);
    setTyped("");
    setTier3Result("idle");
  };

  return (
    <>
      <PageHeader
        title="Design system"
        subtitle="Component and interaction inventory — fixture data only, experimental surface"
      />
      <div className={styles.grid}>
        <Card title="Status vocabulary">
          <div className={styles.row}>
            <StatusBadge status="ok">Proxy Healthy</StatusBadge>
            <StatusBadge status="warn">ClamAV Degraded</StatusBadge>
            <StatusBadge status="critical">Rule evaluation blocked</StatusBadge>
            <StatusBadge status="info">Update available</StatusBadge>
            <StatusBadge status="unknown">State unknown</StatusBadge>
            <StatusBadge status="neutral">Disabled</StatusBadge>
          </div>
          <Divider />
          <div className={styles.stack}>
            <Callout variant="warning" title="ClamAV Degraded">
              Scans are queuing at capacity. Content is still refused
              fail-closed at the scan budget.
            </Callout>
            <Callout variant="unknown" title="Action state is unknown">
              The rollback request was submitted but no result was observed.
              Verify the current release before retrying.
            </Callout>
          </div>
        </Card>

        <Card title="Buttons">
          <div className={styles.stack}>
            <div className={styles.row}>
              <Button variant="primary">Save changes</Button>
              <Button variant="secondary">Validate</Button>
              <Button variant="ghost">Cancel</Button>
              <Button variant="primary" disabled>
                Saving…
              </Button>
            </div>
            <div className={styles.row}>
              <Button variant="danger">Rotate signing key</Button>
              <Button variant="danger-quiet">Evict entry</Button>
              <Button size="sm">Row action</Button>
              <Tooltip text="Explains a control without hiding critical state">
                <Button variant="ghost" size="sm">
                  <IconInfo /> With tooltip
                </Button>
              </Tooltip>
            </div>
            <div className={styles.row}>
              <Spinner />
              <Skeleton>Loading placeholder width</Skeleton>
            </div>
          </div>
        </Card>

        <Card title="Forms">
          <div className={styles.stack}>
            <InputField
              label="Listen address"
              defaultValue="0.0.0.0:8080"
              help="Host and port the proxy accepts connections on."
            />
            <InputField
              label="Session timeout (hours)"
              defaultValue="240"
              error="Must be between 1 and 168."
            />
            <SelectField
              label="Default action"
              defaultValue="deny"
              help="Applied when no rule matches (Zero Trust)."
            >
              <option value="deny">Deny (recommended)</option>
              <option value="allow">Allow</option>
            </SelectField>
            <TextareaField
              label="Allowed CIDR ranges"
              defaultValue={"10.0.0.0/8\n192.168.0.0/16"}
            />
            <div className={styles.row}>
              <Checkbox label="Pre-upgrade backup" defaultChecked />
              <Switch label="SSL inspection" defaultChecked />
            </div>
          </div>
        </Card>

        <Card title="Feedback states">
          <div className={styles.stack}>
            <div className={styles.row}>
              <Button
                onClick={() => toast("success", "Policy version 42 committed.")}
              >
                Success toast
              </Button>
              <Button
                onClick={() =>
                  toast(
                    "error",
                    "Rule reorder rejected: rulebase changed underneath you.",
                  )
                }
              >
                Error toast
              </Button>
            </div>
            <EmptyState title="No enrollment tokens">
              Create a token to enroll a new data-plane node into this cluster.
            </EmptyState>
            <ErrorState
              title="Diagnostics unavailable"
              action={<Button size="sm">Retry</Button>}
            >
              The diagnostics service did not respond within 30 seconds.
            </ErrorState>
          </div>
        </Card>

        <Card title="Cluster nodes (table)">
          <DataTable
            caption="Cluster nodes"
            columns={nodeColumns}
            rows={nodeRows}
            rowKey={(r) => r.name}
          />
        </Card>

        <Card title="Metadata">
          <KeyValue
            items={[
              ["Policy version", <Mono key="v">42</Mono>],
              ["Active nodes", "3 nodes online"],
              [
                "Catalog expires",
                <Timestamp key="t" iso="2027-02-18T03:00:00Z" />,
              ],
              ["Root CA", <Mono key="ca">sha256:9f2a…c41d</Mono>],
            ]}
          />
        </Card>

        <Card title="Overlays">
          <div className={styles.row}>
            <Button onClick={() => setDialogOpen(true)}>Open dialog</Button>
            <Button variant="danger" onClick={() => setTier3Open(true)}>
              Tier-3 ceremony
            </Button>
          </div>
        </Card>

        <Card title="Health">
          <HealthCheck
            items={[
              {
                name: "Proxy",
                status: "ok",
                statusLabel: "Healthy",
                detail: "1,214 active connections",
              },
              {
                name: "ClamAV",
                status: "warn",
                statusLabel: "Degraded",
                detail: "At scanning capacity",
                operatorAction:
                  "Add scan capacity, or review stat_clam_saturated on the Security panel.",
              },
              { name: "Cluster CA", status: "ok", statusLabel: "Valid 9y 2m" },
              {
                name: "Frontend v2",
                status: "unknown",
                statusLabel: "Unknown",
                detail: "No validation result observed",
              },
            ]}
          />
        </Card>

        <Card title="Diagnostics">
          <DiagnosticsResult
            verdict="warn"
            verdictLabel="Warnings"
            generatedAt="2026-08-22T09:14:02Z"
            checks={[
              {
                code: "storage",
                status: "ok",
                statusLabel: "ok",
                message: "41.2 GiB free of 80 GiB",
              },
              {
                code: "identity_backend",
                status: "warn",
                statusLabel: "warn",
                message: "LDAP directory unreachable for 3m",
                operatorAction:
                  "Check connectivity to the configured directory, then re-run the LDAP test.",
              },
              {
                code: "root_ca",
                status: "ok",
                statusLabel: "ok",
                message: "Expires in 8y 11m",
              },
            ]}
          />
        </Card>

        <Card title="Configuration diff">
          <ConfigDiff
            rows={[
              {
                field: "default_action",
                kind: "changed",
                before: "allow",
                after: "deny",
              },
              {
                field: "rules[12].enabled",
                kind: "changed",
                before: "false",
                after: "true",
              },
              {
                field: "blocklist.feeds[2]",
                kind: "added",
                after: "https://feeds.example/urlhaus",
              },
              {
                field: "rewrite.rules[0]",
                kind: "removed",
                before: "strip X-Internal-Debug",
              },
            ]}
          />
        </Card>

        <Card title="Operations">
          <div className={styles.stack}>
            <OperationProgress
              phases={[
                {
                  label: "Pre-upgrade backup",
                  state: "done",
                  detail: "142 MB",
                },
                { label: "Pull pinned image", state: "done" },
                { label: "Apply release v1.9.3", state: "active" },
                { label: "Health verification", state: "pending" },
              ]}
            />
            <RollbackBanner action={<Button size="sm">Roll back</Button>}>
              Rollback available: configuration v41 (before “default action →
              deny”).
            </RollbackBanner>
          </div>
        </Card>

        <Card title="Audit">
          <AuditTimeline
            entries={[
              {
                ts: "2026-08-22T08:59:41Z",
                actor: "admin@10.20.0.4",
                action: "policy.rule.update",
                object: "rule 01J8…",
              },
              {
                ts: "2026-08-22T08:41:12Z",
                actor: "operator@10.20.0.9",
                action: "blocklist.feed.sync",
              },
              {
                ts: "2026-08-22T07:12:55Z",
                actor: "admin@10.20.0.4",
                action: "config.rollback v41",
              },
            ]}
          />
        </Card>

        <Card title="Charts (internal SVG — Chart.js rejected)">
          <div className={styles.stack}>
            <LineChart
              title="Requests per second (15 min)"
              unit="req/s"
              points={[
                112, 118, 131, 129, 140, 162, 155, 149, 171, 168, 177, 190, 183,
                174, 181,
              ]}
            />
            <DonutChart
              title="Verdicts (24h)"
              segments={[
                { label: "Allowed", value: 96410, status: "ok" },
                { label: "Blocked", value: 4210, status: "critical" },
                { label: "Auth required", value: 1180, status: "info" },
              ]}
            />
          </div>
        </Card>
      </div>

      <Dialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        title="Enrollment token created"
      >
        <DialogBody>
          <p>
            Token <Mono>tok_9f2ac41d</Mono> is valid for 24 hours and limited to{" "}
            <Mono>10.20.0.0/16</Mono>. It is shown once.
          </p>
        </DialogBody>
        <DialogFooter>
          <Button variant="primary" onClick={() => setDialogOpen(false)}>
            Done
          </Button>
        </DialogFooter>
      </Dialog>

      <ConfirmationDialog
        open={tier3Open}
        tier={3}
        title="Switch blocklist to allowlist mode"
        body="Every host not explicitly listed will be BLOCKED for all users behind this gateway."
        impact="Traffic to unlisted destinations stops immediately for every connected client."
        rollback="Switch back to blocklist mode; no entries are lost."
        confirmLabel="Switch mode"
        confirmWord="ALLOWLIST"
        typedValue={typed}
        onTypedChange={setTyped}
        result={tier3Result}
        onConfirm={runTier3}
        onCancel={closeTier3}
      />
    </>
  );
}
