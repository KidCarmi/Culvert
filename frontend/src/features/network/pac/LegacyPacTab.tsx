// 2F-E — the legacy default PAC (/pac/default.pac, the pre-profile
// exclusions list): revision-fenced, validation issues rendered verbatim,
// the canonical exclusions echoed back from the appliance after a save.
import { useEffect, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
} from "../../../design-system/primitives";
import { InputField, TextareaField } from "../../../design-system/forms";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../../design-system/dialog";
import { SnapshotBar } from "../../../shared/snapshot";
import { useObjectPage } from "../../objects/useObjectPage";
import { useDirtyGuard } from "../../../shared/dirtyGuard";
import {
  serverErrorText,
  unknownOutcome,
} from "../../../shared/mutationOutcome";
import {
  asPacFence,
  asPacIssues,
  getPacConfig,
  savePacConfig,
} from "../../../api/pac";
import type {
  PacConfig,
  PacFenceRefusal,
  PacIssuesRefusal,
  PacValidationIssue,
} from "../../../api/pac";
import { FenceCallout, IssuesCallout } from "./pacShared";
import styles from "../../policy/policy.module.css";

interface Form {
  proxyHost: string;
  proxyPort: string;
  exclusions: string;
}

function formOf(c: PacConfig): Form {
  return {
    proxyHost: c.proxyHost,
    proxyPort: String(c.proxyPort),
    exclusions: c.exclusions.join("\n"),
  };
}

export function LegacyPacTab({
  isAdmin,
  onDirtyChange,
}: {
  isAdmin: boolean;
  /** 2F-E correction (finding 4): the page guards tab switches on it */
  onDirtyChange?: (dirty: boolean) => void;
}): JSX.Element {
  const page = useObjectPage(["network", "pac", "legacy-config"], getPacConfig);
  const cfg = page.q.data;
  const [form, setForm] = useState<Form | null>(null);
  const [seed, setSeed] = useState<PacConfig | null>(null);
  const [ceremony, setCeremony] = useState<{
    result: ConfirmResult;
    errorText: string;
  } | null>(null);
  const [fence, setFence] = useState<PacFenceRefusal | null>(null);
  const [issues, setIssues] = useState<PacIssuesRefusal | null>(null);
  const [warnings, setWarnings] = useState<readonly PacValidationIssue[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  if (cfg !== undefined && seed !== cfg) {
    const dirtyNow =
      form !== null &&
      seed !== null &&
      JSON.stringify(form) !== JSON.stringify(formOf(seed));
    setSeed(cfg);
    if (!dirtyNow) setForm(formOf(cfg));
  }
  const dirty =
    form !== null &&
    cfg !== undefined &&
    JSON.stringify(form) !== JSON.stringify(formOf(cfg));
  const guard = useDirtyGuard(
    dirty && isAdmin,
    "the unsaved legacy PAC changes",
  );
  const dirtyForPage = dirty && isAdmin;
  useEffect(() => {
    onDirtyChange?.(dirtyForPage);
  }, [dirtyForPage, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);

  const runSave = async (): Promise<void> => {
    if (form === null || cfg === undefined) return;
    setFence(null);
    setIssues(null);
    setWarnings([]);
    const signal = page.owner.begin();
    try {
      const res = await savePacConfig(
        {
          proxyHost: form.proxyHost.trim(),
          proxyPort: Number(form.proxyPort) || 0,
          exclusions: form.exclusions
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l !== ""),
        },
        cfg.revision,
        signal,
      );
      setCeremony(null);
      setWarnings(res.warnings);
      setNotice(
        `Saved as revision ${String(res.revision)}; the appliance canonicalized ${String(res.exclusions.length)} exclusion(s).`,
      );
      setForm(formOf(res));
      page.refreshToResolve();
    } catch (err) {
      const f = asPacFence(err);
      const i = asPacIssues(err);
      if (f !== null) {
        setCeremony(null);
        setFence(f);
        page.refreshToResolve();
      } else if (i !== null) {
        setCeremony(null);
        setIssues(i);
      } else if (unknownOutcome(err)) {
        setCeremony(null);
        page.latchUnknown("edit");
      } else
        setCeremony({
          result: "failed",
          errorText: serverErrorText(err, "Save refused."),
        });
    } finally {
      page.owner.settle(signal);
    }
  };

  return (
    <div>
      {guard.element}
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={cfg !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
          }}
        />
      </div>
      <p className={styles.authNote}>
        The legacy default PAC is served at <Mono>/proxy.pac</Mono> (alias{" "}
        <Mono>/pac/default.pac</Mono>). An empty proxy host serves a fail-open
        DIRECT PAC — a recorded, deliberately-unchanged legacy behaviour.
      </p>
      {page.unknown !== null && (
        <Callout variant="unknown" title="Last change unconfirmed" role="alert">
          A request was sent but no result was observed. Refresh to resolve
          before saving again.
        </Callout>
      )}
      {notice !== null && (
        <Callout variant="success" role="status">
          {notice}
        </Callout>
      )}
      {warnings.length > 0 && (
        <Callout variant="warning" title="Saved with warnings">
          <ul>
            {warnings.map((w, i) => (
              <li key={`${w.code}-${String(i)}`}>
                <Mono>{w.code}</Mono> {w.message}
              </li>
            ))}
          </ul>
        </Callout>
      )}
      {fence !== null && <FenceCallout fence={fence} tokenLabel="revision" />}
      {issues !== null && <IssuesCallout issues={issues} />}
      {cfg === undefined && page.q.isPending && (
        <Skeleton>Loading legacy PAC…</Skeleton>
      )}
      {cfg === undefined && page.q.isError && (
        <ErrorState title="Legacy PAC unavailable">
          {serverErrorText(page.q.error, "The legacy PAC could not be read.")}
        </ErrorState>
      )}
      {cfg !== undefined && form !== null && (
        <Card title={`Default PAC (revision ${String(cfg.revision)})`}>
          {isAdmin ? (
            <div className={styles.editorGroup}>
              <InputField
                label="Proxy host"
                value={form.proxyHost}
                onChange={(e) => {
                  setForm({ ...form, proxyHost: e.target.value });
                }}
              />
              <InputField
                label="Proxy port"
                type="number"
                min={1}
                max={65535}
                value={form.proxyPort}
                onChange={(e) => {
                  setForm({ ...form, proxyPort: e.target.value });
                }}
              />
              <TextareaField
                label="Exclusions (one per line: host, *.suffix, or CIDR)"
                rows={8}
                value={form.exclusions}
                onChange={(e) => {
                  setForm({ ...form, exclusions: e.target.value });
                }}
              />
              <div className={styles.toolbarActions}>
                <Button
                  variant="primary"
                  disabled={!dirty || page.unknown !== null}
                  onClick={() => {
                    setCeremony({ result: "idle", errorText: "" });
                  }}
                >
                  Save legacy PAC
                </Button>
                <Button
                  variant="ghost"
                  disabled={!dirty}
                  onClick={() => {
                    setForm(formOf(cfg));
                  }}
                >
                  Discard local edits
                </Button>
              </div>
            </div>
          ) : (
            <KeyValue
              items={[
                [
                  "Proxy",
                  cfg.proxyHost !== ""
                    ? `${cfg.proxyHost}:${String(cfg.proxyPort)}`
                    : "(none — fail-open DIRECT)",
                ],
                [
                  "Exclusions",
                  cfg.exclusions.length > 0
                    ? cfg.exclusions.join(", ")
                    : "none",
                ],
              ]}
            />
          )}
        </Card>
      )}
      {ceremony !== null && cfg !== undefined && (
        <ConfirmationDialog
          open
          tier={2}
          title="Save the legacy default PAC"
          body={
            <p>
              Replaces the served default PAC (reviewed against revision{" "}
              {String(cfg.revision)}). Exclusions are DIRECT paths: matching
              destinations bypass the proxy entirely.
            </p>
          }
          impact="Every client using /proxy.pac receives the new file on its next fetch."
          rollback="Restore the previous values and save again (config versions record every save)."
          confirmLabel="Save"
          result={ceremony.result}
          {...(ceremony.errorText !== ""
            ? { errorText: ceremony.errorText }
            : {})}
          onConfirm={() => {
            if (ceremony.result === "pending") return;
            setCeremony({ result: "pending", errorText: "" });
            void runSave();
          }}
          onCancel={() => {
            setCeremony(null);
          }}
        />
      )}
    </div>
  );
}
