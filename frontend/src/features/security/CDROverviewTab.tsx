// 2E-C Overview & Health: the effective CDR runtime configuration (only
// `enabled` is runtime-mutable — everything else is YAML/CLI + restart and
// renders read-only), and the engine health snapshot with its REAL scopes:
// the cached snapshot can be up to ~45s of stale reassurance while probes
// fail, so the live poller's consecutiveFailures is surfaced beside it, and
// "healthy" is always labeled as the ENGINE's own claim.
import { useState, type JSX } from "react";
import {
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../design-system/dialog";
import { Button } from "../../design-system/primitives";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage, type ObjectPageState } from "../objects/useObjectPage";
import { unknownOutcome, serverErrorText } from "../../shared/mutationOutcome";
import { ApiError } from "../../api/client";
import {
  getCDRConfig,
  getCDRHealth,
  toggleCDR,
  type CDRConfig,
  type CDRHealth,
} from "../../api/cdr";
import styles from "../policy/policy.module.css";

interface OverviewData {
  config: CDRConfig;
  /** null when no health is available; healthNote says why (a 503 "no
   * active client" is a NORMAL state, not an error). */
  health: CDRHealth | null;
  healthNote: string | null;
}

async function fetchOverview(signal: AbortSignal): Promise<OverviewData> {
  const config = await getCDRConfig(signal);
  try {
    const health = await getCDRHealth(signal);
    return { config, health, healthNote: null };
  } catch (err: unknown) {
    if (
      err instanceof ApiError &&
      err.kind === "http" &&
      (err.status === 503 || err.status === 502)
    ) {
      return {
        config,
        health: null,
        healthNote:
          err.status === 503
            ? "No active CDR client — no enrolled, enabled instance is currently dialed."
            : `On-demand health probe failed: ${serverErrorText(err, "the engine did not answer.")}`,
      };
    }
    throw err;
  }
}

type OverviewPage = ObjectPageState<OverviewData>;

function ToggleDialog({
  page,
  target,
  onClose,
}: {
  page: OverviewPage;
  target: boolean;
  onClose: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={target ? "Enable CDR processing" : "Disable CDR processing"}
      body={
        target ? (
          <>
            Enables the CDR stage at runtime and dials every enrolled, enabled
            instance. Matching downloaded files are then sent to Sluice per the
            policy rules — in ENFORCE mode their content can be modified or
            blocked. The choice persists across restarts.
          </>
        ) : (
          <>
            Disables the CDR stage at runtime and drains the client pool. NO
            file sanitization, detection, or reporting happens through CDR while
            it is off — regardless of policy rules or fail mode. Enrolled
            instances and policy rules are kept. The choice persists across
            restarts.
          </>
        )
      }
      impact={
        target
          ? "File downloads matched by CDR policy are processed by Sluice; ENFORCE-mode rules can alter or block file content."
          : "Files pass through without any CDR processing until re-enabled."
      }
      rollback="Toggle it back — the switch is an absolute state and takes effect immediately."
      confirmLabel={target ? "Enable CDR" : "Disable CDR"}
      destructive={!target}
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        toggleCDR(target, signal)
          .then(() => {
            page.refreshToResolve();
            onClose();
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              // The toggle is an absolute-state idempotent write: a fresh
              // GET shows the truth, and re-issuing the SAME desired state
              // is safe — but nothing is assumed until the refresh lands.
              page.latchUnknown("edit");
              setResult("unknown");
              onClose();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The toggle failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onClose();
      }}
    />
  );
}

export function CDROverviewTab({ isAdmin }: { isAdmin: boolean }): JSX.Element {
  const page = useObjectPage(["security", "cdr", "overview"], fetchOverview);
  const d = page.q.data;
  const [toggleTarget, setToggleTarget] = useState<boolean | null>(null);

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={d !== undefined}
          onRefresh={page.refreshToResolve}
        />
      </div>

      {page.unknown !== null && (
        <Callout variant="warning" title="Last change unconfirmed">
          The outcome of the last change is unknown (the appliance did not
          answer). Refresh to load the authoritative state before making further
          changes.
        </Callout>
      )}

      {d === undefined && page.q.isPending && (
        <Skeleton>Loading CDR configuration…</Skeleton>
      )}
      {d === undefined && page.q.isError && (
        <ErrorState title="CDR configuration unavailable">
          The CDR configuration could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {d !== undefined && (
        <>
          <Card title="Runtime state">
            <KeyValue
              items={[
                ["CDR processing", d.config.enabled ? "enabled" : "disabled"],
                [
                  "Client pool",
                  d.config.clientActive
                    ? "active (at least one instance dialed)"
                    : "no active client",
                ],
                [
                  "Fail mode (when the engine is unreachable or errors)",
                  `${d.config.failMode === "" ? "(unset)" : d.config.failMode} — ${
                    d.config.failOpen
                      ? "files PASS THROUGH unsanitized"
                      : "matching downloads are BLOCKED"
                  }`,
                ],
              ]}
            />
            {d.config.enabled && d.config.failOpen && (
              <Callout variant="warning" title="Fail-open posture">
                When no Sluice instance is reachable (or a call errors),
                matching files are delivered WITHOUT sanitization. Fail mode is
                configured in YAML/CLI (cdr.fail_mode) and requires a restart to
                change.
              </Callout>
            )}
            {isAdmin && (
              <div className={styles.toolbar}>
                <Button
                  variant={d.config.enabled ? "danger" : "primary"}
                  disabled={page.unknown !== null}
                  onClick={() => {
                    setToggleTarget(!d.config.enabled);
                  }}
                >
                  {d.config.enabled
                    ? "Disable CDR processing…"
                    : "Enable CDR processing…"}
                </Button>
              </div>
            )}
          </Card>

          <Card title="Startup configuration — read-only (YAML/CLI + restart)">
            <p className={styles.refDetail}>
              These settings are deliberately not runtime-mutable; change them
              in the appliance configuration and restart.
            </p>
            <KeyValue
              items={[
                [
                  "Bootstrap endpoint",
                  d.config.endpoint === "" ? "(none)" : d.config.endpoint,
                ],
                [
                  "Default profile",
                  d.config.defaultProfile === ""
                    ? "default"
                    : d.config.defaultProfile,
                ],
                [
                  "Default mode",
                  d.config.defaultMode === ""
                    ? "ENFORCE"
                    : d.config.defaultMode,
                ],
                [
                  "Per-file timeout",
                  d.config.timeoutSec === 0
                    ? "35s (default)"
                    : `${String(d.config.timeoutSec)}s`,
                ],
                [
                  "Max file size",
                  d.config.maxFileSizeMB === 0
                    ? "50 MB (default)"
                    : `${String(d.config.maxFileSizeMB)} MB`,
                ],
              ]}
            />
          </Card>

          <Card title="Engine health">
            {d.health === null ? (
              <Callout variant="info" title="No health data">
                {d.healthNote ?? "No health data is available."}
              </Callout>
            ) : (
              <>
                {d.health.consecutiveFailures > 0 && (
                  <Callout variant="warning" title="Snapshot may be stale">
                    The background poller has{" "}
                    {String(d.health.consecutiveFailures)} consecutive failed
                    probe(s); the values below are the last snapshot that
                    succeeded
                    {d.health.lastSeen !== "" ? ` (${d.health.lastSeen})` : ""},
                    not the current engine state.
                  </Callout>
                )}
                <KeyValue
                  items={[
                    [
                      "Engine-reported status",
                      d.health.healthy
                        ? "healthy (the engine's own claim)"
                        : "not healthy",
                    ],
                    [
                      "Live poller view",
                      d.health.liveHealthy
                        ? "at least one instance answered its last probe"
                        : "no instance answered its last probe",
                    ],
                    [
                      "Engine version",
                      d.health.version === "" ? "—" : d.health.version,
                    ],
                    [
                      "Workers",
                      `${String(d.health.activeWorkers)} active / ${String(d.health.maxWorkers)} max`,
                    ],
                    ["Queue depth", String(d.health.queueDepth)],
                    [
                      "Files processed (engine lifetime)",
                      String(d.health.filesProcessed),
                    ],
                    [
                      "Threats removed (engine lifetime)",
                      String(d.health.threatsRemoved),
                    ],
                    [
                      "Snapshot captured",
                      d.health.lastSeen === ""
                        ? "on-demand probe (just now)"
                        : d.health.lastSeen,
                    ],
                  ]}
                />
                {d.health.supportedTypes.length > 0 && (
                  <p className={styles.refDetail}>
                    Supported types:{" "}
                    <Mono>{d.health.supportedTypes.join(", ")}</Mono>
                  </p>
                )}
                {d.health.profiles.length > 0 && (
                  <div className={styles.tableWrap}>
                    <table className={styles.table}>
                      <caption className="sr-only">
                        Sanitization profiles advertised by the engine
                      </caption>
                      <thead>
                        <tr>
                          <th scope="col">Profile</th>
                          <th scope="col">Description</th>
                          <th scope="col">Max file bytes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.health.profiles.map((p) => (
                          <tr key={p.name}>
                            <td>
                              <Mono>{p.name}</Mono>
                            </td>
                            <td>
                              {p.description === "" ? "—" : p.description}
                            </td>
                            <td>
                              {p.maxFileSizeBytes === 0
                                ? "—"
                                : String(p.maxFileSizeBytes)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
            <p className={styles.refDetail}>
              An engine that answered its last health probe is reachable — that
              is not a claim that production file traffic is being sanitized
              (that also requires CDR to be enabled and a policy rule or the
              defaults to select a profile).
            </p>
          </Card>
        </>
      )}

      {toggleTarget !== null && d !== undefined && (
        <ToggleDialog
          page={page}
          target={toggleTarget}
          onClose={() => {
            setToggleTarget(null);
          }}
        />
      )}
    </div>
  );
}
