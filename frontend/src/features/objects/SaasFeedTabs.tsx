// 2D-B §§21–31 — feed status (UT1 + signed compact) and the signed SaaS feed
// surface (full status, settings, manual refresh).
//
// Load-bearing truths encoded here:
//   - Runtime enablement (§24): configured/resolved "enabled" is NOT runtime
//     truth — an untouched install is dormant. The status endpoint's
//     enabled/state/authority are the only runtime claims rendered.
//   - stale (§28) = a previously valid signed generation (the LKG) is SERVED
//     past its manifest expiry — never "not serving" / "no taxonomy".
//   - Nulls (§29) stay "never activated / no signed generation / unknown" —
//     never a fabricated 0 or epoch timestamp.
//   - Official feed only (§23): the endpoint is fixed read-only truth; no
//     custom URL, no mirror, no unsigned fallback.
//   - Managed DP (§22): settings are CP-owned (editable=false; PUT would be a
//     409) and never fall back to local values.
//   - cluster_publish_rejected (§27): LOCAL SAVE SUCCEEDED, fleet publish
//     rejected — a distinct state, never "Save failed".
//   - Manual refresh (§30): admin, operational; result vocabulary rendered
//     verbatim; one status refetch after completion; no polling loop.
import { useEffect, useRef, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  Spinner,
  StatusBadge,
} from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { InputField, Switch } from "../../design-system/forms";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import {
  asRevisionConflict,
  getSaasFeedSettings,
  getSaasFeedStatus,
  getUrlCatFeedStatus,
  isKnownSaasState,
  postSaasFeedRefresh,
  putSaasFeedSettings,
} from "../../api/urlcat";
import type {
  SaasFeedSettingsView,
  SaasFeedStatus,
  SaasRefreshResult,
} from "../../api/urlcat";
import styles from "../policy/policy.module.css";

function orAbsent(v: string | null, absent: string): JSX.Element | string {
  return v === null ? absent : <Mono>{v}</Mono>;
}

// ── Feed Status tab (UT1 + signed compact) ─────────────────────────────────

export function SaasFeedStatusTab(): JSX.Element {
  const q = useSnapshot(["objects", "urlcat-feed-status"], getUrlCatFeedStatus);
  const d = q.data;
  return (
    <section aria-label="Feed status">
      <div className={styles.calloutSpace}>
        <SnapshotBar
          updatedAt={q.dataUpdatedAt}
          fetching={q.isFetching}
          error={q.isError}
          hasData={d !== undefined}
          onRefresh={() => {
            void q.refetch();
          }}
        />
      </div>
      {q.isPending && <Skeleton>Loading feed status…</Skeleton>}
      {q.isError && <ErrorState title="Could not load feed status" />}
      {d !== undefined && (
        <>
          <Card title="UT1 community feed">
            {d.ut1.configured ? (
              <>
                <KeyValue
                  items={[
                    [
                      "Corpus entries (last sync)",
                      <Mono key="e">{String(d.ut1.entries ?? 0)}</Mono>,
                    ],
                    ["Last sync", orAbsent(d.ut1.lastSync, "Never synced")],
                    [
                      "Sync interval",
                      d.ut1.intervalSeconds === null ? (
                        "—"
                      ) : (
                        <Mono key="i">{String(d.ut1.intervalSeconds)}s</Mono>
                      ),
                    ],
                    [
                      "Sync failures",
                      <Mono key="f">{String(d.ut1.syncFailures ?? 0)}</Mono>,
                    ],
                  ]}
                />
                <p className={styles.refDetail}>
                  Read-only node-local community corpus. The entry count is the
                  FULL corpus parsed on the last sync — unrelated to signed SaaS
                  activation deltas.
                </p>
              </>
            ) : (
              <p>UT1 community feed is not configured on this node.</p>
            )}
          </Card>
          <Card title="Signed SaaS feed (summary)">
            <KeyValue
              items={[
                ["State", <SaasStateBadge key="s" state={d.saas.state} />],
                ["Runtime enabled", d.saas.enabled ? "Yes" : "No (dormant)"],
                [
                  "Active signed generation",
                  d.saas.activeFeedVersion === null ? (
                    "No signed generation"
                  ) : (
                    <Mono key="v">v{String(d.saas.activeFeedVersion)}</Mono>
                  ),
                ],
                [
                  "Last successful activation",
                  orAbsent(d.saas.lastSuccess, "Never activated"),
                ],
              ]}
            />
            <p className={styles.refDetail}>
              The full runtime detail lives on the Signed SaaS Feed section.
            </p>
          </Card>
        </>
      )}
    </section>
  );
}

// ── Signed state badge (bounded vocabulary + degraded unknown bucket) ──────

function SaasStateBadge({ state }: { state: string }): JSX.Element {
  if (!isKnownSaasState(state)) {
    return <StatusBadge status="warn">unknown state ({state})</StatusBadge>;
  }
  switch (state) {
    case "critical":
      return <StatusBadge status="critical">critical</StatusBadge>;
    case "waiting_for_authority":
      return <StatusBadge status="warn">waiting for authority</StatusBadge>;
    case "degraded":
      return <StatusBadge status="warn">degraded</StatusBadge>;
    case "stale":
      return <StatusBadge status="warn">stale (LKG serving)</StatusBadge>;
    case "recovering":
      return <StatusBadge status="warn">recovering</StatusBadge>;
    case "disabled":
      return <StatusBadge status="neutral">disabled</StatusBadge>;
    case "embedded":
      return <StatusBadge status="neutral">embedded baseline</StatusBadge>;
    case "syncing":
      return <StatusBadge status="ok">syncing</StatusBadge>;
    case "fresh":
      return <StatusBadge status="ok">fresh</StatusBadge>;
  }
}

// ── Signed SaaS Feed tab (full status + settings + manual refresh) ─────────

export function SignedSaasFeedTab({
  isAdmin,
}: {
  isAdmin: boolean;
}): JSX.Element {
  const statusQ = useSnapshot(["objects", "saas-status"], getSaasFeedStatus);
  const settingsQ = useSnapshot(
    ["objects", "saas-settings"],
    getSaasFeedSettings,
  );
  const refreshAll = (): void => {
    void statusQ.refetch();
    void settingsQ.refetch();
  };
  return (
    <section aria-label="Signed SaaS feed">
      <div className={styles.calloutSpace}>
        <SnapshotBar
          updatedAt={statusQ.dataUpdatedAt}
          fetching={statusQ.isFetching || settingsQ.isFetching}
          error={statusQ.isError || settingsQ.isError}
          hasData={statusQ.data !== undefined}
          onRefresh={refreshAll}
        />
      </div>
      {statusQ.isPending && <Skeleton>Loading signed feed status…</Skeleton>}
      {statusQ.isError && (
        <ErrorState title="Could not load signed feed status" />
      )}
      {statusQ.data !== undefined && (
        <SignedStatusCard
          status={statusQ.data}
          isAdmin={isAdmin}
          onAfterRefresh={refreshAll}
        />
      )}
      {settingsQ.data !== undefined && (
        <SignedSettingsCard
          key={settingsQ.data.revision}
          view={settingsQ.data}
          isAdmin={isAdmin}
          onSaved={refreshAll}
        />
      )}
    </section>
  );
}

function SignedStatusCard({
  status,
  isAdmin,
  onAfterRefresh,
}: {
  status: SaasFeedStatus;
  isAdmin: boolean;
  onAfterRefresh: () => void;
}): JSX.Element {
  const d = status;
  return (
    <Card title="Runtime status">
      {!isKnownSaasState(d.state) && (
        <Callout variant="warning" title="Unknown feed state" role="alert">
          The appliance reported a state (<Mono>{d.state}</Mono>) this UI does
          not know. Rendering raw facts only — treat as degraded, not healthy.
        </Callout>
      )}
      {d.state === "stale" && (
        <Callout
          variant="warning"
          title="Serving the last known-good generation"
        >
          A previously valid signed generation is being served past its manifest
          expiry. Traffic categorization has NOT stopped — the last-known-good
          taxonomy stays active until a fresh generation verifies.
        </Callout>
      )}
      {d.critical && d.criticalReason !== "" && (
        <Callout variant="critical" title="Critical" role="alert">
          <Mono>{d.criticalReason}</Mono>
        </Callout>
      )}
      {d.waitingForAuthority && (
        <Callout variant="warning" title="Waiting for authority" role="alert">
          This managed data-plane node has no valid control-plane feed authority
          yet. It never falls back to local settings.
        </Callout>
      )}
      <KeyValue
        items={[
          ["State", <SaasStateBadge key="s" state={d.state} />],
          ["Authority", <Mono key="a">{d.authority}</Mono>],
          ["Runtime enabled", d.enabled ? "Yes" : "No (dormant)"],
          [
            "Active source",
            d.activeSource === "" ? (
              "—"
            ) : (
              <Mono key="src">{d.activeSource}</Mono>
            ),
          ],
          [
            "Provenance",
            d.provenance === "" ? "—" : <Mono key="p">{d.provenance}</Mono>,
          ],
          [
            "Signature",
            d.signatureStatus === "verified" ? (
              <StatusBadge key="sig" status="ok">
                verified
              </StatusBadge>
            ) : d.signatureStatus === "compiled_trusted" ? (
              <StatusBadge key="sig" status="neutral">
                compiled-in trusted baseline
              </StatusBadge>
            ) : d.signatureStatus === "" ? (
              "—"
            ) : (
              <StatusBadge key="sig" status="critical">
                {d.signatureStatus}
              </StatusBadge>
            ),
          ],
          [
            "Active signed generation",
            d.activeFeedVersion === null ? (
              "No signed generation"
            ) : (
              <Mono key="v">v{String(d.activeFeedVersion)}</Mono>
            ),
          ],
          ["Generated at", orAbsent(d.generatedAt, "No signed generation")],
          [
            "Manifest expires",
            orAbsent(d.manifestExpiresAt, "No signed generation"),
          ],
          [
            "Hosts / categories / overrides",
            <Mono key="c">
              {String(d.hostCount)} / {String(d.categoryCount)} /{" "}
              {String(d.overrideCount)}
            </Mono>,
          ],
          [
            "Last activation change",
            d.lastActivationDelta === null ? (
              "Never activated"
            ) : (
              <Mono key="delta">
                +{String(d.lastActivationDelta.hostsAdded)} −
                {String(d.lastActivationDelta.hostsRemoved)} ~
                {String(d.lastActivationDelta.hostsChanged)}
              </Mono>
            ),
          ],
          [
            "Last successful activation",
            orAbsent(d.lastSuccessfulActivation, "Never activated"),
          ],
          ["Last attempt", orAbsent(d.lastAttempt, "No attempt yet")],
          [
            "Last outcome",
            d.lastOutcome === null ? (
              "—"
            ) : (
              <Mono key="o">
                {d.lastOutcome}
                {d.lastErrorClass !== null ? ` (${d.lastErrorClass})` : ""}
              </Mono>
            ),
          ],
          ["Next attempt", orAbsent(d.nextAttempt, "Not scheduled")],
          [
            "Failures (since start / consecutive)",
            <Mono key="f">
              {String(d.failuresSinceStart)} / {String(d.consecutiveFailures)}
            </Mono>,
          ],
          ...(d.detail !== ""
            ? ([["Detail", <Mono key="d">{d.detail}</Mono>]] as const)
            : []),
        ]}
      />
      {isAdmin && <ManualRefreshControl onAfterRefresh={onAfterRefresh} />}
    </Card>
  );
}

// ── Manual refresh (§30) ───────────────────────────────────────────────────

function ManualRefreshControl({
  onAfterRefresh,
}: {
  onAfterRefresh: () => void;
}): JSX.Element {
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<SaasRefreshResult | null>(null);
  const [error, setError] = useState("");
  const ownerRef = useRef(createRequestRunOwner());

  useEffect(() => {
    const owner = ownerRef.current;
    const cleanup = (): void => {
      owner.abort();
      setResult(null);
      setError("");
      setPending(false);
    };
    const unregister = registerAuthCleanup(cleanup);
    return () => {
      unregister();
      owner.abort();
    };
  }, []);

  const run = (): void => {
    const signal = ownerRef.current.begin();
    setPending(true);
    setError("");
    postSaasFeedRefresh(signal)
      .then((res) => {
        setResult(res);
        // One status refetch after a completed response — never a polling loop.
        if (!res.inProgress) onAfterRefresh();
      })
      .catch((err: unknown) => {
        if (signal.aborted) return;
        if (unknownOutcome(err)) {
          // A lost response never justifies immediately firing another
          // network refresh (§41) — fetch STATUS first.
          setError(
            "The refresh's outcome is unconfirmed. Refresh Status before considering another attempt — a refresh may already have run.",
          );
          onAfterRefresh();
          return;
        }
        setError(serverErrorText(err, "The appliance refused the refresh."));
      })
      .finally(() => {
        setPending(false);
      });
  };

  return (
    <div className={styles.calloutSpace}>
      <Button onClick={run} disabled={pending}>
        Refresh signed feed now
      </Button>
      {pending && <Spinner />}
      {result !== null && (
        <Callout
          variant={
            result.refreshed
              ? "success"
              : result.unavailable
                ? "critical"
                : "info"
          }
          title={
            result.refreshed
              ? "New signed generation activated"
              : result.inProgress
                ? "A refresh is already running"
                : result.unavailable
                  ? "Feed runtime unavailable"
                  : `Refresh finished: ${result.status}`
          }
          role="status"
        >
          {result.refreshed
            ? "A new generation verified and activated."
            : result.inProgress
              ? "Another refresh holds the runtime. Use Refresh on the status bar to observe its outcome — no automatic polling."
              : result.unavailable
                ? "The signed-feed runtime is not armed on this node."
                : "No new feed was applied. The server outcome above is authoritative — a completed refresh with no_change/skipped/failed does not mean a new feed landed."}
        </Callout>
      )}
      {error !== "" && (
        <Callout variant="warning" title="Refresh not confirmed" role="alert">
          {error}
        </Callout>
      )}
    </div>
  );
}

// ── Settings card (§§22–27, §37) ───────────────────────────────────────────

function SignedSettingsCard({
  view,
  isAdmin,
  onSaved,
}: {
  view: SaasFeedSettingsView;
  isAdmin: boolean;
  onSaved: () => void;
}): JSX.Element {
  const [managed, setManaged] = useState(view.managed);
  const [enabled, setEnabled] = useState(view.enabled);
  const [refresh, setRefresh] = useState(
    view.refreshSeconds > 0 ? `${String(view.refreshSeconds / 3600)}h` : "",
  );
  const [confirming, setConfirming] = useState(false);
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<JSX.Element | null>(null);
  const ownerRef = useRef(createRequestRunOwner());

  useEffect(() => {
    const owner = ownerRef.current;
    const cleanup = (): void => {
      owner.abort();
      setConfirming(false);
      setPending(false);
      setNotice(null);
    };
    const unregister = registerAuthCleanup(cleanup);
    return () => {
      unregister();
      owner.abort();
    };
  }, []);

  const ownershipChanged = managed !== view.managed || enabled !== view.enabled;
  const canEdit = isAdmin && view.editable;

  const doSave = (): void => {
    const signal = ownerRef.current.begin();
    setPending(true);
    setNotice(null);
    putSaasFeedSettings(
      { managed, enabled, refresh: refresh.trim() },
      view.revision,
      signal,
    )
      .then((res) => {
        setConfirming(false);
        if (res.clusterPublishRejected !== null) {
          setNotice(
            <Callout
              variant="warning"
              title="Saved locally — fleet publish rejected"
              role="alert"
            >
              The setting is saved on this control plane, but the new fleet
              snapshot was rejected. Data-plane nodes remain on the last valid
              published configuration.
            </Callout>,
          );
        } else {
          setNotice(
            <Callout variant="success" title="Settings saved" role="status">
              The configuration is durable on this node.
            </Callout>,
          );
        }
        onSaved();
      })
      .catch((err: unknown) => {
        setConfirming(false);
        if (unknownOutcome(err)) {
          setNotice(
            <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
              The connection was lost before the appliance answered — refresh
              the settings before writing again.
            </Callout>,
          );
          onSaved();
          return;
        }
        const conflict = asRevisionConflict(err);
        if (conflict !== null) {
          setNotice(
            <Callout
              variant="warning"
              title="Not applied — settings changed"
              role="alert"
            >
              Another administrator changed the feed configuration since this
              page loaded. Nothing was written — refresh and re-apply your
              change on the current state.
            </Callout>,
          );
          onSaved();
          return;
        }
        setNotice(
          <Callout variant="critical" title="Not saved" role="alert">
            {serverErrorText(err, "The appliance refused the settings change.")}
          </Callout>,
        );
      })
      .finally(() => {
        setPending(false);
      });
  };

  return (
    <Card title="Configuration">
      <KeyValue
        items={[
          [
            "Authority",
            view.editable ? (
              <StatusBadge key="auth" status="ok">
                Locally owned (standalone / control plane)
              </StatusBadge>
            ) : (
              <StatusBadge key="auth" status="warn">
                Control-plane managed — read-only on this data-plane node
              </StatusBadge>
            ),
          ],
          [
            "Official signed endpoint",
            <Mono key="url">{view.officialUrl}</Mono>,
          ],
          ["Protocol", <Mono key="proto">signed_manifest_v1</Mono>],
        ]}
      />
      <p className={styles.refDetail}>
        The endpoint and protocol are fixed: only the official signed manifest
        origin is permitted — no custom URL, no mirror, no unsigned fallback.
      </p>
      {view.resolveError !== null && (
        <Callout variant="critical" title="Configuration invalid" role="alert">
          <Mono>{view.resolveError}</Mono>
        </Callout>
      )}
      <Switch
        label="Managed (explicitly configured on this node)"
        checked={managed}
        disabled={!canEdit || pending}
        onChange={() => {
          setManaged(!managed);
        }}
      />
      <Switch
        label="Enabled (network refresh runs only when managed AND enabled)"
        checked={enabled}
        disabled={!canEdit || pending}
        onChange={() => {
          setEnabled(!enabled);
        }}
      />
      <InputField
        label="Refresh interval (minimum 1h, default 24h — e.g. 12h)"
        value={refresh}
        onChange={(e) => {
          setRefresh(e.target.value);
        }}
        placeholder="24h"
        disabled={!canEdit || pending}
      />
      {canEdit && (
        <div className={styles.calloutSpace}>
          <Button
            onClick={() => {
              // §37: ownership/enablement changes get a T2 confirmation;
              // an interval-only change saves normally.
              if (ownershipChanged) setConfirming(true);
              else doSave();
            }}
            disabled={pending}
          >
            Save configuration
          </Button>
        </div>
      )}
      {notice}
      <Dialog
        open={confirming}
        onClose={() => {
          setConfirming(false);
        }}
        title="Change signed-feed enablement"
      >
        <DialogBody>
          <p>
            Changing <Mono>managed</Mono> / <Mono>enabled</Mono> can start or
            stop network activity against the official feed endpoint and change
            which taxonomy generation is served to policy. Confirm to apply:
          </p>
          <KeyValue
            items={[
              ["Managed", managed ? "Yes" : "No"],
              ["Enabled", enabled ? "Yes" : "No"],
            ]}
          />
        </DialogBody>
        <DialogFooter>
          <Button
            variant="ghost"
            onClick={() => {
              setConfirming(false);
            }}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button onClick={doSave} disabled={pending}>
            Apply change
          </Button>
        </DialogFooter>
      </Dialog>
    </Card>
  );
}
