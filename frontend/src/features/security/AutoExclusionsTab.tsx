// 2E-B Auto-Exclusions: the VOLATILE, runtime-generated decryption-exclusion
// cache plus its durable node-local tunables. Entries are learned from
// operational decryption failures — they are NOT Access Rules, NOT Decryption
// Profiles, and NOT permanent operator policy; clearing the cache means
// affected destinations may be attempted for decryption again (and may be
// learned again when failures recur). The tunables are CONFIGURATION
// (fenced, durable + applied on 2xx, node-local, outside rollback).
import { useState, type JSX } from "react";
import {
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { Button } from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { InputField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { asRevisionConflict } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  clearAutoExclusions,
  evictAutoExclusion,
  getAutoExclusions,
  getTunablesMeta,
  putTunables,
  type AutoExcludeTunablesValues,
  type AutoExclusions,
} from "../../api/decryption";
import styles from "../policy/policy.module.css";

/** Bounded management read: the v2 UI never asks for more than this many
 * entries (stats.active carries the full population). */
const LIST_LIMIT = 500;

export function AutoExclusionsTab({
  isOperator,
  isAdmin,
}: {
  isOperator: boolean;
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(
    ["security", "decryption", "exclusions"],
    (signal) => getAutoExclusions(LIST_LIMIT, signal),
  );
  const d = page.q.data;
  const [evicting, setEvicting] = useState<{
    scopeId: string;
    host: string;
  } | null>(null);
  const [clearing, setClearing] = useState(false);
  const [notice, setNotice] = useState("");

  page.setBoundaryCleanup(() => {
    setEvicting(null);
    setClearing(false);
    setNotice("");
  });

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
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            refresh to see the authoritative cache state (the cache is volatile;
            a lost answer is resolved by fresh truth, never by repeating an
            action blindly).
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh exclusions
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {notice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Auto-exclusions" role="status">
            {notice}
          </Callout>
        </div>
      )}

      {d === undefined && page.q.isPending && (
        <Skeleton>Loading auto-exclusions…</Skeleton>
      )}
      {d === undefined && page.q.isError && (
        <ErrorState title="Auto-exclusions unavailable">
          The auto-exclusion cache could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {d !== undefined && (
        <>
          <Card title="Learned exclusions">
            <p className={styles.refDetail}>
              <StatusBadge status="warn">
                Volatile / runtime-generated
              </StatusBadge>{" "}
              These entries were learned automatically from decryption failures
              on fail-open Decryption Profiles. They are runtime cache state on
              this node — cleared on restart, never persisted or distributed —
              and a destination may be learned again when the same failures
              recur. They are not Access Rules or Decryption Profiles.
            </p>
            {d.truncated && (
              <Callout variant="info" title="Listing truncated">
                Showing the first {String(d.exclusions.length)} of{" "}
                {String(d.stats.active)} active entries.
              </Callout>
            )}
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className="sr-only">Learned auto-exclusions</caption>
                <thead>
                  <tr>
                    <th scope="col">Host</th>
                    <th scope="col">Profile scope</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Bypass hits</th>
                    <th scope="col">Expires</th>
                    {isOperator && <th scope="col">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {d.exclusions.length === 0 && (
                    <tr>
                      <td colSpan={isOperator ? 6 : 5}>
                        No learned exclusions — no destination is currently
                        auto-excluded from inspection on this node.
                      </td>
                    </tr>
                  )}
                  {d.exclusions.map((e) => {
                    const currentName = d.scopeNames[e.scopeId];
                    return (
                      <tr key={`${e.scopeId}/${e.host}`}>
                        <td>
                          <Mono>{e.host}</Mono>
                        </td>
                        <td>
                          {currentName ?? (
                            <>
                              {e.scopeName}{" "}
                              <StatusBadge status="warn">
                                profile deleted
                              </StatusBadge>
                            </>
                          )}
                        </td>
                        <td>
                          <Mono>{e.reason}</Mono>
                        </td>
                        <td>{String(e.hits)}</td>
                        <td>{new Date(e.expiresAt).toLocaleString()}</td>
                        {isOperator && (
                          <td>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={page.unknown !== null}
                              aria-label={`Evict exclusion ${e.host}`}
                              onClick={() => {
                                setEvicting({
                                  scopeId: e.scopeId,
                                  host: e.host,
                                });
                                setNotice("");
                              }}
                            >
                              Evict
                            </Button>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {isOperator && (
              <div className={styles.toolbarActions}>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page.unknown !== null}
                  onClick={() => {
                    setClearing(true);
                    setNotice("");
                  }}
                >
                  Clear all learned exclusions…
                </Button>
              </div>
            )}
          </Card>

          <Card title="Cache posture">
            <KeyValue
              items={[
                ["Active entries", String(d.stats.active)],
                ["Pending observations", String(d.stats.pending)],
                ["Confirm count", String(d.stats.confirmN)],
                ["Entry TTL (seconds)", String(d.stats.ttlSecs)],
                ["Pinned-cert TTL (seconds)", String(d.stats.pinnedTtlSecs)],
                ["Observation window (seconds)", String(d.stats.windowSecs)],
                ["Max entries", String(d.stats.maxEntries)],
                ["Fail-open profiles", String(d.failOpenProfiles)],
                ["Rules referencing fail-open", String(d.failOpenRules)],
              ]}
            />
          </Card>

          {isAdmin && (
            <TunablesCard
              current={{
                confirmN: d.stats.confirmN,
                ttlSecs: d.stats.ttlSecs,
                pinnedTtlSecs: d.stats.pinnedTtlSecs,
                windowSecs: d.stats.windowSecs,
                maxEntries: d.stats.maxEntries,
              }}
              revision={d.tunablesRevision}
              page={page}
              onNotice={setNotice}
            />
          )}
        </>
      )}

      {evicting !== null && isOperator && (
        <EvictDialog
          target={evicting}
          page={page}
          onDone={(removed) => {
            setEvicting(null);
            setNotice(
              removed
                ? `Exclusion for ${evicting.host} evicted. The destination may be attempted for decryption again — and may be learned again if the same failures recur.`
                : `The exclusion for ${evicting.host} was already gone (expired or evicted elsewhere). Fresh state loaded.`,
            );
            page.refreshToResolve();
          }}
          onCancel={() => {
            setEvicting(null);
          }}
        />
      )}

      {clearing && isOperator && (
        <ClearAllDialog
          page={page}
          onDone={(cleared) => {
            setClearing(false);
            setNotice(
              `Cleared ${String(cleared)} learned exclusion(s). Affected destinations may be attempted for decryption again; no Decryption Profile or policy rule was changed.`,
            );
            page.refreshToResolve();
          }}
          onCancel={() => {
            setClearing(false);
          }}
        />
      )}
    </div>
  );
}

type ExclusionsPage = ReturnType<typeof useObjectPage<AutoExclusions>>;

function EvictDialog({
  target,
  page,
  onDone,
  onCancel,
}: {
  target: { scopeId: string; host: string };
  page: ExclusionsPage;
  onDone: (removed: boolean) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={`Evict the exclusion for ${target.host}`}
      body={
        <>
          This removes the learned runtime exclusion for{" "}
          <Mono>{target.host}</Mono> in its owning profile scope. The
          destination may be attempted for decryption again on the next session
          — and may be auto-excluded again if the same failures recur.
        </>
      }
      impact="Inspection is attempted again for this destination; clients that genuinely cannot be inspected may see failures until it is re-learned."
      rollback="None needed — the cache re-learns from real failures."
      confirmLabel="Evict exclusion"
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        evictAutoExclusion(target.scopeId, target.host, signal)
          .then((res) => {
            onDone(res.removed);
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The eviction failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

function ClearAllDialog({
  page,
  onDone,
  onCancel,
}: {
  page: ExclusionsPage;
  onDone: (cleared: number) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Clear all learned exclusions"
      body={
        <>
          Clears the current runtime auto-exclusion cache on this node. Affected
          destinations may be attempted for decryption again. This does not
          delete Decryption Profiles or policy rules, and destinations may be
          learned again when decryption failures recur.
        </>
      }
      impact="Every currently-excluded destination is inspected again on its next session; genuinely incompatible destinations may fail until re-learned."
      rollback="None needed — the cache re-learns from real failures."
      confirmLabel="Clear all exclusions"
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        clearAutoExclusions(signal)
          .then((res) => {
            onDone(res.cleared);
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The clear failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

// ── Tunables (admin) ────────────────────────────────────────────────────────

/** relaxes reports whether the candidate weakens the anti-poisoning /
 * blast-radius posture vs the current values — the only case that warrants a
 * ceremony (a plain numeric tightening saves directly). */
export function tunablesRelax(
  current: AutoExcludeTunablesValues,
  next: AutoExcludeTunablesValues,
): boolean {
  return (
    next.confirmN < current.confirmN ||
    next.ttlSecs > current.ttlSecs ||
    next.pinnedTtlSecs > current.pinnedTtlSecs ||
    next.windowSecs > current.windowSecs ||
    next.maxEntries > current.maxEntries
  );
}

function TunablesCard({
  current,
  revision,
  page,
  onNotice,
}: {
  current: AutoExcludeTunablesValues;
  revision: string;
  page: ExclusionsPage;
  onNotice: (text: string) => void;
}): JSX.Element {
  const meta = useObjectPage(
    ["security", "decryption", "tunables-meta"],
    getTunablesMeta,
  );
  const [form, setForm] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  const [staleNotice, setStaleNotice] = useState("");
  const [saving, setSaving] = useState(false);

  const fieldVal = (key: string, cur: number): string =>
    form[key] ?? String(cur);
  const parsed = (key: string, cur: number): number => {
    const n = Number(fieldVal(key, cur));
    return Number.isFinite(n) ? Math.trunc(n) : NaN;
  };
  const next: AutoExcludeTunablesValues = {
    confirmN: parsed("confirm_n", current.confirmN),
    ttlSecs: parsed("ttl_secs", current.ttlSecs),
    pinnedTtlSecs: parsed("pinned_ttl_secs", current.pinnedTtlSecs),
    windowSecs: parsed("window_secs", current.windowSecs),
    maxEntries: parsed("max_entries", current.maxEntries),
  };
  const invalid = Object.values(next).some((v) => Number.isNaN(v));
  const dirty =
    !invalid &&
    (next.confirmN !== current.confirmN ||
      next.ttlSecs !== current.ttlSecs ||
      next.pinnedTtlSecs !== current.pinnedTtlSecs ||
      next.windowSecs !== current.windowSecs ||
      next.maxEntries !== current.maxEntries);

  const commit = (): void => {
    const signal = page.owner.begin();
    setSaving(true);
    setResult("pending");
    setErrorText("");
    putTunables(next, revision, signal)
      .then(() => {
        setConfirming(false);
        setResult("idle");
        setForm({});
        onNotice("Tunables saved (durable and applied).");
        page.refreshToResolve();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("edit");
          setConfirming(false);
          setResult("idle");
          return;
        }
        if (asRevisionConflict(err) !== null) {
          setConfirming(false);
          setResult("idle");
          setStaleNotice(
            "The tunables changed on the appliance since you loaded them. Nothing was applied — your entries are preserved; review the refreshed current values and save again.",
          );
          page.refreshToResolve();
          return;
        }
        setResult("failed");
        setErrorText(
          serverErrorText(err, "The appliance rejected the tunables."),
        );
        setConfirming(false);
      })
      .finally(() => {
        page.owner.settle(signal);
        setSaving(false);
      });
  };

  const boundsHelp = (key: string): string => {
    const b = meta.q.data?.bounds[key];
    return b === undefined ? "" : `Range ${String(b.min)}–${String(b.max)}.`;
  };
  const numField = (key: string, label: string, cur: number): JSX.Element => {
    const b = meta.q.data?.bounds[key];
    return (
      <InputField
        label={label}
        type="number"
        {...(b !== undefined ? { min: b.min, max: b.max } : {})}
        help={`Current: ${String(cur)}. ${boundsHelp(key)}`}
        value={fieldVal(key, cur)}
        disabled={saving}
        onChange={(e) => {
          setForm((f) => ({ ...f, [key]: e.target.value }));
          setStaleNotice("");
        }}
      />
    );
  };

  return (
    <Card title="Cache tuning">
      <p className={styles.refDetail}>
        <StatusBadge status="info">Node-local</StatusBadge> Durable engine
        parameters for the auto-exclusion cache on this appliance — deliberately
        outside export/import, config-version rollback, and fleet sync. A save
        is durable AND applied; learned entries keep their expiry (lowering max
        entries evicts oldest-first to the new cap).
      </p>
      {meta.q.data === undefined && meta.q.isPending && (
        <Skeleton>Loading bounds…</Skeleton>
      )}
      {staleNotice !== "" && (
        <Callout variant="warning" title="Not applied" role="alert">
          {staleNotice}
        </Callout>
      )}
      {errorText !== "" && !confirming && (
        <Callout variant="critical" title="Not applied" role="alert">
          {errorText}
        </Callout>
      )}
      {numField(
        "confirm_n",
        "Confirm count (distinct clients)",
        current.confirmN,
      )}
      {numField("ttl_secs", "Entry TTL (seconds)", current.ttlSecs)}
      {numField(
        "pinned_ttl_secs",
        "Pinned-cert TTL (seconds)",
        current.pinnedTtlSecs,
      )}
      {numField(
        "window_secs",
        "Observation window (seconds)",
        current.windowSecs,
      )}
      {numField("max_entries", "Max entries", current.maxEntries)}
      <div className={styles.toolbarActions}>
        <Button
          size="sm"
          disabled={!dirty || saving || page.unknown !== null}
          onClick={() => {
            setStaleNotice("");
            if (tunablesRelax(current, next)) {
              setConfirming(true);
            } else {
              commit();
            }
          }}
        >
          Save tunables
        </Button>
      </div>
      <ConfirmationDialog
        open={confirming}
        tier={2}
        title="Relax auto-exclusion guardrails"
        body={
          <>
            The new values weaken the cache&apos;s guardrails relative to the
            current configuration (a lower confirm count, longer exclusion
            lifetimes, a wider observation window, or a larger cache). Learned
            exclusions bypass TLS inspection for their destinations, so relaxing
            these extends how easily and how long inspection can be switched off
            automatically.
          </>
        }
        impact="Destinations qualify for automatic inspection bypass more easily and/or stay bypassed longer on this node."
        rollback="Save tighter values (or zeros to reset to defaults) at any time; active entries keep their current expiry."
        confirmLabel="Save relaxed tunables"
        destructive
        result={result}
        {...(errorText !== "" ? { errorText } : {})}
        onConfirm={() => {
          if (result !== "pending") commit();
        }}
        onCancel={() => {
          if (result !== "pending") {
            setConfirming(false);
            setResult("idle");
          }
        }}
      />
    </Card>
  );
}
