// 2E-A Threat Intelligence: factual feed state, the manual Sync action
// (IMPERATIVE, admin — its failure never implies the last-known-good feed
// stopped enforcing), and the fenced domain-allowlist editor. No invented
// "health score" — the tab renders exactly the appliance's sync facts.
import { useState, type JSX } from "react";
import {
  Callout,
  Card,
  Button,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  getDomainAllowlist,
  getSecScanStatus,
  putDomainAllowlist,
  syncThreatFeeds,
} from "../../api/contentsec";
import { FencedListEditor } from "./FencedListEditor";
import styles from "../policy/policy.module.css";

export function ThreatIntelTab({ isAdmin }: { isAdmin: boolean }): JSX.Element {
  const page = useObjectPage(
    ["security", "content", "threat-intel"],
    getDomainAllowlist,
  );
  const status = useObjectPage(
    ["security", "content", "threat-status"],
    getSecScanStatus,
  );
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState("");
  const [syncNote, setSyncNote] = useState("");
  const blocked = page.unknown !== null;
  const allow = page.q.data;
  const s = status.q.data;

  page.setBoundaryCleanup(() => {
    setSyncError("");
    setSyncNote("");
  });

  const runSync = (): void => {
    const signal = status.owner.begin();
    setSyncing(true);
    setSyncError("");
    setSyncNote("");
    syncThreatFeeds(signal)
      .then((after) => {
        setSyncNote(
          after.threatFeedSyncOk === true
            ? `Sync completed — ${String(after.threatFeedEntries ?? 0)} entries.`
            : `Sync attempt finished with a failure${after.threatFeedSyncError !== undefined ? `: ${after.threatFeedSyncError}` : ""}. The previously synced data keeps enforcing.`,
        );
        status.refreshToResolve();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          // Imperative action with a lost answer: the sync may have run.
          // Nothing to repeat blindly — the status snapshot is the truth.
          setSyncNote(
            "The connection was lost before the sync result arrived — refresh the status to see whether it ran.",
          );
          status.refreshToResolve();
          return;
        }
        setSyncError(serverErrorText(err, "The sync request failed."));
      })
      .finally(() => {
        status.owner.settle(signal);
        setSyncing(false);
      });
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching || status.q.isFetching}
          error={page.q.isError || status.q.isError}
          hasData={allow !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
            status.refreshToResolve();
          }}
        />
      </div>

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the allowlist edit may or may not have been applied. Refresh and
            review the current list before further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh allowlist
              </Button>
            </div>
          </Callout>
        </div>
      )}

      <Card title="Feed synchronization">
        {s === undefined ? (
          status.q.isError ? (
            <p className={styles.refDetail}>Feed state could not be loaded.</p>
          ) : (
            <Skeleton>Loading feed state…</Skeleton>
          )
        ) : (
          <>
            <KeyValue
              items={[
                [
                  "Entries",
                  s.threatFeedEntries !== undefined
                    ? String(s.threatFeedEntries)
                    : "not reported",
                ],
                ["Interval", s.threatFeedInterval ?? "not reported"],
                [
                  "Last successful sync",
                  s.threatFeedLastSuccess !== undefined &&
                  s.threatFeedLastSuccess !== ""
                    ? s.threatFeedLastSuccess
                    : "never",
                ],
                [
                  "Last sync result",
                  s.threatFeedSyncOk === true ? (
                    "succeeded"
                  ) : s.threatFeedSyncError !== undefined ? (
                    <StatusBadge status="warn">
                      failed: {s.threatFeedSyncError}
                    </StatusBadge>
                  ) : (
                    "not reported"
                  ),
                ],
              ]}
            />
            {isAdmin && (
              <div className={styles.toolbarActions}>
                <Button size="sm" disabled={syncing} onClick={runSync}>
                  {syncing ? "Syncing…" : "Sync feeds now"}
                </Button>
              </div>
            )}
            {syncNote !== "" && (
              <p className={styles.refDetail} role="status">
                {syncNote}
              </p>
            )}
            {syncError !== "" && (
              <Callout variant="critical" title="Sync failed" role="alert">
                {syncError}
              </Callout>
            )}
          </>
        )}
      </Card>

      <Card title="Domain allowlist">
        <p className={styles.refDetail}>
          Allowlisted domains bypass DOMAIN-level threat-feed blocking;
          URL-level blocking still applies. This list is fleet-distributed from
          the control plane and deliberately outside config-version rollback.
        </p>
        {allow === undefined && page.q.isPending && (
          <Skeleton>Loading allowlist…</Skeleton>
        )}
        {allow === undefined && page.q.isError && (
          <ErrorState title="Allowlist unavailable">
            The domain allowlist could not be loaded. Refresh to try again.
          </ErrorState>
        )}
        {allow !== undefined &&
          (isAdmin ? (
            <FencedListEditor
              label="allowlisted domains"
              itemNoun="domain"
              current={allow.domains}
              revision={allow.revision}
              effect="Every domain on this list bypasses domain-level threat-feed blocking on the whole fleet the moment the change publishes. Removing a domain restores blocking for it."
              ceremonyTitle="Replace the threat-feed domain allowlist"
              page={page}
              blocked={blocked}
              unknownOp="edit"
              doSave={(items, ifRevision, signal) =>
                putDomainAllowlist(items, ifRevision, signal)
              }
              help="One domain per line. The appliance normalizes (trim, lowercase, dedupe)."
            />
          ) : (
            <p>
              {allow.domains.length === 0 ? (
                "No domains are allowlisted."
              ) : (
                <Mono>{allow.domains.join(" ")}</Mono>
              )}
            </p>
          ))}
      </Card>
    </div>
  );
}
