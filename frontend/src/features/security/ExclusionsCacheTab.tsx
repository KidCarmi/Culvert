// 2E-A Exclusions & Cache: the admin scan-exclusion lists (trust-elevation —
// excluded hashes/hosts skip ALL body scanning; deliberately OFF the
// config-version rollback surface) and the scan verdict cache with its
// destructive clear ceremony.
import { useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { TextareaField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { asRevisionConflict } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  clearScanCache,
  getScanCache,
  getScanExclusions,
  putScanExclusions,
} from "../../api/contentsec";
import { diffCounts, splitLines } from "./FencedListEditor";
import styles from "../policy/policy.module.css";

export function ExclusionsCacheTab({
  isAdmin,
}: {
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(
    ["security", "content", "exclusions"],
    getScanExclusions,
  );
  const cache = useObjectPage(
    ["security", "content", "cache-mgmt"],
    getScanCache,
  );
  const excl = page.q.data;
  const [clearing, setClearing] = useState(false);

  const refreshAll = (): void => {
    page.refreshToResolve();
    cache.refreshToResolve();
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching || cache.q.isFetching}
          error={page.q.isError || cache.q.isError}
          hasData={excl !== undefined}
          onRefresh={refreshAll}
        />
      </div>

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the exclusion edit may or may not have been applied. Refresh and
            review the lists before further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh exclusions
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {excl === undefined && page.q.isPending && (
        <Skeleton>Loading scan exclusions…</Skeleton>
      )}
      {excl === undefined && page.q.isError && (
        <ErrorState title="Scan exclusions unavailable">
          The exclusion lists could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {excl !== undefined && (
        <Card title="Scan exclusions">
          <p className={styles.refDetail}>
            Excluded SHA-256 hashes and hosts skip ALL body scanning (ClamAV,
            YARA, DPI). This is a trust-elevation list; it is deliberately
            outside config-version rollback so a rollback can never silently
            re-trust a removed entry.
          </p>
          {isAdmin ? (
            <ExclusionsEditor page={page} excl={excl} />
          ) : (
            <KeyValue
              items={[
                [
                  "Excluded hashes",
                  excl.hashes.length === 0 ? (
                    "none"
                  ) : (
                    <Mono>{excl.hashes.join(" ")}</Mono>
                  ),
                ],
                [
                  "Excluded hosts",
                  excl.hosts.length === 0 ? (
                    "none"
                  ) : (
                    <Mono>{excl.hosts.join(" ")}</Mono>
                  ),
                ],
              ]}
            />
          )}
        </Card>
      )}

      <Card title="Scan verdict cache">
        {cache.q.data === undefined ? (
          cache.q.isError ? (
            <p className={styles.refDetail}>
              The cache state could not be loaded.
            </p>
          ) : (
            <Skeleton>Loading cache state…</Skeleton>
          )
        ) : cache.q.data.enabled ? (
          <>
            <KeyValue
              items={[
                ["Entries", String(cache.q.data.cacheSize ?? 0)],
                ["Hits", String(cache.q.data.cacheHits ?? 0)],
                ["Misses", String(cache.q.data.cacheMisses ?? 0)],
              ]}
            />
            {isAdmin && (
              <div className={styles.toolbarActions}>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setClearing(true);
                  }}
                >
                  Clear cache…
                </Button>
              </div>
            )}
          </>
        ) : (
          <p className={styles.refDetail}>
            The scan verdict cache is not enabled on this appliance.
          </p>
        )}
      </Card>

      {clearing && isAdmin && (
        <ClearCacheDialog
          page={cache}
          onDone={() => {
            setClearing(false);
            cache.refreshToResolve();
          }}
          onCancel={() => {
            setClearing(false);
          }}
        />
      )}
    </div>
  );
}

// One fenced PUT covers BOTH lists — the editor submits them together so two
// admins cannot interleave a hash edit and a host edit unseen.
function ExclusionsEditor({
  page,
  excl,
}: {
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getScanExclusions>>>
  >;
  excl: Awaited<ReturnType<typeof getScanExclusions>>;
}): JSX.Element {
  const [hashText, setHashText] = useState(excl.hashes.join("\n"));
  const [hostText, setHostText] = useState(excl.hosts.join("\n"));
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [serverError, setServerError] = useState("");
  const [notice, setNotice] = useState("");

  const nextHashes = splitLines(hashText);
  const nextHosts = splitLines(hostText);
  const dHash = diffCounts(excl.hashes, nextHashes);
  const dHost = diffCounts(excl.hosts, nextHosts);
  const dirty =
    dHash.added + dHash.removed + dHost.added + dHost.removed > 0 ||
    nextHashes.length !== excl.hashes.length ||
    nextHosts.length !== excl.hosts.length;

  const commit = (): void => {
    const signal = page.owner.begin();
    setResult("pending");
    setServerError("");
    putScanExclusions(nextHashes, nextHosts, excl.revision, signal)
      .then(() => {
        setConfirming(false);
        setResult("idle");
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
          setNotice(
            "The exclusions changed on the appliance since you loaded them. Nothing was applied — review the refreshed lists and reapply.",
          );
          page.refreshToResolve();
          return;
        }
        setResult("failed");
        setServerError(
          serverErrorText(err, "The appliance rejected the exclusion update."),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
      });
  };

  return (
    <div>
      {notice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Not applied" role="alert">
            {notice}
          </Callout>
        </div>
      )}
      <TextareaField
        label="Excluded SHA-256 hashes (one per line)"
        value={hashText}
        rows={5}
        onChange={(e) => {
          setHashText(e.target.value);
          setNotice("");
        }}
      />
      <TextareaField
        label="Excluded hosts (one per line)"
        value={hostText}
        rows={5}
        onChange={(e) => {
          setHostText(e.target.value);
          setNotice("");
        }}
      />
      <div className={styles.toolbarActions}>
        <Button
          size="sm"
          disabled={page.unknown !== null || !dirty}
          onClick={() => {
            setConfirming(true);
            setServerError("");
          }}
        >
          Save exclusions
        </Button>
        {dirty && (
          <span className={styles.counts}>
            hashes: {String(dHash.added)} added, {String(dHash.removed)} removed
            · hosts: {String(dHost.added)} added, {String(dHost.removed)}{" "}
            removed
          </span>
        )}
      </div>
      <ConfirmationDialog
        open={confirming}
        tier={2}
        title="Replace the scan exclusion lists"
        body={
          <>
            This replaces both exclusion lists in one write:{" "}
            {String(nextHashes.length)}{" "}
            {nextHashes.length === 1 ? "hash" : "hashes"} ({String(dHash.added)}{" "}
            added, {String(dHash.removed)} removed) and{" "}
            {String(nextHosts.length)}{" "}
            {nextHosts.length === 1 ? "host" : "hosts"} ({String(dHost.added)}{" "}
            added, {String(dHost.removed)} removed).
          </>
        }
        impact="Every excluded hash and host skips ALL body scanning (ClamAV, YARA, DPI). Additions widen the unscanned set immediately; removals restore scanning."
        rollback="Re-save the previous lists (they remain visible until you refresh)."
        confirmLabel="Replace exclusions"
        destructive
        result={result}
        {...(serverError !== "" ? { errorText: serverError } : {})}
        onConfirm={commit}
        onCancel={() => {
          setConfirming(false);
          setResult("idle");
        }}
      />
    </div>
  );
}

function ClearCacheDialog({
  page,
  onDone,
  onCancel,
}: {
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getScanCache>>>
  >;
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Clear the scan verdict cache"
      body={
        <>
          This clears the ENTIRE scan verdict cache on this node. Every cached
          clean/blocked verdict is discarded.
        </>
      }
      impact="All content is re-scanned on next access until the cache re-warms — scan load increases temporarily; no verdict is lost permanently (the cache is volatile runtime state)."
      rollback="None — the cache rebuilds from traffic."
      confirmLabel="Clear cache"
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        const signal = page.owner.begin();
        setResult("pending");
        clearScanCache(signal)
          .then(onDone)
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              // Idempotent destructive action: the truth is one refresh away.
              setResult("unknown");
              onCancel();
              page.refreshToResolve();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The cache clear failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={onCancel}
    />
  );
}
