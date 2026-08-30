// 2E-B Health & Coverage: the read-only decryption coverage + failure
// aggregate. FACTS ONLY — no derived "health score", no "fully inspected"
// claims. Counters are PROCESS-LIFETIME (they reset when the appliance
// restarts) and are labeled as such; the trend is per-minute deltas over the
// most recent 6 hours (volatile). Unknown taxonomy keys render verbatim.
import { Link } from "react-router";
import type { JSX } from "react";
import {
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { getDecryptionHealth, type CounterMap } from "../../api/decryption";
import styles from "../policy/policy.module.css";

function CounterTable({
  caption,
  map,
}: {
  caption: string;
  map: CounterMap;
}): JSX.Element {
  const keys = Object.keys(map).sort();
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{caption}</th>
            <th scope="col">Sessions</th>
          </tr>
        </thead>
        <tbody>
          {keys.length === 0 && (
            <tr>
              <td colSpan={2}>No sessions recorded since process start.</td>
            </tr>
          )}
          {keys.map((k) => (
            <tr key={k}>
              <td>
                <Mono>{k}</Mono>
              </td>
              <td>{String(map[k])}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DecryptionHealthTab(): JSX.Element {
  const page = useObjectPage(
    ["security", "decryption", "health"],
    getDecryptionHealth,
  );
  const h = page.q.data;

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={h !== undefined}
          onRefresh={page.refreshToResolve}
        />
      </div>

      {h === undefined && page.q.isPending && (
        <Skeleton>Loading decryption health…</Skeleton>
      )}
      {h === undefined && page.q.isError && (
        <ErrorState title="Decryption health unavailable">
          The decryption health aggregate could not be loaded. Refresh to try
          again.
        </ErrorState>
      )}

      {h !== undefined && (
        <>
          <Card title="Coverage — since process start">
            <p className={styles.refDetail}>
              Lifetime counters since the appliance process started (they reset
              on restart). The coverage ratio is inspected ÷ (inspected +
              bypassed); failures are a separate bucket — an attempted
              decryption that failed is triage work, not a deliberate coverage
              choice.
            </p>
            <KeyValue
              items={[
                ["Inspected sessions", String(h.inspected)],
                ["Bypassed / excluded sessions", String(h.bypassed)],
                ["Failed sessions", String(h.failed)],
                [
                  "Inspection coverage",
                  h.inspected + h.bypassed === 0
                    ? "no TLS sessions decisioned yet"
                    : `${(h.inspectedRatio * 100).toFixed(1)}%`,
                ],
              ]}
            />
            <p className={styles.refDetail}>
              Decryption behavior is configured on{" "}
              <Link to="/objects/decryption-profiles">
                Objects → Decryption Profiles
              </Link>
              ; this page never edits profiles.
            </p>
          </Card>

          <Card title="Sessions — since process start">
            <CounterTable caption="By outcome" map={h.byOutcome} />
            <CounterTable
              caption="By decision source"
              map={h.byDecisionSource}
            />
            <CounterTable caption="By TLS version" map={h.byTLSVersion} />
          </Card>

          <Card title="Failure taxonomy — since process start">
            {h.failuresTotal === 0 ? (
              <p>No decryption failures recorded since process start.</p>
            ) : (
              <>
                <KeyValue
                  items={[["Total failures", String(h.failuresTotal)]]}
                />
                <CounterTable caption="By category" map={h.byCategory} />
                <CounterTable caption="By stage" map={h.byStage} />
                <div className={styles.tableWrap}>
                  <table className={styles.table}>
                    <caption className="sr-only">Top failure series</caption>
                    <thead>
                      <tr>
                        <th scope="col">Category</th>
                        <th scope="col">Stage</th>
                        <th scope="col">Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {h.topFailures.map((f) => (
                        <tr key={`${f.category}/${f.stage}`}>
                          <td>
                            <Mono>{f.category}</Mono>
                          </td>
                          <td>
                            <Mono>{f.stage}</Mono>
                          </td>
                          <td>{String(f.count)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Card>

          <Card title="Coverage trend — per-minute deltas, most recent 6 hours">
            <p className={styles.refDetail}>
              Each sample is the coverage delta over one minute (volatile —
              resets on restart). {String(h.trend.length)} sample(s) recorded.
            </p>
            {h.trend.length > 0 && (
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <caption className="sr-only">Recent coverage samples</caption>
                  <thead>
                    <tr>
                      <th scope="col">Time</th>
                      <th scope="col">Inspected</th>
                      <th scope="col">Bypassed</th>
                      <th scope="col">Failed</th>
                      <th scope="col">Ratio</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.trend.slice(-10).map((s) => (
                      <tr key={s.ts}>
                        <td>{new Date(s.ts).toLocaleTimeString()}</td>
                        <td>{String(s.inspected)}</td>
                        <td>{String(s.bypassed)}</td>
                        <td>{String(s.failed)}</td>
                        <td>
                          {s.inspected + s.bypassed === 0
                            ? "—"
                            : `${(s.ratio * 100).toFixed(1)}%`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="Adaptive auto-exclusions">
            <KeyValue
              items={[
                ["Active learned exclusions", String(h.autoexcludeActive)],
                ["Pending observations", String(h.autoexcludePending)],
                ["Bypass hits (lifetime)", String(h.autoexcludeHits)],
                ["Live rescues (lifetime)", String(h.autoexcludeRescues)],
                ["Fail-open profiles", String(h.failOpenProfiles)],
                ["Rules referencing fail-open", String(h.failOpenRules)],
              ]}
            />
            {h.failOpenProfiles === 0 && h.failOpenRules === 0 && (
              <Callout variant="info" title="Auto-exclusion is inert">
                No Decryption Profile opts into fail-open, so nothing can
                automatically exclude a destination from inspection on this
                node.
              </Callout>
            )}
            <p className={styles.refDetail}>
              Manage the learned entries in the Auto-Exclusions tab.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}
