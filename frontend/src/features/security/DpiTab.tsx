// 2E-A DPI: signature patterns (canonical /api/dpi — the deprecated
// /api/content-scan aliases are compatibility surfaces, never requested) and
// the fenced bypass-host list. Pattern add/remove is Operator+ (item-level,
// no fence — the appliance's own contract); removing a pattern is a ceremony
// because it reduces scanning coverage. Bypass replace is Admin, fenced.
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
import { InputField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  addDpiPattern,
  getDpi,
  getDpiBypass,
  putDpiBypass,
  removeDpiPattern,
} from "../../api/contentsec";
import { FencedListEditor } from "./FencedListEditor";
import styles from "../policy/policy.module.css";

export function DpiTab({
  isOperator,
  isAdmin,
}: {
  isOperator: boolean;
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(["security", "content", "dpi"], getDpi);
  const bypass = useObjectPage(
    ["security", "content", "dpi-bypass"],
    getDpiBypass,
  );
  const dpi = page.q.data;
  const [newPattern, setNewPattern] = useState("");
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [serverError, setServerError] = useState("");
  const blocked = page.unknown !== null;

  page.setBoundaryCleanup(() => {
    setNewPattern("");
    setRemoving(null);
    setServerError("");
  });

  const refreshAll = (): void => {
    page.refreshToResolve();
    bypass.refreshToResolve();
  };

  const add = (): void => {
    if (newPattern.trim() === "") return;
    const signal = page.owner.begin();
    setAdding(true);
    setServerError("");
    addDpiPattern(newPattern.trim(), signal)
      .then(() => {
        setNewPattern("");
        page.refreshToResolve();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("create");
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance rejected the pattern."),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
        setAdding(false);
      });
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching || bypass.q.isFetching}
          error={page.q.isError || bypass.q.isError}
          hasData={dpi !== undefined}
          onRefresh={refreshAll}
        />
      </div>

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the DPI change may or may not have been applied. Refresh and review
            the patterns before further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={refreshAll}>
                Refresh patterns
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {dpi === undefined && page.q.isPending && (
        <Skeleton>Loading DPI patterns…</Skeleton>
      )}
      {dpi === undefined && page.q.isError && (
        <ErrorState title="DPI patterns unavailable">
          The DPI pattern list could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {dpi !== undefined && (
        <Card title="Signature patterns">
          <KeyValue
            items={[
              ["Patterns", String(dpi.count)],
              ["Requests blocked by DPI", String(dpi.blockedTotal)],
            ]}
          />
          {isOperator && (
            <div className={styles.toolbarActions}>
              <InputField
                label="New pattern (regular expression)"
                value={newPattern}
                disabled={adding}
                onChange={(e) => {
                  setNewPattern(e.target.value);
                }}
              />
              <Button
                size="sm"
                disabled={adding || blocked || newPattern.trim() === ""}
                onClick={add}
              >
                Add pattern
              </Button>
            </div>
          )}
          {serverError !== "" && (
            <Callout variant="critical" title="Not applied" role="alert">
              {serverError}
            </Callout>
          )}
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">DPI patterns</caption>
              <thead>
                <tr>
                  <th scope="col">Pattern</th>
                  {isOperator && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {dpi.patterns.length === 0 && (
                  <tr>
                    <td colSpan={isOperator ? 2 : 1}>
                      No DPI patterns are configured — DPI content matching is
                      inactive.
                    </td>
                  </tr>
                )}
                {dpi.patterns.map((p) => (
                  <tr key={p}>
                    <td>
                      <Mono>{p}</Mono>
                    </td>
                    {isOperator && (
                      <td>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={blocked}
                          aria-label={`Remove pattern ${p}`}
                          onClick={() => {
                            setRemoving(p);
                          }}
                        >
                          Remove
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {removing !== null && isOperator && (
        <RemovePatternDialog
          pattern={removing}
          page={page}
          onDone={() => {
            setRemoving(null);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setRemoving(null);
          }}
        />
      )}

      <Card title="Bypass hosts">
        <p className={styles.refDetail}>
          Hosts on this list skip DPI content inspection entirely. The list is
          on the config-version rollback surface.
        </p>
        {bypass.q.data === undefined && bypass.q.isPending && (
          <Skeleton>Loading bypass hosts…</Skeleton>
        )}
        {bypass.q.data === undefined && bypass.q.isError && (
          <p className={styles.refDetail}>
            The bypass list could not be loaded.
          </p>
        )}
        {bypass.q.data !== undefined &&
          (isAdmin ? (
            <FencedListEditor
              label="DPI bypass hosts"
              itemNoun="host"
              current={bypass.q.data.hosts}
              revision={bypass.q.data.revision}
              effect="Traffic to every host on this list is NOT inspected by DPI patterns. Adding hosts reduces scanning coverage; removing hosts restores it."
              ceremonyTitle="Replace the DPI bypass host list"
              page={bypass}
              blocked={bypass.unknown !== null}
              unknownOp="edit"
              doSave={(items, ifRevision, signal) =>
                putDpiBypass(items, ifRevision, signal)
              }
              help="One host per line. The appliance lowercases and strips ports."
            />
          ) : (
            <p>
              {bypass.q.data.hosts.length === 0 ? (
                "No bypass hosts."
              ) : (
                <Mono>{bypass.q.data.hosts.join(" ")}</Mono>
              )}
            </p>
          ))}
        {bypass.unknown !== null && (
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The bypass edit&apos;s outcome is unconfirmed — refresh before
            further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={bypass.refreshToResolve}>
                Refresh bypass hosts
              </Button>
            </div>
          </Callout>
        )}
      </Card>
    </div>
  );
}

function RemovePatternDialog({
  pattern,
  page,
  onDone,
  onCancel,
}: {
  pattern: string;
  page: ReturnType<typeof useObjectPage<Awaited<ReturnType<typeof getDpi>>>>;
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Remove DPI pattern"
      body={
        <>
          This removes the pattern <Mono>{pattern}</Mono> from DPI content
          matching.
        </>
      }
      impact="Content matching this pattern is no longer blocked by DPI."
      rollback="Re-add the pattern."
      confirmLabel="Remove pattern"
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        const signal = page.owner.begin();
        setResult("pending");
        removeDpiPattern(pattern, signal)
          .then(onDone)
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The removal failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={onCancel}
    />
  );
}
