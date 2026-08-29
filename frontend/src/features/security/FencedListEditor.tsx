// 2E-A shared whole-set list editor: one textarea (one entry per line), the
// content-revision fence, the T2 replace ceremony (exact add/remove counts +
// surface-specific effect statement — never a generic "are you sure"), the
// structured-conflict fresh-truth flow, and the unknown-outcome latch.
//
// The parent mounts this ONLY for roles the backend permits to write; viewers
// get the read-only presentation the parent renders instead.
import { useState, type JSX, type ReactNode } from "react";
import { Button, Callout } from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { TextareaField } from "../../design-system/forms";
import { asRevisionConflict } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import type { ObjectPageState } from "../objects/useObjectPage";
import styles from "../policy/policy.module.css";

export function splitLines(text: string): readonly string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/** Extracts a decoded FleetPublication rejection fact from a save result
 * (2E-A-2 §4): present ⇒ the LOCAL durable save succeeded but the fleet
 * config publish was rejected — two distinct facts, rendered as such. */
export function publishRejectedOf(res: unknown): string | undefined {
  if (typeof res !== "object" || res === null) return undefined;
  const v: unknown = Reflect.get(res, "publishRejected");
  return typeof v === "string" && v !== "" ? v : undefined;
}

export function diffCounts(
  current: readonly string[],
  next: readonly string[],
): { added: number; removed: number } {
  const cur = new Set(current.map((s) => s.toLowerCase()));
  const nxt = new Set(next.map((s) => s.toLowerCase()));
  let added = 0;
  let removed = 0;
  for (const n of nxt) if (!cur.has(n)) added++;
  for (const c of cur) if (!nxt.has(c)) removed++;
  return { added, removed };
}

export function FencedListEditor({
  label,
  itemNoun,
  current,
  revision,
  effect,
  ceremonyTitle,
  page,
  blocked,
  unknownOp,
  doSave,
  help,
}: {
  label: string;
  itemNoun: string;
  current: readonly string[];
  revision: string;
  /** Surface-specific consequence statement shown in the ceremony Impact. */
  effect: string;
  ceremonyTitle: string;
  page: ObjectPageState<unknown>;
  blocked: boolean;
  unknownOp: "edit";
  doSave: (
    items: readonly string[],
    ifRevision: string,
    signal: AbortSignal,
  ) => Promise<unknown>;
  help?: ReactNode;
}): JSX.Element {
  const [text, setText] = useState(current.join("\n"));
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [serverError, setServerError] = useState("");
  const [notice, setNotice] = useState("");
  const [publishRejected, setPublishRejected] = useState("");

  const next = splitLines(text);
  const { added, removed } = diffCounts(current, next);
  const dirty = added > 0 || removed > 0 || next.length !== current.length;

  const commit = (): void => {
    const signal = page.owner.begin();
    setResult("pending");
    setServerError("");
    setPublishRejected("");
    doSave(next, revision, signal)
      .then((res) => {
        setConfirming(false);
        setResult("idle");
        const rej = publishRejectedOf(res);
        if (rej !== undefined) setPublishRejected(rej);
        page.refreshToResolve();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown(unknownOp);
          setConfirming(false);
          setResult("idle");
          return;
        }
        const conflict = asRevisionConflict(err);
        if (conflict !== null) {
          setConfirming(false);
          setResult("idle");
          setNotice(
            `The ${label} changed on the appliance since you loaded it. Nothing was applied — review the refreshed list and reapply your edit.`,
          );
          page.refreshToResolve();
          return;
        }
        setResult("failed");
        setServerError(
          serverErrorText(err, `The appliance rejected the ${label} update.`),
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
      {publishRejected !== "" && (
        <div className={styles.calloutSpace}>
          <Callout
            variant="critical"
            title="Saved on this node — fleet publication rejected"
            role="alert"
          >
            The {label} was saved and is enforcing on THIS node, but publishing
            the configuration to the fleet was rejected: {publishRejected}.
            Data-plane nodes keep the previous configuration until a publish
            succeeds.
          </Callout>
        </div>
      )}
      <TextareaField
        label={label}
        value={text}
        rows={6}
        onChange={(e) => {
          setText(e.target.value);
          setNotice("");
        }}
      />
      {help !== undefined && <p className={styles.refDetail}>{help}</p>}
      <div className={styles.toolbarActions}>
        <Button
          size="sm"
          disabled={blocked || !dirty}
          onClick={() => {
            setConfirming(true);
            setServerError("");
          }}
        >
          Save {label}
        </Button>
        {dirty && (
          <span className={styles.counts}>
            {String(added)} added, {String(removed)} removed
          </span>
        )}
      </div>
      <ConfirmationDialog
        open={confirming}
        tier={2}
        title={ceremonyTitle}
        body={
          <>
            This replaces the {label} with {String(next.length)}{" "}
            {next.length === 1 ? itemNoun : `${itemNoun}s`} ({String(added)}{" "}
            added, {String(removed)} removed).
          </>
        }
        impact={effect}
        rollback="Re-save the previous list (it remains visible until you refresh)."
        confirmLabel={`Replace ${label}`}
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
