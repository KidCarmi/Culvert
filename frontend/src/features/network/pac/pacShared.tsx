// 2F-E — shared PAC surface pieces: the fence / issues / challenge-stale
// callouts, the bound DIRECT challenge ceremony, and the copy that names
// what DIRECT means (a FULL security-path bypass — the legacy panel's
// exact wording, kept verbatim so both surfaces say the same thing).
import { useState, type JSX } from "react";
import { Callout, Mono } from "../../../design-system/primitives";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../../design-system/dialog";
import type {
  PacChallenge,
  PacFenceRefusal,
  PacIssuesRefusal,
} from "../../../api/pac";
import { fenceCurrentNumber } from "../../../api/pac";

export const DIRECT_IMPACT =
  "DIRECT is a FULL security-path bypass — matching traffic skips SSL inspection, content scanning (ClamAV/YARA/DPI), CDR, Blocklist/URL Category enforcement, Threat Feed, authentication, policy, and all proxy logging (it never reaches Culvert).";

export const NODE_LOCAL_NOTE =
  "Node-local: the draft, the publish history and DIRECT-exception governance live on this appliance only (never cluster-synced, never on config-version rollback). After a failover the promoted node serves the active profile but carries no rollback targets until its lifecycle file is restored.";

/** The 2F-A fence rendered as fresh truth: nothing was changed. */
export function FenceCallout({
  fence,
  tokenLabel,
}: {
  fence: PacFenceRefusal;
  tokenLabel: string;
}): JSX.Element {
  const key =
    tokenLabel === "draft revision"
      ? "draftRevision"
      : tokenLabel === "revision"
        ? "revision"
        : tokenLabel;
  const n = fenceCurrentNumber(fence, key);
  const cur = fence.current[key];
  const shown =
    n !== undefined
      ? String(n)
      : typeof cur === "string"
        ? cur
        : JSON.stringify(fence.current);
  return (
    <Callout
      variant="warning"
      title={
        fence.code === "stale" ? "Stale write refused" : "Precondition required"
      }
      role="alert"
    >
      {fence.code === "stale"
        ? `The object changed since you loaded it — the appliance refused (current ${tokenLabel} ${shown}). Nothing was changed. Refresh, review again, then retry.`
        : `The appliance requires the ${tokenLabel} you loaded (current ${tokenLabel} ${shown}). Nothing was changed.`}
    </Callout>
  );
}

export function IssuesCallout({
  issues,
}: {
  issues: PacIssuesRefusal;
}): JSX.Element {
  return (
    <Callout variant="critical" title={issues.error} role="alert">
      <ul>
        {issues.issues.map((i, idx) => (
          <li key={`${i.code}-${String(idx)}`}>
            <Mono>{i.code}</Mono> {i.field !== "" ? `${i.field}: ` : ""}
            {i.message}
            {i.entry !== "" ? ` (${i.entry})` : ""}
          </li>
        ))}
      </ul>
    </Callout>
  );
}

/** A challenge_stale answer: the reviewed binding no longer holds. */
export function ChallengeStaleCallout({
  challenge,
}: {
  challenge: PacChallenge;
}): JSX.Element {
  return (
    <Callout
      variant="warning"
      title="Challenge invalidated — nothing was changed"
      role="alert"
    >
      The reviewed DIRECT challenge no longer matches the appliance: changed{" "}
      {challenge.changed.length > 0 ? (
        challenge.changed.map((c) => (
          <span key={c}>
            <Mono>{c}</Mono>{" "}
          </span>
        ))
      ) : (
        <Mono>challenge</Mono>
      )}
      . Refresh, review the fresh binding, and confirm again.
    </Callout>
  );
}

export interface ChallengeCeremonyProps {
  open: boolean;
  actionLabel: string; // "Publish bypass" | "Roll back with bypass" | "Create with bypass"
  challenge: PacChallenge;
  result: ConfirmResult;
  errorText: string;
  onConfirm: (typed: string) => void;
  onCancel: () => void;
}

/** The bound DIRECT challenge (C2): the operator reviews the server-issued
 * binding (the exact new DIRECT paths) and retypes the server's
 * confirmValue; the dialog never invents or stores tokens — the caller
 * echoes {challenge, value, binding} verbatim. */
export function ChallengeCeremony(p: ChallengeCeremonyProps): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open={p.open}
      tier={3}
      title="New DIRECT paths require confirmation"
      body={
        <div>
          <p>
            {p.challenge.message !== ""
              ? p.challenge.message
              : "This change introduces new DIRECT (full security-path bypass) paths."}
          </p>
          <ul>
            {p.challenge.newDirectPaths.map((d) => (
              <li key={d}>
                <Mono>{d}</Mono>
              </li>
            ))}
          </ul>
          <p>
            Confirmation value:{" "}
            <code data-testid="pac-confirm-value">
              {p.challenge.confirmValue}
            </code>
          </p>
        </div>
      }
      impact={DIRECT_IMPACT}
      rollback="Roll back to the previous revision from the history (a new revision; the bypass stays in the history)."
      confirmLabel={p.actionLabel}
      confirmWord={p.challenge.confirmValue}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== "" ? { errorText: p.errorText } : {})}
      onConfirm={() => {
        p.onConfirm(typed);
      }}
      onCancel={() => {
        setTyped("");
        p.onCancel();
      }}
    />
  );
}
