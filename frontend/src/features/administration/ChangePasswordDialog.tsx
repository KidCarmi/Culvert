// FE-6A.2 — self-service password change (any authenticated role).
//
// The ceremony IS the dialog: it names the account, states the consequence
// (every session of this account is revoked, this browser signs out) and is
// fenced on the caller's own durable security generation (GET
// /api/auth/status → securityGeneration; without it no request is sent).
// Both passwords live ONLY in this component's state, ride the body once and
// are dropped when the dialog closes, the request completes, or the outcome
// becomes unproven. On success the appliance reports selfAffected:true — the
// shell completes the auth teardown and returns to the login boundary.
import { useState } from "react";
import type { JSX } from "react";
import { Button, Callout, Mono } from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { InputField } from "../../design-system/forms";
import { ApiError } from "../../api/client";
import {
  adminUnproven,
  asAdminRefusal,
  changeOwnPassword,
} from "../../api/admins";
import type { AdminRefusal } from "../../api/admins";

export type ChangePasswordOutcome =
  | { kind: "changed"; sessionsRevoked: boolean }
  | { kind: "unproven"; status: number | undefined };

export function ChangePasswordDialog({
  user,
  generation,
  onOutcome,
  onCancel,
}: {
  user: string;
  /** undefined ⇒ the fence is unavailable (bootstrap window): nothing is sent */
  generation: number | undefined;
  onOutcome: (o: ChangePasswordOutcome) => void;
  onCancel: () => void;
}): JSX.Element {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [pending, setPending] = useState(false);
  const [refusal, setRefusal] = useState<AdminRefusal | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const canSubmit =
    generation !== undefined && current !== "" && next !== "" && !pending;
  const submit = async (): Promise<void> => {
    if (!canSubmit || generation === undefined) return;
    setPending(true);
    setRefusal(null);
    setForbidden(false);
    const body = { currentPassword: current, newPassword: next };
    setCurrent("");
    setNext("");
    try {
      const r = await changeOwnPassword(body, generation);
      onOutcome({ kind: "changed", sessionsRevoked: r.sessionsRevoked });
    } catch (err) {
      const f = asAdminRefusal(err, "change_password");
      if (f !== null) {
        setRefusal(f);
        setPending(false);
        return;
      }
      if (err instanceof ApiError && err.forbidden) {
        setForbidden(true);
        setPending(false);
        return;
      }
      if (adminUnproven(err) || err instanceof ApiError) {
        onOutcome({
          kind: "unproven",
          status: err instanceof ApiError ? err.status : undefined,
        });
        return;
      }
      onOutcome({ kind: "unproven", status: undefined });
    }
  };
  return (
    <Dialog
      open
      onClose={pending ? () => undefined : onCancel}
      title="Change my password"
      closeOnEscape={!pending}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <DialogBody>
          <p>
            Account <Mono>{user}</Mono>. On success every session of this
            account is revoked and this browser signs out; sign in again with
            the new password.
            {generation !== undefined ? (
              <span> Fenced on security generation {String(generation)}.</span>
            ) : (
              <span>
                {" "}
                The security generation is not known for this session, so
                nothing can be sent.
              </span>
            )}
          </p>
          <InputField
            label="Current password"
            type="password"
            autoComplete="current-password"
            spellCheck={false}
            required
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            disabled={pending}
          />
          <InputField
            label="New password"
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            required
            help="At least 8 characters with an uppercase letter, a lowercase letter and a digit (≤ 72 bytes)"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            disabled={pending}
          />
          {refusal !== null && (
            <Callout
              variant="warning"
              title={refusalTitle(refusal)}
              role="alert"
            >
              <Mono>{refusal.code}</Mono> (HTTP {String(refusal.status)})
              {refusal.facts.generation !== undefined
                ? ` · current security generation ${String(refusal.facts.generation)} — refresh and retry`
                : ""}
              . Nothing was changed; re-enter both passwords.
            </Callout>
          )}
          {forbidden && (
            <Callout
              variant="warning"
              title="Refused — insufficient role"
              role="alert"
            >
              The appliance refused the change (HTTP 403); nothing was changed.
            </Callout>
          )}
        </DialogBody>
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            onClick={onCancel}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button type="submit" variant="danger" disabled={!canSubmit}>
            Change password
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}

function refusalTitle(r: AdminRefusal): string {
  switch (r.code) {
    case "invalid_credentials":
      return "Refused — the current password is incorrect";
    case "invalid_input":
      return "Refused — the new password does not meet the policy";
    case "stale":
      return "Refused — your security generation moved";
    case "precondition_required":
      return "Refused — the security generation fence is required";
    case "not_found":
      return "Refused — this account no longer exists";
    case "persistence_not_configured":
      return "Refused — this node has no roster persistence path";
    case "persist_failed":
      return "Refused — the roster write did not persist; nothing changed";
    default:
      return "Refused";
  }
}
