// FE-6A.2 — Administrators WRITE surface: the account editor, the ceremonies
// at their tiers and the bounded outcome callouts. Passwords live only in the
// editor's state and ride the body once; closing the dialog drops them.
import { useState } from "react";
import type { JSX } from "react";
import {
  Button,
  Callout,
  KeyValue,
  Mono,
} from "../../design-system/primitives";
import {
  ConfirmationDialog,
  Dialog,
  DialogBody,
  DialogFooter,
} from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { InputField, SelectField } from "../../design-system/forms";
import type { Role } from "../../api/auth";
import type { AdminRefusal, AdminUser, Lockout } from "../../api/admins";

export const ROLES: readonly Role[] = ["admin", "operator", "viewer"];

export interface AccountDraft {
  username: string;
  role: Role;
  password: string;
}

export function draftFromUser(u: AdminUser | null): AccountDraft {
  return {
    username: u?.username ?? "",
    role: u?.role ?? "viewer",
    password: "",
  };
}

export interface AccountCandidate {
  username: string;
  role: Role;
  /** undefined = unchanged (edit) */
  password?: string;
  roleChanged: boolean;
}

export function draftToCandidate(
  d: AccountDraft,
  mode: "create" | "edit",
  initial: AdminUser | null,
): AccountCandidate | string {
  const username = d.username.trim();
  if (username === "" || username.length > 64)
    return "A username of 1–64 characters is required.";
  if (mode === "create" && d.password === "")
    return "A password is required to create an account.";
  const roleChanged = mode === "create" || initial?.role !== d.role;
  if (mode === "edit" && !roleChanged && d.password === "")
    return "Nothing to save: change the role and/or set a new password.";
  return {
    username,
    role: d.role,
    ...(d.password !== "" ? { password: d.password } : {}),
    roleChanged,
  };
}

export function AccountEditorDialog(p: {
  mode: "create" | "edit";
  initial: AdminUser | null;
  draft: AccountDraft;
  onChange: (d: AccountDraft) => void;
  onReview: () => void;
  onCancel: () => void;
  pending: boolean;
  error: string | null;
  rosterRevision: number;
}): JSX.Element {
  const d = p.draft;
  return (
    <Dialog
      open
      onClose={p.pending ? () => undefined : p.onCancel}
      title={
        p.mode === "create"
          ? "New account"
          : `Edit account ${p.initial?.username ?? ""}`
      }
      closeOnEscape={!p.pending}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!p.pending) p.onReview();
        }}
      >
        <DialogBody>
          <KeyValue
            items={[["Fenced on roster revision", String(p.rosterRevision)]]}
          />
          {p.mode === "create" ? (
            <InputField
              label="Username"
              required
              maxLength={64}
              value={d.username}
              onChange={(e) => p.onChange({ ...d, username: e.target.value })}
              autoComplete="off"
            />
          ) : (
            <KeyValue
              items={[
                ["Username", <Mono key="u">{d.username}</Mono>],
                [
                  "TOTP",
                  p.initial?.totpEnabled === true
                    ? "configured — a password change preserves the enrollment"
                    : "not configured",
                ],
                [
                  "Security generation",
                  String(p.initial?.securityGeneration ?? 0),
                ],
              ]}
            />
          )}
          <SelectField
            label="Role"
            value={d.role}
            onChange={(e) => {
              const r = ROLES.find((x) => x === e.target.value);
              if (r !== undefined) p.onChange({ ...d, role: r });
            }}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </SelectField>
          <InputField
            label={p.mode === "create" ? "Password" : "New password"}
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            required={p.mode === "create"}
            help={
              p.mode === "create"
                ? "At least 8 characters with an uppercase letter, a lowercase letter and a digit (≤ 72 bytes)"
                : "Leave blank to keep the current password"
            }
            value={d.password}
            onChange={(e) => p.onChange({ ...d, password: e.target.value })}
          />
          {p.error !== null && (
            <Callout variant="critical" title="Cannot submit" role="alert">
              {p.error}
            </Callout>
          )}
        </DialogBody>
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            onClick={p.onCancel}
            disabled={p.pending}
          >
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={p.pending}>
            {p.mode === "create" ? "Review and create" : "Review and save"}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}

interface CeremonyCommon {
  result: ConfirmResult;
  errorText?: string;
  onCancel: () => void;
  onConfirm: () => void;
}

/** T2 — create or change an account (privilege and/or credential). */
export function AccountReviewCeremony(
  p: CeremonyCommon & {
    mode: "create" | "edit";
    candidate: AccountCandidate;
    initial: AdminUser | null;
    rosterRevision: number;
    self: boolean;
  },
): JSX.Element {
  const c = p.candidate;
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={
        p.mode === "create"
          ? "Review and create the account"
          : "Review and save the account"
      }
      body={
        <KeyValue
          items={[
            ["Username", <Mono key="u">{c.username}</Mono>],
            [
              "Role",
              p.mode === "edit" && p.initial !== null && c.roleChanged
                ? `${p.initial.role} → ${c.role}`
                : c.role,
            ],
            [
              "Password",
              c.password !== undefined
                ? "set (sent once, write-only)"
                : "unchanged",
            ],
            ["Fenced on roster revision", String(p.rosterRevision)],
          ]}
        />
      }
      impact={
        p.mode === "create"
          ? "A new local administrator-roster account is created on this node; its password is sent once and stored as a hash."
          : `${c.roleChanged || c.password !== undefined ? "The account's security generation advances and every session it holds is revoked." : "No change."}${p.self ? " This is YOUR account: you will be signed out." : ""}${p.initial?.totpEnabled === true ? " Its TOTP enrollment is preserved." : ""}`
      }
      rollback={
        p.mode === "create" ? "Delete the account." : "Edit the account again."
      }
      confirmLabel={p.mode === "create" ? "Create account" : "Save account"}
      destructive={p.mode === "edit"}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** T3 — delete requires the exact username; the roster revision is bound. */
export function DeleteAccountCeremony(
  p: CeremonyCommon & {
    user: AdminUser;
    rosterRevision: number;
    self: boolean;
  },
): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Delete account"
      body={
        <KeyValue
          items={[
            ["Username", <Mono key="u">{p.user.username}</Mono>],
            ["Role", p.user.role],
            ["Fenced on roster revision", String(p.rosterRevision)],
          ]}
        />
      }
      impact={`Every session of this account is revoked immediately; the last administrator is refused (409 last_admin).${p.self ? " This is YOUR account: you will be signed out." : ""}`}
      rollback="None — irreversible."
      confirmLabel="Delete account"
      confirmWord={p.user.username}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** T2 — clear every lock for the username, bound to the lock-set generation. */
export function ClearLockoutCeremony(
  p: CeremonyCommon & { lock: Lockout; generation: number },
): JSX.Element {
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Clear login lockouts"
      body={
        <KeyValue
          items={[
            ["Username", <Mono key="u">{p.lock.username}</Mono>],
            ["Fenced on lock-set generation", String(p.generation)],
          ]}
        />
      }
      impact="Every active lock for this username on this node is cleared; the account can log in immediately."
      rollback="None — the lock re-arms on further failed logins."
      confirmLabel="Clear lockouts"
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

const TITLES: Record<string, string> = {
  last_admin: "Refused — the last administrator cannot be demoted or deleted",
  user_exists:
    "Refused — an account with this username exists (create is never an upsert)",
  not_found: "Refused — the account no longer exists",
  invalid_input: "Refused — the appliance rejected the candidate",
  invalid_credentials: "Refused — the current password is incorrect",
  persist_failed: "Refused — the roster write did not persist; nothing changed",
  persistence_not_configured:
    "Refused — this node has no roster persistence path",
  forbidden: "Refused — insufficient role",
  method_not_allowed: "Refused — method not allowed",
};

export function AdminFenceCallout({
  refusal,
}: {
  refusal: AdminRefusal;
}): JSX.Element {
  const token =
    refusal.facts.generation !== undefined
      ? `${refusal.endpoint === "change_password" ? "security" : "lock-set"} generation ${String(refusal.facts.generation)}`
      : `roster revision ${String(refusal.facts.revision ?? 0)}`;
  return (
    <Callout
      variant="warning"
      title={
        refusal.code === "stale"
          ? "Stale fence — nothing was changed"
          : "Fence required — nothing was changed"
      }
      role="alert"
    >
      <Mono>{refusal.code}</Mono> (HTTP {String(refusal.status)}). The
      appliance's current {token}. Review the refreshed list and repeat the
      change; nothing was retried.
    </Callout>
  );
}

export function AdminRefusalCallout({
  refusal,
}: {
  refusal: AdminRefusal;
}): JSX.Element {
  return (
    <Callout
      variant="warning"
      title={TITLES[refusal.code] ?? "Refused"}
      role="alert"
    >
      <Mono>{refusal.code}</Mono> (HTTP {String(refusal.status)}) — nothing was
      changed.
    </Callout>
  );
}

export function AdminUnprovenCallout({
  action,
  status,
}: {
  action: string;
  status: number | undefined;
}): JSX.Element {
  return (
    <Callout
      variant="unknown"
      title={`Outcome unproven — ${action}`}
      role="alert"
    >
      The answer to this action could not be verified
      {status !== undefined ? ` (HTTP ${String(status)})` : ""}. The change may
      already be applied on the appliance and sessions may already be revoked;
      nothing was retried and nothing is claimed. Every mutation stays blocked
      until a roster read succeeds.
    </Callout>
  );
}
