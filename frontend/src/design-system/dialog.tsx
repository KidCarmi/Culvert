// Dialog + ConfirmationDialog (FE-2 §7–§9).
//
// OQ-2 decision — Dialog: NATIVE <dialog> + internal wrapper. showModal()
// gives top-layer rendering, focus containment, inert background, ::backdrop,
// and Esc → cancel semantics from the platform; the wrapper adds initial
// focus, ceremony-aware Esc policy, and state sync. Radix Dialog was
// rejected: its positioning/presence layers write inline style attributes,
// which the CULVERT contract bans outright (style-src-attr 'none' doctrine,
// contract §4) — no dependency was added.
import { useEffect, useRef } from "react";
import type { FormEvent, JSX, ReactNode } from "react";
import { IconAlert, IconClose } from "./icons";
import { Button, Callout, IconButton, Spinner } from "./primitives";
import { InputField } from "./forms";
import styles from "./dialog.module.css";

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  /** false blocks Esc (pending destructive ceremonies). Default true. */
  closeOnEscape?: boolean;
  /** hide the X control (forced-choice ceremonies). Default shown. */
  dismissible?: boolean;
}

export function DialogBody({ children }: { children: ReactNode }): JSX.Element {
  return <div className={styles.body}>{children}</div>;
}

export function DialogFooter({
  children,
}: {
  children: ReactNode;
}): JSX.Element {
  return <footer className={styles.footer}>{children}</footer>;
}

export function Dialog({
  open,
  onClose,
  title,
  children,
  closeOnEscape = true,
  dismissible = true,
}: DialogProps): JSX.Element {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (el === null) return;
    if (open && !el.open) el.showModal(); // focus moves in; invoker focus is restored by the platform on close
    if (!open && el.open) el.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      className={styles.dialog}
      aria-labelledby={undefined}
      aria-label={title}
      onCancel={(e) => {
        if (!closeOnEscape) {
          e.preventDefault();
          return;
        }
        e.preventDefault(); // route through onClose so React state stays the owner
        onClose();
      }}
      onClose={() => {
        if (open) onClose(); // e.g. form method=dialog submits
      }}
    >
      <header className={styles.header}>
        <h2 className={styles.title}>{title}</h2>
        {dismissible && (
          <IconButton
            label="Close dialog"
            onClick={onClose}
            disabled={!closeOnEscape}
          >
            <IconClose />
          </IconButton>
        )}
      </header>
      {children}
    </dialog>
  );
}

// ── ConfirmationDialog ──────────────────────────────────────────────────────
// Tier 1: simple acknowledgement. Tier 2: impact-focused destructive
// confirmation. Tier 3: typed-word ceremony. `result` distinguishes
// "unknown" (submitted, outcome not observed — network died mid-flight) from
// success/failure as a FIRST-CLASS state.
//
// Future two-phase server ceremonies (Root-CA rotation): the caller performs
// the probe, then renders the server's warning via `impact` and holds the
// server confirmation_token itself — this component deliberately never
// invents or stores tokens (contract §8.D2).

export type ConfirmTier = 1 | 2 | 3;
export type ConfirmResult = "idle" | "pending" | "unknown" | "failed";

export interface ConfirmationDialogProps {
  open: boolean;
  tier: ConfirmTier;
  title: string;
  body: ReactNode;
  /** consequence statement; required for tier ≥ 2 */
  impact?: string;
  /** how to undo, or "None — irreversible" */
  rollback?: string;
  confirmLabel: string;
  /** tier 3: exact phrase the operator must type */
  confirmWord?: string;
  typedValue?: string;
  onTypedChange?: (v: string) => void;
  destructive?: boolean;
  result: ConfirmResult;
  errorText?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmationDialog(
  props: ConfirmationDialogProps,
): JSX.Element {
  const {
    open,
    tier,
    title,
    body,
    impact,
    rollback,
    confirmLabel,
    confirmWord,
    typedValue = "",
    onTypedChange,
    destructive = tier >= 2,
    result,
    errorText,
    onConfirm,
    onCancel,
  } = props;
  const pending = result === "pending";
  const typedOK =
    tier < 3 || (confirmWord !== undefined && typedValue === confirmWord);
  const canConfirm = typedOK && !pending;

  // Enter must not bypass the typed requirement or double-submit: the form's
  // submit handler re-checks; the button is the only submitter and is
  // disabled until the ceremony is satisfied.
  const submit = (e: FormEvent): void => {
    e.preventDefault();
    if (canConfirm) onConfirm();
  };

  return (
    <Dialog
      open={open}
      onClose={pending ? () => undefined : onCancel}
      title={title}
      closeOnEscape={!pending}
      dismissible={tier < 3}
    >
      <form onSubmit={submit}>
        <DialogBody>
          <div>{body}</div>
          {tier >= 2 && impact !== undefined && (
            <div className={styles.impact}>
              <div className={styles.impactTitle}>
                <IconAlert /> Impact
              </div>
              {impact}
              {rollback !== undefined && (
                <div className={styles.rollback}>Rollback: {rollback}</div>
              )}
            </div>
          )}
          {tier === 3 && confirmWord !== undefined && (
            <InputField
              label={`Type ${confirmWord} to confirm`}
              autoComplete="off"
              spellCheck={false}
              value={typedValue}
              onChange={(e) => onTypedChange?.(e.target.value)}
              disabled={pending}
            />
          )}
          {result === "unknown" && (
            <Callout
              variant="unknown"
              title="Action state is unknown"
              role="alert"
            >
              The request was submitted but no result was observed. Do not retry
              blindly — verify the current state first.
            </Callout>
          )}
          {result === "failed" && errorText !== undefined && (
            <Callout variant="critical" title="Action failed" role="alert">
              {errorText}
            </Callout>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </Button>
          <Button
            variant={destructive ? "danger" : "primary"}
            type="submit"
            disabled={!canConfirm}
            aria-disabled={!canConfirm}
          >
            {pending ? <Spinner label="Working" /> : null}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
