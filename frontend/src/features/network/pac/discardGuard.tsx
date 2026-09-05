// 2F-E correction (finding 4) — a discard guard for LOCAL navigation: PAC
// tabs and the profile detail's "← All profiles" are React state changes,
// not pathname changes, so `useDirtyGuard` (a router blocker) never sees
// them. This hook gates a state transition on the operator's confirmation
// while an editor holds unsaved work. Nothing is persisted; the transition
// runs only after "Discard and leave".
import { useState, type JSX } from "react";
import { ConfirmationDialog } from "../../../design-system/dialog";

export interface DiscardGuard {
  /** run `next` now when nothing is dirty, else ask first */
  request: (dirty: boolean, next: () => void) => void;
  element: JSX.Element | null;
}

export function useDiscardGuard(what: string): DiscardGuard {
  const [pending, setPending] = useState<(() => void) | null>(null);
  return {
    request: (dirty, next) => {
      if (!dirty) {
        next();
        return;
      }
      setPending(() => next);
    },
    element:
      pending === null ? null : (
        <ConfirmationDialog
          open
          tier={1}
          title="Discard unsaved changes?"
          body={
            <>
              Leaving discards {what}. Nothing has been sent to the appliance.
            </>
          }
          confirmLabel="Discard and leave"
          destructive
          result="idle"
          onConfirm={() => {
            const next = pending;
            setPending(null);
            next();
          }}
          onCancel={() => {
            setPending(null);
          }}
        />
      ),
  };
}
