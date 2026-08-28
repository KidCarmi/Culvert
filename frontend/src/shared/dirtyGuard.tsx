// 2B §27 — SMALL targeted dirty-route guard for the first real configuration
// drafts in the frontend (rule editor form, staged reorder, commit comment).
// Internal navigation with unsaved local changes requires a deliberate
// confirmation; browser reload/close gets the minimal beforeunload prompt
// while dirty. Nothing is persisted — an auth boundary unmounts the surface
// and the local intent is discarded with it (never offered to the next
// identity). This is deliberately NOT a form framework.
import { useEffect, type JSX } from "react";
import { useBlocker } from "react-router";
import { ConfirmationDialog } from "../design-system/dialog";

export interface DirtyGuard {
  /** render this near the page root — the confirmation for blocked navigation */
  element: JSX.Element | null;
}

/** Blocks internal navigation and arms beforeunload while `dirty` is true.
 * `what` names the unsaved thing ("rule edits", "the staged reorder"). */
export function useDirtyGuard(dirty: boolean, what: string): DirtyGuard {
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      dirty && currentLocation.pathname !== nextLocation.pathname,
  );

  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent): void => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => {
      window.removeEventListener("beforeunload", handler);
    };
  }, [dirty]);

  // A blocker can be left in the blocked state after the dirty condition
  // cleared (e.g. the form was saved while the dialog was open) — release it.
  useEffect(() => {
    if (!dirty && blocker.state === "blocked") {
      blocker.proceed();
    }
  }, [dirty, blocker]);

  if (blocker.state !== "blocked") return { element: null };
  return {
    element: (
      <ConfirmationDialog
        open
        tier={1}
        title="Discard unsaved changes?"
        body={
          <>
            Leaving this page discards {what}. Nothing has been sent to the
            appliance.
          </>
        }
        confirmLabel="Discard and leave"
        destructive
        result="idle"
        onConfirm={() => {
          blocker.proceed();
        }}
        onCancel={() => {
          blocker.reset();
        }}
      />
    ),
  };
}
