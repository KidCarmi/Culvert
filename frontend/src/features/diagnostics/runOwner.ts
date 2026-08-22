// FE-4 active-diagnostic request ownership (hardening §10). TanStack's
// cancelQueries does NOT own an in-flight MUTATION request, so the diagnostic
// run holds its own AbortController: exactly one controller per active run
// (starting a new run aborts a predecessor — no duplicate controllers
// survive), ownership is cleared after settle, and abort() is wired to both
// component unmount and the FE-3 authentication boundary
// (registerAuthCleanup). Abort cancels the CLIENT request and releases
// client state — it cannot undo a server probe that already executed.

export interface DiagnoseRunOwner {
  /** Start a run: aborts any predecessor, takes ownership, returns the
   * run's signal. */
  begin(): AbortSignal;
  /** Settle a run: releases ownership ONLY if `sig` is still the active
   * run's signal (a superseded run must not clear its successor). */
  settle(sig: AbortSignal): void;
  /** Abort the active run (unmount / auth boundary) and clear ownership. */
  abort(): void;
  /** test seam: whether a controller is currently owned. */
  active(): boolean;
}

export function createDiagnoseRunOwner(): DiagnoseRunOwner {
  let controller: AbortController | null = null;
  return {
    begin(): AbortSignal {
      controller?.abort();
      const c = new AbortController();
      controller = c;
      return c.signal;
    },
    settle(sig: AbortSignal): void {
      if (controller !== null && controller.signal === sig) controller = null;
    },
    abort(): void {
      controller?.abort();
      controller = null;
    },
    active(): boolean {
      return controller !== null;
    },
  };
}
