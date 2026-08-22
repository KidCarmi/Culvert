// Slice 2A-M download ownership (§16): built now that a REAL consumer exists
// (the recent-memory export). One owner per consuming surface — NOT a global
// download manager, no event bus.
//
// The owner owns two resources with different lifetimes:
//   - the in-flight download's AbortController (a new download supersedes and
//     aborts its predecessor; unmount and the FE-3 authentication boundary
//     abort the active download);
//   - the current object URL (revoked before being replaced, revoked after
//     the browser download has been handed off, and revoked at abort — an
//     object URL never crosses an identity boundary).
//
// The FE-3 collapsed boundary runs registered cleanups at most once per
// authenticated episode, but a component unmount can still follow the
// boundary — abortAndRevoke is safe to call repeatedly.

export interface DownloadOwner {
  /** Start a download: aborts any predecessor, revokes any lingering object
   * URL, takes ownership, returns the run's signal. */
  begin(): AbortSignal;
  /** Hand a finished blob to the browser as a download. No-ops (returns
   * false) when `sig` is no longer the active run — a superseded or
   * boundary-aborted result must never reach the DOM. The object URL is
   * created, the download is triggered, and the URL is revoked before
   * returning. */
  deliver(sig: AbortSignal, blob: Blob, filename: string): boolean;
  /** Release ownership if `sig` is still the active run (finally-path). */
  settle(sig: AbortSignal): void;
  /** Abort the active download and revoke any object URL (unmount / FE-3
   * authentication boundary). Safe to call more than once. */
  abortAndRevoke(): void;
  /** test seam */
  active(): boolean;
}

// sanitizeDownloadFilename: deterministic client-side filenames are the
// primary path (§15 option B); this gate is defense-in-depth so no caller
// can ever pass a path, CR/LF, or markup into the anchor's download name.
export function sanitizeDownloadFilename(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9._-]/g, "-");
  return cleaned === "" ? "download" : cleaned.slice(0, 128);
}

export function createDownloadOwner(): DownloadOwner {
  let controller: AbortController | null = null;
  let currentURL: string | null = null;

  const revoke = (): void => {
    if (currentURL !== null) {
      URL.revokeObjectURL(currentURL);
      currentURL = null;
    }
  };

  return {
    begin(): AbortSignal {
      controller?.abort();
      revoke();
      const c = new AbortController();
      controller = c;
      return c.signal;
    },
    deliver(sig: AbortSignal, blob: Blob, filename: string): boolean {
      if (controller === null || controller.signal !== sig || sig.aborted) {
        return false; // superseded or aborted — never touches the DOM
      }
      revoke(); // defensive: no prior URL may leak
      const url = URL.createObjectURL(blob);
      currentURL = url;
      try {
        const a = document.createElement("a");
        a.href = url;
        a.download = sanitizeDownloadFilename(filename);
        a.rel = "noopener";
        document.body.appendChild(a);
        a.click();
        a.remove();
      } finally {
        // The browser latches the object URL when the download is initiated;
        // revoking immediately afterwards keeps the URL's lifetime one tick.
        revoke();
        controller = null;
      }
      return true;
    },
    settle(sig: AbortSignal): void {
      if (controller !== null && controller.signal === sig) controller = null;
    },
    abortAndRevoke(): void {
      controller?.abort();
      controller = null;
      revoke();
    },
    active(): boolean {
      return controller !== null;
    },
  };
}
