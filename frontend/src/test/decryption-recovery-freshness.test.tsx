// 2E-B TRUE FINAL recovery-freshness closure — written in final (green) form
// and executed against the reviewed candidate (3669666e) for RED evidence.
//
// BLOCKER 1 — a restored recovery marker must NEVER be resolved from
// pre-existing TanStack cache. The snapshot model uses staleTime:Infinity and
// a SPA route-away/route-back keeps the QueryClient alive, so at the
// candidate the classifier can read the PRE-operation cached snapshot
// (seq=N, no receipts) and falsely conclude NOT-LANDED for an operation that
// actually landed — clearing the marker and re-arming Rotate toward a second
// continuity-breaking rotation. Required: a recovery-hydration gate — Rotate
// is not actionable until the marker inspection completes AND, when a marker
// exists, an authoritative GET initiated AFTER recovery entry has succeeded;
// only THAT truth classifies.
//
// BLOCKER 2 — no durable recovery marker ⇒ no T3 rotation dispatch. The
// candidate's writer swallowed storage failures and dispatched anyway,
// recreating the forgotten-operation defect wherever sessionStorage is
// unavailable. Required: verified write (setItem + read-back) BEFORE the
// PUT; on failure zero dispatch and an explicit safe error.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { DecryptionPage } from "../features/security/DecryptionPage";
import { isRecord } from "../api/decode";

const MARKER_KEY = "culvert.decryption.rotation-recovery.v1";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root | null;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (body: unknown) => Promise<Response>;
let privacyGets: number;
let hangPrivacyGet: boolean;
let failPrivacyGet: boolean;
let privacyKeyId: string;
let privacySeq: number;
let privacyReceipts: Array<{
  operation_id: string;
  key_id: string;
  seq: number;
  ts: string;
}>;

const HEALTH = {
  sessions: {
    total: 1,
    by_outcome: { inspected: 1 },
    by_decision_source: { policy_inspect: 1 },
    by_tls_version: { "1.3": 1 },
  },
  failures: { total: 0, by_category: {}, by_stage: {}, top: [] },
  coverage: { inspected: 1, bypassed: 0, failed: 0, inspected_ratio: 1 },
  trend: [],
  autoexclude: {
    active: 0,
    pending: 0,
    hit_total: 0,
    rescue_total: 0,
    surge_total: 0,
    fail_open_profiles: 0,
    fail_open_rules: 0,
  },
};

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = null;
  sessionStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
  mutations = [];
  onMutate = () => okJSON({ ok: true });
  privacyGets = 0;
  hangPrivacyGet = false;
  failPrivacyGet = false;
  privacyKeyId = "gen-aaaa";
  privacySeq = 4;
  privacyReceipts = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(body);
      }
      if (url.includes("/api/decryption/health")) return okJSON(HEALTH);
      if (url.includes("/api/decryption/redaction")) {
        privacyGets += 1;
        if (hangPrivacyGet) return new Promise<Response>(() => {});
        if (failPrivacyGet)
          return Promise.reject(new TypeError("network down"));
        return okJSON({
          redact_hosts: true,
          scope: "traffic_destination",
          scope_fields: ["host", "uri"],
          key_provisioned: true,
          key_id: privacyKeyId,
          rotation_seq: privacySeq,
          rotation_receipts: privacyReceipts,
          revision: `sha256:rev-${privacyKeyId}-${String(privacySeq)}`,
        });
      }
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  unmountAll();
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function unmountAll(): void {
  if (root !== null) {
    act(() => {
      root?.unmount();
    });
    root = null;
  }
}

// mountPrivacyTab accepts a SHARED QueryClient — the SPA route-away /
// route-back shape: the cache (and its pre-operation snapshot) survives the
// remount, exactly what Blocker 1 is about.
async function mountPrivacyTab(qc: QueryClient): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/decryption", element: <DecryptionPage /> }],
    { initialEntries: ["/security/decryption"] },
  );
  const machine = new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      Promise.resolve({
        loggedIn: true,
        user: "admin-user",
        role: "admin",
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("Coverage — since process start");
  });
  clickButton((t) => t === "Destination Privacy");
  await flushUntil(() => {
    expect(container.textContent).toContain("Destination privacy");
  });
}

async function flushUntil(cond: () => void): Promise<void> {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    cond();
  });
}

async function flushOnce(): Promise<void> {
  await act(async () => {
    await new Promise((r) => {
      setTimeout(r, 20);
    });
  });
}

function clickButton(match: (t: string) => boolean): void {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  act(() => {
    b.click();
  });
}

function rotateButton(): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    (el.textContent ?? "").includes("Rotate pseudonym key…"),
  );
  if (b === undefined) throw new Error("rotate button not mounted");
  return b;
}

async function confirmRotateCeremony(): Promise<void> {
  clickButton((t) => t.includes("Rotate pseudonym key…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  const input = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Type ROTATE"),
  );
  if (input === undefined) throw new Error("typed input not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(input, "ROTATE");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  clickButton((t) => t === "Rotate pseudonym key");
}

// ── BLOCKER 1A: warm-cache false NOT-LANDED ────────────────────────────────

it("A: a restored operation is never classified from the pre-operation cache — a forced fresh GET resolves it LANDED", async () => {
  const qc = new QueryClient();
  await mountPrivacyTab(qc); // cache now holds seq=4, receipts=[]

  // Operation X LANDS on the appliance (seq 5, receipt recorded) but the
  // response is lost in transport.
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    const op = body["operation_id"];
    privacySeq += 1;
    privacyKeyId = "gen-bbbb";
    privacyReceipts = [
      {
        operation_id: typeof op === "string" ? op : "",
        key_id: "gen-bbbb",
        seq: privacySeq,
        ts: "2026-08-30T10:00:00Z",
      },
    ];
    return Promise.reject(new TypeError("network down"));
  };
  await confirmRotateCeremony();
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });

  // SPA route-away / route-back: the component unmounts but the SAME
  // QueryClient (with the STALE pre-operation snapshot) survives.
  unmountAll();
  const getsBeforeReturn = privacyGets;
  await mountPrivacyTab(qc);

  // The stale cache (seq=4, no receipts) must NOT resolve X as NOT-LANDED.
  // A fresh authoritative GET is forced and ITS truth proves LANDED.
  await flushUntil(() => {
    expect(container.textContent).toContain("landed exactly once");
  });
  expect(container.textContent).not.toContain("did not occur");
  expect(privacyGets).toBeGreaterThan(getsBeforeReturn); // fresh GET forced
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull(); // cleared by TRUTH
  expect(mutations).toHaveLength(1); // zero second rotation
});

// ── BLOCKER 1B: hydration gate under a warm cache ──────────────────────────

it("B: with a warm cached snapshot and a pending marker, Rotate is not actionable and nothing classifies until fresh truth arrives", async () => {
  const qc = new QueryClient();
  await mountPrivacyTab(qc); // warm the cache (seq=4, receipts=[])
  unmountAll();

  // A pending operation from an earlier visit; the appliance is now
  // unreachable for fresh truth (the recovery GET hangs).
  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: "op-freshness-gate",
      preSeq: 4,
      startedAt: Date.now(),
      subject: "admin-user",
    }),
  );
  hangPrivacyGet = true;
  const getsBeforeReturn = privacyGets;
  await mountPrivacyTab(qc);
  await flushOnce(); // give any (defective) cache-classification a chance

  // The warm cache would say NOT-LANDED (seq matches, no receipt) — but the
  // cache must be inert: no claim, marker intact, Rotate blocked, and a
  // fresh recovery GET actually initiated.
  expect(container.textContent).not.toContain("did not occur");
  expect(container.textContent).not.toContain("landed exactly once");
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  expect(rotateButton().disabled).toBe(true);
  expect(privacyGets).toBeGreaterThan(getsBeforeReturn);
  expect(container.textContent).toContain("Verifying an unresolved rotation");
});

// ── BLOCKER 1C: a failed recovery GET keeps everything blocked, retry works ─

it("C: a failed recovery fetch retains marker + latch and offers an explicit retry; only the retried fresh truth resolves", async () => {
  const qc = new QueryClient();
  await mountPrivacyTab(qc); // warm cache
  unmountAll();
  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: "op-fetch-failed",
      preSeq: 4,
      startedAt: Date.now(),
      subject: "admin-user",
    }),
  );
  failPrivacyGet = true;
  await mountPrivacyTab(qc);
  await flushUntil(() => {
    expect(container.textContent).toContain("could not be reached to verify");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  expect(rotateButton().disabled).toBe(true);
  expect(container.textContent).not.toContain("did not occur");

  // Explicit retry once the appliance answers again; the fresh truth (seq
  // unchanged, no receipt) then proves NOT-LANDED and unlatches.
  failPrivacyGet = false;
  clickButton((t) => t === "Retry verification");
  await flushUntil(() => {
    expect(container.textContent).toContain("did not occur");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });
  expect(mutations).toHaveLength(0); // recovery never mutates
});

// ── BLOCKER 2: storage failure fails the rotation CLOSED ───────────────────

it("D: a throwing sessionStorage.setItem blocks the dispatch entirely; retry works once storage does", async () => {
  const qc = new QueryClient();
  await mountPrivacyTab(qc);

  const spy = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    throw new DOMException("denied", "SecurityError");
  });
  await confirmRotateCeremony();
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "could not create the recovery record",
    );
  });
  expect(container.textContent).toContain("No rotation was sent");
  expect(mutations).toHaveLength(0); // NO durable marker ⇒ NO dispatch

  // Storage recovers: the same deliberate ceremony can be retried.
  spy.mockRestore();
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      already_applied: false,
      operation_id: body["operation_id"],
      key_id: "gen-cccc",
      rotation_seq: privacySeq + 1,
      revision: "sha256:after",
    });
  };
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
});

it("E: a silent write (read-back mismatch) also blocks the dispatch — the marker must be provably recoverable", async () => {
  const qc = new QueryClient();
  await mountPrivacyTab(qc);

  // setItem "succeeds" but persists nothing — the read-back finds no marker.
  const spy = vi
    .spyOn(Storage.prototype, "setItem")
    .mockImplementation(() => {});
  await confirmRotateCeremony();
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "could not create the recovery record",
    );
  });
  expect(mutations).toHaveLength(0);
  spy.mockRestore();
});
