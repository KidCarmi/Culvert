// 2E-B FINAL storage-read fail-closed closure — written in final (green)
// form and executed against the reviewed candidate (465316df) for RED
// evidence.
//
// BLOCKER — the recovery read collapsed "cannot read / cannot interpret the
// recovery store" into null, and null meant "no pending recovery" ⇒
// recoveryGate "fresh" ⇒ Rotate available. A transient sessionStorage
// failure (or an unsupported/malformed record) therefore FORGOT a pending
// operation X; once storage recovered, a NEW operation Y could dispatch —
// and if X had actually landed, a second continuity-breaking rotation
// occurs that the write-side fail-closed rule cannot stop (Y persists its
// own valid marker). Required: a tri-state/result-typed read where only a
// PROVEN-ABSENT marker (storage readable, key null) enters the normal
// no-recovery state; "unavailable" and "unreadable" keep T3 rotation
// blocked, delete nothing silently, and offer explicit recovery paths
// (retry storage check / admin-only typed DISCARD ceremony with verified
// removal).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { DecryptionPage } from "../features/security/DecryptionPage";

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
  privacyKeyId = "gen-aaaa";
  privacySeq = 4;
  privacyReceipts = [];
  // The fetch stub deliberately touches NO browser storage, so the
  // Storage.prototype mocks in these tests affect only the code under test.
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return okJSON({ ok: true });
      }
      if (url.includes("/api/decryption/health")) return okJSON(HEALTH);
      if (url.includes("/api/decryption/redaction"))
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

async function mountPrivacyTab(): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/decryption", element: <DecryptionPage /> }],
    { initialEntries: ["/security/decryption"] },
  );
  const qc = new QueryClient();
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

function typeCeremonyWord(word: string): void {
  const input = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes(`Type ${word}`),
  );
  if (input === undefined) throw new Error("typed input not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(input, word);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function seedMarker(record: unknown): void {
  sessionStorage.setItem(
    MARKER_KEY,
    typeof record === "string" ? record : JSON.stringify(record),
  );
}

// ── A: transient recovery read failure ──────────────────────────────────────

it("A: a transient storage read failure never reads as 'no marker' — blocked, then retry restores and resolves X", async () => {
  seedMarker({
    version: 1,
    operationId: "op-transient-x",
    preSeq: 4,
    startedAt: Date.now(),
    subject: "admin-user",
  });
  // X actually LANDED on the appliance.
  privacySeq = 5;
  privacyKeyId = "gen-bbbb";
  privacyReceipts = [
    {
      operation_id: "op-transient-x",
      key_id: "gen-bbbb",
      seq: 5,
      ts: "2026-08-30T10:00:00Z",
    },
  ];

  // sessionStorage.getItem throws ONLY for the recovery key, ONLY for now.
  // eslint-disable-next-line @typescript-eslint/unbound-method -- captured for a call-through mock; always invoked with an explicit `this` below
  const original = Storage.prototype.getItem;
  const spy = vi
    .spyOn(Storage.prototype, "getItem")
    .mockImplementation(function (this: Storage, key: string) {
      if (key === MARKER_KEY) throw new DOMException("denied", "SecurityError");
      return original.call(this, key);
    });

  await mountPrivacyTab();
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "recovery store cannot be inspected",
    );
  });
  // X is NOT treated as absent: no claim, Rotate unavailable.
  expect(container.textContent).not.toContain("landed exactly once");
  expect(container.textContent).not.toContain("did not occur");
  expect(rotateButton().disabled).toBe(true);

  // Storage recovers; the explicit retry restores X and forces fresh truth.
  spy.mockRestore();
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull(); // never deleted
  clickButton((t) => t === "Retry storage check");
  await flushUntil(() => {
    expect(container.textContent).toContain("landed exactly once");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull(); // resolved by truth
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });
  expect(mutations).toHaveLength(0); // zero rotation dispatches throughout
});

// ── B: unsupported marker version ───────────────────────────────────────────

it("B: an unsupported-version record blocks Rotate, is never silently discarded, and requires the typed DISCARD ceremony", async () => {
  seedMarker({
    version: 999,
    operationId: "op-v999",
    preSeq: 4,
    startedAt: Date.now(),
    subject: "admin-user",
  });
  await mountPrivacyTab();
  await flushUntil(() => {
    expect(container.textContent).toContain("cannot be safely interpreted");
  });
  expect(rotateButton().disabled).toBe(true);
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull(); // NOT discarded
  expect(container.textContent).not.toContain("landed exactly once");
  expect(container.textContent).not.toContain("did not occur");

  // The explicit admin recovery ceremony: typed, no appliance mutation.
  clickButton((t) => t.includes("Discard unreadable recovery record…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type DISCARD");
    expect(container.textContent).toContain("continuity");
  });
  // Refused before the typed word — the record survives.
  clickButton((t) => t === "Discard recovery record");
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  typeCeremonyWord("DISCARD");
  clickButton((t) => t === "Discard recovery record");
  await flushUntil(() => {
    expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  });
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });
  expect(mutations).toHaveLength(0); // the ceremony mutates nothing
});

// ── C: malformed (schema-invalid) record ────────────────────────────────────

it("C: syntactically valid JSON that fails the marker schema is fail-closed, never a silent 'none'", async () => {
  seedMarker({ hello: 1 });
  await mountPrivacyTab();
  await flushUntil(() => {
    expect(container.textContent).toContain("cannot be safely interpreted");
  });
  expect(rotateButton().disabled).toBe(true);
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  expect(mutations).toHaveLength(0);
});

// ── D: true absence control ─────────────────────────────────────────────────

it("D: with storage readable and no marker, the normal no-recovery flow is unchanged", async () => {
  await mountPrivacyTab();
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });
  expect(container.textContent).not.toContain("cannot be inspected");
  expect(container.textContent).not.toContain("cannot be safely interpreted");
});

// ── E: removal failure keeps everything blocked ─────────────────────────────

it("E: a discard whose removal cannot be verified stays blocked; a later verified removal unblocks", async () => {
  seedMarker({
    version: 999,
    operationId: "op-v999-e",
    preSeq: 4,
    startedAt: Date.now(),
    subject: "admin-user",
  });
  await mountPrivacyTab();
  await flushUntil(() => {
    expect(container.textContent).toContain("cannot be safely interpreted");
  });
  clickButton((t) => t.includes("Discard unreadable recovery record…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type DISCARD");
  });
  const spy = vi
    .spyOn(Storage.prototype, "removeItem")
    .mockImplementation(() => {}); // removal silently does nothing
  typeCeremonyWord("DISCARD");
  clickButton((t) => t === "Discard recovery record");
  await flushUntil(() => {
    expect(container.textContent).toContain("could not be removed");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull(); // still there
  expect(rotateButton().disabled).toBe(true); // still blocked

  // Storage recovers: the same deliberate ceremony verifies removal now.
  spy.mockRestore();
  clickButton((t) => t === "Discard recovery record");
  await flushUntil(() => {
    expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  });
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });
  expect(mutations).toHaveLength(0);
});
