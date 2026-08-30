// 2E-B FINAL lifecycle closure — the T3 rotation recovery identity must
// survive the CLIENT lifecycle. Written in final (green) form and executed
// against the corrected candidate (7f9206b6) for RED evidence: there the
// unresolved operation lives only in component React state, so navigating
// away / remounting forgets operation X and re-enables Rotate — if X had
// actually landed, a second "rotation" would break pseudonym continuity
// again, and backend idempotency cannot help because the new attempt is a
// NEW operation id.
//
// Final contract pinned here:
//  - a NON-SECRET recovery marker {version, operationId, preSeq, startedAt,
//    subject} is written to sessionStorage BEFORE the rotation dispatch
//    (ordering is load-bearing) under the literal key below;
//  - it survives unmount/remount (and, via sessionStorage, page reload);
//  - it is bound to the authenticated subject and never inherited across
//    identities;
//  - on remount it restores the latch: Rotate stays blocked until the
//    accepted server matrix resolves the stored operation; LANDED /
//    NOT-LANDED clear the marker; AMBIGUOUS retains it;
//  - AMBIGUOUS has an EXPLICIT typed recovery ceremony that clears the
//    marker WITHOUT dispatching any mutation;
//  - a later rotation is a fresh T3 with a NEW (32-hex) operation id.
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

// The durable recovery marker's storage contract (literal on purpose — this
// test pins the key and shape as an external contract, not an import).
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
let markerAtDispatch: string | null;
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
  markerAtDispatch = null;
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
        // Ordering proof (matrix I): the durable recovery marker must
        // already exist at the instant the network dispatch happens.
        markerAtDispatch = sessionStorage.getItem(MARKER_KEY);
        return onMutate(body);
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

// Each mount builds a FRESH QueryClient + AuthMachine + router — the
// component-level analog of a route remount / page reload (nothing but the
// browser session storage survives between two mounts).
async function mountPrivacyTab(user = "admin-user"): Promise<void> {
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
        user,
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

async function startUnknownRotation(): Promise<string> {
  clickButton((t) => t.includes("Rotate pseudonym key…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  typeCeremonyWord("ROTATE");
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  const m = mutations[mutations.length - 1];
  if (m === undefined || !isRecord(m.body)) throw new Error("no mutation");
  const op = m.body["operation_id"];
  if (typeof op !== "string" || op === "") throw new Error("no operation id");
  return op;
}

function marker(): Record<string, unknown> | null {
  const raw = sessionStorage.getItem(MARKER_KEY);
  if (raw === null) return null;
  const v: unknown = JSON.parse(raw);
  if (!isRecord(v)) throw new Error("marker is not an object");
  return v;
}

// ── the lifecycle defect itself (matrix A / E) ──────────────────────────────

it("A/E: an unresolved operation survives unmount/remount; ambiguous truth keeps Rotate blocked and the marker retained", async () => {
  await mountPrivacyTab();
  // The request dies in transport while ANOTHER admin's rotation lands —
  // the stored operation must come back AMBIGUOUS after the remount.
  onMutate = () => {
    privacyKeyId = "gen-other";
    privacySeq += 1;
    privacyReceipts = [
      {
        operation_id: "op-of-someone-else",
        key_id: "gen-other",
        seq: privacySeq,
        ts: "2026-08-30T10:00:00Z",
      },
    ];
    return Promise.reject(new TypeError("network down"));
  };
  const opX = await startUnknownRotation();

  // Route away: the component (and ALL its React state) is gone.
  unmountAll();
  // Route back: a completely fresh mount (fresh QueryClient + machine).
  await mountPrivacyTab();

  await flushUntil(() => {
    expect(container.textContent).toContain("cannot yet be proven");
  });
  // The specific operation is remembered, no landed/not-landed claim is
  // made, normal Rotate is NOT offered, and nothing was re-dispatched.
  expect(container.textContent).not.toContain("exactly once");
  expect(container.textContent).not.toContain("did not occur");
  expect(rotateButton().disabled).toBe(true);
  expect(mutations).toHaveLength(1);
  const m = marker();
  expect(m).not.toBeNull();
  expect(m?.["operationId"]).toBe(opX);
});

// ── matrix C: LANDED after remount ──────────────────────────────────────────

it("C: after remount, OUR receipt proves LANDED; the marker clears and a NEW rotation uses a new id", async () => {
  await mountPrivacyTab();
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    const op = body["operation_id"];
    privacyKeyId = "gen-cccc";
    privacySeq += 1;
    privacyReceipts = [
      {
        operation_id: typeof op === "string" ? op : "",
        key_id: "gen-cccc",
        seq: privacySeq,
        ts: "2026-08-30T10:00:00Z",
      },
    ];
    return Promise.reject(new TypeError("network down"));
  };
  const opX = await startUnknownRotation();

  unmountAll();
  await mountPrivacyTab();

  await flushUntil(() => {
    expect(container.textContent).toContain("landed exactly once");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull(); // terminal ⇒ cleared
  expect(mutations).toHaveLength(1); // nothing auto-dispatched
  expect(rotateButton().disabled).toBe(false);

  // A deliberate NEW rotation is a fresh T3 with a fresh identity.
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      already_applied: false,
      operation_id: body["operation_id"],
      key_id: "gen-dddd",
      rotation_seq: privacySeq + 1,
      revision: "sha256:after",
    });
  };
  clickButton((t) => t.includes("Rotate pseudonym key…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  typeCeremonyWord("ROTATE");
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  const second = mutations[1];
  if (second === undefined || !isRecord(second.body))
    throw new Error("no body");
  const opY = second.body["operation_id"];
  expect(typeof opY).toBe("string");
  expect(opY).not.toBe(opX);
  expect(opY).toMatch(/^[0-9a-f]{32}$/); // ≥128-bit operation identity
});

// ── matrix D: NOT-LANDED after remount ──────────────────────────────────────

it("D: after remount, an unchanged sequence proves NOT-LANDED; the marker clears and a NEW rotation uses a new id", async () => {
  await mountPrivacyTab();
  onMutate = () => Promise.reject(new TypeError("network down"));
  const opX = await startUnknownRotation();

  unmountAll();
  await mountPrivacyTab();

  await flushUntil(() => {
    expect(container.textContent).toContain("did not occur");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  expect(rotateButton().disabled).toBe(false);
  expect(mutations).toHaveLength(1);

  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      already_applied: false,
      operation_id: body["operation_id"],
      key_id: "gen-bbbb",
      rotation_seq: privacySeq + 1,
      revision: "sha256:after",
    });
  };
  clickButton((t) => t.includes("Rotate pseudonym key…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  typeCeremonyWord("ROTATE");
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  const second = mutations[1];
  if (second === undefined || !isRecord(second.body))
    throw new Error("no body");
  expect(second.body["operation_id"]).not.toBe(opX);
});

// ── matrix F: explicit AMBIGUOUS recovery ceremony ──────────────────────────

it("F: the ambiguous-recovery ceremony clears the marker only after the typed confirmation and dispatches NO mutation", async () => {
  await mountPrivacyTab();
  onMutate = () => {
    privacyKeyId = "gen-other";
    privacySeq += 1;
    privacyReceipts = [];
    return Promise.reject(new TypeError("network down"));
  };
  const opX = await startUnknownRotation();
  unmountAll();
  await mountPrivacyTab();
  await flushUntil(() => {
    expect(container.textContent).toContain("cannot yet be proven");
  });

  clickButton((t) => t.includes("Resolve ambiguous rotation…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("cannot prove");
    expect(container.textContent).toContain("abandons");
    expect(container.textContent).toContain("continuity");
    expect(container.textContent).toContain("Type ABANDON");
  });
  // Refused before the typed word; the marker survives an un-confirmed
  // ceremony (closing it must not be an accidental escape hatch).
  clickButton((t) => t === "Abandon unresolved rotation");
  expect(marker()?.["operationId"]).toBe(opX);
  typeCeremonyWord("ABANDON");
  clickButton((t) => t === "Abandon unresolved rotation");
  await flushUntil(() => {
    expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  });
  // No API mutation was part of the recovery; Rotate is deliberate again.
  expect(mutations).toHaveLength(1);
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });

  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      already_applied: false,
      operation_id: body["operation_id"],
      key_id: "gen-eeee",
      rotation_seq: privacySeq + 1,
      revision: "sha256:after",
    });
  };
  clickButton((t) => t.includes("Rotate pseudonym key…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  typeCeremonyWord("ROTATE");
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  const second = mutations[1];
  if (second === undefined || !isRecord(second.body))
    throw new Error("no body");
  expect(second.body["operation_id"]).not.toBe(opX);
});

// ── matrix G: subject binding ───────────────────────────────────────────────

it("G: a pending marker from a DIFFERENT authenticated subject is discarded, never inherited", async () => {
  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: "op-of-previous-identity",
      preSeq: 1,
      startedAt: 0,
      subject: "someone-else",
    }),
  );
  await mountPrivacyTab("admin-user");
  await flushUntil(() => {
    expect(rotateButton().disabled).toBe(false);
  });
  // No pending/ambiguous state was inherited and the foreign marker is gone.
  expect(container.textContent).not.toContain("cannot yet be proven");
  expect(container.textContent).not.toContain("Outcome unconfirmed");
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
});

// ── matrix H + I: marker content allowlist and write-before-dispatch ────────

it("H/I: the marker is written BEFORE dispatch and carries ONLY the non-secret recovery facts", async () => {
  await mountPrivacyTab();
  onMutate = () => Promise.reject(new TypeError("network down"));
  const opX = await startUnknownRotation();

  // I — the fetch stub captured storage at dispatch time.
  expect(markerAtDispatch).not.toBeNull();
  const atDispatch: unknown = JSON.parse(markerAtDispatch ?? "null");
  if (!isRecord(atDispatch)) throw new Error("marker at dispatch not object");
  expect(atDispatch["operationId"]).toBe(opX);

  // H — exact non-secret field allowlist; no key material, key_id, or
  // configuration draft ever reaches browser storage.
  const m = marker();
  if (m === null) throw new Error("marker missing");
  expect(Object.keys(m).sort()).toEqual([
    "operationId",
    "preSeq",
    "startedAt",
    "subject",
    "version",
  ]);
  expect(m["version"]).toBe(1);
  expect(m["subject"]).toBe("admin-user");
  expect(typeof m["preSeq"]).toBe("number");
  const raw = sessionStorage.getItem(MARKER_KEY) ?? "";
  expect(raw).not.toContain("gen-aaaa"); // no pseudonym generation values
  expect(raw).not.toContain("revision");
});
