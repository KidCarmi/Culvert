// FE-6B.2 RED matrix — PAGE rows for the Certificates & CA WRITE surfaces,
// written against the frozen FE-6B.1 baseline 212b1617 BEFORE any product
// change (the page is read-only there: every row that needs a control fails
// on the absent control; P01/P02 are CONTROLS that already pass and must
// keep passing — no mutation control below admin).
//
//   P01/P02 viewer / operator: no mutation control, no marker card.
//   P03 admin: the five approved controls (and nothing outside FE-6B scope).
//   P04 rotate: opens a ceremony, requests the SERVER challenge with the
//       minted operationId + the loaded caRevision, shows the CA being
//       replaced and the expiry, gates the confirm on the typed word (Enter
//       does not confirm), confirms with the challenge in the BODY, renders
//       the action-bound result and clears the marker.
//   P05 a stale fence on the challenge renders the authoritative current
//       revision; nothing is retried; the marker is cleared (nothing written).
//   P06 an expired challenge offers a NEW challenge for the SAME operation;
//       the confirm is never re-sent automatically.
//   P07 import: Review issues the dry run (dryRun=1, no operationId, no
//       fence), the reviewed facts + the fence to echo render, Import commits
//       the SAME candidate under the dry run's fence and the minted id.
//   P08 a candidate refusal renders its bounded reason only; no commit.
//   P09 a lost confirm response: the ceremony closes, the marker is retained,
//       every mutation is blocked, the unresolved card offers Recover.
//   P10 a malformed 2xx (another operationId) is the same UNPROVEN latch.
//   P11 reload with a marker under this subject: Recover ⇒ committed ⇒ the
//       marker is cleared and the mutations unblock.
//   P12 Recover distinctions: pending kept; aborted ⇒ nothing written + Abandon;
//       superseded ⇒ TERMINAL UNKNOWN, no Re-send; 404 ⇒ UNKNOWN (no record
//       retained), no Re-send, marker kept (re-expressed by the correction
//       round, record 6B2C-B1 — the candidate read a 404 as "never recorded"
//       and offered a re-send; fe6b2c_red_test.go proves the re-send can
//       execute twice); a record not bound to the marker ⇒ unbound, kept.
//   P13 delete is T3: the persisted identity and the served identity are
//       stated, the typed word is the persisted fingerprint's first 8 bytes,
//       the DELETE carries the loaded fence.
//   P14 OCSP: desired vs runtime vs coverage stated; Apply POSTs the target
//       under the loaded fence; the result renders desired/runtime as stated.
//   P15 a double confirm dispatches ONE request.
//   P16 a lost import answer drops the typed key from the DOM and never
//       stores it; the marker carries only the candidate's public digest.
//   P17 a replace result renders persisted ≠ served: restart activates.
//   P18 the dirty import editor guards navigation.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import type { createMemoryRouter as CreateMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CertificatesPage } from "../features/security/CertificatesPage";
import { ToastProvider } from "../design-system/toast";
import { CERT_RECOVERY_KEY } from "../features/security/certRecovery";
import { isRecord } from "../api/decode";
import {
  CA_FP,
  CA_STATUS_HEALTHY,
  HEX64,
  HEX64_B,
  INVENTORY_HEALTHY,
  LISTENER_CUSTOM_A,
  LISTENER_NET,
  LISTENER_SELF_SIGNED,
  OCSP_STATUS_DEFAULT,
  OP_ABORTED,
  OP_ID,
  OP_PENDING,
  OP_ROTATE_COMMITTED,
  OP_SUPERSEDED,
  RAW_CANARY,
  UI_FP,
  UI_FP_B,
  colonForm,
} from "./fe6b1-fixtures";
import {
  CERT_PEM_CANARY,
  CHALLENGE,
  CHALLENGE_ANSWER,
  DELETE_RESULT,
  IMPORT_DRY_RUN,
  IMPORT_RESULT,
  KEY_PEM_CANARY,
  OCSP_RESULT,
  OP_ID_2,
  REPLACE_DRY_RUN,
  REPLACE_RESULT,
  ROTATE_RESULT,
  UI_PERSISTED_AFTER_REPLACE,
  json,
  refusalBody,
} from "./fe6b2-fixtures";

interface Call {
  url: string;
  method: string;
  body: unknown;
}
/** OP_ID spelled as the type crypto.randomUUID() returns (a typed literal,
 * not an assertion). */
const OP_UUID: `${string}-${string}-${string}-${string}-${string}` =
  "6b1c0000-fe6b-4e2e-9f00-00000000c001";
async function formField(body: unknown, name: string): Promise<string | null> {
  if (!(body instanceof FormData)) return null;
  const v = body.get(name);
  if (typeof v === "string") return v;
  if (v instanceof Blob) return v.text();
  return null;
}
let container: HTMLDivElement;
let root: Root;
let calls: Call[];
let route: (c: Call) => Response | Promise<Response>;
let inventory: unknown;
let router: ReturnType<typeof CreateMemoryRouter>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  calls = [];
  inventory = INVENTORY_HEALTHY;
  sessionStorage.clear();
  // jsdom has no top-layer <dialog>: the same polyfill every page matrix uses.
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
  vi.spyOn(crypto, "randomUUID").mockReturnValue(OP_UUID);
  route = defaultRoute;
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const c: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        body: init?.body,
      };
      calls.push(c);
      try {
        return Promise.resolve(route(c));
      } catch (e) {
        return Promise.reject(e instanceof Error ? e : new Error(String(e)));
      }
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function defaultRoute(c: Call): Response | Promise<Response> {
  const u = new URL(c.url, "http://x");
  if (c.method === "GET") {
    if (u.pathname === "/api/certificates") return json(inventory);
    if (u.pathname === "/api/ca/status") return json(CA_STATUS_HEALTHY);
    if (u.pathname === "/api/ocsp") return json(OCSP_STATUS_DEFAULT);
    if (u.pathname === "/api/settings/network")
      return json(LISTENER_NET(LISTENER_SELF_SIGNED, true, false));
  }
  return Promise.reject(new TypeError(`unrouted ${c.method} ${c.url}`));
}

type RoleName = "viewer" | "operator" | "admin";
function machineFor(role: RoleName, qc: QueryClient): AuthMachine {
  return new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      Promise.resolve({
        loggedIn: true,
        user: `${role}-user`,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mount(role: RoleName = "admin"): Promise<void> {
  router = createMemoryRouter(
    [
      { path: "/security/certificates", element: <CertificatesPage /> },
      { path: "/elsewhere", element: <p>elsewhere</p> },
    ],
    { initialEntries: ["/security/certificates"] },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <ToastProvider>
              <RouterProvider router={router} />
            </ToastProvider>
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
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
const text = (): string => container.textContent ?? "";
const dialogText = (): string =>
  document.querySelector("dialog[open]")?.textContent ?? "";
function buttons(
  name: string,
  scope: ParentNode = document,
): HTMLButtonElement[] {
  return Array.from(scope.querySelectorAll("button")).filter(
    (b) => (b.textContent ?? "").trim() === name,
  );
}
function button(name: string, scope: ParentNode = document): HTMLButtonElement {
  const b = buttons(name, scope)[0];
  if (b === undefined) throw new Error(`no button "${name}"`);
  return b;
}
async function click(
  name: string,
  scope: ParentNode = document,
): Promise<void> {
  const b = button(name, scope);
  await act(async () => {
    b.click();
    await Promise.resolve();
  });
}
function buttonTexts(): string[] {
  return Array.from(container.querySelectorAll("button")).map((b) =>
    (b.textContent ?? "").trim(),
  );
}
function fieldByLabel(
  label: string,
  scope: ParentNode = document,
): HTMLInputElement | HTMLTextAreaElement {
  for (const l of Array.from(scope.querySelectorAll("label"))) {
    if ((l.textContent ?? "").trim().startsWith(label)) {
      const el = l.htmlFor
        ? document.getElementById(l.htmlFor)
        : l.querySelector("input,textarea");
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)
        return el;
    }
  }
  throw new Error(`no field "${label}"`);
}
async function type(label: string, value: string): Promise<void> {
  const el = fieldByLabel(label);
  await act(async () => {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- invoked with call()
    const setter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(el),
      "value",
    )?.set;
    setter?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    await Promise.resolve();
  });
}
async function toggle(label: string): Promise<void> {
  const el = fieldByLabel(label);
  await act(async () => {
    el.click();
    await Promise.resolve();
  });
}
const openDialog = (): HTMLDialogElement => {
  const d = document.querySelector("dialog[open]");
  if (!(d instanceof HTMLDialogElement)) throw new Error("no open dialog");
  return d;
};
const posts = (path: string): Call[] =>
  calls.filter(
    (c) => c.method !== "GET" && new URL(c.url, "http://x").pathname === path,
  );
const query = (c: Call | undefined, k: string): string | null =>
  c === undefined ? null : new URL(c.url, "http://x").searchParams.get(k);
const storageRaw = (): string =>
  sessionStorage.getItem(CERT_RECOVERY_KEY) ?? "";
const marker = (): Record<string, unknown> => {
  const v: unknown = JSON.parse(storageRaw() || "{}");
  return isRecord(v) ? v : {};
};
function seedMarker(m: Record<string, unknown>): void {
  sessionStorage.setItem(
    CERT_RECOVERY_KEY,
    JSON.stringify({ version: 1, subject: "admin-user", ...m }),
  );
}
const ROTATE_MARKER = {
  operationId: OP_ID,
  action: "rotate",
  fence: `car1:${HEX64}`,
  candidate: "",
  previousFingerprint: HEX64,
  startedAt: 1_758_276_000_000,
};

const VIEWER_CONTROLS: readonly string[] = [
  "Certificates",
  "CA Management",
  "Refresh",
  "Download CA certificate (PEM)",
];
const MUTATIONS: readonly string[] = [
  "Rotate Root CA…",
  "Import CA…",
  "Replace UI certificate…",
  "Delete UI certificate…",
  "Set OCSP posture…",
];

function withMutations(
  over: Partial<Record<string, (c: Call) => Response | Promise<Response>>>,
): void {
  route = (c) => {
    const u = new URL(c.url, "http://x");
    if (c.method !== "GET" || u.pathname.startsWith("/api/ca/operations/")) {
      const fn = over[u.pathname];
      if (fn !== undefined) return fn(c);
    }
    return defaultRoute(c);
  };
}

async function openRotate(): Promise<void> {
  await click("Rotate Root CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Rotate the Root CA");
  });
}

// ── P01/P02/P03 roles ───────────────────────────────────────────────────────
for (const role of ["viewer", "operator"] as const) {
  it(`P01/P02 ${role}: no mutation control, no marker card`, async () => {
    seedMarker({ ...ROTATE_MARKER });
    await mount(role);
    expect(buttonTexts().every((b) => VIEWER_CONTROLS.includes(b))).toBe(true);
    expect(text()).not.toContain("Unresolved certificate operation");
    expect(posts("/api/ca/rotate/challenge")).toEqual([]);
  });
}
it("P03 admin: the approved controls exist and nothing beyond FE-6B scope", async () => {
  await mount("admin");
  for (const m of MUTATIONS) expect(buttonTexts()).toContain(m);
  expect(
    buttonTexts().every((b) =>
      [...VIEWER_CONTROLS, ...MUTATIONS, "Look up"].includes(b),
    ),
  ).toBe(true);
});

// ── P04 rotate ──────────────────────────────────────────────────────────────
it("P04 rotate: server challenge bound to the minted id + loaded fence; typed word; body challenge; bound result", async () => {
  withMutations({
    "/api/ca/rotate/challenge": () => json(CHALLENGE_ANSWER),
    "/api/ca/rotate": () => json(ROTATE_RESULT),
  });
  await mount("admin");
  await openRotate();
  expect(dialogText()).toContain(CA_FP);
  expect(posts("/api/ca/rotate/challenge")).toEqual([]);
  await click("Request challenge", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("2026-09-19T10:02:00Z");
  });
  const ch = posts("/api/ca/rotate/challenge")[0];
  expect(query(ch, "operationId")).toBe(OP_ID);
  expect(query(ch, "caRevision")).toBe(`car1:${HEX64}`);
  // 6B2C-B2: the challenge stage never touches the marker store; the marker
  // is armed at the confirm dispatch (the candidate wrote it here and then
  // cleared it on every challenge refusal and on cancel).
  expect(storageRaw()).toBe("");
  expect(dialogText()).toContain("cannot be undone");
  expect(button("Rotate", openDialog()).disabled).toBe(true);
  // Enter with an empty word does not confirm.
  await act(async () => {
    openDialog().querySelector("form")?.requestSubmit();
    await Promise.resolve();
  });
  expect(posts("/api/ca/rotate")).toEqual([]);
  await type("Type ROTATE to confirm", "ROTATE");
  expect(button("Rotate", openDialog()).disabled).toBe(false);
  await click("Rotate", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Root CA rotated");
  });
  const r = posts("/api/ca/rotate")[0];
  expect(query(r, "operationId")).toBe(OP_ID);
  expect(query(r, "caRevision")).toBe(`car1:${HEX64}`);
  expect(r?.url).not.toContain(CHALLENGE);
  expect(JSON.parse(String(r?.body))).toEqual({ challenge: CHALLENGE });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(text()).toContain(colonForm(HEX64_B));
  expect(storageRaw()).toBe("");
  expect(text()).not.toContain(CHALLENGE);
});

// ── P05 stale fence ─────────────────────────────────────────────────────────
it("P05 a stale fence renders the current revision; no retry; marker cleared", async () => {
  withMutations({
    "/api/ca/rotate/challenge": () =>
      json(refusalBody("stale", { caRevision: `car1:${HEX64_B}` }), 409),
  });
  await mount("admin");
  await openRotate();
  await click("Request challenge", openDialog());
  await flushUntil(() => {
    expect(text()).toContain(`car1:${HEX64_B}`);
  });
  expect(text()).toContain("changed since");
  expect(posts("/api/ca/rotate/challenge")).toHaveLength(1);
  expect(posts("/api/ca/rotate")).toEqual([]);
  expect(text()).not.toContain(RAW_CANARY);
  expect(storageRaw()).toBe("");
});

// ── P06 expired challenge ───────────────────────────────────────────────────
it("P06 an expired challenge offers a new one for the SAME operation; nothing auto-retries", async () => {
  withMutations({
    "/api/ca/rotate/challenge": () => json(CHALLENGE_ANSWER),
    "/api/ca/rotate": () =>
      json(refusalBody("challenge_stale", { changed: ["expired"] }), 409),
  });
  await mount("admin");
  await openRotate();
  await click("Request challenge", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("2026-09-19T10:02:00Z");
  });
  await type("Type ROTATE to confirm", "ROTATE");
  await click("Rotate", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("expired");
  });
  expect(posts("/api/ca/rotate")).toHaveLength(1);
  await click("Request a new challenge", openDialog());
  await flushUntil(() => {
    expect(posts("/api/ca/rotate/challenge")).toHaveLength(2);
  });
  expect(query(posts("/api/ca/rotate/challenge")[1], "operationId")).toBe(
    OP_ID,
  );
  expect(posts("/api/ca/rotate")).toHaveLength(1);
});

// ── P07/P08 import ──────────────────────────────────────────────────────────
async function openImportAndReview(): Promise<void> {
  await click("Import CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Import a Root CA");
  });
  await type("CA certificate (PEM)", CERT_PEM_CANARY);
  await type("CA private key (PEM)", KEY_PEM_CANARY);
  await click("Review candidate", openDialog());
}
it("P07 import: dry run first, reviewed facts + fence, then the SAME candidate committed under that fence", async () => {
  withMutations({
    "/api/certs/upload": (c) =>
      new URL(c.url, "http://x").searchParams.get("dryRun") === "1"
        ? json(IMPORT_DRY_RUN)
        : json(IMPORT_RESULT),
  });
  await mount("admin");
  await openImportAndReview();
  await flushUntil(() => {
    expect(dialogText()).toContain("Corp Inspection CA");
  });
  const dry = posts("/api/certs/upload")[0];
  expect(query(dry, "dryRun")).toBe("1");
  expect(query(dry, "operationId")).toBeNull();
  expect(query(dry, "caRevision")).toBeNull();
  expect(dialogText()).toContain(colonForm(HEX64_B));
  expect(dialogText()).toContain(`car1:${HEX64}`);
  expect(posts("/api/certs/upload")).toHaveLength(1);
  await click("Import", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Root CA imported");
  });
  const commit = posts("/api/certs/upload")[1];
  expect(query(commit, "dryRun")).toBeNull();
  expect(query(commit, "operationId")).toBe(OP_ID);
  expect(query(commit, "caRevision")).toBe(`car1:${HEX64}`);
  expect(commit?.body instanceof FormData).toBe(true);
  expect(await formField(commit?.body, "cert")).toBe(CERT_PEM_CANARY);
  expect(await formField(commit?.body, "target")).toBe("mitm");
  expect(storageRaw()).toBe("");
  expect(text()).not.toContain("KEY-CANARY");
});
it("P08 a candidate refusal renders its bounded reason; no commit", async () => {
  withMutations({
    "/api/certs/upload": () =>
      json(refusalBody("candidate_invalid", { reason: "key_mismatch" }), 400),
  });
  await mount("admin");
  await openImportAndReview();
  await flushUntil(() => {
    expect(dialogText()).toContain("key_mismatch");
  });
  expect(posts("/api/certs/upload")).toHaveLength(1);
  expect(text()).not.toContain(RAW_CANARY);
  expect(buttons("Import", openDialog())).toEqual([]);
  expect(storageRaw()).toBe("");
});

// ── P09/P10 unproven ────────────────────────────────────────────────────────
async function rotateTo(
  answer: () => Response | Promise<Response>,
): Promise<void> {
  withMutations({
    "/api/ca/rotate/challenge": () => json(CHALLENGE_ANSWER),
    "/api/ca/rotate": answer,
  });
  await mount("admin");
  await openRotate();
  await click("Request challenge", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("2026-09-19T10:02:00Z");
  });
  await type("Type ROTATE to confirm", "ROTATE");
  await click("Rotate", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Unresolved certificate operation");
  });
}
it("P09 a lost confirm: ceremony closed, marker retained, mutations blocked, Recover offered", async () => {
  await rotateTo(() => Promise.reject(new TypeError("connection reset")));
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(marker()["operationId"]).toBe(OP_ID);
  expect(marker()["action"]).toBe("rotate");
  for (const m of MUTATIONS) expect(button(m).disabled).toBe(true);
  expect(buttons("Recover")).toHaveLength(1);
  expect(buttons("Re-send")).toEqual([]);
  expect(text()).not.toContain("Root CA rotated");
  expect(text()).not.toContain(CHALLENGE);
});
it("P10 a 2xx naming another operation is the same UNPROVEN latch", async () => {
  await rotateTo(() => json({ ...ROTATE_RESULT, operationId: OP_ID_2 }));
  expect(marker()["operationId"]).toBe(OP_ID);
  for (const m of MUTATIONS) expect(button(m).disabled).toBe(true);
  expect(text()).not.toContain("Root CA rotated");
});

// ── P11/P12 recovery ────────────────────────────────────────────────────────
it("P11 reload with a marker: Recover ⇒ committed ⇒ cleared, unblocked, result shown", async () => {
  seedMarker(ROTATE_MARKER);
  withMutations({
    [`/api/ca/operations/${OP_ID}`]: () => json(OP_ROTATE_COMMITTED),
  });
  await mount("admin");
  expect(text()).toContain("Unresolved certificate operation");
  expect(text()).toContain(OP_ID);
  for (const m of MUTATIONS) expect(button(m).disabled).toBe(true);
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("committed on the appliance");
  });
  expect(storageRaw()).toBe("");
  await flushUntil(() => {
    expect(button("Rotate Root CA…").disabled).toBe(false);
  });
  expect(text()).not.toContain("Unresolved certificate operation");
});
const RECOVER_ROWS: Array<[string, unknown, (t: string) => void]> = [
  [
    "pending is kept",
    { ...OP_PENDING, action: "ca.rotate", candidateFingerprint: undefined },
    (t) => {
      expect(t).toContain("still pending");
      expect(storageRaw()).not.toBe("");
      expect(buttons("Re-send")).toEqual([]);
    },
  ],
  [
    "aborted ⇒ nothing written + Abandon",
    { ...OP_ABORTED, action: "ca.rotate", candidateFingerprint: undefined },
    (t) => {
      expect(t).toContain("nothing was written");
      expect(t).toContain("persist_failed");
      expect(buttons("Abandon")).toHaveLength(1);
      expect(buttons("Re-send")).toEqual([]);
    },
  ],
  [
    "superseded ⇒ TERMINAL UNKNOWN, no Re-send",
    { ...OP_SUPERSEDED, action: "ca.rotate", candidateFingerprint: undefined },
    (t) => {
      expect(t).toContain("never be known");
      expect(t).not.toContain("succeeded");
      expect(buttons("Re-send")).toEqual([]);
      expect(storageRaw()).not.toBe("");
    },
  ],
  [
    "a record not bound to the marker ⇒ unbound, kept",
    OP_ROTATE_COMMITTED_WITH_FENCE(`car1:${HEX64_B}`),
    (t) => {
      expect(t).toContain("not bound");
      expect(storageRaw()).not.toBe("");
      expect(buttons("Re-send")).toEqual([]);
    },
  ],
];
function OP_ROTATE_COMMITTED_WITH_FENCE(fence: string): unknown {
  return { ...OP_ROTATE_COMMITTED, fence };
}
for (const [name, rec, check] of RECOVER_ROWS) {
  it(`P12 Recover: ${name}`, async () => {
    seedMarker(ROTATE_MARKER);
    withMutations({ [`/api/ca/operations/${OP_ID}`]: () => json(rec) });
    await mount("admin");
    await click("Recover");
    await flushUntil(() => {
      expect(
        posts(`/api/ca/operations/${OP_ID}`).length +
          calls.filter((c) => c.url.includes("/api/ca/operations/")).length,
      ).toBeGreaterThan(0);
    });
    await flushUntil(() => {
      expect(text()).not.toContain("Looking the operation up");
    });
    check(text());
  });
}
it("P12 Recover: 404 ⇒ UNKNOWN (no record retained) ⇒ no Re-send; marker kept; Abandon offered", async () => {
  seedMarker(ROTATE_MARKER);
  withMutations({
    [`/api/ca/operations/${OP_ID}`]: () => json(refusalBody("not_found"), 404),
  });
  await mount("admin");
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("retains no record");
  });
  expect(text()).not.toContain("never recorded");
  expect(buttons("Re-send")).toEqual([]);
  expect(buttons("Abandon")).toHaveLength(1);
  expect(storageRaw()).not.toBe("");
});

// ── P13 delete ──────────────────────────────────────────────────────────────
it("P13 delete is T3: persisted + served identities stated; typed first 8 bytes; fenced DELETE", async () => {
  inventory = {
    ...INVENTORY_HEALTHY,
    listener: LISTENER_CUSTOM_A(true),
    uiCert: { ...INVENTORY_HEALTHY.uiCert, active: true },
  };
  withMutations({ "/api/certs/ui": () => json(DELETE_RESULT) });
  route = ((inner) => (c: Call) => {
    const u = new URL(c.url, "http://x");
    if (c.method === "GET" && u.pathname === "/api/settings/network")
      return json(LISTENER_NET(LISTENER_CUSTOM_A(true), true, true));
    return inner(c);
  })(route);
  await mount("admin");
  await click("Delete UI certificate…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Delete the UI certificate");
  });
  expect(dialogText()).toContain(UI_FP);
  expect(dialogText()).toContain("keeps serving");
  const word = UI_FP.slice(0, 23);
  expect(dialogText()).toContain(`Type ${word} to confirm`);
  expect(button("Delete", openDialog()).disabled).toBe(true);
  await type(`Type ${word} to confirm`, word);
  await click("Delete", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("UI certificate deleted");
  });
  const d = posts("/api/certs/ui")[0];
  expect(d?.method).toBe("DELETE");
  expect(query(d, "operationId")).toBe(OP_ID);
  expect(query(d, "uiCertRevision")).toBe(`uic1:${HEX64_B}`);
  expect(storageRaw()).toBe("");
});

// ── P14/P15 OCSP ────────────────────────────────────────────────────────────
it("P14 OCSP: desired vs runtime vs coverage stated; fenced POST; result as stated", async () => {
  withMutations({ "/api/ocsp": () => json(OCSP_RESULT) });
  await mount("admin");
  await click("Set OCSP posture…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Set the OCSP posture");
  });
  expect(dialogText()).toContain("Desired: Disabled");
  expect(dialogText()).toContain("Runtime: Disabled");
  expect(dialogText()).toContain("not consulted");
  expect(dialogText()).toContain("Node-local");
  await toggle("Enable OCSP revocation checking");
  await click("Apply", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("OCSP posture set");
  });
  const p = posts("/api/ocsp")[0];
  expect(query(p, "operationId")).toBe(OP_ID);
  expect(query(p, "ocspRevision")).toBe(`ocr1:${HEX64}`);
  expect(JSON.parse(String(p?.body))).toEqual({ enabled: true });
  expect(text()).toContain("Desired: Enabled");
  expect(storageRaw()).toBe("");
});
it("P15 a double confirm dispatches ONE request", async () => {
  let release: (r: Response) => void = () => undefined;
  withMutations({
    "/api/ocsp": () =>
      new Promise<Response>((res) => {
        release = res;
      }),
  });
  await mount("admin");
  await click("Set OCSP posture…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Set the OCSP posture");
  });
  await toggle("Enable OCSP revocation checking");
  const b = button("Apply", openDialog());
  await act(async () => {
    b.click();
    b.click();
    openDialog().querySelector("form")?.requestSubmit();
    await Promise.resolve();
  });
  expect(posts("/api/ocsp")).toHaveLength(1);
  release(json(OCSP_RESULT));
  await flushUntil(() => {
    expect(text()).toContain("OCSP posture set");
  });
  expect(posts("/api/ocsp")).toHaveLength(1);
});

// ── P16 secrets ─────────────────────────────────────────────────────────────
it("P16 a lost import answer drops the key from the DOM; the marker carries only the public digest", async () => {
  withMutations({
    "/api/certs/upload": (c) =>
      new URL(c.url, "http://x").searchParams.get("dryRun") === "1"
        ? json(IMPORT_DRY_RUN)
        : Promise.reject(new TypeError("connection reset")),
  });
  await mount("admin");
  await click("Import CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Import a Root CA");
  });
  await type("CA certificate (PEM)", CERT_PEM_CANARY);
  await type("CA private key (PEM)", KEY_PEM_CANARY);
  // The typed key exists in the OPEN ceremony only (rule 9).
  expect(document.documentElement.outerHTML).toContain("KEY-CANARY");
  await click("Review candidate", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("Corp Inspection CA");
  });
  await click("Import", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Unresolved certificate operation");
  });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(document.documentElement.outerHTML).not.toContain("KEY-CANARY");
  expect(document.documentElement.outerHTML).not.toContain("CERT-CANARY");
  expect(storageRaw()).not.toContain("KEY-CANARY");
  expect(storageRaw()).not.toContain("CERT-CANARY");
  expect(marker()["action"]).toBe("import");
  expect(marker()["candidate"]).toBe(HEX64_B);
  expect(marker()["fence"]).toBe(`car1:${HEX64}`);
});

// ── P17 replacement is not activation ───────────────────────────────────────
it("P17 a replace result renders persisted ≠ served; a restart activates", async () => {
  inventory = {
    ...INVENTORY_HEALTHY,
    listener: LISTENER_CUSTOM_A(true),
    uiCert: { ...INVENTORY_HEALTHY.uiCert, active: true },
  };
  let replaced = false;
  withMutations({
    "/api/certs/upload": (c) => {
      if (new URL(c.url, "http://x").searchParams.get("dryRun") === "1")
        return json(REPLACE_DRY_RUN);
      replaced = true;
      inventory = {
        ...INVENTORY_HEALTHY,
        listener: LISTENER_CUSTOM_A(false),
        uiCert: UI_PERSISTED_AFTER_REPLACE,
      };
      return json({ ...REPLACE_RESULT, uiCert: UI_PERSISTED_AFTER_REPLACE });
    },
  });
  route = ((inner) => (c: Call) => {
    const u = new URL(c.url, "http://x");
    if (c.method === "GET" && u.pathname === "/api/settings/network")
      return json(LISTENER_NET(LISTENER_CUSTOM_A(!replaced), true, !replaced));
    return inner(c);
  })(route);
  await mount("admin");
  await click("Replace UI certificate…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Replace the UI certificate");
  });
  await type("Certificate (PEM)", CERT_PEM_CANARY);
  await type("Private key (PEM)", KEY_PEM_CANARY);
  await click("Review candidate", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("ui-b.example");
  });
  expect(dialogText()).toContain(UI_FP_B);
  expect(dialogText()).toContain("restart");
  await click("Replace", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("UI certificate replaced");
  });
  await flushUntil(() => {
    expect(text()).toContain("Activation requires a restart");
  });
  expect(text()).toContain(UI_FP); // served
  expect(text()).toContain(UI_FP_B); // persisted
  expect(text()).not.toContain("Active on the running listener");
  expect(query(posts("/api/certs/upload")[1], "uiCertRevision")).toBe(
    `uic1:${HEX64_B}`,
  );
});

// ── P18 dirty guard ─────────────────────────────────────────────────────────
it("P18 the dirty import editor guards navigation", async () => {
  await mount("admin");
  await click("Import CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Import a Root CA");
  });
  await type("CA certificate (PEM)", CERT_PEM_CANARY);
  await act(async () => {
    await router.navigate("/elsewhere");
  });
  await flushUntil(() => {
    expect(text()).toContain("Discard unsaved changes?");
  });
  expect(text()).not.toContain("elsewhere");
});
