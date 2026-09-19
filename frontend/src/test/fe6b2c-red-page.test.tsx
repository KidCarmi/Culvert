// FE-6B.2 CORRECTION ROUND — RED matrix (record 6B2C), PAGE rows, written
// against the rejected FE-6B.2 candidate fcdd626f BEFORE any product change.
// The API-level hazard behind B1 is proved by fe6b2c_red_test.go on the
// real handlers (an evicted decided record + an identical reinstall re-arm
// the original fence, so a re-sent delete executes twice); these rows prove
// the PAGE no longer lets a lookup 404 authorise another mutation, that the
// original unresolved marker survives every interaction the page offers,
// and that no ceremony or outcome promises what the next start serves.
//
//   B1 — an ABSENT operation is UNKNOWN, never "never recorded":
//   C01 Recover ⇒ 404 ⇒ the card states the appliance retains no record and
//       that the outcome cannot be known; no Re-send; the marker is kept;
//       every mutation stays blocked; Abandon is the only exit.
//   C02 the counterexample on the page: an unresolved DELETE whose fence
//       equals the CURRENT (identically reinstalled) pair's revision and
//       whose lookup is 404 — no control on the page can dispatch a DELETE.
//   B2 — the original unresolved marker is preserved:
//   C03 identity and startedAt survive Recover (404 / pending), Abandon →
//       Cancel; the page offers no Re-send path that could clear it.
//   C04 the challenge stage NEVER touches the marker store: nothing is
//       written while the challenge is in flight, nothing on its refusal
//       (operation_mismatch), nothing on cancel.
//   C05 CONTROL: the marker is armed at the confirm dispatch (present while
//       the confirm is in flight, retained when the answer is lost).
//   C06 CONTROL: a first-attempt terminal refusal (409 stale) leaves no
//       marker — the only marker that could exist is this attempt's own.
//   B3 — persisted material changed; the running listener is unaffected;
//       what the next start serves depends on the startup configuration:
//   C07 delete ceremony + outcome under tls_configured / tls_custom (served)
//       / unknown / plain_http: the posture FACT is stated, "depends on the
//       startup configuration" is stated, and neither promises a self-signed
//       fallback nor that the next restart serves anything in particular.
//   C08 replace ceremony + outcome under the same four postures, same rule.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CertificatesPage } from "../features/security/CertificatesPage";
import { ToastProvider } from "../design-system/toast";
import { CERT_RECOVERY_KEY } from "../features/security/certRecovery";
import { isRecord } from "../api/decode";
import {
  CA_STATUS_HEALTHY,
  HEX64,
  HEX64_B,
  INVENTORY_HEALTHY,
  LISTENER_CONFIGURED,
  LISTENER_CUSTOM_A,
  LISTENER_NET,
  LISTENER_PLAIN,
  LISTENER_SELF_SIGNED,
  LISTENER_UNKNOWN,
  OCSP_STATUS_DEFAULT,
  OP_ID,
  OP_PENDING,
  UI_FP,
} from "./fe6b1-fixtures";
import {
  CERT_PEM_CANARY,
  CHALLENGE_ANSWER,
  DELETE_RESULT,
  KEY_PEM_CANARY,
  REPLACE_DRY_RUN,
  REPLACE_RESULT,
  UI_PERSISTED_AFTER_REPLACE,
  json,
  refusalBody,
} from "./fe6b2-fixtures";

interface Call {
  url: string;
  method: string;
  body: unknown;
}
const OP_UUID: `${string}-${string}-${string}-${string}-${string}` =
  "6b1c0000-fe6b-4e2e-9f00-00000000c001";
let container: HTMLDivElement;
let root: Root;
let calls: Call[];
let route: (c: Call) => Response | Promise<Response>;
let inventory: unknown;
let network: unknown;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  calls = [];
  inventory = INVENTORY_HEALTHY;
  network = LISTENER_NET(LISTENER_SELF_SIGNED, true, false);
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
    if (u.pathname === "/api/settings/network") return json(network);
  }
  return Promise.reject(new TypeError(`unrouted ${c.method} ${c.url}`));
}

async function mount(): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/certificates", element: <CertificatesPage /> }],
    { initialEntries: ["/security/certificates"] },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
function fieldByLabel(label: string): HTMLInputElement | HTMLTextAreaElement {
  for (const l of Array.from(document.querySelectorAll("label"))) {
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
const mutations = (): Call[] => calls.filter((c) => c.method !== "GET");
const storageRaw = (): string =>
  sessionStorage.getItem(CERT_RECOVERY_KEY) ?? "";
const marker = (): Record<string, unknown> => {
  const v: unknown = JSON.parse(storageRaw() || "{}");
  return isRecord(v) ? v : {};
};
function seedMarker(m: Record<string, unknown>): Record<string, unknown> {
  const stored = { version: 1, subject: "admin-user", ...m };
  sessionStorage.setItem(CERT_RECOVERY_KEY, JSON.stringify(stored));
  return stored;
}
const T0 = 1_758_276_000_000;
const ROTATE_MARKER = {
  operationId: OP_ID,
  action: "rotate",
  fence: `car1:${HEX64}`,
  candidate: "",
  previousFingerprint: HEX64,
  startedAt: T0,
};
/** An unresolved delete fenced on the revision the CURRENT persisted pair
 * carries (INVENTORY_HEALTHY.uiCert.revision) — the identically reinstalled
 * pair of the B1 counterexample. */
const DELETE_MARKER = {
  operationId: OP_ID,
  action: "delete",
  fence: `uic1:${HEX64_B}`,
  candidate: "",
  previousFingerprint: "",
  startedAt: T0,
};
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
const NOT_FOUND = (): Response => json(refusalBody("not_found"), 404);
/** The candidate's "never recorded" reading — none of it may survive. */
const NEVER_RECORDED = [
  "never recorded",
  "did not start",
  "may be re-sent",
  "proof of non-commit",
  "current object state",
];
async function recoverTo404(): Promise<void> {
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("retains no record");
  });
}

// ── B1 ──────────────────────────────────────────────────────────────────────
it("C01 Recover ⇒ 404 ⇒ UNKNOWN: no record retained, no Re-send, marker kept, mutations blocked, Abandon only", async () => {
  seedMarker(ROTATE_MARKER);
  withMutations({ [`/api/ca/operations/${OP_ID}`]: NOT_FOUND });
  await mount();
  await recoverTo404();
  expect(text()).toContain("cannot be known");
  for (const phrase of NEVER_RECORDED) expect(text()).not.toContain(phrase);
  expect(buttons("Re-send")).toEqual([]);
  expect(buttons("Abandon")).toHaveLength(1);
  expect(buttons("Recover")).toHaveLength(1);
  expect(marker()["operationId"]).toBe(OP_ID);
  for (const m of MUTATIONS) expect(button(m).disabled).toBe(true);
  // A second lookup answers the same; nothing changes and nothing is sent.
  await click("Recover");
  await flushUntil(() => {
    expect(text()).not.toContain("Looking the operation up");
  });
  expect(text()).toContain("retains no record");
  expect(buttons("Re-send")).toEqual([]);
  expect(mutations()).toEqual([]);
  expect(marker()["startedAt"]).toBe(T0);
});

it("C02 the counterexample on the page: an absent DELETE whose fence matches the reinstalled pair cannot be dispatched again", async () => {
  seedMarker(DELETE_MARKER);
  withMutations({
    [`/api/ca/operations/${OP_ID}`]: NOT_FOUND,
    "/api/certs/ui": () => json(DELETE_RESULT),
  });
  await mount();
  // The current pair carries exactly the marker's fence (identical bytes ⇒
  // identical token): the candidate offered a re-send here.
  expect(text()).toContain(`uic1:${HEX64_B}`);
  await recoverTo404();
  expect(buttons("Re-send")).toEqual([]);
  expect(button("Delete UI certificate…").disabled).toBe(true);
  // Every enabled control of the unresolved card except Abandon, clicked:
  // none opens a ceremony and none dispatches a mutation (on the candidate,
  // Re-send opened the delete ceremony whose confirm would DELETE again).
  const card = Array.from(container.querySelectorAll('[role="alert"]')).find(
    (e) => (e.textContent ?? "").includes("Unresolved certificate operation"),
  );
  if (card === undefined) throw new Error("no unresolved card");
  const enabled = Array.from(card.querySelectorAll("button")).filter(
    (b) => !b.disabled && (b.textContent ?? "").trim() !== "Abandon",
  );
  expect(enabled.length).toBeGreaterThan(0); // Recover at least
  for (const b of enabled) {
    await act(async () => {
      b.click();
      await Promise.resolve();
    });
  }
  await flushUntil(() => {
    expect(text()).not.toContain("Looking the operation up");
  });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(mutations()).toEqual([]);
  expect(text()).not.toContain("UI certificate deleted");
  expect(marker()["operationId"]).toBe(OP_ID);
  expect(marker()["fence"]).toBe(`uic1:${HEX64_B}`);
});

// ── B2 ──────────────────────────────────────────────────────────────────────
it("C03 the original marker's identity and startedAt survive every interaction the page offers; no Re-send path exists", async () => {
  const seeded = seedMarker(ROTATE_MARKER);
  let lookup: () => Response = NOT_FOUND;
  withMutations({ [`/api/ca/operations/${OP_ID}`]: () => lookup() });
  await mount();
  await recoverTo404();
  expect(buttons("Re-send")).toEqual([]);
  // Abandon opened and cancelled: the marker is untouched.
  await click("Abandon");
  await flushUntil(() => {
    expect(dialogText()).toContain("Abandon the unresolved operation");
  });
  expect(button("Abandon", openDialog()).disabled).toBe(true); // typed word
  await click("Cancel", openDialog());
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(marker()).toEqual(seeded);
  // A later lookup that finds the record pending keeps it too.
  lookup = () =>
    json({
      ...OP_PENDING,
      action: "ca.rotate",
      candidateFingerprint: undefined,
    });
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("still pending");
  });
  expect(marker()).toEqual(seeded);
  expect(buttons("Re-send")).toEqual([]);
  expect(mutations()).toEqual([]);
});

it("C04 the challenge stage never touches the marker store: in flight, on operation_mismatch, on cancel", async () => {
  let release: (r: Response) => void = () => undefined;
  withMutations({
    "/api/ca/rotate/challenge": () =>
      new Promise<Response>((res) => {
        release = res;
      }),
  });
  await mount();
  await click("Rotate Root CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Rotate the Root CA");
  });
  await click("Request challenge", openDialog());
  await flushUntil(() => {
    expect(
      calls.filter((c) => c.url.includes("/api/ca/rotate/challenge")),
    ).toHaveLength(1);
  });
  expect(storageRaw()).toBe(""); // nothing durable is at stake at the challenge
  // The contracted shape: 409 + current.operationId + current.state (a known
  // id — the refusal the candidate cleared the ORIGINAL marker on).
  release(
    json(
      refusalBody("operation_mismatch", {
        operationId: OP_ID,
        state: "committed",
      }),
      409,
    ),
  );
  await flushUntil(() => {
    expect(text()).toContain("Root CA rotation refused");
  });
  expect(storageRaw()).toBe("");
  expect(mutations()).toHaveLength(1); // the challenge request only
  // A fresh ceremony cancelled at step 1 writes nothing either.
  await click("Rotate Root CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Rotate the Root CA");
  });
  await click("Cancel", openDialog());
  expect(storageRaw()).toBe("");
});

it("C05 CONTROL: the marker is armed at the confirm dispatch and retained when the answer is lost", async () => {
  let release: (r: Response) => void = () => undefined;
  withMutations({
    "/api/ca/rotate/challenge": () => json(CHALLENGE_ANSWER),
    "/api/ca/rotate": () =>
      new Promise<Response>((res) => {
        release = res;
      }),
  });
  await mount();
  await click("Rotate Root CA…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Rotate the Root CA");
  });
  await click("Request challenge", openDialog());
  await flushUntil(() => {
    expect(dialogText()).toContain("2026-09-19T10:02:00Z");
  });
  await type("Type ROTATE to confirm", "ROTATE");
  await click("Rotate", openDialog());
  await flushUntil(() => {
    expect(calls.filter((c) => c.url.includes("/api/ca/rotate?"))).toHaveLength(
      1,
    );
  });
  expect(marker()["operationId"]).toBe(OP_ID);
  expect(marker()["action"]).toBe("rotate");
  expect(marker()["fence"]).toBe(`car1:${HEX64}`);
  expect(marker()["previousFingerprint"]).toBe(HEX64);
  release(new Response(null, { status: 502 }));
  await flushUntil(() => {
    expect(text()).toContain("Unresolved certificate operation");
  });
  expect(marker()["operationId"]).toBe(OP_ID);
  expect(document.querySelector("dialog[open]")).toBeNull();
});

it("C06 CONTROL: a first-attempt terminal refusal (409 stale) leaves no marker", async () => {
  withMutations({
    "/api/ocsp": () =>
      json(refusalBody("stale", { ocspRevision: `ocr1:${HEX64_B}` }), 409),
  });
  await mount();
  await click("Set OCSP posture…");
  await flushUntil(() => {
    expect(dialogText()).toContain("Set the OCSP posture");
  });
  await toggle("Enable OCSP revocation checking");
  await click("Apply", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("OCSP posture change refused");
  });
  expect(text()).toContain(`ocr1:${HEX64_B}`);
  expect(storageRaw()).toBe("");
  for (const m of MUTATIONS) expect(button(m).disabled).toBe(false);
});

// ── B3 ──────────────────────────────────────────────────────────────────────
const CLAIMS =
  /self-signed|falls back|takes effect|next restart serves|serves this one|restart, which/i;
const STARTUP = "depends on the startup configuration";
interface Posture {
  name: string;
  listener: Record<string, unknown>;
  /** the fact about the running listener the copy must state */
  fact: string;
  /** the persisted pair is the one served */
  served: boolean;
}
const POSTURES: Posture[] = [
  {
    name: "tls_configured (an explicitly configured pair is served)",
    listener: LISTENER_CONFIGURED,
    fact: "explicitly configured",
    served: false,
  },
  {
    name: "tls_custom (the persisted pair is served)",
    listener: LISTENER_CUSTOM_A(true),
    fact: "keeps serving",
    served: true,
  },
  {
    name: "unknown (no bind evidence)",
    listener: LISTENER_UNKNOWN,
    fact: "not observed",
    served: false,
  },
  {
    name: "plain_http (no TLS on the running listener)",
    listener: LISTENER_PLAIN,
    fact: "plain HTTP",
    served: false,
  },
];
function statusText(title: string): string {
  const el = Array.from(container.querySelectorAll('[role="status"]')).find(
    (e) => (e.textContent ?? "").includes(title),
  );
  return el?.textContent ?? "";
}
function underPosture(p: Posture): void {
  inventory = {
    ...INVENTORY_HEALTHY,
    listener: p.listener,
    uiCert: { ...INVENTORY_HEALTHY.uiCert, active: p.served },
  };
  network = LISTENER_NET(p.listener, true, p.served);
}

for (const p of POSTURES) {
  it(`C07 delete under ${p.name}: the fact is stated; what the next start serves is not promised`, async () => {
    underPosture(p);
    withMutations({ "/api/certs/ui": () => json(DELETE_RESULT) });
    await mount();
    await click("Delete UI certificate…");
    await flushUntil(() => {
      expect(dialogText()).toContain("Delete the UI certificate");
    });
    const d = dialogText();
    expect(d).toContain(p.fact);
    expect(d).toContain("running listener");
    expect(d).toContain(STARTUP);
    expect(d).not.toMatch(CLAIMS);
    const word = UI_FP.slice(0, 23);
    await type(`Type ${word} to confirm`, word);
    await click("Delete", openDialog());
    await flushUntil(() => {
      expect(text()).toContain("UI certificate deleted");
    });
    const out = statusText("UI certificate deleted");
    expect(out).toContain("persisted");
    expect(out).toContain("running listener");
    expect(out).toContain(STARTUP);
    expect(out).not.toMatch(CLAIMS);
  });

  it(`C08 replace under ${p.name}: the fact is stated; what the next start serves is not promised`, async () => {
    underPosture(p);
    withMutations({
      "/api/certs/upload": (c) =>
        new URL(c.url, "http://x").searchParams.get("dryRun") === "1"
          ? json(REPLACE_DRY_RUN)
          : json({ ...REPLACE_RESULT, uiCert: UI_PERSISTED_AFTER_REPLACE }),
    });
    await mount();
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
    const d = dialogText();
    expect(d).toContain("restart_required");
    expect(d).toContain(STARTUP);
    expect(d).not.toMatch(CLAIMS);
    await click("Replace", openDialog());
    await flushUntil(() => {
      expect(text()).toContain("UI certificate replaced");
    });
    const out = statusText("UI certificate replaced");
    expect(out).toContain("persisted");
    expect(out).toContain("running listener");
    expect(out).toContain(STARTUP);
    expect(out).not.toMatch(CLAIMS);
  });
}
