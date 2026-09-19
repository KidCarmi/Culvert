// FE-6B.1 CORRECTION ROUND — RED matrix (page), committed on the reviewed
// candidate 935891f4 BEFORE any product change. Pins the browser-side
// guarantees the external review found missing:
//
//   B1 — activation is rendered from the server-owned listener evidence, never
//        from the boot-time `active` flag.
//   Q1  A served, B persisted (no restart): the page names the SERVED identity
//       (A), says the persisted pair activates on restart, and never claims
//       "Active on the running listener".
//   Q2  after the restart (served == persisted) the claim is made.
//   Q3  a plain-HTTP listener: stated as plain HTTP; no activation claim.
//   Q4  an explicitly configured certificate: named as such with its identity;
//       the persisted pair is never used; no restart claim.
//   Q5  listener evidence unknown: NO activation claim of any kind.
//   Q6  the network-settings cross-check failing does not withdraw a claim
//       that rests on the inventory's own listener evidence; the failed
//       cross-check is stated.
//   Q7  deleted while served: the served identity is named, "no longer
//       persisted", no activation claim.
//
//   B2 — no durability claim beyond the frozen contract.
//   Q8  a rotation persist failure renders the bounded class only — never
//       "memory-only", "not on disk" or a restart re-rotation.
//   Q9  a committed record's audit is qualified by the inventory's audit
//       sink: file ⇒ persisted, memory ⇒ in memory only, inventory
//       unavailable ⇒ sink evidence unavailable — "durable" is never said
//       without the file sink.
//   Q10 the page never asserts that nothing on it is exported, rolled back or
//       synced (the CA bundle IS archived by backup).
//
//   B3 — an unbound or contradictory lookup answer is UNVERIFIED.
//   Q11 X requested / Y answered ⇒ "could not be verified", no verdict;
//       a not_found code on a 500 or on text/plain ⇒ not "No retained
//       operation record".
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
import {
  CA_STATUS_DEGRADED,
  CA_STATUS_HEALTHY,
  CONF_FP,
  INVENTORY_HEALTHY,
  LEDGER_OK,
  LISTENER_CONFIGURED,
  LISTENER_CUSTOM_A,
  LISTENER_NET,
  LISTENER_PLAIN,
  LISTENER_SELF_SIGNED,
  LISTENER_UNKNOWN,
  OCSP_STATUS_DEFAULT,
  OP_COMMITTED,
  OP_ID,
  RAW_CANARY,
  UI_ABSENT,
  UI_ACTIVE_PERSISTED,
  UI_FP,
  UI_FP_B,
  UI_PERSISTED_B,
  UI_PERSISTED_NOT_ACTIVE,
  okJSON,
} from "./fe6b1-fixtures";

let container: HTMLDivElement;
let root: Root;
let requests: Array<{ method: string; url: string }>;
let route: (url: string) => Promise<Response>;

function defaultRoute(url: string): Promise<Response> {
  if (url.startsWith("/api/certificates")) return okJSON(INVENTORY_HEALTHY);
  if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_HEALTHY);
  if (url.startsWith("/api/ocsp")) return okJSON(OCSP_STATUS_DEFAULT);
  if (url.startsWith("/api/settings/network"))
    return okJSON(LISTENER_NET(LISTENER_SELF_SIGNED, true, false));
  if (url.startsWith("/api/ca/operations/")) return okJSON(OP_COMMITTED);
  return Promise.reject(new TypeError(`unexpected ${url}`));
}

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  requests = [];
  route = defaultRoute;
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      requests.push({ method: init?.method ?? "GET", url });
      return route(url);
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

type RoleName = "viewer" | "admin";

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

async function mount(
  role: RoleName,
  path = "/security/certificates",
): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/certificates", element: <CertificatesPage /> }],
    { initialEntries: [path] },
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

function text(): string {
  return container.textContent ?? "";
}

async function click(name: string): Promise<void> {
  const btn = Array.from(container.querySelectorAll("button")).find(
    (b) => (b.textContent ?? "").trim() === name,
  );
  if (btn === undefined) throw new Error(`no button ${name}`);
  await act(async () => {
    btn.click();
    await Promise.resolve();
  });
}

async function typeInto(label: string, value: string): Promise<void> {
  const input = Array.from(container.querySelectorAll("input")).find((i) => {
    const id = i.getAttribute("id");
    const lab =
      id !== null ? container.querySelector(`label[for="${id}"]`) : null;
    return (lab?.textContent ?? "").trim() === label;
  });
  if (input === undefined) throw new Error(`no input ${label}`);
  await act(async () => {
    Reflect.set(HTMLInputElement.prototype, "value", value, input);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await Promise.resolve();
  });
}

function routeWith(
  uiCert: Record<string, unknown>,
  listener: Record<string, unknown>,
  net: Record<string, unknown>,
  extra: Record<string, unknown> = {},
): void {
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({ ...INVENTORY_HEALTHY, uiCert, listener, ...extra });
    if (url.startsWith("/api/settings/network")) return okJSON(net);
    return defaultRoute(url);
  };
}

const NO_CLAIMS = [
  "Active on the running listener",
  "Not active on the running listener",
  "Activation requires a restart",
];

// ── B1 ──────────────────────────────────────────────────────────────────────

it("Q1 A served, B persisted: the served identity is named, restart activates B, no activation claim", async () => {
  routeWith(
    UI_PERSISTED_B,
    LISTENER_CUSTOM_A(false),
    LISTENER_NET(LISTENER_CUSTOM_A(false), true, false),
  );
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain(UI_FP_B);
  });
  const t = text();
  expect(t).toContain("Complete pair persisted");
  expect(t).toContain("Listener serves");
  expect(t).toContain(UI_FP); // the SERVED pair, A
  expect(t).toContain("Activation requires a restart");
  expect(t).not.toContain("Active on the running listener");
});

it("Q2 served == persisted after the restart: active", async () => {
  routeWith(
    UI_ACTIVE_PERSISTED,
    LISTENER_CUSTOM_A(true),
    LISTENER_NET(LISTENER_CUSTOM_A(true), true, true),
  );
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("Active on the running listener");
  });
  expect(text()).not.toContain("Activation requires a restart");
  expect(text()).not.toContain("Contradictory listener facts");
});

it("Q3 plain HTTP: stated, and the persisted pair is not in use", async () => {
  routeWith(
    UI_PERSISTED_NOT_ACTIVE,
    LISTENER_PLAIN,
    LISTENER_NET(LISTENER_PLAIN, true, false),
  );
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("plain HTTP");
  });
  expect(text()).toContain("not in use");
  expect(text()).not.toContain("Active on the running listener");
  expect(text()).not.toContain("Contradictory listener facts");
});

it("Q4 an explicitly configured certificate is served; the persisted pair is never used", async () => {
  routeWith(
    UI_PERSISTED_NOT_ACTIVE,
    LISTENER_CONFIGURED,
    LISTENER_NET(LISTENER_CONFIGURED, true, false),
  );
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain(CONF_FP);
  });
  const t = text();
  expect(t).toContain("explicitly configured");
  expect(t).not.toContain("Active on the running listener");
  expect(t).not.toContain("Activation requires a restart");
});

it("Q5 unknown listener evidence: no activation claim of any kind", async () => {
  routeWith(
    UI_PERSISTED_NOT_ACTIVE,
    LISTENER_UNKNOWN,
    LISTENER_NET(LISTENER_UNKNOWN, true, false),
  );
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("Complete pair persisted");
  });
  const t = text();
  expect(t).toContain("not been observed");
  for (const c of NO_CLAIMS) expect(t).not.toContain(c);
});

it("Q6 a failed cross-check read does not withdraw an evidence-backed claim; the failure is stated", async () => {
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({
        ...INVENTORY_HEALTHY,
        uiCert: UI_ACTIVE_PERSISTED,
        listener: LISTENER_CUSTOM_A(true),
      });
    if (url.startsWith("/api/settings/network"))
      return Promise.resolve(
        new Response(`gone ${RAW_CANARY}`, {
          status: 503,
          headers: { "Content-Type": "text/plain" },
        }),
      );
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("Active on the running listener");
  });
  expect(text()).toContain("cross-check");
  expect(text()).toContain("HTTP 503");
  expect(text()).not.toContain(RAW_CANARY);
});

it("Q7 deleted while served: the served identity is named, no longer persisted, no claim", async () => {
  routeWith(
    UI_ABSENT,
    LISTENER_CUSTOM_A(false),
    LISTENER_NET(LISTENER_CUSTOM_A(false), false, false),
  );
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("no longer persisted");
  });
  const t = text();
  expect(t).toContain(UI_FP);
  expect(t).toContain("No persisted pair");
  expect(t).not.toContain("Active on the running listener");
  expect(t).not.toContain("Activation requires a restart");
});

// ── B2 ──────────────────────────────────────────────────────────────────────

it("Q8 a rotation persist failure renders the bounded class, never an inferred live/disk divergence", async () => {
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({
        ...INVENTORY_HEALTHY,
        ca: {
          ...INVENTORY_HEALTHY.ca,
          persistDegraded: true,
          persistClass: "no_space",
        },
      });
    if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_DEGRADED);
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("no_space");
  });
  const bad =
    /not on disk|memory-only|memory only|in memory|re-rotat|rotated but/i;
  expect(text()).not.toMatch(bad);
  await click("CA Management");
  await flushUntil(() => {
    expect(text()).toContain("Last rotation could not be persisted");
  });
  expect(text()).not.toMatch(bad);
  expect(text()).not.toContain("restart re-rotates");
});

it("Q9 an audited commit is qualified by the audit sink; durable is never said without the file sink", async () => {
  await mount("admin");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  await typeInto("Operation ID", OP_ID);
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Committed");
  });
  let rec =
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    "";
  expect(rec).toContain("Audited");
  expect(rec).toContain("file sink"); // LEDGER_OK.auditSink === "file"
  act(() => {
    root.unmount();
  });

  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({
        ...INVENTORY_HEALTHY,
        operations: { ...LEDGER_OK, auditSink: "memory" },
      });
    return defaultRoute(url);
  };
  await mount("admin");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  await typeInto("Operation ID", OP_ID);
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Committed");
  });
  rec =
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    "";
  expect(rec).toContain("memory sink");
  expect(rec).not.toMatch(/durabl|persisted|file sink/i);
  act(() => {
    root.unmount();
  });

  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return Promise.resolve(
        new Response("gone", {
          status: 503,
          headers: { "Content-Type": "text/plain" },
        }),
      );
    return defaultRoute(url);
  };
  await mount("admin");
  await flushUntil(() => {
    expect(text()).toContain("HTTP 503");
  });
  await typeInto("Operation ID", OP_ID);
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Committed");
  });
  rec =
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    "";
  expect(rec).toContain("sink evidence unavailable");
  expect(rec).not.toMatch(/durabl/i);
});

it("Q10 the page makes no blanket export/rollback/sync claim", async () => {
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  expect(text()).not.toContain("nothing here is exported");
  expect(text()).not.toMatch(/nothing here is exported, rolled back or synced/);
});

// ── B3 ──────────────────────────────────────────────────────────────────────

it("Q11 an unbound or mis-shaped lookup answer is unverified, never a verdict", async () => {
  const OTHER = "6b1c0000-fe6b-4e2e-9f00-00000000dddd";
  let mode: "other" | "500json" | "404text" = "other";
  route = (url) => {
    if (url.startsWith("/api/ca/operations/")) {
      if (mode === "other")
        return okJSON({ ...OP_COMMITTED, operationId: OTHER });
      if (mode === "500json")
        return Promise.resolve(
          new Response(JSON.stringify({ error: "x", code: "not_found" }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
          }),
        );
      return Promise.resolve(
        new Response('{"error":"x","code":"not_found"}', {
          status: 404,
          headers: { "Content-Type": "text/plain" },
        }),
      );
    }
    return defaultRoute(url);
  };
  await mount("admin");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  await typeInto("Operation ID", OP_ID);
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("could not be verified");
  });
  let rec =
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    "";
  expect(rec).not.toContain("Committed");
  expect(rec).not.toContain(OTHER);

  mode = "500json";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("HTTP 500");
  });
  rec =
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    "";
  expect(rec).not.toContain("No retained operation record");

  mode = "404text";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("HTTP 404");
  });
  rec =
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    "";
  expect(rec).not.toContain("No retained operation record");
  expect(
    requests.filter((r) => r.url.includes("/api/ca/operations/")),
  ).toHaveLength(3);
});
