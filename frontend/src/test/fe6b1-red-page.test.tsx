// FE-6B.1 RED matrix (page) — written against the frozen FE-6B.0 entry
// baseline (c540b176) BEFORE the Certificates & CA surface exists; fails at
// import resolution there. Pins the browser-side guarantees of the FE-6B.1
// directive against the frozen FE-6B.0 backend read models, rendered from
// STRUCTURED server facts (never prose that compensates for the appliance):
//
//   P1  viewer, healthy node: the CA identity / revision / usability /
//       persistence / encryption, the persisted UI pair with its revision and
//       "activation requires a restart", the mTLS posture, OCSP desired vs
//       runtime vs durable, the ledger posture and the backup facts render;
//       the page mounts ONLY the tab, Refresh and the PEM-download controls,
//       issues ZERO non-GET requests, ZERO admin-only lookups, and writes
//       nothing to web storage.
//   P2  degraded node: bounded classes only (bundle_malformed, no_ca,
//       key_file_missing, ledger corrupt) — the raw detail line never reaches
//       the DOM; the corrupt pair, the incomplete pair, the unavailable pair
//       ("not absent") and the positively absent pair are four DISTINCT
//       renderings.
//   P3  persisted vs active vs durability: active+persisted, persisted
//       without activation (restart required), active without a persisted
//       pair (the listener holds a pair that is no longer on disk); a
//       listener that fell back to plain HTTP while the pair claims active
//       is a CONTRADICTION callout — no activation claim, and the raw
//       fallback reason never renders.
//   P4  OCSP: desired (source, durable) and runtime are rendered as two
//       facts; a disagreement is stated, never resolved into one; the
//       coverage rows state which handshake paths are checked and the
//       unchecked ENFORCING path is an evidence limitation; node-local.
//   P5  admin lookup: an explicit "Look up" of a typed operation id issues
//       exactly ONE GET (no polling), and every state renders as the server
//       states it — pending; committed (+ owed audit = "audit pending", not
//       a failed mutation); aborted + code; recoverable unknown + code;
//       terminal superseded unknown naming the writer and NEVER the words
//       succeeded / failed / cancelled / retry; 404 = no retained record;
//       503 operation_ledger_degraded = the refusal code; a malformed id is
//       refused client-side with no request; a viewer / operator sees no
//       lookup control and issues no lookup.
//   P6  a raw server error body (500) and a secret-bearing 200 both end in a
//       bounded error state; the canaries never reach the DOM.
//   P7  Refresh keeps truth: a failed refresh keeps the previous snapshot
//       visible behind the explicit stale indicator and does not advance
//       "Updated"; the snapshots are INDEPENDENT (a failed CA-status read
//       leaves the inventory rendered and the CA card in an error state).
//   P8  tabs + deep link: ?tab=ca selects CA Management; an unknown tab
//       value falls back to Certificates; the CA Management tab renders the
//       rotation, recovery-campaign, dual-CA, cache and OCSP facts.
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
  CA_STATUS_DUAL,
  CA_STATUS_HEALTHY,
  HEX64,
  HEX64_B,
  INVENTORY_DEGRADED,
  INVENTORY_HEALTHY,
  LISTENER_FALLBACK,
  LISTENER_TLS,
  OCSP_STATUS_ADMIN_DIFFERS,
  OCSP_STATUS_DEFAULT,
  OP_ABORTED,
  OP_COMMITTED,
  OP_COMMITTED_AUDIT_PENDING,
  OP_ID,
  OP_PENDING,
  OP_SUPERSEDED,
  OP_UNKNOWN_RECOVERABLE,
  OP_WRITER,
  RAW_CANARY,
  SECRET_CANARY,
  UI_ABSENT,
  UI_ACTIVE_NOT_PERSISTED,
  UI_ACTIVE_PERSISTED,
  UI_INCOMPLETE,
  UI_UNAVAILABLE,
  okJSON,
  refusal,
} from "./fe6b1-fixtures";

let container: HTMLDivElement;
let root: Root;
let requests: Array<{ method: string; url: string }>;
let route: (url: string) => Promise<Response>;

function defaultRoute(url: string): Promise<Response> {
  if (url.startsWith("/api/certificates")) return okJSON(INVENTORY_HEALTHY);
  if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_HEALTHY);
  if (url.startsWith("/api/ocsp")) return okJSON(OCSP_STATUS_DEFAULT);
  if (url.startsWith("/api/settings/network")) return okJSON(LISTENER_TLS);
  if (url.startsWith("/api/ca/operations/")) return okJSON(OP_COMMITTED);
  return Promise.reject(new TypeError(`unexpected ${url}`));
}

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  requests = [];
  route = defaultRoute;
  sessionStorage.clear();
  localStorage.clear();
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

function buttonTexts(): string[] {
  return Array.from(container.querySelectorAll("button")).map((b) =>
    (b.textContent ?? "").trim(),
  );
}

function nonGET(): Array<{ method: string; url: string }> {
  return requests.filter((r) => r.method !== "GET");
}

function lookups(): Array<{ method: string; url: string }> {
  return requests.filter((r) => r.url.includes("/api/ca/operations/"));
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
    return (
      (lab?.textContent ?? "").trim() === label ||
      i.getAttribute("aria-label") === label
    );
  });
  if (input === undefined) throw new Error(`no input ${label}`);
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;
  await act(async () => {
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await Promise.resolve();
  });
}

/** The ONLY controls a viewer may see. */
const VIEWER_CONTROLS: readonly string[] = [
  "Certificates",
  "CA Management",
  "Refresh",
  "Download CA certificate (PEM)",
];
const ADMIN_CONTROLS: readonly string[] = [...VIEWER_CONTROLS, "Look up"];

// ── P1 ──────────────────────────────────────────────────────────────────────

it("P1 viewer, healthy node: every server fact renders; only tab/Refresh/download controls; no non-GET; no lookup; no storage", async () => {
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  const t = text();
  expect(t).toContain("Node-local");
  expect(t).toContain(`car1:${HEX64}`);
  expect(t).toContain(INVENTORY_HEALTHY.ca.fingerprint);
  expect(t).toContain("Usable");
  expect(t).toContain("Bundle path configured");
  expect(t).toContain("Encrypted at rest");
  expect(t).toContain("Complete pair persisted");
  expect(t).toContain(`uic1:${HEX64_B}`);
  expect(t).toContain("ui.example");
  expect(t).toContain("Not active on the running listener");
  expect(t).toContain("Activation requires a restart");
  expect(t).toContain("Not configured"); // mTLS client certificate
  expect(t).toContain("Desired: Disabled");
  expect(t).toContain("source: default");
  expect(t).toContain("Runtime: Disabled");
  expect(t).toContain("Not durable");
  expect(t).toContain("Retained: 4 of 256");
  expect(t).toContain("Unresolved intents: 1");
  expect(t).toContain("Audit sink: file");
  expect(t).toContain("UI pair: never archived");
  expect(t).toContain("Operation ledger: never archived");
  expect(t).toContain("CA bundle: archived (encrypted)");
  expect(t).toContain("Config-version rollback: off");
  expect(t).not.toContain("Look up");
  expect(buttonTexts().every((b) => VIEWER_CONTROLS.includes(b))).toBe(true);
  expect(buttonTexts()).toContain("Refresh");
  expect(
    container.querySelectorAll("input,select,textarea,dialog,form").length,
  ).toBe(0);
  expect(nonGET()).toEqual([]);
  expect(lookups()).toEqual([]);
  expect(sessionStorage.length).toBe(0);
  expect(localStorage.length).toBe(0);
});

// ── P2 ──────────────────────────────────────────────────────────────────────

it("P2 degraded node: bounded classes, corrupt pair, ledger reason without its detail", async () => {
  route = (url) => {
    if (url.startsWith("/api/certificates")) return okJSON(INVENTORY_DEGRADED);
    if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_DEGRADED);
    if (url.startsWith("/api/ocsp")) return okJSON(OCSP_STATUS_ADMIN_DIFFERS);
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("bundle_malformed");
  });
  const t = text();
  expect(t).toContain("No Root CA is installed");
  expect(t).toContain("no_ca");
  expect(t).toContain("Load failed");
  expect(t).toContain("Not encrypted at rest");
  expect(t).toContain("did not parse as a matching pair");
  expect(t).toContain("Not loaded");
  expect(t).toContain("key_file_missing");
  expect(t).toContain("Operation ledger degraded");
  expect(t).toContain("corrupt");
  expect(t).not.toContain(RAW_CANARY);
  expect(nonGET()).toEqual([]);
});

it("P2b the four pair evidence classes are distinct renderings", async () => {
  const cases: Array<[Record<string, unknown>, string, string[]]> = [
    [UI_ABSENT, "No persisted pair", ["positively absent"]],
    [UI_INCOMPLETE, "Incomplete pair", ["exactly one of the two files"]],
    [
      UI_UNAVAILABLE,
      "Evidence unavailable",
      ["cannot be examined or read", "not absent"],
    ],
  ];
  for (const [ui, head, more] of cases) {
    route = (url) => {
      if (url.startsWith("/api/certificates"))
        return okJSON({ ...INVENTORY_HEALTHY, uiCert: ui });
      if (url.startsWith("/api/settings/network"))
        return okJSON({ ...LISTENER_TLS, ui_custom_cert_uploaded: false });
      return defaultRoute(url);
    };
    await mount("viewer");
    await flushUntil(() => {
      expect(text()).toContain(head);
    });
    for (const m of more) expect(text()).toContain(m);
    expect(text()).toContain(String(ui["revision"]));
    expect(text()).not.toContain("Activation requires a restart");
    act(() => {
      root.unmount();
    });
  }
  // keep afterEach's unmount valid
  await mount("viewer");
});

// ── P3 ──────────────────────────────────────────────────────────────────────

it("P3 persisted vs active vs durability are three distinct facts", async () => {
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({ ...INVENTORY_HEALTHY, uiCert: UI_ACTIVE_PERSISTED });
    if (url.startsWith("/api/settings/network"))
      return okJSON({ ...LISTENER_TLS, ui_custom_cert_active: true });
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("Active on the running listener");
  });
  expect(text()).toContain("Complete pair persisted");
  expect(text()).not.toContain("Activation requires a restart");
  act(() => {
    root.unmount();
  });

  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({ ...INVENTORY_HEALTHY, uiCert: UI_ACTIVE_NOT_PERSISTED });
    if (url.startsWith("/api/settings/network"))
      return okJSON({
        ...LISTENER_TLS,
        ui_custom_cert_uploaded: false,
        ui_custom_cert_active: true,
      });
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("no longer persisted");
  });
  expect(text()).toContain("Active on the running listener");
  expect(text()).toContain("No persisted pair");
  act(() => {
    root.unmount();
  });

  // Contradiction: the pair claims active while the listener fell back to
  // plain HTTP — no activation claim, the raw reason never renders.
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({ ...INVENTORY_HEALTHY, uiCert: UI_ACTIVE_PERSISTED });
    if (url.startsWith("/api/settings/network"))
      return okJSON({
        ...LISTENER_FALLBACK,
        ui_custom_cert_uploaded: true,
        ui_custom_cert_active: true,
      });
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("Contradictory listener facts");
  });
  expect(text()).toContain("plain HTTP");
  expect(text()).not.toContain("Active on the running listener");
  expect(text()).not.toContain(RAW_CANARY);
  expect(text()).not.toContain("x509");
});

// ── P4 ──────────────────────────────────────────────────────────────────────

it("P4 OCSP desired vs runtime are two facts; coverage names the unchecked enforcing path", async () => {
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return okJSON({
        ...INVENTORY_HEALTHY,
        ocsp: INVENTORY_DEGRADED.ocsp,
      });
    if (url.startsWith("/api/ocsp")) return okJSON(OCSP_STATUS_ADMIN_DIFFERS);
    return defaultRoute(url);
  };
  await mount("viewer", "/security/certificates?tab=ca");
  await flushUntil(() => {
    expect(text()).toContain("Runtime differs from the desired posture");
  });
  const t = text();
  expect(t).toContain("Desired: Enabled");
  expect(t).toContain("source: admin");
  expect(t).toContain("Durable");
  expect(t).toContain("Runtime: Disabled");
  expect(t).toContain("upstream_transport");
  expect(t).toContain("ssl_inspect_origin");
  expect(t).toContain("Not checked");
  expect(t).toContain("Evidence limitation");
  expect(t).toContain("Node-local");
  expect(t).toContain("Fail-closed decisions: 2");
  expect(t).toContain("Revoked: 1");
  expect(nonGET()).toEqual([]);
});

// ── P5 ──────────────────────────────────────────────────────────────────────

async function lookup(id: string): Promise<void> {
  await typeInto("Operation ID", id);
  await click("Look up");
}

it("P5a admin lookup: one explicit GET per Look up, every state rendered as the server states it", async () => {
  const answers: Record<string, unknown> = {
    pending: OP_PENDING,
    committed: OP_COMMITTED,
    audit: OP_COMMITTED_AUDIT_PENDING,
    aborted: OP_ABORTED,
    recoverable: OP_UNKNOWN_RECOVERABLE,
    superseded: OP_SUPERSEDED,
  };
  let current = "pending";
  route = (url) => {
    if (url.startsWith("/api/ca/operations/")) return okJSON(answers[current]);
    return defaultRoute(url);
  };
  await mount("admin");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  expect(buttonTexts().every((b) => ADMIN_CONTROLS.includes(b))).toBe(true);
  expect(text()).toContain(
    "may settle a pending operation and complete its audit",
  );

  await lookup(OP_ID);
  await flushUntil(() => {
    expect(text()).toContain("Pending");
  });
  expect(lookups()).toHaveLength(1);
  expect(lookups()[0]?.url).toBe(`/api/ca/operations/${OP_ID}`);
  expect(text()).toContain("not yet decided");

  current = "committed";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Committed");
  });
  expect(lookups()).toHaveLength(2);
  expect(text()).toContain(`car1:${HEX64_B}`);
  expect(text()).toContain("Audited");

  current = "audit";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Audit pending");
  });
  expect(text()).toContain("not a failed");
  expect(text()).toContain("reconciled_committed");

  current = "aborted";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Aborted");
  });
  expect(text()).toContain("persist_failed");

  current = "recoverable";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Outcome unknown — recoverable");
  });
  expect(text()).toContain("reconciled_evidence_invalid");
  expect(text()).toContain("re-decided");

  current = "superseded";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("Outcome unknown — terminal");
  });
  const sup = text();
  expect(sup).toContain("superseded");
  expect(sup).toContain(OP_WRITER);
  const section = container.querySelector('[data-testid="operation-record"]');
  const st = (section?.textContent ?? "").toLowerCase();
  expect(st.length).toBeGreaterThan(0);
  expect(st).not.toMatch(/succeeded|failed|cancelled|canceled|retry|safe to/);
  expect(lookups()).toHaveLength(6); // one per explicit Look up, never a poll
  expect(nonGET()).toEqual([]);
});

it("P5b lookup refusals and a malformed id", async () => {
  let mode: "404" | "503" | "500" = "404";
  route = (url) => {
    if (url.startsWith("/api/ca/operations/")) {
      if (mode === "404") return refusal(404, "not_found");
      if (mode === "503") return refusal(503, "operation_ledger_degraded");
      return Promise.resolve(
        new Response(`boom ${RAW_CANARY}`, {
          status: 500,
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
  await lookup("nope");
  expect(lookups()).toEqual([]);
  expect(text()).toContain("not a UUID");

  await lookup(OP_ID);
  await flushUntil(() => {
    expect(text()).toContain("No retained operation record");
  });
  mode = "503";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("operation_ledger_degraded");
  });
  mode = "500";
  await click("Look up");
  await flushUntil(() => {
    expect(text()).toContain("HTTP 500");
  });
  expect(text()).not.toContain(RAW_CANARY);
  expect(lookups()).toHaveLength(3);
});

it("P5c viewer and operator never see nor issue the admin-only lookup", async () => {
  for (const role of ["viewer", "operator"] as const) {
    await mount(role);
    await flushUntil(() => {
      expect(text()).toContain("CULVERT Root CA");
    });
    expect(text()).not.toContain("Look up");
    expect(container.querySelectorAll("input").length).toBe(0);
    expect(lookups()).toEqual([]);
    act(() => {
      root.unmount();
    });
  }
  await mount("viewer");
});

// ── P6 ──────────────────────────────────────────────────────────────────────

it("P6 raw server text and secret-bearing answers end in bounded error states", async () => {
  route = (url) => {
    if (url.startsWith("/api/certificates"))
      return Promise.resolve(
        new Response(`fatal ${RAW_CANARY}`, {
          status: 500,
          headers: { "Content-Type": "text/plain" },
        }),
      );
    if (url.startsWith("/api/ca/status"))
      return okJSON({ ...CA_STATUS_HEALTHY, privateKey: SECRET_CANARY });
    return defaultRoute(url);
  };
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("HTTP 500");
  });
  await flushUntil(() => {
    expect(text()).toContain("could not be verified");
  });
  expect(text()).not.toContain(RAW_CANARY);
  expect(text()).not.toContain(SECRET_CANARY);
  expect(text()).not.toContain("CULVERT Root CA");
});

// ── P7 ──────────────────────────────────────────────────────────────────────

it("P7 refresh keeps truth and the snapshots are independent", async () => {
  await mount("viewer");
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  expect(text()).toMatch(/Updated \d\d:\d\d:\d\d/);
  // Next refresh: the inventory fails, the CA status still succeeds.
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
  await click("Refresh");
  await flushUntil(() => {
    expect(text()).toContain("Refresh failed — showing previous snapshot");
  });
  // the previous inventory is still on screen — never blank, never "current"
  expect(text()).toContain(`uic1:${HEX64_B}`);
  expect(text()).toContain("Complete pair persisted");
  act(() => {
    root.unmount();
  });

  // Independence: a failed CA-status read on first load leaves the
  // inventory rendered and the CA detail in a bounded error state.
  route = (url) => {
    if (url.startsWith("/api/ca/status"))
      return Promise.resolve(
        new Response("gone", {
          status: 503,
          headers: { "Content-Type": "text/plain" },
        }),
      );
    return defaultRoute(url);
  };
  await mount("viewer", "/security/certificates?tab=ca");
  await flushUntil(() => {
    expect(text()).toContain("HTTP 503");
  });
  expect(text()).toContain("Desired: Disabled"); // the OCSP read succeeded
  expect(text()).not.toContain("87599h0m0s");
});

// ── P8 ──────────────────────────────────────────────────────────────────────

it("P8 ?tab=ca deep-links CA Management; an unknown tab falls back; the CA tab renders rotation/recovery/dual-CA/cache facts", async () => {
  route = (url) => {
    if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_DUAL);
    return defaultRoute(url);
  };
  await mount("viewer", "/security/certificates?tab=ca");
  await flushUntil(() => {
    expect(text()).toContain("87599h0m0s");
  });
  const tab = Array.from(container.querySelectorAll('[role="tab"]')).find(
    (b) => b.getAttribute("aria-selected") === "true",
  );
  expect((tab?.textContent ?? "").trim()).toBe("CA Management");
  const t = text();
  expect(t).toContain("Auto-rotation: on");
  expect(t).toContain("Overlap: 30 days");
  expect(t).toContain("Dual-CA overlap active");
  expect(t).toContain("CULVERT Root CA (previous)");
  expect(t).toContain("Cache: 12 of 10000");
  expect(t).toContain("Leaf validity: 24h");
  expect(t).toContain("Key provider: local");
  expect(t).toContain("Recovery attempts: 0");
  act(() => {
    root.unmount();
  });

  route = (url) => {
    if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_DEGRADED);
    return defaultRoute(url);
  };
  await mount("viewer", "/security/certificates?tab=bogus");
  await flushUntil(() => {
    expect(text()).toContain("Complete pair persisted");
  });
  const sel = Array.from(container.querySelectorAll('[role="tab"]')).find(
    (b) => b.getAttribute("aria-selected") === "true",
  );
  expect((sel?.textContent ?? "").trim()).toBe("Certificates");
  await click("CA Management");
  await flushUntil(() => {
    expect(text()).toContain("Recovery attempts: 4");
  });
  const d = text();
  expect(d).toContain("Last rotation could not be persisted");
  expect(d).toContain("no_space");
  expect(d).toContain("Inspection bypassed: 7");
  expect(d).toContain("Not given up");
  expect(nonGET()).toEqual([]);
});
