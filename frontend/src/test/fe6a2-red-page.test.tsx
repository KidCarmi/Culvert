// FE-6A.2 RED matrix — PAGE rows for the Identity Providers and Administrators
// WRITE surfaces, written against the frozen FE-6A.1 baseline 98d4a6c8 BEFORE
// any product change (both pages are read-only today: every row that needs a
// control fails on the absent control; the role-gating rows are CONTROLS that
// already pass and must keep passing).
//
//   P1  role gating: no mutation control renders below admin (viewer /
//       operator) on either surface — CONTROL.
//   P2  OIDC create: editor → T2 review (credential material) → the marker is
//       persisted and verified BEFORE the POST; success clears it, closes the
//       dialog, drops the secret, re-reads the registry.
//   P3  a stale document fence renders the authoritative current token; the
//       marker is cleared (nothing was written) and nothing retries.
//   P4  a lost create response keeps the marker and offers Recover; the ledger
//       lookup settles it (committed ⇒ cleared; pending ⇒ kept; 404 ⇒ re-send).
//   P5  delete is T3: the exact provider id must be typed; the request carries
//       the loaded revision.
//   P6  409 referenced renders the referencing rules with working links.
//   P7  an unproven 2xx (text/plain) closes the editor, clears the secret,
//       latches every mutation and issues ONE authoritative read-back.
//   P8  the cutover ceremony (T2) requires the server confirm value and binds
//       operationId + revision + confirm into the PUT.
//   P9  registry repair (T2) requires the exact quarantine evidence, shown only
//       inside the ceremony.
//   P10 legacy import (T2) states "disabled" and "server-side".
//   P11 Administrators create/update/delete/lockout/self-password with their
//       fences and tiers; last_admin rendered; selfAffected ⇒ logout + no
//       roster visible; stale lockout reset changes nothing; dirty guard.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { IdentityProvidersPage } from "../features/objects/IdentityProvidersPage";
import { AdministratorsPage } from "../features/administration/AdministratorsPage";
import { IDP_RECOVERY_KEY } from "../features/objects/idpRecovery";
import { isRecord } from "../api/decode";

const rec = (v: unknown): Record<string, unknown> => {
  if (!isRecord(v)) throw new Error("not a record");
  return v;
};
import {
  CLIENT_SECRET,
  LEGACY_ABSENT,
  LEGACY_PRESENT,
  LEGACY_URL,
  LIST,
  LOCKS,
  OP_ID,
  QUARANTINE,
  RAW,
  ROSTER,
  ldapProfileAnswer,
  oidcProfileAnswer,
} from "./fe6a2-fixtures";

interface Call {
  url: string;
  method: string;
  body: unknown;
  markerAtDispatch: string | null;
}
let calls: Call[];
let route: (c: Call) => Response | Promise<Response>;
let container: HTMLDivElement;
let root: Root;
type MemoryRouter = ReturnType<typeof createMemoryRouter>;
let router: MemoryRouter | undefined;
let postLogout: ReturnType<typeof vi.fn<() => Promise<{ ok: true }>>>;

const marker = (): string | null => sessionStorage.getItem(IDP_RECOVERY_KEY);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  calls = [];
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
  route = () => Promise.reject(new TypeError("unrouted"));
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const raw = init?.body;
      const c: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        body: typeof raw === "string" ? JSON.parse(raw) : undefined,
        markerAtDispatch: marker(),
      };
      calls.push(c);
      return Promise.resolve(route(c));
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
  postLogout = vi.fn<() => Promise<{ ok: true }>>(() =>
    Promise.resolve({ ok: true }),
  );
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
        securityGeneration: 3,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout,
  });
}

async function mount(role: RoleName, path: string): Promise<void> {
  const rt = createMemoryRouter(
    [
      {
        path: "/objects/identity-providers",
        element: <IdentityProvidersPage />,
      },
      { path: "/administrators", element: <AdministratorsPage /> },
      { path: "/elsewhere", element: <div>Elsewhere</div> },
    ],
    { initialEntries: [path] },
  );
  router = rt;
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={rt} />
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
  if (b === undefined)
    throw new Error(
      `no button "${name}" in: ${scope instanceof Element ? (scope.textContent ?? "") : ""}`,
    );
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
function inputByLabel(
  label: string,
  scope: ParentNode = document,
): HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  for (const l of Array.from(scope.querySelectorAll("label"))) {
    if ((l.textContent ?? "").trim().startsWith(label)) {
      const el = l.htmlFor
        ? document.getElementById(l.htmlFor)
        : l.querySelector("input,select,textarea");
      if (
        el instanceof HTMLInputElement ||
        el instanceof HTMLSelectElement ||
        el instanceof HTMLTextAreaElement
      )
        return el;
    }
  }
  throw new Error(`no field "${label}"`);
}
async function type(
  label: string,
  value: string,
  scope: ParentNode = document,
): Promise<void> {
  const el = inputByLabel(label, scope);
  await act(async () => {
    // The prototype setter bypasses React's value tracker so the input event is observed.
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
async function check(
  label: string,
  on: boolean,
  scope: ParentNode = document,
): Promise<void> {
  const el = inputByLabel(label, scope);
  if (!(el instanceof HTMLInputElement)) throw new Error("not a checkbox");
  if (el.checked !== on) {
    await act(async () => {
      el.click();
      await Promise.resolve();
    });
  }
}
const openDialog = (): HTMLDialogElement => {
  const d = document.querySelector("dialog[open]");
  if (!(d instanceof HTMLDialogElement)) throw new Error("no open dialog");
  return d;
};
const gets = (path: string): number =>
  calls.filter((c) => c.method === "GET" && c.url === path).length; // exact: the registry read only

const LDAP_ROW = ldapProfileAnswer("ldap00000001", 2);
const OIDC_ROW = oidcProfileAnswer("a1b2c3d4e5f6", 3, { operationId: OP_ID });

function idpRoutes(
  over: Partial<Record<string, (c: Call) => Response | Promise<Response>>> = {},
  profiles: unknown[] = [OIDC_ROW, LDAP_ROW],
  legacy: unknown = LEGACY_ABSENT,
): void {
  route = (c) => {
    if (c.url.startsWith("/api/idp/legacy-ldap") && c.method === "GET")
      return json(legacy);
    if (c.url.startsWith("/api/objects/references"))
      return json({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (c.url === "/api/idp" && c.method === "GET")
      return json({ ...LIST, profiles });
    for (const [k, fn] of Object.entries(over)) {
      if (fn !== undefined && c.url.startsWith(k) && c.method !== "GET")
        return fn(c);
      if (
        fn !== undefined &&
        c.url.startsWith(k) &&
        k.startsWith("/api/idp/operations/")
      )
        return fn(c);
    }
    return Promise.reject(new TypeError(`unexpected ${c.method} ${c.url}`));
  };
}

// ── P1 CONTROLS ────────────────────────────────────────────────────────────
it("P1 a viewer sees no mutation control on Identity Providers (control)", async () => {
  idpRoutes({}, [OIDC_ROW, LDAP_ROW], LEGACY_PRESENT);
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Corp OIDC");
  });
  for (const name of [
    "Add provider",
    "Edit",
    "Delete",
    "Import legacy configuration",
    "Repair registry",
  ]) {
    expect(buttons(name), name).toHaveLength(0);
  }
});
it("P1b an operator sees no mutation control on Administrators (control)", async () => {
  route = () => json({ error: RAW, code: "forbidden" }, 403);
  await mount("operator", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("requires the admin role");
  });
  for (const name of [
    "Add account",
    "Edit",
    "Delete",
    "Clear",
    "Change my password",
  ]) {
    expect(buttons(name), name).toHaveLength(0);
  }
});

// ── P2 create ─────────────────────────────────────────────────────────────
it("P2 OIDC create: T2 review, marker before dispatch, secret released, registry re-read", async () => {
  let posted: Call | undefined;
  idpRoutes({
    "/api/idp": (c) => {
      posted = c;
      const q = new URL(c.url, "http://x").searchParams;
      return json(
        oidcProfileAnswer("new000000001", 1, {
          name: "New OIDC",
          operationId: q.get("operationId"),
        }),
      );
    },
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Add provider")).toHaveLength(1);
  });
  await click("Add provider");
  const dlg = openDialog();
  await type("Type", "oidc", dlg);
  await type("Name", "New OIDC", dlg);
  await type("Issuer", "https://issuer.example", dlg);
  await type("Client ID", "culvert", dlg);
  await type("Client secret", CLIENT_SECRET, dlg);
  await click("Review and save", dlg);
  // T2 review: impact copy names the credential material, nothing sent yet.
  await flushUntil(() => {
    expect(dialogText()).toContain("credential");
  });
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
  await click("Save provider", openDialog());
  await flushUntil(() => {
    expect(posted).toBeDefined();
  });
  const url = new URL(posted?.url ?? "", "http://x");
  expect(url.pathname).toBe("/api/idp");
  expect(url.searchParams.get("documentRevision")).toBe("r-doc-1");
  expect(url.searchParams.get("operationId")).toMatch(/^[0-9a-f-]{36}$/);
  expect(posted?.markerAtDispatch).not.toBeNull(); // persisted + verified BEFORE dispatch
  expect(posted?.markerAtDispatch).toContain(
    url.searchParams.get("operationId") ?? "!",
  );
  expect(posted?.markerAtDispatch).not.toContain(CLIENT_SECRET);
  await flushUntil(() => {
    expect(document.querySelector("dialog[open]")).toBeNull();
    expect(marker()).toBeNull();
    expect(gets("/api/idp")).toBeGreaterThanOrEqual(2);
  });
  expect(container.innerHTML).not.toContain(CLIENT_SECRET);
  expect(document.body.innerHTML).not.toContain(CLIENT_SECRET);
  expect(text()).toContain("Provider created");
});

// ── P3 stale document fence ───────────────────────────────────────────────
it("P3 a stale document fence renders the current token, clears the marker, never retries", async () => {
  idpRoutes({
    "/api/idp": () =>
      json(
        { error: RAW, code: "stale", current: { documentRevision: "r-doc-9" } },
        409,
      ),
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Add provider")).toHaveLength(1);
  });
  await click("Add provider");
  const dlg = openDialog();
  await type("Type", "ldap", dlg);
  await type("Name", "Plain LDAP", dlg);
  await type("Directory URL", "ldaps://dc.example:636", dlg);
  await type("Base DN", "dc=example", dlg);
  await click("Review and save", dlg);
  await flushUntil(() => {
    expect(text()).toContain("r-doc-9");
  });
  expect(text()).toContain("stale");
  expect(text()).not.toContain(RAW);
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  expect(marker()).toBeNull();
});

// ── P4 lost response + ledger recovery ────────────────────────────────────
it("P4 a lost create response keeps the marker; Recover settles it from the ledger", async () => {
  let lookup: Record<string, unknown> = {
    operationId: "",
    state: "pending",
    action: "idp.create",
    actor: "admin@10.0.0.9",
    profileId: "p",
    registryRevision: "r-doc-1",
    cutover: false,
    startedAt: "2026-09-13T10:00:00Z",
    audited: false,
  };
  idpRoutes({
    "/api/idp": () => Promise.reject(new TypeError("Failed to fetch")),
    "/api/idp/operations/": (c) => {
      const id = c.url.split("/").pop() ?? "";
      return json({ ...lookup, operationId: id });
    },
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Add provider")).toHaveLength(1);
  });
  await click("Add provider");
  const dlg = openDialog();
  await type("Type", "ldap", dlg);
  await type("Name", "Lost LDAP", dlg);
  await type("Directory URL", "ldaps://dc.example:636", dlg);
  await type("Base DN", "dc=example", dlg);
  await click("Review and save", dlg);
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
  });
  expect(marker()).not.toBeNull();
  expect(buttons("Recover")).toHaveLength(1);
  expect(buttons("Abandon")).toHaveLength(0); // pending ⇒ nothing typed-abandonable yet
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("Pending");
  });
  expect(marker()).not.toBeNull();
  // committed + audited ⇒ terminal, ownership-matched clear
  lookup = {
    ...lookup,
    state: "committed",
    audited: true,
    finishedAt: "2026-09-13T10:00:02Z",
    committedRevision: "r-doc-2",
  };
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("Committed");
    expect(marker()).toBeNull();
  });
});
it("P4b a never-recorded operation (404) offers a typed re-send; an aborted one offers Abandon", async () => {
  idpRoutes({
    "/api/idp": () => Promise.reject(new TypeError("Failed to fetch")),
    "/api/idp/operations/": () => json({ error: RAW, code: "not_found" }, 404),
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Add provider")).toHaveLength(1);
  });
  await click("Add provider");
  const dlg = openDialog();
  await type("Type", "ldap", dlg);
  await type("Name", "Lost LDAP");
  await type("Directory URL", "ldaps://dc.example:636", dlg);
  await type("Base DN", "dc=example", dlg);
  await click("Review and save", dlg);
  await flushUntil(() => {
    expect(buttons("Recover")).toHaveLength(1);
  });
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("never recorded");
  });
  expect(buttons("Re-send")).toHaveLength(1);
  expect(buttons("Abandon")).toHaveLength(1);
  expect(text()).not.toContain(RAW);
});

// ── P5 delete T3 ──────────────────────────────────────────────────────────
it("P5 delete is T3: exact id typed, loaded revision echoed", async () => {
  let deleted: Call | undefined;
  idpRoutes({
    "/api/idp/a1b2c3d4e5f6": (c) => {
      deleted = c;
      return json({
        ok: true,
        deleted: true,
        id: "a1b2c3d4e5f6",
        revision: "r-doc-2",
        persisted: true,
        cluster: { publication: "published", version: 9 },
      });
    },
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Delete").length).toBeGreaterThan(0);
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").includes("Corp OIDC"),
  );
  if (row === undefined) throw new Error("no row");
  await click("Delete", row);
  const dlg = openDialog();
  expect(dlg.textContent).toContain("a1b2c3d4e5f6");
  const confirm = button("Delete provider", dlg);
  expect(confirm.disabled).toBe(true);
  await type("Type a1b2c3d4e5f6 to confirm", "a1b2c3d4e5f", dlg);
  expect(button("Delete provider", dlg).disabled).toBe(true);
  await type("Type a1b2c3d4e5f6 to confirm", "a1b2c3d4e5f6", dlg);
  expect(button("Delete provider", dlg).disabled).toBe(false);
  await click("Delete provider", dlg);
  await flushUntil(() => {
    expect(deleted).toBeDefined();
  });
  expect(deleted?.method).toBe("DELETE");
  expect(deleted?.url).toBe("/api/idp/a1b2c3d4e5f6?revision=3");
});

// ── P6 referenced ─────────────────────────────────────────────────────────
it("P6 409 referenced renders the referencing rules with working links", async () => {
  idpRoutes({
    "/api/idp/a1b2c3d4e5f6": () =>
      json(
        {
          error: RAW,
          code: "referenced",
          current: {
            revision: 3,
            references: [
              {
                consumerType: "auth-rule",
                id: "01RULE",
                name: "SSO staff",
                detail: "providerRefs",
                view: "authpolicy",
              },
            ],
          },
        },
        409,
      ),
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Delete").length).toBeGreaterThan(0);
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").includes("Corp OIDC"),
  );
  if (row === undefined) throw new Error("no row");
  await click("Delete", row);
  await type("Type a1b2c3d4e5f6 to confirm", "a1b2c3d4e5f6", openDialog());
  await click("Delete provider", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("SSO staff");
  });
  const link = Array.from(container.querySelectorAll("a")).find((a) =>
    (a.textContent ?? "").includes("SSO staff"),
  );
  expect(link?.getAttribute("href")).toBe(
    "/policies/authentication-rules?rule=01RULE",
  );
  expect(text()).toContain("referenced");
  expect(text()).not.toContain(RAW);
});

// ── P7 unproven 2xx ───────────────────────────────────────────────────────
// (RED correction, transparent: the first cut asserted the latch SYNCHRONOUSLY
// after the callout, but the contract's single automatic read-back can land
// in the same tick and — by contract — clears the latch. A TRANSPORT death
// performs no automatic read-back, so the latch is deterministic there.)
it("P7 an unproven 2xx (wrong media type) closes the editor, drops the secret and re-reads exactly once", async () => {
  idpRoutes({
    "/api/idp/a1b2c3d4e5f6": () =>
      new Response("ok", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      }),
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Edit").length).toBeGreaterThan(0);
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").includes("Corp OIDC"),
  );
  if (row === undefined) throw new Error("no row");
  const getsBefore = gets("/api/idp");
  await click("Edit", row);
  const dlg = openDialog();
  await type("Client secret", CLIENT_SECRET, dlg);
  await click("Review and save", dlg);
  await click("Save provider", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Outcome unproven");
  });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(document.body.innerHTML).not.toContain(CLIENT_SECRET);
  await flushUntil(() => {
    expect(gets("/api/idp")).toBe(getsBefore + 1);
  });
  expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
});
it("P7b a transport death latches every mutation until the operator refreshes", async () => {
  idpRoutes({
    "/api/idp/a1b2c3d4e5f6": () =>
      Promise.reject(new TypeError("Failed to fetch")),
  });
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Edit").length).toBeGreaterThan(0);
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").includes("Corp OIDC"),
  );
  if (row === undefined) throw new Error("no row");
  const getsBefore = gets("/api/idp");
  await click("Edit", row);
  const dlg = openDialog();
  await type("Client secret", CLIENT_SECRET, dlg);
  await click("Review and save", dlg);
  await click("Save provider", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Outcome unproven");
  });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(document.body.innerHTML).not.toContain(CLIENT_SECRET);
  expect(button("Add provider").disabled).toBe(true);
  for (const b of buttons("Edit")) expect(b.disabled).toBe(true);
  for (const b of buttons("Delete")) expect(b.disabled).toBe(true);
  expect(gets("/api/idp")).toBe(getsBefore); // no automatic read-back after a transport death
  expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
  await click("Refresh");
  await flushUntil(() => {
    expect(gets("/api/idp")).toBe(getsBefore + 1);
    expect(button("Add provider").disabled).toBe(false);
  });
});

// ── P8 cutover ceremony ───────────────────────────────────────────────────
it("P8 enabling an LDAP profile on a node with a live legacy block runs the cutover ceremony", async () => {
  let put: Call | undefined;
  idpRoutes(
    {
      "/api/idp/ldap00000001": (c) => {
        put = c;
        const q = new URL(c.url, "http://x").searchParams;
        return json(
          ldapProfileAnswer("ldap00000001", 3, {
            enabled: true,
            operationId: q.get("operationId"),
          }),
        );
      },
    },
    [LDAP_ROW],
    LEGACY_PRESENT,
  );
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Edit").length).toBeGreaterThan(0);
  });
  await click("Edit");
  const dlg = openDialog();
  await check("Enabled", true, dlg);
  await click("Review and save", dlg);
  await flushUntil(() => {
    expect(dialogText()).toContain("Retire the legacy YAML LDAP authenticator");
  });
  const cer = openDialog();
  expect(cer.textContent).toContain(LEGACY_URL);
  expect(button("Retire and enable", cer).disabled).toBe(true);
  await type(`Type ${LEGACY_URL} to confirm`, LEGACY_URL, cer);
  expect(button("Retire and enable", cer).disabled).toBe(false);
  expect(calls.filter((c) => c.method === "PUT")).toHaveLength(0);
  await click("Retire and enable", cer);
  await flushUntil(() => {
    expect(put).toBeDefined();
  });
  const q = new URL(put?.url ?? "", "http://x").searchParams;
  expect(q.get("revision")).toBe("2");
  expect(q.get("operationId")).toMatch(/^[0-9a-f-]{36}$/);
  expect(q.get("cutoverConfirm")).toBe(LEGACY_URL);
  expect(put?.markerAtDispatch).toContain(q.get("operationId") ?? "!");
  expect(rec(put?.body)["enabled"]).toBe(true);
});

// ── P9 repair ─────────────────────────────────────────────────────────────
it("P9 repair requires the exact quarantine evidence, shown only inside the ceremony", async () => {
  let repaired: Call | undefined;
  idpRoutes({
    "/api/idp/repair": (c) => {
      repaired = c;
      return json({
        ok: true,
        repaired: true,
        evidence: QUARANTINE,
        revision: "r-doc-0",
      });
    },
  });
  const degraded = {
    ...LIST,
    degraded: true,
    degradedReason: "corrupt_quarantined",
    quarantineEvidence: QUARANTINE,
    profiles: [],
  };
  route = ((inner) => (c: Call) =>
    c.url === "/api/idp" && c.method === "GET" ? json(degraded) : inner(c))(
    route,
  );
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Repair registry")).toHaveLength(1);
  });
  expect(text()).not.toContain(QUARANTINE);
  await click("Repair registry");
  const dlg = openDialog();
  expect(dlg.textContent).toContain(QUARANTINE);
  expect(button("Repair", dlg).disabled).toBe(true);
  await type(`Type ${QUARANTINE} to confirm`, QUARANTINE, dlg);
  await click("Repair", dlg);
  await flushUntil(() => {
    expect(repaired).toBeDefined();
  });
  expect(repaired?.body).toEqual({ confirm: QUARANTINE });
  await flushUntil(() => {
    expect(document.querySelector("dialog[open]")).toBeNull();
  });
  expect(text()).not.toContain(QUARANTINE);
});

// ── P10 import ────────────────────────────────────────────────────────────
it("P10 legacy import is a T2 ceremony stating disabled + server-side copy", async () => {
  let imported: Call | undefined;
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": (c) => {
        imported = c;
        return json(
          ldapProfileAnswer("imp000000001", 1, {
            name: "Imported legacy LDAP",
          }),
        );
      },
    },
    [],
    LEGACY_PRESENT,
  );
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Import legacy configuration")).toHaveLength(1);
  });
  await click("Import legacy configuration");
  const dlg = openDialog();
  expect(dlg.textContent).toContain("disabled");
  expect(dlg.textContent).toContain("server-side");
  expect(imported).toBeUndefined();
  await click("Import", dlg);
  await flushUntil(() => {
    expect(imported).toBeDefined();
  });
  expect(imported?.method).toBe("POST");
  expect(imported?.body).toBeUndefined();
});

// ── P11 Administrators ────────────────────────────────────────────────────
function adminRoutes(
  over: Partial<Record<string, (c: Call) => Response | Promise<Response>>>,
  roster: unknown = ROSTER,
  locks: unknown = LOCKS,
): void {
  route = (c) => {
    if (c.url.startsWith("/api/auth/users") && c.method === "GET")
      return json(roster);
    if (c.url.startsWith("/api/auth/lockouts") && c.method === "GET")
      return json(locks);
    for (const [k, fn] of Object.entries(over)) {
      if (fn !== undefined && c.url.startsWith(k) && c.method !== "GET")
        return fn(c);
    }
    return Promise.reject(new TypeError(`unexpected ${c.method} ${c.url}`));
  };
}
const SELF_ROSTER = {
  ...ROSTER,
  users: [
    ...ROSTER.users,
    {
      username: "admin-user",
      role: "admin",
      totpEnabled: false,
      securityGeneration: 3,
    },
  ],
};

it("P11a create account: T2 → POST with the roster fence; the password never reaches the DOM afterwards", async () => {
  let posted: Call | undefined;
  adminRoutes({
    "/api/auth/users": (c) => {
      posted = c;
      return json({
        ok: true,
        user: {
          username: "alice",
          role: "viewer",
          totpEnabled: false,
          securityGeneration: 9,
        },
        revision: 5,
        persisted: true,
      });
    },
  });
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(buttons("Add account")).toHaveLength(1);
  });
  await click("Add account");
  const dlg = openDialog();
  await type("Username", "alice", dlg);
  await type("Role", "viewer", dlg);
  await type("Password", "Passw0rd-CANARY-alice", dlg);
  await click("Review and create", dlg);
  await flushUntil(() => {
    expect(dialogText()).toContain("alice");
  });
  expect(posted).toBeUndefined();
  await click("Create account", openDialog());
  await flushUntil(() => {
    expect(posted).toBeDefined();
  });
  expect(posted?.method).toBe("POST");
  expect(posted?.url).toBe("/api/auth/users?revision=4");
  expect(posted?.body).toEqual({
    username: "alice",
    role: "viewer",
    password: "Passw0rd-CANARY-alice",
  });
  await flushUntil(() => {
    expect(document.querySelector("dialog[open]")).toBeNull();
  });
  expect(document.body.innerHTML).not.toContain("Passw0rd-CANARY-alice");
});

it("P11b last_admin is rendered as the structured refusal; nothing retries", async () => {
  adminRoutes({
    "/api/auth/users": () => json({ error: RAW, code: "last_admin" }, 409),
  });
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(buttons("Edit").length).toBeGreaterThan(0);
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").startsWith("admin"),
  );
  if (row === undefined) throw new Error("no row");
  await click("Edit", row);
  const dlg = openDialog();
  await type("Role", "viewer", dlg);
  await click("Review and save", dlg);
  await click("Save account", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("last_admin");
  });
  expect(text()).not.toContain(RAW);
  expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
});

it("P11c selfAffected:true completes the auth teardown and hides the roster", async () => {
  adminRoutes(
    {
      "/api/auth/users": () =>
        json({
          ok: true,
          user: {
            username: "admin-user",
            role: "operator",
            totpEnabled: false,
            securityGeneration: 4,
          },
          revision: 5,
          persisted: true,
          sessionsRevoked: true,
          selfAffected: true,
          securityGeneration: 4,
        }),
      "/api/auth/logout": () => json({ ok: true }),
    },
    SELF_ROSTER,
  );
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("admin-user");
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").startsWith("admin-user"),
  );
  if (row === undefined) throw new Error("no row");
  await click("Edit", row);
  await type("Role", "operator", openDialog());
  await click("Review and save", openDialog());
  await click("Save account", openDialog());
  await flushUntil(() => {
    expect(postLogout).toHaveBeenCalledTimes(1);
  });
  await flushUntil(() => {
    expect(text()).not.toContain("bob");
  });
  expect(text()).not.toContain("Roster revision");
});

it("P11d delete account is T3 (exact username) fenced on the roster revision", async () => {
  let del: Call | undefined;
  adminRoutes({
    "/api/auth/users": (c) => {
      del = c;
      return json({
        ok: true,
        deleted: true,
        username: "bob",
        revision: 5,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
      });
    },
  });
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(buttons("Delete").length).toBeGreaterThan(0);
  });
  const row = Array.from(container.querySelectorAll("tr")).find((r) =>
    (r.textContent ?? "").startsWith("bob"),
  );
  if (row === undefined) throw new Error("no row");
  await click("Delete", row);
  const dlg = openDialog();
  expect(button("Delete account", dlg).disabled).toBe(true);
  await type("Type bob to confirm", "bob", dlg);
  await click("Delete account", dlg);
  await flushUntil(() => {
    expect(del).toBeDefined();
  });
  expect(del?.method).toBe("DELETE");
  expect(del?.url).toBe("/api/auth/users?username=bob&revision=4");
});

it("P11e lockout clear is bound to the loaded generation; a stale reset changes nothing", async () => {
  adminRoutes({
    "/api/auth/lockouts": () =>
      json({ error: RAW, code: "stale", current: { generation: 13 } }, 409),
  });
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(buttons("Clear")).toHaveLength(1);
  });
  await click("Clear");
  const dlg = openDialog();
  expect(dlg.textContent).toContain("bob");
  await click("Clear lockouts", dlg);
  await flushUntil(() => {
    expect(text()).toContain("13");
  });
  const post = calls.find((c) => c.method === "POST");
  expect(post?.url).toBe("/api/auth/lockouts?generation=12");
  expect(post?.body).toEqual({ username: "bob" });
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  expect(text()).toContain("stale");
});

it("P11f self-service password change is fenced on the security generation and signs out on success", async () => {
  let posted: Call | undefined;
  adminRoutes({
    "/api/auth/change-password": (c) => {
      posted = c;
      return json({
        ok: true,
        revision: 5,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: true,
        securityGeneration: 4,
      });
    },
    "/api/auth/logout": () => json({ ok: true }),
  });
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(buttons("Change my password")).toHaveLength(1);
  });
  await click("Change my password");
  const dlg = openDialog();
  await type("Current password", "OldPassw0rd-CANARY", dlg);
  await type("New password", "NewPassw0rd-CANARY", dlg);
  await click("Change password", dlg);
  await flushUntil(() => {
    expect(posted).toBeDefined();
  });
  expect(posted?.url).toBe("/api/auth/change-password?generation=3");
  expect(posted?.body).toEqual({
    current_password: "OldPassw0rd-CANARY",
    new_password: "NewPassw0rd-CANARY",
  });
  await flushUntil(() => {
    expect(postLogout).toHaveBeenCalledTimes(1);
  });
  expect(document.body.innerHTML).not.toContain("NewPassw0rd-CANARY");
  expect(document.body.innerHTML).not.toContain("OldPassw0rd-CANARY");
});

it("P11g a dirty editor guards navigation", async () => {
  idpRoutes();
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(buttons("Add provider")).toHaveLength(1);
  });
  await click("Add provider");
  await type("Name", "Half typed", openDialog());
  await act(async () => {
    await router?.navigate("/elsewhere");
  });
  await flushUntil(() => {
    expect(document.body.textContent ?? "").toContain(
      "Discard unsaved changes?",
    );
  });
  expect(text()).not.toContain("Elsewhere");
});
