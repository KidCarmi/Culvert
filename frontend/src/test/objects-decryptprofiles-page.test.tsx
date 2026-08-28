// 2D-A.3 — Decryption Profiles page proofs: viewer posture + enum/tri-state
// display fidelity, the never-euphemized skip presentation, the pre-save
// fail-open adaptive-exclusion warning, tri-state serialization fidelity
// (inherit is OMITTED, never false), rename by stable ID with the
// exclusion-scope-stability truth, degraded read-only rows, the authoritative
// delete-refusal 409, and the absence of the retired "permissive" value.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { DecryptionProfilesPage } from "../features/objects/DecryptionProfilesPage";
import { isRecord } from "../api/decode";

const PROF_INHERIT = {
  id: "p-inherit-001",
  name: "inherit-most",
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-02T00:00:00Z",
};
const PROF_STRICT = {
  id: "p-strict-002",
  name: "strict-verify",
  inspectHttp2: true,
  certVerification: "strict",
  onUnsupported: "fail-close",
  onInspectError: "fail-open",
  minTlsVersion: "1.2",
  maxTlsVersion: "1.3",
  stallTimeoutSecs: 120,
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-01T00:00:00Z",
};
const PROF_SKIP = {
  id: "p-skip-003",
  name: "skip-verify",
  certVerification: "skip",
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-01T00:00:00Z",
};
const PROF_DEGRADED = {
  id: "p-degraded-004",
  name: "weird",
  onInspectError: "fail-sideways",
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-01T00:00:00Z",
};

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let profilesBody: unknown;
let refsBody: unknown;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string) => Promise<Response>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
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
  profilesBody = {
    profiles: [PROF_INHERIT, PROF_STRICT, PROF_SKIP, PROF_DEGRADED],
    names: ["inherit-most", "strict-verify", "skip-verify", "weird"],
    version: 6,
  };
  refsBody = {
    object: { type: "decryption-profile", name: "strict-verify" },
    referencedBy: [],
  };
  mutations = [];
  onMutate = () => okJSON({ ok: true, version: 7 });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(method, url);
      }
      if (url.includes("/api/objects/references")) return okJSON(refsBody);
      if (url.includes("/api/decryption-profiles")) return okJSON(profilesBody);
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
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

function machineFor(
  role: "viewer" | "operator" | "admin",
  qc: QueryClient,
): AuthMachine {
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

async function mount(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [
      {
        path: "/objects/decryption-profiles",
        element: <DecryptionProfilesPage />,
      },
    ],
    { initialEntries: ["/objects/decryption-profiles"] },
  );
  const qc = new QueryClient();
  const machine = machineFor(role, qc);
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
    expect(container.textContent).toContain("strict-verify");
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

function findButton(match: (t: string) => boolean): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  return b;
}

function findButtonByLabel(labelIncludes: string): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    (el.getAttribute("aria-label") ?? "").includes(labelIncludes),
  );
  if (b === undefined)
    throw new Error(`button not found by label: ${labelIncludes}`);
  return b;
}

function hasButtonByLabel(labelIncludes: string): boolean {
  return Array.from(container.querySelectorAll("button")).some((el) =>
    (el.getAttribute("aria-label") ?? "").includes(labelIncludes),
  );
}

async function click(btn: HTMLButtonElement): Promise<void> {
  await act(async () => {
    btn.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

function controlFor(
  labelIncludes: string,
): HTMLInputElement | HTMLSelectElement {
  const label = Array.from(container.querySelectorAll("label")).find((l) =>
    (l.textContent ?? "").includes(labelIncludes),
  );
  if (label === undefined) throw new Error(`label not found: ${labelIncludes}`);
  const forId = label.getAttribute("for");
  const el =
    forId !== null
      ? document.getElementById(forId)
      : label.querySelector("input,select");
  if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLSelectElement)) {
    throw new Error(`control not found for label: ${labelIncludes}`);
  }
  return el;
}

function setInput(labelIncludes: string, value: string): void {
  const el = controlFor(labelIncludes);
  const proto =
    el instanceof HTMLInputElement
      ? HTMLInputElement.prototype
      : HTMLSelectElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(el, value);
  act(() => {
    el.dispatchEvent(
      new Event(el instanceof HTMLSelectElement ? "change" : "input", {
        bubbles: true,
      }),
    );
  });
}

// A — viewer: display fidelity for inherit/tri-state/skip; no mutation controls.
it("viewer: renders tri-state + enum truth; no mutation controls", async () => {
  await mount("viewer");
  expect(container.textContent).toContain("inherit (strip → HTTP/1.1)");
  expect(container.textContent).toContain("native HTTP/2 inspection");
  expect(container.textContent).toContain("skip (disabled)");
  expect(container.textContent).toContain("4 decryption profiles");
  expect(hasButtonByLabel("Edit profile")).toBe(false);
});

// B — degraded profile: read-only row with the decoder reason, never coerced.
it("renders a contract-violating profile as a degraded read-only row", async () => {
  await mount("operator");
  expect(container.textContent).toContain("degraded");
  expect(container.textContent).toContain("weird");
  expect(hasButtonByLabel("Edit profile weird")).toBe(false);
  // Valid profiles still editable.
  expect(hasButtonByLabel("Edit profile strict-verify")).toBe(true);
});

// C — the editor never offers the retired permissive value (§15).
it("the certificate-verification select never offers permissive", async () => {
  await mount("operator");
  await click(findButton((t) => t.includes("New decryption profile")));
  const sel = controlFor("Certificate verification");
  const values = Array.from(sel.querySelectorAll("option")).map((o) => o.value);
  expect(values).toEqual(["", "strict", "skip"]);
  expect(values).not.toContain("permissive");
});

// D — fail-open pre-save warning (§16): visible the moment it is selected.
it("selecting onInspectError=fail-open surfaces the adaptive-exclusion warning before save", async () => {
  await mount("operator");
  await click(findButton((t) => t.includes("New decryption profile")));
  expect(container.textContent).not.toContain(
    "Fail-open enables adaptive decryption exclusion",
  );
  setInput("On inspect error", "fail-open");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Fail-open enables adaptive decryption exclusion",
    );
  });
  expect(container.textContent).toContain("BYPASS inspection");
});

// E — tri-state serialization: an untouched inherit profile OMITS inspectHttp2;
// choosing "force strip" sends false.
it("inherit is serialized by omission — never collapsed into false", async () => {
  await mount("operator");
  await click(findButtonByLabel("Edit profile inherit-most"));
  setInput("Profile name", "inherit-most"); // no-op; keep dirty state honest
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const body1 = mutations[0]?.body;
  if (!isRecord(body1)) throw new Error("mutation body missing");
  expect("inspectHttp2" in body1).toBe(false);

  mutations = [];
  await click(findButtonByLabel("Edit profile inherit-most"));
  setInput("Inspect HTTP/2", "strip");
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const body2 = mutations[0]?.body;
  if (!isRecord(body2)) throw new Error("mutation body missing");
  expect(body2["inspectHttp2"]).toBe(false);
});

// F — rename: stable-ID PUT under the fence + the exclusion-stability truth.
it("rename PUTs by stable id and states the exclusion scope stays valid", async () => {
  await mount("operator");
  await click(findButtonByLabel("Edit profile strict-verify"));
  setInput("Profile name", "strict-verify-v2");
  await flushUntil(() => {
    expect(container.textContent).toContain("This is a rename");
  });
  expect(container.textContent).toContain(
    "learned adaptive decryption exclusions scoped to it remain valid",
  );
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("PUT");
  expect(m?.url).toContain("/api/decryption-profiles?id=p-strict-002");
  expect(m?.url).toContain("ifVersion=6");
  expect(m?.body).toMatchObject({
    name: "strict-verify-v2",
    certVerification: "strict",
    onInspectError: "fail-open",
  });
});

// G — delete refused by the server renders the authoritative consumers.
it("a referenced delete renders the server's consumers and keeps the row", async () => {
  await mount("operator");
  onMutate = () =>
    okJSON(
      {
        error:
          'cannot delete decryption-profile "strict-verify": referenced by policy rule "inspect-all"',
        object: { type: "decryption-profile", name: "strict-verify" },
        referencedBy: [
          {
            consumerType: "access-rule",
            id: "01J3ZV9E3JD0FFFFFFFFFFFFFF",
            name: "inspect-all",
            detail: "decryptionProfile",
            view: "policy",
          },
        ],
      },
      409,
    );
  await click(findButtonByLabel("Delete profile strict-verify"));
  await flushUntil(() => {
    expect(container.textContent).toContain("No references were found");
  });
  const deleteButtons = Array.from(container.querySelectorAll("button")).filter(
    (b) => b.textContent === "Delete",
  );
  const confirmBtn = deleteButtons[deleteButtons.length - 1];
  if (confirmBtn === undefined) throw new Error("confirm button not found");
  await click(confirmBtn);
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Delete refused — still referenced",
    );
  });
  expect(container.textContent).toContain("inspect-all");
  expect(mutations[0]?.url).toContain("id=p-strict-002");
  expect(container.textContent).toContain("strict-verify");
});

// H — the skip warning is visible before save when verification is disabled.
it("selecting certVerification=skip surfaces the disabled-verification warning", async () => {
  await mount("operator");
  await click(findButton((t) => t.includes("New decryption profile")));
  setInput("Certificate verification", "skip");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Certificate verification disabled",
    );
  });
  expect(container.textContent).toContain("man-in-the-middle protection");
});
