// 2D-C — File Profiles + Header Rewrite page proofs: viewer read-only
// posture, fenced stable-ID mutations (ifRevision echoed on every write),
// the rename truth callout, server-side normalization preview, the shared
// structured revision-409 notice, the unknown-outcome latch, rewrite
// EVALUATION-ORDER rendering (no client sorting), create-never-submits-
// stableId, and delete addressed by stableId only.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import type { JSX } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { FileProfilesPage } from "../features/objects/FileProfilesPage";
import { HeaderRewritePage } from "../features/policy/HeaderRewritePage";
import { isRecord } from "../api/decode";

const PROFILE_BUILTIN = {
  id: "builtin-executables",
  name: "Executables",
  extensions: [".exe", ".msi", ".bat"],
};
const PROFILE_CUSTOM = {
  id: "9f8e7d6c-1111-2222-3333-444455556666",
  name: "CAD Files",
  extensions: [".dwg"],
};

const RW_FIRST = {
  id: 1,
  stableId: "aaaa1111-0000-0000-0000-000000000001",
  host: "*.example.com",
  req_set: { "X-Env": "prod" },
};
const RW_SECOND = {
  id: 2,
  stableId: "aaaa1111-0000-0000-0000-000000000002",
  host: "api.internal.test",
  resp_remove: ["X-Powered-By"],
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
let rewriteBody: unknown;
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
    profiles: [PROFILE_BUILTIN, PROFILE_CUSTOM],
    revision: "fprev4",
  };
  rewriteBody = { rules: [RW_FIRST, RW_SECOND], revision: "rwrev7" };
  refsBody = {
    object: { type: "file-profile", name: "Executables" },
    referencedBy: [],
  };
  mutations = [];
  onMutate = () => okJSON({ ok: true });
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
      if (url.includes("/api/fileblock/profiles/state"))
        return okJSON(profilesBody);
      if (url.includes("/api/rewrite/state")) return okJSON(rewriteBody);
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

async function mount(
  role: "viewer" | "operator" | "admin",
  path: string,
  element: JSX.Element,
  readyText: string,
): Promise<void> {
  const router = createMemoryRouter([{ path, element }], {
    initialEntries: [path],
  });
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
    expect(container.textContent).toContain(readyText);
  });
}

function mountProfiles(role: "viewer" | "operator" | "admin"): Promise<void> {
  return mount(
    role,
    "/objects/file-profiles",
    <FileProfilesPage />,
    "Executables",
  );
}

function mountRewrite(role: "viewer" | "operator" | "admin"): Promise<void> {
  return mount(
    role,
    "/policies/header-rewrite",
    <HeaderRewritePage />,
    "example.com",
  );
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

function hasButton(match: (t: string) => boolean): boolean {
  return Array.from(container.querySelectorAll("button")).some((el) =>
    match(el.textContent ?? ""),
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

function setField(labelIncludes: string, value: string): void {
  const label = Array.from(container.querySelectorAll("label")).find((l) =>
    (l.textContent ?? "").includes(labelIncludes),
  );
  if (label === undefined) throw new Error(`label not found: ${labelIncludes}`);
  const forId = label.getAttribute("for");
  const el =
    forId !== null
      ? document.getElementById(forId)
      : label.querySelector("input,textarea");
  if (el instanceof HTMLInputElement) {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set?.call(el, value);
  } else if (el instanceof HTMLTextAreaElement) {
    Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set?.call(el, value);
  } else {
    throw new Error(`field not found for label: ${labelIncludes}`);
  }
  act(() => {
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

// ── File Profiles ───────────────────────────────────────────────────────────

// A — viewer reads; built-in badge; zero mutation controls.
it("file profiles: viewer reads with built-in badge and no mutation controls", async () => {
  await mountProfiles("viewer");
  expect(container.textContent).toContain("2 file profiles");
  expect(container.textContent).toContain("Built-in");
  expect(container.textContent).toContain("CAD Files");
  expect(hasButton((t) => t.includes("New file profile"))).toBe(false);
  expect(
    Array.from(container.querySelectorAll("button")).some((b) =>
      (b.getAttribute("aria-label") ?? "").startsWith("Edit profile"),
    ),
  ).toBe(false);
});

// B — operator create: fenced POST with the NORMALIZED extension list.
it("file profiles: create posts the fenced mutation with normalized extensions", async () => {
  await mountProfiles("operator");
  await click(findButton((t) => t.includes("New file profile")));
  setField("Profile name", "Scripts");
  setField("Blocked extensions", "PS1\n.ps1\n Vbs \n\n.");
  await flushUntil(() => {
    // Live normalization preview mirrors the server's rule.
    expect(container.textContent).toContain("2 normalized extensions");
  });
  await click(findButton((t) => t === "Create profile"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("POST");
  expect(m?.url).toContain("/api/fileblock/profiles?ifRevision=fprev4");
  expect(m?.body).toEqual({ name: "Scripts", extensions: [".ps1", ".vbs"] });
});

// C — rename: the ID-stability truth callout appears; PUT addresses the ID.
it("file profiles: rename shows the identity truth and PUTs by stable id", async () => {
  await mountProfiles("operator");
  await click(findButtonByLabel("Edit profile CAD Files"));
  expect(container.textContent).toContain(PROFILE_CUSTOM.id);
  setField("Profile name", "Engineering Files");
  await flushUntil(() => {
    expect(container.textContent).toContain("This is a rename");
  });
  expect(container.textContent).toContain("stable object ID is preserved");
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("PUT");
  expect(m?.url).toContain(`/api/fileblock/profiles?id=${PROFILE_CUSTOM.id}`);
  expect(m?.url).toContain("ifRevision=fprev4");
  expect(m?.body).toMatchObject({ name: "Engineering Files" });
});

// D — the shared structured revision 409 surfaces as the refreshed notice.
it("file profiles: a revision-fence 409 surfaces as the not-applied notice", async () => {
  await mountProfiles("operator");
  onMutate = () =>
    okJSON(
      {
        error: "file profiles changed",
        currentRevision: "fprev9",
        yourRevision: "fprev4",
      },
      409,
    );
  await click(findButtonByLabel("Edit profile CAD Files"));
  setField("Profile name", "Doomed Rename");
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "The file profiles changed since you loaded them",
    );
  });
});

// E — unknown outcome latches the page and blocks further writes.
it("file profiles: a lost connection latches unknown-outcome and blocks writes", async () => {
  await mountProfiles("operator");
  onMutate = () => Promise.reject(new TypeError("network down"));
  await click(findButton((t) => t.includes("New file profile")));
  setField("Profile name", "Doomed");
  setField("Blocked extensions", "exe");
  await click(findButton((t) => t === "Create profile"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  expect(findButton((t) => t.includes("New file profile")).disabled).toBe(true);
});

// F — delete: fenced, stable-ID addressed, with the reference preflight shown.
it("file profiles: delete is fenced and addressed by stable id", async () => {
  await mountProfiles("operator");
  await click(findButtonByLabel("Delete profile CAD Files"));
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
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]?.method).toBe("DELETE");
  expect(mutations[0]?.url).toContain(`id=${PROFILE_CUSTOM.id}`);
  expect(mutations[0]?.url).toContain("ifRevision=fprev4");
});

// ── Header Rewrite ──────────────────────────────────────────────────────────

// G — viewer: rules render in EVALUATION order with positions; no controls.
it("header rewrite: viewer sees rules in evaluation order with no controls", async () => {
  await mountRewrite("viewer");
  const text = container.textContent ?? "";
  expect(text).toContain("2 rewrite rules");
  // Wire order preserved: *.example.com (pos 1) before api.internal.test (2).
  expect(text.indexOf("*.example.com")).toBeGreaterThan(-1);
  expect(text.indexOf("*.example.com")).toBeLessThan(
    text.indexOf("api.internal.test"),
  );
  expect(text).toContain("set X-Env");
  expect(text).toContain("remove X-Powered-By");
  expect(hasButton((t) => t.includes("New rewrite rule"))).toBe(false);
});

// H — operator create: fenced POST; the body NEVER carries a stableId.
it("header rewrite: create posts fenced structured ops and never a stableId", async () => {
  await mountRewrite("operator");
  await click(findButton((t) => t.includes("New rewrite rule")));
  setField("Host scope", "app.example.com");
  const setLabels = Array.from(container.querySelectorAll("label")).filter(
    (l) => (l.textContent ?? "").includes("Set (Header-Name"),
  );
  // First "Set" textarea is the request section.
  const reqSetLabel = setLabels[0];
  if (reqSetLabel === undefined) throw new Error("request Set field missing");
  const forId = reqSetLabel.getAttribute("for");
  const ta = forId !== null ? document.getElementById(forId) : null;
  if (!(ta instanceof HTMLTextAreaElement))
    throw new Error("request Set textarea missing");
  Object.getOwnPropertyDescriptor(
    HTMLTextAreaElement.prototype,
    "value",
  )?.set?.call(ta, "X-Team: platform");
  act(() => {
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("1 header operation defined");
  });
  await click(findButton((t) => t === "Create rule"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("POST");
  expect(m?.url).toContain("/api/rewrite?ifRevision=rwrev7");
  const body = m?.body;
  if (!isRecord(body)) throw new Error("mutation body missing");
  expect(body["host"]).toBe("app.example.com");
  expect(body["req_set"]).toEqual({ "X-Team": "platform" });
  expect("stableId" in body).toBe(false);
});

// I — create with zero operations is refused locally (server contract mirror).
it("header rewrite: zero header operations is refused before any request", async () => {
  await mountRewrite("operator");
  await click(findButton((t) => t.includes("New rewrite rule")));
  setField("Host scope", "app.example.com");
  await click(findButton((t) => t === "Create rule"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "At least one header operation",
    );
  });
  expect(mutations).toHaveLength(0);
});

// J — delete: addressed by stableId, fenced; conflict surfaces the notice.
it("header rewrite: delete addresses the stableId and honors the fence 409", async () => {
  await mountRewrite("operator");
  onMutate = () =>
    okJSON(
      {
        error: "rewrite rules changed",
        currentRevision: "rwrev9",
        yourRevision: "rwrev7",
      },
      409,
    );
  await click(findButtonByLabel("Delete rewrite rule 1"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Delete rewrite rule");
  });
  const deleteButtons = Array.from(container.querySelectorAll("button")).filter(
    (b) => b.textContent === "Delete",
  );
  const confirmBtn = deleteButtons[deleteButtons.length - 1];
  if (confirmBtn === undefined) throw new Error("confirm button not found");
  await click(confirmBtn);
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "The rewrite rules changed since you loaded them",
    );
  });
  expect(mutations[0]?.method).toBe("DELETE");
  expect(mutations[0]?.url).toContain(`stableId=${RW_FIRST.stableId}`);
  expect(mutations[0]?.url).toContain("ifRevision=rwrev7");
});

// K — unknown outcome on rewrite create latches the page.
it("header rewrite: a lost connection latches unknown-outcome", async () => {
  await mountRewrite("operator");
  onMutate = () => Promise.reject(new TypeError("network down"));
  await click(findButton((t) => t.includes("New rewrite rule")));
  const removeLabels = Array.from(container.querySelectorAll("label")).filter(
    (l) => (l.textContent ?? "").includes("Remove (header name"),
  );
  const label = removeLabels[0];
  if (label === undefined) throw new Error("Remove field missing");
  const forId = label.getAttribute("for");
  const ta = forId !== null ? document.getElementById(forId) : null;
  if (!(ta instanceof HTMLTextAreaElement))
    throw new Error("Remove textarea missing");
  Object.getOwnPropertyDescriptor(
    HTMLTextAreaElement.prototype,
    "value",
  )?.set?.call(ta, "X-Debug");
  act(() => {
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await click(findButton((t) => t === "Create rule"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  expect(findButton((t) => t.includes("New rewrite rule")).disabled).toBe(true);
});
