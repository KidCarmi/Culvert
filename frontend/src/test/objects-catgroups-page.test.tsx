// 2D-A.2 — Category Groups page proofs: viewer read-only posture, the fenced
// stable-ID mutation flows (create / edit / rename with the rename truth
// callout), dangling-member preservation (§12), the delete ceremony's
// authoritative server 409 with real consumers (§13), version-fence conflict
// handling, and the unknown-outcome latch.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CategoryGroupsPage } from "../features/objects/CategoryGroupsPage";

const GROUP_A = {
  id: "aaa111bbb222",
  name: "Prod Allowed",
  categories: ["news", "ai"],
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-02T00:00:00Z",
};
const GROUP_B = {
  id: "ccc333ddd444",
  name: "Legacy Set",
  categories: ["retiredcat"],
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
let groupsBody: unknown;
let urlcatBody: unknown;
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
  groupsBody = {
    groups: [GROUP_A, GROUP_B],
    names: [GROUP_A.name, GROUP_B.name],
    version: 4,
  };
  urlcatBody = [{ name: "News" }, { name: "AI" }, { name: "Finance" }];
  refsBody = {
    object: { type: "category-group", name: "Prod Allowed" },
    referencedBy: [],
  };
  mutations = [];
  onMutate = () => okJSON({ ok: true, version: 5 });
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
      if (url.includes("/api/category-groups")) return okJSON(groupsBody);
      if (url.includes("/api/urlcat")) return okJSON(urlcatBody);
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
    [{ path: "/objects/category-groups", element: <CategoryGroupsPage /> }],
    { initialEntries: ["/objects/category-groups"] },
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
    expect(container.textContent).toContain("Prod Allowed");
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
      : label.querySelector("input,textarea,select");
  if (!(el instanceof HTMLInputElement)) {
    throw new Error(`input not found for label: ${labelIncludes}`);
  }
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;
  act(() => {
    setter?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function toggleCheckbox(labelIncludes: string): Promise<void> {
  const label = Array.from(container.querySelectorAll("label")).find((l) =>
    (l.textContent ?? "").includes(labelIncludes),
  );
  if (label === undefined)
    throw new Error(`checkbox label not found: ${labelIncludes}`);
  const input = label.querySelector("input[type=checkbox]");
  if (!(input instanceof HTMLInputElement)) {
    throw new Error(`checkbox not found: ${labelIncludes}`);
  }
  return act(async () => {
    input.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

// A — viewer reads; zero mutation controls; stable IDs and counts rendered.
it("viewer: reads groups with stable IDs; no mutation controls", async () => {
  await mount("viewer");
  expect(container.textContent).toContain("aaa111bbb222");
  expect(container.textContent).toContain("2 category groups");
  expect(hasButton((t) => t.includes("New category group"))).toBe(false);
  expect(
    Array.from(container.querySelectorAll("button")).some((b) =>
      (b.getAttribute("aria-label") ?? "").startsWith("Edit group"),
    ),
  ).toBe(false);
});

// B — dangling membership renders as unresolved (§12), never silently dropped.
it("marks member categories that no longer resolve as unresolved", async () => {
  await mount("viewer");
  expect(container.textContent).toContain("1 unresolved");
  await click(findButtonByLabel("Details for group Legacy Set"));
  expect(container.textContent).toContain("retiredcat");
  expect(container.textContent).toContain("Unresolved member categories");
});

// C — operator create: fenced POST with the snapshot version and exact body.
it("operator: create posts the fenced mutation with name + categories", async () => {
  await mount("operator");
  await click(findButton((t) => t.includes("New category group")));
  setField("Group name", "Marketing Set");
  await toggleCheckbox("News");
  await toggleCheckbox("Finance");
  await click(findButton((t) => t === "Create group"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("POST");
  expect(m?.url).toContain("/api/category-groups?ifVersion=4");
  expect(m?.body).toEqual({
    name: "Marketing Set",
    categories: ["News", "Finance"],
  });
});

// D — rename: the truth callout appears and the PUT addresses the stable ID.
it("operator: rename shows the ID-stability truth and PUTs by stable id", async () => {
  await mount("operator");
  await click(findButtonByLabel("Edit group Prod Allowed"));
  expect(container.textContent).toContain("aaa111bbb222");
  setField("Group name", "Prod Allowed v2");
  await flushUntil(() => {
    expect(container.textContent).toContain("This is a rename");
  });
  expect(container.textContent).toContain("stable object ID is preserved");
  expect(container.textContent).toContain("any open Policy Draft candidate");
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("PUT");
  expect(m?.url).toContain("/api/category-groups?id=aaa111bbb222");
  expect(m?.url).toContain("ifVersion=4");
  expect(m?.body).toMatchObject({ name: "Prod Allowed v2" });
});

// E — editing another field NEVER silently drops a dangling member (§12).
it("keeps a dangling member on save unless explicitly unchecked", async () => {
  await mount("operator");
  await click(findButtonByLabel("Edit group Legacy Set"));
  await toggleCheckbox("News"); // add a resolved member; dangling stays checked
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const body = mutations[0]?.body as { categories: string[] };
  expect(body.categories).toContain("retiredcat");
  expect(body.categories).toContain("News");
});

// F — delete: the server's structured 409 renders the REAL consumers and the
// object is never optimistically removed.
it("delete refused by the server renders the authoritative consumers", async () => {
  await mount("operator");
  onMutate = () =>
    okJSON(
      {
        error:
          'cannot delete category-group "Prod Allowed": referenced by policy rule "allow-prod"',
        object: { type: "category-group", name: "Prod Allowed" },
        referencedBy: [
          {
            consumerType: "access-rule",
            id: "01J3ZV9E3JD0EEEEEEEEEEEEEE",
            name: "allow-prod",
            detail: "destCategoryGroup",
            view: "policy",
          },
        ],
      },
      409,
    );
  await click(findButtonByLabel("Delete group Prod Allowed"));
  await flushUntil(() => {
    expect(container.textContent).toContain("No references were found");
  });
  // Both the row action and the dialog confirm read "Delete" — the dialog
  // footer renders last in the DOM.
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
  expect(container.textContent).toContain("allow-prod");
  expect(container.textContent).toContain("destCategoryGroup");
  // Delete URL was fenced + stable-ID addressed.
  expect(mutations[0]?.method).toBe("DELETE");
  expect(mutations[0]?.url).toContain("id=aaa111bbb222");
  expect(mutations[0]?.url).toContain("ifVersion=4");
  // The row is still there (no optimistic removal).
  expect(container.textContent).toContain("Prod Allowed");
});

// G — version-fence conflict: the change is not applied and the page says so.
it("a version-fence 409 surfaces as the refreshed-objects notice", async () => {
  await mount("operator");
  onMutate = () =>
    okJSON({ error: "changed", currentVersion: 9, yourVersion: 4 }, 409);
  await click(findButtonByLabel("Edit group Prod Allowed"));
  setField("Group name", "Prod Allowed v2");
  await click(findButton((t) => t === "Save changes"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "The category groups changed since you loaded them",
    );
  });
});

// H — unknown outcome: the page latches and blocks further mutations.
it("a lost connection latches the unknown-outcome state and blocks writes", async () => {
  await mount("operator");
  onMutate = () => Promise.reject(new TypeError("network down"));
  await click(findButton((t) => t.includes("New category group")));
  setField("Group name", "Doomed");
  await click(findButton((t) => t === "Create group"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  expect(findButton((t) => t.includes("New category group")).disabled).toBe(
    true,
  );
});
