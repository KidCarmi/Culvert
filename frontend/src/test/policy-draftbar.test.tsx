// 2B.3 — Draft Bar proofs: all four §18 states (including the STRANDED
// recovery draft, which must never be hidden or blindly committable), the
// Require Commit mode ceremony (§20), the shared-actor warning (§21), and
// the revert ceremony (§31).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";

const POLICY_BODY = {
  rules: [
    {
      priority: 1,
      name: "Some rule",
      id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
      action: "Allow",
      sslAction: "Bypass",
      hitCount: 0,
    },
  ],
  count: 1,
  version: 3,
  updatedAt: "2026-08-28T12:00:00Z",
  draft: false,
};

const ACTIVE_DRAFT = {
  requireCommit: true,
  active: true,
  actor: "other-admin",
  startedAt: "2026-08-28T10:00:00Z",
  diff: { added: ["Staged one"], modified: [], removed: ["Old rule"] },
  pendingCount: 2,
  version: 9,
  shadows: [],
};

function okJSON(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let draftBody: unknown;
let policyBody: unknown;
let onModePut: (body: unknown) => Promise<Response>;
let onRevertPost: () => Promise<Response>;
let modePuts: unknown[];
let revertPosts: number;

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
  draftBody = { requireCommit: false, active: false, actor: "", startedAt: "" };
  policyBody = POLICY_BODY;
  onModePut = () => okJSON({ requireCommit: true });
  onRevertPost = () => okJSON({ ok: true, discarded: 2 });
  modePuts = [];
  revertPosts = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.includes("/api/policy/draft/revert") && method === "POST") {
        revertPosts += 1;
        return onRevertPost();
      }
      if (url.includes("/api/policy/draft") && method === "PUT") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        modePuts.push(body);
        return onModePut(body);
      }
      if (url.includes("/api/policy/draft")) return okJSON(draftBody);
      if (url.includes("/api/policy")) return okJSON(policyBody);
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
  user: string,
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
        user,
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
  user?: string,
): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/policies/access-rules", element: <AccessRulesPage /> }],
    { initialEntries: ["/policies/access-rules"] },
  );
  const qc = new QueryClient();
  const machine = machineFor(role, user ?? role, qc);
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
    expect(container.textContent).toContain("Some rule");
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

it("state A (live-write): admin gets the arm control; the ceremony PUTs require_commit true", async () => {
  await mount("admin");
  expect(container.textContent).toContain("Live-write mode");
  await click(findButton((t) => t.includes("Require commit for changes")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "staged into one shared Policy Draft",
    );
  });
  await click(findButton((t) => t === "Require commit"));
  await flushUntil(() => {
    expect(modePuts.length).toBe(1);
  });
  expect(modePuts[0]).toEqual({ require_commit: true });
});

it("state A: operator sees the mode truth but no mode controls", async () => {
  await mount("operator");
  expect(container.textContent).toContain("Live-write mode");
  expect(hasButton((t) => t.includes("Require commit for changes"))).toBe(
    false,
  );
});

it("state B (armed, no draft): staged-write truth + admin disarm; a dirty-draft 409 shows the server refusal verbatim", async () => {
  draftBody = { requireCommit: true, active: false, actor: "", startedAt: "" };
  await mount("admin");
  expect(container.textContent).toContain("Commit mode armed");
  onModePut = () =>
    Promise.resolve(
      new Response(
        "a draft with pending changes exists — commit or revert it before disabling commit mode",
        { status: 409 },
      ),
    );
  await click(findButton((t) => t.includes("Disable commit mode…")));
  await flushUntil(() => {
    expect(container.textContent).toContain("LIVE immediately");
  });
  await click(findButton((t) => t === "Disable commit mode"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "a draft with pending changes exists",
    );
  });
});

it("state C (shared candidate): actor, pending counts, revert ceremony with impact; actor warning only for a DIFFERENT user", async () => {
  draftBody = ACTIVE_DRAFT;
  policyBody = { ...POLICY_BODY, draft: true };
  await mount("operator", "me-operator");
  expect(container.textContent).toContain("Editing the shared Policy Draft");
  expect(container.textContent).toContain("other-admin");
  expect(container.textContent).toContain("2 pending changes");
  // §21 shared-actor warning — one shared candidate, never "their draft".
  expect(container.textContent).toContain(
    "This shared draft was opened by other-admin. Your edits modify the same candidate.",
  );
  expect(container.textContent).not.toContain("their draft");

  await click(findButton((t) => t.includes("Revert draft…")));
  await flushUntil(() => {
    expect(container.textContent).toContain("Discards 2 pending changes");
  });
  expect(container.textContent).toContain("1 added, 0 modified, 1 removed");
  await click(findButton((t) => t === "Revert draft"));
  await flushUntil(() => {
    expect(revertPosts).toBe(1);
  });
});

it("state C: no shared-actor warning when the current user opened the draft", async () => {
  draftBody = { ...ACTIVE_DRAFT, actor: "me-operator" };
  policyBody = { ...POLICY_BODY, draft: true };
  await mount("operator", "me-operator");
  expect(container.textContent).toContain("Editing the shared Policy Draft");
  expect(container.textContent).not.toContain(
    "Your edits modify the same candidate",
  );
});

it("state D (stranded): admin may resume review or revert; commit is never offered", async () => {
  draftBody = { ...ACTIVE_DRAFT, requireCommit: false };
  await mount("admin");
  expect(container.textContent).toContain("Stranded Policy Draft");
  expect(container.textContent).toContain(
    "the candidate's rules cannot be reviewed here right now",
  );
  expect(hasButton((t) => t.includes("Resume draft review"))).toBe(true);
  expect(hasButton((t) => t.includes("Revert draft"))).toBe(true);
  expect(hasButton((t) => t.includes("commit…"))).toBe(false);
  expect(hasButton((t) => t.includes("Review & commit"))).toBe(false);

  // Resume runs the SAME arm ceremony.
  await click(findButton((t) => t.includes("Resume draft review")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "staged into one shared Policy Draft",
    );
  });
});

it("state D (stranded): operator gets the warning and safe revert, never resume or commit", async () => {
  draftBody = { ...ACTIVE_DRAFT, requireCommit: false };
  await mount("operator");
  expect(container.textContent).toContain("Stranded Policy Draft");
  expect(hasButton((t) => t.includes("Resume draft review"))).toBe(false);
  expect(hasButton((t) => t.includes("Revert draft"))).toBe(true);
  expect(hasButton((t) => t.includes("Review & commit"))).toBe(false);
});

it("2C §8 (stale base): critical callout with the exact guidance; commit entry withheld; revert still offered", async () => {
  draftBody = { ...ACTIVE_DRAFT, baseStale: true };
  policyBody = { ...POLICY_BODY, draft: true };
  await mount("admin", "other-admin");
  expect(container.textContent).toContain("Draft baseline is stale");
  expect(container.textContent).toContain(
    "The running policy changed after this Access Policy Draft was opened.",
  );
  expect(container.textContent).toContain(
    "This draft cannot be safely committed as-is.",
  );
  expect(hasButton((t) => t.includes("Review & commit"))).toBe(false);
  expect(hasButton((t) => t.includes("Revert draft"))).toBe(true);
});

it("2C §8 (fresh base): no stale callout; commit entry offered; absent baseStale decodes as fresh", async () => {
  draftBody = ACTIVE_DRAFT; // baseStale absent on the wire ⇒ decoded false
  policyBody = { ...POLICY_BODY, draft: true };
  await mount("admin", "other-admin");
  expect(container.textContent).not.toContain("Draft baseline is stale");
  expect(hasButton((t) => t.includes("Review & commit"))).toBe(true);
});
