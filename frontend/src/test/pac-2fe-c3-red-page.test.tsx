// 2F-E CORRECTION ROUND 3 RED matrix (page) — external freeze review of
// the candidate 33f6f21c (findings 1–2). Written and executed on the
// UNTOUCHED candidate before any product change; every P-case fails there:
//
//   P22  UNKNOWN EPOCH: the lifecycle GET reports an EMPTY historyIncarnation
//        for an existing profile — the appliance could not make the history
//        epoch identity durable (a failed migration write, finding 2). A
//        dispatch reviewed against no epoch can never be resolved if its
//        response is lost, so publish (and rollback) are WITHHELD with an
//        explanation; nothing is sent. The candidate dispatched with
//        expectedHistoryIncarnation "" (the appliance treats that as "no
//        epoch reviewed").
//   P23  SPEC DIGEST FENCE: the publish dispatched from the page carries the
//        reviewed active spec digest (`expectedActiveSpecDigest`) beside the
//        revision and the epoch, so a same-revision replacement (replace
//        import / config rollback, finding 1) is refused on the appliance.
//
// The scaffold (fixtures, mount, fetch stub, helpers) is the round-2 page
// scaffold verbatim.
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { PACPage } from "../features/network/pac/PACPage";
import { isRecord } from "../api/decode";

const INC_A = "a1a1a1a1-0000-4000-8000-000000000001";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

const RULE = { kind: "domain", pattern: "intranet.example", action: "direct" };
const ACTIVE = {
  id: "hq",
  name: "HQ",
  description: "",
  enabled: true,
  poolId: "p1",
  rules: [],
  privateNetworks: "proxy",
  availabilityMode: "secure",
  revision: 3,
};
const BRANCH = { ...ACTIVE, id: "branch", name: "Branch" };
const POOL = {
  id: "p1",
  name: "Pool One",
  endpoints: [{ host: "proxy.example", port: 8080 }],
};
const LISTING = {
  defaultProfile: {
    id: "default",
    name: "Default (legacy)",
    enabled: true,
    legacyManaged: true,
    availabilityMode: "balanced",
    privateNetworks: "direct",
    proxyHost: "proxy.example",
    proxyPort: 8080,
    exclusions: 2,
    pacPath: "/pac/default.pac",
  },
  profiles: [ACTIVE, BRANCH],
  pools: [POOL],
  collectionEtag: "sha256:coll",
  poolEtags: { p1: "sha256:pool1" },
};
const BINDING = {
  profileId: "hq",
  action: "publish",
  targetN: 0,
  candidateSpecDigest: "sha256:1a2b3c4d5e6f",
  expectedActiveRevision: 3,
  expectedActiveSpecDigest: "sha256:bbbb",
  poolDigest: "sha256:pppp",
  artifactDigest: "sha256:arti",
  newDirectPaths: ["rule: direct domain intranet.example"],
};

let container: HTMLDivElement;
let root: Root;
let requested: string[];
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string, body: unknown) => Promise<Response>;
let lifecycle: Record<string, unknown>;
let lookup: Record<string, unknown> | null;

function baseLifecycle(): Record<string, unknown> {
  return {
    profileId: "hq",
    activeExists: true,
    active: ACTIVE,
    draft: { ...ACTIVE, rules: [RULE], revision: 0 },
    draftDirty: true,
    activeN: 2,
    revisions: [
      {
        n: 1,
        spec: ACTIVE,
        digest: "a1",
        author: "admin",
        ts: "2026-09-04T10:00:00Z",
        specDigest: "sha256:aaaa",
        poolDigest: "sha256:pppp",
      },
      {
        n: 2,
        spec: ACTIVE,
        digest: "a2",
        author: "admin",
        ts: "2026-09-04T11:00:00Z",
        specDigest: "sha256:bbbb",
        poolDigest: "sha256:pppp",
      },
    ],
    draftDiff: {
      rulesAdded: ["rule 1: direct domain intranet.example"],
      rulesReordered: false,
      poolChanged: false,
      newDirectPaths: BINDING.newDirectPaths,
      securitySensitive: true,
    },
    draftRevision: 4,
    activeRevision: 3,
    collectionEtag: "sha256:coll",
    state: "idle",
    historyState: "recorded",
    pendingOp: null,
    ambiguous: null,
    operations: [],
    activeSpecDigest: "sha256:bbbb",
    draftSpecDigest: "sha256:cand",
    operationsRetained: 0,
    operationsCap: 64,
    poolChangedSince: false,
    scope: "node-local",
    historyIncarnation: INC_A,
    previousRevision: 1,
  };
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
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
  requested = [];
  mutations = [];
  sessionStorage.clear();
  lifecycle = baseLifecycle();
  lookup = null;
  onMutate = () => okJSON({ ok: true });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requested.push(`${method} ${url}`);
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(method, url, body);
      }
      if (url === "/api/pac/profiles") return okJSON(LISTING);
      if (url.startsWith("/api/pac/profiles/hq/lifecycle?operationId="))
        return okJSON(lookup ?? lifecycle);
      if (url === "/api/pac/profiles/hq/lifecycle") return okJSON(lifecycle);
      if (url === "/api/pac/profiles/branch/lifecycle")
        return okJSON({
          ...baseLifecycle(),
          profileId: "branch",
          active: BRANCH,
          draft: { ...BRANCH, revision: 0 },
        });
      if (url === "/api/pac/pools")
        return okJSON([{ ...POOL, etag: "sha256:pool1" }]);
      if (url === "/api/pac/posture/exceptions")
        return okJSON({
          exceptions: [
            {
              profileId: "hq",
              name: "HQ",
              serving: true,
              directCapable: true,
              status: "ungoverned",
              record: null,
            },
          ],
        });
      // Fixture completion (harness, not an assertion): the DIRECT Exceptions
      // tab renders the posture inventory beside the exception records.
      if (url === "/api/pac/posture/inventory")
        return okJSON({
          evidenceClass: "config",
          profiles: [
            {
              profileId: "hq",
              name: "HQ",
              serving: true,
              availabilityMode: "served",
              directCapable: true,
              directPaths: [],
            },
          ],
          totalProfiles: 1,
          directCapableProfiles: 1,
          servingDirectProfiles: 1,
          totalDirectPaths: 0,
          broadDirectPaths: 0,
        });
      if (url === "/api/pac-config")
        return okJSON({
          proxyHost: "proxy.example",
          proxyPort: 8080,
          exclusions: ["*.local", "10.0.0.0/8"],
          revision: 2,
        });
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
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

async function mountPage(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/network/pac", element: <PACPage /> }],
    {
      initialEntries: ["/network/pac"],
    },
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
    expect(container.textContent).toContain("HQ");
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

function buttons(): string[] {
  return Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
}

function clickButton(match: (t: string) => boolean): void {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined)
    throw new Error("button not found: " + buttons().join("|"));
  act(() => {
    b.click();
  });
}

async function openProfile(): Promise<void> {
  clickButton((t) => t === "Open");
  await flushUntil(() => {
    expect(container.textContent).toContain("Active revision");
  });
}

function publishButton(): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === "Publish",
  );
}

async function publishAndLoseResponse(): Promise<Record<string, unknown>> {
  onMutate = () => Promise.reject(new TypeError("connection lost"));
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("unknown");
  });
  const sent = mutations[0]?.body;
  if (!isRecord(sent)) throw new Error("no dispatch body");
  return sent;
}

// ── P22 ─────────────────────────────────────────────────────────────────────

it("P22 admin: an EMPTY history epoch identity withholds publish and sends nothing", async () => {
  lifecycle = { ...baseLifecycle(), historyIncarnation: "" };
  await mountPage("admin");
  await openProfile();
  // the page explains WHY nothing can be dispatched
  expect(container.textContent).toMatch(/history epoch/i);
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
  // even if the button could be reached, the ceremony never dispatches
  if (pub !== undefined && !pub.disabled) {
    clickButton((t) => t === "Publish");
    await flushUntil(() => {
      expect(buttons().some((t) => t === "Publish now")).toBe(true);
    });
    clickButton((t) => t === "Publish now");
    await flushUntil(() => {
      expect(container.textContent).not.toContain("Publish now");
    });
  }
  expect(mutations).toHaveLength(0);
});

// ── P23 ─────────────────────────────────────────────────────────────────────

it("P23 admin: the dispatched publish carries the reviewed active spec digest as its own fence", async () => {
  const sent = await publishAndLoseResponse();
  expect(sent["expectedActiveRevision"]).toBe(3);
  expect(sent["expectedHistoryIncarnation"]).toBe(INC_A);
  expect(sent["expectedActiveSpecDigest"]).toBe("sha256:bbbb");
});
