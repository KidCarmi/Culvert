// 2F-E RED matrix (page) — written against the merged entry-gate head
// (e8ae527a) BEFORE the PAC surface exists; fails at import resolution
// there. Pins the browser-side lifecycle guarantees of the directive:
//
//   P1  viewer mounts ZERO mutation controls on every tab and issues ZERO
//       non-GET requests; every lifecycle/exception surface says node-local.
//   P2  a stale write (409 stale) renders the server's current token and is
//       NEVER auto-retried (exactly one POST).
//   P3  the bound DIRECT challenge renders the binding (newDirectPaths) and
//       the typed confirmValue; Enter/wrong word cannot confirm; the retry
//       echoes {challenge, value, binding} VERBATIM with the SAME reviewed
//       draft and operationId.
//   P4  a challenge_stale on retry names the changed fields and is never
//       retried blindly (no third POST).
//   P5  a lost response (transport death after dispatch) latches the page
//       as UNKNOWN with the operation identity persisted BEFORE dispatch;
//       "Recover" resolves AUTHORITATIVELY from the lifecycle GET (our id
//       decided ⇒ landed) before any fresh dispatch is allowed.
//   P6  history_reset: publish is withheld and the acknowledgement ceremony
//       binds expectedActiveRevision + expectedActiveSpecDigest from the GET.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { PACPage } from "../features/network/pac/PACPage";
import { PAC_RECOVERY_KEY } from "../features/network/pac/pacRecovery";
import { isRecord } from "../api/decode";

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
  profiles: [ACTIVE],
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
    poolChangedSince: false,
    scope: "node-local",
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
      if (url === "/api/pac/profiles/hq/lifecycle") return okJSON(lifecycle);
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

async function openTab(name: string, readyText: string): Promise<void> {
  clickButton((t) => t === name);
  await flushUntil(() => {
    expect(container.textContent).toContain(readyText);
  });
}

async function openProfile(): Promise<void> {
  clickButton((t) => t === "Open");
  await flushUntil(() => {
    expect(container.textContent).toContain("Active revision");
  });
}

function typeInto(label: string, value: string): void {
  const el = Array.from(container.querySelectorAll("input")).find((i) => {
    const l = i.labels?.[0]?.textContent ?? "";
    return l.includes(label);
  });
  if (el === undefined) throw new Error("input not found: " + label);
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function nonGets(): string[] {
  return requested.filter((r) => !r.startsWith("GET "));
}

const MUTATION_WORDS = [
  "Publish",
  "Save draft",
  "New profile",
  "New pool",
  "Delete",
  "Roll back",
  "Acknowledge",
  "Repair",
  "Save",
  "Clear",
  "Recover",
];

// ── P1 ──────────────────────────────────────────────────────────────────────

it("P1 viewer: zero mutation controls on every tab, zero non-GET requests, node-local labels", async () => {
  await mountPage("viewer");
  await openProfile();
  expect(container.textContent).toContain("node-local");
  await openTab("Pools", "Pool One");
  await openTab("DIRECT Exceptions", "ungoverned");
  expect(container.textContent).toContain("node-local");
  await openTab("Legacy PAC", "proxy.example");
  await openTab("Profiles", "HQ");
  const found = buttons().filter((t) =>
    MUTATION_WORDS.some((w) => t.includes(w)),
  );
  expect(found).toEqual([]);
  expect(nonGets()).toEqual([]);
});

// ── P2 ──────────────────────────────────────────────────────────────────────

it("P2 admin: a stale publish renders the server's current revision and is never auto-retried", async () => {
  onMutate = () =>
    okJSON(
      {
        error: "stale revision 3 (current 5): reload and retry",
        code: "stale",
        current: { revision: 5 },
      },
      409,
    );
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("current revision 5");
  });
  expect(mutations.filter((m) => m.url.includes("/lifecycle"))).toHaveLength(1);
  const body = mutations[0]?.body;
  expect(isRecord(body) && body["expectedActiveRevision"]).toBe(3);
  expect(isRecord(body) && body["action"]).toBe("publish");
});

// ── P3 / P4 ─────────────────────────────────────────────────────────────────

it("P3 admin: the DIRECT challenge shows the binding, needs the exact typed value, and the retry echoes it verbatim with the same operationId", async () => {
  let n = 0;
  onMutate = () => {
    n += 1;
    if (n === 1)
      return okJSON(
        {
          error: "new DIRECT paths",
          code: "confirm_required",
          confirmField: "confirm",
          challenge: "v1:deadbeef",
          confirmValue: "hq:1a2b3c4d",
          binding: BINDING,
        },
        409,
      );
    return okJSON({
      operationId: "x",
      activeRevision: 4,
      activeSpecDigest: "sha256:1a2b3c4d5e6f",
      digest: "arti",
      draftRevision: 4,
      historyState: "recorded",
      scope: "node-local-history",
      published: true,
      revision: 3,
    });
  };
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "rule: direct domain intranet.example",
    );
    expect(container.textContent).toContain("hq:1a2b3c4d");
  });
  // wrong word ⇒ confirm stays disabled; no second POST
  typeInto("Type", "hq:wrong");
  const disabled = Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === "Publish bypass",
  );
  expect(disabled?.disabled).toBe(true);
  expect(mutations).toHaveLength(1);
  typeInto("Type", "hq:1a2b3c4d");
  clickButton((t) => t === "Publish bypass");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  const first = mutations[0]?.body;
  const second = mutations[1]?.body;
  if (!isRecord(first) || !isRecord(second)) throw new Error("bodies");
  expect(second["operationId"]).toBe(first["operationId"]);
  expect(second["draft"]).toEqual(first["draft"]);
  expect(second["confirm"]).toEqual({
    challenge: "v1:deadbeef",
    value: "hq:1a2b3c4d",
    binding: BINDING,
  });
  expect("confirmDirect" in second).toBe(false);
  await flushUntil(() => {
    expect(container.textContent).toContain("Published");
  });
});

it("P4 admin: challenge_stale on retry names the changed fields and is not retried blindly", async () => {
  let n = 0;
  onMutate = () => {
    n += 1;
    if (n === 1)
      return okJSON(
        {
          error: "new DIRECT paths",
          code: "confirm_required",
          confirmField: "confirm",
          challenge: "v1:deadbeef",
          confirmValue: "hq:1a2b3c4d",
          binding: BINDING,
        },
        409,
      );
    return okJSON(
      {
        error: "stale",
        code: "challenge_stale",
        confirmField: "confirm",
        challenge: "v1:cafe",
        confirmValue: "hq:1a2b3c4d",
        binding: { ...BINDING, poolDigest: "sha256:new" },
        changed: ["poolDigest"],
      },
      409,
    );
  };
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("hq:1a2b3c4d");
  });
  typeInto("Type", "hq:1a2b3c4d");
  clickButton((t) => t === "Publish bypass");
  await flushUntil(() => {
    expect(container.textContent).toContain("poolDigest");
    expect(container.textContent).toContain("changed");
  });
  expect(mutations).toHaveLength(2);
});

// ── P5 ──────────────────────────────────────────────────────────────────────

it("P5 admin: a lost response latches UNKNOWN with the operation id persisted before dispatch; Recover resolves LANDED from the lifecycle GET", async () => {
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
  const raw = sessionStorage.getItem(PAC_RECOVERY_KEY);
  expect(raw).not.toBeNull();
  const marker: unknown = JSON.parse(raw ?? "{}");
  const sent = mutations[0]?.body;
  if (!isRecord(marker) || !isRecord(sent)) throw new Error("marker/body");
  expect(marker["operationId"]).toBe(sent["operationId"]);
  expect(marker["subject"]).toBe("admin-user");
  expect(marker["profileId"]).toBe("hq");
  // publish is withheld while unresolved
  const pub = Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === "Publish",
  );
  expect(pub === undefined || pub.disabled).toBe(true);
  // the operation landed server-side: the lifecycle GET now decides it
  lifecycle = {
    ...baseLifecycle(),
    activeRevision: 4,
    activeSpecDigest: "sha256:1a2b3c4d5e6f",
    draftDirty: false,
    draftDiff: null,
    operations: [
      {
        operationId: String(sent["operationId"]),
        action: "publish",
        state: "recorded",
        ts: "t",
        status: 200,
        result: null,
      },
    ],
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("landed");
  });
  expect(sessionStorage.getItem(PAC_RECOVERY_KEY)).toBeNull();
  expect(mutations).toHaveLength(1);
  await flushUntil(() => {
    const p = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Publish",
    );
    expect(p !== undefined && !p.disabled).toBe(true);
  });
});

// ── P6 ──────────────────────────────────────────────────────────────────────

it("P6 admin: history_reset withholds publish and the acknowledgement binds the reviewed active revision + spec digest", async () => {
  lifecycle = {
    ...baseLifecycle(),
    historyState: "history_reset",
    historyReset: {
      at: "2026-09-04T09:00:00Z",
      quarantinedTo: "/data/pac_profiles_lifecycle.json.corrupt.1",
      cause: "decode",
      scoped: true,
      activeAtReset: ["hq"],
      acknowledgedProfiles: 0,
      ackAction: "acknowledge_history_reset",
    },
  };
  onMutate = (_m, _u, body) => {
    if (isRecord(body) && body["action"] === "acknowledge_history_reset") {
      lifecycle = baseLifecycle();
      return okJSON({
        acknowledged: true,
        operationId: String(body["operationId"]),
        historyState: "recorded",
        activeRevision: 3,
        activeSpecDigest: "sha256:bbbb",
      });
    }
    return okJSON({ error: "x" }, 400);
  };
  await mountPage("admin");
  await openProfile();
  await flushUntil(() => {
    expect(container.textContent).toContain("quarantined");
  });
  const pub = Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === "Publish",
  );
  expect(pub === undefined || pub.disabled).toBe(true);
  clickButton((t) => t.startsWith("Acknowledge"));
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Acknowledge and continue")).toBe(true);
  });
  clickButton((t) => t === "Acknowledge and continue");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const body = mutations[0]?.body;
  if (!isRecord(body)) throw new Error("body");
  expect(body["action"]).toBe("acknowledge_history_reset");
  expect(body["expectedActiveRevision"]).toBe(3);
  expect(body["expectedActiveSpecDigest"]).toBe("sha256:bbbb");
  expect(String(body["operationId"])).toMatch(/^[0-9a-f-]{36}$/);
  await flushUntil(() => {
    const p = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Publish",
    );
    expect(p !== undefined && !p.disabled).toBe(true);
  });
});
