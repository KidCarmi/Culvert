// 2D-C shared-object management API: File Profiles + Header Rewrite.
//
// Contract highlights (FRONTEND-SECURITY-CONTRACT + 2D-C):
//   - FILE PROFILES: the stable object ID (server UUID; deterministic
//     `builtin-*` for the seeded built-ins) is the authoritative link
//     identity. The browser addresses edit/delete by ?id= and NEVER submits
//     a fileProfileId on policy rules — the server stamps name → ID. The v2
//     fence is a CONTENT-DERIVED revision (restart-stable): every mutation
//     echoes ?ifRevision= from GET /api/fileblock/profiles/state; the server
//     compares inside the store's critical section and a mismatch is the
//     shared structured 409 ({error, currentRevision, yourRevision}).
//   - HEADER REWRITE: the durable identity is `stableId` (server UUID). The
//     legacy integer `id` is PROCESS-LOCAL compatibility metadata — never
//     used for addressing, deep links, or fencing by this client. Rules are
//     rendered and stored in EVALUATION ORDER (list order is semantics —
//     multiple matching rules apply top-to-bottom); the client never sorts
//     the authoritative list. Mutations echo ?ifRevision= from
//     GET /api/rewrite/state (content fingerprint over identity + position +
//     host + all header operations).
//   - A confirmed 2xx is restart-durable (settings-owner persistence for
//     rewrite; durable-or-nothing store for profiles); a hard persist
//     failure is a non-2xx with the runtime unchanged.
import { apiRequest } from "./client";
import {
  field,
  readArray,
  readNumber,
  readOptional,
  readRecord,
  readString,
  type Decoder,
} from "./decode";

// ── File Profiles ───────────────────────────────────────────────────────────

export interface FileProfileView {
  id: string;
  name: string;
  extensions: readonly string[];
  /** Deterministic seeded built-ins carry `builtin-*` IDs; they stay editable
   * (existing product behavior) — the ID, not the name, is the anchor. */
  builtIn: boolean;
}

export interface FileProfileState {
  profiles: readonly FileProfileView[];
  /** Content-derived restart-stable revision — the ifRevision fence token. */
  revision: string;
}

const decodeFileProfile: Decoder<FileProfileView> = (v, path = "$") => {
  const o = readRecord(v, path);
  const id = field(o, "id", readString, path);
  const exts = o["extensions"];
  return {
    id,
    name: field(o, "name", readString, path),
    extensions:
      exts === undefined || exts === null
        ? []
        : field(o, "extensions", readArray(readString), path),
    builtIn: id.startsWith("builtin-"),
  };
};

export const decodeFileProfileState: Decoder<FileProfileState> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = o["profiles"];
  return {
    profiles:
      raw === undefined || raw === null
        ? []
        : field(o, "profiles", readArray(decodeFileProfile), path),
    revision: field(o, "revision", readString, path),
  };
};

export function getFileProfileState(
  signal?: AbortSignal,
): Promise<FileProfileState> {
  return apiRequest(
    "/api/fileblock/profiles/state",
    decodeFileProfileState,
    signal !== undefined ? { signal } : {},
  );
}

function fencedRev(path: string, ifRevision: string): string {
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}ifRevision=${encodeURIComponent(ifRevision)}`;
}

const decodeCreated: Decoder<FileProfileView> = decodeFileProfile;
const decodeOk: Decoder<void> = () => undefined;

export interface FileProfileWrite {
  name: string;
  /** Raw user entries; the SERVER normalizes (lowercase, leading dot, dedupe)
   * and its normalized result is what the refreshed state shows. */
  extensions: readonly string[];
}

export function createFileProfile(
  write: FileProfileWrite,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<FileProfileView> {
  return apiRequest(
    fencedRev("/api/fileblock/profiles", ifRevision),
    decodeCreated,
    {
      method: "POST",
      body: { name: write.name, extensions: write.extensions },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

/** Update (and, when `write.name` differs, RENAME) the profile with the given
 * stable ID. A rename is a TRUE rename: the object ID — and therefore every
 * referencing rule's enforcement identity — is preserved; the server cascades
 * the display name onto running rules and an active draft candidate. */
export function updateFileProfile(
  id: string,
  write: FileProfileWrite,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedRev(
      `/api/fileblock/profiles?id=${encodeURIComponent(id)}`,
      ifRevision,
    ),
    decodeOk,
    {
      method: "PUT",
      body: { name: write.name, extensions: write.extensions },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export function deleteFileProfile(
  id: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedRev(
      `/api/fileblock/profiles?id=${encodeURIComponent(id)}`,
      ifRevision,
    ),
    decodeOk,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

/** UX mirror of the server's extension normalization (lowercase, leading dot,
 * dedupe, drop empties). PREVIEW ONLY — the server remains authoritative and
 * the editor re-reads its normalized result after save. */
export function previewNormalizedExtensions(
  lines: readonly string[],
): readonly string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of lines) {
    let e = raw.trim().toLowerCase();
    if (e === "" || e === ".") continue;
    if (!e.startsWith(".")) e = `.${e}`;
    if (!seen.has(e)) {
      seen.add(e);
      out.push(e);
    }
  }
  return out;
}

// ── Header Rewrite ──────────────────────────────────────────────────────────

export interface RewriteRuleView {
  /** Durable server-owned identity — the ONLY addressing this client uses. */
  stableId: string;
  /** Legacy process-local integer; shown nowhere prominent, never addressed. */
  legacyId: number;
  host: string;
  reqSet: Readonly<Record<string, string>>;
  reqAdd: Readonly<Record<string, string>>;
  reqRemove: readonly string[];
  respSet: Readonly<Record<string, string>>;
  respAdd: Readonly<Record<string, string>>;
  respRemove: readonly string[];
}

export interface RewriteState {
  /** In EVALUATION order — the order the appliance applies them. */
  rules: readonly RewriteRuleView[];
  revision: string;
}

const optStr = readOptional(readString);

function readStrMap(
  v: unknown,
  path: string,
): Readonly<Record<string, string>> {
  if (v === undefined || v === null) return {};
  const o = readRecord(v, path);
  const out: Record<string, string> = {};
  for (const k of Object.keys(o)) {
    out[k] = readString(o[k], `${path}.${k}`);
  }
  return out;
}

const decodeRewriteRule: Decoder<RewriteRuleView> = (v, path = "$") => {
  const o = readRecord(v, path);
  const rr = o["req_remove"];
  const pr = o["resp_remove"];
  return {
    stableId: field(o, "stableId", optStr, path) ?? "",
    legacyId: field(o, "id", readNumber, path),
    host: field(o, "host", optStr, path) ?? "",
    reqSet: readStrMap(o["req_set"], `${path}.req_set`),
    reqAdd: readStrMap(o["req_add"], `${path}.req_add`),
    reqRemove:
      rr === undefined || rr === null
        ? []
        : field(o, "req_remove", readArray(readString), path),
    respSet: readStrMap(o["resp_set"], `${path}.resp_set`),
    respAdd: readStrMap(o["resp_add"], `${path}.resp_add`),
    respRemove:
      pr === undefined || pr === null
        ? []
        : field(o, "resp_remove", readArray(readString), path),
  };
};

export const decodeRewriteState: Decoder<RewriteState> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["rules"];
  return {
    rules:
      raw === undefined || raw === null
        ? []
        : field(o, "rules", readArray(decodeRewriteRule), path),
    revision: field(o, "revision", readString, path),
  };
};

export function getRewriteState(signal?: AbortSignal): Promise<RewriteState> {
  return apiRequest(
    "/api/rewrite/state",
    decodeRewriteState,
    signal !== undefined ? { signal } : {},
  );
}

export interface RewriteRuleWrite {
  host: string;
  reqSet: Readonly<Record<string, string>>;
  reqAdd: Readonly<Record<string, string>>;
  reqRemove: readonly string[];
  respSet: Readonly<Record<string, string>>;
  respAdd: Readonly<Record<string, string>>;
  respRemove: readonly string[];
}

function serializeRewriteWrite(w: RewriteRuleWrite): Record<string, unknown> {
  const out: Record<string, unknown> = { host: w.host };
  // The client NEVER submits a stableId — identity is server-owned on create.
  if (Object.keys(w.reqSet).length > 0) out["req_set"] = w.reqSet;
  if (Object.keys(w.reqAdd).length > 0) out["req_add"] = w.reqAdd;
  if (w.reqRemove.length > 0) out["req_remove"] = w.reqRemove;
  if (Object.keys(w.respSet).length > 0) out["resp_set"] = w.respSet;
  if (Object.keys(w.respAdd).length > 0) out["resp_add"] = w.respAdd;
  if (w.respRemove.length > 0) out["resp_remove"] = w.respRemove;
  return out;
}

export function createRewriteRule(
  write: RewriteRuleWrite,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<RewriteRuleView> {
  return apiRequest(fencedRev("/api/rewrite", ifRevision), decodeRewriteRule, {
    method: "POST",
    body: serializeRewriteWrite(write),
    ...(signal !== undefined ? { signal } : {}),
  });
}

export function deleteRewriteRule(
  stableId: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedRev(
      `/api/rewrite?stableId=${encodeURIComponent(stableId)}`,
      ifRevision,
    ),
    decodeOk,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

/** Compact one-line summary of a rule's operations for the list columns. */
export function summarizeOps(
  set: Readonly<Record<string, string>>,
  add: Readonly<Record<string, string>>,
  remove: readonly string[],
): string {
  const parts: string[] = [];
  for (const k of Object.keys(set)) parts.push(`set ${k}`);
  for (const k of Object.keys(add)) parts.push(`add ${k}`);
  for (const k of remove) parts.push(`remove ${k}`);
  return parts.length === 0 ? "—" : parts.join(", ");
}
