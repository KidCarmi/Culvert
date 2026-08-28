// 2D-A shared-object management API: Category Groups + Decryption Profiles.
//
// Contract highlights (FRONTEND-SECURITY-CONTRACT + 2D-A):
//   - The stable object ID is the authoritative link identity; the browser
//     addresses every v2 mutation by ?id= and NEVER chooses or submits
//     object-link IDs on policy rules (the Policy server stamps name → ID).
//   - Every v2 mutation asserts ?ifVersion= (the durable per-store generation
//     from the list read); the server evaluates fence + mutation + persist in
//     one critical section and a mismatch is the structured 409
//     ({error, currentVersion, yourVersion}) shared with the policy rulebase.
//   - A confirmed 2xx means the mutation is restart-durable (2D-A.0 backend
//     contract); a 500 means it was rolled back — except a rename cascade
//     failure, whose 500 body states the object rename itself IS durable.
//   - Security enums are decoded STRICTLY against the backend vocabulary. An
//     unknown value never coerces to inherit/fail-open — the profile is
//     surfaced as a DEGRADED entry the UI renders read-only.
//   - InspectHTTP2 is TRI-STATE: absent/null = inherit, true, false. The
//     inherit state is never collapsed into false.
import { ApiError, apiRequest } from "./client";
import {
  DecodeError,
  field,
  isRecord,
  readArray,
  readBoolean,
  readEnum,
  readNumber,
  readOptional,
  readRecord,
  readString,
  type Decoder,
} from "./decode";
import { decodeObjectReferences } from "./policy";
import type { ObjectRefConsumer } from "./policy";
import type { components } from "./types.gen";

// ── Enum lockstep (compile-time, pinned to the generated OpenAPI contract) ──
// The value arrays are checked BOTH ways against the generated union types:
// `satisfies` rejects a value the contract does not know, and the Exhaustive
// assertions reject a contract value the array is missing. The Go-side
// lockstep test additionally probes every value through the runtime
// validator (objects_enum_lockstep_test.go).

type GenProfile = components["schemas"]["DecryptionProfileFull"];

export type CertVerification = NonNullable<GenProfile["certVerification"]>;
export type OnUnsupported = NonNullable<GenProfile["onUnsupported"]>;
export type OnInspectError = NonNullable<GenProfile["onInspectError"]>;
export type TLSVersion = NonNullable<GenProfile["minTlsVersion"]>;

export const CERT_VERIFICATION_VALUES = [
  "",
  "strict",
  "skip",
] as const satisfies readonly CertVerification[];
export const ON_UNSUPPORTED_VALUES = [
  "",
  "fail-close",
  "fail-open",
] as const satisfies readonly OnUnsupported[];
export const ON_INSPECT_ERROR_VALUES = [
  "",
  "fail-close",
  "fail-open",
] as const satisfies readonly OnInspectError[];
export const TLS_VERSION_VALUES = [
  "",
  "1.2",
  "1.3",
] as const satisfies readonly TLSVersion[];

type Exhaustive<Union extends string, Arr extends readonly string[]> = [
  Exclude<Union, Arr[number]>,
] extends [never]
  ? true
  : never;
// Compile-time exhaustiveness: these lines fail to typecheck if the OpenAPI
// contract gains an enum value the arrays above do not carry.
const certExhaustive: Exhaustive<
  CertVerification,
  typeof CERT_VERIFICATION_VALUES
> = true;
const onUnsupportedExhaustive: Exhaustive<
  OnUnsupported,
  typeof ON_UNSUPPORTED_VALUES
> = true;
const onInspectErrorExhaustive: Exhaustive<
  OnInspectError,
  typeof ON_INSPECT_ERROR_VALUES
> = true;
const tlsExhaustive: Exhaustive<TLSVersion, typeof TLS_VERSION_VALUES> = true;
void certExhaustive;
void onUnsupportedExhaustive;
void onInspectErrorExhaustive;
void tlsExhaustive;

// Backend stall-timeout bounds (decryptprofile.MinStallSecs/MaxStallSecs);
// 0 = inherit the engine default. Pinned by the Go lockstep test.
export const STALL_TIMEOUT_MIN_SECS = 5;
export const STALL_TIMEOUT_MAX_SECS = 3600;

// ── Category Groups ─────────────────────────────────────────────────────────

export interface CategoryGroupView {
  id: string;
  name: string;
  categories: readonly string[];
  createdAt: string;
  updatedAt: string;
}

export interface CategoryGroupList {
  groups: readonly CategoryGroupView[];
  /** Durable per-store mutation generation — the ifVersion fence token. */
  version: number;
}

const optStr = readOptional(readString);

const decodeCategoryGroup: Decoder<CategoryGroupView> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    id: field(o, "id", readString, path),
    name: field(o, "name", readString, path),
    categories:
      o["categories"] === undefined || o["categories"] === null
        ? []
        : field(o, "categories", readArray(readString), path),
    createdAt: field(o, "created_at", optStr, path) ?? "",
    updatedAt: field(o, "updated_at", optStr, path) ?? "",
  };
};

export const decodeCategoryGroupList: Decoder<CategoryGroupList> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = o["groups"];
  const groups =
    raw === undefined || raw === null
      ? []
      : field(o, "groups", readArray(decodeCategoryGroup), path);
  return { groups, version: field(o, "version", readNumber, path) };
};

export function getCategoryGroups(
  signal?: AbortSignal,
): Promise<CategoryGroupList> {
  return apiRequest(
    "/api/category-groups",
    decodeCategoryGroupList,
    signal !== undefined ? { signal } : {},
  );
}

// ── Decryption Profiles ─────────────────────────────────────────────────────

export interface DecryptionProfileView {
  id: string;
  name: string;
  /** TRI-STATE: null = inherit (strip → HTTP/1.1 today), true = native HTTP/2
   * inspection, false = force strip. Never collapse null into false. */
  inspectHttp2: boolean | null;
  certVerification: CertVerification;
  onUnsupported: OnUnsupported;
  onInspectError: OnInspectError;
  minTlsVersion: TLSVersion;
  maxTlsVersion: TLSVersion;
  /** 0 = inherit the engine default; else seconds in the backend bounds. */
  stallTimeoutSecs: number;
  createdAt: string;
  updatedAt: string;
}

/** A profile whose payload violates the security-enum contract. Rendered as a
 * read-only degraded row — its raw values are never coerced (in particular
 * never into inherit or fail-open) and it can not be edited from the v2 UI. */
export interface DegradedProfile {
  id: string;
  name: string;
  reason: string;
}

export interface DecryptionProfileList {
  profiles: readonly DecryptionProfileView[];
  degraded: readonly DegradedProfile[];
  /** Durable per-store mutation generation — the ifVersion fence token. */
  version: number;
}

const readCert = readEnum(CERT_VERIFICATION_VALUES);
const readOnUnsupported = readEnum(ON_UNSUPPORTED_VALUES);
const readOnInspectError = readEnum(ON_INSPECT_ERROR_VALUES);
const readTLS = readEnum(TLS_VERSION_VALUES);

const decodeProfile: Decoder<DecryptionProfileView> = (v, path = "$") => {
  const o = readRecord(v, path);
  const rawH2 = o["inspectHttp2"];
  return {
    id: field(o, "id", readString, path),
    name: field(o, "name", readString, path),
    inspectHttp2:
      rawH2 === undefined || rawH2 === null
        ? null
        : readBoolean(rawH2, `${path}.inspectHttp2`),
    certVerification:
      o["certVerification"] === undefined
        ? ""
        : field(o, "certVerification", readCert, path),
    onUnsupported:
      o["onUnsupported"] === undefined
        ? ""
        : field(o, "onUnsupported", readOnUnsupported, path),
    onInspectError:
      o["onInspectError"] === undefined
        ? ""
        : field(o, "onInspectError", readOnInspectError, path),
    minTlsVersion:
      o["minTlsVersion"] === undefined
        ? ""
        : field(o, "minTlsVersion", readTLS, path),
    maxTlsVersion:
      o["maxTlsVersion"] === undefined
        ? ""
        : field(o, "maxTlsVersion", readTLS, path),
    stallTimeoutSecs:
      o["stallTimeoutSecs"] === undefined
        ? 0
        : field(o, "stallTimeoutSecs", readNumber, path),
    createdAt: field(o, "created_at", optStr, path) ?? "",
    updatedAt: field(o, "updated_at", optStr, path) ?? "",
  };
};

export const decodeProfileList: Decoder<DecryptionProfileList> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = o["profiles"];
  const items =
    raw === undefined || raw === null
      ? []
      : readArray((x) => x)(raw, `${path}.profiles`);
  const profiles: DecryptionProfileView[] = [];
  const degraded: DegradedProfile[] = [];
  items.forEach((item, i) => {
    const p = `${path}.profiles[${String(i)}]`;
    try {
      profiles.push(decodeProfile(item, p));
    } catch (e) {
      if (!(e instanceof DecodeError)) throw e;
      // Controlled degraded state (§25): keep best-effort identity for the
      // read-only degraded row; never coerce the violating value.
      let id = "";
      let name = "";
      if (isRecord(item)) {
        if (typeof item["id"] === "string") id = item["id"];
        if (typeof item["name"] === "string") name = item["name"];
      }
      degraded.push({ id, name, reason: e.message });
    }
  });
  return { profiles, degraded, version: field(o, "version", readNumber, path) };
};

export function getDecryptionProfiles(
  signal?: AbortSignal,
): Promise<DecryptionProfileList> {
  return apiRequest(
    "/api/decryption-profiles",
    decodeProfileList,
    signal !== undefined ? { signal } : {},
  );
}

// ── Structured 409s ─────────────────────────────────────────────────────────
// Version-fence conflicts reuse the policy contract ({error, currentVersion,
// yourVersion}) — recognize them with policyWrite's asPolicyConflict. The
// reference-block 409 (delete refused while referenced) carries the SAME
// referencedBy shape as GET /api/objects/references plus the error summary.

export interface ReferenceBlock {
  error: string;
  object: { type: string; name: string };
  referencedBy: readonly ObjectRefConsumer[];
}

/** Recognizes the reference-block 409. Returns null for anything else — a 409
 * whose body is not the structured shape stays a generic ApiError. */
export function asReferenceBlock(err: unknown): ReferenceBlock | null {
  if (!(err instanceof ApiError)) return null;
  if (err.status !== 409 || err.bodyText === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  try {
    const o = readRecord(parsed, "$");
    const refs = decodeObjectReferences(parsed, "$");
    return {
      error: field(o, "error", readString, "$"),
      object: refs.object,
      referencedBy: refs.referencedBy,
    };
  } catch (e) {
    if (e instanceof DecodeError) return null;
    throw e;
  }
}

// ── Mutations (all fenced; confirmed 2xx = restart-durable) ─────────────────

function fenced(path: string, ifVersion: number): string {
  return `${path}${path.includes("?") ? "&" : "?"}ifVersion=${String(ifVersion)}`;
}

const decodeMutationOk: Decoder<void> = (v, path = "$") => {
  const o = readRecord(v, path);
  field(o, "ok", readBoolean, path);
};

export interface CategoryGroupWrite {
  name: string;
  categories: readonly string[];
}

export function createCategoryGroup(
  write: CategoryGroupWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced("/api/category-groups", ifVersion),
    decodeMutationOk,
    {
      method: "POST",
      body: { name: write.name, categories: write.categories },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

/** Update (and, when `write.name` differs from the stored name, RENAME) the
 * group with the given stable ID. The server preserves the ID and cascades the
 * denormalized name onto referencing rules (running + draft candidate). */
export function updateCategoryGroup(
  id: string,
  write: CategoryGroupWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced(`/api/category-groups?id=${encodeURIComponent(id)}`, ifVersion),
    decodeMutationOk,
    {
      method: "PUT",
      body: { name: write.name, categories: write.categories },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export function deleteCategoryGroup(
  id: string,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced(`/api/category-groups?id=${encodeURIComponent(id)}`, ifVersion),
    decodeMutationOk,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

export interface DecryptionProfileWrite {
  name: string;
  inspectHttp2: boolean | null;
  certVerification: CertVerification;
  onUnsupported: OnUnsupported;
  onInspectError: OnInspectError;
  minTlsVersion: TLSVersion;
  maxTlsVersion: TLSVersion;
  stallTimeoutSecs: number;
}

function serializeProfileWrite(
  w: DecryptionProfileWrite,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: w.name,
    certVerification: w.certVerification,
    onUnsupported: w.onUnsupported,
    onInspectError: w.onInspectError,
    minTlsVersion: w.minTlsVersion,
    maxTlsVersion: w.maxTlsVersion,
    stallTimeoutSecs: w.stallTimeoutSecs,
  };
  // Tri-state fidelity: inherit (null) is expressed by OMITTING the key —
  // never by sending false.
  if (w.inspectHttp2 !== null) out["inspectHttp2"] = w.inspectHttp2;
  return out;
}

export function createDecryptionProfile(
  write: DecryptionProfileWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced("/api/decryption-profiles", ifVersion),
    decodeMutationOk,
    {
      method: "POST",
      body: serializeProfileWrite(write),
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

/** Update (and, when `write.name` differs, RENAME) the profile with the given
 * stable ID. The ID — and therefore the adaptive-decryption exclusion scope
 * and security generation — is preserved; the server cascades the denormalized
 * name onto referencing rules (running + draft candidate). */
export function updateDecryptionProfile(
  id: string,
  write: DecryptionProfileWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced(`/api/decryption-profiles?id=${encodeURIComponent(id)}`, ifVersion),
    decodeMutationOk,
    {
      method: "PUT",
      body: serializeProfileWrite(write),
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export function deleteDecryptionProfile(
  id: string,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced(`/api/decryption-profiles?id=${encodeURIComponent(id)}`, ifVersion),
    decodeMutationOk,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}
