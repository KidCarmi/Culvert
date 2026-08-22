// Runtime decoder foundation (FE-2 §13; FRONTEND-SECURITY-CONTRACT §7).
// Generated OpenAPI types are compile-time only; these small composable
// helpers are how untrusted parsed JSON becomes trusted typed values at the
// API boundary. Deliberately in-repo — no schema library.

export class DecodeError extends Error {
  readonly path: string;

  constructor(path: string, want: string, got: unknown) {
    super(`decode: ${path}: expected ${want}, got ${typeof got}`);
    this.name = "DecodeError";
    this.path = path;
  }
}

export type Decoder<T> = (v: unknown, path?: string) => T;

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function readRecord(v: unknown, path = "$"): Record<string, unknown> {
  if (!isRecord(v)) throw new DecodeError(path, "object", v);
  return v;
}

export function readString(v: unknown, path = "$"): string {
  if (typeof v !== "string") throw new DecodeError(path, "string", v);
  return v;
}

export function readBoolean(v: unknown, path = "$"): boolean {
  if (typeof v !== "boolean") throw new DecodeError(path, "boolean", v);
  return v;
}

export function readNumber(v: unknown, path = "$"): number {
  if (typeof v !== "number" || Number.isNaN(v))
    throw new DecodeError(path, "number", v);
  return v;
}

export function readOptional<T>(
  decode: Decoder<T>,
): (v: unknown, path?: string) => T | undefined {
  return (v, path = "$") =>
    v === undefined || v === null ? undefined : decode(v, path);
}

export function readArray<T>(decode: Decoder<T>): Decoder<readonly T[]> {
  return (v, path = "$") => {
    if (!Array.isArray(v)) throw new DecodeError(path, "array", v);
    return v.map((el, i) => decode(el, `${path}[${String(i)}]`));
  };
}

export function readEnum<T extends string>(allowed: readonly T[]): Decoder<T> {
  return (v, path = "$") => {
    const s = readString(v, path);
    const hit = allowed.find((a) => a === s);
    if (hit === undefined)
      throw new DecodeError(path, `one of ${allowed.join("|")}`, v);
    return hit;
  };
}

/** field: read obj[key] through a decoder with a precise error path. */
export function field<T>(
  obj: Record<string, unknown>,
  key: string,
  decode: Decoder<T>,
  path = "$",
): T {
  return decode(obj[key], `${path}.${key}`);
}
