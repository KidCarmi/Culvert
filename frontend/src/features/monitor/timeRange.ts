// FE-4 Monitor time model (§4): a time range is mandatory — the UI never
// issues an unbounded historical query. Presets are resolved to concrete
// [from, to] seconds at APPLY/REFRESH time; a custom range must satisfy
// from < to.

export const TIME_PRESETS = ["15m", "1h", "6h", "24h", "custom"] as const;
export type TimePreset = (typeof TIME_PRESETS)[number];

export const DEFAULT_PRESET: TimePreset = "1h";

const presetSeconds: Record<Exclude<TimePreset, "custom">, number> = {
  "15m": 15 * 60,
  "1h": 60 * 60,
  "6h": 6 * 60 * 60,
  "24h": 24 * 60 * 60,
};

export interface ResolvedWindow {
  fromSec: number;
  toSec: number;
}

/** Resolve a preset (relative to now) or a custom range into an explicit
 * window. Returns an error string for an invalid custom range. */
export function resolveWindow(
  preset: TimePreset,
  customFrom: string, // datetime-local value
  customTo: string,
  nowMs: number,
): ResolvedWindow | string {
  if (preset !== "custom") {
    const to = Math.floor(nowMs / 1000);
    return { fromSec: to - presetSeconds[preset], toSec: to };
  }
  if (customFrom === "" || customTo === "") {
    return "Custom range requires both a start and an end time.";
  }
  const from = Date.parse(customFrom);
  const to = Date.parse(customTo);
  if (Number.isNaN(from) || Number.isNaN(to)) {
    return "Custom range times could not be parsed.";
  }
  if (from >= to) {
    return "The start of the range must be before its end.";
  }
  return { fromSec: Math.floor(from / 1000), toSec: Math.floor(to / 1000) };
}

export function isTimePreset(v: string): v is TimePreset {
  return TIME_PRESETS.some((p) => p === v);
}
