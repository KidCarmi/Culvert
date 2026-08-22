// FE-4 §19: runtime decoders for the operational surfaces fail closed —
// unknown fields are ignored, missing/invalid required fields throw
// DecodeError, enums and schema versions are validated, optional fields
// default explicitly. Null-tolerance for the legacy Go nil-slice encodings
// (`/api/logs` memory mode, `/api/audit`) is proven in the browser suite
// (fe4.spec.ts, history-disabled appliance) where the real backend emits it.
import { describe, expect, it } from "vitest";
import {
  decodeGovernance,
  decodeOperatorContract,
  decodeStats,
  decodeTrafficEntry,
  decodeTrafficPage,
} from "../api/ops";
import { DecodeError } from "../api/decode";
import { resolveWindow, isTimePreset } from "../features/monitor/timeRange";
import { governanceHealthBadgeStatus } from "../features/governance/health";

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

const entry = {
  ts: 1700000000000,
  time: "13:00:00",
  ip: "127.0.0.1",
  method: "GET",
  host: "example.test",
  status: "POLICY_DEFAULT_DENY",
  level: "INFO",
};

describe("decodeTrafficEntry", () => {
  it("defaults optional fields explicitly", () => {
    const e = decodeTrafficEntry(entry);
    expect(e.identity).toBe("");
    expect(e.uri).toBe("");
    expect(e.bytesSent).toBe(0);
    expect(e.durationMs).toBe(0);
    expect(e.dec).toBeNull();
  });

  it("decodes the decryption block when present", () => {
    const e = decodeTrafficEntry({
      ...entry,
      dec: { outcome: "bypassed", decision_source: "rule" },
    });
    expect(e.dec).toEqual({
      outcome: "bypassed",
      decisionSource: "rule",
      failCategory: "",
      profileId: "",
    });
  });

  it("fails closed on a missing required field", () => {
    expect(() => decodeTrafficEntry(omit(entry, "host"))).toThrow(DecodeError);
  });
});

describe("decodeTrafficPage (cursor contract)", () => {
  const page = {
    logs: [entry],
    next_cursor: "abc",
    has_more: true,
    scan_limited: false,
    history: true,
    snapshot_at: "2026-08-22T13:00:00Z",
    limit: 100,
  };

  it("decodes the full page shape", () => {
    const p = decodeTrafficPage(page);
    expect(p.logs).toHaveLength(1);
    expect(p.nextCursor).toBe("abc");
    expect(p.hasMore).toBe(true);
    expect(p.scanLimited).toBe(false);
    expect(p.history).toBe(true);
  });

  it("decodes a scan-limited continuation page", () => {
    const p = decodeTrafficPage({
      ...page,
      logs: [],
      scan_limited: true,
    });
    expect(p.logs).toHaveLength(0);
    expect(p.scanLimited).toBe(true);
    expect(p.hasMore).toBe(true);
    expect(p.nextCursor).toBe("abc");
  });

  it("carries no total — and requires the truth-telling fields", () => {
    expect(() => decodeTrafficPage(omit(page, "history"))).toThrow(DecodeError);
    expect(() => decodeTrafficPage(omit(page, "has_more"))).toThrow(
      DecodeError,
    );
    expect(() => decodeTrafficPage(omit(page, "scan_limited"))).toThrow(
      DecodeError,
    );
  });
});

describe("decodeOperatorContract", () => {
  it("validates the verdict/status enum fail-closed", () => {
    expect(() =>
      decodeOperatorContract({
        verdict: "unknown",
        generated_at: "t",
        checks: [],
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeOperatorContract({
        verdict: "ok",
        generated_at: "t",
        checks: [{ code: "c", status: "maybe", message: "m" }],
      }),
    ).toThrow(DecodeError);
  });

  it("defaults operator_action to empty", () => {
    const c = decodeOperatorContract({
      verdict: "warn",
      generated_at: "t",
      checks: [{ code: "c", status: "warn", message: "m" }],
    });
    expect(c.checks[0]?.operatorAction).toBe("");
  });
});

describe("decodeGovernance", () => {
  it("extracts numeric counters sorted and reads the health block", () => {
    const g = decodeGovernance({
      generated_at: "t",
      routes: { total: 232, public: 18, method_entries: 346 },
      c2: { mode: "enforce", kill_switch_active: false },
      counters: { would_deny: 2, audit_missing: 0, note: "not-a-number" },
      governance_health: { status: "healthy", issues: [] },
    });
    expect(g.counters).toEqual([
      { key: "audit_missing", value: 0 },
      { key: "would_deny", value: 2 },
    ]);
    expect(g.mode).toBe("enforce");
    expect(g.healthStatus).toBe("healthy");
    expect(g.issues).toEqual([]);
  });

  it("maps the backend health vocabulary to badge severities (Codex fix)", () => {
    // The TOP-LEVEL status vocabulary is healthy|warn|drift (ui_governance.go);
    // "ok" exists only per-axis. healthy must render the SUCCESS badge.
    expect(governanceHealthBadgeStatus("healthy")).toBe("ok");
    expect(governanceHealthBadgeStatus("warn")).toBe("warn");
    expect(governanceHealthBadgeStatus("drift")).toBe("critical");
    // Unknown future value degrades visibly, never silently green.
    expect(governanceHealthBadgeStatus("mystery")).toBe("warn");
  });
});

describe("decodeStats", () => {
  it("requires the persistence-truth fields", () => {
    expect(() => decodeStats({ total: 1 })).toThrow(DecodeError);
  });
});

describe("timeRange (§4)", () => {
  it("resolves presets relative to now", () => {
    const w = resolveWindow("1h", "", "", 3_600_000_000);
    expect(w).toEqual({ fromSec: 3_596_400, toSec: 3_600_000 });
  });

  it("requires both custom bounds", () => {
    expect(resolveWindow("custom", "", "2026-08-22T10:00", 0)).toMatch(
      /requires both/,
    );
  });

  it("rejects unparsable and inverted custom ranges", () => {
    expect(resolveWindow("custom", "zzz", "2026-08-22T10:00", 0)).toMatch(
      /could not be parsed/,
    );
    expect(
      resolveWindow("custom", "2026-08-22T10:00", "2026-08-22T09:00", 0),
    ).toMatch(/before its end/);
  });

  it("accepts a valid custom range", () => {
    const w = resolveWindow(
      "custom",
      "2026-08-22T09:00",
      "2026-08-22T10:00",
      0,
    );
    expect(typeof w).toBe("object");
  });

  it("isTimePreset guards without casts", () => {
    expect(isTimePreset("1h")).toBe(true);
    expect(isTimePreset("2h")).toBe(false);
  });
});
