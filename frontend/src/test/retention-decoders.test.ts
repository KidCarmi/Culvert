// 2A-M §20: RetentionView runtime decoder matrix. Fixtures mirror
// logStoreRetentionView (logstore.go) exactly — the SAME decoder serves GET,
// the PUT mutation response, and the purge response.
import { describe, expect, it } from "vitest";
import { decodeRetentionView } from "../api/retention";
import { DecodeError } from "../api/decode";

const guardFull = {
  criticalDiskPct: 95,
  minimalMode: false,
  loggingMode: "Normal",
  lastCleanupMs: 1_755_800_000_000,
  lastCleanupReason: "size cap",
  pressureBytes: 0,
  pressureCount: 0,
  warning: "",
  diskUsedPct: 71.5,
  diskFreeBytes: 19_540_414_464,
  diskTotalBytes: 270_553_174_016,
};

const guardNoDisk = {
  criticalDiskPct: 90,
  minimalMode: true,
  loggingMode: "Minimal",
  lastCleanupMs: 0,
  lastCleanupReason: "",
  pressureBytes: 1024,
  pressureCount: 3,
  warning: "disk almost full",
};

const estimate = {
  avgEntryBytes: 350,
  reqPerMin: 12.5,
  bytesPerDay: 6_300_000,
  bytesPerWeek: 44_100_000,
  bytesPerMonth: 189_000_000,
};

const enabledFixture = {
  enabled: true,
  configurable: true,
  retentionDays: 30,
  retentionMaxGB: 2.5,
  encrypted: true,
  encryptionAvailable: true,
  usage: {
    enabled: true,
    bytes: 123_456,
    dropped: 0,
    pruned: 7,
    count: 5000,
    capped: false,
    oldestMs: 1_755_700_000_000,
  },
  estimate,
  guard: guardFull,
};

const disabledFixture = {
  enabled: false,
  configurable: true,
  retentionDays: 14,
  retentionMaxGB: 1,
  encrypted: false,
  encryptionAvailable: false,
  usage: { enabled: false }, // logStoreHealth: the ONLY key when off
  estimate,
  guard: guardNoDisk,
};

describe("retention view decoder (§20)", () => {
  it("decodes an enabled store with full usage", () => {
    const v = decodeRetentionView(enabledFixture);
    expect(v.enabled).toBe(true);
    expect(v.encrypted).toBe(true);
    expect(v.usage.bytes).toBe(123_456);
    expect(v.usage.count).toBe(5000);
    expect(v.usage.capped).toBe(false);
    expect(v.guard.diskUsedPct).toBeCloseTo(71.5);
  });

  it("decodes a disabled-but-configurable store with minimal usage — absent stats stay undefined, never zero", () => {
    const v = decodeRetentionView(disabledFixture);
    expect(v.enabled).toBe(false);
    expect(v.configurable).toBe(true);
    expect(v.usage.enabled).toBe(false);
    expect(v.usage.bytes).toBeUndefined();
    expect(v.usage.count).toBeUndefined();
    expect(v.usage.oldestMs).toBeUndefined();
  });

  it("decodes a disabled non-configurable store", () => {
    const v = decodeRetentionView({ ...disabledFixture, configurable: false });
    expect(v.configurable).toBe(false);
  });

  it("decodes encryption posture combinations", () => {
    expect(
      decodeRetentionView({ ...enabledFixture, encrypted: false }).encrypted,
    ).toBe(false);
    expect(
      decodeRetentionView({ ...enabledFixture, encryptionAvailable: false })
        .encryptionAvailable,
    ).toBe(false);
  });

  it("decodes a capped (approximate) count", () => {
    const v = decodeRetentionView({
      ...enabledFixture,
      usage: { ...enabledFixture.usage, capped: true },
    });
    expect(v.usage.capped).toBe(true);
  });

  it("guard optional disk fields absent decode as undefined", () => {
    const v = decodeRetentionView(disabledFixture);
    expect(v.guard.diskUsedPct).toBeUndefined();
    expect(v.guard.diskFreeBytes).toBeUndefined();
    expect(v.guard.diskTotalBytes).toBeUndefined();
    expect(v.guard.minimalMode).toBe(true);
    expect(v.guard.warning).toBe("disk almost full");
  });

  it("fails closed on a wrong required type", () => {
    expect(() =>
      decodeRetentionView({ ...enabledFixture, enabled: "yes" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeRetentionView({ ...enabledFixture, retentionDays: "30" }),
    ).toThrow(DecodeError);
  });

  it("fails closed on malformed nested usage", () => {
    expect(() =>
      decodeRetentionView({
        ...enabledFixture,
        usage: { enabled: true, bytes: "many" },
      }),
    ).toThrow(DecodeError);
    expect(() => decodeRetentionView({ ...enabledFixture, usage: 7 })).toThrow(
      DecodeError,
    );
  });

  it("fails closed on a malformed estimate", () => {
    expect(() =>
      decodeRetentionView({
        ...enabledFixture,
        estimate: { ...estimate, bytesPerDay: undefined },
      }),
    ).toThrow(DecodeError);
  });

  it("fails closed on a malformed guard", () => {
    expect(() =>
      decodeRetentionView({
        ...enabledFixture,
        guard: { ...guardFull, criticalDiskPct: "95" },
      }),
    ).toThrow(DecodeError);
  });

  it("rejects bare/incomplete payloads", () => {
    expect(() => decodeRetentionView({})).toThrow(DecodeError);
    expect(() => decodeRetentionView({ enabled: true })).toThrow(DecodeError);
    expect(() => decodeRetentionView(null)).toThrow(DecodeError);
  });
});
