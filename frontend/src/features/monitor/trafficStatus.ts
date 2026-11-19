// Request-log status presentation for the Traffic console. The statuses are
// the ones the proxy already stamps on a request-log row (proxy.go,
// proxy_http.go, proxy_tunnel.go, cdr_proxy.go, decryption_metrics.go); this
// table only EXPLAINS an outcome that was already decided — it never feeds
// back into enforcement. A status that is not listed here stays neutral with
// no stated meaning: an unknown outcome is never labelled as a known cause.
import type { Status } from "../../design-system/primitives";

interface TrafficStatusInfo {
  readonly tone: Status;
  /** One-line, cause-level meaning shown in the row detail ("" = none). */
  readonly meaning: string;
}

const TRAFFIC_STATUS: Readonly<Record<string, TrafficStatusInfo>> = {
  OK: { tone: "ok", meaning: "" },
  BLOCKED: { tone: "critical", meaning: "" },
  POLICY_BLOCK: { tone: "critical", meaning: "" },
  POLICY_DEFAULT_DENY: { tone: "critical", meaning: "" },
  AUTH_FAIL: { tone: "warn", meaning: "" },
  RATE_LIMITED: { tone: "warn", meaning: "" },
  IP_BLOCKED: { tone: "critical", meaning: "" },
  POLICY_DROP: {
    tone: "critical",
    meaning: "A policy rule with a Drop action matched; see the Rule column.",
  },
  THREAT_BLOCKED: {
    tone: "critical",
    meaning:
      "Blocked by the threat-intelligence check; the Rule column names the feed source.",
  },
  FILE_BLOCKED: {
    tone: "critical",
    meaning:
      "Blocked by file-type control (extension, file profile or detected file type).",
  },
  SCAN_BLOCKED: {
    tone: "critical",
    meaning:
      "Blocked by the content scan (antivirus/YARA verdict or scan limits), not by an access rule.",
  },
  POLYGLOT_BLOCKED: {
    tone: "critical",
    meaning:
      "Blocked: the file content matched polyglot (multi-format) detection.",
  },
  DPI_BLOCKED: {
    tone: "critical",
    meaning: "Blocked by a deep-inspection content pattern.",
  },
  CDR_BLOCKED: {
    tone: "critical",
    meaning: "Blocked by content disarm & reconstruction (CDR).",
  },
  CDR_ERROR: {
    tone: "warn",
    meaning:
      "CDR could not process this content and passed it on unmodified (fail-open) to the remaining inspection, which may still have blocked it. This row is not a block; clear the status filter to see a later DPI or antivirus block for the same request.",
  },
  DECRYPT_FAILED: {
    tone: "warn",
    meaning:
      "The TLS decryption handshake failed, so this session was not inspected. See the Decryption failure category.",
  },
};

export function trafficStatusTone(status: string): Status {
  return TRAFFIC_STATUS[status]?.tone ?? "neutral";
}

/** "" when the meaning is self-evident or the status is not known. */
export function trafficStatusMeaning(status: string): string {
  return TRAFFIC_STATUS[status]?.meaning ?? "";
}

/** Statuses offered by the Status filter (exact match on the server). */
export const TRAFFIC_STATUS_FILTERS: readonly string[] = [
  "OK",
  "BLOCKED",
  "POLICY_BLOCK",
  "POLICY_DEFAULT_DENY",
  "POLICY_DROP",
  "AUTH_FAIL",
  "RATE_LIMITED",
  "IP_BLOCKED",
  "THREAT_BLOCKED",
  "FILE_BLOCKED",
  "SCAN_BLOCKED",
  "POLYGLOT_BLOCKED",
  "DPI_BLOCKED",
  "CDR_BLOCKED",
  "CDR_ERROR",
  "DECRYPT_FAILED",
];
