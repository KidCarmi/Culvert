#!/usr/bin/env python3
"""
Independent Expected-Behavior Oracle for the Culvert Edge-Case Validation Lab.

DESIGN CONTRACT (role isolation):
  * The Oracle consumes ONLY the abstract, product-neutral `intent` model of a
    scenario plus a `vector` (the traffic to send). It NEVER imports Culvert code,
    NEVER reads a live Culvert response, and NEVER sees the Operator's Culvert-
    specific translation. It derives the expected outcome from first principles:
    general enterprise-SWG semantics (first-match rule evaluation, default-deny,
    glob/subnet/schedule matching, TLS-inspection precedence, fail-closed
    asymmetries) that a mature SWG (PAN-OS / Zscaler / Netskope class) implements,
    cross-checked against Culvert's DOCUMENTED contract.
  * Because the Operator translates the SAME intent into Culvert config through a
    completely separate code path, comparing Oracle-expected vs Culvert-actual is
    a genuine differential test: agreement => PASS, divergence => a candidate
    finding to be triaged (product bug / missing capability / contract gap / etc).

The Oracle returns an `Expectation` describing what a correct SWG MUST do for the
vector, with an explicit `certainty` and human-readable `rationale` so the Failure
Reviewer can distinguish deterministic expectations from genuinely-uncertain ones
(the campaign never files a PRODUCT_BUG on an uncertain expectation).
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# ---- Expected outcome vocabulary -------------------------------------------
# Product-neutral disposition of a request at the proxy.
# Culvert ships a global default file-extension blocklist (fileBlockExtensions) that
# blocks these executable/script types on any inspected download regardless of profile.
# A mature SWG blocks executables by default too. Encoded here so the Oracle matches
# Culvert's documented contract for file-type control.
GLOBAL_BLOCKED_EXTS = {".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com", ".exe", ".msi", ".pif"}

ALLOW = "allow"            # request reaches origin; client gets origin response
BLOCK_PAGE = "block_page"  # proxy serves a block page (HTTP error + explanatory body)
DROP = "drop"             # connection dropped/reset, no HTTP response
REDIRECT = "redirect"      # proxy 3xx-redirects the client
AUTH_CHALLENGE = "auth_challenge"  # proxy demands authentication (407 / portal 302)
TLS_INTERCEPTED = "tls_intercepted"  # (sub-flag) the TLS session is MITM'd by the proxy
TLS_PASSTHROUGH = "tls_passthrough"  # (sub-flag) TLS tunnelled opaquely (bypass)
CONN_FAIL = "conn_fail"    # handshake/connection fails (e.g. inspect w/ untrusted upstream, fail-close)


@dataclass
class Expectation:
    disposition: str                      # one of the vocabulary constants above
    tls: Optional[str] = None             # TLS_INTERCEPTED | TLS_PASSTHROUGH | None (plain http)
    matched_rule: Optional[str] = None    # name of the rule the oracle expects to win, or None
    http_status_family: Optional[str] = None  # "2xx" | "3xx" | "403" | "407" | "conn_fail"
    certainty: str = "deterministic"      # "deterministic" | "uncertain"
    rationale: str = ""
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "disposition": self.disposition,
            "tls": self.tls,
            "matched_rule": self.matched_rule,
            "http_status_family": self.http_status_family,
            "certainty": self.certainty,
            "rationale": self.rationale,
            "notes": self.notes,
        }


# ---- Matching primitives (general SWG semantics) ---------------------------

def _norm_host(h: str) -> str:
    return (h or "").strip().rstrip(".").lower().split(":")[0]


def match_fqdn(pattern: str, host: str) -> bool:
    """PAN-OS/Culvert-style FQDN matching:
      "*"            -> any
      "*.example.com"-> host endswith ".example.com" OR host == "example.com"
      "example.com"  -> host == "example.com" OR host endswith ".example.com" (bare implies subdomains)
      exact-with-dot handled by the two rules above.
    """
    if not pattern:
        return True
    pattern = pattern.strip().rstrip(".").lower()
    host = _norm_host(host)
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        base = pattern[2:]
        return host == base or host.endswith(suffix)
    # bare domain: exact or subdomain
    return host == pattern or host.endswith("." + pattern)


def match_ip(cidr: Optional[str], client_ip: str) -> bool:
    if not cidr:
        return True
    try:
        if "/" in cidr:
            return ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(client_ip) == ipaddress.ip_address(cidr)
    except ValueError:
        return False


def match_schedule(sched: Optional[dict], when: Optional[str]) -> bool:
    """days: ["Mon",...]; start/end "HH:MM"; tz IANA (default UTC).
    Overnight window supported (start>end). when is RFC3339; None => 'now' (caller
    should pass an explicit time for deterministic scenarios)."""
    if not sched:
        return True
    if when is None:
        # Non-deterministic without an explicit time; treat as uncertain-match handled upstream.
        return True
    dt = _parse_when(sched.get("tz"), when)
    days = [d[:3].lower() for d in (sched.get("days") or [])]
    if days and dt.strftime("%a").lower() not in days:
        return False
    start = sched.get("start") or sched.get("timeStart") or ""
    end = sched.get("end") or sched.get("timeEnd") or ""
    if not start or not end:
        return True
    cur = dt.strftime("%H:%M")
    if start <= end:
        return start <= cur < end
    # overnight
    return cur >= start or cur < end


def _parse_when(tzname: Optional[str], when: str) -> datetime:
    dt = datetime.fromisoformat(when.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if tzname:
        try:
            from zoneinfo import ZoneInfo
            dt = dt.astimezone(ZoneInfo(tzname))
        except Exception:
            dt = dt.astimezone(timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _host_category(intent: dict, host: str) -> Optional[str]:
    host = _norm_host(host)
    for cat, hosts in (intent.get("objects", {}).get("categories") or {}).items():
        for h in hosts:
            h = _norm_host(h)
            if host == h or host.endswith("." + h):
                return cat
    return None


def _host_in_group(intent: dict, host: str, group: str) -> bool:
    cat = _host_category(intent, host)
    if cat is None:
        return False  # fail-closed: uncategorised host never matches a category group
    members = (intent.get("objects", {}).get("category_groups") or {}).get(group)
    if members is None:
        return False
    return cat in members


# ---- Rule matching ----------------------------------------------------------

def _rule_matches(intent: dict, rule: dict, vec: dict) -> tuple[bool, bool]:
    """Return (matches, uncertain). uncertain=True when the match hinges on a
    dimension the lab cannot deterministically control for this vector."""
    if rule.get("enabled") is False:
        return (False, False)
    m = rule.get("match", {})
    uncertain = False

    if not match_ip(m.get("src_ip"), vec.get("client_ip", "127.0.0.1")):
        return (False, False)
    if m.get("identity") and (vec.get("identity") or "").lower() != m["identity"].lower():
        return (False, False)
    if m.get("group"):
        groups = [g.lower() for g in (vec.get("groups") or [])]
        if m["group"].lower() not in groups:
            return (False, False)
    if m.get("auth_source") and (vec.get("auth_source") or "").lower() != m["auth_source"].lower():
        return (False, False)
    if m.get("fqdn") is not None and not match_fqdn(m["fqdn"], vec["host"]):
        return (False, False)
    if m.get("category") is not None:
        cat = _host_category(intent, vec["host"])
        if cat is None or cat.lower() != m["category"].lower():
            return (False, False)
    if m.get("category_group") is not None:
        if not _host_in_group(intent, vec["host"], m["category_group"]):
            return (False, False)
    if m.get("country") is not None:
        # GeoIP: Culvert is cache-only fail-closed. The lab cannot populate the
        # GeoIP cache for TEST-NET fixtures, so country rules are structurally
        # uncertain at execution time; oracle flags them.
        vc = (vec.get("country") or "").upper()
        if not vc or vc not in [c.upper() for c in m["country"]]:
            return (False, False)
        uncertain = True
    if m.get("schedule") is not None:
        if vec.get("when") is None:
            uncertain = True
        if not match_schedule(m["schedule"], vec.get("when")):
            return (False, False)
    return (True, uncertain)


# ---- The oracle -------------------------------------------------------------

def evaluate(intent: dict, vec: dict) -> Expectation:
    """Compute the expected SWG disposition for `vec` under `intent`."""
    scheme = vec.get("scheme", "http")
    is_connect = scheme == "https"

    # Stage 1: authentication gate (only the no-rule/no-credential default is modelled;
    # the lab drives auth scenarios with explicit credentials/identity in the vector).
    default_auth = intent.get("default_auth", "Default")
    has_creds = bool(vec.get("identity")) or bool(vec.get("proxy_auth"))
    auth_backend = intent.get("auth_backend", False)  # a credential/SSO backend exists
    if not has_creds and (auth_backend or default_auth == "Exempt"):
        if default_auth == "Default" and auth_backend:
            return Expectation(
                disposition=AUTH_CHALLENGE, http_status_family="407",
                rationale="Auth backend configured and default-auth=Default: unauthenticated "
                          "request must be challenged (407 Proxy-Authenticate) before policy.",
            )
        # Exempt => fall through to Stage-2 (open != allow; default-deny still applies).

    # Stage 2: first-match access rule evaluation, priority ascending.
    rules = sorted(intent.get("rules", []), key=lambda r: r.get("priority", 1000))
    winner = None
    winner_uncertain = False
    for r in rules:
        if r.get("kind", "access") != "access":
            continue
        ok, unc = _rule_matches(intent, r, vec)
        if ok:
            winner = r
            winner_uncertain = unc
            break

    if winner is None:
        default_action = intent.get("default_action", "allow")
        if default_action == "deny":
            return Expectation(
                disposition=BLOCK_PAGE, http_status_family="403", matched_rule=None,
                rationale="No access rule matched and Stage-2 default is deny (Zero Trust): "
                          "proxy serves POLICY_DEFAULT_DENY block page.",
            )
        return Expectation(
            disposition=ALLOW, http_status_family="2xx", matched_rule=None,
            tls=(TLS_PASSTHROUGH if is_connect else None),
            rationale="No access rule matched and Stage-2 default is allow: passthrough.",
        )

    # Pre-policy hard blocks (blocklist / threat feed) override even an allow match.
    blocklist = [_norm_host(h) for h in (intent.get("objects", {}).get("blocklist") or [])]
    host = _norm_host(vec["host"])
    if any(host == b or host.endswith("." + b) for b in blocklist):
        return Expectation(
            disposition=BLOCK_PAGE, http_status_family="403", matched_rule=winner.get("name"),
            rationale="Destination is on the blocklist/threat feed; pre-policy gate blocks "
                      "regardless of a matching allow rule.",
        )

    action = winner.get("action", "allow")
    cert = "uncertain" if winner_uncertain else "deterministic"

    if action == "block_page":
        return Expectation(BLOCK_PAGE, matched_rule=winner["name"], http_status_family="403",
                           certainty=cert, rationale=f"Rule '{winner['name']}' action=Block_Page.")
    if action == "drop":
        return Expectation(DROP, matched_rule=winner["name"], http_status_family="conn_fail",
                           certainty=cert, rationale=f"Rule '{winner['name']}' action=Drop (silent RST).")
    if action == "redirect":
        return Expectation(REDIRECT, matched_rule=winner["name"], http_status_family="3xx",
                           certainty=cert, rationale=f"Rule '{winner['name']}' action=Redirect.")

    # action == allow: determine TLS disposition for CONNECT and file-profile blocks.
    exp = Expectation(ALLOW, matched_rule=winner["name"], http_status_family="2xx",
                      certainty=cert, rationale=f"Rule '{winner['name']}' action=Allow.")
    if is_connect:
        exp.tls = _tls_disposition(intent, winner, vec, exp)
    # File-type enforcement on an allowed, INSPECTED download may still block.
    dl = vec.get("download_ext")
    if dl and winner.get("ssl") == "inspect":
        ext = "." + dl.lstrip(".").lower()
        fp = winner.get("file_profile")
        prof_exts = [e.lower() for e in intent.get("objects", {}).get("file_profiles", {}).get(fp or "", [])]
        if ext in GLOBAL_BLOCKED_EXTS or ext in prof_exts:
            return Expectation(BLOCK_PAGE, matched_rule=winner["name"], http_status_family="403",
                               certainty=cert,
                               rationale=f"Rule '{winner['name']}' allows but the download '{ext}' is blocked "
                                         f"({'global executable blocklist' if ext in GLOBAL_BLOCKED_EXTS else 'file profile ' + str(fp)}).")
    return exp


def _tls_disposition(intent: dict, rule: dict, vec: dict, exp: Expectation) -> str:
    """Resolve inspect vs bypass with SWG precedence:
       explicit operator ssl-bypass > learned auto-exclusion > policy inspect."""
    ssl = rule.get("ssl")
    if ssl != "inspect":
        return TLS_PASSTHROUGH
    # explicit ssl-bypass override
    host = _norm_host(vec["host"])
    for pat in (intent.get("objects", {}).get("ssl_bypass") or []):
        if match_fqdn(pat, host):
            exp.notes.append("ssl-bypass override forces passthrough despite inspect rule")
            return TLS_PASSTHROUGH
    # inspect active. If upstream cert is untrusted and the rule does NOT skip verify
    # and the profile is not permissive/skip => inspect leg fails => connection fails.
    upstream_untrusted = vec.get("upstream_cert") == "untrusted"
    prof = (intent.get("objects", {}).get("decryption_profiles") or {}).get(rule.get("decryption_profile") or "", {})
    # Profiles are stored as {"api": {"certVerification": "skip"|"permissive"|"strict", ...}}
    prof_verify = (prof.get("api", {}) or {}).get("certVerification") or prof.get("cert_verification")
    verify_relaxed = rule.get("tls_skip_verify") or prof_verify in ("skip", "permissive")
    if upstream_untrusted and not verify_relaxed:
        exp.disposition = CONN_FAIL
        exp.http_status_family = "conn_fail"
        exp.rationale += " Upstream cert untrusted and verification strict => inspect leg fails (fail-closed)."
        return TLS_INTERCEPTED
    return TLS_INTERCEPTED


# Self-test when run directly.
if __name__ == "__main__":
    intent = {
        "default_action": "deny",
        "objects": {"categories": {"social": ["social.example.test"]},
                     "category_groups": {"blocked": ["social"]}},
        "rules": [
            {"name": "allow-app", "priority": 1, "kind": "access",
             "match": {"fqdn": "app.corp.local"}, "action": "allow"},
            {"name": "block-social-grp", "priority": 2, "kind": "access",
             "match": {"category_group": "blocked"}, "action": "block_page"},
        ],
    }
    for v in [
        {"scheme": "http", "host": "app.corp.local", "client_ip": "127.0.0.1"},
        {"scheme": "http", "host": "social.example.test", "client_ip": "127.0.0.1"},
        {"scheme": "http", "host": "unknown.corp.local", "client_ip": "127.0.0.1"},
    ]:
        e = evaluate(intent, v)
        print(v["host"], "->", e.disposition, "| rule=", e.matched_rule, "|", e.rationale)
