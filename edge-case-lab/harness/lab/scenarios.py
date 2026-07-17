#!/usr/bin/env python3
"""
Scenario Generator (Manager / Scenario Generator role) for the Culvert
Edge-Case Validation Lab.

Produces enterprise-realistic administrator requirements as machine-readable
scenarios. Each scenario carries:
  - a natural-language administrator requirement + enterprise-validity rationale
  - a comparable mature-SWG capability category (PAN-OS / Zscaler / Netskope class)
  - an abstract, product-neutral `intent` (consumed by BOTH the Operator, which
    translates it to Culvert config, AND the Oracle, which independently derives
    expected results — separate code paths => genuine differential test)
  - deterministic `vectors` (positive / negative / boundary) with reproducible
    local fixtures (all traffic on 192.0.2.2 TEST-NET fixture; no public internet)
  - a semantic fingerprint for duplicate prevention
  - capability tags for the coverage matrix

Determinism notes:
  * Schedule scenarios are anchored relative to the campaign's current wall-clock
    (computed at generation time) so the live proxy's real-time evaluation is
    deterministic (active-now vs inactive-now windows).
  * GeoIP/country and IdP-group scenarios are marked with the honest limitation
    that the lab cannot populate those data sources for TEST-NET fixtures.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

# Fixture hosts (all resolve to 192.0.2.2 via /etc/hosts; served by origin_server).
H_APP = "app.corp.local"
H_INTRANET = "intranet.corp.local"
H_MEDIA = "media.corp.local"
H_FILES = "files.corp.local"
H_PARTNER = "partner.corp.local"
H_SOCIAL = "social.example.test"
H_NEWS = "news.example.test"
H_EXAMPLE = "example.test"
H_TENANTB = "tenantb.corp.local"
H_BADSSL = "badssl.corp.local"

SRC_CORP = "192.0.2.2"    # "corporate LAN" subnet 192.0.2.0/24
SRC_OTHER = "127.0.0.1"   # "guest / unmanaged" source


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _v(vid, scheme, host, **kw):
    d = {"id": vid, "scheme": scheme, "host": host, "client_ip": kw.pop("client_ip", SRC_OTHER)}
    d.update(kw)
    return d


class Gen:
    def __init__(self):
        self.n = 0
        self.now = datetime.now(timezone.utc)
        self.seen = {}
        self.out = []
        self.candidates = 0            # total add() calls (candidate scenarios)
        self.rejected_duplicate = 0    # rejected as semantic duplicates

    def _id(self):
        self.n += 1
        return f"SWG-{self.n:04d}"

    def add(self, title, requirement, rationale, product_category, capabilities,
            intent, vectors, fingerprint, requires_auth=False, notes=""):
        self.candidates += 1
        if fingerprint in self.seen:
            self.rejected_duplicate += 1
            return None  # duplicate — reject
        sid = self._id()
        self.seen[fingerprint] = sid
        sc = {
            "id": sid, "title": title, "requirement": requirement,
            "rationale": rationale, "product_category": product_category,
            "capabilities": capabilities, "fingerprint": fingerprint,
            "requires_auth": requires_auth, "notes": notes,
            "intent": intent, "vectors": vectors,
        }
        self.out.append(sc)
        return sc

    # ---- capability families ------------------------------------------------
    def fam_fqdn(self):
        cases = [
            ("exact", H_NEWS, [(H_NEWS, "block"), (H_APP, "allow_default"), ("sub." + H_NEWS, "block_sub")]),
            ("wildcard", "*.corp.local", [(H_INTRANET, "block"), (H_APP, "block"), (H_EXAMPLE, "allow_default")]),
            ("bare_implies_sub", "corp.local", [(H_APP, "block"), (H_INTRANET, "block"), (H_SOCIAL, "allow_default")]),
        ]
        for tag, pat, checks in cases:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": f"block-{tag}", "priority": 10, "kind": "access",
                                 "match": {"fqdn": pat}, "action": "block_page"}]}
            vectors = []
            for i, (h, _) in enumerate(checks):
                vectors.append(_v(f"vec{i}", "http", h))
            self.add(
                f"Block destination FQDN ({tag}: {pat})",
                f"Block all HTTP/HTTPS access to destinations matching '{pat}' with a policy block page; "
                f"everything else follows the default.",
                "FQDN/URL object blocking with wildcard and implicit-subdomain semantics is a core SWG "
                "capability (PAN-OS URL objects, Zscaler URL policy).",
                "URL/Domain object policy", ["url_domain_objects", "http", "https_connect", "rule_first_match"],
                intent, vectors, _fp("fqdn", tag, pat))

    def fam_category(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "objects": {"categories": {"social-media": [H_SOCIAL], "news": [H_NEWS]}},
                  "rules": [{"name": "block-social", "priority": 10, "kind": "access",
                             "match": {"category": "social-media"}, "action": "block_page"}]}
        vectors = [_v("v0", "http", H_SOCIAL), _v("v1", "http", H_NEWS), _v("v2", "http", H_APP)]
        self.add("Block a URL category (social-media)",
                 "Block access to hosts classified as social-media; permit news and everything else.",
                 "URL categorisation is the defining SWG feature; admins write category-based rather than "
                 "host-by-host policy (PAN-OS URL categories, Zscaler/Netskope categories).",
                 "URL category policy", ["url_categories", "http", "rule_first_match"],
                 intent, vectors, _fp("cat", "social"))

    def fam_category_group(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "objects": {"categories": {"social-media": [H_SOCIAL], "news": [H_NEWS], "webmail": [H_EXAMPLE]},
                              "category_groups": {"non-productive": ["social-media", "news"]}},
                  "rules": [{"name": "block-nonproductive", "priority": 10, "kind": "access",
                             "match": {"category_group": "non-productive"}, "action": "block_page"}]}
        vectors = [_v("v0", "http", H_SOCIAL), _v("v1", "http", H_NEWS),
                   _v("v2", "http", H_EXAMPLE), _v("v3", "http", H_APP)]
        self.add("Block a category GROUP (non-productive = social+news)",
                 "Group multiple URL categories into 'non-productive' and block the group in one rule; "
                 "webmail and uncategorised traffic must remain allowed.",
                 "Category groups / custom URL-category bundles reduce rule sprawl and are standard in "
                 "enterprise SWGs (PAN-OS custom URL categories, Zscaler URL super-categories).",
                 "URL category group policy", ["url_categories", "category_groups", "http"],
                 intent, vectors, _fp("catgrp", "nonproductive"))

    def fam_source(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "corp-only-intranet", "priority": 10, "kind": "access",
                             "match": {"src_ip": "192.0.2.0/24", "fqdn": H_INTRANET}, "action": "allow"},
                            {"name": "block-intranet-else", "priority": 20, "kind": "access",
                             "match": {"fqdn": H_INTRANET}, "action": "block_page"}]}
        vectors = [_v("corp", "http", H_INTRANET, client_ip=SRC_CORP),
                   _v("guest", "http", H_INTRANET, client_ip=SRC_OTHER)]
        self.add("Restrict intranet to the corporate subnet",
                 "Permit the corporate LAN (192.0.2.0/24) to reach the intranet host; block all other "
                 "source networks (guest/unmanaged) from it.",
                 "Source-zone / source-IP conditioned policy is fundamental to SWG segmentation "
                 "(PAN-OS source zones, Zscaler location policy).",
                 "Source IP/zone policy", ["source_ip_subnet", "rule_first_match", "http"],
                 intent, vectors, _fp("src", "intranet-corp"))

    def fam_ordering(self):
        # first-match: a permit above a broad block wins; and vice versa.
        intent_a = {"default_action": "deny", "default_auth": "Exempt",
                    "rules": [{"name": "permit-app", "priority": 1, "kind": "access",
                               "match": {"fqdn": H_APP}, "action": "allow"},
                              {"name": "block-corp", "priority": 2, "kind": "access",
                               "match": {"fqdn": "*.corp.local"}, "action": "block_page"}]}
        vectors_a = [_v("app", "http", H_APP), _v("intranet", "http", H_INTRANET)]
        self.add("Rule precedence: specific permit above broad block",
                 "A high-priority permit for the app host sits above a broad block of *.corp.local; the app "
                 "host must be allowed while every other *.corp.local host is blocked (first-match wins).",
                 "First-match rule evaluation with explicit precedence is the SWG policy contract (PAN-OS "
                 "top-down, Zscaler rule order).",
                 "Rule ordering / first-match", ["rule_first_match", "rule_ordering", "default_deny", "http"],
                 intent_a, vectors_a, _fp("order", "permit-above-block"))

        intent_b = {"default_action": "allow", "default_auth": "Exempt",
                    "rules": [{"name": "block-corp", "priority": 1, "kind": "access",
                               "match": {"fqdn": "*.corp.local"}, "action": "block_page"},
                              {"name": "permit-app", "priority": 2, "kind": "access",
                               "match": {"fqdn": H_APP}, "action": "allow"}]}
        vectors_b = [_v("app", "http", H_APP), _v("intranet", "http", H_INTRANET)]
        self.add("Rule precedence: broad block above specific permit (shadowing)",
                 "A broad block of *.corp.local sits ABOVE a permit for the app host; first-match means the "
                 "permit is shadowed and the app host is blocked. Verifies the product does not silently "
                 "reorder or leak the lower permit.",
                 "Shadowed-rule behaviour is a critical correctness property of first-match SWG engines.",
                 "Rule ordering / shadowing", ["rule_first_match", "rule_ordering", "http"],
                 intent_b, vectors_b, _fp("order", "block-above-permit"))

    def fam_default(self):
        intent = {"default_action": "deny", "default_auth": "Exempt",
                  "rules": [{"name": "permit-app", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow"}]}
        vectors = [_v("app", "http", H_APP), _v("other", "http", H_MEDIA), _v("connect", "https", H_MEDIA)]
        self.add("Zero-Trust default deny with an explicit allow-list",
                 "With default-deny enabled, only the explicitly permitted app host is reachable; all other "
                 "destinations (HTTP and HTTPS CONNECT) are denied a block page.",
                 "Default-deny (Zero Trust egress) is the recommended posture for enterprise SWGs.",
                 "Default deny", ["default_deny", "http", "https_connect", "rule_first_match"],
                 intent, vectors, _fp("default", "deny-allowlist"))

    def fam_tls(self):
        # inspect vs bypass
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "inspect-app", "priority": 1, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow", "ssl": "inspect", "tls_skip_verify": True},
                            {"name": "bypass-partner", "priority": 2, "kind": "access",
                             "match": {"fqdn": H_PARTNER}, "action": "allow", "ssl": "bypass"}]}
        vectors = [_v("inspect", "https", H_APP, upstream_cert="untrusted"),
                   _v("bypass", "https", H_PARTNER)]
        self.add("Selective TLS inspection (inspect app, bypass partner)",
                 "Decrypt and inspect TLS to the app host; bypass decryption for the partner host (e.g. "
                 "regulatory/pinned). Verify interception actually occurs for one and not the other.",
                 "Selective TLS decryption with per-destination bypass is a core SWG capability "
                 "(PAN-OS decryption policy, Zscaler SSL inspection with bypass).",
                 "TLS inspection / bypass", ["tls_inspection", "manual_ssl_bypass", "https_connect"],
                 intent, vectors, _fp("tls", "inspect-vs-bypass"))

    def fam_ssl_bypass_override(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "objects": {"ssl_bypass": [H_PARTNER]},
                  "rules": [{"name": "inspect-all-corp", "priority": 1, "kind": "access",
                             "match": {"fqdn": "*.corp.local"}, "action": "allow", "ssl": "inspect", "tls_skip_verify": True}]}
        vectors = [_v("app-inspected", "https", H_APP, upstream_cert="untrusted"),
                   _v("partner-bypassed", "https", H_PARTNER)]
        self.add("Manual SSL-bypass list overrides an inspect rule",
                 "An inspect rule covers *.corp.local, but the partner host is on the manual SSL-bypass "
                 "list; bypass must win (explicit operator bypass > policy inspect).",
                 "Explicit decryption-exclusion lists that override inspect policy are standard "
                 "(PAN-OS decryption exclusions, Zscaler do-not-inspect).",
                 "Manual SSL bypass precedence", ["manual_ssl_bypass", "tls_inspection", "https_connect"],
                 intent, vectors, _fp("sslbypass", "override"))

    def fam_cert_fail(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "inspect-strict", "priority": 1, "kind": "access",
                             "match": {"fqdn": H_BADSSL}, "action": "allow", "ssl": "inspect"}]}
        # inspect with NO tls_skip_verify -> upstream self-signed cert is untrusted -> inspect leg fails
        vectors = [_v("strict", "https", H_BADSSL, upstream_cert="untrusted")]
        self.add("TLS inspection fails closed on an untrusted upstream certificate",
                 "When inspecting, if the upstream server presents an untrusted/self-signed certificate and "
                 "the policy does not relax verification, the session must fail closed (not silently "
                 "downgrade to an unverified passthrough).",
                 "Fail-closed certificate validation during decryption is a security-critical SWG behaviour "
                 "(PAN-OS block-on-untrusted-issuer).",
                 "Certificate validation failure", ["cert_validation", "tls_inspection", "https_connect"],
                 intent, vectors, _fp("cert", "strict-untrusted"))

    def fam_blocklist(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "objects": {"blocklist": [H_NEWS]},
                  "rules": [{"name": "allow-all", "priority": 100, "kind": "access",
                             "match": {"fqdn": "*"}, "action": "allow"}]}
        vectors = [_v("blocked", "http", H_NEWS), _v("clean", "http", H_APP)]
        self.add("Threat-intel/blocklist pre-empts an allow rule",
                 "A host on the manual blocklist/threat feed must be blocked even though a broad allow-all "
                 "rule matches it — the pre-policy reputation gate takes precedence.",
                 "Threat-intelligence enforcement ahead of allow policy is standard SWG behaviour "
                 "(Zscaler advanced threat, PAN-OS EDL).",
                 "Threat intelligence / blocklist", ["threat_intel", "blocklist", "http", "rule_first_match"],
                 intent, vectors, _fp("blocklist", "preempt-allow"))

    def fam_redirect(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "redirect-social", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_SOCIAL}, "action": "redirect",
                             "redirect_url": "http://intranet.corp.local:18091/policy-notice"}]}
        vectors = [_v("redir", "http", H_SOCIAL)]
        self.add("Redirect blocked category to an acceptable-use notice",
                 "Instead of a hard block, redirect users hitting the social host to an internal "
                 "acceptable-use policy page (302).",
                 "Redirect-to-notice / coaching pages are a standard SWG user-experience control "
                 "(Zscaler end-user notification, Netskope coaching).",
                 "Redirect action", ["redirect", "http"],
                 intent, vectors, _fp("redirect", "social-notice"))

    def fam_drop(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "drop-media", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_MEDIA}, "action": "drop"}]}
        vectors = [_v("drop", "http", H_MEDIA)]
        self.add("Silently drop connections to a destination",
                 "Drop (reset) connections to the media host with no HTTP block page — a covert-deny posture "
                 "for specific destinations.",
                 "Silent-drop / reset actions exist alongside block pages in mature SWGs.",
                 "Drop action", ["drop", "http"],
                 intent, vectors, _fp("drop", "media"))

    def fam_disabled_rule(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "block-news-disabled", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_NEWS}, "action": "block_page", "enabled": False}]}
        vectors = [_v("news", "http", H_NEWS)]
        self.add("A disabled rule must not enforce",
                 "A block rule that is administratively disabled must have no effect; traffic follows the "
                 "default (allow).",
                 "Enable/disable toggles on rules are universal; a disabled rule leaking enforcement is a bug.",
                 "Rule lifecycle", ["rule_lifecycle", "http"],
                 intent, vectors, _fp("disabled", "news"))

    def fam_boundary(self):
        # negative/boundary: wildcard must NOT match a sibling public domain
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "block-corp-wild", "priority": 10, "kind": "access",
                             "match": {"fqdn": "*.corp.local"}, "action": "block_page"}]}
        vectors = [_v("in", "http", H_APP), _v("boundary", "http", H_EXAMPLE),
                   _v("connect-in", "https", H_INTRANET)]
        self.add("Wildcard scope boundary (no over-matching of sibling domains)",
                 "A *.corp.local block must cover corp.local subdomains only and must NOT block the "
                 "unrelated example.test domain (boundary/negative test against over-broad matching).",
                 "Correct wildcard scoping (no accidental over-blocking) is a key SWG correctness property.",
                 "URL object boundary", ["url_domain_objects", "http", "https_connect"],
                 intent, vectors, _fp("boundary", "corp-wild"))

    def fam_method(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "block-app", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "block_page"}]}
        vectors = [_v("get", "http", H_APP, method="GET"), _v("post", "http", H_APP, method="POST")]
        self.add("Destination block applies regardless of HTTP method",
                 "A destination block must apply to all methods (GET and POST alike); access rules are "
                 "destination-scoped, not method-scoped.",
                 "Method-agnostic destination enforcement is expected of an SWG access rule.",
                 "HTTP method handling", ["http", "upload_download"],
                 intent, vectors, _fp("method", "block-app-allmethods"))

    def fam_schedule(self):
        # Anchor a window that is ACTIVE now and one that is INACTIVE now.
        now = self.now
        cur_day = now.strftime("%a")
        active_start = (now - timedelta(hours=1)).strftime("%H:%M")
        active_end = (now + timedelta(hours=1)).strftime("%H:%M")
        # ensure ordering start<end for the simple window (skip midnight wrap by clamping)
        if active_start >= active_end:
            active_start, active_end = "00:00", "23:59"
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "block-social-hours", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_SOCIAL,
                                       "schedule": {"days": [cur_day], "start": active_start,
                                                    "end": active_end, "tz": "UTC"}},
                             "action": "block_page"}]}
        # vector time = now (executor uses real clock; oracle uses when=now)
        vectors = [_v("active", "http", H_SOCIAL, when=now.isoformat())]
        self.add("Time-of-day policy (block social during a scheduled window)",
                 f"Block the social host during a scheduled window on {cur_day} ({active_start}-{active_end} "
                 "UTC); outside the window it is allowed. Tested at a time inside the window.",
                 "Schedule/time-of-day conditions (business-hours policy) are standard SWG controls "
                 "(PAN-OS schedules, Zscaler time-based rules).",
                 "Schedule / time condition", ["schedule_time", "http", "rule_first_match"],
                 intent, vectors, _fp("sched", "social-active"))

        # inactive window (a schedule that does NOT cover now -> allowed)
        other_day = (now + timedelta(days=2)).strftime("%a")
        intent2 = {"default_action": "allow", "default_auth": "Exempt",
                   "rules": [{"name": "block-social-otherday", "priority": 10, "kind": "access",
                              "match": {"fqdn": H_SOCIAL,
                                        "schedule": {"days": [other_day], "start": "00:00",
                                                     "end": "23:59", "tz": "UTC"}},
                              "action": "block_page"}]}
        vectors2 = [_v("inactive", "http", H_SOCIAL, when=now.isoformat())]
        self.add("Time-of-day policy (rule inactive outside its window)",
                 f"A block scheduled only for {other_day} must NOT enforce on other days; the social host is "
                 "allowed now (boundary/negative schedule test).",
                 "Correct schedule scoping (no enforcement outside the window) is a key correctness property.",
                 "Schedule / time boundary", ["schedule_time", "http"],
                 intent2, vectors2, _fp("sched", "social-inactive"))

    def fam_multi_condition(self):
        # AND of source + category
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "objects": {"categories": {"streaming": [H_MEDIA]}},
                  "rules": [{"name": "guest-no-streaming", "priority": 10, "kind": "access",
                             "match": {"src_ip": "127.0.0.0/8", "category": "streaming"}, "action": "block_page"}]}
        vectors = [_v("guest-media", "http", H_MEDIA, client_ip=SRC_OTHER),
                   _v("corp-media", "http", H_MEDIA, client_ip=SRC_CORP),
                   _v("guest-app", "http", H_APP, client_ip=SRC_OTHER)]
        self.add("Compound condition: block streaming for guest source only",
                 "Block streaming-category hosts, but only from the guest source network; corporate source "
                 "and non-streaming destinations are unaffected (AND of source + category).",
                 "Multi-condition rules (source AND destination-category) are standard SWG expressiveness.",
                 "Compound match (source+category)", ["source_ip_subnet", "url_categories", "http"],
                 intent, vectors, _fp("multi", "guest-streaming"))

    def fam_streaming(self):
        # allowed large / chunked integrity
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "allow-files", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_FILES}, "action": "allow"}]}
        vectors = [_v("chunked", "http", H_FILES, path="/chunked?n=6"),
                   _v("large", "http", H_FILES, path="/size/1048576")]
        self.add("Allowed traffic preserves chunked and large-body responses",
                 "Permitted destinations must deliver chunked transfer-encoding and large bodies intact "
                 "through the proxy (no truncation or corruption).",
                 "Transparent handling of chunked/streaming/large responses is a baseline proxy correctness "
                 "requirement.",
                 "Streaming / chunked / large", ["streaming_chunked", "large_files", "http"],
                 intent, vectors, _fp("stream", "chunked-large"))

    def fam_auth_challenge(self):
        # configured mode: default_auth=Default -> unauthenticated challenged 407
        intent = {"default_action": "allow", "default_auth": "Default", "configure_auth": True,
                  "auth_backend": True,
                  "rules": [{"name": "allow-app", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow"}]}
        vectors = [_v("unauth", "http", H_APP)]
        self.add("Require proxy authentication for unmatched/uncredentialed traffic",
                 "With an authentication backend configured and default-auth=Default, an unauthenticated "
                 "request must receive a 407 Proxy Authentication Required challenge before any allow policy "
                 "applies.",
                 "Forward-proxy authentication (407 / captive portal) gating egress is a defining "
                 "enterprise-SWG capability.",
                 "Authentication policy", ["auth_policy", "http"],
                 intent, vectors, _fp("auth", "default-407"), requires_auth=True)

    def build(self):
        self.fam_fqdn()
        self.fam_category()
        self.fam_category_group()
        self.fam_source()
        self.fam_ordering()
        self.fam_default()
        self.fam_tls()
        self.fam_ssl_bypass_override()
        self.fam_cert_fail()
        self.fam_blocklist()
        self.fam_redirect()
        self.fam_drop()
        self.fam_disabled_rule()
        self.fam_boundary()
        self.fam_method()
        self.fam_schedule()
        self.fam_multi_condition()
        self.fam_streaming()
        self.fam_auth_challenge()
        return self.out


if __name__ == "__main__":
    import json
    g = Gen()
    scs = g.build()
    print(f"generated {len(scs)} base scenarios; {g.n} ids, {len(g.seen)} unique fingerprints")
    for s in scs:
        print(f"  {s['id']:9} [{'AUTH' if s['requires_auth'] else '    '}] {s['title']}  "
              f"(vecs={len(s['vectors'])}, caps={','.join(s['capabilities'][:3])})")
