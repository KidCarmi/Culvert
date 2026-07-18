#!/usr/bin/env python3
"""
Full campaign scenario generator — extends the validated base families (Gen) with
parametric matrices across the capability matrix and a set of gap-finding families
whose expected behaviour is derived from GENERAL mature-SWG semantics (so a genuine
Culvert divergence surfaces as a finding rather than being pre-baked to pass).

Every scenario is enterprise-realistic, deterministic, dedup'd by semantic
fingerprint, and reproducible with local TEST-NET fixtures (no public internet).
"""
from __future__ import annotations
from datetime import timedelta
from .scenarios import (Gen, _fp, _v, H_APP, H_INTRANET, H_MEDIA, H_FILES, H_PARTNER,
                        H_SOCIAL, H_NEWS, H_EXAMPLE, H_TENANTB, H_BADSSL, SRC_CORP, SRC_OTHER)

ALLOWED = [H_APP, H_INTRANET, H_FILES]
RESTRICTED = {H_SOCIAL: "social-media", H_NEWS: "news", H_MEDIA: "streaming", H_EXAMPLE: "webmail"}
PATTERN_STYLES = ["exact", "wildcard", "bare"]


def _pat(host, style):
    if style == "exact":
        return host
    # derive a parent domain
    parent = ".".join(host.split(".")[1:]) if host.count(".") >= 2 else host
    if style == "wildcard":
        return "*." + parent
    return parent  # bare


class FullGen(Gen):
    # ---------- A. destination-block matrix -------------------------------
    def m_fqdn_block(self):
        for host, cat in RESTRICTED.items():
            for style in PATTERN_STYLES:
                pat = _pat(host, style)
                fpk = _fp("A-fqdnblock", host, style, pat)
                intent = {"default_action": "allow", "default_auth": "Exempt",
                          "rules": [{"name": f"block-{cat}-{style}", "priority": 10, "kind": "access",
                                     "match": {"fqdn": pat}, "action": "block_page"}]}
                vectors = [_v("http", "http", host), _v("connect", "https", host),
                           _v("neg", "http", H_APP)]  # app must remain default-allow
                self.add(
                    f"Block '{cat}' destination by {style} FQDN ({pat})",
                    f"Block corporate access to the {cat} destination '{host}' via a {style} URL object "
                    f"('{pat}') for both HTTP and HTTPS(CONNECT); unrelated business traffic stays allowed.",
                    "Host/URL object blocking with exact, wildcard, and implicit-subdomain matching is a "
                    "baseline SWG capability (PAN-OS URL objects / Zscaler URL policy).",
                    "URL/Domain object policy",
                    ["url_domain_objects", "http", "https_connect", "rule_first_match"],
                    intent, vectors, fpk)

    # ---------- B. allow-list under default deny --------------------------
    def m_allowlist(self):
        for host in ALLOWED:
            for style in ["exact", "wildcard"]:
                pat = _pat(host, style)
                intent = {"default_action": "deny", "default_auth": "Exempt",
                          "rules": [{"name": f"permit-{style}", "priority": 10, "kind": "access",
                                     "match": {"fqdn": pat}, "action": "allow"}]}
                # R4: the negative vector must target a host OUTSIDE the permit's scope.
                # example.test is neither app.corp.local (exact) nor *.corp.local (wildcard),
                # so it genuinely exercises default-deny for BOTH pattern styles.
                vectors = [_v("permit", "http", host), _v("permit-c", "https", host),
                           _v("deny-other", "http", H_EXAMPLE)]
                self.add(
                    f"Default-deny egress with {style} allow-list for {host}",
                    f"Under Zero-Trust default-deny, permit only '{pat}'; every other destination is denied.",
                    "Explicit allow-listing under default-deny egress is the recommended enterprise posture.",
                    "Default deny + allow-list",
                    ["default_deny", "url_domain_objects", "http", "https_connect"],
                    intent, vectors, _fp("B-allowlist", host, style))

    # ---------- C. category & group matrix --------------------------------
    def m_categories(self):
        cats = {c: [h] for h, c in RESTRICTED.items()}
        for host, cat in RESTRICTED.items():
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "objects": {"categories": {cat: [host]}},
                      "rules": [{"name": f"block-cat-{cat}", "priority": 10, "kind": "access",
                                 "match": {"category": cat}, "action": "block_page"}]}
            other = next(h for h in RESTRICTED if h != host)
            vectors = [_v("in", "http", host), _v("out", "http", other), _v("biz", "http", H_APP)]
            self.add(
                f"Block URL category '{cat}'",
                f"Block all hosts classified as '{cat}'; other categories and business apps remain allowed.",
                "Category-based policy (not host-by-host) is the defining SWG control.",
                "URL category policy", ["url_categories", "http", "rule_first_match"],
                intent, vectors, _fp("C-cat", cat))
        # groups: pairwise bundles
        combos = [("non-productive", ["social-media", "news"], [H_SOCIAL, H_NEWS], [H_MEDIA]),
                  ("recreational", ["streaming", "social-media"], [H_MEDIA, H_SOCIAL], [H_NEWS]),
                  ("personal-comms", ["webmail", "social-media"], [H_EXAMPLE, H_SOCIAL], [H_NEWS])]
        for gname, members, blocked_hosts, allowed_hosts in combos:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "objects": {"categories": {c: [h] for h, c in RESTRICTED.items()},
                                  "category_groups": {gname: members}},
                      "rules": [{"name": f"block-grp-{gname}", "priority": 10, "kind": "access",
                                 "match": {"category_group": gname}, "action": "block_page"}]}
            vectors = [_v(f"b{i}", "http", h) for i, h in enumerate(blocked_hosts)] + \
                      [_v(f"a{i}", "http", h) for i, h in enumerate(allowed_hosts)]
            self.add(
                f"Block category group '{gname}' ({'+'.join(members)})",
                f"Bundle {', '.join(members)} into '{gname}' and block the group; categories outside the "
                "group stay allowed.",
                "Category groups reduce rule sprawl (PAN-OS custom URL categories / Zscaler super-cats).",
                "URL category group policy", ["url_categories", "category_groups", "http"],
                intent, vectors, _fp("C-grp", gname))

    # ---------- D. source-conditioned matrix ------------------------------
    def m_source(self):
        for host in [H_INTRANET, H_FILES, H_MEDIA, H_APP]:
            # corp-only permit under default deny
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "rules": [{"name": "corp-permit", "priority": 10, "kind": "access",
                                 "match": {"src_ip": "192.0.2.0/24", "fqdn": host}, "action": "allow"}]}
            vectors = [_v("corp", "http", host, client_ip=SRC_CORP),
                       _v("guest", "http", host, client_ip=SRC_OTHER)]
            self.add(
                f"Corporate-subnet-only access to {host}",
                f"Only the corporate LAN (192.0.2.0/24) may reach '{host}'; all other sources are denied.",
                "Source-zone conditioned access is fundamental to SWG segmentation.",
                "Source IP/zone policy", ["source_ip_subnet", "default_deny", "http", "rule_first_match"],
                intent, vectors, _fp("D-corponly", host))
            # guest-block overlay
            intent2 = {"default_action": "allow", "default_auth": "Exempt",
                       "rules": [{"name": "guest-block", "priority": 10, "kind": "access",
                                  "match": {"src_ip": "127.0.0.0/8", "fqdn": host}, "action": "block_page"}]}
            vectors2 = [_v("guest", "http", host, client_ip=SRC_OTHER),
                        _v("corp", "http", host, client_ip=SRC_CORP)]
            self.add(
                f"Block guest network from {host}",
                f"Block the guest/unmanaged source network from '{host}' while corporate keeps access.",
                "Guest-network egress restriction is a common SWG location policy.",
                "Source IP/zone policy", ["source_ip_subnet", "http", "rule_first_match"],
                intent2, vectors2, _fp("D-guestblock", host))

    # ---------- E. precedence matrix --------------------------------------
    def m_precedence(self):
        shapes = [
            ("permit-above-block", "deny",
             [{"name": "permit", "priority": 1, "kind": "access", "match": {"fqdn": H_APP}, "action": "allow"},
              {"name": "block", "priority": 2, "kind": "access", "match": {"fqdn": "*.corp.local"}, "action": "block_page"}],
             [_v("app", "http", H_APP), _v("intra", "http", H_INTRANET)]),
            ("block-above-permit", "allow",
             [{"name": "block", "priority": 1, "kind": "access", "match": {"fqdn": "*.corp.local"}, "action": "block_page"},
              {"name": "permit", "priority": 2, "kind": "access", "match": {"fqdn": H_APP}, "action": "allow"}],
             [_v("app", "http", H_APP), _v("intra", "http", H_INTRANET)]),
            ("three-tier", "deny",
             [{"name": "permit-app", "priority": 1, "kind": "access", "match": {"fqdn": H_APP}, "action": "allow"},
              {"name": "block-media", "priority": 2, "kind": "access", "match": {"fqdn": H_MEDIA}, "action": "block_page"},
              {"name": "permit-files", "priority": 3, "kind": "access", "match": {"fqdn": H_FILES}, "action": "allow"}],
             [_v("app", "http", H_APP), _v("media", "http", H_MEDIA), _v("files", "http", H_FILES),
              _v("other", "http", H_INTRANET)]),
        ]
        for name, dflt, rules, vectors in shapes:
            intent = {"default_action": dflt, "default_auth": "Exempt", "rules": rules}
            self.add(
                f"Rule precedence shape: {name}",
                f"Verify first-match evaluation for the '{name}' rule layout (default {dflt}); the winning "
                "rule for each destination must be the highest-priority match, with no leakage or reorder.",
                "Deterministic first-match precedence is the core SWG policy contract.",
                "Rule ordering / first-match", ["rule_first_match", "rule_ordering", "http"],
                intent, vectors, _fp("E-prec", name))

    # ---------- F. TLS matrix ---------------------------------------------
    def m_tls(self):
        for host in [H_APP, H_INTRANET, H_FILES, H_MEDIA]:
            # inspect (skip-verify so untrusted fixture cert is accepted)
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "inspect", "priority": 1, "kind": "access",
                                 "match": {"fqdn": host}, "action": "allow", "ssl": "inspect",
                                 "tls_skip_verify": True}]}
            self.add(
                f"TLS inspection (decrypt) of {host}",
                f"Decrypt and inspect TLS to '{host}' so downstream content controls can see plaintext.",
                "Per-destination TLS decryption is core to SWG DLP/threat inspection.",
                "TLS inspection", ["tls_inspection", "https_connect"],
                intent, [_v("i", "https", host, upstream_cert="untrusted")], _fp("F-inspect", host))
            # bypass
            intent2 = {"default_action": "allow", "default_auth": "Exempt",
                       "rules": [{"name": "bypass", "priority": 1, "kind": "access",
                                  "match": {"fqdn": host}, "action": "allow", "ssl": "bypass"}]}
            self.add(
                f"TLS bypass (no decrypt) of {host}",
                f"Tunnel TLS to '{host}' opaquely without decryption (e.g. privacy/compliance category).",
                "Selective do-not-decrypt is required for privacy/regulated destinations.",
                "TLS bypass", ["tls_inspection", "manual_ssl_bypass", "https_connect"],
                intent2, [_v("b", "https", host)], _fp("F-bypass", host))
        # cert-verification profile variants.
        #
        # certVerification='permissive' was RETIRED (#716): its documented
        # "verify, allow+log" semantics were never implemented (it verified like
        # 'strict'), and the value is now rejected on every write path (HTTP 400)
        # and fail-closed-migrated to 'strict' on load/sync. Generating it here
        # would fail profile setup and re-surface the now-CLOSED SWG-0069
        # configuration-contract gap. The retired-value contract (reject +
        # migrate) is covered by the Go tests (internal/decryptprofile/
        # decryptprofile_cert_migration_test.go, decryptprofile_cert_contract_test.go);
        # the historical SWG-0069 evidence is retained under representative_evidence/.
        for verify, cert_state, expect in [("skip", "untrusted", "intercept")]:
            prof = {"api": {"certVerification": verify}}
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "objects": {"decryption_profiles": {"prof-" + verify: prof}},
                      "rules": [{"name": "inspect-prof", "priority": 1, "kind": "access",
                                 "match": {"fqdn": H_APP}, "action": "allow", "ssl": "inspect",
                                 "decryption_profile": "prof-" + verify}]}
            self.add(
                f"Decryption profile certVerification={verify}",
                f"Use a named decryption profile with certVerification='{verify}' to inspect '{H_APP}' when "
                "the upstream presents an untrusted certificate.",
                "Named decryption profiles with configurable upstream cert handling are enterprise-standard.",
                "Decryption profile", ["tls_inspection", "decryption_profile", "cert_validation", "https_connect"],
                intent, [_v("p", "https", H_APP, upstream_cert="untrusted")], _fp("F-prof", verify))

    # ---------- G. schedule matrix ----------------------------------------
    def m_schedule(self):
        now = self.now
        day = now.strftime("%a")
        a_start = (now - timedelta(hours=1)).strftime("%H:%M")
        a_end = (now + timedelta(hours=1)).strftime("%H:%M")
        if a_start >= a_end:
            a_start, a_end = "00:00", "23:59"
        variants = [
            ("active-window", {"days": [day], "start": a_start, "end": a_end, "tz": "UTC"}, True, H_SOCIAL),
            ("inactive-day", {"days": [(now + timedelta(days=2)).strftime("%a")], "start": "00:00", "end": "23:59", "tz": "UTC"}, False, H_SOCIAL),
            ("overnight-now", {"days": [day], "start": a_start, "end": a_start, "tz": "UTC"}, None, H_MEDIA),
        ]
        for name, sched, active, host in variants[:2]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": f"sched-{name}", "priority": 10, "kind": "access",
                                 "match": {"fqdn": host, "schedule": sched}, "action": "block_page"}]}
            self.add(
                f"Schedule-conditioned block ({name})",
                f"Block '{host}' only within a defined schedule; verify enforcement {'inside' if active else 'is absent outside'} the window.",
                "Time-of-day / business-hours policy is a standard SWG control (PAN-OS schedules).",
                "Schedule / time condition", ["schedule_time", "http", "rule_first_match"],
                intent, [_v("t", "http", host, when=now.isoformat())], _fp("G-sched", name))

    # ---------- H. compound matrix ----------------------------------------
    def m_compound(self):
        combos = [
            ("src+cat", {"src_ip": "127.0.0.0/8", "category": "streaming"}, H_MEDIA, SRC_OTHER, SRC_CORP),
            ("src+fqdn", {"src_ip": "127.0.0.0/8", "fqdn": H_FILES}, H_FILES, SRC_OTHER, SRC_CORP),
        ]
        for name, match, host, hit_src, miss_src in combos:
            objs = {"categories": {"streaming": [H_MEDIA]}} if "category" in match else {}
            intent = {"default_action": "allow", "default_auth": "Exempt", "objects": objs,
                      "rules": [{"name": f"cmp-{name}", "priority": 10, "kind": "access",
                                 "match": match, "action": "block_page"}]}
            vectors = [_v("hit", "http", host, client_ip=hit_src),
                       _v("miss-src", "http", host, client_ip=miss_src),
                       _v("miss-dst", "http", H_APP, client_ip=hit_src)]
            self.add(
                f"Compound condition ({name}) — all predicates must hold",
                f"Block only when ALL of ({name}) match; a miss on any single predicate must not block.",
                "Multi-predicate rules (AND semantics) are standard SWG expressiveness.",
                "Compound match", ["source_ip_subnet", "url_categories", "http", "rule_first_match"],
                intent, vectors, _fp("H-cmp", name))

    # ---------- I. file/MIME download matrix ------------------------------
    def m_files(self):
        for ext, profile in [("exe", "Executables"), ("bat", "Executables")]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "inspect-files", "priority": 1, "kind": "access",
                                 "match": {"fqdn": H_FILES}, "action": "allow", "ssl": "inspect",
                                 "tls_skip_verify": True, "file_profile": profile}]}
            vec_block = _v("dl", "https", H_FILES, path=f"/file/malware.{ext}",
                           upstream_cert="untrusted", download_ext=ext)
            vec_ok = _v("pdf", "https", H_FILES, path="/file/doc.pdf", upstream_cert="untrusted")
            self.add(
                f"Block .{ext} downloads via file profile '{profile}' (under TLS inspection)",
                f"Under TLS inspection, block download of .{ext} executables using the '{profile}' file "
                "profile; permit benign document downloads.",
                "File-type / true-type download control is a core SWG DLP capability (PAN-OS file blocking).",
                "File type / MIME enforcement",
                ["file_type_mime", "upload_download", "tls_inspection", "https_connect"],
                intent, [vec_block, vec_ok], _fp("I-file", ext))

    # ---------- J. redirect / drop / lifecycle ----------------------------
    def m_actions(self):
        for host in [H_SOCIAL, H_NEWS]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "redir", "priority": 10, "kind": "access",
                                 "match": {"fqdn": host}, "action": "redirect",
                                 "redirect_url": "http://intranet.corp.local:18091/aup"}]}
            self.add(
                f"Redirect {host} to acceptable-use notice",
                f"Redirect (302) users hitting '{host}' to an internal acceptable-use page instead of a block.",
                "Coaching/redirect pages are standard SWG UX controls.",
                "Redirect action", ["redirect", "http"],
                intent, [_v("r", "http", host)], _fp("J-redir", host))
        for host in [H_MEDIA, H_SOCIAL]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "drop", "priority": 10, "kind": "access",
                                 "match": {"fqdn": host}, "action": "drop"}]}
            self.add(
                f"Silently drop connections to {host}",
                f"Reset/drop connections to '{host}' with no block page (covert deny).",
                "Silent-drop actions exist alongside block pages in mature SWGs.",
                "Drop action", ["drop", "http"],
                intent, [_v("d", "http", host)], _fp("J-drop", host))
        for host in [H_NEWS, H_MEDIA]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "disabled", "priority": 10, "kind": "access",
                                 "match": {"fqdn": host}, "action": "block_page", "enabled": False}]}
            self.add(
                f"Disabled block rule for {host} must not enforce",
                f"A disabled block rule for '{host}' must have no effect (traffic follows default).",
                "Enable/disable toggles are universal; a disabled rule leaking enforcement is a defect.",
                "Rule lifecycle", ["rule_lifecycle", "http"],
                intent, [_v("x", "http", host)], _fp("J-disabled", host))

    # ---------- K. streaming / integrity ----------------------------------
    def m_streaming(self):
        for name, path in [("chunked", "/chunked?n=8"), ("large-1mb", "/size/1048576"),
                           ("many-redirect", "/redirect?to=/&n=3")]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "allow-files", "priority": 1, "kind": "access",
                                 "match": {"fqdn": H_FILES}, "action": "allow"}]}
            exp = "redirect" if "redirect" in name else "allow"
            self.add(
                f"Permitted traffic integrity: {name}",
                f"A permitted destination must transparently deliver {name} responses through the proxy.",
                "Transparent chunked/large/redirect handling is a baseline proxy correctness requirement.",
                "Streaming / chunked / redirect", ["streaming_chunked", "large_files", "redirect_chains", "http"],
                intent, [_v("s", "http", H_FILES, path=path)], _fp("K-stream", name))

    # ---------- L. boundary / negative ------------------------------------
    def m_boundary(self):
        cases = [
            ("wildcard-no-over-match", "*.corp.local", [(H_APP, True), (H_EXAMPLE, False)]),
            ("subdomain-boundary", "app.corp.local", [(H_APP, True), (H_INTRANET, False)]),
            ("case-insensitive", H_NEWS.upper(), [(H_NEWS, True), (H_APP, False)]),
        ]
        for name, pat, checks in cases:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "block", "priority": 10, "kind": "access",
                                 "match": {"fqdn": pat}, "action": "block_page"}]}
            vectors = [_v(f"c{i}", "http", h) for i, (h, _) in enumerate(checks)]
            self.add(
                f"Matching boundary: {name}",
                f"Verify '{pat}' matches exactly the intended hosts and NOTHING else (boundary/negative).",
                "Precise match scoping (no over/under-blocking) is a core SWG correctness property.",
                "URL object boundary", ["url_domain_objects", "http"],
                intent, vectors, _fp("L-bound", name))

    # ---------- M. blocklist / threat -------------------------------------
    def m_blocklist(self):
        for host in [H_NEWS, H_MEDIA, H_SOCIAL]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "objects": {"blocklist": [host]},
                      "rules": [{"name": "allow-all", "priority": 100, "kind": "access",
                                 "match": {"fqdn": "*"}, "action": "allow"}]}
            self.add(
                f"Threat blocklist pre-empts allow for {host}",
                f"'{host}' on the reputation blocklist must be blocked even though a broad allow-all matches.",
                "Threat-intel enforcement ahead of allow policy is standard SWG behaviour.",
                "Threat intelligence", ["threat_intel", "blocklist", "http", "rule_first_match"],
                intent, [_v("b", "http", host), _v("clean", "http", H_APP)], _fp("M-bl", host))

    # ---------- N. method / concurrency -----------------------------------
    def m_methods(self):
        for m in ["POST", "PUT", "DELETE"]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "block-app", "priority": 10, "kind": "access",
                                 "match": {"fqdn": H_APP}, "action": "block_page"}]}
            self.add(
                f"Destination block applies to HTTP {m}",
                f"A destination block for '{H_APP}' must apply to {m} (upload) as well as GET (download); "
                "access rules are method-agnostic.",
                "Method-agnostic destination enforcement is expected of SWG access rules.",
                "HTTP method / upload-download", ["http", "upload_download"],
                intent, [_v("m", "http", H_APP, method=m)], _fp("N-method", m))

    # =====================================================================
    # GAP-FINDING families (general-SWG expectation; Culvert may diverge)
    # =====================================================================
    def g_socks5_bypass(self):
        for host in [H_NEWS, H_MEDIA]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "block", "priority": 1, "kind": "access",
                                 "match": {"fqdn": host}, "action": "block_page"}],
                      "triage": {"class": "SECURITY_BYPASS",
                                 "note": "Culvert SOCKS5 handler does not run the PBAC policy engine "
                                         "(only the legacy blocklist); destination policy cannot be "
                                         "represented for SOCKS5 clients. Documented architecture, but a "
                                         "valid enterprise requirement that is unrepresentable => missing capability."}}
            self.add(
                f"Egress policy must apply to SOCKS5 clients ({host})",
                f"A blocked destination '{host}' must be blocked for SOCKS5 clients exactly as for HTTP/"
                "CONNECT clients; egress policy is transport-agnostic in a mature SWG.",
                "SWGs enforce the same egress policy across HTTP, CONNECT, and SOCKS transports "
                "(Zscaler/PAN-OS forward proxy).",
                "Authorization policy (SOCKS5)", ["socks5", "authorization_policy", "rule_first_match"],
                intent, [_v("http", "http", host), _v("socks", "socks5", host)], _fp("G-socks5", host))

    def g_identity_scrub(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "inspect-app", "priority": 1, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow", "ssl": "inspect", "tls_skip_verify": True}]}
        vec = _v("spoof", "https", H_APP, path="/echo", upstream_cert="untrusted",
                 inject_headers={"X-User-Identity": "attacker@evil.test"},
                 assert_header_absent="X-User-Identity")
        self.add(
            "Client-supplied identity header must be scrubbed before upstream",
            "A client that injects a spoofed 'X-User-Identity' header must NOT have it forwarded to the "
            "origin; the proxy owns identity assertion and must strip client-supplied copies.",
            "Preventing identity-header spoofing to upstreams is a security-critical SWG behaviour.",
            "Header hygiene / identity", ["header_scrub", "identity", "tls_inspection", "https_connect"],
            intent, [vec], _fp("G-scrub", "xuserid"))

    def g_object_lifecycle(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "objects": {"categories": {"blocked-cat": [H_SOCIAL]}},
                  "rules": [{"name": "block-by-cat", "priority": 10, "kind": "access",
                             "match": {"category": "blocked-cat"}, "action": "block_page"}],
                  "post_apply": [{"method": "DELETE", "path": "/api/urlcat?name=blocked-cat",
                                  "label": "delete-referenced-category", "expect_status": None}]}
        # After deleting the referenced category, what happens to the rule's enforcement?
        vec = _v("after-delete", "http", H_SOCIAL)
        self.add(
            "Deleting a category referenced by a live rule (referential integrity)",
            "Delete a URL category that a live block rule references; the product must behave safely and "
            "predictably (block the deletion, or clearly neutralise the dangling rule) — not leave an "
            "ambiguous rule whose behaviour silently changes.",
            "Referential integrity / safe object deletion is expected of enterprise policy management.",
            "Deleted/referenced objects", ["object_lifecycle", "config_persistence", "http"],
            intent, [vec], _fp("G-lifecycle", "delcat"),
            notes="Oracle expects the pre-deletion semantics (block) OR an explicit safe outcome; "
                  "divergence is triaged as a config-contract/UX observation, not necessarily a bug.")

    def g_conflict(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "conflict-allow", "priority": 5, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow"},
                            {"name": "conflict-block", "priority": 5, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "block_page"}]}
        self.add(
            "Conflicting same-priority rules resolve deterministically",
            "Two rules at the SAME priority match the same host with opposite actions; the engine must "
            "resolve deterministically (stable order) and ideally surface a conflict warning — not flap.",
            "Deterministic conflict resolution + conflict detection is expected of SWG policy engines.",
            "Conflicting objects and policies", ["policy_conflict", "rule_ordering", "http"],
            intent, [_v("c1", "http", H_APP), _v("c2", "http", H_APP), _v("c3", "http", H_APP)],
            _fp("G-conflict", "samepri"),
            notes="Determinism is the pass criterion: all three probes must agree.")

    def g_redirect_safety(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "bad-redirect", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_SOCIAL}, "action": "redirect",
                             "redirect_url": "http://attacker.evil.test/phish"}],
                  "triage": {"class": "EXPECTED_LIMITATION",
                             "note": "Culvert refuses to redirect to an unvalidated external host "
                                     "(isSafeRedirectURL -> 403 instead of an open 302). This is a DEFENSIBLE "
                                     "safety posture (no open-redirect), but it also means an admin cannot "
                                     "configure a legitimate external redirect target; the constraint is not "
                                     "surfaced at config time. Recorded as a contract nuance, explicitly NOT a "
                                     "product bug — the secure behavior is correct."}}
        self.add(
            "Open-redirect safety on the redirect action",
            "A redirect action pointing at an unvalidated external URL must be handled safely (rejected / "
            "403), not blindly 302'd to an attacker-controlled host.",
            "Safe-redirect validation prevents the proxy from being an open-redirect (OWASP).",
            "Redirect safety", ["redirect", "security", "http"],
            intent, [_v("r", "http", H_SOCIAL)], _fp("G-redirsafe", "external"),
            notes="Oracle expects the redirect NOT to succeed to an external host; either a safe 3xx to an "
                  "internal target or a 403.")

    # ---------- densification passes --------------------------------------
    def m_https_variants(self):
        """CONNECT-specific block/allow across hosts (distinct from plain-HTTP)."""
        for host in [H_APP, H_INTRANET, H_MEDIA, H_SOCIAL, H_NEWS, H_FILES, H_PARTNER]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "block-connect", "priority": 10, "kind": "access",
                                 "match": {"fqdn": host}, "action": "block_page"}]}
            self.add(
                f"Block HTTPS (CONNECT) to {host}",
                f"Deny the CONNECT tunnel to '{host}:443'-class destinations with a policy block, "
                "independent of plain-HTTP handling.",
                "CONNECT-tunnel destination control is required for HTTPS egress governance.",
                "HTTPS CONNECT policy", ["https_connect", "url_domain_objects", "rule_first_match"],
                intent, [_v("c", "https", host)], _fp("HV-connect", host))

    def m_allowlist_more(self):
        for host in [H_MEDIA, H_SOCIAL, H_NEWS, H_PARTNER, H_EXAMPLE, H_TENANTB]:
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "rules": [{"name": "permit", "priority": 10, "kind": "access",
                                 "match": {"fqdn": host}, "action": "allow"}]}
            self.add(
                f"Default-deny with single-host exception for {host}",
                f"Under default-deny, permit exactly one destination '{host}'; all others denied.",
                "Minimal allow-listing under Zero Trust is a standard enterprise pattern.",
                "Default deny + allow-list", ["default_deny", "url_domain_objects", "http", "https_connect"],
                intent, [_v("p", "http", host), _v("pc", "https", host), _v("d", "http", H_APP)],
                _fp("BX-allow1", host))

    def m_cat_guest(self):
        """Category block scoped to guest source (source+category compound, per category)."""
        for host, cat in RESTRICTED.items():
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "objects": {"categories": {cat: [host]}},
                      "rules": [{"name": f"guest-block-{cat}", "priority": 10, "kind": "access",
                                 "match": {"src_ip": "127.0.0.0/8", "category": cat}, "action": "block_page"}]}
            vectors = [_v("guest", "http", host, client_ip=SRC_OTHER),
                       _v("corp", "http", host, client_ip=SRC_CORP)]
            self.add(
                f"Block category '{cat}' for guest network only",
                f"Guests may not reach '{cat}' hosts; corporate users may. Combines source zone with URL "
                "category.",
                "Per-audience category policy (guest vs corporate) is standard SWG location policy.",
                "Compound match (source+category)", ["source_ip_subnet", "url_categories", "http"],
                intent, vectors, _fp("CG-guest", cat))

    def m_tls_more(self):
        knobs = [("mintls12", {"minTlsVersion": "1.2"}), ("http2native", {"inspectHttp2": True}),
                 ("failopen", {"onInspectError": "fail-open"}), ("failclose", {"onInspectError": "fail-close"})]
        for name, api in knobs:
            prof = {"api": api}
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "objects": {"decryption_profiles": {"p-" + name: prof}},
                      "rules": [{"name": "inspect", "priority": 1, "kind": "access",
                                 "match": {"fqdn": H_APP}, "action": "allow", "ssl": "inspect",
                                 "tls_skip_verify": True, "decryption_profile": "p-" + name}]}
            self.add(
                f"Decryption profile knob: {name}",
                f"Inspect '{H_APP}' using a decryption profile configured with {api}; verify inspection "
                "still succeeds and the profile is accepted/persisted.",
                "Fine-grained decryption profiles (TLS floor, HTTP/2, fail-mode) are enterprise-standard.",
                "Decryption profile", ["tls_inspection", "decryption_profile", "https_connect"],
                intent, [_v("i", "https", H_APP, upstream_cert="untrusted")], _fp("FX-tls", name))

    def m_schedule_more(self):
        now = self.now
        wknd = "Sat"
        variants = [
            ("business-hours", {"days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "start": "09:00", "end": "17:00", "tz": "UTC"}),
            ("weekend-only", {"days": ["Sat", "Sun"], "start": "00:00", "end": "23:59", "tz": "UTC"}),
            ("tz-newyork", {"days": [now.strftime("%a")], "start": "00:00", "end": "23:59", "tz": "America/New_York"}),
        ]
        for name, sched in variants:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": f"sched-{name}", "priority": 10, "kind": "access",
                                 "match": {"fqdn": H_SOCIAL, "schedule": sched}, "action": "block_page"}]}
            self.add(
                f"Schedule policy: {name}",
                f"Block '{H_SOCIAL}' according to the '{name}' schedule; enforcement must match the "
                "wall-clock evaluation of the window.",
                "Business-hours / weekend / timezone-aware schedules are standard SWG controls.",
                "Schedule / time condition", ["schedule_time", "http"],
                intent, [_v("t", "http", H_SOCIAL, when=now.isoformat())], _fp("GX-sched", name))

    def m_compound_more(self):
        combos = [
            ("cat+schedule", {"category": "social-media",
                              "schedule": {"days": [self.now.strftime("%a")], "start": "00:00", "end": "23:59", "tz": "UTC"}},
             {"categories": {"social-media": [H_SOCIAL]}}, H_SOCIAL, H_APP),
            ("fqdn+corp", {"src_ip": "192.0.2.0/24", "fqdn": H_FILES}, {}, H_FILES, H_APP),
            ("wild+guest", {"src_ip": "127.0.0.0/8", "fqdn": "*.corp.local"}, {}, H_INTRANET, H_EXAMPLE),
        ]
        for name, match, objs, hit, miss in combos:
            src = SRC_CORP if "192.0.2" in str(match.get("src_ip", "")) else SRC_OTHER
            intent = {"default_action": "allow", "default_auth": "Exempt", "objects": objs,
                      "rules": [{"name": f"cmp-{name}", "priority": 10, "kind": "access",
                                 "match": match, "action": "block_page"}]}
            act = "block_page" if match.get("fqdn", "").startswith("*") or "cat" in name else "block_page"
            vectors = [_v("hit", "http", hit, client_ip=src), _v("miss", "http", miss, client_ip=src)]
            self.add(
                f"Compound rule: {name}",
                f"Block only when all of ({name}) hold; a single-predicate miss must not block.",
                "Rich multi-predicate rules are a core SWG expressiveness requirement.",
                "Compound match", ["source_ip_subnet", "url_categories", "schedule_time", "http"],
                intent, vectors, _fp("HX-cmp", name))

    def m_tenant(self):
        """Multi-tenant-style config isolation on a single node (logical scoping)."""
        intent = {"default_action": "deny", "default_auth": "Exempt",
                  "rules": [{"name": "tenantA-app", "priority": 10, "kind": "access",
                             "match": {"src_ip": "192.0.2.0/24", "fqdn": H_APP}, "action": "allow"},
                            {"name": "tenantB-app", "priority": 11, "kind": "access",
                             "match": {"src_ip": "127.0.0.0/8", "fqdn": H_TENANTB}, "action": "allow"}]}
        vectors = [_v("A-own", "http", H_APP, client_ip=SRC_CORP),
                   _v("A-cross", "http", H_TENANTB, client_ip=SRC_CORP),
                   _v("B-own", "http", H_TENANTB, client_ip=SRC_OTHER),
                   _v("B-cross", "http", H_APP, client_ip=SRC_OTHER)]
        self.add(
            "Per-tenant egress isolation by source network",
            "Tenant A (corp subnet) may reach only its app; Tenant B (guest subnet) only its app. Neither "
            "may reach the other's destination (no cross-tenant leakage) under default-deny.",
            "Multi-tenant isolation via source-scoped policy is a common MSP/SWG deployment.",
            "Multi-tenant isolation", ["multi_tenant", "source_ip_subnet", "default_deny", "http"],
            intent, vectors, _fp("T-tenant", "iso"))

    def m_observability(self):
        intent = {"default_action": "allow", "default_auth": "Exempt",
                  "rules": [{"name": "obs-block", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_NEWS}, "action": "block_page"}]}
        self.add(
            "Blocked request is attributable in stats/decision trace",
            "A blocked request must be observable: reflected in blocked counters and carry a decision trace "
            "naming the matched rule (rule id) so an admin can explain the enforcement.",
            "Per-request decision trace / rule attribution is required for SWG operations and audit.",
            "Logging / decision trace", ["observability", "decision_trace", "logging", "http"],
            intent, [_v("b", "http", H_NEWS)], _fp("O-trace", "blocked"),
            notes="Pass requires the block to enforce AND a POLICY_ decision trace with the rule name.")

    def m_concurrency(self):
        intent = {"default_action": "deny", "default_auth": "Exempt",
                  "rules": [{"name": "permit-app", "priority": 1, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow"},
                            {"name": "block-media", "priority": 2, "kind": "access",
                             "match": {"fqdn": H_MEDIA}, "action": "block_page"}]}
        vectors = [_v(f"conc-app-{i}", "http", H_APP) for i in range(3)] + \
                  [_v(f"conc-media-{i}", "http", H_MEDIA) for i in range(3)]
        self.add(
            "Consistent enforcement under concurrent requests",
            "Under concurrent load, permitted and blocked destinations must be enforced consistently "
            "(no cross-talk / race between decisions).",
            "Correct policy enforcement under concurrency is a baseline SWG reliability property.",
            "Concurrent users", ["concurrency", "default_deny", "http", "rule_first_match"],
            intent, vectors, _fp("Q-conc", "mixed"))

    def m_persistence(self):
        # R1: the harness now runs Culvert with the shipped durable-store contract
        # (-policy /data/policy.json). This scenario creates policy via the Admin API,
        # restarts the proxy WITHOUT wiping /data, and asserts the rule is both
        # PRESENT (config persistence) and ENFORCED (runtime, via decision trace) after
        # restart. It PASSES on a correct build and FLIPS (a Save()-disabling mutation
        # is detected) when persistence is broken.
        intent = {"default_action": "deny", "default_auth": "Exempt",
                  "rules": [{"name": "permit-app", "priority": 10, "kind": "access",
                             "match": {"fqdn": H_APP}, "action": "allow"}],
                  "persistence_check": True}
        self.add(
            "Policy configuration persists AND enforces across a proxy restart",
            "Policy created through the admin API (with the shipped -policy durable store) must survive "
            "a data-plane restart and remain ENFORCEABLE — the permitted host is still allowed and an "
            "unmatched host is still default-denied after restart, confirmed by the post-restart decision "
            "trace, not just a config read-back.",
            "Configuration durability + post-restart enforcement is a fundamental enterprise expectation.",
            "Configuration persistence", ["config_persistence", "data_plane_restart", "http"],
            intent, [_v("app", "http", H_APP), _v("deny", "http", H_MEDIA)], _fp("P-persist", "restart"),
            notes="Runner restarts WITHOUT wiping /data; asserts post-restart readback + enforcement trace.")

    def m_limitations(self):
        """Honest capability-coverage records for dimensions the local fixture lab cannot
        deterministically exercise; classified EXPECTED_LIMITATION/TEST_INFRA, documented."""
        recs = [
            ("geoip-country", "Block destinations by GeoIP country (e.g. deny CN/RU egress).",
             "Country-based egress control is a standard SWG capability.",
             "GeoIP / destination country", ["geoip_country"],
             "GeoIP is cache-only fail-closed and requires a GeoLite2 DB + public IPs; TEST-NET fixtures "
             "cannot populate the GeoIP cache, so this dimension is recorded, not executed."),
            ("ipv6-egress", "Enforce policy for IPv6 destinations.",
             "Dual-stack egress governance is expected of a modern SWG.",
             "IPv6 support", ["ipv6"],
             "The SSRF guard blocks ::1/ULA and the lab cannot assign a public IPv6 to a fixture; recorded "
             "as an untested dimension."),
            ("dns-rebinding", "Resist DNS-rebinding to internal targets during a tunnel.",
             "DNS-rebinding protection is a security-critical SWG behaviour.",
             "DNS rebinding protection", ["dns_rebinding", "security"],
             "Culvert applies a connect-time ssrfControl re-check (verified by code review); a full "
             "rebinding harness (TTL=0 flip) is out of scope for the fixture lab and recorded."),
            ("websocket", "Govern WebSocket upgrades through policy and TLS inspection.",
             "WebSocket-aware policy is expected of a modern SWG.",
             "WebSocket handling", ["websocket"],
             "The fixture provides a WS stub; deterministic frame-level assertions were deferred and the "
             "dimension recorded for coverage completeness."),
            ("partial-content", "Handle HTTP Range / partial downloads under content control.",
             "Range/partial handling matters for large-file DLP.",
             "Partial downloads", ["partial_content"],
             "Recorded; the fixture supports byte-sized bodies but deterministic multi-range assertions "
             "were deferred."),
        ]
        for key, req, rat, cat, caps, note in recs:
            self.add(
                f"[Coverage record] {cat}", req, rat, cat, caps + ["limitation_record"],
                {"limitation": True, "triage": {"class": "EXPECTED_LIMITATION", "note": note}},
                [], _fp("LIM", key), notes=note)

    def m_extra_bulk(self):
        """Additional distinct, realistic destination/category permutations to broaden coverage."""
        # per-restricted-host: redirect + drop under default-deny business context
        for host, cat in RESTRICTED.items():
            # R4: the carve-out exception MUST be higher priority (lower number) than
            # the broad permit, otherwise a restricted host that is ALSO inside the
            # *.corp.local permit (e.g. media.corp.local) is shadowed by the permit and
            # the exception never fires. except=1 (top), permit-biz=2.
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "rules": [{"name": f"except-{cat}", "priority": 1, "kind": "access",
                                 "match": {"fqdn": host}, "action": "block_page"},
                                {"name": "permit-biz", "priority": 2, "kind": "access",
                                 "match": {"fqdn": "*.corp.local"}, "action": "allow"}]}
            vectors = [_v("biz", "http", H_APP), _v("restricted", "http", host)]
            self.add(
                f"Permit business domain but carve out {cat} exception",
                f"Under default-deny, permit all *.corp.local business traffic but carve out an explicit "
                f"block for the {cat} destination '{host}'.",
                "Broad-permit-with-exceptions is a very common enterprise policy shape.",
                "Rule ordering / exceptions", ["rule_first_match", "default_deny", "url_domain_objects", "http"],
                intent, vectors, _fp("BLK-except", host))
        # per allowed host: inspect + allow (productivity apps inspected for DLP)
        for host in ALLOWED + [H_MEDIA, H_EXAMPLE]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "inspect", "priority": 1, "kind": "access",
                                 "match": {"fqdn": host}, "action": "allow", "ssl": "inspect", "tls_skip_verify": True}]}
            self.add(
                f"Inspect productivity destination {host} for DLP",
                f"Decrypt '{host}' so DLP/content controls apply to its TLS traffic while keeping it allowed.",
                "Inspecting sanctioned apps for DLP is a primary SWG use-case (Netskope/Zscaler inline DLP).",
                "TLS inspection (DLP)", ["tls_inspection", "https_connect"],
                intent, [_v("i", "https", host, upstream_cert="untrusted")], _fp("BLK-inspect", host))
        # per restricted host: bare-domain block covering subdomain
        for host, cat in RESTRICTED.items():
            parent = ".".join(host.split(".")[1:]) if host.count(".") >= 2 else host
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "block-bare", "priority": 10, "kind": "access",
                                 "match": {"fqdn": parent}, "action": "block_page"}]}
            self.add(
                f"Bare-domain block '{parent}' covers subdomains ({cat})",
                f"A bare-domain block object '{parent}' must implicitly cover its subdomains (PAN-OS "
                "semantics) so the whole {cat} domain is blocked.",
                "Implicit-subdomain semantics of bare-domain objects is a documented SWG matching rule.",
                "URL object semantics", ["url_domain_objects", "http", "https_connect"],
                intent, [_v("root", "http", parent if "." in parent else host),
                         _v("sub", "http", host)], _fp("BLK-bare", parent))

    def m_wide(self):
        """Wide per-host/per-action expansion — each a distinct, realistic admin ask."""
        ALLHOSTS = [H_APP, H_INTRANET, H_FILES, H_MEDIA, H_SOCIAL, H_NEWS, H_EXAMPLE, H_PARTNER, H_TENANTB]
        role = {H_APP: "line-of-business app", H_INTRANET: "intranet portal", H_FILES: "file server",
                H_MEDIA: "streaming media", H_SOCIAL: "social media", H_NEWS: "news",
                H_EXAMPLE: "personal webmail", H_PARTNER: "partner extranet", H_TENANTB: "tenant-B app"}
        # 1) block by exact FQDN (HTTP) — every host (temporary/administrative block)
        for h in ALLHOSTS:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "adminblock", "priority": 10, "kind": "access",
                                 "match": {"fqdn": h}, "action": "block_page"}]}
            self.add(
                f"Administrative block of {role[h]} ({h})",
                f"Place an administrative block on the {role[h]} '{h}' (e.g. incident response); all other "
                "destinations unaffected.",
                "Ad-hoc destination blocking (incident containment) is a routine SWG operation.",
                "URL/Domain object policy", ["url_domain_objects", "http", "rule_first_match"],
                intent, [_v("blk", "http", h), _v("neg", "http", H_APP if h != H_APP else H_INTRANET)],
                _fp("W-block", h))
        # 2) source-scoped permit under deny (corp) for every host
        for h in ALLHOSTS:
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "rules": [{"name": "corp-permit", "priority": 10, "kind": "access",
                                 "match": {"src_ip": "192.0.2.0/24", "fqdn": h}, "action": "allow"}]}
            self.add(
                f"Corporate-only access to {role[h]} ({h})",
                f"Only the corporate subnet may reach the {role[h]} '{h}'; guests denied by default.",
                "Source-scoped allow under default-deny is a standard segmentation control.",
                "Source IP/zone policy", ["source_ip_subnet", "default_deny", "http", "rule_first_match"],
                intent, [_v("corp", "http", h, client_ip=SRC_CORP), _v("guest", "http", h, client_ip=SRC_OTHER)],
                _fp("W-corp", h))
        # 3) inspect-for-DLP OR bypass depending on sensitivity, per host
        for h in ALLHOSTS:
            sens = h in (H_PARTNER, H_EXAMPLE)  # privacy-sensitive => bypass
            if sens:
                intent = {"default_action": "allow", "default_auth": "Exempt",
                          "rules": [{"name": "bypass", "priority": 1, "kind": "access",
                                     "match": {"fqdn": h}, "action": "allow", "ssl": "bypass"}]}
                self.add(
                    f"Do-not-decrypt {role[h]} ({h}) for privacy",
                    f"Bypass TLS decryption for the privacy-sensitive {role[h]} '{h}'.",
                    "Do-not-decrypt for regulated/privacy destinations is a compliance requirement.",
                    "TLS bypass", ["tls_inspection", "manual_ssl_bypass", "https_connect"],
                    intent, [_v("b", "https", h)], _fp("W-bypass", h))
            else:
                intent = {"default_action": "allow", "default_auth": "Exempt",
                          "rules": [{"name": "inspect", "priority": 1, "kind": "access",
                                     "match": {"fqdn": h}, "action": "allow", "ssl": "inspect", "tls_skip_verify": True}]}
                self.add(
                    f"Decrypt {role[h]} ({h}) for inline inspection",
                    f"Decrypt and inspect the {role[h]} '{h}' so inline threat/DLP controls apply.",
                    "Decrypting sanctioned apps for inline inspection is a primary SWG use-case.",
                    "TLS inspection", ["tls_inspection", "https_connect"],
                    intent, [_v("i", "https", h, upstream_cert="untrusted")], _fp("W-inspect", h))
        # 4) redirect restricted categories to coaching page (per restricted host, distinct)
        for h in [H_MEDIA, H_EXAMPLE, H_PARTNER]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "coach", "priority": 10, "kind": "access",
                                 "match": {"fqdn": h}, "action": "redirect",
                                 "redirect_url": "http://intranet.corp.local:18091/coaching"}]}
            self.add(
                f"Coaching redirect for {role[h]} ({h})",
                f"Redirect users of '{h}' to a coaching page rather than hard-blocking.",
                "User-coaching redirects balance security with productivity (Netskope coaching).",
                "Redirect action", ["redirect", "http"],
                intent, [_v("r", "http", h)], _fp("W-coach", h))
        # 5) default-deny + wildcard corp permit + explicit category block (layered) per restricted host
        for h, cat in RESTRICTED.items():
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "objects": {"categories": {cat: [h]}},
                      "rules": [{"name": "permit-corp", "priority": 1, "kind": "access",
                                 "match": {"fqdn": "*"}, "action": "allow"},
                                {"name": f"block-{cat}", "priority": 0, "kind": "access",
                                 "match": {"category": cat}, "action": "block_page"}],
                      "triage": {"class": "CONFIGURATION_CONTRACT_GAP",
                                 "note": "The admin set the category-exception rule to priority 0 intending "
                                         "TOP precedence (a common '0 = highest' convention), but Culvert "
                                         "treats priority 0 as the Go zero-value 'unset' and silently "
                                         "auto-assigns it to the END (persisted as priority 2, BELOW the "
                                         "priority-1 allow-all). The config is accepted with NO warning, so "
                                         "the intended precedence is silently INVERTED and the exception never "
                                         "fires. Priority 0 is unusable as a top-priority value; the coercion "
                                         "is not surfaced. (The same layering works correctly with priorities "
                                         ">=1 — see the precedence family, which passes.)"}}
            self.add(
                f"Allow-all-with-{cat}-carveout (category exception above broad permit)",
                f"Permit all egress but block the '{cat}' category via a higher-priority rule; verifies "
                "priority-0 category block wins over a priority-1 allow-all.",
                "Layered allow-with-exceptions using categories is a very common enterprise shape.",
                "Rule ordering + category", ["rule_first_match", "url_categories", "rule_ordering", "http"],
                intent, [_v("blocked", "http", h), _v("allowed", "http", H_APP)], _fp("W-carve", cat))

    def m_wide3(self):
        ALLHOSTS = [H_APP, H_INTRANET, H_FILES, H_MEDIA, H_SOCIAL, H_NEWS, H_EXAMPLE, H_PARTNER, H_TENANTB]
        role = {H_APP: "line-of-business app", H_INTRANET: "intranet portal", H_FILES: "file server",
                H_MEDIA: "streaming media", H_SOCIAL: "social media", H_NEWS: "news",
                H_EXAMPLE: "personal webmail", H_PARTNER: "partner extranet", H_TENANTB: "tenant-B app"}
        # inspect each host under default-deny + permit (secured productivity path)
        for h in ALLHOSTS:
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "rules": [{"name": "permit-inspect", "priority": 10, "kind": "access",
                                 "match": {"fqdn": h}, "action": "allow", "ssl": "inspect", "tls_skip_verify": True}]}
            self.add(
                f"Zero-Trust: only {role[h]} permitted, and inspected ({h})",
                f"Under default-deny, permit only '{h}' AND decrypt it for inspection — a sanctioned, "
                "inspected egress path.",
                "Combining allow-listing with mandatory inspection is a Zero-Trust SWG pattern.",
                "Default-deny + inspection", ["default_deny", "tls_inspection", "https_connect", "rule_first_match"],
                intent, [_v("permit", "https", h, upstream_cert="untrusted"), _v("deny", "http", H_BADSSL)],
                _fp("W3-zti", h))

    def m_wide2(self):
        ALLHOSTS = [H_APP, H_INTRANET, H_FILES, H_MEDIA, H_SOCIAL, H_NEWS, H_EXAMPLE, H_PARTNER, H_TENANTB]
        role = {H_APP: "line-of-business app", H_INTRANET: "intranet portal", H_FILES: "file server",
                H_MEDIA: "streaming media", H_SOCIAL: "social media", H_NEWS: "news",
                H_EXAMPLE: "personal webmail", H_PARTNER: "partner extranet", H_TENANTB: "tenant-B app"}
        # 6) block each host via parent wildcard (distinct from exact) — domain-wide block
        for h in ALLHOSTS:
            parent = ".".join(h.split(".")[1:]) if h.count(".") >= 2 else h
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "domain-block", "priority": 10, "kind": "access",
                                 "match": {"fqdn": "*." + parent}, "action": "block_page"}]}
            self.add(
                f"Domain-wide wildcard block covering {role[h]} (*.{parent})",
                f"Block the entire '{parent}' domain (wildcard) which includes the {role[h]} '{h}'.",
                "Domain-wide wildcard blocking is a routine SWG bulk control.",
                "URL object (wildcard)", ["url_domain_objects", "http", "https_connect", "rule_first_match"],
                intent, [_v("sub", "http", h), _v("subc", "https", h)], _fp("W2-domwild", parent + h))
        # 7) guest-block each host (source-scoped block overlay)
        for h in ALLHOSTS:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "guest-block", "priority": 10, "kind": "access",
                                 "match": {"src_ip": "127.0.0.0/8", "fqdn": h}, "action": "block_page"}]}
            self.add(
                f"Guest network blocked from {role[h]} ({h})",
                f"Block the guest/unmanaged network from '{h}' while corporate keeps access.",
                "Guest-egress restriction per destination is a common location policy.",
                "Source IP/zone policy", ["source_ip_subnet", "http", "rule_first_match"],
                intent, [_v("guest", "http", h, client_ip=SRC_OTHER), _v("corp", "http", h, client_ip=SRC_CORP)],
                _fp("W2-guest", h))
        # 8) category allow-list mode: permit only one category, deny the rest
        cats = {c: [h] for h, c in RESTRICTED.items()}
        for h, cat in RESTRICTED.items():
            intent = {"default_action": "deny", "default_auth": "Exempt",
                      "objects": {"categories": cats},
                      "rules": [{"name": f"permit-{cat}", "priority": 10, "kind": "access",
                                 "match": {"category": cat}, "action": "allow"}]}
            other = next(hh for hh in RESTRICTED if hh != h)
            # Fixture caveat: the 'webmail' category host is example.test, which is a
            # PARENT domain of social.example.test / news.example.test. Culvert's
            # documented suffix category-matching therefore also classifies those
            # subdomains as webmail (a host matching multiple categories resolves to
            # the suffix-parent here), so the permit-webmail allow-list unexpectedly
            # permits social/news. This is an AMBIGUOUS-FIXTURE artifact of the lab's
            # category host choice, NOT a Culvert defect — recorded as test-infra.
            if cat == "webmail":
                intent["triage"] = {"class": "TEST_INFRA_FAILURE",
                                    "note": "Lab fixture defect: webmail category host 'example.test' is a "
                                            "parent domain of social.example.test/news.example.test, so "
                                            "Culvert's (correct) suffix category matching classifies those "
                                            "subdomains as webmail too, making the allow-list permit them. "
                                            "Culvert behaves correctly; the scenario's category fixture is "
                                            "ambiguous. Observation: for a host matching multiple categories "
                                            "(exact vs suffix-parent), Culvert resolved to the suffix-parent "
                                            "category — worth a documentation note on multi-category precedence."}
            self.add(
                f"Category allow-list: permit only '{cat}' under default-deny",
                f"Under default-deny, permit only the '{cat}' category; other categories (and uncategorised) "
                "are denied.",
                "Category allow-listing (deny-by-default with sanctioned categories) is a Zero-Trust SWG pattern.",
                "URL category allow-list", ["url_categories", "default_deny", "http", "rule_first_match"],
                intent, [_v("permit", "http", h), _v("deny", "http", other), _v("deny2", "http", H_APP)],
                _fp("W2-catallow", cat))
        # 9) drop each restricted host (covert deny) distinct
        for h in [H_SOCIAL, H_NEWS, H_EXAMPLE, H_PARTNER]:
            intent = {"default_action": "allow", "default_auth": "Exempt",
                      "rules": [{"name": "covert-drop", "priority": 10, "kind": "access",
                                 "match": {"fqdn": h}, "action": "drop"}]}
            self.add(
                f"Covert drop of {role[h]} ({h})",
                f"Silently reset connections to '{h}' (no block page) for a covert-deny posture.",
                "Silent-drop actions are used for covert containment in mature SWGs.",
                "Drop action", ["drop", "http"],
                intent, [_v("d", "http", h)], _fp("W2-drop", h))

    def build_full(self):
        # base validated families first
        super().build()
        # parametric matrices
        self.m_fqdn_block(); self.m_allowlist(); self.m_categories(); self.m_source()
        self.m_precedence(); self.m_tls(); self.m_schedule(); self.m_compound()
        self.m_files(); self.m_actions(); self.m_streaming(); self.m_boundary()
        self.m_blocklist(); self.m_methods()
        # densification
        self.m_https_variants(); self.m_allowlist_more(); self.m_cat_guest()
        self.m_tls_more(); self.m_schedule_more(); self.m_compound_more()
        self.m_tenant(); self.m_observability(); self.m_concurrency()
        self.m_persistence(); self.m_extra_bulk(); self.m_wide(); self.m_wide2(); self.m_wide3(); self.m_limitations()
        # gap families
        self.g_socks5_bypass(); self.g_identity_scrub(); self.g_object_lifecycle()
        self.g_conflict(); self.g_redirect_safety()
        return self.out


if __name__ == "__main__":
    g = FullGen()
    scs = g.build_full()
    caps = {}
    for s in scs:
        for c in s["capabilities"]:
            caps[c] = caps.get(c, 0) + 1
    auth = sum(1 for s in scs if s["requires_auth"])
    print(f"TOTAL scenarios: {len(scs)}  (unique fingerprints: {len(g.seen)}, auth: {auth})")
    print(f"capability coverage: {len(caps)} tags")
    for k in sorted(caps):
        print(f"  {k:26} {caps[k]}")
