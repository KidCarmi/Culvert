# Release-catalog R2 bucket. In the pinned cloudflare v4 provider, account_id + name
# are the only required arguments (`location` is optional and owner-specific, left
# unset).
resource "cloudflare_r2_bucket" "release_catalog" {
  account_id = var.cloudflare_account_id
  name       = var.r2_bucket_name
}

# ── Owner-specific / version-sensitive guardrails — deferred to the activation
#    runbook (docs/operator/catalog-hosting-r2-activation.md), NOT declared here
#    because their schemas need owner detail this skeleton must not invent:
#
#   * R2 custom domain — the `cloudflare_r2_custom_domain` resource does NOT exist in
#     the pinned v4 provider (v5 only). Bind the custom domain per the runbook so it
#     publicly serves BOTH `history/stable/**` (staging — required by the dormant R2
#     publisher's verify step) AND `release-catalog/**` (the live pointer).
#   * Cache rules (cache-phase `cloudflare_ruleset`) + Smart Tiered Cache
#     (`cloudflare_tiered_cache`) — require a zone_id and a version-specific
#     `action_parameters` shape; configure per the runbook.
#   * Disable the public `r2.dev` endpoint (serve only via the custom domain).
