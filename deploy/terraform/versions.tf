terraform {
  required_version = ">= 1.6"

  required_providers {
    # v4.52: hand-written, well-documented schemas — deliberately pinned over the
    # v5.x OpenAPI-generated rewrite for least-churn `terraform validate` on this
    # declarations-only skeleton. Trade-off (v4 is on the deprecation path) is
    # accepted for M0 stability; revisit at the R2 activation (M0-PR5 runbook).
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }
}
