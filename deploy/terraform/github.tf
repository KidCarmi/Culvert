# Protected `release` environment — the deploy boundary the release/publish jobs run
# under; requires named reviewers before a deployment proceeds.
resource "github_repository_environment" "release" {
  repository  = var.github_repository
  environment = "release"

  reviewers {
    users = var.release_reviewer_user_ids # list(number) — GitHub user IDs
    teams = var.release_reviewer_team_ids # list(number) — GitHub team IDs
  }

  # Both fields are REQUIRED whenever this block is present.
  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

# `v*` TAG protection ruleset: block out-of-policy creation, deletion, and
# non-fast-forward of release tags.
resource "github_repository_ruleset" "v_tag_protection" {
  name        = "v-tag-protection"
  repository  = var.github_repository
  target      = "tag"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["refs/tags/v*"]
      exclude = [] # required list, even when empty
    }
  }

  # Protect existing release tags WITHOUT blocking creation: ci.yml's auto-tag job
  # (github-actions[bot] pushing the next vX.Y.Z via GITHUB_TOKEN) must be able to
  # create v* tags, and this ruleset declares no bypass_actors — so `creation`/`update`
  # are intentionally left disabled. Block deletion + non-fast-forward (force-move)
  # only. (An owner who wants to restrict WHO may create release tags adds a
  # `bypass_actors` block for the release automation instead of enabling `creation`.)
  rules {
    deletion         = true
    non_fast_forward = true
  }
}
