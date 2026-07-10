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

  # The rules block is required (MinItems 1).
  rules {
    creation         = true
    update           = true
    deletion         = true
    non_fast_forward = true
  }
}
