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

  # SEC-F7 (M1-4): a v* tag is a SIGNING CONTEXT — dispatching ci.yml at a v* tag
  # with resign=true re-signs the release catalog under the pinned
  # ci.yml@refs/tags/v* identity. So tag CREATION (not just deletion) must be
  # restricted to bypass actors. Release automation (ci.yml `auto-tag`) pushes the
  # next vX.Y.Z authenticated as RELEASE_TAG_PAT — a fine-grained PAT owned by a
  # Repository admin — so the Repository-admin role is the sole bypass actor.
  # (github-actions[bot] itself CANNOT be a repository-ruleset bypass actor, which
  # is exactly why auto-tag pushes as the PAT; see docs/operator/catalog-resign-runbook.md.)
  # Keep this in lock-step with the live ruleset: without `creation` + this bypass,
  # a `terraform apply` would silently revert SEC-F7 and re-open unrestricted tag creation.
  rules {
    creation         = true
    deletion         = true
    non_fast_forward = true
  }

  bypass_actors {
    actor_id    = 5 # built-in RepositoryRole: Admin
    actor_type  = "RepositoryRole"
    bypass_mode = "always"
  }
}
