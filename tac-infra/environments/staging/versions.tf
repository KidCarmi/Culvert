terraform {
  # OpenTofu-compatible. The proof slice uses the null provider (no cloud/cost).
  required_version = ">= 1.6.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}
