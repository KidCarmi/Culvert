# State backend. Local for the $0 pilot; the controlled executor holds the state
# lock during apply (in addition to the per-worker operation lease in the op DB).
# In production this becomes an object-storage backend (R2/S3) with locking —
# same desired-state, no rewrite.
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
