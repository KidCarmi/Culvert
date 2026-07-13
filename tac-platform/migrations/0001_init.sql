-- tac-platform 0001_init.sql — deterministic infra-ops spine (PostgreSQL).
-- Every domain object carries tenant_id (structural tenant isolation).
-- operation_events is append-only + hash-chained + signed; outbox commits atomically with events.

BEGIN;

CREATE TABLE workers (
    tenant_id            text NOT NULL,
    worker_id            text NOT NULL,
    environment          text NOT NULL,
    region               text NOT NULL,
    allowlisted          boolean NOT NULL DEFAULT false,
    approved_registry    text NOT NULL,
    current_image_digest text,
    known_good_digest    text,
    config               jsonb NOT NULL DEFAULT '{}'::jsonb,
    max_replicas         int NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, worker_id)
);

CREATE TABLE approved_digests (
    tenant_id    text NOT NULL,
    worker_id    text NOT NULL,
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, worker_id, image_digest),
    FOREIGN KEY (tenant_id, worker_id) REFERENCES workers(tenant_id, worker_id)
);

CREATE TABLE operations (
    id               text PRIMARY KEY,
    tenant_id        text NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('restart','deploy')),
    level            text NOT NULL CHECK (level IN ('L2','L3')),
    environment      text NOT NULL,
    region           text NOT NULL,
    worker_id        text NOT NULL,
    intent           text NOT NULL,
    state            text NOT NULL,
    current_plan_id  text,
    rollback_target  jsonb,
    idempotency_key  text NOT NULL,
    initiating_actor text NOT NULL,
    session_meta     jsonb NOT NULL DEFAULT '{}'::jsonb,
    version          bigint NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    UNIQUE (tenant_id, idempotency_key)            -- exactly-once create per tenant
);
CREATE INDEX ix_ops_worker_active ON operations (tenant_id, worker_id)
    WHERE state IN ('EXECUTION_QUEUED','EXECUTING','VALIDATING','ROLLBACK_PENDING','ROLLING_BACK');

CREATE TABLE plans (
    plan_id              text PRIMARY KEY,          -- content-addressed
    tenant_id            text NOT NULL,
    op_id                text NOT NULL REFERENCES operations(id),
    kind                 text NOT NULL,
    commit_sha           text,
    config_digest        text NOT NULL,
    provider_lock_digest text,
    target_image_digest  text,
    expected_changes     jsonb NOT NULL,
    policy_result        jsonb NOT NULL,
    review_results       jsonb NOT NULL DEFAULT '{}'::jsonb,
    rollback_target      jsonb NOT NULL,
    cost_delta_usd       numeric NOT NULL DEFAULT 0,
    health_validation    boolean NOT NULL,
    signature            text NOT NULL,            -- domain=plan
    signer_key_id        text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL
);

CREATE TABLE approvals (
    approval_id          text PRIMARY KEY,
    tenant_id            text NOT NULL,
    op_id                text NOT NULL REFERENCES operations(id),
    plan_id              text NOT NULL REFERENCES plans(plan_id),
    bound_plan_signature text NOT NULL,            -- must equal plans.signature at execute time
    approver             text NOT NULL,
    approver_is_author   boolean NOT NULL DEFAULT false,
    approver_signature   text NOT NULL,            -- domain=approval
    decision             text NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
    single_use_consumed  boolean NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    UNIQUE (op_id, plan_id)
);

CREATE TABLE leases (
    resource_key text PRIMARY KEY,                 -- tenant:env:region:worker
    tenant_id    text NOT NULL,
    holder_op_id text NOT NULL REFERENCES operations(id),
    holder_exec  text NOT NULL,
    acquired_at  timestamptz NOT NULL DEFAULT now(),
    heartbeat_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);

CREATE TABLE operation_events (
    id         bigserial PRIMARY KEY,
    tenant_id  text NOT NULL,
    op_id      text NOT NULL REFERENCES operations(id),
    seq        int NOT NULL,
    ts         timestamptz NOT NULL DEFAULT now(),
    actor      text NOT NULL,
    actor_kind text NOT NULL CHECK (actor_kind IN ('model','human','service')),
    event_type text NOT NULL,
    from_state text,
    to_state   text,
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb, -- refs only; never secrets
    prev_hash  text NOT NULL,
    hash       text NOT NULL,
    sig_domain text NOT NULL DEFAULT 'audit',
    signature  text NOT NULL,
    UNIQUE (op_id, seq)
);

-- Transactional outbox: rows committed in the SAME tx as the event they mirror.
CREATE TABLE outbox (
    id           bigserial PRIMARY KEY,            -- monotonic publish order
    tenant_id    text NOT NULL,
    op_id        text NOT NULL,
    event_seq    int NOT NULL,
    topic        text NOT NULL,
    payload      jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);
CREATE INDEX ix_outbox_unpublished ON outbox (id) WHERE published_at IS NULL;

CREATE TABLE execution_results (
    id                     bigserial PRIMARY KEY,
    tenant_id              text NOT NULL,
    op_id                  text NOT NULL REFERENCES operations(id),
    attempt                int NOT NULL DEFAULT 1,
    phase                  text NOT NULL CHECK (phase IN ('deploy','restart','rollback')),
    provider_correlation_id text,
    provider_response      jsonb,
    applied_resources      jsonb NOT NULL DEFAULT '[]'::jsonb,
    validation_result      jsonb,
    outcome                text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (op_id, attempt, phase)
);

-- Deterministic mock provider "truth" — durable + cross-process, so the reconciler
-- can read what actually happened after an executor process is killed mid-op.
CREATE TABLE provider_worker_state (
    tenant_id           text NOT NULL,
    worker_id           text NOT NULL,
    current_digest      text NOT NULL,
    healthy             boolean NOT NULL DEFAULT true,
    generation          int NOT NULL DEFAULT 1,
    last_correlation_id text,
    PRIMARY KEY (tenant_id, worker_id)
);

COMMIT;
