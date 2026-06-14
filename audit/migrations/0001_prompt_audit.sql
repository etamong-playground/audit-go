-- Prompt audit log. user/IP are stored as keyed hashes (HMAC-SHA256, truncated)
-- so per-actor abuse can be correlated without retaining raw PII. The prompt
-- text is kept (mask PII before insert) for spam/pattern analysis.
CREATE TABLE IF NOT EXISTS prompt_audit (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_hash    TEXT,
    ip_hash      TEXT,
    domain       TEXT NOT NULL,
    prompt       TEXT NOT NULL,
    ok           BOOLEAN NOT NULL,
    error        TEXT,
    duration_ms  BIGINT NOT NULL DEFAULT 0,
    llm_model    TEXT,
    attempts     INT NOT NULL DEFAULT 0,
    -- App-specific output metrics (draw uses nodes/edges, xatu uses sessions,
    -- minccino uses receipt totals). Keeps the table portable.
    extra        JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- populated by the per-app daily analyzer CronJob
    spam_score   REAL,
    spam_label   TEXT,
    analyzed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS prompt_audit_created_at_idx ON prompt_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS prompt_audit_user_hash_idx ON prompt_audit (user_hash);
CREATE INDEX IF NOT EXISTS prompt_audit_unanalyzed_idx ON prompt_audit (created_at) WHERE analyzed_at IS NULL;

-- Versioned system prompts, editable from the per-app backoffice. The app
-- falls back to compiled-in defaults when no active row exists for a domain.
CREATE TABLE IF NOT EXISTS system_prompts (
    id          BIGSERIAL PRIMARY KEY,
    domain      TEXT NOT NULL,
    body        TEXT NOT NULL,
    version     INT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by  TEXT,
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS system_prompts_active_idx
    ON system_prompts (domain) WHERE active;
