-- 0001_init.sql — schema for TNC-server (crypto + web UI)

CREATE TABLE IF NOT EXISTS devices (
    id            TEXT PRIMARY KEY,
    password_hash TEXT        NOT NULL DEFAULT '',
    public_key    TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ,
    in_service    BOOLEAN     NOT NULL DEFAULT false,
    updated_by    UUID,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_devices_deleted_at  ON devices (deleted_at);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen   ON devices (last_seen_at);
CREATE INDEX IF NOT EXISTS idx_devices_updated_by  ON devices (updated_by);

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL CHECK (role IN ('user', 'privileged', 'admin')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_devices_updated_by') THEN
        ALTER TABLE devices
        ADD CONSTRAINT fk_devices_updated_by
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;
    END IF;
END $$;
