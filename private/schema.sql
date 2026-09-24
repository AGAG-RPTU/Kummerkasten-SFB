-- Run on every request, so every statement must be idempotent. Other
-- changes need a migration in migrate() in app.php. Tables are WITHOUT ROWID,
-- so storage order follows the random keys, not insertion time.
--
-- Times are Unix seconds rounded to the nearest hour. Keys, ciphertexts and
-- signatures are stored as base64 text.

CREATE TABLE IF NOT EXISTS conversations (
    conv_id         TEXT PRIMARY KEY,           -- hex, derived from the codeword
    public_id       INTEGER NOT NULL UNIQUE,    -- shown to staff and in notifications
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    notified_at     INTEGER,                    -- last sender notification; NULL after a staff reply
    sender_sign_pk  TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS conversations_updated_at ON conversations (updated_at);

CREATE TABLE IF NOT EXISTS recipient_keys (
    conv_id         TEXT NOT NULL REFERENCES conversations (conv_id) ON DELETE CASCADE,
    staff_id        TEXT NOT NULL,
    sealed_key      TEXT NOT NULL,
    PRIMARY KEY (conv_id, staff_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS messages (
    conv_id         TEXT NOT NULL REFERENCES conversations (conv_id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    author          TEXT NOT NULL,              -- 'sender' or a staff id
    created_at      INTEGER NOT NULL,
    ciphertext      TEXT NOT NULL,
    PRIMARY KEY (conv_id, seq)
) WITHOUT ROWID;

-- Global rate limiting; no per-client data.
CREATE TABLE IF NOT EXISTS counters (
    name            TEXT NOT NULL,              -- 'create' or 'notify'
    hour            INTEGER NOT NULL,
    value           INTEGER NOT NULL,
    PRIMARY KEY (name, hour)
) WITHOUT ROWID;

-- One row per trusted person who wants the conversation deleted.
CREATE TABLE IF NOT EXISTS delete_votes (
    conv_id         TEXT NOT NULL REFERENCES conversations (conv_id) ON DELETE CASCADE,
    staff_id        TEXT NOT NULL,
    PRIMARY KEY (conv_id, staff_id)
) WITHOUT ROWID;

-- Proof-of-work challenges already spent, kept until the hour after expiry.
CREATE TABLE IF NOT EXISTS used_challenges (
    salt            TEXT PRIMARY KEY,
    expires         INTEGER NOT NULL
) WITHOUT ROWID;
