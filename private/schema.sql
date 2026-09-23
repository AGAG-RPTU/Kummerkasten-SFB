-- Times are Unix seconds rounded down to the hour. Keys, ciphertexts and
-- signatures are stored as base64 text.

CREATE TABLE conversations (
    conv_id         TEXT PRIMARY KEY,           -- hex, derived from the codeword
    public_id       INTEGER NOT NULL UNIQUE,    -- shown to staff and in notifications
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    notified_at     INTEGER,                    -- last sender notification; NULL after a staff reply
    sender_sign_pk  TEXT NOT NULL
);
CREATE INDEX conversations_updated_at ON conversations (updated_at);

CREATE TABLE recipient_keys (
    conv_id         TEXT NOT NULL REFERENCES conversations (conv_id) ON DELETE CASCADE,
    staff_id        TEXT NOT NULL,
    sealed_key      TEXT NOT NULL,
    PRIMARY KEY (conv_id, staff_id)
);

CREATE TABLE messages (
    conv_id         TEXT NOT NULL REFERENCES conversations (conv_id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    author          TEXT NOT NULL,              -- 'sender' or a staff id
    created_at      INTEGER NOT NULL,
    ciphertext      TEXT NOT NULL,
    PRIMARY KEY (conv_id, seq)
);

-- Global rate limiting; no per-client data.
CREATE TABLE counters (
    name            TEXT NOT NULL,              -- 'create'
    hour            INTEGER NOT NULL,
    value           INTEGER NOT NULL,
    PRIMARY KEY (name, hour)
);
