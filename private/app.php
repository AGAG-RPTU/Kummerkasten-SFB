<?php
// JSON API. Every request is a POST with a JSON object carrying an 'action'.
// The server stores only what the browser hands it: ciphertexts, sealed keys,
// public keys. It checks signatures so that nobody without the codeword or a
// staff key can write, but it cannot read anything.

declare(strict_types=1);

const PROTOCOL = 'kk1';
const SENDER = 'sender';
// D: '$' must not accept a trailing newline.
const STAFF_ID_PATTERN = '/^(?!sender$)[a-z][a-z0-9_]{0,31}$/D';
const CONV_ID_PATTERN = '/^[0-9a-f]{64}$/D';
const SCHEMA_VERSION = 3;

const HOUR = 3600;
const DAY = 86400;
const CLOCK_SKEW = 300;                 // seconds accepted for signed timestamps
const MAX_REQUEST_BYTES = 262144;
const MAX_CIPHERTEXT_BYTES = 65536;
const SEALED_KEY_BYTES = SODIUM_CRYPTO_BOX_SEALBYTES + 32;
const POW_SALT_PATTERN = '/^[0-9a-f]{32}$/D';
const PUBLIC_ID_MIN = 100000;
const PUBLIC_ID_MAX = 999999;

const HTTP_OK = 200;
const HTTP_BAD_REQUEST = 400;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const HTTP_NOT_FOUND = 404;
const HTTP_METHOD_NOT_ALLOWED = 405;
const HTTP_CONFLICT = 409;
const HTTP_PAYLOAD_TOO_LARGE = 413;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_INTERNAL_ERROR = 500;
const HTTP_INSUFFICIENT_STORAGE = 507;
const SQLITE_CONSTRAINT = '23000';

// Used for any setting config.php leaves out, so new settings need no
// config change. See config.example.php for their meaning.
const DEFAULT_CONFIG = [
    'password_hash' => null,
    'ntfy_url' => null,
    'pow' => ['bits' => 17, 'count' => 16, 'ttl' => 3600, 'step' => 5],
    'retention' => ['closed_days' => 30, 'inactive_days' => 365, 'error_log_days' => 7],
    'limits' => [
        'creates_per_hour' => 100,
        'messages_per_conversation' => 200,
        'conversation_bytes' => 1000000,
        'sender_messages_per_hour' => 20,
        'database_bytes' => 200000000,
    ],
];

final class HttpError extends Exception
{
}

function run(string $privateDir): void
{
    ini_set('display_errors', '0');     // errors go to a log, never to the client
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    try {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            throw new HttpError('POST only', HTTP_METHOD_NOT_ALLOWED);
        }
        $body = file_get_contents('php://input', false, null, 0, MAX_REQUEST_BYTES + 1);
        if (strlen($body) > MAX_REQUEST_BYTES) {
            throw new HttpError('request too large', HTTP_PAYLOAD_TOO_LARGE);
        }
        $req = json_decode($body, true);
        if (!is_array($req)) {
            throw new HttpError('invalid JSON', HTTP_BAD_REQUEST);
        }

        $config = array_replace_recursive(DEFAULT_CONFIG, require getenv('KK_CONFIG') ?: $privateDir . '/config.php');
        keep_own_error_log(dirname($config['db']), $config['retention']['error_log_days']);
        $db = open_db($config['db'], $privateDir . '/schema.sql');
        expire($db, $config['retention']);
        $staff = load_staff($config['keys_file']);

        $action = $req['action'] ?? null;
        $result = match ($action) {
            'challenge' => challenge($db, $config),
            'create' => create($db, $req, $config, $staff),
            'get' => get($db, $req, $staff),
            'append' => append($db, $req, $config, $staff),
            'delete' => delete($db, $req),
            'staff_list' => staff_list($db, $req, $staff),
            'staff_close' => staff_close($db, $req, $config, $staff),
            'staff_delete_vote' => staff_delete_vote($db, $req, $staff),
            'staff_rekey' => staff_rekey($db, $req, $staff),
            default => throw new HttpError('unknown action', HTTP_BAD_REQUEST),
        };

        // Not when a sender reads or deletes: the mail's time would show when.
        if (!in_array($action, ['get', 'delete'], true)) {
            remind($db, $config, $staff);
        }
        respond(HTTP_OK, $result);
    } catch (HttpError $e) {
        respond($e->getCode(), ['error' => $e->getMessage()]);
    } catch (Throwable $e) {
        log_error($e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
        respond(HTTP_INTERNAL_ERROR, ['error' => 'internal error']);
    }
}

function respond(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
}

// ------------------------------------------------------------------ actions

// A proof-of-work challenge, plus whether the SFB access password is
// switched on (password_hash set in the config).
function challenge(PDO $db, array $config): array
{
    $pow = $config['pow'];
    $bits = required_bits($db, $config);
    $salt = bin2hex(random_bytes(16));
    $expires = time() + $pow['ttl'];
    return [
        'salt' => $salt,
        'bits' => $bits,
        'count' => $pow['count'],
        'expires' => $expires,
        'signature' => pow_signature($config, $salt, $bits, $pow['count'], $expires),
        'password_required' => !empty($config['password_hash']),
    ];
}

// Each `step` new conversations this hour double the work for the next one,
// so a flood slows itself down instead of locking everyone out at once.
function required_bits(PDO $db, array $config): int
{
    return $config['pow']['bits'] + intdiv(counter($db, 'create'), $config['pow']['step']);
}

// Senders cannot write once the database reaches its size limit; trusted
// persons still can, so they can answer and delete.
function require_storage(PDO $db, array $config): void
{
    $size = (int)$db->query('PRAGMA page_count')->fetchColumn() * (int)$db->query('PRAGMA page_size')->fetchColumn();
    if ($size >= $config['limits']['database_bytes']) {
        throw new HttpError('storage full, try again later', HTTP_INSUFFICIENT_STORAGE);
    }
}

function create(PDO $db, array $req, array $config, array $staff): array
{
    require_storage($db, $config);

    // Checked before the password, so every guess costs a solved challenge too.
    verify_pow($db, $req['pow'] ?? null, $config);

    // No lockout after wrong passwords: a global one would let anyone block
    // everybody. The password only keeps out spam; bcrypt slows guessing.
    if (!empty($config['password_hash'])
        && !password_verify(trim((string)($req['password'] ?? '')), $config['password_hash'])) {
        throw new HttpError('wrong password', HTTP_UNAUTHORIZED);
    }
    $convId = conv_id_field($req);
    $signPk = b64_field($req, 'sender_sign_pk', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
    $ciphertext = ciphertext_field($req);
    verify(append_statement($convId, 1, SENDER, $ciphertext), b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES), $signPk);

    // The sender chooses the recipients: a key for each, at least one, all in
    // keys.json. Whether each key really opens is only checkable by its
    // recipient.
    $sealed = $req['sealed_keys'] ?? null;
    if (!is_array($sealed) || !$sealed || array_diff_key($sealed, $staff)) {
        throw new HttpError('sealed_keys must name at least one trusted person from keys.json', HTTP_BAD_REQUEST);
    }
    foreach (array_keys($sealed) as $id) {
        $sealed[$id] = b64_field($sealed, (string)$id, SEALED_KEY_BYTES);
    }

    $now = now_hour();
    $db->exec('BEGIN IMMEDIATE');
    try {
        if (counter($db, 'create') >= $config['limits']['creates_per_hour']) {
            throw new HttpError('too many new conversations, try again later', HTTP_TOO_MANY_REQUESTS);
        }
        if (find_conversation($db, $convId)) {
            throw new HttpError('conversation exists', HTTP_CONFLICT);
        }
        $publicId = unused_public_id($db);
        query($db, 'INSERT INTO conversations (conv_id, public_id, created_at, updated_at, sender_sign_pk)
                    VALUES (?, ?, ?, ?, ?)', [$convId, $publicId, $now, $now, b64($signPk)]);
        foreach ($sealed as $id => $key) {
            query($db, 'INSERT INTO recipient_keys (conv_id, staff_id, sealed_key) VALUES (?, ?, ?)',
                [$convId, $id, b64($key)]);
        }
        insert_message($db, $convId, 1, SENDER, $ciphertext, $now);
        count_up($db, 'create');
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    }

    notify($db, $config, $staff, array_keys($sealed));
    return ['public_id' => $publicId];
}

function get(PDO $db, array $req, array $staff): array
{
    $conv = find_conversation($db, conv_id_field($req)) ?? throw new HttpError('not found', HTTP_NOT_FOUND);
    return [
        'public_id' => $conv['public_id'],
        'status' => $conv['status'],
        'recipients' => recipients($db, $conv['conv_id'], $staff),
        'messages' => messages($db, $conv['conv_id']),
    ];
}

function append(PDO $db, array $req, array $config, array $staff): array
{
    $convId = conv_id_field($req);
    $seq = $req['seq'] ?? null;
    if (!is_int($seq) || $seq < 2) {
        throw new HttpError('invalid seq', HTTP_BAD_REQUEST);
    }
    $author = $req['author'] ?? null;
    if (!is_string($author) || ($author !== SENDER && !isset($staff[$author]))) {
        throw new HttpError('invalid author', HTTP_BAD_REQUEST);
    }
    $ciphertext = ciphertext_field($req);
    $signature = b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES);

    $conv = find_conversation($db, $convId) ?? throw new HttpError('not found', HTTP_NOT_FOUND);
    if ($author === SENDER) {
        require_storage($db, $config);
    } else {
        require_recipient($db, $convId, $author);
    }
    $signPk = $author === SENDER ? unb64($conv['sender_sign_pk']) : $staff[$author]['sign'];
    verify(append_statement($convId, $seq, $author, $ciphertext), $signature, $signPk);

    // IMMEDIATE takes the write lock now, so two replies cannot both see the
    // same last seq.
    $db->exec('BEGIN IMMEDIATE');
    try {
        $last = (int)query($db, 'SELECT MAX(seq) FROM messages WHERE conv_id = ?', [$convId])->fetchColumn();
        if ($seq !== $last + 1) {
            throw new HttpError('conversation changed, reload', HTTP_CONFLICT);
        }
        check_append_limits($db, $config['limits'], $convId, $last, $author, strlen($ciphertext));
        insert_message($db, $convId, $seq, $author, $ciphertext, now_hour());

        // Nobody should delete a message they have not seen.
        query($db, 'DELETE FROM delete_votes WHERE conv_id = ?', [$convId]);

        query($db, "UPDATE conversations SET updated_at = ?, status = 'open' WHERE conv_id = ?", [now_hour(), $convId]);
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    }

    notify($db, $config, $staff, array_diff(recipients($db, $convId, $staff), [$author]));
    return ['seq' => $seq];
}

// Bounds what one conversation can cost: messages, bytes, and sender
// messages per hour, the last so a sender cannot flood without new work.
function check_append_limits(PDO $db, array $limits, string $convId, int $last, string $author, int $bytes): void
{
    if ($last >= $limits['messages_per_conversation']) {
        throw new HttpError('conversation is full; please start a new one', HTTP_FORBIDDEN);
    }
    // Stored as base64: 4 characters per 3 bytes.
    $stored = (int)query($db, 'SELECT SUM(LENGTH(ciphertext)) FROM messages WHERE conv_id = ?', [$convId])->fetchColumn();
    if (intdiv($stored * 3, 4) + $bytes > $limits['conversation_bytes']) {
        throw new HttpError('conversation is full; please start a new one', HTTP_PAYLOAD_TOO_LARGE);
    }
    if ($author !== SENDER) {
        return;
    }
    $recent = (int)query($db, 'SELECT COUNT(*) FROM messages WHERE conv_id = ? AND author = ? AND created_at = ?',
        [$convId, SENDER, now_hour()])->fetchColumn();
    if ($recent >= $limits['sender_messages_per_hour']) {
        throw new HttpError('too many messages, try again later', HTTP_TOO_MANY_REQUESTS);
    }
}

function delete(PDO $db, array $req): array
{
    $convId = conv_id_field($req);
    $timestamp = timestamp_field($req);
    $conv = find_conversation($db, $convId) ?? throw new HttpError('not found', HTTP_NOT_FOUND);
    verify(PROTOCOL . "/delete|$convId|$timestamp", b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES),
        unb64($conv['sender_sign_pk']));

    query($db, 'DELETE FROM conversations WHERE conv_id = ?', [$convId]);
    return [];
}

function staff_list(PDO $db, array $req, array $staff): array
{
    $staffId = staff_field($req, $staff);
    $timestamp = timestamp_field($req);
    verify(PROTOCOL . "/list|$staffId|$timestamp", b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES),
        $staff[$staffId]['sign']);

    // They are about to see everything new, so the next news is mailed again.
    query($db, 'DELETE FROM pending_notifications WHERE staff_id = ?', [$staffId]);

    $rows = query($db, 'SELECT c.conv_id, c.public_id, c.status, c.created_at, c.updated_at, k.sealed_key
                        FROM conversations c JOIN recipient_keys k ON k.conv_id = c.conv_id AND k.staff_id = ?
                        ORDER BY c.updated_at DESC, c.public_id', [$staffId])->fetchAll();
    // Metadata only; staff fetch a conversation's messages with 'get'. One
    // response holding everything would grow without bound.
    foreach ($rows as &$row) {
        $last = query($db, 'SELECT seq, author FROM messages WHERE conv_id = ? ORDER BY seq DESC LIMIT 1',
            [$row['conv_id']])->fetch();
        $row['last_seq'] = $last['seq'];
        $row['last_author'] = $last['author'];
        $row['recipients'] = recipients($db, $row['conv_id'], $staff);
        $row['delete_votes'] = query($db, 'SELECT staff_id FROM delete_votes WHERE conv_id = ? ORDER BY staff_id',
            [$row['conv_id']])->fetchAll(PDO::FETCH_COLUMN);
    }
    return ['conversations' => $rows];
}

function staff_close(PDO $db, array $req, array $config, array $staff): array
{
    $staffId = staff_field($req, $staff);
    $timestamp = timestamp_field($req);
    $publicId = $req['public_id'] ?? null;
    $lastSeq = $req['last_seq'] ?? null;
    if (!is_int($publicId) || !is_int($lastSeq)) {
        throw new HttpError('invalid public_id or last_seq', HTTP_BAD_REQUEST);
    }
    verify(PROTOCOL . "/close|$staffId|$publicId|$lastSeq|$timestamp",
        b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES), $staff[$staffId]['sign']);

    $convId = query($db, 'SELECT conv_id FROM conversations WHERE public_id = ?', [$publicId])->fetchColumn()
        ?: throw new HttpError('not found', HTTP_NOT_FOUND);
    require_recipient($db, $convId, $staffId);

    // Naming the last message makes a replayed close fail once the sender wrote again.
    $db->exec('BEGIN IMMEDIATE');
    try {
        $last = (int)query($db, 'SELECT MAX(seq) FROM messages WHERE conv_id = ?', [$convId])->fetchColumn();
        if ($lastSeq !== $last) {
            throw new HttpError('conversation changed, reload', HTTP_CONFLICT);
        }
        query($db, "UPDATE conversations SET status = 'closed', updated_at = ? WHERE conv_id = ?", [now_hour(), $convId]);
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    }

    // One person can shorten the retention, so the others should know.
    notify($db, $config, $staff, array_diff(recipients($db, $convId, $staff), [$staffId]));
    return [];
}

// Staff delete a conversation only when all of them agree: each casts a
// signed vote, and the last missing vote deletes it. Votes are bound to the
// last message and cleared by any new one.
function staff_delete_vote(PDO $db, array $req, array $staff): array
{
    $staffId = staff_field($req, $staff);
    $timestamp = timestamp_field($req);
    $publicId = $req['public_id'] ?? null;
    $lastSeq = $req['last_seq'] ?? null;
    $vote = $req['vote'] ?? null;
    if (!is_int($publicId) || !is_int($lastSeq) || !is_bool($vote)) {
        throw new HttpError('invalid public_id, last_seq or vote', HTTP_BAD_REQUEST);
    }
    $voteWord = $vote ? 'yes' : 'no';
    verify(PROTOCOL . "/delete-vote|$staffId|$publicId|$lastSeq|$voteWord|$timestamp",
        b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES), $staff[$staffId]['sign']);

    $convId = query($db, 'SELECT conv_id FROM conversations WHERE public_id = ?', [$publicId])->fetchColumn()
        ?: throw new HttpError('not found', HTTP_NOT_FOUND);
    require_recipient($db, $convId, $staffId);

    $db->exec('BEGIN IMMEDIATE');
    try {
        $last = (int)query($db, 'SELECT MAX(seq) FROM messages WHERE conv_id = ?', [$convId])->fetchColumn();
        if ($lastSeq !== $last) {
            throw new HttpError('conversation changed, reload', HTTP_CONFLICT);
        }
        if ($vote) {
            query($db, 'INSERT OR IGNORE INTO delete_votes (conv_id, staff_id) VALUES (?, ?)', [$convId, $staffId]);
        } else {
            query($db, 'DELETE FROM delete_votes WHERE conv_id = ? AND staff_id = ?', [$convId, $staffId]);
        }
        $votes = query($db, 'SELECT staff_id FROM delete_votes WHERE conv_id = ?', [$convId])->fetchAll(PDO::FETCH_COLUMN);
        $deleted = !array_diff(recipients($db, $convId, $staff), $votes);
        if ($deleted) {
            query($db, 'DELETE FROM conversations WHERE conv_id = ?', [$convId]);
        }
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    }
    return ['deleted' => $deleted];
}

// After a trusted person's key changed (same id, new keys in keys.json),
// their browser opens each conversation key with the previous passphrase and
// seals it to the current key; this stores the new copy. Signed with the
// current key, so a leaked previous passphrase alone cannot do it. It only
// replaces the caller's own copy and so grants no one new access.
function staff_rekey(PDO $db, array $req, array $staff): array
{
    $staffId = staff_field($req, $staff);
    $timestamp = timestamp_field($req);
    $publicId = $req['public_id'] ?? null;
    if (!is_int($publicId)) {
        throw new HttpError('invalid public_id', HTTP_BAD_REQUEST);
    }
    $sealed = b64_field($req, 'sealed_key', SEALED_KEY_BYTES);
    verify(PROTOCOL . "/rekey|$staffId|$publicId|" . hash('sha256', $sealed) . "|$timestamp",
        b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES), $staff[$staffId]['sign']);

    $convId = query($db, 'SELECT conv_id FROM conversations WHERE public_id = ?', [$publicId])->fetchColumn()
        ?: throw new HttpError('not found', HTTP_NOT_FOUND);
    require_recipient($db, $convId, $staffId);
    query($db, 'UPDATE recipient_keys SET sealed_key = ? WHERE conv_id = ? AND staff_id = ?',
        [b64($sealed), $convId, $staffId]);
    return [];
}

// Who can read a conversation: staff who hold its key and are still in
// keys.json. They get its notifications, and deleting it needs all their
// votes; someone removed from keys.json cannot block that.
function recipients(PDO $db, string $convId, array $staff): array
{
    $recipients = query($db, 'SELECT staff_id FROM recipient_keys WHERE conv_id = ? ORDER BY staff_id', [$convId])
        ->fetchAll(PDO::FETCH_COLUMN);
    return array_values(array_intersect($recipients, array_keys($staff)));
}

// A trusted person added after a conversation started holds no key for it
// and must not act on it.
function require_recipient(PDO $db, string $convId, string $staffId): void
{
    if (!query($db, 'SELECT 1 FROM recipient_keys WHERE conv_id = ? AND staff_id = ?', [$convId, $staffId])->fetchColumn()) {
        throw new HttpError('not a recipient of this conversation', HTTP_FORBIDDEN);
    }
}

// ------------------------------------------------------------------ crypto

// Must match appendStatement() in public/js/crypto.js.
function append_statement(string $convId, int $seq, string $author, string $ciphertext): string
{
    return PROTOCOL . "/append|$convId|$seq|$author|" . hash('sha256', $ciphertext);
}

function verify(string $statement, string $signature, string $publicKey): void
{
    if (!sodium_crypto_sign_verify_detached($signature, $statement, $publicKey)) {
        throw new HttpError('bad signature', HTTP_FORBIDDEN);
    }
}

// keys.json: {"staff": [{"id": ..., "name": ..., "email": ..., "box": b64, "sign": b64}, ...]}
function load_staff(string $file): array
{
    $data = json_decode((string)file_get_contents($file), true, 8, JSON_THROW_ON_ERROR);
    $staff = [];
    foreach ($data['staff'] as $entry) {
        if (!preg_match(STAFF_ID_PATTERN, $entry['id'])) {
            throw new RuntimeException("invalid staff id in keys.json");
        }
        $staff[$entry['id']] = [
            'sign' => unb64($entry['sign']),
            'email' => is_string($entry['email'] ?? null) ? $entry['email'] : null,
        ];
    }
    return $staff;
}

// ------------------------------------------------------------------ proof of work
// Must match public/js/pow.js.

function pow_signature(array $config, string $salt, int $bits, int $count, int $expires): string
{
    return hash_hmac('sha256', PROTOCOL . "/pow|$salt|$bits|$count|$expires", $config['pow_secret']);
}

function verify_pow(PDO $db, mixed $pow, array $config): void
{
    $valid = is_array($pow)
        && is_string($pow['salt'] ?? null) && preg_match(POW_SALT_PATTERN, $pow['salt'])
        && is_int($pow['bits'] ?? null) && is_int($pow['count'] ?? null) && is_int($pow['expires'] ?? null)
        && is_string($pow['signature'] ?? null) && is_array($pow['nonces'] ?? null);
    if (!$valid) {
        throw new HttpError('missing or malformed proof of work', HTTP_BAD_REQUEST);
    }
    ['salt' => $salt, 'bits' => $bits, 'count' => $count, 'expires' => $expires, 'nonces' => $nonces] = $pow;

    // Signed by us, not expired, and at least as hard as currently configured.
    if (!hash_equals(pow_signature($config, $salt, $bits, $count, $expires), $pow['signature'])
        || $bits < required_bits($db, $config) || $count < $config['pow']['count']) {
        throw new HttpError('invalid proof of work', HTTP_FORBIDDEN);
    }
    if ($expires < time()) {
        throw new HttpError('proof of work expired', HTTP_FORBIDDEN);
    }
    if (!array_is_list($nonces) || count($nonces) !== $count) {
        throw new HttpError('invalid proof of work', HTTP_FORBIDDEN);
    }
    foreach ($nonces as $i => $nonce) {
        if (!is_int($nonce) || $nonce < 0 || leading_zero_bits(hash('sha256', "$salt|$i|$nonce", true)) < $bits) {
            throw new HttpError('invalid proof of work', HTTP_FORBIDDEN);
        }
    }

    // Each challenge counts once. The row is kept until the hour after expiry;
    // an exact time would reveal when the sender opened the page.
    try {
        query($db, 'INSERT INTO used_challenges (salt, expires) VALUES (?, ?)',
            [$salt, intdiv($expires + HOUR - 1, HOUR) * HOUR]);
    } catch (PDOException $e) {
        if ($e->getCode() !== SQLITE_CONSTRAINT) {
            throw $e;
        }
        throw new HttpError('proof of work already used', HTTP_FORBIDDEN);
    }
}

function leading_zero_bits(string $hash): int
{
    $bits = 0;
    foreach (unpack('C*', $hash) as $byte) {
        if ($byte !== 0) {
            return $bits + 8 - strlen(decbin($byte));
        }
        $bits += 8;
    }
    return $bits;
}

// ------------------------------------------------------------------ input

function conv_id_field(array $req): string
{
    $id = $req['conv_id'] ?? null;
    if (!is_string($id) || !preg_match(CONV_ID_PATTERN, $id)) {
        throw new HttpError('invalid conv_id', HTTP_BAD_REQUEST);
    }
    return $id;
}

function staff_field(array $req, array $staff): string
{
    $id = $req['staff_id'] ?? null;
    if (!is_string($id) || !isset($staff[$id])) {
        throw new HttpError('unknown staff_id', HTTP_FORBIDDEN);
    }
    return $id;
}

function timestamp_field(array $req): int
{
    $ts = $req['timestamp'] ?? null;
    if (!is_int($ts) || abs(time() - $ts) > CLOCK_SKEW) {
        throw new HttpError('timestamp out of range; check your clock', HTTP_FORBIDDEN);
    }
    return $ts;
}

function ciphertext_field(array $req): string
{
    $ct = b64_field($req, 'ciphertext');
    if (strlen($ct) > MAX_CIPHERTEXT_BYTES) {
        throw new HttpError('message too long', HTTP_PAYLOAD_TOO_LARGE);
    }
    return $ct;
}

// Returns the decoded bytes; $length, if given, is the exact byte count required.
function b64_field(array $req, string $name, ?int $length = null): string
{
    $value = $req[$name] ?? null;
    $bytes = is_string($value) ? base64_decode($value, true) : false;
    if ($bytes === false || $bytes === '' || ($length !== null && strlen($bytes) !== $length)) {
        throw new HttpError("invalid $name", HTTP_BAD_REQUEST);
    }
    return $bytes;
}

// ------------------------------------------------------------------ storage

function open_db(string $file, string $schemaFile): PDO
{
    $db = new PDO('sqlite:' . $file, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_STRINGIFY_FETCHES => false,
    ]);
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA secure_delete = ON');     // overwrite deleted content in the file
    $db->exec('PRAGMA busy_timeout = 5000');
    migrate($db, (string)file_get_contents($schemaFile));
    return $db;
}

// The schema is idempotent, so tables added later appear in existing
// databases. PRAGMA user_version marks changes that need a rebuild:
//   2  tables WITHOUT ROWID, so storage order follows the random keys
//      instead of revealing which row was inserted when
//   3  conversations.notified_at is gone
function migrate(PDO $db, string $schema): void
{
    $version = (int)$db->query('PRAGMA user_version')->fetchColumn();
    $tables = $db->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(PDO::FETCH_COLUMN);
    if ($version < SCHEMA_VERSION && $tables) {
        rebuild_tables($db, $tables, $schema);
    }
    $db->exec($schema);
    if ($version < SCHEMA_VERSION) {
        $db->exec('PRAGMA user_version = ' . SCHEMA_VERSION);
    }
}

// Recreates every table from the schema and copies the columns both have.
function rebuild_tables(PDO $db, array $tables, string $schema): void
{
    $db->exec('PRAGMA foreign_keys = OFF');
    $db->exec('PRAGMA legacy_alter_table = ON');     // keep references pointing at the new tables
    $db->exec('BEGIN IMMEDIATE');
    try {
        $db->exec('DROP INDEX IF EXISTS conversations_updated_at');
        foreach ($tables as $table) {
            $db->exec("ALTER TABLE \"$table\" RENAME TO \"{$table}_old\"");
        }
        $db->exec($schema);
        foreach ($tables as $table) {
            $columns = implode(', ', array_map(fn($c) => "\"$c\"",
                array_intersect(column_names($db, "{$table}_old"), column_names($db, $table))));
            $db->exec("INSERT INTO \"$table\" ($columns) SELECT $columns FROM \"{$table}_old\"");
            $db->exec("DROP TABLE \"{$table}_old\"");
        }
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    } finally {
        $db->exec('PRAGMA legacy_alter_table = OFF');
        $db->exec('PRAGMA foreign_keys = ON');
    }
}

function column_names(PDO $db, string $table): array
{
    return $db->query("SELECT name FROM pragma_table_info('$table')")->fetchAll(PDO::FETCH_COLUMN);
}

function query(PDO $db, string $sql, array $params = []): PDOStatement
{
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    return $stmt;
}

function find_conversation(PDO $db, string $convId): ?array
{
    return query($db, 'SELECT * FROM conversations WHERE conv_id = ?', [$convId])->fetch() ?: null;
}

function messages(PDO $db, string $convId): array
{
    return query($db, 'SELECT seq, author, created_at, ciphertext FROM messages WHERE conv_id = ? ORDER BY seq',
        [$convId])->fetchAll();
}

function insert_message(PDO $db, string $convId, int $seq, string $author, string $ciphertext, int $now): void
{
    query($db, 'INSERT INTO messages (conv_id, seq, author, created_at, ciphertext) VALUES (?, ?, ?, ?, ?)',
        [$convId, $seq, $author, $now, b64($ciphertext)]);
}

function unused_public_id(PDO $db): int
{
    do {
        $id = random_int(PUBLIC_ID_MIN, PUBLIC_ID_MAX);
    } while (query($db, 'SELECT 1 FROM conversations WHERE public_id = ?', [$id])->fetchColumn());
    return $id;
}

// Runs on every request; there is no cron on shared webspace.
function expire(PDO $db, array $retention): void
{
    query($db, "DELETE FROM conversations
                WHERE (status = 'closed' AND updated_at < ?) OR updated_at < ?", [
        time() - $retention['closed_days'] * DAY,
        time() - $retention['inactive_days'] * DAY,
    ]);
    query($db, 'DELETE FROM counters WHERE hour < ?', [now_hour() - DAY]);
    query($db, 'DELETE FROM used_challenges WHERE expires < ?', [time()]);
}

function counter(PDO $db, string $name): int
{
    return (int)query($db, 'SELECT value FROM counters WHERE name = ? AND hour = ?', [$name, now_hour()])->fetchColumn();
}

function count_up(PDO $db, string $name): void
{
    query($db, 'INSERT INTO counters (name, hour, value) VALUES (?, ?, 1)
                ON CONFLICT (name, hour) DO UPDATE SET value = value + 1', [$name, now_hour()]);
}

// Stored times are coarse so they are less useful for linking a message to a person.
function now_hour(): int
{
    return rounded_hour(time());
}

// Nearest full hour: 1:30:01-2:30:00 becomes 2:00.
function rounded_hour(int $time): int
{
    return intdiv($time + HOUR / 2 - 1, HOUR) * HOUR;
}

function b64(string $bytes): string
{
    return base64_encode($bytes);
}

function unb64(string $text): string
{
    return base64_decode($text, true);
}

// ------------------------------------------------------------------ error log

const FATAL_ERRORS = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_RECOVERABLE_ERROR;

// PHP's own log is the web server's error log, which puts the visitor's IP
// address and the exact time on every line. From here on errors go to a
// daily file in $dir instead, kept for $days days. Before the config is
// read there is no $dir, and errors still go to PHP's log.
function keep_own_error_log(string $dir, int $days): void
{
    error_log_dir($dir);
    ini_set('log_errors', '0');

    set_error_handler(function (int $level, string $message, string $file, int $line): bool {
        if (error_reporting() & $level) {       // not silenced with @
            log_error("$message at $file:$line");
        }
        return true;
    });

    // Fatal errors never reach the handler above.
    register_shutdown_function(function (): void {
        $last = error_get_last();
        if ($last !== null && $last['type'] & FATAL_ERRORS) {
            log_error("{$last['message']} at {$last['file']}:{$last['line']}");
        }
    });

    // The dates in the names sort like the names.
    $oldest = error_log_file($dir, time() - $days * DAY);
    foreach (glob("$dir/error-*.log") ?: [] as $file) {
        if ($file < $oldest) {
            unlink($file);
        }
    }
}

// The time is rounded like every stored time, so a line does not say when
// exactly someone wrote.
function log_error(string $message): void
{
    $dir = error_log_dir();
    if ($dir === null) {
        error_log("kummerkasten: $message");
        return;
    }
    $line = gmdate('Y-m-d H:i', now_hour()) . " UTC $message\n";
    @file_put_contents(error_log_file($dir, now_hour()), $line, FILE_APPEND | LOCK_EX);
}

function error_log_file(string $dir, int $time): string
{
    return "$dir/error-" . gmdate('Y-m-d', $time) . '.log';
}

// Where log_error() writes; null until keep_own_error_log() has set it.
function error_log_dir(?string $set = null): ?string
{
    static $dir = null;
    $dir = $set ?? $dir;
    return $dir;
}

// ------------------------------------------------------------------ notifications

// [subject, first line of the mail]
const MAIL_NEWS = ['New activity', 'There is new activity in the Kummerkasten.'];
const MAIL_REMINDER = ['Reminder: a message waits for an answer',
    'A message in the Kummerkasten still waits for an answer.'];

// A trusted person gets one mail and then none until they log in, so a flood
// of messages cannot flood mailboxes. The mail names no conversation, because
// it stands for everything that follows it too.
function notify(PDO $db, array $config, array $staff, array $staffIds): void
{
    send_mail($config, $staff, array_filter($staffIds, fn($id) => claim_mail($db, $id)), MAIL_NEWS);
}

// Runs on requests, as there is no cron: whoever was mailed a day ago, has
// not logged in since and can read a message nobody answered is mailed again.
function remind(PDO $db, array $config, array $staff): void
{
    $mailed = query($db, 'SELECT staff_id FROM pending_notifications WHERE mailed_at <= ?', [now_hour() - DAY])
        ->fetchAll(PDO::FETCH_COLUMN);
    $due = array_filter($mailed, fn($id) => isset($staff[$id]) && awaits_answer($db, $id) && claim_mail($db, $id));
    send_mail($config, $staff, $due, MAIL_REMINDER);
}

// Whether a mail to this person may go out now: none since their last login,
// or the last one is a day old. Records the mail, so call it once per mail.
function claim_mail(PDO $db, string $staffId): bool
{
    $claimed = query($db, 'INSERT INTO pending_notifications (staff_id, mailed_at) VALUES (?, ?)
                           ON CONFLICT (staff_id) DO UPDATE SET mailed_at = excluded.mailed_at
                           WHERE pending_notifications.mailed_at <= ?', [$staffId, now_hour(), now_hour() - DAY]);
    return $claimed->rowCount() === 1;
}

// An open conversation they can read whose last message is the sender's.
function awaits_answer(PDO $db, string $staffId): bool
{
    return (bool)query($db, "SELECT 1 FROM conversations c
                             JOIN recipient_keys k ON k.conv_id = c.conv_id AND k.staff_id = ?
                             WHERE c.status = 'open' AND ? =
                                 (SELECT author FROM messages WHERE conv_id = c.conv_id ORDER BY seq DESC LIMIT 1)
                             LIMIT 1", [$staffId, SENDER])->fetchColumn();
}

// Best effort: a failed notification must not fail the request, and staff see
// new messages on the staff page anyway. Never put message content here.
function send_mail(array $config, array $staff, array $staffIds, array $text): void
{
    if (!$staffIds) {
        return;
    }
    [$subject, $firstLine] = $text;

    $body = "$firstLine\n\nRead it at {$config['site_url']}staff\n\n"
        . "Until you log in there you get no further mail, except a reminder every\n"
        . "24 hours while a message waits for an answer.\n\n"
        . "This notification contains no message content.\n";

    $headers = [
        'From' => $config['mail_from'],
        'Content-Type' => 'text/plain; charset=UTF-8',
        'Auto-Submitted' => 'auto-generated',
    ];
    // -f sets the envelope sender. PHP's default, user@hostname, is no valid
    // address on most hosts, and mail servers then refuse the mail.
    $sender = '-f' . $config['mail_from'];
    foreach ($staffIds as $id) {
        $to = $staff[$id]['email'];
        if ($to !== null && !@mail($to, "[Kummerkasten] $subject", $body, $headers, $sender)) {
            log_error("mail to staff '$id' failed");
        }
    }

    if (!empty($config['ntfy_url'])) {
        $ch = curl_init($config['ntfy_url']);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $subject,
            CURLOPT_HTTPHEADER => ['Title: Kummerkasten', 'Click: ' . $config['site_url'] . 'staff'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);
        if (curl_exec($ch) === false) {
            log_error('ntfy failed: ' . curl_error($ch));
        }
    }
}
