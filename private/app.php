<?php
// JSON API. Every request is a POST with a JSON object carrying an 'action'.
// The server stores only what the browser hands it: ciphertexts, sealed keys,
// public keys. It checks signatures so that nobody without the codeword or a
// staff key can write, but it cannot read anything.

declare(strict_types=1);

const PROTOCOL = 'kk1';
const SENDER = 'sender';
const STAFF_ID_PATTERN = '/^(?!sender$)[a-z][a-z0-9_]{0,31}$/';
const CONV_ID_PATTERN = '/^[0-9a-f]{64}$/';

const HOUR = 3600;
const DAY = 86400;
const CLOCK_SKEW = 300;                 // seconds accepted for signed timestamps
const MAX_REQUEST_BYTES = 262144;
const MAX_CIPHERTEXT_BYTES = 65536;
const SEALED_KEY_BYTES = SODIUM_CRYPTO_BOX_SEALBYTES + 32;
const POW_SALT_PATTERN = '/^[0-9a-f]{32}$/';
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

final class HttpError extends Exception
{
}

function run(string $privateDir): void
{
    ini_set('display_errors', '0');     // errors go to the log, never to the client
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

        $config = require getenv('KK_CONFIG') ?: $privateDir . '/config.php';
        $db = open_db($config['db'], $privateDir . '/schema.sql');
        expire($db, $config['retention']);
        $staff = load_staff($config['keys_file']);

        $result = match ($req['action'] ?? null) {
            'challenge' => challenge($config),
            'create' => create($db, $req, $config, $staff),
            'get' => get($db, $req),
            'append' => append($db, $req, $config, $staff),
            'delete' => delete($db, $req),
            'staff_list' => staff_list($db, $req, $staff),
            'staff_close' => staff_close($db, $req, $staff),
            'staff_delete_vote' => staff_delete_vote($db, $req, $staff),
            default => throw new HttpError('unknown action', HTTP_BAD_REQUEST),
        };
        respond(HTTP_OK, $result);
    } catch (HttpError $e) {
        respond($e->getCode(), ['error' => $e->getMessage()]);
    } catch (Throwable $e) {
        error_log('kummerkasten: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
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
function challenge(array $config): array
{
    $pow = $config['pow'];
    $salt = bin2hex(random_bytes(16));
    $expires = time() + $pow['ttl'];
    return [
        'salt' => $salt,
        'bits' => $pow['bits'],
        'count' => $pow['count'],
        'expires' => $expires,
        'signature' => pow_signature($config, $salt, $pow['bits'], $pow['count'], $expires),
        'password_required' => !empty($config['password_hash']),
    ];
}

function create(PDO $db, array $req, array $config, array $staff): array
{
    // Checked first, so every password guess costs a solved challenge too.
    verify_pow($db, $req['pow'] ?? null, $config);

    // No lockout after wrong passwords: a global one would let anyone block
    // everybody. The password only keeps out spam; bcrypt slows guessing.
    if (!empty($config['password_hash'])
        && !password_verify(trim((string)($req['password'] ?? '')), $config['password_hash'])) {
        throw new HttpError('wrong password', HTTP_UNAUTHORIZED);
    }
    if (counter($db, 'create') >= $config['limits']['creates_per_hour']) {
        throw new HttpError('too many new conversations, try again later', HTTP_TOO_MANY_REQUESTS);
    }

    $convId = conv_id_field($req);
    $signPk = b64_field($req, 'sender_sign_pk', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
    $ciphertext = ciphertext_field($req);
    verify(append_statement($convId, 1, SENDER, $ciphertext), b64_field($req, 'signature', SODIUM_CRYPTO_SIGN_BYTES), $signPk);

    // Every trusted person must be able to read, otherwise a tampered client
    // could quietly exclude one of them.
    $sealed = $req['sealed_keys'] ?? null;
    if (!is_array($sealed) || array_diff_key($staff, $sealed) || array_diff_key($sealed, $staff)) {
        throw new HttpError('sealed_keys must cover exactly the staff in keys.json', HTTP_BAD_REQUEST);
    }
    foreach (array_keys($staff) as $id) {
        $sealed[$id] = b64_field($sealed, $id, SEALED_KEY_BYTES);
    }

    $now = now_hour();
    $db->exec('BEGIN IMMEDIATE');
    try {
        if (find_conversation($db, $convId)) {
            throw new HttpError('conversation exists', HTTP_CONFLICT);
        }
        $publicId = unused_public_id($db);
        query($db, 'INSERT INTO conversations (conv_id, public_id, created_at, updated_at, notified_at, sender_sign_pk)
                    VALUES (?, ?, ?, ?, ?, ?)', [$convId, $publicId, $now, $now, $now, b64($signPk)]);
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

    notify($config, array_keys($staff), "New conversation #$publicId");
    return ['public_id' => $publicId];
}

function get(PDO $db, array $req): array
{
    $conv = find_conversation($db, conv_id_field($req)) ?? throw new HttpError('not found', HTTP_NOT_FOUND);
    return [
        'public_id' => $conv['public_id'],
        'status' => $conv['status'],
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
    if ($author !== SENDER) {
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
        if ($last >= $config['limits']['messages_per_conversation']) {
            throw new HttpError('conversation is full; please start a new one', HTTP_FORBIDDEN);
        }
        insert_message($db, $convId, $seq, $author, $ciphertext, now_hour());

        // Nobody should delete a message they have not seen.
        query($db, 'DELETE FROM delete_votes WHERE conv_id = ?', [$convId]);

        // Sender messages notify at most once per hour, so a flood of appends
        // cannot flood mailboxes; a staff reply re-arms the notification.
        $notify = $author !== SENDER || $conv['notified_at'] === null || $conv['notified_at'] < now_hour();
        query($db, "UPDATE conversations SET updated_at = ?, status = 'open', notified_at = ? WHERE conv_id = ?", [
            now_hour(),
            $author === SENDER ? ($notify ? now_hour() : $conv['notified_at']) : null,
            $convId,
        ]);
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    }

    if ($notify) {
        $others = array_values(array_diff(array_keys($staff), [$author]));
        $what = $author === SENDER ? 'New message' : 'New reply by a colleague';
        notify($config, $others, "$what in conversation #{$conv['public_id']}");
    }
    return ['seq' => $seq];
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

    $rows = query($db, 'SELECT c.conv_id, c.public_id, c.status, c.created_at, c.updated_at, k.sealed_key
                        FROM conversations c JOIN recipient_keys k ON k.conv_id = c.conv_id AND k.staff_id = ?
                        ORDER BY c.updated_at DESC, c.public_id', [$staffId])->fetchAll();
    foreach ($rows as &$row) {
        $row['messages'] = messages($db, $row['conv_id']);
        $row['delete_voters'] = delete_voters($db, $row['conv_id'], $staff);
        $row['delete_votes'] = query($db, 'SELECT staff_id FROM delete_votes WHERE conv_id = ? ORDER BY staff_id',
            [$row['conv_id']])->fetchAll(PDO::FETCH_COLUMN);
    }
    return ['conversations' => $rows];
}

function staff_close(PDO $db, array $req, array $staff): array
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
        $deleted = !array_diff(delete_voters($db, $convId, $staff), $votes);
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

// Whose vote a deletion needs: staff who hold the conversation's key and are
// still in keys.json. Someone removed from keys.json cannot block it.
function delete_voters(PDO $db, string $convId, array $staff): array
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

// keys.json: {"staff": [{"id": ..., "name": ..., "box": b64, "sign": b64}, ...]}
function load_staff(string $file): array
{
    $data = json_decode((string)file_get_contents($file), true, 8, JSON_THROW_ON_ERROR);
    $staff = [];
    foreach ($data['staff'] as $entry) {
        if (!preg_match(STAFF_ID_PATTERN, $entry['id'])) {
            throw new RuntimeException("invalid staff id in keys.json");
        }
        $staff[$entry['id']] = ['sign' => unb64($entry['sign'])];
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
        || $bits < $config['pow']['bits'] || $count < $config['pow']['count']) {
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

    // Each challenge counts once. Rows expire with the challenge.
    try {
        query($db, 'INSERT INTO used_challenges (salt, expires) VALUES (?, ?)', [$salt, $expires]);
    } catch (PDOException) {
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
    // Idempotent, so tables added later appear in existing databases.
    $db->exec((string)file_get_contents($schemaFile));
    return $db;
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
    return intdiv(time(), HOUR) * HOUR;
}

function b64(string $bytes): string
{
    return base64_encode($bytes);
}

function unb64(string $text): string
{
    return base64_decode($text, true);
}

// ------------------------------------------------------------------ notifications

// Best effort: a failed notification must not fail the request, and staff see
// new messages on the staff page anyway. Never put message content here.
function notify(array $config, array $staffIds, string $subject): void
{
    $body = "$subject.\n\nRead it at {$config['site_url']}staff.html\n\n"
        . "This notification contains no message content.\n";

    $headers = [
        'From' => $config['mail_from'],
        'Content-Type' => 'text/plain; charset=UTF-8',
        'Auto-Submitted' => 'auto-generated',
    ];
    foreach ($staffIds as $id) {
        $to = $config['staff_email'][$id] ?? null;
        if ($to !== null && !@mail($to, "[Kummerkasten] $subject", $body, $headers)) {
            error_log("kummerkasten: mail to staff '$id' failed");
        }
    }

    if (!empty($config['ntfy_url'])) {
        $ch = curl_init($config['ntfy_url']);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $subject,
            CURLOPT_HTTPHEADER => ['Title: Kummerkasten', 'Click: ' . $config['site_url'] . 'staff.html'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);
        if (curl_exec($ch) === false) {
            error_log('kummerkasten: ntfy failed: ' . curl_error($ch));
        }
    }
}
