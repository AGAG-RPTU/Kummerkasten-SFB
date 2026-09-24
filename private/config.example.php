<?php
// Copy to config.php and fill in. config.php is not in git. Settings left
// out fall back to DEFAULT_CONFIG in app.php.

return [
    // SQLite file; its directory must be writable by the web server.
    'db' => __DIR__ . '/data/kummerkasten.sqlite',

    // Trusted persons: public keys and notification addresses (in git, see README).
    'keys_file' => __DIR__ . '/../public/keys.json',

    // SFB access password for starting a conversation, or null for none
    // (proof of work alone then keeps out spam):
    //   php tools/hash-password.php
    'password_hash' => null,

    // Proof of work for starting a conversation: count puzzles of `bits` zero
    // bits each, 2^bits * count SHA-256 hashes on average. 17/16 takes about
    // 3 s on a recent laptop, 10 s on a mid-range phone, in the background
    // while the sender writes. ttl is how long a challenge stays valid (s);
    // every `step` new conversations in an hour add one bit.
    'pow' => ['bits' => 17, 'count' => 16, 'ttl' => 3600, 'step' => 5],

    // Random key for signing challenges:
    //   php -r 'echo bin2hex(random_bytes(32)), "\n";'
    'pow_secret' => '',

    // Base URL of the site, used in notifications.
    'site_url' => 'https://example.org/kummerkasten/',

    // Notifications go to the addresses in keys.json and never contain
    // message content.
    'mail_from' => 'kummerkasten@example.org',

    // Optional ntfy topic URL (https://ntfy.sh/<unguessable-topic>) for push
    // notifications, also without content, or null.
    'ntfy_url' => null,

    'retention' => [
        'closed_days' => 30,        // after staff closed the conversation
        'inactive_days' => 365,     // since the last message
    ],

    'limits' => [
        'creates_per_hour' => 100,              // hard cap; `step` slows floods first
        'messages_per_conversation' => 200,
        'conversation_bytes' => 1000000,        // ciphertext per conversation
        'sender_messages_per_hour' => 20,       // per conversation
        'database_bytes' => 200000000,          // senders are refused beyond this
        'notifications_per_hour' => 30,         // then one summary mail
    ],
];
