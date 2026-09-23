<?php
// Copy to config.php and fill in. config.php is not in git.

return [
    // SQLite file; its directory must be writable by the web server.
    'db' => __DIR__ . '/data/kummerkasten.sqlite',

    // Public keys of the trusted persons (committed to git, see README).
    'keys_file' => __DIR__ . '/../public/keys.json',

    // Shared password for starting a conversation:
    //   php tools/hash-password.php
    'password_hash' => '',

    // Base URL of the site, used in notifications.
    'site_url' => 'https://example.org/kummerkasten/',

    // Notification targets per staff id from keys.json. Notifications never
    // contain message content.
    'staff_email' => [
        // 'hannah' => 'hannah@example.org',
    ],
    'mail_from' => 'kummerkasten@example.org',

    // Optional ntfy topic URL (https://ntfy.sh/<unguessable-topic>), or null.
    'ntfy_url' => null,

    'retention' => [
        'closed_days' => 30,        // after staff closed the conversation
        'inactive_days' => 365,     // since the last message
    ],

    'limits' => [
        'creates_per_hour' => 30,
        'messages_per_conversation' => 200,
    ],
];
