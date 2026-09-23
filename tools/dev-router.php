<?php
// Router for `php -S`: applies the security headers from public/.htaccess so
// that CSP problems show up locally, and serves keys.json from the config's
// keys_file (the dev keys made by tools/dev-env.js).
//   KK_CONFIG=private/data/dev/config.php php -S localhost:8765 -t public tools/dev-router.php

const MIME_TYPES = [
    'html' => 'text/html; charset=utf-8',
    'js' => 'text/javascript; charset=utf-8',
    'css' => 'text/css; charset=utf-8',
    'json' => 'application/json',
    'txt' => 'text/plain; charset=utf-8',
];

$htaccess = file_get_contents(__DIR__ . '/../public/.htaccess');
preg_match_all('/^\s*Header always set (\S+) "(.*)"\s*$/m', $htaccess, $matches, PREG_SET_ORDER);
foreach ($matches as [, $name, $value]) {
    if ($name !== 'Strict-Transport-Security') {
        header("$name: $value");
    }
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/') {
    $path = '/index.html';
}
if (str_ends_with($path, '.php')) {
    return false;
}

$file = __DIR__ . '/../public' . $path;
if ($path === '/keys.json' && getenv('KK_CONFIG')) {
    $file = (require getenv('KK_CONFIG'))['keys_file'];
}

// The built-in server drops headers set here when it serves a static file
// itself, and answers missing files with index.html; Apache does neither.
$type = MIME_TYPES[pathinfo($file, PATHINFO_EXTENSION)] ?? null;
if ($type === null || !is_file($file) || str_contains($path, '..')) {
    http_response_code(404);
    return true;
}
header("Content-Type: $type");
readfile($file);
return true;
