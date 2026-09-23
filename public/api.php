<?php
// private/ holds code, config and database. It lives next to the webroot, or
// wherever KK_PRIVATE_DIR points (e.g. `SetEnv KK_PRIVATE_DIR ...` in Apache).
// KK_CONFIG overrides the config file, for tests and local development.
$privateDir = getenv('KK_PRIVATE_DIR') ?: __DIR__ . '/../private';
require $privateDir . '/app.php';
run($privateDir);
