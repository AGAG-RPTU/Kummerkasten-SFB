<?php
// private/ holds code, config and database: inside the webroot when
// open_basedir confines PHP there (its .htaccess denies web access),
// otherwise next to it, or wherever KK_PRIVATE_DIR points.
// KK_CONFIG overrides the config file, for tests and local development.
$privateDir = getenv('KK_PRIVATE_DIR')
    ?: (is_dir(__DIR__ . '/private') ? __DIR__ . '/private' : __DIR__ . '/../private');
require $privateDir . '/app.php';
run($privateDir);
