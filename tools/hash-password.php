<?php
// Prints the password_hash value for private/config.php.
// Usage: php tools/hash-password.php   (reads the password from stdin)
fwrite(STDERR, "Shared password: ");
$password = trim((string)fgets(STDIN));
if ($password === '') {
    fwrite(STDERR, "empty password\n");
    exit(1);
}
echo password_hash($password, PASSWORD_DEFAULT), "\n";
