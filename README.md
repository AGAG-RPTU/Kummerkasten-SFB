# SFB TRR 195 Kummerkasten

A contact form for members of the SFB TRR 195 to reach the trusted persons
(Vertrauenspersonen), anonymously or by name. Senders receive a six-word
codeword and use it to return, read replies and answer.

Messages are encrypted in the browser. The server stores ciphertext only;
neither its operator nor a stolen database reveals content.

## How it works

```
 sender browser                    server (PHP + SQLite)              trusted person's browser
 codeword ─Argon2id─► conv_id,  ──► stores ciphertext, sealed keys,
   signing key, conversation key K  checks shared password and       passphrase ─Argon2id─► key pair
 K sealed to each public key in     signatures, mails "new message   ◄── signed list request
   public/keys.json                 #123456" (no content)            opens K, decrypts, replies
```

- `public/js/crypto.js` has the whole protocol; `private/app.php` the API.
- Trusted persons' public keys live in `public/keys.json`, in git, so swapping
  them on the server shows up in `tools/verify.sh`.
- Appends are signed by the codeword's key or a trusted person's key; the
  server enforces a gapless sequence per conversation.
- Plaintext is padded to 512-byte blocks; stored times are rounded to the hour;
  the application stores no IP addresses.

Codewords share one Argon2 salt, so an attacker with the database tests each
guess against all conversations at once; 62 bits leave ample margin at the
expected scale.

Limits, also stated on the info page: whoever controls the server can deliver
altered JavaScript (detectable with `tools/verify.sh`, not preventable); the
server can drop messages; no forward secrecy, so a leaked passphrase exposes
that person's past conversations; web server access logs and host backups are
outside the application's control.

## Layout

```
public/     webroot: pages, JS, vendored libsodium, api.php entry point, .htaccess
private/    app.php, schema.sql, config.php (not in git), data/ (SQLite)
tests/      node --test: crypto unit tests, API tests against php -S
tools/      vendor.sh, dev-env.js, dev-router.php, hash-password.php, verify.sh
```

## Development

Requires Node ≥ 20 and PHP ≥ 8.1 with `sodium` and `pdo_sqlite`.

```sh
npm test                      # 31 tests, ~10 s
node tools/dev-env.js         # dev config, shared password "dev", two dev trusted persons
KK_CONFIG=$PWD/private/data/dev/config.php \
  php -d "sendmail_path=cat >> $PWD/private/data/dev/mail.log" \
  -S localhost:8765 -t public tools/dev-router.php
```

`tools/dev-router.php` applies the headers from `public/.htaccess`, so the
Content Security Policy is active locally too.

`tools/vendor.sh` regenerates `public/vendor/` and `public/js/wordlist.js`;
`cd public/vendor && shasum -a 256 -c SHA256SUMS` checks the vendored files.

## Deployment

Host checklist (`gap-www` meets all of these):

- PHP ≥ 8.1 with `sodium` and `pdo_sqlite` (`php -m`).
- Apache with `.htaccess` support for `mod_headers` and `mod_rewrite`.
- `mail()` delivers (`sendmail_path` set, relay configured). Otherwise set
  `ntfy_url` in the config for push notifications instead.
- A directory outside the webroot for `private/`, writable by PHP. If there is
  none, keep `private/` inside the webroot; its `.htaccess` denies access.
- Access logs: ask the host to disable or anonymise IP logging for this site,
  then adjust `index.security.body` in `public/js/i18n.js` accordingly.

Steps:

1. Copy `public/` to the webroot and `private/` next to it. If `private/` sits
   elsewhere, add `SetEnv KK_PRIVATE_DIR /path/to/private` to
   `public/.htaccess`.
2. `cp private/config.example.php private/config.php` and fill it in. Generate
   the shared password hash with `php tools/hash-password.php`.
3. Each trusted person opens `setup.html` on the deployed site, on their own
   device, and sends the displayed JSON entry to the maintainer. The maintainer
   adds it to `public/keys.json`, commits, deploys, and adds the email address
   to `staff_email` in `config.php`.
4. `git rev-parse --short HEAD > public/version.txt` on the deployed copy; the
   footer shows it.
5. `tools/verify.sh https://…/ <deployed-ref>` must report `ok` for every file.

Changing trusted persons: a person added later cannot read or act on
conversations that started before. Removing someone from `keys.json` stops
them from listing, replying and closing, but anyone who once held a
conversation's key and ID can keep reading it; keys are never rotated.

Changing the shared password: replace `password_hash` in `config.php`. Senders
with a codeword are unaffected.

Retention: closed conversations are deleted after `closed_days`, all others
after `inactive_days` without a message. Senders can delete their own
conversation at any time.

Abuse limits (`limits` in `config.php`): new conversations per hour
site-wide, messages per conversation. Sender messages notify at most once per
hour per conversation until a trusted person replies. Wrong passwords never
lock anyone out.
