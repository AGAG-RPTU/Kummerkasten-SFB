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
   signing key, conversation key K  checks proof of work and         passphrase ─Argon2id─► key pair
 K sealed to each public key in     signatures, mails "new message   ◄── signed list request
   public/keys.json                 #123456" (no content)            opens K, decrypts, replies
```

- `public/js/crypto.js` has the whole protocol; `private/app.php` the API.
- Trusted persons' public keys live in `public/keys.json`, in git, so swapping
  them on the server shows up in `tools/verify.sh`.
- Appends are signed by the codeword's key or a trusted person's key; the
  server enforces a gapless sequence per conversation.
- Plaintext is padded to 512-byte blocks, stored times are rounded to the
  nearest hour, and the application stores no IP addresses.

Codewords share one Argon2 salt, so an attacker with the database tests each
guess against all conversations at once; 62 bits leave ample margin at the
expected scale.

Limits (the info page names those that matter to senders): whoever controls
the server can deliver altered JavaScript (detectable with `tools/verify.sh`,
not preventable); the server can drop messages; no forward secrecy, so a
leaked passphrase exposes that person's past conversations; web server access
logs and host backups are outside the application's control.

## Layout

```
public/     webroot: pages, JS, vendored libsodium, api.php entry point, .htaccess
private/    app.php, schema.sql, config.php (not in git), data/ (SQLite)
tests/      node --test: unit tests, API tests against php -S, keys.json checks
tools/      vendor.sh, dev-env.js, dev-router.php, hash-password.php, deploy.sh, verify.sh
```

## Development

Requires Node ≥ 20 and PHP ≥ 8.1 with `sodium` and `pdo_sqlite`.

```sh
npm test                      # ~15 s
node tools/dev-env.js         # dev config, access password "dev", two dev trusted persons
KK_CONFIG=$PWD/private/data/dev/config.php \
  php -d "sendmail_path=cat >> $PWD/private/data/dev/mail.log" \
  -S localhost:8765 -t public tools/dev-router.php
```

`tools/dev-router.php` applies the headers from `public/.htaccess`, so the
Content Security Policy is active locally too.

`tools/vendor.sh` regenerates `public/vendor/` and `public/js/wordlist.js`;
`cd public/vendor && shasum -a 256 -c SHA256SUMS` checks the vendored files.

## Deployment

Host checklist (netcup, the current host, meets all of these; on `gap-www`
`mail()` did not deliver without SMTP credentials):

- PHP ≥ 8.1 with `sodium` and `pdo_sqlite` (`php -m`).
- Apache with `.htaccess` support for `mod_headers` and `mod_rewrite`.
- `mail()` delivers (`sendmail_path` set, relay configured). Otherwise set
  `ntfy_url` in the config for push notifications instead.
- `private/` writable by PHP. `tools/deploy.sh` puts it inside the webroot,
  where `open_basedir` usually confines PHP; its `.htaccess` denies web
  access. Check with `curl -I <site>/private/app.php`, which must give 403.
- Access logs: ask the host to disable or anonymise IP logging for this site,
  then adjust `index.security.body` in `public/js/i18n.js` accordingly.

Steps:

1. `tools/deploy.sh <ssh-host> <webroot>` copies the committed `HEAD`:
   `public/` to the webroot, `private/` to `<webroot>/private`, and writes
   `version.txt` with the commit hash, which the footer links to on GitHub. It removes files git no longer has
   and leaves `config.php` and the database alone.
2. On the host, copy `private/config.example.php` to `private/config.php` and
   fill it in: at least `pow_secret`, and `password_hash` if the SFB access
   password should be required.
3. Each trusted person opens `/setup` on the deployed site, on their own
   device, and sends the displayed JSON entry to the maintainer, who adds it
   to `public/keys.json`, runs `npm test` (which checks every entry, including
   the notification address), commits and deploys. Notification addresses
   are public there, like the names.
4. `tools/verify.sh https://…/ <deployed-ref>` must report `ok` for every file.

Moving to another host (**TODO**: netcup is a stopgap until RHRZ hosting):

- Update the hosting paragraphs in `public/imprint.html` and
  `public/privacy.html` (marked `TODO(hosting)`): provider, address, log
  retention, and whether a processing agreement applies.
- Switch off web statistics built from access logs, as done in Plesk.
- `tools/deploy.sh` warns while the legal pages still name netcup.

Changing trusted persons: a person added later cannot read or act on
conversations that started before. Removing someone from `keys.json` stops
them from listing, replying and closing, but anyone who once held a
conversation's key and ID can keep reading it; keys are never rotated.

Spam protection for new conversations: the browser solves a proof-of-work
challenge in a worker while the sender writes (`pow` in `config.php`; see
`public/js/pow.js`). The SFB access password is optional on top: set
`password_hash` (from `php tools/hash-password.php`) to require it, `null` to
drop it. `/write#pw=<password>` fills it in; the fragment never reaches
the server. Changing it does not affect senders who already have a codeword.

Retention: closed conversations are deleted after `closed_days`, all others
after `inactive_days` without a message. Senders can delete their own
conversation at any time. Trusted persons delete only unanimously: each votes,
the last missing vote deletes, and any new message clears the votes. Only
people in `keys.json` who hold the conversation's key count.

Abuse limits (`limits` and `pow` in `config.php`, defaults in `app.php`):
every `step` new conversations in an hour make the proof of work twice as
hard, with a hard cap behind it; per conversation, a maximum number of
messages, of bytes, and of sender messages per hour; senders are refused once
the database reaches `database_bytes`, trusted persons are not. Sender
messages notify at most once per hour per conversation until a trusted person
replies, and past `notifications_per_hour` one summary mail replaces the
rest. Wrong passwords never lock anyone out.
